"""Deterministic SNAP a2q acquisition transform and ordered-event traces.

The public transform accepts only the frozen full-size shape.  Its external
sort keeps the 17.8M-record source out of Python object memory while preserving
the exact ``(timestamp, within_file_ordinal)`` order.  Raw source bytes stay in
caller-owned scratch and are never part of a returned artifact object.
"""

from __future__ import annotations

import gzip
import hashlib
import heapq
import json
import os
import re
import shutil
import stat
import struct
import tempfile
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.route_a_workloads import RouteAAcceptedGroup, RouteASetTransition

__all__ = (
    "RouteASnapAcceptedRecord",
    "RouteASnapError",
    "RouteASnapPartitionTransform",
    "RouteASnapTrace",
    "RouteASnapTransform",
    "build_route_a_snap_trace",
    "decode_route_a_snap_partition",
    "route_a_snap_shard_identity",
    "transform_route_a_snap_gzip",
    "validate_route_a_snap_trace",
)

_SOURCE_URL = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
_MAPPING_SCHEMA = "dynamic-cssc-route-a-snap-mapping-v1"
_ACCEPTED_SCHEMA = "dynamic-cssc-route-a-snap-accepted-trace-v1"
_SEMANTIC_SCHEMA = "dynamic-cssc-route-a-snap-semantic-event-trace-v1"
_INITIAL_SCHEMA = "dynamic-cssc-route-a-snap-empty-initial-state-v1"
_SHARD_SCHEMA = "dynamic-cssc-route-a-shard-identity-v1"
_LINE_PATTERN = re.compile(rb"[1-9][0-9]*[ \t]+[1-9][0-9]*[ \t]+(?:0|[1-9][0-9]*)\Z")
_PARTITION_DOMAIN = bytes.fromhex("726f7574652d612d736e61702d6132712d763100")
_PREFIX_DOMAIN = bytes.fromhex("726f7574652d612d736e61702d7072656669782d763100")
_RECORD = struct.Struct(">QQQQ")  # timestamp, physical ordinal, source, target
_UINT64_MAX = (1 << 64) - 1
_INT64_MAX = (1 << 63) - 1
_FORMAL_PREFIX = 1_000_000
_FORMAL_ROWS = 1_024
_FORMAL_COLUMNS = 8_193
_FORMAL_MIN_OBSERVED_COLUMNS = 7_374
_FORMAL_SUFFIX = 4_096
_FORMAL_CHUNK_RECORDS = 250_000
_T2_FIFO = 1_024
_COEFFICIENT_CAP = 7


class RouteASnapError(ValueError):
    """The source object, transform, or semantic trace failed closed."""


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise RouteASnapError("SNAP value is not canonical finite JSON") from error
    return (rendered + "\n").encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RouteASnapError("SNAP JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RouteASnapError(f"{label} contains non-finite {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteASnapError(f"{label} is not duplicate-free ASCII JSON") from error
    if type(value) is not dict or _canonical(value) != content:
        raise RouteASnapError(f"{label} is not one canonical object")
    return value


def _identity(value: int) -> str:
    if type(value) is not int or not 1 <= value <= _UINT64_MAX:
        raise RouteASnapError("SNAP identity is outside uint64")
    return f"stack-overflow:user:{value:020d}"


def _partition(source: int) -> int:
    digest = hashlib.sha256(_PARTITION_DOMAIN + _identity(source).encode("ascii")).digest()
    return int.from_bytes(digest, "big") % 2


def _direct_file(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be an absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise RouteASnapError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
        raise RouteASnapError(f"{label} is not one owned regular file")
    return path


def _sha256_stable(path: Path) -> tuple[str, int, tuple[int, ...]]:
    path = _direct_file(path, label="SNAP raw gzip")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
            total += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    projection = lambda value: (  # noqa: E731 - stable stat projection
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if total != before.st_size or projection(before) != projection(after):
        raise RouteASnapError("SNAP raw gzip changed while hashed")
    return digest.hexdigest(), total, projection(before)


def _empty_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TypeError(f"{label} must be an absolute pathlib.Path")
    try:
        observed = path.lstat()
    except OSError as error:
        raise RouteASnapError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode) or any(path.iterdir()):
        raise RouteASnapError(f"{label} must be one empty direct directory")
    return path


def _write_chunk(path: Path, rows: list[tuple[int, int, int, int]]) -> None:
    rows.sort()
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        for timestamp, ordinal, source, target in rows:
            view = memoryview(_RECORD.pack(timestamp, ordinal, source, target))
            while view:
                written = os.write(descriptor, view)
                if written <= 0:  # pragma: no cover - os.write advances or raises
                    raise RouteASnapError("SNAP chunk write stalled")
                view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _iter_chunk(path: Path):  # type: ignore[no-untyped-def]
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        while True:
            block = os.read(descriptor, _RECORD.size)
            if not block:
                return
            if len(block) != _RECORD.size:
                raise RouteASnapError("SNAP sorted chunk is truncated")
            yield _RECORD.unpack(block)
    finally:
        os.close(descriptor)


def _parse_to_chunks(
    gzip_path: Path,
    sort_root: Path,
    *,
    chunk_records: int,
) -> tuple[tuple[Path, ...], dict[str, int]]:
    if type(chunk_records) is not int or chunk_records <= 0:
        raise RouteASnapError("SNAP chunk size is outside its closed bound")
    chunks: list[Path] = []
    pending: list[tuple[int, int, int, int]] = []
    counts = {
        "blank": 0,
        "comment": 0,
        "eligible": 0,
        "malformed": 0,
        "physical_records": 0,
        "self_loop": 0,
    }
    try:
        with gzip.open(gzip_path, "rb") as source_file:
            for ordinal, raw_record in enumerate(source_file):
                counts["physical_records"] += 1
                if raw_record.endswith(b"\n"):
                    raw_record = raw_record[:-1]
                if raw_record.endswith(b"\r"):
                    raw_record = raw_record[:-1]
                try:
                    raw_record.decode("utf-8", errors="strict")
                except UnicodeDecodeError as error:
                    raise RouteASnapError("SNAP record is not strict UTF-8") from error
                if not raw_record:
                    counts["blank"] += 1
                    continue
                if raw_record[:1] == b"#":
                    counts["comment"] += 1
                    continue
                if _LINE_PATTERN.fullmatch(raw_record) is None:
                    counts["malformed"] += 1
                    continue
                source_text, target_text, timestamp_text = re.split(rb"[ \t]+", raw_record)
                source = int(source_text)
                target = int(target_text)
                timestamp = int(timestamp_text)
                if source > _UINT64_MAX or target > _UINT64_MAX or timestamp > _INT64_MAX:
                    counts["malformed"] += 1
                    continue
                if source == target:
                    counts["self_loop"] += 1
                    continue
                pending.append((timestamp, ordinal, source, target))
                counts["eligible"] += 1
                if len(pending) == chunk_records:
                    path = sort_root / f"chunk-{len(chunks):06d}.bin"
                    _write_chunk(path, pending)
                    chunks.append(path)
                    pending = []
        if pending:
            path = sort_root / f"chunk-{len(chunks):06d}.bin"
            _write_chunk(path, pending)
            chunks.append(path)
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        if isinstance(error, RouteASnapError):
            raise
        raise RouteASnapError("SNAP gzip object cannot be parsed exactly") from error
    if not chunks:
        raise RouteASnapError("SNAP object contains no eligible record")
    return tuple(chunks), counts


def _read_binary_records(path: Path):  # type: ignore[no-untyped-def]
    with path.open("rb") as source:
        while block := source.read(_RECORD.size):
            if len(block) != _RECORD.size:
                raise RouteASnapError("SNAP prefix record file is truncated")
            yield _RECORD.unpack(block)


def _selected(counter: Counter[int], count: int, *, label: str) -> tuple[int, ...]:
    if len(counter) < count:
        raise RouteASnapError(f"SNAP {label} has fewer than {count} identities")
    return tuple(
        identity
        for identity, _frequency in sorted(
            counter.items(),
            key=lambda item: (-item[1], _identity(item[0]).encode("ascii")),
        )[:count]
    )


@dataclass(frozen=True, slots=True)
class RouteASnapAcceptedRecord:
    accepted_ordinal: int
    within_file_ordinal: int
    source_id: int
    target_id: int
    historical_timestamp: int
    row_ordinal: int
    column_ordinal: int

    def to_document(self) -> dict[str, int]:
        return {
            "accepted_ordinal": self.accepted_ordinal,
            "column_ordinal": self.column_ordinal,
            "historical_timestamp": self.historical_timestamp,
            "row_ordinal": self.row_ordinal,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "within_file_ordinal": self.within_file_ordinal,
        }


@dataclass(frozen=True, slots=True)
class RouteASnapPartitionTransform:
    partition: int
    raw_object_sha256: str
    mapping_prefix_identity_sha256: str
    ordered_row_identities: tuple[str, ...]
    ordered_column_identities: tuple[str, ...]
    ordered_reserved_column_identities: tuple[str, ...]
    mapping_bytes: bytes
    mapping_sha256: str
    accepted_records: tuple[RouteASnapAcceptedRecord, ...]
    accepted_trace_bytes: bytes
    accepted_trace_sha256: str


@dataclass(frozen=True, slots=True)
class RouteASnapTransform:
    raw_object_sha256: str
    raw_object_byte_count: int
    source_url: str
    parsing_counts: dict[str, int]
    partitions: tuple[RouteASnapPartitionTransform, RouteASnapPartitionTransform]


def _identity_value(identity: object, *, label: str) -> int:
    if (
        type(identity) is not str
        or re.fullmatch(r"stack-overflow:user:[0-9]{20}", identity) is None
    ):
        raise RouteASnapError(f"{label} is not one canonical source identity")
    value = int(identity.rsplit(":", 1)[1])
    if value == 0 or _identity(value) != identity:
        raise RouteASnapError(f"{label} is outside the canonical ID domain")
    return value


def decode_route_a_snap_partition(
    mapping_bytes: bytes,
    accepted_trace_bytes: bytes,
) -> RouteASnapPartitionTransform:
    """Decode one exact formal 1024x8193 mapping and 4096-record suffix."""

    mapping = _canonical_object(mapping_bytes, label="SNAP mapping")
    mapping_fields = {
        "mapping_prefix_eligible_record_count",
        "mapping_prefix_identity_sha256",
        "ordered_1024_row_identities",
        "ordered_8193_column_identities",
        "ordered_reserved_column_identities",
        "partition",
        "raw_object_sha256",
        "reserved_column_count",
        "schema_version",
    }
    rows = mapping.get("ordered_1024_row_identities")
    columns = mapping.get("ordered_8193_column_identities")
    reserved = mapping.get("ordered_reserved_column_identities")
    if (
        set(mapping) != mapping_fields
        or mapping.get("schema_version") != _MAPPING_SCHEMA
        or mapping.get("mapping_prefix_eligible_record_count") != _FORMAL_PREFIX
        or type(mapping.get("partition")) is not int
        or mapping["partition"] not in {0, 1}
        or type(mapping.get("raw_object_sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", mapping["raw_object_sha256"]) is None
        or type(mapping.get("mapping_prefix_identity_sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", mapping["mapping_prefix_identity_sha256"])
        is None
        or type(rows) is not list
        or len(rows) != _FORMAL_ROWS
        or type(columns) is not list
        or len(columns) != _FORMAL_COLUMNS
        or type(reserved) is not list
        or type(mapping.get("reserved_column_count")) is not int
        or mapping["reserved_column_count"] != len(reserved)
        or len(reserved) > _FORMAL_COLUMNS - _FORMAL_MIN_OBSERVED_COLUMNS
    ):
        raise RouteASnapError("SNAP mapping schema or frozen dimensions changed")
    row_values = tuple(_identity_value(value, label="SNAP row identity") for value in rows)
    if len(set(row_values)) != len(row_values):
        raise RouteASnapError("SNAP row mapping contains a duplicate identity")
    observed_count = _FORMAL_COLUMNS - len(reserved)
    column_values = tuple(
        _identity_value(value, label="SNAP observed column identity")
        for value in columns[:observed_count]
    )
    expected_reserved = tuple(
        f"route-a:reserved-column:{ordinal:08d}" for ordinal in range(len(reserved))
    )
    if (
        len(set(column_values)) != len(column_values)
        or tuple(reserved) != expected_reserved
        or tuple(columns[observed_count:]) != expected_reserved
    ):
        raise RouteASnapError("SNAP column or reserved mapping changed")

    accepted = _canonical_object(accepted_trace_bytes, label="SNAP accepted trace")
    accepted_fields = {
        "accepted_record_count",
        "mapping_sha256",
        "ordered_records",
        "partition",
        "raw_object_sha256",
        "schema_version",
    }
    mapping_sha256 = hashlib.sha256(mapping_bytes).hexdigest()
    record_values = accepted.get("ordered_records")
    if (
        set(accepted) != accepted_fields
        or accepted.get("schema_version") != _ACCEPTED_SCHEMA
        or accepted.get("accepted_record_count") != _FORMAL_SUFFIX
        or accepted.get("mapping_sha256") != mapping_sha256
        or accepted.get("partition") != mapping["partition"]
        or accepted.get("raw_object_sha256") != mapping["raw_object_sha256"]
        or type(record_values) is not list
        or len(record_values) != _FORMAL_SUFFIX
    ):
        raise RouteASnapError("SNAP accepted trace binding changed")
    record_fields = {
        "accepted_ordinal",
        "column_ordinal",
        "historical_timestamp",
        "row_ordinal",
        "source_id",
        "target_id",
        "within_file_ordinal",
    }
    records: list[RouteASnapAcceptedRecord] = []
    previous_order: tuple[int, int] | None = None
    for ordinal, value in enumerate(record_values):
        if type(value) is not dict or set(value) != record_fields:
            raise RouteASnapError("SNAP accepted record schema changed")
        row = value.get("row_ordinal")
        column = value.get("column_ordinal")
        source = value.get("source_id")
        target = value.get("target_id")
        timestamp = value.get("historical_timestamp")
        physical = value.get("within_file_ordinal")
        if (
            value.get("accepted_ordinal") != ordinal
            or type(row) is not int
            or not 0 <= row < _FORMAL_ROWS
            or type(column) is not int
            or not 0 <= column < observed_count
            or type(source) is not int
            or not 1 <= source <= _UINT64_MAX
            or type(target) is not int
            or not 1 <= target <= _UINT64_MAX
            or type(timestamp) is not int
            or not 0 <= timestamp <= _INT64_MAX
            or type(physical) is not int
            or not 0 <= physical <= _UINT64_MAX
            or row_values[row] != source
            or column_values[column] != target
            or (previous_order is not None and (timestamp, physical) <= previous_order)
        ):
            raise RouteASnapError("SNAP accepted record identity or order changed")
        previous_order = (timestamp, physical)
        records.append(
            RouteASnapAcceptedRecord(
                accepted_ordinal=ordinal,
                within_file_ordinal=physical,
                source_id=source,
                target_id=target,
                historical_timestamp=timestamp,
                row_ordinal=row,
                column_ordinal=column,
            )
        )
    frozen_records = tuple(records)
    if accepted_trace_bytes != _accepted_trace_bytes(
        partition=mapping["partition"],  # type: ignore[arg-type]
        raw_object_sha256=mapping["raw_object_sha256"],  # type: ignore[arg-type]
        mapping_sha256=mapping_sha256,
        records=frozen_records,
    ):
        raise RouteASnapError("SNAP accepted trace is not canonical from its records")
    return RouteASnapPartitionTransform(
        partition=mapping["partition"],  # type: ignore[arg-type]
        raw_object_sha256=mapping["raw_object_sha256"],  # type: ignore[arg-type]
        mapping_prefix_identity_sha256=mapping[  # type: ignore[arg-type]
            "mapping_prefix_identity_sha256"
        ],
        ordered_row_identities=tuple(rows),  # type: ignore[arg-type]
        ordered_column_identities=tuple(columns),  # type: ignore[arg-type]
        ordered_reserved_column_identities=tuple(reserved),  # type: ignore[arg-type]
        mapping_bytes=mapping_bytes,
        mapping_sha256=mapping_sha256,
        accepted_records=frozen_records,
        accepted_trace_bytes=accepted_trace_bytes,
        accepted_trace_sha256=hashlib.sha256(accepted_trace_bytes).hexdigest(),
    )


def _accepted_trace_bytes(
    *,
    partition: int,
    raw_object_sha256: str,
    mapping_sha256: str,
    records: tuple[RouteASnapAcceptedRecord, ...],
) -> bytes:
    return _canonical(
        {
            "accepted_record_count": len(records),
            "mapping_sha256": mapping_sha256,
            "ordered_records": [record.to_document() for record in records],
            "partition": partition,
            "raw_object_sha256": raw_object_sha256,
            "schema_version": _ACCEPTED_SCHEMA,
        }
    )


def _transform(
    gzip_path: Path,
    scratch_root: Path,
    *,
    raw_object_sha256: str,
    raw_object_byte_count: int,
    prefix_count: int,
    row_count: int,
    column_count: int,
    minimum_observed_columns: int,
    suffix_count: int,
    chunk_records: int,
) -> RouteASnapTransform:
    gzip_path = _direct_file(gzip_path, label="SNAP raw gzip")
    scratch_root = _empty_directory(scratch_root, label="SNAP transform scratch")
    if (
        type(raw_object_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", raw_object_sha256) is None
        or type(raw_object_byte_count) is not int
        or raw_object_byte_count != gzip_path.stat().st_size
        or any(
            type(value) is not int or value <= 0
            for value in (
                prefix_count,
                row_count,
                column_count,
                minimum_observed_columns,
                suffix_count,
                chunk_records,
            )
        )
        or minimum_observed_columns > column_count
    ):
        raise RouteASnapError("SNAP transform scope is malformed")
    sort_root = Path(tempfile.mkdtemp(prefix="route-a-snap-sort-", dir=scratch_root))
    prefix_path = sort_root / "mapping-prefix.bin"
    try:
        observed_sha256, observed_bytes, observed_stat = _sha256_stable(gzip_path)
        if (
            observed_sha256 != raw_object_sha256
            or observed_bytes != raw_object_byte_count
        ):
            raise RouteASnapError("SNAP raw object address differs from its exact bytes")
        chunks, parsing_counts = _parse_to_chunks(
            gzip_path,
            sort_root,
            chunk_records=chunk_records,
        )
        if parsing_counts["eligible"] < prefix_count:
            raise RouteASnapError("SNAP object lacks the frozen mapping prefix")
        merged = heapq.merge(*(_iter_chunk(path) for path in chunks))
        source_counts = (Counter(), Counter())
        prefix_digest = hashlib.sha256(_PREFIX_DOMAIN)
        with prefix_path.open("xb") as prefix_output:
            for _ in range(prefix_count):
                try:
                    timestamp, ordinal, source, target = next(merged)
                except StopIteration as error:
                    raise RouteASnapError("SNAP mapping prefix ended early") from error
                source_counts[_partition(source)][source] += 1
                prefix_digest.update(
                    struct.pack(">QQQQ", source, target, timestamp, ordinal)
                )
                prefix_output.write(_RECORD.pack(timestamp, ordinal, source, target))
        prefix_identity_sha256 = prefix_digest.hexdigest()
        selected_rows = tuple(
            _selected(source_counts[partition], row_count, label=f"partition-{partition} rows")
            for partition in (0, 1)
        )
        selected_row_sets = tuple(set(rows) for rows in selected_rows)
        target_counts = (Counter(), Counter())
        for _timestamp, _ordinal, source, target in _read_binary_records(prefix_path):
            partition = _partition(source)
            if source in selected_row_sets[partition]:
                target_counts[partition][target] += 1
        selected_columns: list[tuple[int, ...]] = []
        reserved_columns: list[tuple[str, ...]] = []
        for partition in (0, 1):
            observed_count = len(target_counts[partition])
            if observed_count < minimum_observed_columns:
                raise RouteASnapError(
                    f"SNAP partition-{partition} lacks the frozen observed columns"
                )
            take = min(observed_count, column_count)
            observed = _selected(
                target_counts[partition],
                take,
                label=f"partition-{partition} columns",
            )
            selected_columns.append(observed)
            reserved_columns.append(
                tuple(
                    f"route-a:reserved-column:{ordinal:08d}"
                    for ordinal in range(column_count - len(observed))
                )
            )
        row_maps = tuple(
            {identity: ordinal for ordinal, identity in enumerate(rows)}
            for rows in selected_rows
        )
        column_maps = tuple(
            {identity: ordinal for ordinal, identity in enumerate(columns)}
            for columns in selected_columns
        )
        accepted: tuple[list[RouteASnapAcceptedRecord], list[RouteASnapAcceptedRecord]] = (
            [],
            [],
        )
        for timestamp, ordinal, source, target in merged:
            partition = _partition(source)
            row = row_maps[partition].get(source)
            column = column_maps[partition].get(target)
            if row is None or column is None or len(accepted[partition]) >= suffix_count:
                continue
            accepted[partition].append(
                RouteASnapAcceptedRecord(
                    accepted_ordinal=len(accepted[partition]),
                    within_file_ordinal=ordinal,
                    source_id=source,
                    target_id=target,
                    historical_timestamp=timestamp,
                    row_ordinal=row,
                    column_ordinal=column,
                )
            )
            if all(len(records) == suffix_count for records in accepted):
                break
        if any(len(records) != suffix_count for records in accepted):
            raise RouteASnapError("SNAP suffix cannot close both frozen partitions")

        partition_results: list[RouteASnapPartitionTransform] = []
        for partition in (0, 1):
            row_identities = tuple(_identity(value) for value in selected_rows[partition])
            observed_column_identities = tuple(
                _identity(value) for value in selected_columns[partition]
            )
            ordered_column_identities = (
                observed_column_identities + reserved_columns[partition]
            )
            mapping_bytes = _canonical(
                {
                    "mapping_prefix_eligible_record_count": prefix_count,
                    "mapping_prefix_identity_sha256": prefix_identity_sha256,
                    "ordered_1024_row_identities": list(row_identities),
                    "ordered_8193_column_identities": list(ordered_column_identities),
                    "ordered_reserved_column_identities": list(reserved_columns[partition]),
                    "partition": partition,
                    "raw_object_sha256": raw_object_sha256,
                    "reserved_column_count": len(reserved_columns[partition]),
                    "schema_version": _MAPPING_SCHEMA,
                }
            )
            mapping_sha256 = hashlib.sha256(mapping_bytes).hexdigest()
            frozen_records = tuple(accepted[partition])
            accepted_trace_bytes = _accepted_trace_bytes(
                partition=partition,
                raw_object_sha256=raw_object_sha256,
                mapping_sha256=mapping_sha256,
                records=frozen_records,
            )
            partition_results.append(
                RouteASnapPartitionTransform(
                    partition=partition,
                    raw_object_sha256=raw_object_sha256,
                    mapping_prefix_identity_sha256=prefix_identity_sha256,
                    ordered_row_identities=row_identities,
                    ordered_column_identities=ordered_column_identities,
                    ordered_reserved_column_identities=reserved_columns[partition],
                    mapping_bytes=mapping_bytes,
                    mapping_sha256=mapping_sha256,
                    accepted_records=frozen_records,
                    accepted_trace_bytes=accepted_trace_bytes,
                    accepted_trace_sha256=hashlib.sha256(accepted_trace_bytes).hexdigest(),
                )
            )
        final_sha256, final_bytes, final_stat = _sha256_stable(gzip_path)
        if (
            final_sha256 != observed_sha256
            or final_bytes != observed_bytes
            or final_stat != observed_stat
        ):
            raise RouteASnapError("SNAP raw object changed during its transform")
        return RouteASnapTransform(
            raw_object_sha256=raw_object_sha256,
            raw_object_byte_count=raw_object_byte_count,
            source_url=_SOURCE_URL,
            parsing_counts=dict(parsing_counts),
            partitions=(partition_results[0], partition_results[1]),
        )
    finally:
        if sort_root.exists() and not sort_root.is_symlink():
            shutil.rmtree(sort_root, ignore_errors=True)


def transform_route_a_snap_gzip(
    gzip_path: Path,
    scratch_root: Path,
    *,
    raw_object_sha256: str,
    raw_object_byte_count: int,
) -> RouteASnapTransform:
    """Transform the one frozen full-size a2q object without retaining raw bytes."""

    return _transform(
        gzip_path,
        scratch_root,
        raw_object_sha256=raw_object_sha256,
        raw_object_byte_count=raw_object_byte_count,
        prefix_count=_FORMAL_PREFIX,
        row_count=_FORMAL_ROWS,
        column_count=_FORMAL_COLUMNS,
        minimum_observed_columns=_FORMAL_MIN_OBSERVED_COLUMNS,
        suffix_count=_FORMAL_SUFFIX,
        chunk_records=_FORMAL_CHUNK_RECORDS,
    )


def _transition(row: int, column: int, before: int, after: int) -> RouteASetTransition:
    if before == after:
        raise RouteASnapError("SNAP no-change cannot be emitted as one SET")
    cause: Literal["insert", "modify", "delete"]
    if before == 0:
        cause = "insert"
    elif after == 0:
        cause = "delete"
    else:
        cause = "modify"
    return RouteASetTransition(
        row=row,
        column=column,
        before=before,
        after=after,
        cause=cause,
    )


def _semantic_groups(
    records: tuple[RouteASnapAcceptedRecord, ...],
    semantics: Literal["T1", "T2"],
) -> tuple[tuple[RouteAAcceptedGroup, ...], list[dict[str, object]]]:
    counts: Counter[tuple[int, int]] = Counter()
    fifo: deque[RouteASnapAcceptedRecord] = deque()
    typed: list[RouteAAcceptedGroup] = []
    documents: list[dict[str, object]] = []
    for record in records:
        transitions: list[RouteASetTransition] = []
        expired: RouteASnapAcceptedRecord | None = None
        if semantics == "T2" and len(fifo) == _T2_FIFO:
            expired = fifo.popleft()
            coordinate = (expired.row_ordinal, expired.column_ordinal)
            before_count = counts[coordinate]
            before = min(_COEFFICIENT_CAP, before_count)
            counts[coordinate] -= 1
            if counts[coordinate] == 0:
                del counts[coordinate]
            after = min(_COEFFICIENT_CAP, counts.get(coordinate, 0))
            if before != after:
                transitions.append(_transition(*coordinate, before, after))
        coordinate = (record.row_ordinal, record.column_ordinal)
        before = min(_COEFFICIENT_CAP, counts[coordinate])
        counts[coordinate] += 1
        after = min(_COEFFICIENT_CAP, counts[coordinate])
        if before != after:
            transitions.append(_transition(*coordinate, before, after))
        if semantics == "T2":
            fifo.append(record)
        group = RouteAAcceptedGroup(
            accepted_ordinal=record.accepted_ordinal,
            logical_time_numerator=record.accepted_ordinal,
            logical_time_denominator=128,
            transitions=tuple(transitions),
        )
        typed.append(group)
        documents.append(
            {
                "accepted_ordinal": record.accepted_ordinal,
                "column_ordinal": record.column_ordinal,
                "expired_occurrence_accepted_ordinal_or_null": (
                    None if expired is None else expired.accepted_ordinal
                ),
                "historical_timestamp": record.historical_timestamp,
                "logical_time_denominator": 128,
                "logical_time_numerator": record.accepted_ordinal,
                "no_change_reason_or_null": (
                    None if transitions else "coefficient-cap-capped-no-change"
                ),
                "ordered_set_transitions": [
                    {
                        "after": transition.after,
                        "before": transition.before,
                        "cause": transition.cause,
                        "column_ordinal": transition.column,
                        "row_ordinal": transition.row,
                        "transition_ordinal_within_group": ordinal,
                    }
                    for ordinal, transition in enumerate(transitions)
                ],
                "row_ordinal": record.row_ordinal,
                "within_file_ordinal": record.within_file_ordinal,
            }
        )
    return tuple(typed), documents


@dataclass(frozen=True, slots=True)
class RouteASnapTrace:
    suite_role: Literal["formal"]
    source_kind: Literal["snap-a2q"]
    raw_object_sha256: str
    partition: int
    semantics: Literal["T1", "T2"]
    rows: int
    columns: int
    initial_nonzeros: tuple[tuple[int, int, int], ...]
    initial_state_bytes: bytes
    initial_state_sha256: str
    mapping_bytes: bytes
    mapping_sha256: str
    accepted_trace_bytes: bytes
    accepted_trace_sha256: str
    accepted_records: tuple[RouteASnapAcceptedRecord, ...]
    accepted_groups: tuple[RouteAAcceptedGroup, ...]
    event_trace_bytes: bytes
    event_trace_sha256: str

    def initial_state(self) -> dict[tuple[int, int], int]:
        return {}


def build_route_a_snap_trace(
    partition: RouteASnapPartitionTransform,
    *,
    semantics: str,
) -> RouteASnapTrace:
    """Build one of the four canonical ordered-event semantic traces."""

    if type(partition) is not RouteASnapPartitionTransform or partition.partition not in {0, 1}:
        raise TypeError("partition must be one exact RouteASnapPartitionTransform")
    if semantics not in {"T1", "T2"}:
        raise RouteASnapError("SNAP semantics must be T1 or T2")
    typed_groups, group_documents = _semantic_groups(
        partition.accepted_records,
        semantics,  # type: ignore[arg-type]
    )
    event_trace_bytes = _canonical(
        {
            "accepted_trace_sha256": partition.accepted_trace_sha256,
            "mapping_sha256": partition.mapping_sha256,
            "ordered_event_groups": group_documents,
            "partition": partition.partition,
            "schema_version": _SEMANTIC_SCHEMA,
            "semantics": semantics,
        }
    )
    initial_state_bytes = _canonical(
        {
            "columns": _FORMAL_COLUMNS,
            "ordered_nonzeros": [],
            "rows": _FORMAL_ROWS,
            "schema_version": _INITIAL_SCHEMA,
        }
    )
    return RouteASnapTrace(
        suite_role="formal",
        source_kind="snap-a2q",
        raw_object_sha256=partition.raw_object_sha256,
        partition=partition.partition,
        semantics=semantics,  # type: ignore[arg-type]
        rows=_FORMAL_ROWS,
        columns=_FORMAL_COLUMNS,
        initial_nonzeros=(),
        initial_state_bytes=initial_state_bytes,
        initial_state_sha256=hashlib.sha256(initial_state_bytes).hexdigest(),
        mapping_bytes=partition.mapping_bytes,
        mapping_sha256=partition.mapping_sha256,
        accepted_trace_bytes=partition.accepted_trace_bytes,
        accepted_trace_sha256=partition.accepted_trace_sha256,
        accepted_records=partition.accepted_records,
        accepted_groups=typed_groups,
        event_trace_bytes=event_trace_bytes,
        event_trace_sha256=hashlib.sha256(event_trace_bytes).hexdigest(),
    )


def validate_route_a_snap_trace(trace: RouteASnapTrace) -> RouteASnapTrace:
    """Rebuild all typed semantic groups and canonical bytes from accepted records."""

    if type(trace) is not RouteASnapTrace:
        raise TypeError("trace must be an exact RouteASnapTrace")
    partition = RouteASnapPartitionTransform(
        partition=trace.partition,
        raw_object_sha256=trace.raw_object_sha256,
        mapping_prefix_identity_sha256="0" * 64,
        ordered_row_identities=(),
        ordered_column_identities=(),
        ordered_reserved_column_identities=(),
        mapping_bytes=trace.mapping_bytes,
        mapping_sha256=trace.mapping_sha256,
        accepted_records=trace.accepted_records,
        accepted_trace_bytes=trace.accepted_trace_bytes,
        accepted_trace_sha256=trace.accepted_trace_sha256,
    )
    expected = build_route_a_snap_trace(partition, semantics=trace.semantics)
    if trace != expected:
        raise RouteASnapError("SNAP typed trace differs from its canonical derived bytes")
    if (
        hashlib.sha256(trace.mapping_bytes).hexdigest() != trace.mapping_sha256
        or hashlib.sha256(trace.accepted_trace_bytes).hexdigest()
        != trace.accepted_trace_sha256
        or trace.accepted_trace_bytes
        != _accepted_trace_bytes(
            partition=trace.partition,
            raw_object_sha256=trace.raw_object_sha256,
            mapping_sha256=trace.mapping_sha256,
            records=trace.accepted_records,
        )
    ):
        raise RouteASnapError("SNAP mapping or accepted trace digest changed")
    return trace


def route_a_snap_shard_identity(
    trace: RouteASnapTrace,
    *,
    experiment_source_sha: str,
    workflow_head_sha: str,
    compatibility_receipt_sha256: str,
    provider_run_id: int,
    provider_run_attempt: int,
    unit_attempt_ordinal: int,
) -> str:
    """Bind one SNAP semantic trace to its provider and follow-up attempt."""

    trace = validate_route_a_snap_trace(trace)
    if (
        re.fullmatch(r"[0-9a-f]{40}", experiment_source_sha) is None
        or re.fullmatch(r"[0-9a-f]{40}", workflow_head_sha) is None
        or re.fullmatch(r"[0-9a-f]{64}", compatibility_receipt_sha256) is None
        or type(provider_run_id) is not int
        or provider_run_id <= 0
        or provider_run_attempt != 1
        or unit_attempt_ordinal not in {0, 1}
    ):
        raise RouteASnapError("SNAP shard lineage is malformed")
    return hashlib.sha256(
        _canonical(
            {
                "compatibility_receipt_sha256": compatibility_receipt_sha256,
                "experiment_source_sha": experiment_source_sha,
                "formal_seed_or_null": None,
                "object_sha256_or_null": trace.raw_object_sha256,
                "partition_or_null": trace.partition,
                "provider_run_attempt": provider_run_attempt,
                "provider_run_id": provider_run_id,
                "scale_or_null": None,
                "schema_version": _SHARD_SCHEMA,
                "source_event_trace_sha256": trace.event_trace_sha256,
                "source_kind": "snap-a2q",
                "suite_role": "formal",
                "unit_attempt_ordinal": unit_attempt_ordinal,
                "workflow_head_sha": workflow_head_sha,
            }
        )
    ).hexdigest()
