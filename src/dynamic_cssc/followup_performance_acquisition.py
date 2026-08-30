"""Two-download SNAP acquisition artifacts without redistributed raw bytes."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.followup_performance_artifacts import (
    _direct_directory,
    _tree_rows,
)
from dynamic_cssc.followup_performance_campaign import (
    followup_campaign_artifact_binding_scope,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
    _issue_followup_inner_admission,
    _parse_ascii_json,
    build_followup_unit_identity,
    followup_artifact_name,
    followup_inherited_unit_attempt_ordinal,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)
from dynamic_cssc.followup_performance_formal_artifacts import _write_new
from dynamic_cssc.route_a_snap import (
    RouteASnapPartitionTransform,
    RouteASnapTrace,
    RouteASnapTransform,
    build_route_a_snap_trace,
    decode_route_a_snap_partition,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FOLLOWUP_SNAP_SOURCE_URL",
    "FollowupAcquisitionArtifactError",
    "FollowupAcquisitionInspection",
    "FollowupAcquisitionProviderBinding",
    "RouteASnapAcquisitionReceipt",
    "build_route_a_snap_acquisition_receipt",
    "build_followup_acquisition_provider_binding",
    "guard_and_produce_followup_acquisition_artifact",
    "inspect_followup_acquisition_artifact",
    "produce_followup_acquisition_handoff",
)

FOLLOWUP_SNAP_SOURCE_URL = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
FollowupAcquisitionPhase = Literal["private-handoff", "guarded-final"]

_RECEIPT_SCHEMA = "dynamic-cssc-route-a-snap-acquisition-receipt-v2"
_MANIFEST_SCHEMA = "dynamic-cssc-followup-performance-acquisition-inner-tree-v1"
_STATS_SCHEMA = "dynamic-cssc-followup-performance-snap-transform-statistics-v1"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)
_RECEIPT_FIELDS = {
    "compressed_byte_count",
    "compressed_sha256",
    "final_url",
    "http_status",
    "requested_url",
    "response_headers",
    "retrieved_utc",
    "schema_version",
    "unit_attempt_ordinal",
}
_HEADER_FIELDS = {"content-length", "content-type", "etag", "last-modified"}
_MAX_WRAPPER_BYTES = 4 * 1024 * 1024
_MAX_DERIVED_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_PARTITION_FILES = tuple(
    f"partition-{partition}/{name}"
    for partition in (0, 1)
    for name in ("mapping.json", "accepted-trace.json", "semantic-T1.json", "semantic-T2.json")
)


class FollowupAcquisitionArtifactError(FollowupContractError):
    """One acquisition receipt, transform, or outer artifact failed closed."""


def _sha256_file(path: Path) -> tuple[str, int]:
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
        raise FollowupAcquisitionArtifactError("downloaded SNAP object changed while hashed")
    return digest.hexdigest(), total


def _stable_read_owned(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise FollowupAcquisitionArtifactError(
                "acquisition member is not one bounded owned file"
            )
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        projection = lambda value: (  # noqa: E731 - stable stat projection
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or projection(before) != projection(after)
        ):
            raise FollowupAcquisitionArtifactError(
                "acquisition member changed while read"
            )
        return bytes(content)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class RouteASnapAcquisitionReceipt:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str

    @property
    def compressed_sha256(self) -> str:
        return self.document["compressed_sha256"]  # type: ignore[return-value]

    @property
    def compressed_byte_count(self) -> int:
        return self.document["compressed_byte_count"]  # type: ignore[return-value]


def _receipt_from_bytes(content: bytes) -> RouteASnapAcquisitionReceipt:
    value = _parse_ascii_json(content, label="SNAP acquisition receipt")
    if type(value) is not dict:
        raise FollowupAcquisitionArtifactError("SNAP acquisition receipt is not an object")
    headers = value.get("response_headers")
    if (
        set(value) != _RECEIPT_FIELDS
        or value.get("schema_version") != _RECEIPT_SCHEMA
        or value.get("unit_attempt_ordinal") not in {0, 1}
        or value.get("requested_url") != FOLLOWUP_SNAP_SOURCE_URL
        or value.get("final_url") != FOLLOWUP_SNAP_SOURCE_URL
        or value.get("http_status") != 200
        or type(value.get("retrieved_utc")) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            value["retrieved_utc"],
        )
        is None
        or type(value.get("compressed_byte_count")) is not int
        or value["compressed_byte_count"] <= 0
        or type(value.get("compressed_sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", value["compressed_sha256"]) is None
        or type(headers) is not dict
        or set(headers) != _HEADER_FIELDS
        or any(item is not None and type(item) is not str for item in headers.values())
        or _canonical_json_bytes(value) != content
    ):
        raise FollowupAcquisitionArtifactError("SNAP acquisition receipt schema changed")
    return RouteASnapAcquisitionReceipt(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_route_a_snap_acquisition_receipt(
    raw_object_path: Path,
    *,
    unit_attempt_ordinal: int,
    final_url: str,
    retrieved_utc: str,
    response_headers: dict[str, str | None],
) -> RouteASnapAcquisitionReceipt:
    """Hash one complete response body into the frozen receipt byte domain."""

    if type(unit_attempt_ordinal) is not int or unit_attempt_ordinal not in {0, 1}:
        raise FollowupAcquisitionArtifactError("acquisition inner attempt must be 0 or 1")
    if not isinstance(raw_object_path, Path) or not raw_object_path.is_absolute():
        raise TypeError("raw_object_path must be an absolute pathlib.Path")
    try:
        observed = raw_object_path.lstat()
    except OSError as error:
        raise FollowupAcquisitionArtifactError("downloaded SNAP object is unavailable") from error
    if raw_object_path.is_symlink() or not raw_object_path.is_file() or observed.st_nlink != 1:
        raise FollowupAcquisitionArtifactError("downloaded SNAP object is not one owned file")
    sha256, byte_count = _sha256_file(raw_object_path)
    content = _canonical_json_bytes(
        {
            "compressed_byte_count": byte_count,
            "compressed_sha256": sha256,
            "final_url": final_url,
            "http_status": 200,
            "requested_url": FOLLOWUP_SNAP_SOURCE_URL,
            "response_headers": response_headers,
            "retrieved_utc": retrieved_utc,
            "schema_version": _RECEIPT_SCHEMA,
            "unit_attempt_ordinal": unit_attempt_ordinal,
        }
    )
    return _receipt_from_bytes(content)


def _phase_files(phase: FollowupAcquisitionPhase) -> tuple[str, ...]:
    if phase == "private-handoff":
        return (
            "producer-acquisition-receipt.json",
            "transform-statistics.json",
            *_PARTITION_FILES,
        )
    if phase == "guarded-final":
        return (
            "producer-acquisition-receipt.json",
            "guard-acquisition-receipt.json",
            "transform-statistics.json",
            *_PARTITION_FILES,
        )
    raise FollowupAcquisitionArtifactError("acquisition phase is outside its domain")


def _partition_payloads(
    transform: RouteASnapTransform,
) -> tuple[dict[str, bytes], tuple[RouteASnapTrace, ...]]:
    if type(transform) is not RouteASnapTransform:
        raise TypeError("transform must be an exact RouteASnapTransform")
    if (
        transform.source_url != FOLLOWUP_SNAP_SOURCE_URL
        or tuple(item.partition for item in transform.partitions) != (0, 1)
    ):
        raise FollowupAcquisitionArtifactError("SNAP transform source or partitions changed")
    payloads: dict[str, bytes] = {}
    traces: list[RouteASnapTrace] = []
    for partition in transform.partitions:
        prefix = f"partition-{partition.partition}"
        payloads[f"{prefix}/mapping.json"] = partition.mapping_bytes
        payloads[f"{prefix}/accepted-trace.json"] = partition.accepted_trace_bytes
        for semantics in ("T1", "T2"):
            trace = build_route_a_snap_trace(partition, semantics=semantics)
            payloads[f"{prefix}/semantic-{semantics}.json"] = trace.event_trace_bytes
            traces.append(trace)
    payloads["transform-statistics.json"] = _canonical_json_bytes(
        {
            "parsing_counts": transform.parsing_counts,
            "raw_object_byte_count": transform.raw_object_byte_count,
            "raw_object_sha256": transform.raw_object_sha256,
            "schema_version": _STATS_SCHEMA,
            "source_url": transform.source_url,
        }
    )
    return payloads, tuple(traces)


def _tree_manifest(
    *,
    phase: FollowupAcquisitionPhase,
    rows: tuple[dict[str, object], ...],
    transform: RouteASnapTransform,
    producer_receipt: RouteASnapAcquisitionReceipt,
    guard_receipt: RouteASnapAcquisitionReceipt | None,
) -> bytes:
    rows_bytes = _canonical_json_bytes(list(rows))
    return _canonical_json_bytes(
        {
            "authority": False,
            "files": list(rows),
            "files_sha256": hashlib.sha256(rows_bytes).hexdigest(),
            "formal_evidence_candidate": phase == "guarded-final",
            "guard_receipt_sha256_or_null": (
                None if guard_receipt is None else guard_receipt.sha256
            ),
            "producer_receipt_sha256": producer_receipt.sha256,
            "publication_evidence_admitted": False,
            "raw_object_byte_count": transform.raw_object_byte_count,
            "raw_object_sha256": transform.raw_object_sha256,
            "raw_source_bytes_included": False,
            "schema_version": _MANIFEST_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
            "unit_phase": phase,
        }
    )


def _identity(
    *,
    phase: FollowupAcquisitionPhase,
    lineage: RouteASyntheticSuiteLineage,
    transform: RouteASnapTransform,
    unit_attempt_ordinal: int,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
) -> tuple[bytes, str]:
    inherited_attempt = followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-acquisition",
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    scope = {
        "accepted_trace_sha256s": [
            partition.accepted_trace_sha256 for partition in transform.partitions
        ],
        "artifact_phase": phase,
        "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
        "evidence_freeze_S2_sha": lineage.workflow_head_sha,
        "experiment_source_S1_sha": lineage.experiment_source_sha,
        "inherited_unit_attempt_ordinal": inherited_attempt,
        "mapping_sha256s": [
            partition.mapping_sha256 for partition in transform.partitions
        ],
        "provider_run_attempt": lineage.provider_run_attempt,
        "provider_run_id": lineage.provider_run_id,
        "raw_object_sha256": transform.raw_object_sha256,
        "source_url": FOLLOWUP_SNAP_SOURCE_URL,
    }
    scope.update(
        followup_campaign_artifact_binding_scope(
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
        )
    )
    return build_followup_unit_identity(
        unit_kind="formal-acquisition",
        unit_attempt_ordinal=unit_attempt_ordinal,
        scope=scope,
    )


def _checksums(contents: dict[str, bytes]) -> bytes:
    return b"".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n".encode("ascii")
        for name in _WRAPPER_FILES
    )


def _write_inner_tree(root: Path, payloads: dict[str, bytes]) -> None:
    for relative in sorted(payloads):
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_new(path, payloads[relative])


def _transform_from_inner(
    inner: Path,
    *,
    producer_receipt: RouteASnapAcquisitionReceipt,
) -> tuple[RouteASnapTransform, tuple[RouteASnapTrace, ...]]:
    stats_value = _parse_ascii_json(
        _stable_read_owned(
            inner / "transform-statistics.json",
            maximum=_MAX_WRAPPER_BYTES,
        ),
        label="SNAP transform statistics",
    )
    if type(stats_value) is not dict:
        raise FollowupAcquisitionArtifactError("SNAP transform statistics is not an object")
    parsing_counts = stats_value.get("parsing_counts")
    if (
        set(stats_value)
        != {
            "parsing_counts",
            "raw_object_byte_count",
            "raw_object_sha256",
            "schema_version",
            "source_url",
        }
        or stats_value.get("schema_version") != _STATS_SCHEMA
        or stats_value.get("source_url") != FOLLOWUP_SNAP_SOURCE_URL
        or stats_value.get("raw_object_sha256") != producer_receipt.compressed_sha256
        or stats_value.get("raw_object_byte_count")
        != producer_receipt.compressed_byte_count
        or type(parsing_counts) is not dict
        or set(parsing_counts)
        != {"blank", "comment", "eligible", "malformed", "physical_records", "self_loop"}
        or any(type(value) is not int or value < 0 for value in parsing_counts.values())
        or parsing_counts["physical_records"]
        != sum(
            parsing_counts[field]
            for field in ("blank", "comment", "eligible", "malformed", "self_loop")
        )
    ):
        raise FollowupAcquisitionArtifactError("SNAP transform statistics changed")
    partitions: list[RouteASnapPartitionTransform] = []
    traces: list[RouteASnapTrace] = []
    for partition in (0, 1):
        prefix = inner / f"partition-{partition}"
        mapping = _stable_read_owned(
            prefix / "mapping.json",
            maximum=_MAX_DERIVED_MEMBER_BYTES,
        )
        accepted = _stable_read_owned(
            prefix / "accepted-trace.json",
            maximum=_MAX_DERIVED_MEMBER_BYTES,
        )
        decoded = decode_route_a_snap_partition(mapping, accepted)
        if decoded.partition != partition:
            raise FollowupAcquisitionArtifactError("acquisition partition identity changed")
        partitions.append(decoded)
        for semantics in ("T1", "T2"):
            trace = build_route_a_snap_trace(decoded, semantics=semantics)
            if _stable_read_owned(
                prefix / f"semantic-{semantics}.json",
                maximum=_MAX_DERIVED_MEMBER_BYTES,
            ) != trace.event_trace_bytes:
                raise FollowupAcquisitionArtifactError(
                    "acquisition semantic trace differs from its exact transform"
                )
            traces.append(trace)
    if any(
        partition.raw_object_sha256 != producer_receipt.compressed_sha256
        for partition in partitions
    ):
        raise FollowupAcquisitionArtifactError("acquisition raw-object digest bridge changed")
    transform = RouteASnapTransform(
        raw_object_sha256=producer_receipt.compressed_sha256,
        raw_object_byte_count=producer_receipt.compressed_byte_count,
        source_url=FOLLOWUP_SNAP_SOURCE_URL,
        parsing_counts=dict(parsing_counts),
        partitions=(partitions[0], partitions[1]),
    )
    return transform, tuple(traces)


@dataclass(frozen=True, slots=True)
class FollowupAcquisitionInspection:
    phase: FollowupAcquisitionPhase
    artifact_name: str
    root: Path
    inner_directory: Path
    producer_receipt: RouteASnapAcquisitionReceipt
    guard_receipt: RouteASnapAcquisitionReceipt | None
    transform: RouteASnapTransform
    traces: tuple[RouteASnapTrace, ...]
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope


@dataclass(frozen=True, slots=True)
class FollowupAcquisitionProviderBinding:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def build_followup_acquisition_provider_binding(
    inspection: FollowupAcquisitionInspection,
    *,
    artifact_id: int,
    artifact_provider_digest: str,
) -> FollowupAcquisitionProviderBinding:
    """Bind ordered units to the exact admitted acquisition provider object."""

    if (
        type(inspection) is not FollowupAcquisitionInspection
        or inspection.phase != "guarded-final"
        or type(artifact_id) is not int
        or artifact_id <= 0
        or type(artifact_provider_digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_provider_digest) is None
    ):
        raise FollowupAcquisitionArtifactError(
            "acquisition provider binding identity changed"
        )
    document = {
        "artifact_id": artifact_id,
        "artifact_name": inspection.artifact_name,
        "artifact_provider_digest": artifact_provider_digest,
        "authority": False,
        "publication_evidence_admitted": False,
        "schema_version": (
            "dynamic-cssc-followup-performance-acquisition-provider-binding-v1"
        ),
        "study_id": FOLLOWUP_STUDY_ID,
        "unit_identity_sha256": inspection.unit_identity_sha256,
        "unit_output_envelope_sha256": inspection.envelope.sha256,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupAcquisitionProviderBinding(
        document=document,
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
    )


def inspect_followup_acquisition_artifact(
    artifact_directory: Path,
    *,
    phase: FollowupAcquisitionPhase,
    lineage: RouteASyntheticSuiteLineage,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
) -> FollowupAcquisitionInspection:
    """Rehash and reconstruct one acquisition object without any raw source bytes."""

    artifact_directory = _direct_directory(
        artifact_directory,
        label="follow-up acquisition artifact",
    )
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    if set(entries) != {*_WRAPPER_FILES, "checksums.sha256", "inner"}:
        raise FollowupAcquisitionArtifactError("acquisition wrapper members changed")
    inner = _direct_directory(entries["inner"], label="acquisition derived inner tree")
    observed_inner_paths = {
        path.relative_to(inner).as_posix() for path in inner.rglob("*") if path.is_file()
    }
    if observed_inner_paths != set(_phase_files(phase)):
        raise FollowupAcquisitionArtifactError("acquisition derived member set changed")
    contents = {
        name: _stable_read_owned(entries[name], maximum=_MAX_WRAPPER_BYTES)
        for name in _WRAPPER_FILES
    }
    if _stable_read_owned(
        entries["checksums.sha256"], maximum=_MAX_WRAPPER_BYTES
    ) != _checksums(contents):
        raise FollowupAcquisitionArtifactError("acquisition wrapper checksums changed")
    producer_receipt = _receipt_from_bytes(
        _stable_read_owned(
            inner / "producer-acquisition-receipt.json",
            maximum=_MAX_WRAPPER_BYTES,
        )
    )
    guard_receipt = (
        None
        if phase == "private-handoff"
        else _receipt_from_bytes(
            _stable_read_owned(
                inner / "guard-acquisition-receipt.json",
                maximum=_MAX_WRAPPER_BYTES,
            )
        )
    )
    inherited_attempt = followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-acquisition",
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    if (
        producer_receipt.document["unit_attempt_ordinal"] != inherited_attempt
        or (
            guard_receipt is not None
            and (
                guard_receipt.document["unit_attempt_ordinal"] != inherited_attempt
                or guard_receipt.compressed_sha256 != producer_receipt.compressed_sha256
                or guard_receipt.compressed_byte_count
                != producer_receipt.compressed_byte_count
            )
        )
    ):
        raise FollowupAcquisitionArtifactError("acquisition attempt or second download changed")
    transform, traces = _transform_from_inner(
        inner,
        producer_receipt=producer_receipt,
    )
    rows = _tree_rows(inner)
    manifest_bytes = _tree_manifest(
        phase=phase,
        rows=rows,
        transform=transform,
        producer_receipt=producer_receipt,
        guard_receipt=guard_receipt,
    )
    if contents["inner-payload.json"] != manifest_bytes:
        raise FollowupAcquisitionArtifactError("acquisition inner manifest changed")
    unit_bytes, unit_sha256 = _identity(
        phase=phase,
        lineage=lineage,
        transform=transform,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupAcquisitionArtifactError("acquisition unit identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != "formal-acquisition"
        or envelope.document["inner_role"] != "formal-acquisition"
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != unit_attempt_ordinal
    ):
        raise FollowupAcquisitionArtifactError("acquisition outer envelope changed")
    return FollowupAcquisitionInspection(
        phase=phase,
        artifact_name=followup_artifact_name(
            unit_kind="formal-acquisition",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
        root=artifact_directory,
        inner_directory=inner,
        producer_receipt=producer_receipt,
        guard_receipt=guard_receipt,
        transform=transform,
        traces=traces,
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
    )


def _produce(
    output_directory: Path,
    *,
    phase: FollowupAcquisitionPhase,
    lineage: RouteASyntheticSuiteLineage,
    transform: RouteASnapTransform,
    producer_receipt: RouteASnapAcquisitionReceipt,
    guard_receipt: RouteASnapAcquisitionReceipt | None,
    unit_attempt_ordinal: int,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
) -> FollowupAcquisitionInspection:
    _direct_directory(output_directory.parent, label="acquisition output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupAcquisitionArtifactError("acquisition output already exists")
    if (
        transform.raw_object_sha256 != producer_receipt.compressed_sha256
        or transform.raw_object_byte_count != producer_receipt.compressed_byte_count
        or (phase == "private-handoff") != (guard_receipt is None)
    ):
        raise FollowupAcquisitionArtifactError("acquisition receipt and transform changed")
    payloads, _traces = _partition_payloads(transform)
    payloads["producer-acquisition-receipt.json"] = producer_receipt.document_bytes
    if guard_receipt is not None:
        if (
            guard_receipt.compressed_sha256 != producer_receipt.compressed_sha256
            or guard_receipt.compressed_byte_count != producer_receipt.compressed_byte_count
        ):
            raise FollowupAcquisitionArtifactError("acquisition second download differs")
        payloads["guard-acquisition-receipt.json"] = guard_receipt.document_bytes
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    try:
        inner = temporary / "inner"
        inner.mkdir(mode=0o700)
        _write_inner_tree(inner, payloads)
        rows = _tree_rows(inner)
        manifest_bytes = _tree_manifest(
            phase=phase,
            rows=rows,
            transform=transform,
            producer_receipt=producer_receipt,
            guard_receipt=guard_receipt,
        )
        unit_bytes, unit_sha256 = _identity(
            phase=phase,
            lineage=lineage,
            transform=transform,
            unit_attempt_ordinal=unit_attempt_ordinal,
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
        )
        admission = _issue_followup_inner_admission(
            inner_role="formal-acquisition",
            inner_bytes=manifest_bytes,
        )
        envelope = seal_followup_inner_payload(
            admission,
            experiment_source_s1_sha=lineage.experiment_source_sha,
            evidence_freeze_s2_sha=lineage.workflow_head_sha,
            unit_kind="formal-acquisition",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
        contents = {
            "inner-payload.json": manifest_bytes,
            "outer-envelope.json": envelope.document_bytes,
            "unit-identity.json": unit_bytes,
        }
        for name in _WRAPPER_FILES:
            _write_new(temporary / name, contents[name])
        _write_new(temporary / "checksums.sha256", _checksums(contents))
        os.replace(temporary, output_directory)
        return inspect_followup_acquisition_artifact(
            output_directory,
            phase=phase,
            lineage=lineage,
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise


def produce_followup_acquisition_handoff(
    transform: RouteASnapTransform,
    producer_receipt: RouteASnapAcquisitionReceipt,
    output_directory: Path,
    *,
    lineage: RouteASyntheticSuiteLineage,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
) -> FollowupAcquisitionInspection:
    """Produce the one-day non-evidence acquisition handoff without raw bytes."""

    return _produce(
        output_directory,
        phase="private-handoff",
        lineage=lineage,
        transform=transform,
        producer_receipt=producer_receipt,
        guard_receipt=None,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )


def guard_and_produce_followup_acquisition_artifact(
    producer_artifact_directory: Path,
    guard_transform: RouteASnapTransform,
    guard_receipt: RouteASnapAcquisitionReceipt,
    output_directory: Path,
    *,
    lineage: RouteASyntheticSuiteLineage,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    unit_attempt_ordinal: int = 1,
) -> FollowupAcquisitionInspection:
    """Compare an independent second download/transform and emit one candidate."""

    producer = inspect_followup_acquisition_artifact(
        producer_artifact_directory,
        phase="private-handoff",
        lineage=lineage,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    producer_payloads, _producer_traces = _partition_payloads(producer.transform)
    guard_payloads, _guard_traces = _partition_payloads(guard_transform)
    if (
        guard_receipt.compressed_sha256 != producer.producer_receipt.compressed_sha256
        or guard_receipt.compressed_byte_count
        != producer.producer_receipt.compressed_byte_count
        or producer_payloads != guard_payloads
    ):
        raise FollowupAcquisitionArtifactError(
            "independent acquisition download or transform differs from producer"
        )
    return _produce(
        output_directory,
        phase="guarded-final",
        lineage=lineage,
        transform=guard_transform,
        producer_receipt=producer.producer_receipt,
        guard_receipt=guard_receipt,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
    )
