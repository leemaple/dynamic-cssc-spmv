"""Deterministic one-day private handoffs for Route A synthetic replay."""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass

from dynamic_cssc.route_a_evaluation import RouteASyntheticCellRun
from dynamic_cssc.route_a_results import (
    canonical_route_a_document,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)

__all__ = (
    "RouteAArtifactError",
    "RouteASyntheticCellArchiveInspection",
    "inspect_route_a_synthetic_cell_archive",
    "produce_route_a_synthetic_cell_archive",
)

_ARCHIVE_SCHEMA = "dynamic-cssc-route-a-synthetic-cell-handoff-v2"
_MEMBER_PATHS = (
    "cell.json",
    "private/mask-ledger.sqlite3",
    "private/preparation-records.bin",
    "streams/consumption-receipts.jsonl",
    "streams/output-digests.jsonl",
    "streams/preparation-digests.jsonl",
    "streams/query-identities.jsonl",
    "window-trace.json",
)
_ALL_PATHS = (*_MEMBER_PATHS, "manifest.json")
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
_PREPARATION_FRAME_MAGIC = b"dynamic-cssc-route-a-private-preparations-v1\x00"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_ID = re.compile(r"v[0-9]{8}\Z")


class RouteAArtifactError(ValueError):
    """A Route A handoff is open, noncanonical, or internally inconsistent."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RouteAArtifactError("Route A archive JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAArtifactError(f"{label} is not ASCII JSON") from error
    if type(decoded) is not dict or canonical_route_a_document(decoded) != content:
        raise RouteAArtifactError(f"{label} is not one canonical object")
    return decoded


def _split_jsonl(content: bytes, *, label: str) -> tuple[bytes, ...]:
    if content and not content.endswith(b"\n"):
        raise RouteAArtifactError(f"{label} does not end at a JSONL boundary")
    documents = tuple(content.splitlines(keepends=True))
    for ordinal, document in enumerate(documents):
        _canonical_object(document, label=f"{label}[{ordinal}]")
    return documents


def _frame_private_preparations(documents: tuple[bytes, ...]) -> bytes:
    if type(documents) is not tuple or any(type(item) is not bytes for item in documents):
        raise RouteAArtifactError("private preparation records must be exact bytes")
    framed = bytearray(_PREPARATION_FRAME_MAGIC)
    framed.extend(len(documents).to_bytes(8, "big"))
    for document in documents:
        framed.extend(len(document).to_bytes(8, "big"))
        framed.extend(document)
    return bytes(framed)


def _unframe_private_preparations(content: bytes) -> tuple[bytes, ...]:
    if not content.startswith(_PREPARATION_FRAME_MAGIC):
        raise RouteAArtifactError("private preparation framing magic changed")
    cursor = len(_PREPARATION_FRAME_MAGIC)
    if len(content) < cursor + 8:
        raise RouteAArtifactError("private preparation framing is truncated")
    count = int.from_bytes(content[cursor : cursor + 8], "big")
    cursor += 8
    if count > 10_000_000:
        raise RouteAArtifactError("private preparation record count exceeds its bound")
    documents: list[bytes] = []
    for _ordinal in range(count):
        if len(content) < cursor + 8:
            raise RouteAArtifactError("private preparation length frame is truncated")
        length = int.from_bytes(content[cursor : cursor + 8], "big")
        cursor += 8
        if length > _MAX_MEMBER_BYTES or len(content) < cursor + length:
            raise RouteAArtifactError("private preparation record exceeds its frame")
        documents.append(content[cursor : cursor + length])
        cursor += length
    if cursor != len(content):
        raise RouteAArtifactError("private preparation framing has trailing bytes")
    return tuple(documents)


def _stream_documents(run: RouteASyntheticCellRun) -> dict[str, bytes]:
    return {
        "cell.json": run.cell.document_bytes,
        "private/mask-ledger.sqlite3": run.ledger_snapshot_bytes,
        "private/preparation-records.bin": _frame_private_preparations(
            run.private_preparation_documents
        ),
        "streams/consumption-receipts.jsonl": b"".join(
            run.consumption_receipt_documents
        ),
        "streams/output-digests.jsonl": b"".join(run.output_digest_documents),
        "streams/preparation-digests.jsonl": b"".join(
            run.preparation_digest_documents
        ),
        "streams/query-identities.jsonl": b"".join(run.query_identity_documents),
        "window-trace.json": run.window_trace_bytes,
    }


def _manifest(members: dict[str, bytes]) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "cell_sha256": hashlib.sha256(members["cell.json"]).hexdigest(),
            "formal_evidence": False,
            "handoff_role": "private-pre-replay-NON-EVIDENCE",
            "ledger_snapshot_sha256": hashlib.sha256(
                members["private/mask-ledger.sqlite3"]
            ).hexdigest(),
            "members": [
                {
                    "byte_count": len(members[path]),
                    "path": path,
                    "sha256": hashlib.sha256(members[path]).hexdigest(),
                }
                for path in _MEMBER_PATHS
            ],
            "private_preparation_bytes_included": True,
            "producer_timing_scope": (
                "candidate-result-assembly-plus-window-accounting-preparation-consumption-"
                "typed-execution-oracle-and-terminal-reconciliation-through-serialized-byte-"
                "accounting-before-cell-serialization"
            ),
            "retention_days": 1,
            "scratch_observation_scope": (
                "allocated-st_blocks-times-512-sampled-after-ledger-initialization-each-state-"
                "transition-query-preparation-query-consumption-and-terminal-ledger-closure"
            ),
            "schema_version": _ARCHIVE_SCHEMA,
            "window_trace_sha256": hashlib.sha256(
                members["window-trace.json"]
            ).hexdigest(),
        }
    )


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def produce_route_a_synthetic_cell_archive(run: RouteASyntheticCellRun) -> bytes:
    """Serialize one private, non-evidence producer handoff with stable ZIP bytes."""

    if type(run) is not RouteASyntheticCellRun:
        raise TypeError("run must be an exact RouteASyntheticCellRun")
    members = _stream_documents(run)
    members["manifest.json"] = _manifest(members)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in _ALL_PATHS:
            archive.writestr(_zip_info(path), members[path])
    content = buffer.getvalue()
    if len(content) > _MAX_ARCHIVE_BYTES:
        raise RouteAArtifactError("Route A cell handoff exceeds its closed byte bound")
    return content


def _archive_members(archive_bytes: bytes) -> dict[str, bytes]:
    if type(archive_bytes) is not bytes or not archive_bytes:
        raise RouteAArtifactError("Route A cell handoff must be nonempty bytes")
    if len(archive_bytes) > _MAX_ARCHIVE_BYTES:
        raise RouteAArtifactError("Route A cell handoff exceeds its closed byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if names != _ALL_PATHS or len(set(names)) != len(names):
                raise RouteAArtifactError(
                    "Route A cell handoff members are missing, extra, reordered, or repeated"
                )
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.file_size > _MAX_MEMBER_BYTES
                    or info.compress_type != zipfile.ZIP_STORED
                ):
                    raise RouteAArtifactError("Route A cell handoff member type is unsafe")
                content = archive.read(info)
                if len(content) != info.file_size:
                    raise RouteAArtifactError("Route A cell handoff member size changed")
                members[info.filename] = content
            return members
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, RouteAArtifactError):  # pragma: no cover - direct raises escape
            raise
        raise RouteAArtifactError("Route A cell handoff is not a readable ZIP") from error


def _closed_stream_document(
    content: bytes,
    *,
    schema: str,
    fields: frozenset[str],
    label: str,
) -> dict[str, object]:
    document = _canonical_object(content, label=label)
    if set(document) != fields or document.get("schema_version") != schema:
        raise RouteAArtifactError(f"{label} does not match its closed schema")
    return document


@dataclass(frozen=True, slots=True)
class RouteASyntheticCellArchiveInspection:
    cell_run: RouteASyntheticCellRun
    archive_sha256: str
    manifest_bytes: bytes


def inspect_route_a_synthetic_cell_archive(
    archive_bytes: bytes,
    *,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteASyntheticCellArchiveInspection:
    """Independently reconstruct and cross-check one private replay handoff."""

    members = _archive_members(archive_bytes)
    manifest = _canonical_object(members["manifest.json"], label="manifest")
    expected_manifest = _manifest({path: members[path] for path in _MEMBER_PATHS})
    if members["manifest.json"] != expected_manifest or manifest != _canonical_object(
        expected_manifest,
        label="expected manifest",
    ):
        raise RouteAArtifactError("Route A cell handoff manifest does not match its members")

    cell = validate_route_a_strategy_cell(
        _canonical_object(members["cell.json"], label="cell"),
        scientific_profile=scientific_profile,
    )
    window_trace = _canonical_object(members["window-trace.json"], label="window trace")
    if (
        manifest.get("schema_version") != _ARCHIVE_SCHEMA
        or manifest.get("authority_granted") is not False
        or manifest.get("formal_evidence") is not False
        or manifest.get("private_preparation_bytes_included") is not True
        or manifest.get("producer_timing_scope")
        != (
            "candidate-result-assembly-plus-window-accounting-preparation-consumption-"
            "typed-execution-oracle-and-terminal-reconciliation-through-serialized-byte-"
            "accounting-before-cell-serialization"
        )
        or manifest.get("handoff_role") != "private-pre-replay-NON-EVIDENCE"
        or manifest.get("retention_days") != 1
        or manifest.get("scratch_observation_scope")
        != (
            "allocated-st_blocks-times-512-sampled-after-ledger-initialization-each-state-"
            "transition-query-preparation-query-consumption-and-terminal-ledger-closure"
        )
        or manifest.get("ledger_snapshot_sha256")
        != hashlib.sha256(members["private/mask-ledger.sqlite3"]).hexdigest()
        or manifest.get("cell_sha256") != cell.sha256
        or manifest.get("window_trace_sha256")
        != hashlib.sha256(members["window-trace.json"]).hexdigest()
        or type(window_trace) is not dict
    ):
        raise RouteAArtifactError("Route A cell handoff authority or digest boundary changed")

    query_documents = _split_jsonl(
        members["streams/query-identities.jsonl"],
        label="query identities",
    )
    preparation_documents = _split_jsonl(
        members["streams/preparation-digests.jsonl"],
        label="preparation digests",
    )
    receipt_documents = _split_jsonl(
        members["streams/consumption-receipts.jsonl"],
        label="consumption receipts",
    )
    output_documents = _split_jsonl(
        members["streams/output-digests.jsonl"],
        label="output digests",
    )
    private_preparation_documents = _unframe_private_preparations(
        members["private/preparation-records.bin"]
    )
    query_count = cell.document["counts"]["queries"]
    if any(
        len(stream) != query_count
        for stream in (
            query_documents,
            preparation_documents,
            receipt_documents,
            output_documents,
            private_preparation_documents,
        )
    ):
        raise RouteAArtifactError("Route A cell handoff stream cardinality is incomplete")

    for ordinal, (query_bytes, preparation_bytes, receipt_bytes, output_bytes) in enumerate(
        zip(
            query_documents,
            preparation_documents,
            receipt_documents,
            output_documents,
            strict=True,
        )
    ):
        query = _closed_stream_document(
            query_bytes,
            schema="dynamic-cssc-route-a-query-id-v1",
            fields=frozenset(
                {
                    "evaluation_lane_identity_sha256",
                    "global_query_ordinal",
                    "schema_version",
                }
            ),
            label=f"query identity {ordinal}",
        )
        preparation = _closed_stream_document(
            preparation_bytes,
            schema="dynamic-cssc-route-a-preparation-digest-v1",
            fields=frozenset(
                {
                    "execution_binding_digest",
                    "query_id",
                    "query_preparation_sha256",
                    "schema_version",
                    "version_id",
                }
            ),
            label=f"preparation digest {ordinal}",
        )
        receipt = _closed_stream_document(
            receipt_bytes,
            schema="dynamic-cssc-route-a-consumption-receipt-v1",
            fields=frozenset(
                {
                    "consumed_exactly_once",
                    "execution_binding_digest",
                    "ledger_commitment_token",
                    "query_id",
                    "query_preparation_sha256",
                    "schema_version",
                    "version_id",
                }
            ),
            label=f"consumption receipt {ordinal}",
        )
        output = _closed_stream_document(
            output_bytes,
            schema="dynamic-cssc-route-a-output-digest-v1",
            fields=frozenset(
                {
                    "direct_output_sha256",
                    "query_id",
                    "schema_version",
                    "typed_output_sha256",
                }
            ),
            label=f"output digest {ordinal}",
        )
        query_id = hashlib.sha256(query_bytes).hexdigest()
        if (
            type(query.get("global_query_ordinal")) is not int
            or query["global_query_ordinal"] != ordinal
            or type(query.get("evaluation_lane_identity_sha256")) is not str
            or _LOWER_SHA256.fullmatch(query["evaluation_lane_identity_sha256"])
            is None
            or type(preparation.get("query_id")) is not str
            or _LOWER_SHA256.fullmatch(preparation["query_id"]) is None
            or type(preparation.get("query_preparation_sha256")) is not str
            or _LOWER_SHA256.fullmatch(preparation["query_preparation_sha256"])
            is None
            or type(preparation.get("execution_binding_digest")) is not str
            or _LOWER_SHA256.fullmatch(preparation["execution_binding_digest"])
            is None
            or type(preparation.get("version_id")) is not str
            or _VERSION_ID.fullmatch(preparation["version_id"]) is None
            or type(receipt.get("ledger_commitment_token")) is not str
            or _LOWER_SHA256.fullmatch(receipt["ledger_commitment_token"]) is None
            or type(output.get("typed_output_sha256")) is not str
            or _LOWER_SHA256.fullmatch(output["typed_output_sha256"]) is None
            or type(output.get("direct_output_sha256")) is not str
            or _LOWER_SHA256.fullmatch(output["direct_output_sha256"]) is None
            or preparation["query_id"] != query_id
            or receipt["query_id"] != query_id
            or output["query_id"] != query_id
            or receipt["consumed_exactly_once"] is not True
            or receipt["query_preparation_sha256"]
            != preparation["query_preparation_sha256"]
            or receipt["execution_binding_digest"]
            != preparation["execution_binding_digest"]
            or receipt["version_id"] != preparation["version_id"]
            or output["typed_output_sha256"] != output["direct_output_sha256"]
        ):
            raise RouteAArtifactError("Route A cell handoff query binding is inconsistent")

    scratch = cell.document["measurements"]["scratch_allocated_bytes"]
    if type(scratch) is not int:
        raise RouteAArtifactError("direct Route A cell lacks its scratch observation")
    run = RouteASyntheticCellRun(
        cell=cell,
        window_trace_bytes=members["window-trace.json"],
        window_trace_sha256=hashlib.sha256(members["window-trace.json"]).hexdigest(),
        query_identity_documents=query_documents,
        preparation_digest_documents=preparation_documents,
        consumption_receipt_documents=receipt_documents,
        output_digest_documents=output_documents,
        private_preparation_documents=private_preparation_documents,
        ledger_snapshot_bytes=members["private/mask-ledger.sqlite3"],
        ledger_snapshot_sha256=hashlib.sha256(
            members["private/mask-ledger.sqlite3"]
        ).hexdigest(),
        scratch_high_water_bytes=scratch,
    )
    return RouteASyntheticCellArchiveInspection(
        cell_run=run,
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        manifest_bytes=members["manifest.json"],
    )
