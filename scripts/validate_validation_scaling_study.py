#!/usr/bin/env python3
"""Independent decoder, exact analysis, and aggregate audit for the study."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from fractions import Fraction
from pathlib import Path
from typing import Literal

from dynamic_cssc.route_a_artifacts import inspect_route_a_synthetic_cell_archive
from dynamic_cssc.route_a_replay import RouteASyntheticCellTarget
from dynamic_cssc.route_a_results import (
    canonical_route_a_document,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

_STUDY_ID = "dynamic-cssc-validation-scaling-2026-09-01"
_PLAN_SHA256 = "337de174c6cc445fe9ab54c64dda74b0e9fb6d070e7b5478e09def8940a3b712"
_MACHINE_PLAN_SHA256 = "ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c"
_SOURCE_TAG = "validation-scaling-source-v2"
_PAYLOAD_SCHEMA = "dynamic-cssc-validation-scaling-seed-payload-v1"
_RECEIPT_SCHEMA = "dynamic-cssc-validation-scaling-execution-receipt-v1"
_BINDING_SCHEMA = "dynamic-cssc-validation-scaling-producer-binding-v1"
_AGGREGATE_SCHEMA = "dynamic-cssc-validation-scaling-aggregate-v1"
_STRATEGIES = (
    "periodic-repack/windows=1",
    "padding-reuse",
    "packed-coo-cloud-segmented-delta/segment-width=128",
)
_RHOS = ("1/100", "1/10", "1")
_QUERY_COUNTS = {"1/100": 5, "1/10": 51, "1": 512}
_STRATEGY_ORDERS = (
    _STRATEGIES,
    (_STRATEGIES[1], _STRATEGIES[2], _STRATEGIES[0]),
    (_STRATEGIES[2], _STRATEGIES[0], _STRATEGIES[1]),
)
_RHO_ORDERS = (
    _RHOS,
    (_RHOS[1], _RHOS[2], _RHOS[0]),
    (_RHOS[2], _RHOS[0], _RHOS[1]),
)
_SEMANTIC_FIELDS = (
    "schema_version",
    "identity",
    "evaluation",
    "counts",
    "window_query_counts",
    "primitive_counts",
    "rotation_inventory",
    "serialized_object_multiplicities",
    "serialized_bytes",
    "correctness",
    "bindings",
)
_CELL_ROW_FIELDS = (
    "strategy_candidate_id",
    "rho",
    "formal_seed",
    "seed_ordinal",
    "role",
    "query_count",
    "compile_query_call_count",
    "operation_wall_nanoseconds",
    "operation_process_nanoseconds",
    "producer_cell_archive_wall_nanoseconds_or_null",
    "producer_cell_archive_process_nanoseconds_or_null",
    "producer_state_transition_nanoseconds_or_null",
    "producer_result_assembly_nanoseconds_or_null",
    "replay_elapsed_nanoseconds_or_null",
    "semantic_projection_sha256",
    "source_trace_sha256",
    "machine_plan_sha256",
)
_RECEIPT_FIELDS = (
    "schema_version",
    "artifact_role",
    "seed_ordinal",
    "runner_os",
    "runner_arch",
    "python_version",
    "github_run_id",
    "github_run_attempt",
    "github_job",
    "source_git_sha",
    "operation_started_utc",
    "package_finished_utc",
    "seed_package_wall_nanoseconds",
    "seed_package_process_nanoseconds",
    "process_peak_rss_bytes_or_null",
    "payload_filename",
    "payload_byte_count",
    "payload_sha256",
)
_MANIFEST_FIELDS = (
    "schema_version",
    "study_id",
    "artifact_role",
    "seed_ordinal",
    "formal_seed",
    "scale",
    "stage0_plan_sha256",
    "source_tag",
    "source_trace_sha256",
    "machine_plan_sha256",
    "cell_count",
    "cell_order",
    "member_count",
    "members",
    "retention_days",
    "private_material_included",
    "producer_payload_sha256_or_null",
    "claim_scope",
    "formal_authority_granted",
)
_BINDING_FIELDS = (
    "schema_version",
    "producer_payload_sha256",
    "producer_cell_archive_sha256",
    "producer_cell_archive_byte_count",
    "producer_cell_sha256",
    "producer_semantic_projection_sha256",
    "producer_timing_row_sha256",
)
_ROUTE_A_REPLAY_RECEIPT_FIELDS = {
    "deterministic_accounting_equal",
    "final_cell_sha256",
    "expected_target_sha256",
    "formal_authority_granted",
    "independent_oracle_equality",
    "independent_replay_cell_sha256",
    "machine_plan_sha256",
    "ledger_snapshot_read_only_verified",
    "producer_archive_sha256",
    "producer_cell_sha256",
    "producer_ledger_root",
    "producer_ledger_snapshot_sha256",
    "producer_output_digest_root",
    "producer_prepared_query_root",
    "publication_evidence",
    "replay_elapsed_seconds",
    "replay_ledger_root",
    "replay_ledger_snapshot_sha256",
    "replay_output_digest_root",
    "replay_prepared_query_root",
    "replay_timing_scope",
    "schema_version",
    "source_event_trace_sha256",
    "window_trace_sha256",
}
_AGGREGATE_PATHS = (
    "closed-cell-table.json",
    "compile-semantic-verdicts.json",
    "timing-summaries.json",
    "ols-records.json",
    "provider-observations.json",
    "input-artifacts.json",
    "human-renderings.json",
    "manifest.json",
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_EXECUTION_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z"
)
_PROVIDER_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
_MAX_PAYLOAD_BYTES = 18 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class ValidationScalingEvidenceError(ValueError):
    """Evidence is incomplete, noncanonical, retargeted, or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class ProviderArtifactMetadata:
    artifact_id: int
    name: str
    size_in_bytes: int
    digest: str


@dataclass(frozen=True, slots=True)
class SeedEvidence:
    role: Literal["producer", "independent-replay"]
    seed_ordinal: int
    payload_bytes: bytes
    payload_sha256: str
    receipt_bytes: bytes
    receipt: dict[str, object]
    rows: tuple[dict[str, object], ...]
    row_bytes: tuple[bytes, ...]
    semantic_bytes: tuple[bytes, ...]
    cell_bytes: tuple[bytes, ...]
    private_archive_bytes: tuple[bytes, ...]
    binding_bytes: tuple[bytes, ...]
    metadata: ProviderArtifactMetadata


@dataclass(frozen=True, slots=True)
class _ValidationEvidenceDomain:
    profile: RouteAScientificProfile
    formal_seeds: tuple[int, int, int]
    plan_sha256: str


def _scientific_values() -> tuple[tuple[int, int, int], int]:
    path = Path(__file__).resolve(strict=True).parents[1] / "config/validation-scaling-study.json"
    content = _direct_file(path, label="Stage-0 v2 plan")
    if hashlib.sha256(content).hexdigest() != _PLAN_SHA256:
        raise ValidationScalingEvidenceError("Stage-0 v2 plan digest changed")
    try:
        plan = json.loads(content.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationScalingEvidenceError("Stage-0 v2 plan is not exact ASCII JSON") from error
    if type(plan) is not dict or type(plan.get("matrix")) is not dict:
        raise ValidationScalingEvidenceError("Stage-0 v2 matrix is not one object")
    matrix = plan["matrix"]
    assert type(matrix) is dict
    records = matrix.get("formal_seeds")
    query_vector_seed = matrix.get("query_vector_seed")
    if type(records) is not list or len(records) != 3:
        raise ValidationScalingEvidenceError("Stage-0 v2 formal seed matrix changed")
    seeds: list[int] = []
    for expected_ordinal, record in enumerate(records, start=1):
        if (
            type(record) is not dict
            or record.get("ordinal") != expected_ordinal
            or type(record.get("seed")) is not int
            or record["seed"] < 0
        ):
            raise ValidationScalingEvidenceError("Stage-0 v2 formal seed record changed")
        seeds.append(record["seed"])
    if (
        type(query_vector_seed) is not int
        or query_vector_seed < 0
        or len(set(seeds)) != 3
        or query_vector_seed in seeds
    ):
        raise ValidationScalingEvidenceError("Stage-0 v2 scientific seed domain changed")
    return (seeds[0], seeds[1], seeds[2]), query_vector_seed


def _production_evidence_domain() -> _ValidationEvidenceDomain:
    formal_seeds, query_vector_seed = _scientific_values()
    qualification_seed = int.from_bytes(
        hashlib.sha256(f"{_STUDY_ID}|unused-qualification".encode("ascii")).digest()[:4],
        "big",
    ) & 0x7FFF_FFFF
    return _ValidationEvidenceDomain(
        profile=RouteAScientificProfile(
            profile_id=_STUDY_ID,
            qualification_seed=qualification_seed,
            formal_seeds=formal_seeds,
            query_vector_seed=query_vector_seed,
            machine_plan_sha256=_MACHINE_PLAN_SHA256,
        ),
        formal_seeds=formal_seeds,
        plan_sha256=_PLAN_SHA256,
    )


def _make_validation_scaling_sentinel_evidence_domain(
    *,
    qualification_seed: int,
    formal_seeds: tuple[int, int, int],
    query_vector_seed: int,
    plan_sha256: str,
) -> _ValidationEvidenceDomain:
    """Construct the independent decoder's private, production-disjoint test domain."""

    registered_formal, registered_query = _scientific_values()
    registered_qualification = _production_evidence_domain().profile.qualification_seed
    seeds = (qualification_seed, *formal_seeds, query_vector_seed)
    if (
        type(qualification_seed) is not int
        or type(formal_seeds) is not tuple
        or len(formal_seeds) != 3
        or any(type(seed) is not int or seed < 0 for seed in seeds)
        or len(set(seeds)) != len(seeds)
        or set(seeds) & {*registered_formal, registered_query, registered_qualification}
        or type(plan_sha256) is not str
        or _LOWER_SHA256.fullmatch(plan_sha256) is None
        or plan_sha256 == _PLAN_SHA256
    ):
        raise ValidationScalingEvidenceError(
            "sentinel evidence domain is not closed and production-disjoint"
        )
    return _ValidationEvidenceDomain(
        profile=RouteAScientificProfile(
            profile_id="dynamic-cssc-validation-scaling-sentinel-only",
            qualification_seed=qualification_seed,
            formal_seeds=formal_seeds,
            query_vector_seed=query_vector_seed,
            machine_plan_sha256=_MACHINE_PLAN_SHA256,
        ),
        formal_seeds=formal_seeds,
        plan_sha256=plan_sha256,
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationScalingEvidenceError("evidence JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    if type(content) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    try:
        decoded = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationScalingEvidenceError(f"{label} is not canonical ASCII JSON") from error
    if type(decoded) is not dict or canonical_route_a_document(decoded) != content:
        raise ValidationScalingEvidenceError(f"{label} is not one canonical object")
    return decoded


def _strict_positive(value: object, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValidationScalingEvidenceError(f"{label} must be one positive strict integer")
    return value


def _strict_nonnegative(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValidationScalingEvidenceError(f"{label} must be a nonnegative strict integer")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValidationScalingEvidenceError(f"{label} must be one lowercase SHA-256")
    return value


def _timestamp(value: object, *, provider: bool, label: str) -> datetime:
    pattern = _PROVIDER_TIMESTAMP if provider else _EXECUTION_TIMESTAMP
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValidationScalingEvidenceError(f"{label} is not one canonical UTC timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo != UTC:
        raise ValidationScalingEvidenceError(f"{label} is not UTC")
    return parsed


def _producer_paths() -> tuple[str, ...]:
    return tuple(
        path
        for cell_ordinal in range(9)
        for path in (
            f"cells/{cell_ordinal:02d}/timing-row.json",
            f"cells/{cell_ordinal:02d}/semantic-projection.json",
            f"cells/{cell_ordinal:02d}/producer-cell.zip",
        )
    ) + ("manifest.json",)


def _replay_paths() -> tuple[str, ...]:
    return tuple(
        path
        for cell_ordinal in range(9)
        for path in (
            f"cells/{cell_ordinal:02d}/timing-row.json",
            f"cells/{cell_ordinal:02d}/final-cell.json",
            f"cells/{cell_ordinal:02d}/semantic-projection.json",
            f"cells/{cell_ordinal:02d}/replay-receipt.json",
            f"cells/{cell_ordinal:02d}/producer-binding.json",
        )
    ) + ("manifest.json",)


def _read_canonical_zip(
    content: bytes,
    *,
    expected_paths: tuple[str, ...],
    label: str,
    max_bytes: int = _MAX_PAYLOAD_BYTES,
) -> dict[str, bytes]:
    if type(content) is not bytes or not content or len(content) > max_bytes:
        raise ValidationScalingEvidenceError(f"{label} is empty or exceeds its byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if names != expected_paths or len(set(names)) != len(names):
                raise ValidationScalingEvidenceError(
                    f"{label} members are missing, extra, repeated, or reordered"
                )
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.create_system != 3
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != _ZIP_TIME
                    or info.extra
                    or info.comment
                    or info.file_size > _MAX_MEMBER_BYTES
                    or info.compress_size != info.file_size
                ):
                    raise ValidationScalingEvidenceError(f"{label} member metadata changed")
                members[info.filename] = archive.read(info)
            if archive.comment:
                raise ValidationScalingEvidenceError(f"{label} contains an archive comment")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ValidationScalingEvidenceError(f"{label} is not a safe canonical ZIP") from error
    return members


def _direct_file(path: Path, *, label: str) -> bytes:
    try:
        observed = path.lstat()
    except OSError as error:
        raise ValidationScalingEvidenceError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(observed.st_mode):
        raise ValidationScalingEvidenceError(f"{label} is not direct regular bytes")
    return path.read_bytes()


def _outer_artifact(directory: Path) -> tuple[bytes, bytes]:
    if not directory.is_absolute():
        raise ValidationScalingEvidenceError("seed artifact directory must be absolute")
    try:
        observed = directory.lstat()
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise ValidationScalingEvidenceError("seed artifact directory is unavailable") from error
    if directory.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise ValidationScalingEvidenceError("seed artifact directory is not direct")
    names = tuple(sorted((entry.name for entry in entries), key=lambda name: name.encode()))
    if names != ("execution-receipt.json", "payload.zip"):
        raise ValidationScalingEvidenceError(
            "seed provider artifact must contain exactly two sorted-path files"
        )
    return (
        _direct_file(directory / "payload.zip", label="seed payload"),
        _direct_file(directory / "execution-receipt.json", label="execution receipt"),
    )


def _read_provider_seed_artifact_zip(
    content: bytes,
    *,
    metadata: ProviderArtifactMetadata,
) -> dict[str, bytes]:
    """Rehash and decode one provider-created, order-nonauthoritative seed ZIP."""

    if type(metadata) is not ProviderArtifactMetadata:
        raise TypeError("provider artifact metadata has the wrong type")
    if (
        type(content) is not bytes
        or not content
        or len(content) != metadata.size_in_bytes
        or "sha256:" + hashlib.sha256(content).hexdigest() != metadata.digest
    ):
        raise ValidationScalingEvidenceError(
            "provider ZIP byte count or independent SHA-256 differs from metadata"
        )
    expected = ("execution-receipt.json", "payload.zip")
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if (
                len(infos) != 2
                or len(set(names)) != 2
                or tuple(sorted(names, key=lambda value: value.encode("utf-8"))) != expected
            ):
                raise ValidationScalingEvidenceError(
                    "provider ZIP outer entries are missing, extra, or duplicated"
                )
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or "/" in info.filename
                    or "\\" in info.filename
                    or file_type not in {0, stat.S_IFREG}
                    or info.file_size > _MAX_MEMBER_BYTES
                ):
                    raise ValidationScalingEvidenceError(
                        "provider ZIP contains a linked or unsafe outer entry"
                    )
                members[info.filename] = archive.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise ValidationScalingEvidenceError(
            "provider ZIP is not one safe outer archive"
        ) from error
    return {name: members[name] for name in expected}


def _expected_cell_order(seed_ordinal: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    cell_ordinal = 0
    for strategy in _STRATEGY_ORDERS[seed_ordinal - 1]:
        for rho in _RHO_ORDERS[seed_ordinal - 1]:
            rows.append(
                {
                    "cell_ordinal": cell_ordinal,
                    "query_count": _QUERY_COUNTS[rho],
                    "rho": rho,
                    "strategy_candidate_id": strategy,
                }
            )
            cell_ordinal += 1
    return rows


def _semantic_projection(cell: dict[str, object]) -> bytes:
    if set(_SEMANTIC_FIELDS) - set(cell):
        raise ValidationScalingEvidenceError("cell omitted a semantic projection field")
    return canonical_route_a_document({field: cell[field] for field in _SEMANTIC_FIELDS})


def _validate_row(
    content: bytes,
    *,
    domain: _ValidationEvidenceDomain,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
    strategy: str,
    rho: str,
    semantic_bytes: bytes,
) -> dict[str, object]:
    row = _canonical_object(content, label="cell timing row")
    if set(row) != set(_CELL_ROW_FIELDS):
        raise ValidationScalingEvidenceError("cell timing row fields are not closed")
    expected = {
        "strategy_candidate_id": strategy,
        "rho": rho,
        "formal_seed": domain.formal_seeds[seed_ordinal - 1],
        "seed_ordinal": seed_ordinal,
        "role": role,
        "query_count": _QUERY_COUNTS[rho],
        "machine_plan_sha256": _MACHINE_PLAN_SHA256,
        "semantic_projection_sha256": hashlib.sha256(semantic_bytes).hexdigest(),
    }
    if any(row[field] != value for field, value in expected.items()):
        raise ValidationScalingEvidenceError("cell timing row identity or digest changed")
    _sha256(row["source_trace_sha256"], label="source trace digest")
    query_count = _strict_positive(row["query_count"], label="query_count")
    compile_count = _strict_positive(
        row["compile_query_call_count"],
        label="compile_query_call_count",
    )
    if not query_count <= compile_count <= 2 * query_count:
        raise ValidationScalingEvidenceError("cell violates Q <= C <= 2Q")
    for field in ("operation_wall_nanoseconds", "operation_process_nanoseconds"):
        _strict_nonnegative(row[field], label=field)
    producer_fields = (
        "producer_cell_archive_wall_nanoseconds_or_null",
        "producer_cell_archive_process_nanoseconds_or_null",
        "producer_state_transition_nanoseconds_or_null",
        "producer_result_assembly_nanoseconds_or_null",
    )
    if role == "producer":
        for field in producer_fields:
            _strict_nonnegative(row[field], label=field)
        if row["replay_elapsed_nanoseconds_or_null"] is not None:
            raise ValidationScalingEvidenceError("producer row contains replay timing")
    else:
        if any(row[field] is not None for field in producer_fields):
            raise ValidationScalingEvidenceError("replay row contains producer timing")
        _strict_nonnegative(
            row["replay_elapsed_nanoseconds_or_null"],
            label="replay_elapsed_nanoseconds_or_null",
        )
    return row


def _validate_manifest(
    content: bytes,
    *,
    domain: _ValidationEvidenceDomain,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
    payload_members: tuple[tuple[str, bytes], ...],
    producer_payload_sha256: str | None,
) -> dict[str, object]:
    manifest = _canonical_object(content, label="seed payload manifest")
    if set(manifest) != set(_MANIFEST_FIELDS):
        raise ValidationScalingEvidenceError("seed payload manifest fields are not closed")
    expected_members = [
        {
            "path": path,
            "byte_count": len(member),
            "sha256": hashlib.sha256(member).hexdigest(),
        }
        for path, member in payload_members
    ]
    expected = {
        "schema_version": _PAYLOAD_SCHEMA,
        "study_id": _STUDY_ID,
        "artifact_role": role,
        "seed_ordinal": seed_ordinal,
        "formal_seed": domain.formal_seeds[seed_ordinal - 1],
        "scale": "S",
        "stage0_plan_sha256": domain.plan_sha256,
        "source_tag": _SOURCE_TAG,
        "machine_plan_sha256": _MACHINE_PLAN_SHA256,
        "cell_count": 9,
        "cell_order": _expected_cell_order(seed_ordinal),
        "member_count": len(payload_members),
        "members": expected_members,
        "retention_days": 1 if role == "producer" else 90,
        "private_material_included": role == "producer",
        "producer_payload_sha256_or_null": producer_payload_sha256,
        "claim_scope": "validation-scaling-only",
        "formal_authority_granted": False,
    }
    if any(manifest[field] != value for field, value in expected.items()):
        raise ValidationScalingEvidenceError("seed payload manifest differs from its members")
    _sha256(manifest["source_trace_sha256"], label="manifest source trace digest")
    return manifest


def _validate_receipt(
    content: bytes,
    *,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
    payload: bytes,
    run_id: int,
    source_git_sha: str,
) -> dict[str, object]:
    receipt = _canonical_object(content, label="execution receipt")
    if set(receipt) != set(_RECEIPT_FIELDS):
        raise ValidationScalingEvidenceError("execution receipt fields are not closed")
    expected_job = "producer" if role == "producer" else "replay"
    expected = {
        "schema_version": _RECEIPT_SCHEMA,
        "artifact_role": role,
        "seed_ordinal": seed_ordinal,
        "runner_os": "Linux",
        "runner_arch": "X64",
        "python_version": "3.12.13",
        "github_run_id": run_id,
        "github_run_attempt": 1,
        "github_job": f"{expected_job}-seed-{seed_ordinal}",
        "source_git_sha": source_git_sha,
        "payload_filename": "payload.zip",
        "payload_byte_count": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if any(receipt[field] != value for field, value in expected.items()):
        raise ValidationScalingEvidenceError("execution receipt does not bind its exact job")
    started = _timestamp(
        receipt["operation_started_utc"],
        provider=False,
        label="operation_started_utc",
    )
    finished = _timestamp(
        receipt["package_finished_utc"],
        provider=False,
        label="package_finished_utc",
    )
    if finished < started:
        raise ValidationScalingEvidenceError("execution receipt UTC interval is reversed")
    for field in ("seed_package_wall_nanoseconds", "seed_package_process_nanoseconds"):
        _strict_nonnegative(receipt[field], label=field)
    rss = receipt["process_peak_rss_bytes_or_null"]
    if rss is not None:
        _strict_nonnegative(rss, label="process_peak_rss_bytes_or_null")
    return receipt


def _seconds_to_nanoseconds(value: object, *, label: str) -> int:
    if type(value) is not str or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{9}", value) is None:
        raise ValidationScalingEvidenceError(f"{label} is not canonical nine-place seconds")
    whole, fractional = value.split(".", 1)
    return int(whole) * 1_000_000_000 + int(fractional)


def _shard_identity(
    source_trace_sha256: str,
    formal_seed: int,
    *,
    domain: _ValidationEvidenceDomain,
) -> str:
    return hashlib.sha256(
        canonical_route_a_document(
            {
                "formal_seed": formal_seed,
                "plan_sha256": domain.plan_sha256,
                "scale": "S",
                "source_tag": _SOURCE_TAG,
                "source_trace_sha256": source_trace_sha256,
                "study_id": _STUDY_ID,
                "unit_attempt_ordinal": 0,
            }
        )
    ).hexdigest()


def _validate_cell_identity(
    cell: dict[str, object],
    *,
    domain: _ValidationEvidenceDomain,
    seed_ordinal: int,
    strategy: str,
    rho: str,
    shard_identity: str,
) -> None:
    identity = cell.get("identity")
    if type(identity) is not dict or identity != {
        "formal_seed_or_null": domain.formal_seeds[seed_ordinal - 1],
        "object_sha256_or_null": None,
        "partition_or_null": None,
        "rho": rho,
        "scale_or_null": "S",
        "semantics_or_null": None,
        "shard_identity_sha256": shard_identity,
        "source_kind": "synthetic",
        "strategy_candidate_id": strategy,
        "suite_role": "formal",
        "unit_attempt_ordinal": 0,
    }:
        raise ValidationScalingEvidenceError("canonical cell identity was retargeted")


def _validate_metadata(
    metadata: ProviderArtifactMetadata,
    *,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
) -> None:
    if type(metadata) is not ProviderArtifactMetadata:
        raise TypeError("metadata must be exact ProviderArtifactMetadata")
    _strict_positive(metadata.artifact_id, label="provider artifact id")
    _strict_positive(metadata.size_in_bytes, label="provider artifact size")
    expected_name = (
        f"validation-scaling-producer-seed-{seed_ordinal}-v1"
        if role == "producer"
        else f"validation-scaling-replay-seed-{seed_ordinal}-v1"
    )
    if metadata.name != expected_name:
        raise ValidationScalingEvidenceError("provider artifact name differs from the matrix")
    if (
        type(metadata.digest) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.digest) is None
    ):
        raise ValidationScalingEvidenceError("provider artifact digest is unavailable or malformed")


def _validate_producer_payload(
    payload: bytes,
    *,
    domain: _ValidationEvidenceDomain,
    seed_ordinal: int,
) -> tuple[
    tuple[dict[str, object], ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
]:
    members = _read_canonical_zip(
        payload,
        expected_paths=_producer_paths(),
        label="producer payload",
    )
    profile = domain.profile
    trace = generate_route_a_formal_trace(
        scale="S",
        formal_seed=domain.formal_seeds[seed_ordinal - 1],
        scientific_profile=profile,
    )
    shard_identity = _shard_identity(
        trace.event_trace_sha256,
        trace.formal_seed,
        domain=domain,
    )
    rows: list[dict[str, object]] = []
    row_bytes: list[bytes] = []
    semantic_bytes: list[bytes] = []
    cell_bytes: list[bytes] = []
    private_archives: list[bytes] = []
    cell_ordinal = 0
    for strategy in _STRATEGY_ORDERS[seed_ordinal - 1]:
        for rho in _RHO_ORDERS[seed_ordinal - 1]:
            prefix = f"cells/{cell_ordinal:02d}"
            row_content = members[f"{prefix}/timing-row.json"]
            semantic_content = members[f"{prefix}/semantic-projection.json"]
            archive_content = members[f"{prefix}/producer-cell.zip"]
            semantic = _canonical_object(semantic_content, label="producer semantic projection")
            if set(semantic) != set(_SEMANTIC_FIELDS):
                raise ValidationScalingEvidenceError("producer semantic fields are not closed")
            inspection = inspect_route_a_synthetic_cell_archive(
                archive_content,
                scientific_profile=profile,
            )
            cell = inspection.cell_run.cell.document
            _validate_cell_identity(
                cell,
                domain=domain,
                seed_ordinal=seed_ordinal,
                strategy=strategy,
                rho=rho,
                shard_identity=shard_identity,
            )
            if semantic_content != _semantic_projection(cell):
                raise ValidationScalingEvidenceError(
                    "producer semantic projection differs from the nested cell"
                )
            row = _validate_row(
                row_content,
                domain=domain,
                role="producer",
                seed_ordinal=seed_ordinal,
                strategy=strategy,
                rho=rho,
                semantic_bytes=semantic_content,
            )
            measurements = cell["measurements"]
            assert type(measurements) is dict
            if (
                row["source_trace_sha256"] != trace.event_trace_sha256
                or row["producer_state_transition_nanoseconds_or_null"]
                != _seconds_to_nanoseconds(
                    measurements["producer_state_transition_seconds"],
                    label="producer state transition seconds",
                )
                or row["producer_result_assembly_nanoseconds_or_null"]
                != _seconds_to_nanoseconds(
                    measurements["producer_result_assembly_seconds"],
                    label="producer result assembly seconds",
                )
            ):
                raise ValidationScalingEvidenceError(
                    "producer row differs from its source trace or supporting stages"
                )
            rows.append(row)
            row_bytes.append(row_content)
            semantic_bytes.append(semantic_content)
            cell_bytes.append(inspection.cell_run.cell.document_bytes)
            private_archives.append(archive_content)
            cell_ordinal += 1
    payload_members = tuple(
        (path, members[path]) for path in _producer_paths() if path != "manifest.json"
    )
    manifest = _validate_manifest(
        members["manifest.json"],
        domain=domain,
        role="producer",
        seed_ordinal=seed_ordinal,
        payload_members=payload_members,
        producer_payload_sha256=None,
    )
    if manifest["source_trace_sha256"] != trace.event_trace_sha256:
        raise ValidationScalingEvidenceError("producer manifest source trace changed")
    return (
        tuple(rows),
        tuple(row_bytes),
        tuple(semantic_bytes),
        tuple(cell_bytes),
        tuple(private_archives),
    )


def _validate_replay_receipt(
    content: bytes,
    *,
    final_cell_sha256: str,
    producer_cell_sha256: str,
    producer_archive_sha256: str,
    expected_target_sha256: str,
    source_trace_sha256: str,
    replay_elapsed_seconds: object,
) -> None:
    receipt = _canonical_object(content, label="Route A replay receipt")
    if set(receipt) != _ROUTE_A_REPLAY_RECEIPT_FIELDS:
        raise ValidationScalingEvidenceError("Route A replay receipt fields are not closed")
    expected = {
        "schema_version": "dynamic-cssc-route-a-synthetic-cell-replay-receipt-v2",
        "final_cell_sha256": final_cell_sha256,
        "producer_cell_sha256": producer_cell_sha256,
        "producer_archive_sha256": producer_archive_sha256,
        "expected_target_sha256": expected_target_sha256,
        "formal_authority_granted": False,
        "publication_evidence": False,
        "machine_plan_sha256": _MACHINE_PLAN_SHA256,
        "deterministic_accounting_equal": True,
        "independent_oracle_equality": True,
        "ledger_snapshot_read_only_verified": True,
        "source_event_trace_sha256": source_trace_sha256,
        "replay_elapsed_seconds": replay_elapsed_seconds,
        "replay_timing_scope": (
            "function-entry-through-inspection-rehash-read-only-ledger-verification-"
            "typed-reexecution-oracle-and-final-comparison-before-receipt-serialization"
        ),
    }
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise ValidationScalingEvidenceError("Route A replay receipt binding changed")
    for field in (
        "independent_replay_cell_sha256",
        "producer_ledger_root",
        "producer_ledger_snapshot_sha256",
        "producer_output_digest_root",
        "producer_prepared_query_root",
        "replay_ledger_root",
        "replay_ledger_snapshot_sha256",
        "replay_output_digest_root",
        "replay_prepared_query_root",
        "window_trace_sha256",
    ):
        _sha256(receipt[field], label=f"Route A replay receipt {field}")
    if (
        receipt["producer_ledger_root"] != receipt["replay_ledger_root"]
        or receipt["producer_ledger_snapshot_sha256"]
        != receipt["replay_ledger_snapshot_sha256"]
        or receipt["producer_output_digest_root"] != receipt["replay_output_digest_root"]
        or receipt["producer_prepared_query_root"]
        != receipt["replay_prepared_query_root"]
    ):
        raise ValidationScalingEvidenceError("Route A replay receipt roots diverged")


def _validate_replay_payload(
    payload: bytes,
    *,
    domain: _ValidationEvidenceDomain,
    seed_ordinal: int,
    producer: SeedEvidence,
) -> tuple[
    tuple[dict[str, object], ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
    tuple[bytes, ...],
]:
    members = _read_canonical_zip(
        payload,
        expected_paths=_replay_paths(),
        label="replay payload",
    )
    profile = domain.profile
    trace = generate_route_a_formal_trace(
        scale="S",
        formal_seed=domain.formal_seeds[seed_ordinal - 1],
        scientific_profile=profile,
    )
    shard_identity = _shard_identity(
        trace.event_trace_sha256,
        trace.formal_seed,
        domain=domain,
    )
    rows: list[dict[str, object]] = []
    row_bytes: list[bytes] = []
    semantic_bytes: list[bytes] = []
    cell_bytes: list[bytes] = []
    binding_bytes: list[bytes] = []
    cell_ordinal = 0
    for strategy in _STRATEGY_ORDERS[seed_ordinal - 1]:
        for rho in _RHO_ORDERS[seed_ordinal - 1]:
            prefix = f"cells/{cell_ordinal:02d}"
            row_content = members[f"{prefix}/timing-row.json"]
            final_cell_content = members[f"{prefix}/final-cell.json"]
            semantic_content = members[f"{prefix}/semantic-projection.json"]
            replay_receipt = members[f"{prefix}/replay-receipt.json"]
            binding_content = members[f"{prefix}/producer-binding.json"]
            semantic = _canonical_object(semantic_content, label="replay semantic projection")
            if set(semantic) != set(_SEMANTIC_FIELDS):
                raise ValidationScalingEvidenceError("replay semantic fields are not closed")
            final_cell_object = _canonical_object(final_cell_content, label="replay final cell")
            final_cell = validate_route_a_strategy_cell(
                final_cell_object,
                scientific_profile=profile,
            )
            if final_cell.document_bytes != final_cell_content:
                raise ValidationScalingEvidenceError("replay final cell bytes are not canonical")
            _validate_cell_identity(
                final_cell.document,
                domain=domain,
                seed_ordinal=seed_ordinal,
                strategy=strategy,
                rho=rho,
                shard_identity=shard_identity,
            )
            if semantic_content != _semantic_projection(final_cell.document):
                raise ValidationScalingEvidenceError(
                    "replay semantic projection differs from its final cell"
                )
            if semantic_content != producer.semantic_bytes[cell_ordinal]:
                raise ValidationScalingEvidenceError(
                    "producer/replay semantic projections are not byte-identical"
                )
            row = _validate_row(
                row_content,
                domain=domain,
                role="independent-replay",
                seed_ordinal=seed_ordinal,
                strategy=strategy,
                rho=rho,
                semantic_bytes=semantic_content,
            )
            measurements = final_cell.document["measurements"]
            assert type(measurements) is dict
            if (
                row["source_trace_sha256"] != trace.event_trace_sha256
                or row["replay_elapsed_nanoseconds_or_null"]
                != _seconds_to_nanoseconds(
                    measurements["replay_seconds"],
                    label="replay seconds",
                )
            ):
                raise ValidationScalingEvidenceError(
                    "replay row differs from its source trace or supporting stage"
                )
            binding = _canonical_object(binding_content, label="producer binding")
            if set(binding) != set(_BINDING_FIELDS):
                raise ValidationScalingEvidenceError("producer binding fields are not closed")
            producer_cell_sha256 = hashlib.sha256(
                producer.cell_bytes[cell_ordinal]
            ).hexdigest()
            producer_archive = producer.private_archive_bytes[cell_ordinal]
            producer_archive_sha256 = hashlib.sha256(producer_archive).hexdigest()
            expected_binding = {
                "schema_version": _BINDING_SCHEMA,
                "producer_payload_sha256": producer.payload_sha256,
                "producer_cell_archive_sha256": producer_archive_sha256,
                "producer_cell_archive_byte_count": len(producer_archive),
                "producer_cell_sha256": producer_cell_sha256,
                "producer_semantic_projection_sha256": hashlib.sha256(
                    producer.semantic_bytes[cell_ordinal]
                ).hexdigest(),
                "producer_timing_row_sha256": hashlib.sha256(
                    producer.row_bytes[cell_ordinal]
                ).hexdigest(),
            }
            if any(binding[field] != value for field, value in expected_binding.items()):
                raise ValidationScalingEvidenceError("replay producer binding changed")
            target = RouteASyntheticCellTarget.for_synthetic_trace(
                trace,
                strategy_candidate_id=strategy,
                rho=Fraction(rho),
                shard_identity_sha256=shard_identity,
                unit_attempt_ordinal=0,
                scientific_profile=profile,
            )
            _validate_replay_receipt(
                replay_receipt,
                final_cell_sha256=final_cell.sha256,
                producer_cell_sha256=producer_cell_sha256,
                producer_archive_sha256=producer_archive_sha256,
                expected_target_sha256=target.sha256,
                source_trace_sha256=trace.event_trace_sha256,
                replay_elapsed_seconds=measurements["replay_seconds"],
            )
            rows.append(row)
            row_bytes.append(row_content)
            semantic_bytes.append(semantic_content)
            cell_bytes.append(final_cell_content)
            binding_bytes.append(binding_content)
            cell_ordinal += 1
    payload_members = tuple(
        (path, members[path]) for path in _replay_paths() if path != "manifest.json"
    )
    manifest = _validate_manifest(
        members["manifest.json"],
        domain=domain,
        role="independent-replay",
        seed_ordinal=seed_ordinal,
        payload_members=payload_members,
        producer_payload_sha256=producer.payload_sha256,
    )
    if manifest["source_trace_sha256"] != trace.event_trace_sha256:
        raise ValidationScalingEvidenceError("replay manifest source trace changed")
    return (
        tuple(rows),
        tuple(row_bytes),
        tuple(semantic_bytes),
        tuple(cell_bytes),
        tuple(binding_bytes),
    )


def _inspect_seed_artifact(
    directory: Path,
    *,
    domain: _ValidationEvidenceDomain,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
    run_id: int,
    source_git_sha: str,
    metadata: ProviderArtifactMetadata,
    provider_zip_bytes: bytes,
    producer: SeedEvidence | None = None,
) -> SeedEvidence:
    """Independently close one extracted two-file provider seed artifact."""

    if role not in {"producer", "independent-replay"}:
        raise ValidationScalingEvidenceError("seed artifact role is outside the closed study")
    if type(seed_ordinal) is not int or seed_ordinal not in {1, 2, 3}:
        raise ValidationScalingEvidenceError("seed ordinal is outside the closed study")
    _strict_positive(run_id, label="GitHub run id")
    if type(source_git_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise ValidationScalingEvidenceError("source Git SHA is malformed")
    _validate_metadata(metadata, role=role, seed_ordinal=seed_ordinal)
    payload, receipt_bytes = _outer_artifact(directory)
    provider_members = _read_provider_seed_artifact_zip(
        provider_zip_bytes,
        metadata=metadata,
    )
    if (
        provider_members["payload.zip"] != payload
        or provider_members["execution-receipt.json"] != receipt_bytes
    ):
        raise ValidationScalingEvidenceError(
            "provider ZIP bytes differ from the extracted seed artifact"
        )
    receipt = _validate_receipt(
        receipt_bytes,
        role=role,
        seed_ordinal=seed_ordinal,
        payload=payload,
        run_id=run_id,
        source_git_sha=source_git_sha,
    )
    if role == "producer":
        if producer is not None:
            raise ValidationScalingEvidenceError("producer artifact received a predecessor")
        rows, row_bytes, semantics, cells, private_archives = _validate_producer_payload(
            payload,
            domain=domain,
            seed_ordinal=seed_ordinal,
        )
        bindings: tuple[bytes, ...] = ()
    else:
        if (
            type(producer) is not SeedEvidence
            or producer.role != "producer"
            or producer.seed_ordinal != seed_ordinal
        ):
            raise ValidationScalingEvidenceError("replay lacks its exact producer predecessor")
        rows, row_bytes, semantics, cells, bindings = _validate_replay_payload(
            payload,
            domain=domain,
            seed_ordinal=seed_ordinal,
            producer=producer,
        )
        private_archives = ()
    return SeedEvidence(
        role=role,
        seed_ordinal=seed_ordinal,
        payload_bytes=payload,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        receipt_bytes=receipt_bytes,
        receipt=receipt,
        rows=rows,
        row_bytes=row_bytes,
        semantic_bytes=semantics,
        cell_bytes=cells,
        private_archive_bytes=private_archives,
        binding_bytes=bindings,
        metadata=metadata,
    )


def inspect_seed_artifact(
    directory: Path,
    *,
    role: Literal["producer", "independent-replay"],
    seed_ordinal: int,
    run_id: int,
    source_git_sha: str,
    metadata: ProviderArtifactMetadata,
    provider_zip_bytes: bytes,
    producer: SeedEvidence | None = None,
) -> SeedEvidence:
    """Independently close one production two-file provider seed artifact."""

    return _inspect_seed_artifact(
        directory,
        domain=_production_evidence_domain(),
        role=role,
        seed_ordinal=seed_ordinal,
        run_id=run_id,
        source_git_sha=source_git_sha,
        metadata=metadata,
        provider_zip_bytes=provider_zip_bytes,
        producer=producer,
    )


def _integer_summary(values: list[int]) -> dict[str, object]:
    if len(values) != 3 or any(type(value) is not int or value < 0 for value in values):
        raise ValidationScalingEvidenceError("timing summary requires three nonnegative integers")
    ordered = sorted(values)
    return {
        "observations": values,
        "minimum": ordered[0],
        "median": ordered[1],
        "maximum": ordered[2],
    }


def _rational(value: Fraction) -> dict[str, int]:
    if type(value) is not Fraction or value.denominator <= 0:
        raise ValidationScalingEvidenceError("statistic is not one reduced rational")
    return {"numerator": value.numerator, "denominator": value.denominator}


def _ols_record(
    *,
    strategy: str,
    role: Literal["producer", "independent-replay"],
    medians: tuple[int, int, int],
) -> dict[str, object]:
    if any(type(value) is not int or value < 0 for value in medians):
        raise ValidationScalingEvidenceError("OLS inputs are not nonnegative integers")
    xs = tuple(Fraction(value) for value in (5, 51, 512))
    ys = tuple(Fraction(value) for value in medians)
    mean_x = sum(xs, Fraction()) / 3
    mean_y = sum(ys, Fraction()) / 3
    sxx = sum(((value - mean_x) ** 2 for value in xs), Fraction())
    if sxx == 0:  # pragma: no cover - the registered query counts are distinct
        raise ValidationScalingEvidenceError("OLS query counts have zero spread")
    beta = sum(
        (
            (x_value - mean_x) * (y_value - mean_y)
            for x_value, y_value in zip(xs, ys, strict=True)
        ),
        Fraction(),
    ) / sxx
    alpha = mean_y - beta * mean_x
    fitted = tuple(alpha + beta * value for value in xs)
    sse = sum(
        ((observed - fit) ** 2 for observed, fit in zip(ys, fitted, strict=True)),
        Fraction(),
    )
    sst = sum(((observed - mean_y) ** 2 for observed in ys), Fraction())
    if sst == 0:
        if sse != 0:
            raise ValidationScalingEvidenceError("zero-SST OLS has nonzero SSE")
        r_squared = Fraction(1)
    else:
        r_squared = Fraction(1) - sse / sst
    return {
        "strategy_candidate_id": strategy,
        "role": role,
        "query_counts": [5, 51, 512],
        "median_wall_nanoseconds": list(medians),
        "alpha_nanoseconds": _rational(alpha),
        "beta_nanoseconds_per_query": _rational(beta),
        "r_squared": _rational(r_squared),
        "intercept_label": "extrapolated-descriptive-intercept-not-observed-fixed-cost",
        "pass_threshold": None,
    }


def _fraction_from_document(document: object, *, label: str) -> Fraction:
    if type(document) is not dict or set(document) != {"numerator", "denominator"}:
        raise ValidationScalingEvidenceError(f"{label} is not one closed rational")
    numerator = document["numerator"]
    denominator = document["denominator"]
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise ValidationScalingEvidenceError(f"{label} rational types are invalid")
    value = Fraction(numerator, denominator)
    if value.numerator != numerator or value.denominator != denominator:
        raise ValidationScalingEvidenceError(f"{label} rational is not reduced")
    return value


def _render_fraction(value: Fraction, *, nanoseconds: bool) -> str:
    with localcontext() as context:
        context.prec = 80
        decimal = Decimal(value.numerator) / Decimal(value.denominator)
        if nanoseconds:
            decimal /= Decimal(1_000_000_000)
        quantized = decimal.quantize(Decimal("0.000000001"), rounding=ROUND_HALF_EVEN)
    return format(quantized, ".9f")


def _provider_observation(
    document: object,
    *,
    expected_name: str,
) -> dict[str, object]:
    fields = {
        "github_job_database_id",
        "github_job_name",
        "github_job_started_at",
        "github_job_completed_at",
        "github_job_conclusion",
    }
    if type(document) is not dict or set(document) != fields:
        raise ValidationScalingEvidenceError("provider job observation fields are not closed")
    if document["github_job_name"] != expected_name:
        raise ValidationScalingEvidenceError("provider job observation name changed")
    _strict_positive(document["github_job_database_id"], label="provider job database id")
    started = _timestamp(
        document["github_job_started_at"],
        provider=True,
        label="provider job startedAt",
    )
    completed = _timestamp(
        document["github_job_completed_at"],
        provider=True,
        label="provider job completedAt",
    )
    if completed < started or document["github_job_conclusion"] != "success":
        raise ValidationScalingEvidenceError("provider job did not close successfully")
    return dict(document)


def _validate_provider_observations(
    observations: tuple[dict[str, object], ...],
    seeds: tuple[SeedEvidence, ...],
) -> tuple[dict[str, object], ...]:
    expected_names = tuple(
        f"{role}-seed-{ordinal}"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    if type(observations) is not tuple or len(observations) != 6:
        raise ValidationScalingEvidenceError("provider observations must contain six jobs")
    validated = tuple(
        _provider_observation(document, expected_name=name)
        for document, name in zip(observations, expected_names, strict=True)
    )
    ids = tuple(document["github_job_database_id"] for document in validated)
    if len(set(ids)) != 6:
        raise ValidationScalingEvidenceError("provider job database IDs are not unique")
    for observation, seed in zip(validated, seeds, strict=True):
        job_started = _timestamp(
            observation["github_job_started_at"],
            provider=True,
            label="provider job startedAt",
        )
        job_completed = _timestamp(
            observation["github_job_completed_at"],
            provider=True,
            label="provider job completedAt",
        )
        operation_started = _timestamp(
            seed.receipt["operation_started_utc"],
            provider=False,
            label="operation_started_utc",
        )
        package_finished = _timestamp(
            seed.receipt["package_finished_utc"],
            provider=False,
            label="package_finished_utc",
        )
        if not job_started <= operation_started <= package_finished <= job_completed:
            raise ValidationScalingEvidenceError(
                "process-owned package interval falls outside its provider job"
            )
    return validated


def _row_key(row: dict[str, object]) -> tuple[str, str, str, int]:
    strategy = row["strategy_candidate_id"]
    role = row["role"]
    rho = row["rho"]
    ordinal = row["seed_ordinal"]
    if (
        type(strategy) is not str
        or type(role) is not str
        or type(rho) is not str
        or type(ordinal) is not int
    ):
        raise ValidationScalingEvidenceError("cell row key types changed")
    return strategy, role, rho, ordinal


def _write_canonical_zip(paths: tuple[str, ...], members: dict[str, bytes]) -> bytes:
    if tuple(members) != paths:
        raise ValidationScalingEvidenceError("aggregate member order is not closed")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in paths:
            info = zipfile.ZipInfo(path, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[path])
    return buffer.getvalue()


def build_aggregate(
    *,
    producers: tuple[SeedEvidence, SeedEvidence, SeedEvidence],
    replays: tuple[SeedEvidence, SeedEvidence, SeedEvidence],
    provider_observations: tuple[dict[str, object], ...],
    source_git_sha: str,
) -> bytes:
    """Build the complete redacted aggregate from six independently closed inputs."""

    if type(source_git_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise ValidationScalingEvidenceError("aggregate source Git SHA is malformed")
    if type(producers) is not tuple or type(replays) is not tuple:
        raise TypeError("producer and replay evidence must be exact tuples")
    if len(producers) != 3 or len(replays) != 3:
        raise ValidationScalingEvidenceError("aggregate requires three producer/replay pairs")
    for ordinal, (producer, replay) in enumerate(
        zip(producers, replays, strict=True),
        start=1,
    ):
        if (
            type(producer) is not SeedEvidence
            or type(replay) is not SeedEvidence
            or producer.role != "producer"
            or replay.role != "independent-replay"
            or producer.seed_ordinal != ordinal
            or replay.seed_ordinal != ordinal
            or producer.receipt["source_git_sha"] != source_git_sha
            or replay.receipt["source_git_sha"] != source_git_sha
            or producer.receipt["github_run_id"] != replay.receipt["github_run_id"]
        ):
            raise ValidationScalingEvidenceError("aggregate seed-pair identity changed")
    run_ids = {
        evidence.receipt["github_run_id"] for evidence in (*producers, *replays)
    }
    if len(run_ids) != 1:
        raise ValidationScalingEvidenceError("seed artifacts came from different workflow runs")
    all_seeds = (*producers, *replays)
    observations = _validate_provider_observations(provider_observations, all_seeds)

    rows_by_key: dict[tuple[str, str, str, int], dict[str, object]] = {}
    semantics_by_key: dict[tuple[str, str, int], dict[str, bytes]] = {}
    for evidence in all_seeds:
        for row, semantic in zip(evidence.rows, evidence.semantic_bytes, strict=True):
            key = _row_key(row)
            if key in rows_by_key:
                raise ValidationScalingEvidenceError("aggregate contains a duplicate cell row")
            rows_by_key[key] = row
            semantic_key = (key[0], key[2], key[3])
            role_map = semantics_by_key.setdefault(semantic_key, {})
            role_map[key[1]] = semantic
    if len(rows_by_key) != 54 or len(semantics_by_key) != 27:
        raise ValidationScalingEvidenceError("aggregate matrix is incomplete")

    reporting_rows: list[dict[str, object]] = []
    verdicts: list[dict[str, object]] = []
    for strategy in _STRATEGIES:
        for role in ("producer", "independent-replay"):
            for rho in _RHOS:
                for ordinal in (1, 2, 3):
                    key = (strategy, role, rho, ordinal)
                    if key not in rows_by_key:
                        raise ValidationScalingEvidenceError("reporting-order cell is missing")
                    row = rows_by_key[key]
                    reporting_rows.append(row)
                    semantic_pair = semantics_by_key[(strategy, rho, ordinal)]
                    if set(semantic_pair) != {"producer", "independent-replay"}:
                        raise ValidationScalingEvidenceError(
                            "semantic producer/replay pair is open"
                        )
                    equal = semantic_pair["producer"] == semantic_pair["independent-replay"]
                    if not equal:
                        raise ValidationScalingEvidenceError(
                            "semantic producer/replay pair differs"
                        )
                    verdicts.append(
                        {
                            "strategy_candidate_id": strategy,
                            "rho": rho,
                            "seed_ordinal": ordinal,
                            "role": role,
                            "query_count": row["query_count"],
                            "compile_query_call_count": row["compile_query_call_count"],
                            "compile_depth_verified": True,
                            "semantic_projection_sha256": row[
                                "semantic_projection_sha256"
                            ],
                            "producer_replay_semantic_equal_or_null": (
                                True if role == "independent-replay" else None
                            ),
                        }
                    )

    supporting_fields = (
        "producer_cell_archive_wall_nanoseconds_or_null",
        "producer_cell_archive_process_nanoseconds_or_null",
        "producer_state_transition_nanoseconds_or_null",
        "producer_result_assembly_nanoseconds_or_null",
        "replay_elapsed_nanoseconds_or_null",
    )
    summaries: list[dict[str, object]] = []
    medians_by_fit: dict[tuple[str, str], dict[str, int]] = {}
    for strategy in _STRATEGIES:
        for role in ("producer", "independent-replay"):
            for rho in _RHOS:
                rows = [rows_by_key[(strategy, role, rho, ordinal)] for ordinal in (1, 2, 3)]
                wall_values = [row["operation_wall_nanoseconds"] for row in rows]
                process_values = [row["operation_process_nanoseconds"] for row in rows]
                if any(type(value) is not int for value in (*wall_values, *process_values)):
                    raise ValidationScalingEvidenceError("timing observations changed type")
                wall_summary = _integer_summary(wall_values)  # type: ignore[arg-type]
                process_summary = _integer_summary(process_values)  # type: ignore[arg-type]
                summary: dict[str, object] = {
                    "strategy_candidate_id": strategy,
                    "role": role,
                    "rho": rho,
                    "query_count": _QUERY_COUNTS[rho],
                    "seed_ordinals": [1, 2, 3],
                    "operation_wall_nanoseconds": wall_summary,
                    "operation_process_nanoseconds": process_summary,
                }
                for field in supporting_fields:
                    values = [row[field] for row in rows]
                    if all(value is None for value in values):
                        summary[field] = None
                    elif all(type(value) is int and value >= 0 for value in values):
                        summary[field] = _integer_summary(values)  # type: ignore[arg-type]
                    else:
                        raise ValidationScalingEvidenceError(
                            "supporting timing observations are mixed or malformed"
                        )
                summaries.append(summary)
                median = wall_summary["median"]
                assert type(median) is int
                medians_by_fit.setdefault((strategy, role), {})[rho] = median

    ols_records: list[dict[str, object]] = []
    human_renderings: list[dict[str, object]] = []
    for strategy in _STRATEGIES:
        for role in ("producer", "independent-replay"):
            medians = medians_by_fit[(strategy, role)]
            record = _ols_record(
                strategy=strategy,
                role=role,
                medians=(medians["1/100"], medians["1/10"], medians["1"]),
            )
            ols_records.append(record)
            alpha = _fraction_from_document(record["alpha_nanoseconds"], label="alpha")
            beta = _fraction_from_document(
                record["beta_nanoseconds_per_query"],
                label="beta",
            )
            r_squared = _fraction_from_document(record["r_squared"], label="r_squared")
            human_renderings.append(
                {
                    "strategy_candidate_id": strategy,
                    "role": role,
                    "alpha_seconds": _render_fraction(alpha, nanoseconds=True),
                    "beta_seconds_per_query": _render_fraction(beta, nanoseconds=True),
                    "r_squared": _render_fraction(r_squared, nanoseconds=False),
                }
            )

    artifact_records: list[dict[str, object]] = []
    artifact_ids: set[int] = set()
    for evidence in all_seeds:
        metadata = evidence.metadata
        if metadata.artifact_id in artifact_ids:
            raise ValidationScalingEvidenceError("provider artifact ID is duplicated")
        artifact_ids.add(metadata.artifact_id)
        artifact_records.append(
            {
                "artifact_role": evidence.role,
                "seed_ordinal": evidence.seed_ordinal,
                "provider_artifact_name": metadata.name,
                "provider_artifact_id": metadata.artifact_id,
                "provider_artifact_size_in_bytes": metadata.size_in_bytes,
                "provider_artifact_digest": metadata.digest,
                "execution_receipt_sha256": hashlib.sha256(
                    evidence.receipt_bytes
                ).hexdigest(),
                "execution_receipt": evidence.receipt,
                "payload_byte_count": len(evidence.payload_bytes),
                "payload_sha256": evidence.payload_sha256,
                "independent_rehash_verified": True,
            }
        )

    documents = {
        "closed-cell-table.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-closed-cell-table-v1",
                "study_id": _STUDY_ID,
                "cell_count": 54,
                "rows": reporting_rows,
            }
        ),
        "compile-semantic-verdicts.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-verdicts-v1",
                "study_id": _STUDY_ID,
                "verdict_count": 54,
                "verdicts": verdicts,
            }
        ),
        "timing-summaries.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-timing-summaries-v1",
                "study_id": _STUDY_ID,
                "summary_count": 18,
                "summaries": summaries,
            }
        ),
        "ols-records.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-ols-records-v1",
                "study_id": _STUDY_ID,
                "record_count": 6,
                "records": ols_records,
            }
        ),
        "provider-observations.json": canonical_route_a_document(
            {
                "schema_version": (
                    "dynamic-cssc-validation-scaling-provider-observations-v1"
                ),
                "study_id": _STUDY_ID,
                "observation_count": 6,
                "observations": list(observations),
            }
        ),
        "input-artifacts.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-input-artifacts-v1",
                "study_id": _STUDY_ID,
                "artifact_count": 6,
                "artifacts": artifact_records,
            }
        ),
        "human-renderings.json": canonical_route_a_document(
            {
                "schema_version": "dynamic-cssc-validation-scaling-human-renderings-v1",
                "study_id": _STUDY_ID,
                "rounding": "Decimal-ROUND_HALF_EVEN-nine-decimal-places",
                "rendering_count": 6,
                "renderings": human_renderings,
            }
        ),
    }
    member_records = [
        {
            "path": path,
            "byte_count": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for path, content in documents.items()
    ]
    documents["manifest.json"] = canonical_route_a_document(
        {
            "schema_version": _AGGREGATE_SCHEMA,
            "study_id": _STUDY_ID,
            "source_git_sha": source_git_sha,
            "source_tag": _SOURCE_TAG,
            "stage0_plan_sha256": _PLAN_SHA256,
            "closed_cell_count": 54,
            "input_artifact_count": 6,
            "member_count": 7,
            "members": member_records,
            "matrix_complete": True,
            "claim_scope": "validation-scaling-only",
            "formal_authority_granted": False,
        }
    )
    return _write_canonical_zip(_AGGREGATE_PATHS, documents)


def _load_transport_object(path: Path, *, label: str) -> dict[str, object]:
    if not path.is_absolute():
        raise ValidationScalingEvidenceError(f"{label} path must be absolute")
    return _canonical_object(_direct_file(path, label=label), label=label)


def _load_artifact_metadata(
    path: Path,
    *,
    run_id: int,
    source_git_sha: str,
) -> dict[str, ProviderArtifactMetadata]:
    document = _load_transport_object(path, label="provider artifact metadata")
    if set(document) != {"schema_version", "run_id", "source_git_sha", "artifacts"}:
        raise ValidationScalingEvidenceError("provider artifact metadata fields are not closed")
    if (
        document["schema_version"]
        != "dynamic-cssc-validation-scaling-provider-artifact-metadata-v1"
        or document["run_id"] != run_id
        or document["source_git_sha"] != source_git_sha
    ):
        raise ValidationScalingEvidenceError("provider artifact metadata identity changed")
    artifacts = document["artifacts"]
    if type(artifacts) is not list or len(artifacts) != 6:
        raise ValidationScalingEvidenceError("provider artifact metadata must contain six inputs")
    expected_names = tuple(
        f"validation-scaling-{role}-seed-{ordinal}-v1"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    result: dict[str, ProviderArtifactMetadata] = {}
    ids: set[int] = set()
    for item, expected_name in zip(artifacts, expected_names, strict=True):
        fields = {
            "artifact_id",
            "name",
            "size_in_bytes",
            "digest",
            "expired",
            "workflow_run_id",
            "workflow_run_head_branch",
            "workflow_run_head_sha",
        }
        if type(item) is not dict or set(item) != fields:
            raise ValidationScalingEvidenceError("provider artifact record fields are not closed")
        artifact_id = _strict_positive(item["artifact_id"], label="provider artifact id")
        size = _strict_positive(item["size_in_bytes"], label="provider artifact size")
        if (
            item["name"] != expected_name
            or item["expired"] is not False
            or item["workflow_run_id"] != run_id
            or item["workflow_run_head_branch"] != _SOURCE_TAG
            or item["workflow_run_head_sha"] != source_git_sha
            or artifact_id in ids
        ):
            raise ValidationScalingEvidenceError("provider artifact record binding changed")
        digest = item["digest"]
        if type(digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValidationScalingEvidenceError("provider artifact digest is malformed")
        ids.add(artifact_id)
        result[expected_name] = ProviderArtifactMetadata(
            artifact_id=artifact_id,
            name=expected_name,
            size_in_bytes=size,
            digest=digest,
        )
    return result


def _load_provider_observations(path: Path) -> tuple[dict[str, object], ...]:
    document = _load_transport_object(path, label="provider job observations")
    if set(document) != {"schema_version", "observations"} or document[
        "schema_version"
    ] != "dynamic-cssc-validation-scaling-provider-job-transport-v1":
        raise ValidationScalingEvidenceError("provider observation transport fields changed")
    observations = document["observations"]
    if type(observations) is not list or len(observations) != 6:
        raise ValidationScalingEvidenceError("provider observation transport is incomplete")
    return tuple(observations)  # type: ignore[return-value]


def _inspect_six_inputs(
    *,
    input_root: Path,
    metadata_by_name: dict[str, ProviderArtifactMetadata],
    provider_zip_bytes_by_name: dict[str, bytes],
    run_id: int,
    source_git_sha: str,
) -> tuple[
    tuple[SeedEvidence, SeedEvidence, SeedEvidence],
    tuple[SeedEvidence, SeedEvidence, SeedEvidence],
]:
    if not input_root.is_absolute():
        raise ValidationScalingEvidenceError("input_root must be absolute")
    try:
        observed = input_root.lstat()
        names = tuple(sorted(path.name for path in input_root.iterdir()))
    except OSError as error:
        raise ValidationScalingEvidenceError("input_root is unavailable") from error
    expected_directories = tuple(
        f"{role}-seed-{ordinal}"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    if (
        input_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or names != tuple(sorted(expected_directories))
    ):
        raise ValidationScalingEvidenceError("input_root does not contain the exact six inputs")
    expected_artifact_names = tuple(
        f"validation-scaling-{role}-seed-{ordinal}-v1"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    if (
        type(metadata_by_name) is not dict
        or type(provider_zip_bytes_by_name) is not dict
        or tuple(metadata_by_name) != expected_artifact_names
        or tuple(provider_zip_bytes_by_name) != expected_artifact_names
        or any(type(content) is not bytes for content in provider_zip_bytes_by_name.values())
    ):
        raise ValidationScalingEvidenceError("provider artifact inputs are not closed")
    producers: list[SeedEvidence] = []
    for ordinal in (1, 2, 3):
        name = f"validation-scaling-producer-seed-{ordinal}-v1"
        producers.append(
            inspect_seed_artifact(
                input_root / f"producer-seed-{ordinal}",
                role="producer",
                seed_ordinal=ordinal,
                run_id=run_id,
                source_git_sha=source_git_sha,
                metadata=metadata_by_name[name],
                provider_zip_bytes=provider_zip_bytes_by_name[name],
            )
        )
    replays: list[SeedEvidence] = []
    for ordinal in (1, 2, 3):
        name = f"validation-scaling-replay-seed-{ordinal}-v1"
        replays.append(
            inspect_seed_artifact(
                input_root / f"replay-seed-{ordinal}",
                role="independent-replay",
                seed_ordinal=ordinal,
                run_id=run_id,
                source_git_sha=source_git_sha,
                metadata=metadata_by_name[name],
                provider_zip_bytes=provider_zip_bytes_by_name[name],
                producer=producers[ordinal - 1],
            )
        )
    return tuple(producers), tuple(replays)  # type: ignore[return-value]


def _atomic_write(path: Path, content: bytes) -> None:
    if not path.is_absolute():
        raise ValidationScalingEvidenceError("aggregate output path must be absolute")
    temporary = path.with_name(f".{path.name}.tmp")
    if path.exists() or temporary.exists():
        raise ValidationScalingEvidenceError("refusing to replace an aggregate output")
    file_descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(file_descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=("build-aggregate", "audit-aggregate"))
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--provider-zip-root", required=True, type=Path)
    parser.add_argument("--artifact-metadata", required=True, type=Path)
    parser.add_argument("--provider-observations", required=True, type=Path)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--aggregate", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def _run(arguments: argparse.Namespace) -> int:
    run_id = _strict_positive(arguments.run_id, label="GitHub run id")
    if (
        type(arguments.source_git_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(arguments.source_git_sha) is None
    ):
        raise ValidationScalingEvidenceError("source Git SHA is malformed")
    metadata = _load_artifact_metadata(
        arguments.artifact_metadata,
        run_id=run_id,
        source_git_sha=arguments.source_git_sha,
    )
    observations = _load_provider_observations(arguments.provider_observations)
    expected_artifact_names = tuple(metadata)
    if not arguments.provider_zip_root.is_absolute():
        raise ValidationScalingEvidenceError("provider_zip_root must be absolute")
    try:
        zip_root_observed = arguments.provider_zip_root.lstat()
        zip_names = tuple(
            sorted(path.name for path in arguments.provider_zip_root.iterdir())
        )
    except OSError as error:
        raise ValidationScalingEvidenceError("provider_zip_root is unavailable") from error
    expected_zip_names = tuple(sorted(f"{name}.zip" for name in expected_artifact_names))
    if (
        arguments.provider_zip_root.is_symlink()
        or not stat.S_ISDIR(zip_root_observed.st_mode)
        or zip_names != expected_zip_names
    ):
        raise ValidationScalingEvidenceError("provider_zip_root does not contain six raw ZIPs")
    provider_zip_bytes_by_name = {
        name: _direct_file(
            arguments.provider_zip_root / f"{name}.zip",
            label=f"raw provider ZIP {name}",
        )
        for name in expected_artifact_names
    }
    producers, replays = _inspect_six_inputs(
        input_root=arguments.input_root,
        metadata_by_name=metadata,
        provider_zip_bytes_by_name=provider_zip_bytes_by_name,
        run_id=run_id,
        source_git_sha=arguments.source_git_sha,
    )
    expected = build_aggregate(
        producers=producers,
        replays=replays,
        provider_observations=observations,
        source_git_sha=arguments.source_git_sha,
    )
    if arguments.mode == "build-aggregate":
        if arguments.output is None or arguments.aggregate is not None:
            raise ValidationScalingEvidenceError("build mode requires only --output")
        _atomic_write(arguments.output, expected)
        print(
            canonical_route_a_document(
                {
                    "aggregate_sha256": hashlib.sha256(expected).hexdigest(),
                    "authority": False,
                    "formal_authority_granted": False,
                    "matrix_complete": True,
                }
            ).decode("ascii"),
            end="",
        )
        return 0
    if arguments.aggregate is None or arguments.output is not None:
        raise ValidationScalingEvidenceError("audit mode requires only --aggregate")
    observed = _direct_file(arguments.aggregate, label="aggregate package")
    _read_canonical_zip(
        observed,
        expected_paths=_AGGREGATE_PATHS,
        label="aggregate package",
    )
    if observed != expected:
        raise ValidationScalingEvidenceError("aggregate bytes differ from independent rebuild")
    print(
        canonical_route_a_document(
            {
                "aggregate_sha256": hashlib.sha256(observed).hexdigest(),
                "independent_audit": "PASS",
                "matrix_complete": True,
            }
        ).decode("ascii"),
        end="",
    )
    return 0


def main() -> int:
    try:
        return _run(_parser().parse_args())
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"validation-scaling evidence validation failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
