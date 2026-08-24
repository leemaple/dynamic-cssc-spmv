"""Closed projection from an accepted synthetic Day 1A suite.

The projection does not reinterpret predicted counts as measurements.  It
binds every fixed-candidate count record and derives the exact rotation-index
union needed by a later Day 2 profile-policy review.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import fields
from pathlib import Path, PurePosixPath

from .metrics import StrategyMetrics
from .report import (
    CAUSAL_MEASUREMENT_KIND,
    CAUSAL_SCHEMA,
    CAUSAL_STATE_MODEL,
    validate_causal_payload,
)

COUNT_BUNDLE_FILENAME = "DAY1A_COUNT_BUNDLE.json"
ROTATION_INVENTORY_FILENAME = "DAY1A_ROTATION_INVENTORY.json"
AUTHORITY_RECEIPT_FILENAME = "DAY1A_AUTHORITY_RECEIPT.json"

COUNT_BUNDLE_SCHEMA = "dynamic-cssc-day1a-count-bundle-v1"
ROTATION_INVENTORY_SCHEMA = "dynamic-cssc-day1a-rotation-inventory-v1"
AUTHORITY_RECEIPT_SCHEMA = "dynamic-cssc-day1a-authority-receipt-v1"
EVIDENCE_SCOPE = "synthetic-causal-count-and-exact-rotation-inventory-only"

_NUMERIC_METRIC_FIELDS = tuple(
    field.name
    for field in fields(StrategyMetrics)
    if field.name not in {"strategy", "category", "source"}
)
_LOWER_GIT_SHA_LENGTH = 40
_LOWER_SHA256_LENGTH = 64


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _strict_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a strict nonnegative integer")
    return value


def _strict_positive_int(value: object, field: str) -> int:
    value = _strict_nonnegative_int(value, field)
    if value == 0:
        raise ValueError(f"{field} must be positive")
    return value


def _load_json(path: Path, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} must be readable UTF-8 JSON") from error
    if type(value) is not dict:
        raise ValueError(f"{field} must be a JSON object")
    return value


def _strict_string_list(value: object, field: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise ValueError(f"{field} must be a list of nonempty strings")
    strings = list(value)
    if strings != sorted(set(strings)):
        raise ValueError(f"{field} must be sorted and unique")
    return strings


def _safe_cell_metrics_path(suite_dir: Path, cell_id: str) -> Path:
    relative = PurePosixPath(cell_id)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != cell_id
    ):
        raise ValueError("Day1A cell_id must be a canonical safe relative POSIX path")
    current = suite_dir
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Day1A cell paths must not contain symlinks")
    metrics_path = current / "metrics.json"
    if metrics_path.is_symlink() or not metrics_path.is_file():
        raise ValueError(f"Day1A metrics file is missing or unsafe: {cell_id}")
    return metrics_path


def _fixed_record_projection(
    record: dict[str, object],
    *,
    cell_id: str,
    metrics_sha256: str,
) -> tuple[dict[str, object], Counter[int]]:
    if record.get("record_kind") != "fixed-candidate":
        raise ValueError("Day1A projection accepts only fixed-candidate records")
    candidate_id = record.get("candidate_id")
    candidate_role = record.get("candidate_role")
    if type(candidate_id) is not str or not candidate_id:
        raise ValueError("fixed Day1A record candidate_id must be nonempty")
    if candidate_role not in {"reference", "ablation"}:
        raise ValueError("fixed Day1A record candidate_role must be frozen")

    counts = {
        field: _strict_nonnegative_int(record.get(field), f"{cell_id}.{candidate_id}.{field}")
        for field in _NUMERIC_METRIC_FIELDS
    }
    inventory = record.get("rotation_inventory")
    if type(inventory) is not dict or set(inventory) != {
        "measured_counts_by_exact_index",
        "required_indices",
    }:
        raise ValueError("fixed Day1A rotation inventory keys must be exact")
    raw_required = inventory["required_indices"]
    if type(raw_required) is not list or any(
        type(index) is not int or index == 0 for index in raw_required
    ):
        raise ValueError("fixed Day1A required rotation indices must be exact nonzero integers")
    required = list(raw_required)
    if required != sorted(set(required)):
        raise ValueError("fixed Day1A required rotation indices must be canonical")

    raw_measured = inventory["measured_counts_by_exact_index"]
    if type(raw_measured) is not list:
        raise ValueError("fixed Day1A measured rotation counts must be a list")
    measured = Counter()
    measured_rows: list[list[int]] = []
    for ordinal, item in enumerate(raw_measured):
        if type(item) is not list or len(item) != 2:
            raise ValueError(f"fixed Day1A measured rotation row {ordinal} must be a pair")
        index, count = item
        if type(index) is not int or index == 0:
            raise ValueError("fixed Day1A measured rotation index must be a nonzero integer")
        count = _strict_positive_int(count, "fixed Day1A measured rotation count")
        if index in measured:
            raise ValueError("fixed Day1A measured rotation indices must be unique")
        measured[index] = count
        measured_rows.append([index, count])
    if measured_rows != sorted(measured_rows) or not set(measured).issubset(required):
        raise ValueError("fixed Day1A measured rotation inventory is not canonical")
    if sum(measured.values()) != counts["rotations"]:
        raise ValueError("fixed Day1A rotation inventory does not reconcile with rotations")

    return (
        {
            "candidate_id": candidate_id,
            "candidate_role": candidate_role,
            "cell_id": cell_id,
            "metrics_json_sha256": metrics_sha256,
            "metric_counts": counts,
            "rotation_inventory": {
                "measured_counts_by_exact_index": measured_rows,
                "required_indices": required,
            },
        },
        measured,
    )


def export_day1a_evidence(
    *,
    suite_dir: Path,
    source_git_sha: str,
    publication_rows: int,
    publication_cols: int,
    publication_effective_slots: int,
    publication_partition_rows: int,
) -> dict[str, object]:
    """Write the canonical count bundle, rotation inventory, and scoped receipt."""

    if not isinstance(suite_dir, Path) or not suite_dir.is_dir() or suite_dir.is_symlink():
        raise ValueError("suite_dir must be a regular directory")
    if not _is_lower_hex(source_git_sha, _LOWER_GIT_SHA_LENGTH):
        raise ValueError("source_git_sha must be an exact lowercase 40-hex commit SHA")
    publication_rows = _strict_positive_int(publication_rows, "publication_rows")
    publication_cols = _strict_positive_int(publication_cols, "publication_cols")
    publication_effective_slots = _strict_positive_int(
        publication_effective_slots, "publication_effective_slots"
    )
    publication_partition_rows = _strict_positive_int(
        publication_partition_rows, "publication_partition_rows"
    )
    if publication_partition_rows > publication_effective_slots:
        raise ValueError("publication_partition_rows must not exceed effective slots")
    output_paths = tuple(
        suite_dir / filename
        for filename in (
            COUNT_BUNDLE_FILENAME,
            ROTATION_INVENTORY_FILENAME,
            AUTHORITY_RECEIPT_FILENAME,
        )
    )
    if any(path.exists() for path in output_paths):
        raise ValueError("Day1A export targets must be absent")

    status_path = suite_dir / "SUITE_STATUS.json"
    status = _load_json(status_path, "SUITE_STATUS.json")
    required_status = {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "suite_complete": True,
        "complete_reference_set": True,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "source_git_sha": source_git_sha,
    }
    if any(
        type(status.get(key)) is not type(value) or status.get(key) != value
        for key, value in required_status.items()
    ):
        raise ValueError("SUITE_STATUS.json does not satisfy the closed Day1A export gate")
    candidate_ids = _strict_string_list(status.get("candidate_ids"), "candidate_ids")
    reference_candidate_ids = _strict_string_list(
        status.get("reference_candidate_ids"),
        "reference_candidate_ids",
    )
    ablation_candidate_ids = _strict_string_list(
        status.get("ablation_candidate_ids"),
        "ablation_candidate_ids",
    )
    if set(candidate_ids) != set(reference_candidate_ids) | set(ablation_candidate_ids):
        raise ValueError("Day1A candidate roles do not form the exact fixed set")
    if set(reference_candidate_ids) & set(ablation_candidate_ids):
        raise ValueError("Day1A reference and ablation roles must be disjoint")
    if (len(candidate_ids), len(reference_candidate_ids), len(ablation_candidate_ids)) != (
        14,
        13,
        1,
    ):
        raise ValueError("Day1A candidate roles must have the exact 14/13/1 topology")
    for field, expected in (
        ("fixed_candidate_count", 14),
        ("reference_candidate_count", 13),
        ("ablation_candidate_count", 1),
    ):
        if type(status.get(field)) is not int or status.get(field) != expected:
            raise ValueError(f"SUITE_STATUS.json {field} must equal {expected}")
    effective_slots = _strict_positive_int(status.get("effective_slots"), "effective_slots")
    partition_rows = _strict_positive_int(status.get("partition_rows"), "partition_rows")
    if partition_rows > effective_slots:
        raise ValueError("Day1A partition_rows must not exceed effective_slots")
    cell_ids = _strict_string_list(status.get("cell_ids"), "cell_ids")
    if _strict_positive_int(status.get("cells_completed"), "cells_completed") != len(cell_ids):
        raise ValueError("Day1A cell_ids do not reconcile with cells_completed")
    for field in ("experiment_plan_sha256", "manifest_sha256"):
        if not _is_lower_hex(status.get(field), _LOWER_SHA256_LENGTH):
            raise ValueError(f"SUITE_STATUS.json {field} must be a lowercase SHA-256")

    count_records: list[dict[str, object]] = []
    total_rotations: Counter[int] = Counter()
    required_by_candidate: dict[str, set[int]] = defaultdict(set)
    observed_matrix_dimensions: set[tuple[int, int]] = set()
    for cell_id in cell_ids:
        metrics_path = _safe_cell_metrics_path(suite_dir, cell_id)
        metrics_content = metrics_path.read_bytes()
        metrics_sha256 = _sha256(metrics_content)
        payload = _load_json(metrics_path, f"{cell_id}/metrics.json")
        validate_causal_payload(payload)
        metadata = payload.get("metadata")
        if type(metadata) is not dict:
            raise ValueError("Day1A metrics metadata must be an object")
        rows = _strict_positive_int(metadata.get("rows"), f"{cell_id}.metadata.rows")
        cols = _strict_positive_int(metadata.get("cols"), f"{cell_id}.metadata.cols")
        if (
            _strict_positive_int(
                metadata.get("effective_slots"),
                f"{cell_id}.metadata.effective_slots",
            )
            != effective_slots
            or _strict_positive_int(
                metadata.get("partition_rows"),
                f"{cell_id}.metadata.partition_rows",
            )
            != partition_rows
        ):
            raise ValueError("Day1A cell layout domain contradicts SUITE_STATUS.json")
        observed_matrix_dimensions.add((rows, cols))
        records = payload.get("records")
        if type(records) is not list:
            raise ValueError("Day1A metrics records must be a list")
        fixed_records = [
            record
            for record in records
            if type(record) is dict and record.get("record_kind") == "fixed-candidate"
        ]
        if len(fixed_records) != len(candidate_ids):
            raise ValueError("each Day1A cell must contain every fixed candidate exactly once")
        projected_by_id: dict[str, dict[str, object]] = {}
        for record in fixed_records:
            projected, measured = _fixed_record_projection(
                record,
                cell_id=cell_id,
                metrics_sha256=metrics_sha256,
            )
            candidate_id = str(projected["candidate_id"])
            if candidate_id in projected_by_id:
                raise ValueError("Day1A cell contains a duplicate fixed candidate")
            expected_role = "ablation" if candidate_id in ablation_candidate_ids else "reference"
            if projected["candidate_role"] != expected_role:
                raise ValueError("Day1A fixed record role contradicts the registered role set")
            projected_by_id[candidate_id] = projected
            total_rotations.update(measured)
            required = projected["rotation_inventory"]["required_indices"]  # type: ignore[index]
            required_by_candidate[candidate_id].update(required)  # type: ignore[arg-type]
        if sorted(projected_by_id) != candidate_ids:
            raise ValueError("Day1A fixed records do not match the registered candidate set")
        count_records.extend(projected_by_id[candidate_id] for candidate_id in candidate_ids)

    if len(observed_matrix_dimensions) != 1:
        raise ValueError("all Day1A cells must use one exact matrix domain")
    rows, cols = next(iter(observed_matrix_dimensions))

    count_bundle: dict[str, object] = {
        "schema_version": COUNT_BUNDLE_SCHEMA,
        "source_git_sha": source_git_sha,
        "suite_status_sha256": _sha256(status_path.read_bytes()),
        "experiment_plan_sha256": status["experiment_plan_sha256"],
        "manifest_sha256": status["manifest_sha256"],
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "state_model": CAUSAL_STATE_MODEL,
        "evidence_scope": EVIDENCE_SCOPE,
        "rows": rows,
        "cols": cols,
        "effective_slots": effective_slots,
        "partition_rows": partition_rows,
        "candidate_ids": candidate_ids,
        "reference_candidate_ids": reference_candidate_ids,
        "ablation_candidate_ids": ablation_candidate_ids,
        "metric_count_fields": list(_NUMERIC_METRIC_FIELDS),
        "cell_count": len(cell_ids),
        "fixed_record_count": len(count_records),
        "records": count_records,
    }
    count_bundle_bytes = _canonical_json_bytes(count_bundle)
    count_bundle_sha256 = _sha256(count_bundle_bytes)

    required_indices = sorted(set().union(*required_by_candidate.values()))
    indices_in_range = all(
        -(effective_slots - 1) <= index <= effective_slots - 1 for index in required_indices
    )
    modulo_alias_free = len({index % effective_slots for index in required_indices}) == len(
        required_indices
    )
    publication_domain_match = (
        rows,
        cols,
        effective_slots,
        partition_rows,
    ) == (
        publication_rows,
        publication_cols,
        publication_effective_slots,
        publication_partition_rows,
    )
    direct_key_plan_eligible = (
        bool(required_indices)
        and indices_in_range
        and modulo_alias_free
        and publication_domain_match
    )
    rotation_inventory: dict[str, object] = {
        "schema_version": ROTATION_INVENTORY_SCHEMA,
        "source_git_sha": source_git_sha,
        "count_bundle_sha256": count_bundle_sha256,
        "rows": rows,
        "cols": cols,
        "effective_slots": effective_slots,
        "partition_rows": partition_rows,
        "publication_rows": publication_rows,
        "publication_cols": publication_cols,
        "publication_effective_slots": publication_effective_slots,
        "publication_partition_rows": publication_partition_rows,
        "publication_domain_match": publication_domain_match,
        "indices_in_range": indices_in_range,
        "modulo_alias_free": modulo_alias_free,
        "day2_direct_key_plan_eligible": direct_key_plan_eligible,
        "required_exact_indices": required_indices,
        "measured_counts_by_exact_index": [
            [index, total_rotations[index]] for index in sorted(total_rotations)
        ],
        "candidate_required_exact_indices": [
            {
                "candidate_id": candidate_id,
                "required_exact_indices": sorted(required_by_candidate[candidate_id]),
            }
            for candidate_id in candidate_ids
        ],
    }
    rotation_inventory_bytes = _canonical_json_bytes(rotation_inventory)
    rotation_inventory_sha256 = _sha256(rotation_inventory_bytes)

    receipt: dict[str, object] = {
        "schema_version": AUTHORITY_RECEIPT_SCHEMA,
        "status": "pass",
        "evidence_scope": EVIDENCE_SCOPE,
        "source_git_sha": source_git_sha,
        "suite_status_sha256": count_bundle["suite_status_sha256"],
        "count_bundle_schema_version": COUNT_BUNDLE_SCHEMA,
        "count_bundle_sha256": count_bundle_sha256,
        "rotation_inventory_schema_version": ROTATION_INVENTORY_SCHEMA,
        "rotation_inventory_sha256": rotation_inventory_sha256,
        "cell_count": len(cell_ids),
        "fixed_record_count": len(count_records),
        "day1a_count_evidence_authorized": True,
        "day2_direct_key_plan_authorized": direct_key_plan_eligible,
        "publication_domain_match": publication_domain_match,
        "complete_cost_claim_allowed": False,
        "formal_performance_claim_allowed": False,
        "paper_verdict_allowed": False,
        "security_claim_allowed": False,
    }
    receipt_bytes = _canonical_json_bytes(receipt)

    for path, content in zip(
        output_paths,
        (count_bundle_bytes, rotation_inventory_bytes, receipt_bytes),
        strict=True,
    ):
        path.write_bytes(content)
    return receipt


__all__ = (
    "AUTHORITY_RECEIPT_FILENAME",
    "AUTHORITY_RECEIPT_SCHEMA",
    "COUNT_BUNDLE_FILENAME",
    "COUNT_BUNDLE_SCHEMA",
    "EVIDENCE_SCOPE",
    "ROTATION_INVENTORY_FILENAME",
    "ROTATION_INVENTORY_SCHEMA",
    "export_day1a_evidence",
)
