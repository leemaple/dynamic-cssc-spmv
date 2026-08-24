from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, fields, replace
from math import isfinite
from pathlib import Path
from typing import Literal

from .day1_registry import (
    CandidateRole,
    Day1CandidateCatalog,
    repository_day1_candidate_catalog,
)
from .metrics import StrategyMetrics, UnitCosts
from .simulator import RotationInventory

CAUSAL_SCHEMA = "day1-causal-predicted-v2"
CAUSAL_COMPLETION_PROOF_SCHEMA = "day1-causal-completion-proof-v1"
CAUSAL_STATE_MODEL = "persistent-strategy-snapshots"
CAUSAL_MEASUREMENT_KIND = "predicted-proxy"
CAUSAL_DISCLOSURE = (
    "Predicted synthetic proxy; bandwidth dimension deferred; "
    "complete_reference_set=true; performance/security gates remain HOLD."
)
CausalRecordKind = Literal["fixed-candidate", "tuned-fixed-policy", "diagnostic-oracle"]
_CAUSAL_RECORD_KINDS = {
    "fixed-candidate",
    "tuned-fixed-policy",
    "diagnostic-oracle",
}
_CAUSAL_LABELS = {
    "tuned-fixed-policy": "TunedFixedPolicy",
    "diagnostic-oracle": "BestFixed-Offline-Oracle",
}
_CAUSAL_SELECTION_SOURCES = {
    "fixed-candidate": "fixed-candidate",
    "tuned-fixed-policy": "tuning-prefix-only",
    "diagnostic-oracle": "held-out-hindsight-diagnostic-only",
}
_CAUSAL_METRIC_IDENTITY = {
    "fixed-candidate": (None, "reference", "persistent-state-predicted"),
    "tuned-fixed-policy": (
        "TunedFixedPolicy",
        "tuned-fixed-policy",
        "tuning-prefix-frozen",
    ),
    "diagnostic-oracle": (
        "BestFixed-Offline-Oracle",
        "diagnostic-oracle",
        "held-out-hindsight-diagnostic",
    ),
}
_CAUSAL_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "state_model",
        "measurement_kind",
        "complete_reference_set",
        "gate_eligible",
        "complete_cost_claim_allowed",
        "security_claim_allowed",
        "formal_performance_claim",
        "unit_costs",
        "tuning_aggregates",
        "metadata",
        "records",
        "completion_proof",
    }
)
_UNIT_COST_KEYS = frozenset(field.name for field in fields(UnitCosts))
_STRATEGY_METRIC_KEYS = frozenset(field.name for field in fields(StrategyMetrics))
_TUNING_AGGREGATE_KEYS = frozenset({"candidate_id", "metrics", "score"})
_ROTATION_INVENTORY_KEYS = frozenset({"measured_counts_by_exact_index", "required_indices"})
_FIXED_ROTATION_PROOF_KEYS = frozenset(
    {"candidate_id", "measured_counts_by_exact_index", "required_indices"}
)
_ACCOUNTING_INVARIANTS = (
    "metadata_units=ci_patch_entries+ci_full_sync_entries",
    "update_encryptions=update_ciphertexts+compaction_ciphertexts",
    "query_ciphertexts=cc_multiplications=relinearizations",
    "result_ciphertexts=decryptions",
    "blinding_encryptions=blinding_mask_ciphertexts+blinding_dummy_ciphertexts",
    "blinding_additions=blinding_encryptions",
    "rotations=sum(measured_counts_by_exact_index)",
)
_COMPLETION_PROOF_KEYS = frozenset(
    {
        "schema",
        "registration",
        "complete_reference_set",
        "fixed_candidate_count",
        "reference_candidate_count",
        "ablation_candidate_count",
        "tuning_candidate_count",
        "record_count",
        "fixed_candidate_ids",
        "reference_candidate_ids",
        "ablation_candidate_ids",
        "tuning_candidate_ids",
        "fixed_rotation_inventories",
        "accounting_invariants",
    }
)
_DERIVED_METRIC_RECORD_KEYS = frozenset(
    {
        "predicted_update_time",
        "predicted_query_time",
        "predicted_query_time_per_query",
        "predicted_normalized_time",
        "update_ct_equivalents_per_update",
    }
)
_CAUSAL_RECORD_ENVELOPE_KEYS = frozenset(
    {
        "schema",
        "state_model",
        "measurement_kind",
        "complete_reference_set",
        "gate_eligible",
        "complete_cost_claim_allowed",
        "security_claim_allowed",
        "formal_performance_claim",
        "unit_cost_model",
        "record_kind",
        "candidate_id",
        "label",
        "strategy_kind",
        "phase",
        "selection_source",
        "candidate_role",
        "rotation_inventory",
    }
)
_FLAT_UNIT_COST_KEYS = frozenset(f"unit_cost_{field_name}" for field_name in _UNIT_COST_KEYS)
_CAUSAL_RECORD_KEYS = (
    _STRATEGY_METRIC_KEYS
    | _DERIVED_METRIC_RECORD_KEYS
    | _CAUSAL_RECORD_ENVELOPE_KEYS
    | _FLAT_UNIT_COST_KEYS
)
_CAUSAL_METADATA_REQUIRED_KEYS = frozenset(
    {
        "state_model",
        "measurement_kind",
        "complete_reference_set",
        "gate_eligible",
        "complete_cost_claim_allowed",
        "security_claim_allowed",
        "formal_performance_claim",
        "fixed_candidate_count",
        "reference_candidate_count",
        "ablation_candidate_count",
        "selected_candidate_id",
        "oracle_candidate_id",
    }
)
CAUSAL_ARTIFACT_FILENAMES = (
    "metrics.json",
    "metrics.csv",
    "tuning_aggregates.csv",
    "SUMMARY.md",
    "ua_vs_qa_proxy.png",
    "t_rho_proxy.png",
)


@dataclass(frozen=True, slots=True)
class _DecodedCausalPayload:
    records: tuple[CausalMetricRecord, ...]
    costs: UnitCosts
    tuning_results: dict[str, StrategyMetrics]
    metadata: dict[str, object]
    selected_candidate_id: str
    oracle_candidate_id: str
    candidate_catalog: Day1CandidateCatalog


def _require_exact_dict(value: object, field_name: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError(f"{field_name} must be an exact object")
    return value


def _require_exact_list(value: object, field_name: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(f"{field_name} must be an exact array")
    return value


def _validate_json_value(value: object, field_name: str) -> None:
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not isfinite(value):
            raise ValueError(f"{field_name} must be finite")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_json_value(item, f"{field_name}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError(f"{field_name} keys must be exact str values")
            _validate_json_value(item, f"{field_name}.{key}")
        return
    raise TypeError(f"{field_name} contains a non-JSON value")


def _require_exact_keys(
    value: dict[str, object],
    expected: frozenset[str],
    field_name: str,
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise ValueError(f"{field_name} keys mismatch; missing={missing}, extra={extra}")


def _catalog_role_ids(
    candidate_catalog: Day1CandidateCatalog,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if type(candidate_catalog) is not Day1CandidateCatalog:
        raise TypeError("candidate_catalog must be an exact Day1CandidateCatalog")
    fixed_ids = tuple(sorted(candidate.candidate_id for candidate in candidate_catalog.candidates))
    reference_ids = tuple(
        sorted(candidate.candidate_id for candidate in candidate_catalog.selection_candidates)
    )
    ablation_ids = tuple(
        sorted(candidate.candidate_id for candidate in candidate_catalog.ablation_candidates)
    )
    if len(fixed_ids) != 14 or len(set(fixed_ids)) != 14:
        raise ValueError("candidate catalog must contain exactly 14 unique fixed candidates")
    if len(reference_ids) != 13 or len(set(reference_ids)) != 13:
        raise ValueError("candidate catalog must contain exactly 13 unique references")
    if len(ablation_ids) != 1 or len(set(ablation_ids)) != 1:
        raise ValueError("candidate catalog must contain exactly one ablation")
    if set(reference_ids).isdisjoint(ablation_ids) and set(fixed_ids) == (
        set(reference_ids) | set(ablation_ids)
    ):
        return fixed_ids, reference_ids, ablation_ids
    raise ValueError("candidate catalog roles must partition the fixed candidates exactly")


def _repository_candidate_catalog() -> Day1CandidateCatalog:
    candidate_catalog = repository_day1_candidate_catalog()
    if type(candidate_catalog) is not Day1CandidateCatalog:
        raise TypeError("repository Day-1 candidate catalog has the wrong type")
    _catalog_role_ids(candidate_catalog)
    return candidate_catalog


def _decode_unit_costs(value: object) -> UnitCosts:
    serialized = _require_exact_dict(value, "unit_costs")
    _require_exact_keys(serialized, _UNIT_COST_KEYS, "unit_costs")
    costs = UnitCosts(**serialized)
    _serialize_unit_costs(costs)
    frozen_costs = asdict(UnitCosts())
    for field_name, expected in frozen_costs.items():
        actual = serialized[field_name]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(
                f"unit_costs.{field_name} does not match the frozen UnitCosts() vector"
            )
    return costs


def _decode_strategy_metrics(value: object, field_name: str) -> StrategyMetrics:
    serialized = _require_exact_dict(value, field_name)
    _require_exact_keys(serialized, _STRATEGY_METRIC_KEYS, field_name)
    metrics = StrategyMetrics(**serialized)
    for identity_field in ("strategy", "category", "source"):
        _require_nonempty_exact_str(
            getattr(metrics, identity_field),
            f"{field_name}.{identity_field}",
        )
    _validate_metrics_numbers(metrics)
    _validate_metrics_accounting(metrics)
    return metrics


def _decode_rotation_inventory(value: object, field_name: str) -> RotationInventory:
    serialized = _require_exact_dict(value, field_name)
    _require_exact_keys(serialized, _ROTATION_INVENTORY_KEYS, field_name)
    measured_items = _require_exact_list(
        serialized["measured_counts_by_exact_index"],
        f"{field_name}.measured_counts_by_exact_index",
    )
    measured: list[tuple[int, int]] = []
    for index, value_item in enumerate(measured_items):
        item_name = f"{field_name}.measured_counts_by_exact_index[{index}]"
        item = _require_exact_list(value_item, item_name)
        if len(item) != 2 or any(type(part) is not int for part in item):
            raise TypeError(f"{item_name} must contain two exact integers")
        measured.append((item[0], item[1]))
    required_items = _require_exact_list(
        serialized["required_indices"],
        f"{field_name}.required_indices",
    )
    if any(type(index) is not int for index in required_items):
        raise TypeError(f"{field_name}.required_indices must contain exact integers")
    try:
        return RotationInventory(tuple(measured), tuple(required_items))
    except ValueError as error:
        raise ValueError(f"{field_name} is not canonical and complete") from error


def _rotation_inventory_payload(inventory: RotationInventory) -> dict[str, object]:
    if type(inventory) is not RotationInventory:
        raise TypeError("rotation_inventory must be RotationInventory")
    return {
        "measured_counts_by_exact_index": [
            [index, count] for index, count in inventory.measured_counts_by_exact_index
        ],
        "required_indices": list(inventory.required_indices),
    }


def _require_finite_number(value: object, field_name: str) -> int | float:
    if type(value) not in (int, float):
        raise TypeError(f"{field_name} must be an exact finite number")
    if not isfinite(value) or value < 0:
        raise ValueError(f"{field_name} must be finite and nonnegative")
    return value


def _decode_tuning_aggregates(
    value: object,
    costs: UnitCosts,
    canonical_candidate_ids: tuple[str, ...],
) -> dict[str, StrategyMetrics]:
    serialized_items = _require_exact_list(value, "tuning_aggregates")
    if len(serialized_items) != 13:
        raise ValueError("tuning_aggregates must contain exactly 13 entries")
    decoded: dict[str, StrategyMetrics] = {}
    serialized_ids: list[str] = []
    for index, value_item in enumerate(serialized_items):
        field_name = f"tuning_aggregates[{index}]"
        item = _require_exact_dict(value_item, field_name)
        _require_exact_keys(item, _TUNING_AGGREGATE_KEYS, field_name)
        candidate_id = item["candidate_id"]
        _require_nonempty_exact_str(candidate_id, f"{field_name}.candidate_id")
        metrics = _decode_strategy_metrics(item["metrics"], f"{field_name}.metrics")
        score = _require_finite_number(item["score"], f"{field_name}.score")
        recomputed_score = metrics.predicted_time(costs)
        if type(score) is not type(recomputed_score) or score != recomputed_score:
            raise ValueError(f"{field_name}.score does not match reconstructed metrics")
        serialized_ids.append(candidate_id)
        decoded[candidate_id] = metrics
    if tuple(serialized_ids) != canonical_candidate_ids:
        raise ValueError("tuning_aggregates candidate_ids must equal canonical sorted IDs")
    return decoded


def _decode_causal_records(
    value: object,
    costs: UnitCosts,
    candidate_catalog: Day1CandidateCatalog,
) -> list[CausalMetricRecord]:
    fixed_candidate_ids, _reference_ids, _ablation_ids = _catalog_role_ids(candidate_catalog)
    serialized_records = _require_exact_list(value, "records")
    if len(serialized_records) != 16:
        raise ValueError("records must contain exactly 16 entries")
    decoded: list[CausalMetricRecord] = []
    for index, value_record in enumerate(serialized_records):
        field_name = f"records[{index}]"
        record = _require_exact_dict(value_record, field_name)
        _require_exact_keys(record, _CAUSAL_RECORD_KEYS, field_name)
        metrics = _decode_strategy_metrics(
            {key: record[key] for key in _STRATEGY_METRIC_KEYS},
            f"{field_name}.metrics",
        )
        rotation_inventory = _decode_rotation_inventory(
            record["rotation_inventory"],
            f"{field_name}.rotation_inventory",
        )
        item = CausalMetricRecord(
            record_kind=record["record_kind"],
            candidate_id=record["candidate_id"],
            label=record["label"],
            strategy_kind=record["strategy_kind"],
            selection_source=record["selection_source"],
            metrics=metrics,
            candidate_role=record["candidate_role"],
            rotation_inventory=rotation_inventory,
            phase=record["phase"],
            gate_eligible=record["gate_eligible"],
            complete_cost_claim_allowed=record["complete_cost_claim_allowed"],
            security_claim_allowed=record["security_claim_allowed"],
            formal_performance_claim=record["formal_performance_claim"],
        )
        expected_record = _causal_record(item, costs)
        for key, expected in expected_record.items():
            actual = record[key]
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError(f"{field_name}.{key} does not match recomputed value")
        decoded.append(item)

    _validate_causal_record_set(decoded, candidate_catalog)
    fixed_ids = tuple(
        item.candidate_id for item in decoded if item.record_kind == "fixed-candidate"
    )
    if fixed_ids != fixed_candidate_ids:
        raise ValueError("fixed record candidate_ids must equal the registered sorted IDs")
    if decoded[-2].record_kind != "tuned-fixed-policy":
        raise ValueError("records[14] must be the tuned-fixed-policy alias")
    if decoded[-1].record_kind != "diagnostic-oracle":
        raise ValueError("records[15] must be the diagnostic-oracle alias")
    return decoded


def _require_exact_value(actual: object, expected: object, field_name: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f"{field_name} does not match the causal schema")


def _decode_causal_metadata(
    value: object,
    candidate_catalog: Day1CandidateCatalog,
) -> tuple[str, str]:
    fixed_candidate_ids, reference_candidate_ids, _ablation_candidate_ids = _catalog_role_ids(
        candidate_catalog
    )
    metadata = _require_exact_dict(value, "metadata")
    missing = sorted(_CAUSAL_METADATA_REQUIRED_KEYS - set(metadata))
    if missing:
        raise ValueError(f"metadata keys mismatch; missing={missing}")
    for field_name, expected in (
        ("state_model", CAUSAL_STATE_MODEL),
        ("measurement_kind", CAUSAL_MEASUREMENT_KIND),
        ("complete_reference_set", True),
        ("gate_eligible", False),
        ("complete_cost_claim_allowed", False),
        ("security_claim_allowed", False),
        ("formal_performance_claim", False),
        ("fixed_candidate_count", 14),
        ("reference_candidate_count", 13),
        ("ablation_candidate_count", 1),
    ):
        _require_exact_value(metadata[field_name], expected, f"metadata.{field_name}")
    selected_candidate_id = metadata["selected_candidate_id"]
    oracle_candidate_id = metadata["oracle_candidate_id"]
    _require_nonempty_exact_str(selected_candidate_id, "metadata.selected_candidate_id")
    _require_nonempty_exact_str(oracle_candidate_id, "metadata.oracle_candidate_id")
    if selected_candidate_id not in reference_candidate_ids:
        raise ValueError("metadata.selected_candidate_id is not a selectable reference")
    if oracle_candidate_id not in reference_candidate_ids:
        raise ValueError("metadata.oracle_candidate_id is not a reference candidate")
    span80_by_candidate = metadata.get("span80_by_candidate")
    if span80_by_candidate is not None:
        span80 = _require_exact_dict(span80_by_candidate, "metadata.span80_by_candidate")
        if tuple(sorted(span80)) != fixed_candidate_ids:
            raise ValueError("metadata.span80_by_candidate keys must equal registered fixed IDs")
    return selected_candidate_id, oracle_candidate_id


def _completion_proof_payload(
    records: Iterable[CausalMetricRecord],
    tuning_candidate_ids: Iterable[str],
    candidate_catalog: Day1CandidateCatalog,
) -> dict[str, object]:
    fixed_candidate_ids, reference_candidate_ids, ablation_candidate_ids = _catalog_role_ids(
        candidate_catalog
    )
    records_tuple = tuple(records)
    fixed_by_candidate = {
        item.candidate_id: item for item in records_tuple if item.record_kind == "fixed-candidate"
    }
    canonical_tuning_ids = tuple(sorted(tuning_candidate_ids))
    return {
        "schema": CAUSAL_COMPLETION_PROOF_SCHEMA,
        "registration": asdict(candidate_catalog.registration),
        "complete_reference_set": True,
        "fixed_candidate_count": 14,
        "reference_candidate_count": 13,
        "ablation_candidate_count": 1,
        "tuning_candidate_count": 13,
        "record_count": 16,
        "fixed_candidate_ids": list(fixed_candidate_ids),
        "reference_candidate_ids": list(reference_candidate_ids),
        "ablation_candidate_ids": list(ablation_candidate_ids),
        "tuning_candidate_ids": list(canonical_tuning_ids),
        "fixed_rotation_inventories": [
            {
                "candidate_id": candidate_id,
                **_rotation_inventory_payload(fixed_by_candidate[candidate_id].rotation_inventory),
            }
            for candidate_id in fixed_candidate_ids
        ],
        "accounting_invariants": list(_ACCOUNTING_INVARIANTS),
    }


def _require_exact_json_tree(actual: object, expected: object, field_name: str) -> None:
    if type(actual) is not type(expected):
        raise ValueError(f"{field_name} has a noncanonical JSON type")
    if type(expected) is dict:
        actual_dict = _require_exact_dict(actual, field_name)
        expected_dict = _require_exact_dict(expected, field_name)
        _require_exact_keys(actual_dict, frozenset(expected_dict), field_name)
        for key, expected_value in expected_dict.items():
            _require_exact_json_tree(
                actual_dict[key],
                expected_value,
                f"{field_name}.{key}",
            )
        return
    if type(expected) is list:
        actual_list = _require_exact_list(actual, field_name)
        expected_list = _require_exact_list(expected, field_name)
        if len(actual_list) != len(expected_list):
            raise ValueError(f"{field_name} has the wrong length")
        for index, (actual_item, expected_item) in enumerate(
            zip(actual_list, expected_list, strict=True)
        ):
            _require_exact_json_tree(
                actual_item,
                expected_item,
                f"{field_name}[{index}]",
            )
        return
    if actual != expected:
        raise ValueError(f"{field_name} does not match the completion proof")


def _decode_completion_proof(
    value: object,
    records: list[CausalMetricRecord],
    tuning_candidate_ids: Iterable[str],
    candidate_catalog: Day1CandidateCatalog,
) -> None:
    proof = _require_exact_dict(value, "completion_proof")
    _require_exact_keys(proof, _COMPLETION_PROOF_KEYS, "completion_proof")
    rotation_items = _require_exact_list(
        proof["fixed_rotation_inventories"],
        "completion_proof.fixed_rotation_inventories",
    )
    for index, value_item in enumerate(rotation_items):
        field_name = f"completion_proof.fixed_rotation_inventories[{index}]"
        item = _require_exact_dict(value_item, field_name)
        _require_exact_keys(item, _FIXED_ROTATION_PROOF_KEYS, field_name)
        _decode_rotation_inventory(
            {
                "measured_counts_by_exact_index": item["measured_counts_by_exact_index"],
                "required_indices": item["required_indices"],
            },
            field_name,
        )
    expected = _completion_proof_payload(
        records,
        tuning_candidate_ids,
        candidate_catalog,
    )
    _require_exact_json_tree(proof, expected, "completion_proof")


def validate_causal_payload(payload: object) -> None:
    """Validate one serialized Day-1 causal payload against repository authority."""

    _decode_causal_payload(
        payload,
        candidate_catalog=_repository_candidate_catalog(),
    )


def _decode_causal_payload(
    payload: object,
    *,
    candidate_catalog: Day1CandidateCatalog,
) -> _DecodedCausalPayload:
    """Purely validate and decode one serialized Day-1 causal payload."""

    _validate_json_value(payload, "payload")
    payload_dict = _require_exact_dict(payload, "payload")
    _require_exact_keys(payload_dict, _CAUSAL_PAYLOAD_KEYS, "payload")
    for field_name, expected in (
        ("schema", CAUSAL_SCHEMA),
        ("state_model", CAUSAL_STATE_MODEL),
        ("measurement_kind", CAUSAL_MEASUREMENT_KIND),
        ("complete_reference_set", True),
        ("gate_eligible", False),
        ("complete_cost_claim_allowed", False),
        ("security_claim_allowed", False),
        ("formal_performance_claim", False),
    ):
        _require_exact_value(payload_dict[field_name], expected, field_name)
    _fixed_candidate_ids, reference_candidate_ids, _ablation_candidate_ids = _catalog_role_ids(
        candidate_catalog
    )
    costs = _decode_unit_costs(payload_dict["unit_costs"])
    tuning_by_candidate = _decode_tuning_aggregates(
        payload_dict["tuning_aggregates"],
        costs,
        reference_candidate_ids,
    )
    records = _decode_causal_records(
        payload_dict["records"],
        costs,
        candidate_catalog,
    )
    selected_candidate_id, oracle_candidate_id = _decode_causal_metadata(
        payload_dict["metadata"],
        candidate_catalog,
    )
    fixed_by_candidate = {
        item.candidate_id: item.metrics for item in records if item.record_kind == "fixed-candidate"
    }
    for candidate_id in reference_candidate_ids:
        tuning_metrics = tuning_by_candidate[candidate_id]
        fixed_metrics = fixed_by_candidate[candidate_id]
        if any(
            getattr(tuning_metrics, field_name) != getattr(fixed_metrics, field_name)
            for field_name in ("strategy", "category", "source")
        ):
            raise ValueError(
                f"tuning_aggregates candidate {candidate_id} identity does not match "
                "its fixed record"
            )
    recomputed_selected_id = min(
        (metrics.predicted_time(costs), candidate_id)
        for candidate_id, metrics in tuning_by_candidate.items()
    )[1]
    if selected_candidate_id != recomputed_selected_id:
        raise ValueError("selected_candidate_id does not match tuning_aggregates ranking")
    recomputed_oracle_id = min(
        (fixed_by_candidate[candidate_id].predicted_time(costs), candidate_id)
        for candidate_id in reference_candidate_ids
    )[1]
    if oracle_candidate_id != recomputed_oracle_id:
        raise ValueError("oracle_candidate_id does not match held-out reference ranking")
    _validate_alias_ids(records, selected_candidate_id, oracle_candidate_id)
    _decode_completion_proof(
        payload_dict["completion_proof"],
        records,
        tuning_by_candidate,
        candidate_catalog,
    )
    return _DecodedCausalPayload(
        records=tuple(records),
        costs=costs,
        tuning_results=tuning_by_candidate,
        metadata=dict(payload_dict["metadata"]),
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
        candidate_catalog=candidate_catalog,
    )


def _require_nonempty_exact_str(value: object, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be an exact str")
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_exact_false(value: object, field_name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{field_name} must be an exact bool")
    if value is not False:
        raise ValueError(f"{field_name} must be false")


def _validate_metrics_numbers(metrics: StrategyMetrics) -> None:
    for field_name, value in asdict(metrics).items():
        if field_name in {"strategy", "category", "source"}:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"metrics.{field_name} must be a finite nonnegative integer")


def _validate_metrics_accounting(metrics: StrategyMetrics) -> None:
    if metrics.update_encryptions != (metrics.update_ciphertexts + metrics.compaction_ciphertexts):
        raise ValueError(
            "metrics.update_encryptions must equal update_ciphertexts + compaction_ciphertexts"
        )
    if not (metrics.query_ciphertexts == metrics.cc_multiplications == metrics.relinearizations):
        raise ValueError(
            "metrics.query_ciphertexts, cc_multiplications, and relinearizations must be equal"
        )
    if metrics.result_ciphertexts != metrics.decryptions:
        raise ValueError("metrics.result_ciphertexts must equal decryptions")
    if metrics.blinding_encryptions != (
        metrics.blinding_mask_ciphertexts + metrics.blinding_dummy_ciphertexts
    ):
        raise ValueError(
            "metrics.blinding_encryptions must equal blinding_mask_ciphertexts + "
            "blinding_dummy_ciphertexts"
        )
    if metrics.blinding_additions != metrics.blinding_encryptions:
        raise ValueError("metrics.blinding_additions must equal blinding_encryptions")


@dataclass(frozen=True, slots=True)
class CausalMetricRecord:
    record_kind: CausalRecordKind
    candidate_id: str
    label: str
    strategy_kind: str
    selection_source: str
    metrics: StrategyMetrics
    candidate_role: CandidateRole = "reference"
    rotation_inventory: RotationInventory = RotationInventory()
    phase: Literal["held-out"] = "held-out"
    gate_eligible: Literal[False] = False
    complete_cost_claim_allowed: Literal[False] = False
    security_claim_allowed: Literal[False] = False
    formal_performance_claim: Literal[False] = False

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        for field_name in (
            "record_kind",
            "candidate_id",
            "label",
            "strategy_kind",
            "phase",
            "selection_source",
            "candidate_role",
        ):
            _require_nonempty_exact_str(getattr(self, field_name), field_name)
        _require_exact_false(self.gate_eligible, "gate_eligible")
        _require_exact_false(
            self.complete_cost_claim_allowed,
            "complete_cost_claim_allowed",
        )
        _require_exact_false(self.security_claim_allowed, "security_claim_allowed")
        _require_exact_false(
            self.formal_performance_claim,
            "formal_performance_claim",
        )
        if self.record_kind not in _CAUSAL_RECORD_KINDS:
            raise ValueError("unknown causal record_kind")
        if self.candidate_role not in {"reference", "ablation"}:
            raise ValueError("candidate_role must be reference or ablation")
        if self.record_kind != "fixed-candidate" and self.candidate_role != "reference":
            raise ValueError(f"{self.record_kind} must have candidate_role reference")
        if self.phase != "held-out":
            raise ValueError("causal record phase must be held-out")

        expected_label = (
            self.candidate_id
            if self.record_kind == "fixed-candidate"
            else _CAUSAL_LABELS[self.record_kind]
        )
        if self.label != expected_label:
            raise ValueError(f"label contradicts record_kind {self.record_kind}")
        expected_source = _CAUSAL_SELECTION_SOURCES[self.record_kind]
        if self.selection_source != expected_source:
            raise ValueError(f"selection_source contradicts record_kind {self.record_kind}")
        if not isinstance(self.metrics, StrategyMetrics):
            raise TypeError("metrics must be StrategyMetrics")
        if type(self.rotation_inventory) is not RotationInventory:
            raise TypeError("rotation_inventory must be RotationInventory")
        _validate_metrics_numbers(self.metrics)
        _validate_metrics_accounting(self.metrics)
        measured_rotation_count = sum(
            count for _index, count in self.rotation_inventory.measured_counts_by_exact_index
        )
        if measured_rotation_count != self.metrics.rotations:
            raise ValueError("rotation inventory must reconcile with metrics.rotations")
        for field_name in ("strategy", "category", "source"):
            _require_nonempty_exact_str(
                getattr(self.metrics, field_name),
                f"metrics.{field_name}",
            )

        expected_strategy, expected_category, expected_metric_source = _CAUSAL_METRIC_IDENTITY[
            self.record_kind
        ]
        if expected_strategy is None:
            expected_strategy = self.strategy_kind
            expected_category = self.candidate_role
        if self.metrics.strategy != expected_strategy:
            if self.record_kind == "fixed-candidate":
                raise ValueError("fixed-candidate strategy_kind must match metrics.strategy")
            raise ValueError(f"metrics.strategy contradicts record_kind {self.record_kind}")
        if self.metrics.category != expected_category:
            raise ValueError(f"metrics.category contradicts record_kind {self.record_kind}")
        if self.metrics.source != expected_metric_source:
            raise ValueError(f"metrics.source contradicts record_kind {self.record_kind}")


def _validate_causal_record_set(
    items: list[CausalMetricRecord],
    candidate_catalog: Day1CandidateCatalog,
) -> None:
    fixed_candidate_ids, _reference_candidate_ids, _ablation_candidate_ids = _catalog_role_ids(
        candidate_catalog
    )
    registered_by_id = {
        candidate.candidate_id: candidate for candidate in candidate_catalog.candidates
    }
    fixed_by_candidate: dict[str, CausalMetricRecord] = {}
    tuned_count = 0
    oracle_count = 0
    for item in items:
        if not isinstance(item, CausalMetricRecord):
            raise TypeError("causal records must be CausalMetricRecord instances")
        item._validate()
        if item.record_kind == "tuned-fixed-policy":
            tuned_count += 1
        elif item.record_kind == "diagnostic-oracle":
            oracle_count += 1
        if item.record_kind != "fixed-candidate":
            continue
        if item.candidate_id in fixed_by_candidate:
            raise ValueError(f"duplicate fixed-candidate candidate_id: {item.candidate_id}")
        fixed_by_candidate[item.candidate_id] = item

    if tuned_count != 1:
        raise ValueError("causal records must contain exactly one tuned-fixed-policy")
    if oracle_count != 1:
        raise ValueError("causal records must contain exactly one diagnostic-oracle")

    for item in items:
        if item.record_kind == "fixed-candidate":
            continue
        basis = fixed_by_candidate.get(item.candidate_id)
        if basis is None:
            raise ValueError(
                f"{item.record_kind} has no fixed basis candidate_id {item.candidate_id}"
            )
        if basis.candidate_role != "reference":
            raise ValueError(f"{item.record_kind} cannot use an ablation basis")
        if item.strategy_kind != basis.metrics.strategy:
            raise ValueError(
                f"{item.record_kind} basis strategy_kind does not match "
                f"fixed metrics.strategy for {item.candidate_id}"
            )
        normalized_metrics = replace(
            item.metrics,
            strategy=basis.metrics.strategy,
            category=basis.metrics.category,
            source=basis.metrics.source,
        )
        if normalized_metrics != basis.metrics:
            raise ValueError(
                f"{item.record_kind} metrics must equal its fixed basis after "
                "normalizing strategy/category/source identity"
            )
        if item.rotation_inventory != basis.rotation_inventory:
            raise ValueError(f"{item.record_kind} rotation inventory must equal its fixed basis")

    if tuple(sorted(fixed_by_candidate)) != fixed_candidate_ids:
        raise ValueError("fixed records must exactly match the registered candidate IDs")
    for candidate_id, item in fixed_by_candidate.items():
        registered = registered_by_id[candidate_id]
        if item.strategy_kind != registered.strategy:
            raise ValueError(
                f"fixed record {candidate_id} strategy_kind does not match registration"
            )
        if item.candidate_role != registered.role:
            raise ValueError(
                f"fixed record {candidate_id} candidate_role does not match registration"
            )


def _causal_record(item: CausalMetricRecord, costs: UnitCosts) -> dict[str, object]:
    record = item.metrics.to_record(costs)
    record.update(
        {
            "schema": CAUSAL_SCHEMA,
            "state_model": CAUSAL_STATE_MODEL,
            "measurement_kind": CAUSAL_MEASUREMENT_KIND,
            "complete_reference_set": True,
            "gate_eligible": item.gate_eligible,
            "complete_cost_claim_allowed": item.complete_cost_claim_allowed,
            "security_claim_allowed": item.security_claim_allowed,
            "formal_performance_claim": item.formal_performance_claim,
            "unit_cost_model": "normalized-predicted-proxy",
            "record_kind": item.record_kind,
            "candidate_id": item.candidate_id,
            "label": item.label,
            "strategy_kind": item.strategy_kind,
            "phase": item.phase,
            "selection_source": item.selection_source,
            "candidate_role": item.candidate_role,
            "rotation_inventory": _rotation_inventory_payload(item.rotation_inventory),
        }
    )
    record.update({f"unit_cost_{field_name}": value for field_name, value in asdict(costs).items()})
    return record


def _validate_tuning_selection(
    items: list[CausalMetricRecord],
    tuning_results: Mapping[str, StrategyMetrics],
    costs: UnitCosts,
    selected_candidate_id: str,
    candidate_catalog: Day1CandidateCatalog,
) -> list[dict[str, object]]:
    if not isinstance(tuning_results, Mapping):
        raise TypeError("tuning_results must be a mapping")
    fixed_by_candidate = {
        item.candidate_id: item for item in items if item.record_kind == "fixed-candidate"
    }
    fixed_candidate_ids, reference_candidate_ids, _ablation_candidate_ids = _catalog_role_ids(
        candidate_catalog
    )
    if tuple(sorted(fixed_by_candidate)) != fixed_candidate_ids:
        raise ValueError("causal report must contain exactly 14 registered fixed candidates")
    tuning_entries = list(tuning_results.items())
    tuning_ids = [candidate_id for candidate_id, _metrics in tuning_entries]
    for candidate_id in tuning_ids:
        _require_nonempty_exact_str(candidate_id, "tuning candidate_id")
    if len(tuning_ids) != len(set(tuning_ids)):
        raise ValueError("tuning_results contains duplicate candidate_id values")
    tuning_by_candidate = dict(tuning_entries)
    selectable_candidate_ids = set(reference_candidate_ids)
    tuning_candidate_ids = set(tuning_by_candidate)
    missing = sorted(selectable_candidate_ids - tuning_candidate_ids)
    extra = sorted(tuning_candidate_ids - selectable_candidate_ids)
    if missing or extra:
        raise ValueError(
            "tuning_results IDs must exactly match registered reference candidate IDs; "
            f"missing={missing}, extra={extra}"
        )
    ranked: list[tuple[float, str]] = []
    for candidate_id, metrics in tuning_entries:
        if not isinstance(metrics, StrategyMetrics):
            raise TypeError("tuning_results values must be StrategyMetrics")
        _validate_metrics_numbers(metrics)
        _validate_metrics_accounting(metrics)
        fixed_metrics = fixed_by_candidate[candidate_id].metrics
        if any(
            getattr(metrics, field_name) != getattr(fixed_metrics, field_name)
            for field_name in ("strategy", "category", "source")
        ):
            raise ValueError(
                f"tuning_results candidate {candidate_id} identity does not match its fixed basis"
            )
        score = metrics.predicted_time(costs)
        if not isfinite(score):
            raise ValueError(f"nonfinite tuning score for {candidate_id}")
        ranked.append((score, candidate_id))
    if not ranked:
        raise ValueError("tuning_results must not be empty")
    recomputed_candidate_id = min(ranked)[1]
    if selected_candidate_id != recomputed_candidate_id:
        raise ValueError("selected_candidate_id does not match the serialized tuning aggregates")
    return [
        {
            "candidate_id": candidate_id,
            "metrics": asdict(tuning_by_candidate[candidate_id]),
            "score": tuning_by_candidate[candidate_id].predicted_time(costs),
        }
        for candidate_id in sorted(tuning_by_candidate)
    ]


def _validate_oracle_selection(
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    oracle_candidate_id: str,
) -> None:
    ranked: list[tuple[float, str]] = []
    for item in items:
        if item.record_kind != "fixed-candidate" or item.candidate_role != "reference":
            continue
        score = item.metrics.predicted_time(costs)
        if not isfinite(score):
            raise ValueError(f"nonfinite held-out score for {item.candidate_id}")
        ranked.append((score, item.candidate_id))
    recomputed_candidate_id = min(ranked)[1]
    if oracle_candidate_id != recomputed_candidate_id:
        raise ValueError("oracle_candidate_id does not match the serialized held-out fixed records")


def _validate_metadata_ids(
    metadata: Mapping[str, object],
    selected_candidate_id: str,
    oracle_candidate_id: str,
) -> None:
    if not isinstance(metadata, Mapping):
        raise TypeError("metadata must be a mapping")
    fixed_candidate_count = metadata.get("fixed_candidate_count")
    if type(fixed_candidate_count) is not int or fixed_candidate_count != 14:
        raise ValueError("metadata.fixed_candidate_count must equal 14")
    canonical_fields: dict[str, object] = {
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "complete_reference_set": True,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "reference_candidate_count": 13,
        "ablation_candidate_count": 1,
    }
    for field_name, expected in canonical_fields.items():
        if field_name not in metadata:
            continue
        actual = metadata[field_name]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(f"metadata.{field_name} contradicts the causal schema")
    for field_name, expected in (
        ("selected_candidate_id", selected_candidate_id),
        ("oracle_candidate_id", oracle_candidate_id),
    ):
        if field_name not in metadata:
            raise ValueError(f"metadata.{field_name} is required")
        actual = metadata[field_name]
        _require_nonempty_exact_str(actual, f"metadata.{field_name}")
        if actual != expected:
            raise ValueError(f"metadata.{field_name} does not match writer input")


def _validate_alias_ids(
    items: list[CausalMetricRecord],
    selected_candidate_id: str,
    oracle_candidate_id: str,
) -> None:
    expected_by_kind = {
        "tuned-fixed-policy": selected_candidate_id,
        "diagnostic-oracle": oracle_candidate_id,
    }
    for item in items:
        expected = expected_by_kind.get(item.record_kind)
        if expected is not None and item.candidate_id != expected:
            raise ValueError(
                f"{item.record_kind} candidate_id does not match the reported selection"
            )


def _validate_metadata_candidate_ids(
    metadata: Mapping[str, object],
    items: list[CausalMetricRecord],
) -> None:
    span80_by_candidate = metadata.get("span80_by_candidate")
    if span80_by_candidate is None:
        return
    if not isinstance(span80_by_candidate, Mapping):
        raise TypeError("span80_by_candidate must be a mapping")
    fixed_candidate_ids = {
        item.candidate_id for item in items if item.record_kind == "fixed-candidate"
    }
    if set(span80_by_candidate) != fixed_candidate_ids:
        raise ValueError("span80_by_candidate keys must match fixed candidate_id values")


def _csv_text(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return handle.getvalue()


def _serialize_unit_costs(costs: UnitCosts) -> dict[str, object]:
    if not isinstance(costs, UnitCosts):
        raise TypeError("costs must be UnitCosts")
    serialized = asdict(costs)
    _require_nonempty_exact_str(serialized["label"], "unit costs label")
    for field_name, value in serialized.items():
        if field_name == "label":
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not isfinite(value)
            or value < 0
        ):
            raise ValueError("unit costs must contain finite nonnegative numeric values")
    return serialized


def _canonical_payload(decoded: _DecodedCausalPayload) -> dict[str, object]:
    serialized_costs = _serialize_unit_costs(decoded.costs)
    return {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "complete_reference_set": True,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "unit_costs": serialized_costs,
        "tuning_aggregates": [
            {
                "candidate_id": candidate_id,
                "metrics": asdict(decoded.tuning_results[candidate_id]),
                "score": decoded.tuning_results[candidate_id].predicted_time(decoded.costs),
            }
            for candidate_id in sorted(decoded.tuning_results)
        ],
        "metadata": decoded.metadata,
        "records": [_causal_record(item, decoded.costs) for item in decoded.records],
        "completion_proof": _completion_proof_payload(
            decoded.records,
            decoded.tuning_results,
            decoded.candidate_catalog,
        ),
    }


def _causal_summary_text(decoded: _DecodedCausalPayload) -> str:
    serialized_costs = _serialize_unit_costs(decoded.costs)
    lines = [
        "# Day-1 causal predicted report",
        "",
        f"> Evidence scope: **{CAUSAL_DISCLOSURE}**",
        "",
        f"- Schema: `{CAUSAL_SCHEMA}`",
        f"- State model: `{CAUSAL_STATE_MODEL}`",
        f"- Measurement kind: `{CAUSAL_MEASUREMENT_KIND}`",
        "- `gate_eligible=false`",
        "- `complete_cost_claim_allowed=false`",
        "- `security_claim_allowed=false`",
        "- `formal_performance_claim=false`",
        "- `complete_reference_set=true`",
        "- Bandwidth dimension: `deferred`",
        "- Performance/security gates remain: **HOLD**",
        f"- Workload: `{decoded.metadata.get('workload')}`",
        f"- Publication windows: `{decoded.metadata.get('windows_total')}`",
        f"- Selected fixed basis: `{decoded.selected_candidate_id}`",
        f"- Held-out oracle basis: `{decoded.oracle_candidate_id}`",
        "",
        "## Unit-cost vector",
        "",
        "| Field | Value |",
        "|---|---:|",
    ]
    lines.extend(f"| {field_name} | {value} |" for field_name, value in serialized_costs.items())
    lines.extend(
        [
            "",
            "## Tuning-prefix aggregates",
            "",
            "| Candidate ID | Strategy | Windows | Updates | Queries | Score |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for candidate_id in sorted(decoded.tuning_results):
        metrics = decoded.tuning_results[candidate_id]
        lines.append(
            f"| {candidate_id} | {metrics.strategy} | {metrics.windows} | "
            f"{metrics.updates} | {metrics.queries} | "
            f"{metrics.predicted_time(decoded.costs):.2f} |"
        )
    lines.extend(
        [
            "",
            (
                "| Record kind | Fixed-policy basis | Strategy | Windows | Updates | "
                "Queries | Predicted normalized cost |"
            ),
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for item in decoded.records:
        metrics = item.metrics
        lines.append(
            f"| {item.record_kind} | {item.candidate_id} | "
            f"{metrics.strategy} | {metrics.windows} | {metrics.updates} | "
            f"{metrics.queries} | {metrics.predicted_time(decoded.costs):.2f} |"
        )
    span80_by_candidate = decoded.metadata.get("span80_by_candidate")
    if span80_by_candidate is not None:
        if not isinstance(span80_by_candidate, dict):
            raise TypeError("span80_by_candidate must be a mapping")
        fixed_candidate_ids = [
            item.candidate_id for item in decoded.records if item.record_kind == "fixed-candidate"
        ]
        if set(span80_by_candidate) != set(fixed_candidate_ids):
            raise ValueError("span80_by_candidate keys must match fixed candidate_id values")
        lines.extend(
            [
                "",
                "## Span80 audit by fixed candidate",
                "",
                "| Fixed candidate | Span80 curve |",
                "|---|---|",
            ]
        )
        for candidate_id in fixed_candidate_ids:
            curve = json.dumps(
                span80_by_candidate[candidate_id],
                sort_keys=True,
                allow_nan=False,
            )
            lines.append(f"| {candidate_id} | `{curve}` |")
    lines.extend(
        [
            "",
            "The tuned policy is frozen from tuning-prefix evidence. The best fixed "
            "offline oracle is a held-out hindsight diagnostic and is not a gate candidate.",
            "",
        ]
    )
    return "\n".join(lines)


def _figure_png_bytes(figure: object) -> bytes:
    import matplotlib.pyplot as plt

    output = io.BytesIO()
    figure.savefig(  # type: ignore[attr-defined]
        output,
        format="png",
        dpi=160,
        metadata={
            "Software": "dynamic-cssc-spmv canonical causal renderer",
            "Description": CAUSAL_DISCLOSURE,
        },
    )
    plt.close(figure)
    return output.getvalue()


def _causal_plot_artifacts(decoded: _DecodedCausalPayload) -> dict[str, bytes]:
    import matplotlib.pyplot as plt

    items = decoded.records
    labels = [_causal_plot_label(item) for item in items]
    update_values = [item.metrics.update_ct_equivalents() for item in items]
    query_values = [
        (
            (item.metrics.cc_multiplications + item.metrics.rotations) / item.metrics.queries
            if item.metrics.queries
            else 0.0
        )
        for item in items
    ]
    footer = (
        "Bandwidth deferred | complete_reference_set=true | performance/security gates remain HOLD"
    )

    figure, axis = plt.subplots(figsize=(10, 6))
    axis.scatter(query_values, update_values)
    for label, x_value, y_value in zip(
        labels,
        query_values,
        update_values,
        strict=True,
    ):
        axis.annotate(label, (x_value, y_value), fontsize=7)
    axis.set_xlabel("Query operation proxy per query (CC multiplications + rotations)")
    axis.set_ylabel("Update ciphertext-equivalents per update")
    axis.set_title("Predicted synthetic proxy: update amplification vs query cost")
    figure.text(0.5, 0.01, footer, ha="center", fontsize=7)
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    ua_vs_qa = _figure_png_bytes(figure)

    figure, axis = plt.subplots(figsize=(10, 6))
    plotted = False
    positive_y_plotted = False
    for item, label in zip(items, labels, strict=True):
        metrics = item.metrics
        if metrics.updates == 0:
            continue
        rho = metrics.queries / metrics.updates
        per_update = metrics.predicted_update_time(decoded.costs) / metrics.updates
        value = per_update + rho * metrics.predicted_query_time_per_query(decoded.costs)
        axis.scatter([rho], [value], label=label)
        axis.annotate(label, (rho, value), fontsize=7)
        plotted = True
        positive_y_plotted = positive_y_plotted or value > 0
    if items and all(item.metrics.queries > 0 and item.metrics.updates > 0 for item in items):
        axis.set_xscale("log")
    if positive_y_plotted:
        axis.set_yscale("log")
    axis.set_xlabel("Actual query/update ratio ρ from the event schedule")
    axis.set_ylabel("Predicted normalized cost per update at actual ρ")
    axis.set_title("Predicted synthetic proxy at the executed query/update ratio")
    figure.text(0.5, 0.01, footer, ha="center", fontsize=7)
    if plotted:
        axis.legend(fontsize=7)
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    t_rho = _figure_png_bytes(figure)
    return {
        "ua_vs_qa_proxy.png": ua_vs_qa,
        "t_rho_proxy.png": t_rho,
    }


def _render_causal_artifact_bytes(
    decoded: _DecodedCausalPayload,
    filenames: Iterable[str],
) -> dict[str, bytes]:
    requested = frozenset(filenames)
    payload = _canonical_payload(decoded)
    records = payload["records"]
    tuning_aggregates = payload["tuning_aggregates"]
    if not isinstance(records, list) or not isinstance(tuning_aggregates, list):
        raise TypeError("canonical causal rows must be lists")
    serialized_cost_columns = {
        f"unit_cost_{field_name}": value for field_name, value in asdict(decoded.costs).items()
    }
    tuning_rows = [
        {
            "candidate_id": aggregate["candidate_id"],
            **aggregate["metrics"],
            "score": aggregate["score"],
            **serialized_cost_columns,
        }
        for aggregate in tuning_aggregates
    ]
    artifacts: dict[str, bytes] = {}
    if "metrics.json" in requested:
        artifacts["metrics.json"] = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    if "metrics.csv" in requested:
        artifacts["metrics.csv"] = _csv_text(records).encode("utf-8")
    if "tuning_aggregates.csv" in requested:
        artifacts["tuning_aggregates.csv"] = _csv_text(tuning_rows).encode("utf-8")
    if "SUMMARY.md" in requested:
        artifacts["SUMMARY.md"] = _causal_summary_text(decoded).encode("utf-8")
    if requested & {"ua_vs_qa_proxy.png", "t_rho_proxy.png"}:
        for filename, content in _causal_plot_artifacts(decoded).items():
            if filename in requested:
                artifacts[filename] = content
    return artifacts


def render_causal_artifacts(
    output_dir: Path,
    payload: object,
) -> dict[str, str]:
    """Validate a payload and write its canonical, reproducible report artifacts."""

    decoded = _decode_causal_payload(
        payload,
        candidate_catalog=_repository_candidate_catalog(),
    )
    artifacts = _render_causal_artifact_bytes(decoded, CAUSAL_ARTIFACT_FILENAMES)
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in artifacts.items():
        (output_dir / filename).write_bytes(content)
    return {
        filename: hashlib.sha256(content).hexdigest() for filename, content in artifacts.items()
    }


def _validate_causal_audit(
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: Mapping[str, object],
    *,
    tuning_results: Mapping[str, StrategyMetrics],
    selected_candidate_id: str,
    oracle_candidate_id: str,
    candidate_catalog: Day1CandidateCatalog,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    serialized_costs = _serialize_unit_costs(costs)
    _validate_causal_record_set(items, candidate_catalog)
    _validate_metadata_ids(metadata, selected_candidate_id, oracle_candidate_id)
    _validate_metadata_candidate_ids(metadata, items)
    tuning_aggregates = _validate_tuning_selection(
        items,
        tuning_results,
        costs,
        selected_candidate_id,
        candidate_catalog,
    )
    _validate_oracle_selection(items, costs, oracle_candidate_id)
    _validate_alias_ids(items, selected_candidate_id, oracle_candidate_id)
    return serialized_costs, tuning_aggregates


def _decode_causal_inputs(
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: Mapping[str, object],
    *,
    tuning_results: Mapping[str, StrategyMetrics],
    selected_candidate_id: str,
    oracle_candidate_id: str,
    candidate_catalog: Day1CandidateCatalog,
) -> _DecodedCausalPayload:
    serialized_costs, tuning_aggregates = _validate_causal_audit(
        items,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
        candidate_catalog=candidate_catalog,
    )
    canonical_items = [
        *sorted(
            (item for item in items if item.record_kind == "fixed-candidate"),
            key=lambda item: item.candidate_id,
        ),
        *(item for item in items if item.record_kind == "tuned-fixed-policy"),
        *(item for item in items if item.record_kind == "diagnostic-oracle"),
    ]
    payload = {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "complete_reference_set": True,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "unit_costs": serialized_costs,
        "tuning_aggregates": tuning_aggregates,
        "metadata": {
            **metadata,
            "state_model": CAUSAL_STATE_MODEL,
            "measurement_kind": CAUSAL_MEASUREMENT_KIND,
            "complete_reference_set": True,
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "security_claim_allowed": False,
            "formal_performance_claim": False,
            "fixed_candidate_count": 14,
            "reference_candidate_count": 13,
            "ablation_candidate_count": 1,
        },
        "records": [_causal_record(item, costs) for item in canonical_items],
        "completion_proof": _completion_proof_payload(
            canonical_items,
            tuning_results,
            candidate_catalog,
        ),
    }
    serialized_payload = json.loads(json.dumps(payload, allow_nan=False))
    return _decode_causal_payload(
        serialized_payload,
        candidate_catalog=candidate_catalog,
    )


def write_causal_records(
    output_dir: Path,
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: dict[str, object],
    *,
    tuning_results: Mapping[str, StrategyMetrics],
    selected_candidate_id: str,
    oracle_candidate_id: str,
) -> None:
    """Write Day-1 causal proxy records without implying a gate verdict."""

    decoded = _decode_causal_inputs(
        items,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
        candidate_catalog=_repository_candidate_catalog(),
    )
    artifacts = _render_causal_artifact_bytes(
        decoded,
        ("metrics.json", "metrics.csv", "tuning_aggregates.csv"),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in artifacts.items():
        (output_dir / filename).write_bytes(content)


def write_causal_summary(
    output_dir: Path,
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: dict[str, object],
    *,
    tuning_results: Mapping[str, StrategyMetrics],
    selected_candidate_id: str,
    oracle_candidate_id: str,
) -> None:
    decoded = _decode_causal_inputs(
        items,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
        candidate_catalog=_repository_candidate_catalog(),
    )
    artifacts = _render_causal_artifact_bytes(decoded, ("SUMMARY.md",))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "SUMMARY.md").write_bytes(artifacts["SUMMARY.md"])


def write_records(
    output_dir: Path,
    metrics: list[StrategyMetrics],
    costs: UnitCosts,
    metadata: dict[str, object],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    records = [item.to_record(costs) for item in metrics]
    (output_dir / "metrics.json").write_text(
        json.dumps({"metadata": metadata, "records": records}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    if records:
        with (output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)


def write_summary(
    output_dir: Path,
    metrics: list[StrategyMetrics],
    costs: UnitCosts,
    metadata: dict[str, object],
) -> None:
    lines = [
        "# Day-1 smoke report",
        "",
        "> Status: **predicted proxy, not an OpenFHE measurement**.",
        "",
        f"- Unit-cost model: `{costs.label}`",
        f"- Seed: `{metadata.get('seed')}`",
        f"- Workload: `{metadata.get('workload')}`",
        f"- Publication windows: `{metadata.get('windows')}`",
        "",
        (
            "| Strategy | Category | Update ct-equiv/update | Queries | Tq/query | "
            "Query ciphertexts | CC mults | Rotations | Predicted normalized cost |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in sorted(metrics, key=lambda candidate: candidate.predicted_time(costs)):
        lines.append(
            f"| {item.strategy} | {item.category} | "
            f"{item.update_ct_equivalents():.4f} | {item.queries} | "
            f"{item.predicted_query_time_per_query(costs):.2f} | "
            f"{item.query_ciphertexts} | {item.cc_multiplications} | "
            f"{item.rotations} | {item.predicted_time(costs):.2f} |"
        )
    lines.extend(
        [
            "",
            "## Plain-language interpretation",
            "",
            (
                "This report only checks that the accounting pipeline works and that all "
                "split-output F1-M strategies pay their mask, download, decryption, and "
                "client-merge costs. It is not evidence that any strategy is faster. "
                "P0b/Day-2 can replace isolated unit-cost proxies, but the result remains a "
                "model prediction until an end-to-end OpenFHE prototype validates the "
                "held-out interval."
            ),
            "",
        ]
    )
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def _causal_plot_label(item: CausalMetricRecord) -> str:
    if item.record_kind == "fixed-candidate":
        return item.candidate_id
    return f"{item.label} [basis: {item.candidate_id}]"


def write_causal_plots(
    output_dir: Path,
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    *,
    tuning_results: Mapping[str, StrategyMetrics],
    selected_candidate_id: str,
    oracle_candidate_id: str,
) -> None:
    """Plot causal records without discarding fixed-candidate identity."""

    decoded = _decode_causal_inputs(
        items,
        costs,
        {
            "selected_candidate_id": selected_candidate_id,
            "oracle_candidate_id": oracle_candidate_id,
            "fixed_candidate_count": 14,
            "reference_candidate_count": 13,
            "ablation_candidate_count": 1,
            "complete_reference_set": True,
        },
        tuning_results=tuning_results,
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
        candidate_catalog=_repository_candidate_catalog(),
    )
    artifacts = _render_causal_artifact_bytes(
        decoded,
        ("ua_vs_qa_proxy.png", "t_rho_proxy.png"),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in artifacts.items():
        (output_dir / filename).write_bytes(content)


def write_plots(output_dir: Path, metrics: list[StrategyMetrics], costs: UnitCosts) -> None:
    import matplotlib.pyplot as plt

    names = [item.strategy for item in metrics]
    update_values = [item.update_ct_equivalents() for item in metrics]
    query_values = [
        (item.cc_multiplications + item.rotations) / item.queries if item.queries else 0.0
        for item in metrics
    ]

    figure, axis = plt.subplots(figsize=(10, 6))
    axis.scatter(query_values, update_values)
    for name, x_value, y_value in zip(names, query_values, update_values, strict=True):
        axis.annotate(name, (x_value, y_value), fontsize=7)
    axis.set_xlabel("Query operation proxy per query (CC multiplications + rotations)")
    axis.set_ylabel("Update ciphertext-equivalents per update")
    axis.set_title("Predicted proxy: update amplification vs query cost")
    figure.tight_layout()
    figure.savefig(output_dir / "ua_vs_qa_proxy.png", dpi=160)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(10, 6))
    for item in metrics:
        if item.updates == 0:
            continue
        rho = item.queries / item.updates
        per_update = item.predicted_update_time(costs) / item.updates
        value = per_update + rho * item.predicted_query_time_per_query(costs)
        axis.scatter([rho], [value], label=item.strategy)
        axis.annotate(item.strategy, (rho, value), fontsize=7)
    if metrics and all(item.queries > 0 and item.updates > 0 for item in metrics):
        axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("Actual query/update ratio ρ from the event schedule")
    axis.set_ylabel("Predicted normalized cost per update at actual ρ")
    axis.set_title("Predicted proxy at the executed query/update ratio")
    axis.legend(fontsize=7)
    figure.tight_layout()
    figure.savefig(output_dir / "t_rho_proxy.png", dpi=160)
    plt.close(figure)


def write_checksums(output_dir: Path) -> None:
    rows = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(output_dir)}")
    (output_dir / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
