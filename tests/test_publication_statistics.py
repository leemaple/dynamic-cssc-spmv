from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from copy import deepcopy
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_authority as day2_calibration_authority
import dynamic_cssc.publication_statistics as publication_statistics
from dynamic_cssc.evidence_compatibility import (
    EvidenceCompatibilityError,
    EvidenceRole,
    repository_behavior_paths,
    verify_current_analysis_source,
)
from dynamic_cssc.publication_schedule import ACCEPTED_EVENT_SCHEDULE_SCHEMA
from dynamic_cssc.publication_statistics import (
    ABLATION_CANDIDATE_ID,
    ANALYSIS_RUNTIME_IMPLEMENTATION,
    ANALYSIS_RUNTIME_VERSION,
    CALIBRATION_CLASSIFICATION_REPETITIONS,
    CALIBRATION_CLASSIFICATION_SEED,
    CELL_BINDING_SCHEMA,
    COMPARATOR_CANDIDATE_ID,
    DATASET_IDS,
    EVENT_SCHEDULE_SCHEMA,
    FIXED_CANDIDATE_IDS,
    FRESHNESS_VALUES,
    HELDOUT_RECORD_SCHEMA,
    HELDOUT_SCHEMA,
    PARTITION_RESAMPLING_REPETITIONS,
    PARTITION_RESAMPLING_SEED,
    PRIMARY_CONFIRMATORY_FAMILY,
    PRIMITIVE_NAMES,
    QUERY_VECTOR_SCHEMA,
    REFERENCE_CANDIDATE_IDS,
    RHO_VALUES,
    SAMPLER_SCHEMA,
    SEMANTICS,
    TRACE_UNIT_SCHEMA,
    VERDICT_SCHEMA,
    analyze_publication_results,
    calibration_operation_order,
    write_publication_analysis_artifacts,
)


def _canonical_digest(payload: object) -> str:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


_SAMPLER_SCHEMA = "dynamic-cssc-publication-shake256-counter-sampler-v1"
_CALIBRATION_OPERATION_ORDER_SEED = 2_026_082_302
_CALIBRATION_BLOCK_SCHEMA = "dynamic-cssc-publication-calibration-block-v1"


class _ReferenceCounterSampler:
    """Independent test-side transcription of the frozen sampler specification."""

    def __init__(self, domain: object) -> None:
        self._domain = (
            json.dumps(
                domain,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        self._counter = 0
        self._buffer = b""

    def randbelow(self, upper_bound: int) -> int:
        width = max(1, (upper_bound.bit_length() + 7) // 8)
        space = 1 << (8 * width)
        acceptance_limit = space - (space % upper_bound)
        while True:
            while len(self._buffer) < width:
                self._buffer += hashlib.shake_256(
                    self._domain + self._counter.to_bytes(16, "big")
                ).digest(64)
                self._counter += 1
            raw, self._buffer = self._buffer[:width], self._buffer[width:]
            candidate = int.from_bytes(raw, "big")
            if candidate < acceptance_limit:
                return candidate % upper_bound


def _reference_calibration_operation_order(block_ordinal: int) -> list[str]:
    sampler = _ReferenceCounterSampler(
        {
            "analysis_kind": "calibration-operation-order",
            "block_ordinal": block_ordinal,
            "schema_version": _SAMPLER_SCHEMA,
            "seed": _CALIBRATION_OPERATION_ORDER_SEED,
        }
    )
    order = list(PRIMITIVE_NAMES)
    for upper in range(len(order) - 1, 0, -1):
        selected = sampler.randbelow(upper + 1)
        order[upper], order[selected] = order[selected], order[upper]
    return order


def _whole_block_calibration(
    primitive_block_values: dict[str, tuple[str, ...]] | None = None,
) -> dict[str, object]:
    values_by_primitive = primitive_block_values or {}
    return {
        "schema_version": "dynamic-cssc-publication-calibration-v3",
        "primitive_names": list(PRIMITIVE_NAMES),
        "operation_order_seed": _CALIBRATION_OPERATION_ORDER_SEED,
        "measurement_block_count": 14,
        "measurement_stop_rule": (
            "exactly-14-whole-blocks-outcome-independent-no-optional-stopping"
        ),
        "raw_repetition_blocks": [
            {
                "schema_version": _CALIBRATION_BLOCK_SCHEMA,
                "block_ordinal": block_ordinal,
                "operation_order": _reference_calibration_operation_order(block_ordinal),
                "seconds_by_primitive": {
                    primitive_name: (
                        values_by_primitive.get(primitive_name, ("1",))[
                            block_ordinal % len(values_by_primitive.get(primitive_name, ("1",)))
                        ]
                    )
                    for primitive_name in PRIMITIVE_NAMES
                },
            }
            for block_ordinal in range(14)
        ],
    }


def _set_calibration_primitive_values(
    payload: dict[str, object],
    primitive_name: str,
    values: tuple[str, ...],
) -> None:
    blocks = payload["calibration"]["raw_repetition_blocks"]
    for block in blocks:
        block["seconds_by_primitive"][primitive_name] = values[block["block_ordinal"] % len(values)]


def _primitive_counts(multiplier: int) -> dict[str, int]:
    return {name: multiplier if name == "encrypt" else 0 for name in PRIMITIVE_NAMES}


def _set_encrypt_cost_per_observation(
    record: dict[str, object],
    multiplier: int,
) -> None:
    record["update_primitive_counts"] = _primitive_counts(multiplier * record["update_count"])
    record["query_primitive_counts"] = _primitive_counts(multiplier * record["query_count"])


_ACCEPTED_RAW_EVENTS_TOTAL = 1_000


def _accepted_event_group_ranges(total: int) -> dict[str, object]:
    warmup_end = total // 10
    tuning_end = total * 4 // 10
    ranges: dict[str, object] = {
        "accepted_raw_events_total": total,
        "warmup_accepted_event_group_range": [0, warmup_end],
        "tuning_accepted_event_group_range": [warmup_end, tuning_end],
        "heldout_accepted_event_group_range": [tuning_end, total],
    }
    ranges["accepted_event_group_ranges_sha256"] = _canonical_digest(ranges)
    return ranges


def _phase_counts(rho: str, start: int, end: int) -> tuple[int, int]:
    ratio = Fraction(rho)
    query_count = (end * ratio.numerator // ratio.denominator) - (
        start * ratio.numerator // ratio.denominator
    )
    return end - start, query_count


def _records_for_cell_binding(
    payload: dict[str, object],
    cell_binding_sha256: str,
) -> list[dict[str, object]]:
    return [
        record
        for record in payload["records"]
        if record["cell_binding_sha256"] == cell_binding_sha256
    ]


def _rehash_cell_binding(
    payload: dict[str, object],
    cell_binding: dict[str, object],
) -> None:
    old_digest = cell_binding["cell_binding_sha256"]
    records = _records_for_cell_binding(payload, old_digest)
    cell_binding["cell_binding_sha256"] = _canonical_digest(
        {key: value for key, value in cell_binding.items() if key != "cell_binding_sha256"}
    )
    for record in records:
        record["cell_binding_sha256"] = cell_binding["cell_binding_sha256"]


def _retarget_experiment_source(payload: dict[str, object], source_git_sha: str) -> None:
    payload["experiment_source_git_sha"] = source_git_sha
    trace_digest_map: dict[str, str] = {}
    for trace_unit in payload["trace_units"]:
        old_digest = trace_unit["trace_binding_sha256"]
        trace_unit["experiment_source_git_sha"] = source_git_sha
        trace_unit["trace_binding_sha256"] = _canonical_digest(
            {key: value for key, value in trace_unit.items() if key != "trace_binding_sha256"}
        )
        trace_digest_map[old_digest] = trace_unit["trace_binding_sha256"]
    cell_digest_map: dict[str, str] = {}
    for cell_binding in payload["cell_bindings"]:
        old_digest = cell_binding["cell_binding_sha256"]
        cell_binding["experiment_source_git_sha"] = source_git_sha
        cell_binding["trace_binding_sha256"] = trace_digest_map[
            cell_binding["trace_binding_sha256"]
        ]
        cell_binding["cell_binding_sha256"] = _canonical_digest(
            {key: value for key, value in cell_binding.items() if key != "cell_binding_sha256"}
        )
        cell_digest_map[old_digest] = cell_binding["cell_binding_sha256"]
    for record in payload["records"]:
        record["cell_binding_sha256"] = cell_digest_map[record["cell_binding_sha256"]]


@pytest.fixture(scope="module", autouse=True)
def _frozen_analysis_source() -> object:
    with publication_statistics._test_only_analysis_source():
        yield


def _complete_payload(
    *,
    selected_multiplier: int = 8,
    selected_update_bytes: int = 0,
    calibration_repetitions: tuple[str, ...] = ("1", "1"),
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    trace_units: list[dict[str, object]] = []
    cell_bindings: list[dict[str, object]] = []
    for dataset_id in DATASET_IDS:
        for semantics in SEMANTICS:
            for source_partition in range(5):
                shared_trace_identity = f"{dataset_id}:{source_partition}"
                trace_unit = {
                    "schema_version": TRACE_UNIT_SCHEMA,
                    "experiment_source_git_sha": "1" * 40,
                    "dataset_id": dataset_id,
                    "semantics": semantics,
                    "source_partition": source_partition,
                    "trace_manifest_sha256": _canonical_digest(
                        [shared_trace_identity, semantics, "manifest"]
                    ),
                    "mapping_sha256": _canonical_digest([shared_trace_identity, "mapping"]),
                    "accepted_events_sha256": _canonical_digest(
                        [shared_trace_identity, "accepted-events"]
                    ),
                    **_accepted_event_group_ranges(_ACCEPTED_RAW_EVENTS_TOTAL),
                    "replay_receipt_sha256": _canonical_digest(
                        [shared_trace_identity, semantics, "replay"]
                    ),
                    "source_bundle_sha256": _canonical_digest(
                        [shared_trace_identity, "source-bundle"]
                    ),
                }
                trace_unit["trace_binding_sha256"] = _canonical_digest(trace_unit)
                trace_units.append(trace_unit)
                for freshness_seconds in FRESHNESS_VALUES:
                    for rho in RHO_VALUES:
                        tuning_range = trace_unit["tuning_accepted_event_group_range"]
                        heldout_range = trace_unit["heldout_accepted_event_group_range"]
                        tuning_update_count, tuning_query_count = _phase_counts(
                            rho,
                            tuning_range[0],
                            tuning_range[1],
                        )
                        heldout_update_count, heldout_query_count = _phase_counts(
                            rho,
                            heldout_range[0],
                            heldout_range[1],
                        )
                        cell_binding = {
                            "schema_version": CELL_BINDING_SCHEMA,
                            "experiment_source_git_sha": "1" * 40,
                            "dataset_id": dataset_id,
                            "semantics": semantics,
                            "source_partition": source_partition,
                            "freshness_seconds": freshness_seconds,
                            "rho": rho,
                            "trace_manifest_sha256": trace_unit["trace_manifest_sha256"],
                            "mapping_sha256": trace_unit["mapping_sha256"],
                            "accepted_events_sha256": trace_unit["accepted_events_sha256"],
                            "accepted_raw_events_total": trace_unit["accepted_raw_events_total"],
                            "warmup_accepted_event_group_range": trace_unit[
                                "warmup_accepted_event_group_range"
                            ],
                            "tuning_accepted_event_group_range": tuning_range,
                            "heldout_accepted_event_group_range": heldout_range,
                            "accepted_event_group_ranges_sha256": trace_unit[
                                "accepted_event_group_ranges_sha256"
                            ],
                            "replay_receipt_sha256": trace_unit["replay_receipt_sha256"],
                            "source_bundle_sha256": trace_unit["source_bundle_sha256"],
                            "trace_binding_sha256": trace_unit["trace_binding_sha256"],
                            "tuning_update_count": tuning_update_count,
                            "tuning_query_count": tuning_query_count,
                            "heldout_update_count": heldout_update_count,
                            "heldout_query_count": heldout_query_count,
                            "event_schedule_schema_version": EVENT_SCHEDULE_SCHEMA,
                            "event_schedule_sha256": _canonical_digest(
                                [shared_trace_identity, semantics, rho, "event-schedule"]
                            ),
                            "query_vector_schema_version": QUERY_VECTOR_SCHEMA,
                            "query_vector_sha256": _canonical_digest(
                                [shared_trace_identity, semantics, "query-vector"]
                            ),
                        }
                        cell_binding["cell_binding_sha256"] = _canonical_digest(cell_binding)
                        cell_bindings.append(cell_binding)
                        tuning_fixed: dict[str, dict[str, object]] = {}
                        heldout_fixed: dict[str, dict[str, object]] = {}
                        for candidate_id in REFERENCE_CANDIDATE_IDS:
                            multiplier = 12
                            if candidate_id == COMPARATOR_CANDIDATE_ID:
                                multiplier = 10
                            if candidate_id == "padding-reuse":
                                multiplier = 8
                            tuning_record = {
                                "schema_version": HELDOUT_RECORD_SCHEMA,
                                "dataset_id": dataset_id,
                                "semantics": semantics,
                                "source_partition": source_partition,
                                "freshness_seconds": freshness_seconds,
                                "rho": rho,
                                "phase": "tuning-prefix",
                                "record_kind": "fixed-candidate",
                                "candidate_id": candidate_id,
                                "candidate_role": "reference",
                                "selection_source": "fixed-reference-tuning-prefix",
                                "cell_binding_sha256": cell_binding["cell_binding_sha256"],
                                "outcome": "complete",
                                "failure_reason": None,
                                "update_count": tuning_update_count,
                                "query_count": tuning_query_count,
                                "update_primitive_counts": _primitive_counts(
                                    multiplier * tuning_update_count
                                ),
                                "query_primitive_counts": _primitive_counts(
                                    multiplier * tuning_query_count
                                ),
                                "update_serialized_bytes": 0,
                                "query_serialized_bytes": 0,
                            }
                            records.append(tuning_record)
                            tuning_fixed[candidate_id] = tuning_record
                        for candidate_id in FIXED_CANDIDATE_IDS:
                            basis_id = (
                                candidate_id
                                if candidate_id in REFERENCE_CANDIDATE_IDS
                                else "mini-cssc-delta"
                            )
                            heldout_record = deepcopy(tuning_fixed[basis_id])
                            heldout_record.update(
                                {
                                    "phase": "held-out",
                                    "candidate_id": candidate_id,
                                    "candidate_role": (
                                        "ablation"
                                        if candidate_id == ABLATION_CANDIDATE_ID
                                        else "reference"
                                    ),
                                    "selection_source": (
                                        "fixed-ablation-held-out"
                                        if candidate_id == ABLATION_CANDIDATE_ID
                                        else "fixed-reference-held-out"
                                    ),
                                    "update_count": heldout_update_count,
                                    "query_count": heldout_query_count,
                                }
                            )
                            heldout_record["update_serialized_bytes"] = (
                                selected_update_bytes * heldout_update_count
                                if candidate_id == "padding-reuse"
                                else 0
                            )
                            heldout_multiplier = 12
                            if candidate_id == COMPARATOR_CANDIDATE_ID:
                                heldout_multiplier = 10
                            if candidate_id == "padding-reuse":
                                heldout_multiplier = selected_multiplier
                            heldout_record["update_primitive_counts"] = _primitive_counts(
                                heldout_multiplier * heldout_update_count
                            )
                            heldout_record["query_primitive_counts"] = _primitive_counts(
                                heldout_multiplier * heldout_query_count
                            )
                            records.append(heldout_record)
                            heldout_fixed[candidate_id] = heldout_record
    return {
        "schema_version": HELDOUT_SCHEMA,
        "experiment_source_git_sha": "1" * 40,
        "measurement_kind": ("heldout-calibrated-component-complete-protocol-serialization"),
        "bandwidth_mbps": 1000,
        "partition_resampling_seed": PARTITION_RESAMPLING_SEED,
        "partition_resampling_repetitions": PARTITION_RESAMPLING_REPETITIONS,
        "calibration_classification_seed": CALIBRATION_CLASSIFICATION_SEED,
        "calibration_classification_repetitions": CALIBRATION_CLASSIFICATION_REPETITIONS,
        "dataset_ids": list(DATASET_IDS),
        "semantics": list(SEMANTICS),
        "evaluated_freshness_seconds": list(FRESHNESS_VALUES),
        "primary_confirmatory_family": list(PRIMARY_CONFIRMATORY_FAMILY),
        "rho_values": list(RHO_VALUES),
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": [ABLATION_CANDIDATE_ID],
        "comparator_candidate_id": COMPARATOR_CANDIDATE_ID,
        "calibration": _whole_block_calibration({"encrypt": calibration_repetitions}),
        "trace_units": trace_units,
        "cell_bindings": cell_bindings,
        "records": records,
    }


@pytest.fixture(scope="module")
def successful_analysis(_frozen_analysis_source: object) -> dict[str, object]:
    return analyze_publication_results(_complete_payload())


def test_v7_input_calls_both_freshness_values_evaluated_not_primary() -> None:
    payload = _complete_payload()

    result = analyze_publication_results(payload)

    assert result["analysis_completed"] is True


def test_legacy_primary_freshness_field_is_rejected_by_the_closed_v7_input() -> None:
    payload = _complete_payload()
    payload["primary_freshness_seconds"] = payload.pop("evaluated_freshness_seconds")

    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(payload)


def test_v6_input_schema_cannot_be_relabelled_with_the_v7_field_names() -> None:
    payload = _complete_payload()
    payload["schema_version"] = "dynamic-cssc-publication-heldout-v6"

    with pytest.raises(ValueError, match="schema_version.*exact frozen value"):
        analyze_publication_results(payload)


def test_panel_verdicts_separate_classification_from_headline_authority(
    successful_analysis: dict[str, object],
) -> None:
    verdicts = successful_analysis["group_verdicts"]
    primary = [
        verdict for verdict in verdicts if verdict["analysis_role"] == "sole-confirmatory-primary"
    ]
    secondary = [
        verdict
        for verdict in verdicts
        if verdict["analysis_role"] == "prespecified-secondary-robustness"
    ]

    assert len(primary) == 1
    assert primary[0]["is_primary_confirmatory_family"] is True
    assert primary[0]["finite_corpus_adjacent_pair_classification_passed"] is True
    assert len(secondary) == 3
    assert all(verdict["is_primary_confirmatory_family"] is False for verdict in secondary)
    assert all(
        verdict["finite_corpus_adjacent_pair_classification_passed"] is True
        for verdict in secondary
    )
    assert all("gate_passed" not in verdict for verdict in verdicts)


def test_every_panel_view_marks_only_the_exact_primary_family_as_authoritative(
    successful_analysis: dict[str, object],
) -> None:
    primary_family = successful_analysis["primary_confirmatory_family"]
    secondary_families = successful_analysis["secondary_robustness_families"]
    summaries = successful_analysis["summaries"]
    calibration = successful_analysis["calibration_sensitivity"]

    assert primary_family == {
        "semantics": "T2",
        "freshness_seconds": "0.1",
        "analysis_role": "sole-confirmatory-primary",
        "is_primary_confirmatory_family": True,
    }
    assert all(family["is_primary_confirmatory_family"] is False for family in secondary_families)
    assert sum(summary["is_primary_confirmatory_family"] is True for summary in summaries) == len(
        RHO_VALUES
    )
    assert all(
        summary["is_primary_confirmatory_family"]
        is (summary["analysis_role"] == "sole-confirmatory-primary")
        for summary in summaries
    )
    assert all(
        panel["is_primary_confirmatory_family"]
        is (panel["analysis_role"] == "sole-confirmatory-primary")
        for panel in calibration
    )


def test_artifact_evidence_chain_name_does_not_claim_formal_proof(
    successful_analysis: dict[str, object],
) -> None:
    assert successful_analysis["artifact_evidence_chain_verified"] is False
    assert "formal_evidence_verified" not in successful_analysis


def test_calibrated_component_stability_does_not_grant_release_claims(
    successful_analysis: dict[str, object],
) -> None:
    assert successful_analysis["calibrated_component_result_stable"] is False
    assert "headline_result_stable" not in successful_analysis
    assert successful_analysis["headline_claim_allowed"] is False
    assert successful_analysis["complete_cost_claim_allowed"] is False
    assert successful_analysis["formal_performance_claim_allowed"] is False
    assert successful_analysis["security_claim_allowed"] is False


def test_complete_unit_level_analysis_passes_the_descriptive_gate_but_not_claim_authority(
    successful_analysis: dict[str, object],
) -> None:
    assert successful_analysis["analysis_completed"] is True
    assert successful_analysis["all_candidate_outcomes_complete"] is True
    assert successful_analysis["finite_corpus_decision_calculation_passed"] is True
    assert successful_analysis["preregistered_finite_corpus_gate_passed"] is False
    assert successful_analysis["calibration_sensitivity_stable"] is True
    assert successful_analysis["headline_stability_calculation_passed"] is True
    assert successful_analysis["calibrated_component_result_stable"] is False
    assert successful_analysis["headline_claim_allowed"] is False
    assert successful_analysis["complete_cost_claim_allowed"] is False
    assert successful_analysis["formal_performance_claim_allowed"] is False
    assert successful_analysis["security_claim_allowed"] is False
    assert successful_analysis["trace_binding_count"] == 30
    assert successful_analysis["cell_binding_count"] == 540
    assert successful_analysis["trace_bindings_descriptive_only"] is True
    assert successful_analysis["trace_source_authority_verified"] is False
    assert successful_analysis["day1b_producer_authority_verified"] is False
    assert successful_analysis["calibration_measurement_authority_verified"] is False
    assert successful_analysis["mixed_circuit_authority_verified"] is False
    assert successful_analysis["evidence_chain_authority_verified"] is False
    assert successful_analysis["point_calibration_estimator"] == ("whole-block-primitive-median")
    assert successful_analysis["calibration_raw_block_count"] == 14
    assert successful_analysis["calibration_block_resampling"] is True
    assert successful_analysis["nested_tuning_reselection"] is True
    assert successful_analysis["nested_tuning_tie_break"] == "canonical-candidate-id"
    assert successful_analysis["experiment_source_git_sha"] == "1" * 40
    assert successful_analysis["analysis_source_git_sha"] == "1" * 40
    assert successful_analysis["analysis_source_attestation"] == "test-only-injected"
    assert successful_analysis["analysis_source_clean_head_verified"] is False
    assert successful_analysis["analysis_runtime_implementation"] == "CPython"
    assert successful_analysis["analysis_runtime_version"] == "3.12.13"
    assert successful_analysis["analysis_runtime_identity_verified"] is True
    assert successful_analysis["artifact_evidence_chain_verified"] is False
    assert "source_git_sha" not in successful_analysis
    summaries = successful_analysis["summaries"]
    assert isinstance(summaries, list)
    assert len(summaries) == 2 * 2 * 9
    first = summaries[0]
    assert first["unit_count"] == 15
    assert first["effect_median"] == "0.2"
    assert first["effect_iqr"] == ["0.2", "0.2"]
    assert first["partition_resampling_stability_interval_95"] == ["0.2", "0.2"]
    assert first["positive_effect_count"] == 15
    assert first["all_15_unit_effects_positive"] is True
    assert "raw_sign_test_p" not in first
    assert "holm_adjusted_p" not in first
    assert first["all_units_non_dominated"] is True
    assert first["finite_corpus_rho_gate_passed"] is True
    assert successful_analysis["inference_scope"] == (
        "fixed-three-dataset-corpus-no-population-inference"
    )
    assert successful_analysis["resampling_interval_role"] == (
        "descriptive-partition-weighting-stability"
    )

    group = successful_analysis["group_verdicts"][0]
    assert group["adjacent_passing_rho_pairs"] == [
        [left, right] for left, right in zip(RHO_VALUES, RHO_VALUES[1:], strict=False)
    ]
    roles = [group["analysis_role"] for group in successful_analysis["group_verdicts"]]
    assert roles.count("sole-confirmatory-primary") == 1
    assert roles.count("prespecified-secondary-robustness") == 3


def test_v7_input_preserves_the_v6_split_and_cell_binding_contract() -> None:
    assert HELDOUT_SCHEMA == "dynamic-cssc-publication-heldout-v7"
    assert HELDOUT_RECORD_SCHEMA == "dynamic-cssc-publication-heldout-record-v4"
    assert TRACE_UNIT_SCHEMA == "dynamic-cssc-publication-trace-unit-binding-v2"
    assert CELL_BINDING_SCHEMA == "dynamic-cssc-publication-cell-binding-v2"
    assert VERDICT_SCHEMA == "dynamic-cssc-publication-verdict-v7"
    assert EVENT_SCHEDULE_SCHEMA == ACCEPTED_EVENT_SCHEDULE_SCHEMA
    assert EVENT_SCHEDULE_SCHEMA == "dynamic-cssc-accepted-event-schedule-v2"
    assert QUERY_VECTOR_SCHEMA == "dynamic-cssc-publication-query-vector-v1"
    assert ANALYSIS_RUNTIME_IMPLEMENTATION == "CPython"
    assert ANALYSIS_RUNTIME_VERSION == "3.12.13"

    result = analyze_publication_results(_complete_payload())

    assert result["schema_version"] == VERDICT_SCHEMA
    assert result["analysis_completed"] is True
    assert result["artifact_evidence_chain_verified"] is False
    assert result["formal_performance_claim_allowed"] is False


def test_day2_authority_alone_cannot_bypass_trace_and_day1b_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        publication_statistics,
        "_repository_calibration_authority_verified",
        lambda _projection, *, source_git_sha: bool(source_git_sha),
    )

    result = analyze_publication_results(_complete_payload())

    assert result["calibration_measurement_authority_verified"] is True
    assert result["trace_source_authority_verified"] is False
    assert result["day1b_producer_authority_verified"] is False
    assert result["mixed_circuit_authority_verified"] is False
    assert result["evidence_chain_authority_verified"] is False
    assert result["artifact_evidence_chain_verified"] is False
    assert result["artifact_evidence_chain_verified"] is all(
        (
            result["analysis_source_clean_head_verified"],
            result["trace_source_authority_verified"],
            result["day1b_producer_authority_verified"],
            result["calibration_measurement_authority_verified"],
            result["mixed_circuit_authority_verified"],
        )
    )
    assert result["preregistered_finite_corpus_gate_passed"] is False
    assert result["calibrated_component_result_stable"] is False


def test_day2_authority_is_bound_to_the_exact_calibration_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calibration = _whole_block_calibration()
    capability = day2_calibration_authority._mint_repository_calibration_authority(
        source_git_sha="1" * 40,
        outer_archive_sha256="2" * 64,
        raw_measurement_blocks_sha256="3" * 64,
        calibration_projection_sha256=hashlib.sha256(
            day2_calibration_authority._canonical_json_bytes(calibration)
        ).hexdigest(),
    )
    monkeypatch.setattr(
        day2_calibration_authority,
        "repository_day2_calibration_authority",
        lambda: capability,
    )

    assert publication_statistics._repository_calibration_authority_verified(
        calibration,
        source_git_sha="1" * 40,
    )

    tampered = deepcopy(calibration)
    tampered["raw_repetition_blocks"][0]["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = "2"
    assert not publication_statistics._repository_calibration_authority_verified(
        tampered,
        source_git_sha="1" * 40,
    )
    assert not publication_statistics._repository_calibration_authority_verified(
        calibration,
        source_git_sha="2" * 40,
    )


def test_v7_calibration_accepts_only_closed_whole_raw_repetition_blocks() -> None:
    payload = _complete_payload()
    payload["schema_version"] = "dynamic-cssc-publication-heldout-v7"
    payload["calibration"] = _whole_block_calibration()

    result = analyze_publication_results(payload)

    assert result["schema_version"] == "dynamic-cssc-publication-verdict-v7"
    assert result["calibration_raw_block_count"] == 14
    assert result["calibration_measurement_block_count"] == 14
    assert result["calibration_measurement_stop_rule"] == (
        "exactly-14-whole-blocks-outcome-independent-no-optional-stopping"
    )
    assert result["calibration_measurements_descriptive_only"] is True
    assert result["calibration_measurement_authority_verified"] is False
    assert result["calibration_block_resampling"] is True


def test_v7_calibration_accepts_canonical_nonterminating_exact_rationals() -> None:
    payload = _complete_payload()
    payload["calibration"]["raw_repetition_blocks"][0]["seconds_by_primitive"][
        PRIMITIVE_NAMES[0]
    ] = "1/3000000000"

    result = analyze_publication_results(payload)

    assert result["analysis_completed"] is True


@pytest.mark.parametrize("value", ["2/4", "1/1", "01/3", "1/03", "0/3", "1/0"])
def test_v7_calibration_rejects_noncanonical_or_nonpositive_fraction_text(value: str) -> None:
    payload = _complete_payload()
    payload["calibration"]["raw_repetition_blocks"][0]["seconds_by_primitive"][
        PRIMITIVE_NAMES[0]
    ] = value

    with pytest.raises(ValueError, match="canonical|positive"):
        analyze_publication_results(payload)


def test_counter_sampler_has_a_frozen_known_answer_and_separate_analysis_domains(
    successful_analysis: dict[str, object],
) -> None:
    assert SAMPLER_SCHEMA == "dynamic-cssc-publication-shake256-counter-sampler-v1"
    assert calibration_operation_order(0) == (
        "mask_random_element",
        "encode",
        "client_merge",
        "deserialize_ciphertext",
        "client_reorder_element",
        "query_vector_pack",
        "eval_mult_with_relinearization",
        "eval_add_ciphertext",
        "mask_map_element",
        "eval_mult_plaintext_mask",
        "encrypt",
        "decrypt",
        "eval_rotate",
        "serialize_ciphertext",
    )
    assert successful_analysis["sampling_stream_known_answer_sha256"] == (
        "10246ee8ccdeaf978dba3a1df3739187014e57ebc56fa5f83b24fc010f8bb9ee"
    )
    assert successful_analysis["sampling_stream_known_answer_verified"] is True
    primary_domains = {
        domain["analysis_kind"]: domain["domain_sha256"]
        for domain in successful_analysis["sampling_stream_domains"]
        if (domain["semantics"], domain["freshness_seconds"]) == PRIMARY_CONFIRMATORY_FAMILY
    }
    assert set(primary_domains) == {
        "partition-resampling",
        "calibration-classification",
    }
    assert len(set(primary_domains.values())) == 2


def test_secondary_completeness_cannot_shift_primary_draws_or_the_primary_verdict() -> None:
    complete_payload = _complete_payload(calibration_repetitions=("0.01", "1.99"))
    for record in complete_payload["records"]:
        if (
            (record["semantics"], record["freshness_seconds"]) == PRIMARY_CONFIRMATORY_FAMILY
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
        ):
            _set_encrypt_cost_per_observation(record, 5 + record["source_partition"])
    incomplete_payload = deepcopy(complete_payload)
    secondary = next(
        record
        for record in incomplete_payload["records"]
        if record["semantics"] == "T1"
        and record["freshness_seconds"] == "0.1"
        and record["source_partition"] == 0
        and record["rho"] == "0.01"
        and record["phase"] == "held-out"
        and record["candidate_id"] == "padding-reuse"
    )
    secondary["outcome"] = "missing"
    secondary["failure_reason"] = "secondary robustness execution was not emitted"
    for field in (
        "update_primitive_counts",
        "query_primitive_counts",
        "update_serialized_bytes",
        "query_serialized_bytes",
    ):
        secondary[field] = None

    complete = analyze_publication_results(complete_payload)
    incomplete = analyze_publication_results(incomplete_payload)

    def primary_view(result: dict[str, object]) -> dict[str, object]:
        return {
            "group": next(
                group
                for group in result["group_verdicts"]
                if group["analysis_role"] == "sole-confirmatory-primary"
            ),
            "calibration": next(
                group
                for group in result["calibration_sensitivity"]
                if group["analysis_role"] == "sole-confirmatory-primary"
            ),
            "summaries": [
                summary
                for summary in result["summaries"]
                if summary["analysis_role"] == "sole-confirmatory-primary"
            ],
            "primary_finite_corpus_decision_calculation_passed": result[
                "primary_finite_corpus_decision_calculation_passed"
            ],
        }

    assert incomplete["all_candidate_outcomes_complete"] is False
    assert primary_view(incomplete) == primary_view(complete)
    assert complete["statistical_gate_calculation_passed"] is True
    assert incomplete["statistical_gate_calculation_passed"] is False
    assert incomplete["finite_corpus_decision_calculation_passed"] is False
    assert incomplete["headline_stability_calculation_passed"] is False


def test_nested_calibration_resamples_whole_blocks_to_preserve_common_drift() -> None:
    payload = _complete_payload()
    blocks = payload["calibration"]["raw_repetition_blocks"]
    for block in blocks:
        common_seconds = "0.01" if block["block_ordinal"] < 7 else "100"
        block["seconds_by_primitive"] = {
            primitive_name: common_seconds for primitive_name in PRIMITIVE_NAMES
        }
    for record in payload["records"]:
        if record["candidate_id"] != COMPARATOR_CANDIDATE_ID:
            continue
        update_counts = _primitive_counts(0)
        update_counts["query_vector_pack"] = 10 * record["update_count"]
        query_counts = _primitive_counts(0)
        query_counts["query_vector_pack"] = 10 * record["query_count"]
        record["update_primitive_counts"] = update_counts
        record["query_primitive_counts"] = query_counts

    result = analyze_publication_results(payload)
    primary_summaries = [
        summary
        for summary in result["summaries"]
        if summary["analysis_role"] == "sole-confirmatory-primary"
    ]

    assert result["calibration_sensitivity_stable"] is True
    assert all(
        summary["calibration_median_effect_stability_interval_95"] == ["0.2", "0.2"]
        for summary in primary_summaries
    )


def test_json_object_iteration_order_cannot_change_draws_or_verdict_bytes() -> None:
    def reverse_object_order(value: object) -> object:
        if type(value) is dict:
            return {key: reverse_object_order(value[key]) for key in reversed(tuple(value))}
        if type(value) is list:
            return [reverse_object_order(item) for item in value]
        return value

    payload = _complete_payload(calibration_repetitions=("0.01", "1.99"))

    assert analyze_publication_results(reverse_object_order(payload)) == (
        analyze_publication_results(payload)
    )


def test_legacy_per_primitive_calibration_arrays_are_fail_closed() -> None:
    payload = _complete_payload()
    payload["calibration"] = {
        "schema_version": "dynamic-cssc-publication-calibration-v2",
        "primitive_names": list(PRIMITIVE_NAMES),
        "raw_repetitions_seconds": {
            primitive_name: ["1", "1"] for primitive_name in PRIMITIVE_NAMES
        },
    }

    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        "too-few-blocks",
        "too-many-blocks",
        "declared-block-count",
        "measurement-stop-rule",
        "block-ordinal",
        "block-ordinal-bool",
        "operation-order-swap",
        "operation-order-missing",
        "operation-order-extra",
        "primitive-missing",
        "primitive-extra",
        "block-field-missing",
        "block-field-extra",
        "duration-zero",
        "duration-negative",
        "duration-noncanonical",
        "duration-nonstring",
    ),
)
def test_whole_calibration_block_contract_rejects_splice_and_shape_attacks(
    mutation: str,
) -> None:
    payload = _complete_payload()
    calibration = payload["calibration"]
    block = calibration["raw_repetition_blocks"][0]
    if mutation == "too-few-blocks":
        calibration["raw_repetition_blocks"].pop()
    elif mutation == "too-many-blocks":
        calibration["raw_repetition_blocks"].append(
            deepcopy(calibration["raw_repetition_blocks"][-1])
        )
    elif mutation == "declared-block-count":
        calibration["measurement_block_count"] = 15
    elif mutation == "measurement-stop-rule":
        calibration["measurement_stop_rule"] = "stop-when-stable"
    elif mutation == "block-ordinal":
        block["block_ordinal"] = 1
    elif mutation == "block-ordinal-bool":
        block["block_ordinal"] = False
    elif mutation == "operation-order-swap":
        block["operation_order"][0], block["operation_order"][1] = (
            block["operation_order"][1],
            block["operation_order"][0],
        )
    elif mutation == "operation-order-missing":
        block["operation_order"].pop()
    elif mutation == "operation-order-extra":
        block["operation_order"].append(PRIMITIVE_NAMES[0])
    elif mutation == "primitive-missing":
        block["seconds_by_primitive"].pop(PRIMITIVE_NAMES[0])
    elif mutation == "primitive-extra":
        block["seconds_by_primitive"]["invented-primitive"] = "1"
    elif mutation == "block-field-missing":
        block.pop("operation_order")
    elif mutation == "block-field-extra":
        block["ambient_temperature"] = "unknown"
    elif mutation == "duration-zero":
        block["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = "0"
    elif mutation == "duration-negative":
        block["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = "-1"
    elif mutation == "duration-noncanonical":
        block["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = "1.0"
    else:
        block["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = 1

    with pytest.raises(ValueError, match="calibration|primitive|operation|block|keys"):
        analyze_publication_results(payload)


def test_caller_supplied_tuned_alias_is_rejected() -> None:
    payload = _complete_payload()
    cell_width = len(REFERENCE_CANDIDATE_IDS) + len(FIXED_CANDIDATE_IDS)
    first_cell = payload["records"][:cell_width]
    forged_alias = next(
        record
        for record in first_cell
        if record["phase"] == "held-out"
        and record["record_kind"] == "fixed-candidate"
        and record["candidate_id"] == "padding-reuse"
    )
    forged_alias.update(
        {
            "record_kind": "tuned-fixed-policy",
            "candidate_role": "reference",
            "selection_source": "tuning-prefix-selected",
        }
    )

    with pytest.raises(ValueError, match="physical fixed execution|aliases"):
        analyze_publication_results(payload)


def test_input_contains_only_physical_fixed_executions_and_aliases_are_derived() -> None:
    payload = _complete_payload()
    result = analyze_publication_results(payload)

    assert result["physical_records_per_cell"] == 27
    assert result["heldout_view_records_per_cell"] == 16
    assert result["fixed_candidate_count"] == 14
    assert result["reference_candidate_count"] == 13
    assert result["ablation_candidate_count"] == 1
    assert result["derived_alias_count"] == 2
    first = result["unit_effects"][0]
    assert first["ablation_candidate_id"] == ABLATION_CANDIDATE_ID
    assert first["selected_candidate_id"] == "padding-reuse"
    assert first["diagnostic_oracle_candidate_id"] == "padding-reuse"


def test_tuning_source_identity_cannot_be_forged() -> None:
    payload = _complete_payload()
    payload["records"][0]["selection_source"] = "fixed-reference-held-out"

    with pytest.raises(ValueError, match="selection source contradict"):
        analyze_publication_results(payload)


def test_tuning_ties_use_the_canonical_candidate_id() -> None:
    payload = _complete_payload()
    cell_width = len(REFERENCE_CANDIDATE_IDS) + len(FIXED_CANDIDATE_IDS)
    first_cell = payload["records"][:cell_width]
    for record in first_cell[: len(REFERENCE_CANDIDATE_IDS)]:
        _set_encrypt_cost_per_observation(record, 10)
    expected = min(REFERENCE_CANDIDATE_IDS)
    result = analyze_publication_results(payload)

    assert result["unit_effects"][0]["selected_candidate_id"] == expected


def test_t1_and_t2_cannot_bind_unrelated_accepted_event_traces() -> None:
    payload = _complete_payload()
    t2_unit = payload["trace_units"][5]
    t2_unit["accepted_events_sha256"] = "f" * 64
    t2_unit["trace_binding_sha256"] = _canonical_digest(
        {key: value for key, value in t2_unit.items() if key != "trace_binding_sha256"}
    )

    with pytest.raises(ValueError, match="same paired raw trace"):
        analyze_publication_results(payload)


def test_record_cannot_splice_a_cell_binding_from_another_semantics() -> None:
    payload = _complete_payload()
    first_t2_cell = next(
        binding
        for binding in payload["cell_bindings"]
        if binding["dataset_id"] == DATASET_IDS[0]
        and binding["semantics"] == "T2"
        and binding["source_partition"] == 0
        and binding["freshness_seconds"] == FRESHNESS_VALUES[0]
        and binding["rho"] == RHO_VALUES[0]
    )
    payload["records"][0]["cell_binding_sha256"] = first_t2_cell["cell_binding_sha256"]

    with pytest.raises(ValueError, match="does not bind its canonical trace cell"):
        analyze_publication_results(payload)


def test_cell_cannot_splice_a_different_rho_schedule_even_after_rehashing() -> None:
    payload = _complete_payload()
    target = payload["cell_bindings"][0]
    donor = payload["cell_bindings"][1]
    assert target["rho"] != donor["rho"]
    assert target["freshness_seconds"] == donor["freshness_seconds"]
    target["event_schedule_sha256"] = donor["event_schedule_sha256"]
    _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="event schedule.*different rho"):
        analyze_publication_results(payload)


def test_one_freshness_cannot_retarget_its_event_schedule() -> None:
    payload = _complete_payload()
    target = payload["cell_bindings"][0]
    target["event_schedule_sha256"] = "f" * 64
    _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="all freshness cells.*same.*event schedule"):
        analyze_publication_results(payload)


def test_both_freshness_cells_cannot_reuse_another_rho_event_schedule() -> None:
    payload = _complete_payload()
    first_trace_cells = [
        binding
        for binding in payload["cell_bindings"]
        if binding["dataset_id"] == DATASET_IDS[0]
        and binding["semantics"] == SEMANTICS[0]
        and binding["source_partition"] == 0
    ]
    donor = next(binding for binding in first_trace_cells if binding["rho"] == RHO_VALUES[1])
    targets = [binding for binding in first_trace_cells if binding["rho"] == RHO_VALUES[0]]
    assert len(targets) == len(FRESHNESS_VALUES)
    for target in targets:
        target["event_schedule_sha256"] = donor["event_schedule_sha256"]
        _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="event schedule.*different rho"):
        analyze_publication_results(payload)


def test_cell_cannot_splice_another_trace_query_vector_even_after_rehashing() -> None:
    payload = _complete_payload()
    target = payload["cell_bindings"][0]
    donor = next(
        binding
        for binding in payload["cell_bindings"]
        if binding["source_partition"] == 1
        and binding["dataset_id"] == target["dataset_id"]
        and binding["semantics"] == target["semantics"]
    )
    target["query_vector_sha256"] = donor["query_vector_sha256"]
    _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="all freshness and rho cells.*same.*query vector"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    ("schema_field", "retargeted"),
    (
        ("event_schedule_schema_version", "dynamic-cssc-window-schedule-v1"),
        ("query_vector_schema_version", "caller-selected-query-vectors-v1"),
    ),
)
def test_cell_schedule_schema_identity_cannot_be_retargeted(
    schema_field: str,
    retargeted: str,
) -> None:
    payload = _complete_payload()
    target = payload["cell_bindings"][0]
    target[schema_field] = retargeted
    _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="schema_version is not the frozen"):
        analyze_publication_results(payload)


def test_phase_range_cannot_be_retargeted_even_when_descendant_digests_are_rewritten() -> None:
    payload = _complete_payload()
    trace_unit = payload["trace_units"][0]
    old_trace_binding = trace_unit["trace_binding_sha256"]
    trace_unit["tuning_accepted_event_group_range"] = [100, 401]
    trace_unit["heldout_accepted_event_group_range"] = [401, 1_000]
    range_receipt = {
        field: trace_unit[field]
        for field in (
            "accepted_raw_events_total",
            "warmup_accepted_event_group_range",
            "tuning_accepted_event_group_range",
            "heldout_accepted_event_group_range",
        )
    }
    trace_unit["accepted_event_group_ranges_sha256"] = _canonical_digest(range_receipt)
    trace_unit["trace_binding_sha256"] = _canonical_digest(
        {key: value for key, value in trace_unit.items() if key != "trace_binding_sha256"}
    )
    for cell_binding in payload["cell_bindings"]:
        if cell_binding["trace_binding_sha256"] != old_trace_binding:
            continue
        cell_binding.update(range_receipt)
        cell_binding["accepted_event_group_ranges_sha256"] = trace_unit[
            "accepted_event_group_ranges_sha256"
        ]
        cell_binding["trace_binding_sha256"] = trace_unit["trace_binding_sha256"]
        _rehash_cell_binding(payload, cell_binding)

    with pytest.raises(ValueError, match="exact common 10/30/60"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    ("phase", "record_count_field"),
    (("tuning-prefix", "update_count"), ("held-out", "query_count")),
)
def test_candidate_consistent_record_counts_cannot_override_the_cell_contract(
    phase: str,
    record_count_field: str,
) -> None:
    payload = _complete_payload()
    first_cell_binding = payload["cell_bindings"][0]
    first_cell_records = _records_for_cell_binding(
        payload,
        first_cell_binding["cell_binding_sha256"],
    )
    for record in first_cell_records:
        if record["phase"] == phase:
            record[record_count_field] += 1

    with pytest.raises(ValueError, match="record's phase update/query counts.*cell binding"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    "count_field",
    (
        "tuning_update_count",
        "tuning_query_count",
        "heldout_update_count",
        "heldout_query_count",
    ),
)
def test_cell_phase_counts_are_recomputed_from_ranges_and_rho(
    count_field: str,
) -> None:
    payload = _complete_payload()
    first_cell_binding = payload["cell_bindings"][0]
    old_digest = first_cell_binding["cell_binding_sha256"]
    first_cell_binding[count_field] += 1
    affected_records = _records_for_cell_binding(payload, old_digest)
    affected_phase = "tuning-prefix" if count_field.startswith("tuning_") else "held-out"
    for record in affected_records:
        if record["phase"] == affected_phase:
            record["update_count" if "_update_" in count_field else "query_count"] += 1
    _rehash_cell_binding(payload, first_cell_binding)

    with pytest.raises(ValueError, match="derived from.*accepted-event ranges.*exact rho"):
        analyze_publication_results(payload)


def test_one_rho_cannot_retarget_the_common_raw_event_ranges_after_rehashing() -> None:
    payload = _complete_payload()
    target = payload["cell_bindings"][1]
    replacement = _accepted_event_group_ranges(2_000)
    target.update(replacement)
    _rehash_cell_binding(payload, target)

    with pytest.raises(ValueError, match="does not match its trace unit"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    ("legacy_field", "value"),
    (
        ("split_receipt_sha256", "a" * 64),
        ("query_schedule_sha256", "b" * 64),
        ("query_vector_schedule_sha256", "c" * 64),
        ("warmup_window_range", [0, 10]),
        ("tuning_window_count", 30),
    ),
)
def test_window_based_split_fields_are_rejected_by_the_closed_cell_schema(
    legacy_field: str,
    value: object,
) -> None:
    payload = _complete_payload()
    payload["cell_bindings"][0][legacy_field] = value

    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(payload)


def test_legacy_trace_level_window_split_receipt_is_rejected() -> None:
    payload = _complete_payload()
    payload["trace_units"][0]["split_receipt_sha256"] = "a" * 64

    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(payload)


def test_old_trace_bundle_cannot_be_relabelled_with_the_analysis_head() -> None:
    payload = _complete_payload()
    trace_by_key: dict[tuple[str, str, int], dict[str, object]] = {}
    for trace_unit in payload["trace_units"]:
        trace_unit["experiment_source_git_sha"] = "2" * 40
        trace_unit["trace_binding_sha256"] = _canonical_digest(
            {key: value for key, value in trace_unit.items() if key != "trace_binding_sha256"}
        )
        trace_by_key[
            (
                trace_unit["dataset_id"],
                trace_unit["semantics"],
                trace_unit["source_partition"],
            )
        ] = trace_unit
    binding_by_key: dict[tuple[str, str, int, str, str], str] = {}
    for cell_binding in payload["cell_bindings"]:
        trace_unit = trace_by_key[
            (
                cell_binding["dataset_id"],
                cell_binding["semantics"],
                cell_binding["source_partition"],
            )
        ]
        cell_binding["experiment_source_git_sha"] = "2" * 40
        cell_binding["trace_binding_sha256"] = trace_unit["trace_binding_sha256"]
        cell_binding["cell_binding_sha256"] = _canonical_digest(
            {key: value for key, value in cell_binding.items() if key != "cell_binding_sha256"}
        )
        binding_by_key[
            (
                cell_binding["dataset_id"],
                cell_binding["semantics"],
                cell_binding["source_partition"],
                cell_binding["freshness_seconds"],
                cell_binding["rho"],
            )
        ] = cell_binding["cell_binding_sha256"]
    for record in payload["records"]:
        record["cell_binding_sha256"] = binding_by_key[
            (
                record["dataset_id"],
                record["semantics"],
                record["source_partition"],
                record["freshness_seconds"],
                record["rho"],
            )
        ]

    with pytest.raises(ValueError, match="experiment source"):
        analyze_publication_results(payload)


@pytest.mark.parametrize("mutation", ("missing", "extra", "invented"))
def test_primitive_vocabulary_is_closed_and_complete(mutation: str) -> None:
    payload = _complete_payload()
    calibration = payload["calibration"]
    if mutation == "missing":
        calibration["primitive_names"].pop()
    elif mutation == "extra":
        calibration["primitive_names"].append("measured-op")
    else:
        calibration["primitive_names"] = ["measured-op"]

    with pytest.raises(ValueError, match="frozen primitive vocabulary"):
        analyze_publication_results(payload)


def test_frozen_primitive_vocabulary_names_every_admitted_measured_operation() -> None:
    assert PRIMITIVE_NAMES == (
        "client_merge",
        "client_reorder_element",
        "decrypt",
        "deserialize_ciphertext",
        "encode",
        "encrypt",
        "eval_add_ciphertext",
        "eval_mult_plaintext_mask",
        "eval_mult_with_relinearization",
        "eval_rotate",
        "mask_map_element",
        "mask_random_element",
        "query_vector_pack",
        "serialize_ciphertext",
    )


def test_query_vector_pack_cannot_be_replaced_by_an_unused_blinding_primitive() -> None:
    payload = _complete_payload()
    names = payload["calibration"]["primitive_names"]
    index = names.index("query_vector_pack")
    names[index] = "eval_add_plaintext_blinding"
    for record in payload["records"]:
        for field in ("update_primitive_counts", "query_primitive_counts"):
            record[field]["eval_add_plaintext_blinding"] = record[field].pop("query_vector_pack")

    with pytest.raises(ValueError, match="frozen primitive vocabulary"):
        analyze_publication_results(payload)


def test_each_record_must_count_every_frozen_primitive() -> None:
    payload = _complete_payload()
    payload["records"][0]["update_primitive_counts"].pop(PRIMITIVE_NAMES[-1])

    with pytest.raises(ValueError, match="keys must exactly match"):
        analyze_publication_results(payload)


def test_experiment_source_sha_cannot_be_retargeted_away_from_the_analysis_head() -> None:
    payload = _complete_payload()
    _retarget_experiment_source(payload, "2" * 40)

    with pytest.raises(ValueError, match="HOLD.*Day1B"):
        analyze_publication_results(payload)


def test_caller_compatibility_document_cannot_bypass_the_repository_receipt() -> None:
    payload = _complete_payload()
    _retarget_experiment_source(payload, "2" * 40)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        analyze_publication_results(
            payload,
            evidence_compatibility_receipt={"compatibility_verified": True},
        )

    with pytest.raises(ValueError, match="HOLD.*Day1B"):
        analyze_publication_results(
            payload,
            evidence_freeze_git_sha="3" * 40,
            artifact_behavior_inventory={"role": "day1b"},
        )


def test_equal_source_is_identity_only_and_never_runtime_authority(
    successful_analysis: dict[str, object],
) -> None:
    assert successful_analysis["evidence_freeze_git_sha"] == "1" * 40
    assert successful_analysis["evidence_compatibility_kind"] == (
        "identical-snapshot-no-post-run-anchor"
    )
    assert successful_analysis["source_snapshot_compatibility_verified"] is True
    assert successful_analysis["evidence_compatibility_verified"] is False
    assert successful_analysis["evidence_compatibility_receipt_sha256"] is None
    assert successful_analysis["evidence_compatibility_post_run_anchor_verified"] is False
    assert successful_analysis["runtime_execution_isolation_authority_state"].startswith(
        "HOLD-until-fresh-checkout-isolated-interpreter"
    )
    assert successful_analysis["runtime_execution_isolation_verified"] is False
    assert successful_analysis["runtime_execution_isolation_receipt_schema_version"] == (
        "dynamic-cssc-runtime-execution-isolation-receipt-v1"
    )
    assert successful_analysis["runtime_execution_isolation_required_checks"][-1] == (
        "source-attestation-after-render-and-atomic-install"
    )
    assert successful_analysis["evidence_chain_authority_verified"] is False


def test_repository_analysis_source_requires_a_stable_fully_clean_head(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
    subprocess.run(
        ("git", "config", "user.email", "publication-test@example.invalid"),
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ("git", "config", "user.name", "Publication Test"),
        cwd=repository,
        check=True,
    )
    for relative_path in repository_behavior_paths(EvidenceRole.ANALYZER):
        behavior_source = repository / relative_path
        behavior_source.parent.mkdir(parents=True, exist_ok=True)
        behavior_source.write_text(f"fixture for {relative_path}\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(("git", "commit", "-qm", "trusted snapshot"), cwd=repository, check=True)

    source = verify_current_analysis_source(repository)
    assert source.attestation == "repository-clean-head"
    assert not hasattr(publication_statistics, "_verify_repository_analysis_source")

    (repository / "unrelated-untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(EvidenceCompatibilityError, match="stable fully clean"):
        verify_current_analysis_source(repository)


def test_analysis_rechecks_the_exact_source_attestation_after_long_computation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestations = iter(
        (
            publication_statistics._AnalysisSource("1" * 40, "test-only-injected"),
            publication_statistics._AnalysisSource("2" * 40, "repository-clean-head"),
        )
    )
    monkeypatch.setattr(publication_statistics, "_analysis_source", lambda: next(attestations))

    with pytest.raises(RuntimeError, match="changed during publication analysis"):
        analyze_publication_results(_complete_payload())


def test_point_calibration_uses_the_raw_median_not_the_mean_for_outliers() -> None:
    result = analyze_publication_results(
        _complete_payload(
            selected_update_bytes=50_000_000,
            calibration_repetitions=("1", "1", "100"),
        )
    )

    first = result["unit_effects"][0]
    assert first["selected_cost_seconds"] == "8.48"
    assert first["comparator_cost_seconds"] == "10.1"
    assert result["point_calibration_estimator"] == "whole-block-primitive-median"
    assert result["calibration_sensitivity_method"] == (
        "whole-block-resampling-with-fixed-15-unit-corpus-and-tuning-reselection"
    )
    assert result["calibration_partition_resampling"] is False


def test_threshold_boundary_is_rendered_as_an_exact_fraction_not_rounded_to_point_15() -> None:
    primitive_seconds = "3000000000000000000"
    selected_update_bytes = 189_375_000_000_000_012_625_000_000
    result = analyze_publication_results(
        _complete_payload(
            selected_update_bytes=selected_update_bytes,
            calibration_repetitions=(primitive_seconds, primitive_seconds),
        )
    )

    exact_below_threshold = "44999999999999999/300000000000000000"
    first = result["summaries"][0]
    assert result["unit_effects"][0]["effect"] == exact_below_threshold
    assert first["effect_median"] == exact_below_threshold
    assert first["partition_resampling_stability_interval_95"] == [
        exact_below_threshold,
        exact_below_threshold,
    ]
    assert first["calibration_median_effect_stability_interval_95"] == [
        exact_below_threshold,
        exact_below_threshold,
    ]
    assert first["calibration_median_threshold_classification_stable"] is True
    assert first["finite_corpus_rho_gate_passed"] is False


@pytest.mark.parametrize("extra_field", ("window_id", "query_seed", "measurement_seed"))
def test_windows_and_repeated_measurement_seeds_cannot_become_statistical_units(
    extra_field: str,
) -> None:
    payload = _complete_payload()
    payload["records"][0][extra_field] = 1

    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(payload)


@pytest.mark.parametrize(
    ("field", "retargeted"),
    (
        ("semantics", ["T1+T2"]),
        ("evaluated_freshness_seconds", ["0.1"]),
        ("primary_confirmatory_family", ["T1", "1"]),
        ("fixed_candidate_ids", list(reversed(FIXED_CANDIDATE_IDS))),
        ("ablation_candidate_ids", []),
        ("rho_values", sorted(RHO_VALUES)),
        ("comparator_candidate_id", "periodic-repack/windows=4"),
    ),
)
def test_frozen_semantics_rho_order_and_comparator_cannot_be_retargeted(
    field: str,
    retargeted: object,
) -> None:
    payload = _complete_payload()
    payload[field] = retargeted

    with pytest.raises(ValueError, match="exact frozen value"):
        analyze_publication_results(payload)


def test_secondary_only_success_cannot_authorize_the_sole_primary_gate() -> None:
    payload = _complete_payload()
    for record in payload["records"]:
        if (
            record["semantics"] == PRIMARY_CONFIRMATORY_FAMILY[0]
            and record["freshness_seconds"] == PRIMARY_CONFIRMATORY_FAMILY[1]
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
        ):
            _set_encrypt_cost_per_observation(record, 10)

    result = analyze_publication_results(payload)
    groups = result["group_verdicts"]
    primary = next(
        group for group in groups if group["analysis_role"] == "sole-confirmatory-primary"
    )
    secondary = [
        group for group in groups if group["analysis_role"] == "prespecified-secondary-robustness"
    ]

    assert primary["finite_corpus_adjacent_pair_classification_passed"] is False
    assert any(
        group["finite_corpus_adjacent_pair_classification_passed"] is True for group in secondary
    )
    assert result["finite_corpus_decision_calculation_passed"] is False
    assert result["headline_stability_calculation_passed"] is False
    assert result["primary_confirmatory_family"] == {
        "semantics": "T2",
        "freshness_seconds": "0.1",
        "analysis_role": "sole-confirmatory-primary",
        "is_primary_confirmatory_family": True,
    }


def test_complete_poor_secondary_panels_cannot_veto_a_passing_primary_family() -> None:
    payload = _complete_payload()
    for record in payload["records"]:
        if (
            (record["semantics"], record["freshness_seconds"]) != PRIMARY_CONFIRMATORY_FAMILY
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
        ):
            _set_encrypt_cost_per_observation(record, 12)

    result = analyze_publication_results(payload)
    primary = next(
        group
        for group in result["group_verdicts"]
        if group["analysis_role"] == "sole-confirmatory-primary"
    )
    secondary = [
        group
        for group in result["group_verdicts"]
        if group["analysis_role"] == "prespecified-secondary-robustness"
    ]

    assert primary["finite_corpus_adjacent_pair_classification_passed"] is True
    assert all(
        group["finite_corpus_adjacent_pair_classification_passed"] is False for group in secondary
    )
    assert result["all_candidate_outcomes_complete"] is True
    assert result["finite_corpus_decision_calculation_passed"] is True
    assert result["headline_stability_calculation_passed"] is True


def test_nonadjacent_primary_rho_points_cannot_satisfy_the_adjacency_rule() -> None:
    passing_rho = {RHO_VALUES[0], RHO_VALUES[2]}
    payload = _complete_payload()
    for record in payload["records"]:
        if (
            (record["semantics"], record["freshness_seconds"]) == PRIMARY_CONFIRMATORY_FAMILY
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
            and record["rho"] not in passing_rho
        ):
            _set_encrypt_cost_per_observation(record, 12)

    result = analyze_publication_results(payload)
    primary = next(
        group
        for group in result["group_verdicts"]
        if group["analysis_role"] == "sole-confirmatory-primary"
    )

    assert primary["adjacent_passing_rho_pairs"] == []
    assert primary["finite_corpus_adjacent_pair_classification_passed"] is False
    assert result["finite_corpus_decision_calculation_passed"] is False


@pytest.mark.parametrize(
    ("field", "retargeted"),
    (
        ("record_kind", "diagnostic-oracle"),
        ("candidate_id", ABLATION_CANDIDATE_ID),
        ("candidate_role", "ablation"),
    ),
)
def test_oracle_and_tuning_prefix_ablation_records_are_forbidden_from_input(
    field: str,
    retargeted: object,
) -> None:
    payload = _complete_payload()
    payload["records"][0][field] = retargeted

    with pytest.raises(ValueError, match="oracle|ablation|fixed candidate|contradict"):
        analyze_publication_results(payload)


def test_missing_records_and_forged_summaries_are_rejected_instead_of_dropped() -> None:
    missing_record = _complete_payload()
    missing_record["records"].pop()
    with pytest.raises(ValueError, match="exact 30 units"):
        analyze_publication_results(missing_record)

    forged_summary = _complete_payload()
    forged_summary["summary"] = {"effect_median": "0.99", "gate_passed": True}
    with pytest.raises(ValueError, match="keys must be exact"):
        analyze_publication_results(forged_summary)


def test_an_explicit_missing_candidate_is_reported_and_cannot_pass() -> None:
    payload = _complete_payload()
    missing = payload["records"][len(REFERENCE_CANDIDATE_IDS) + 1]
    missing["outcome"] = "missing"
    missing["failure_reason"] = "required held-out record was not emitted"
    for field in (
        "update_primitive_counts",
        "query_primitive_counts",
        "update_serialized_bytes",
        "query_serialized_bytes",
    ):
        missing[field] = None

    result = analyze_publication_results(payload)

    assert result["all_candidate_outcomes_complete"] is False
    assert result["preregistered_finite_corpus_gate_passed"] is False
    assert result["calibrated_component_result_stable"] is False
    assert len(result["failed_outcomes"]) == 1
    first = result["summaries"][0]
    assert first["complete_effect_count"] == 15
    assert first["effect_median"] == "0.2"
    assert first["all_candidate_outcomes_complete"] is False
    assert first["finite_corpus_rho_gate_passed"] is False
    assert result["unit_effects"][0]["diagnostic_oracle_candidate_id"] == (
        "diagnostic-oracle/unavailable"
    )
    assert result["unit_effects"][0]["diagnostic_oracle_outcome"] == "ineligible"


def test_incomplete_ablation_is_reported_but_never_enters_selection_or_oracle() -> None:
    payload = _complete_payload()
    first_ablation = next(
        record
        for record in payload["records"]
        if record["phase"] == "held-out" and record["candidate_id"] == ABLATION_CANDIDATE_ID
    )
    first_ablation["outcome"] = "timeout"
    first_ablation["failure_reason"] = "ablation exceeded the frozen timeout"
    for field in (
        "update_primitive_counts",
        "query_primitive_counts",
        "update_serialized_bytes",
        "query_serialized_bytes",
    ):
        first_ablation[field] = None

    result = analyze_publication_results(payload)
    first = result["unit_effects"][0]

    assert first["selected_candidate_id"] == "padding-reuse"
    assert first["diagnostic_oracle_candidate_id"] == "padding-reuse"
    assert first["ablation_outcome"] == "timeout"
    assert first["effect"] == "0.2"
    assert first["all_reference_outcomes_complete"] is True
    assert first["all_candidate_outcomes_complete"] is False
    assert result["all_candidate_outcomes_complete"] is False
    assert result["finite_corpus_decision_calculation_passed"] is False


def test_incomplete_tuning_candidate_is_reported_without_selecting_survivors() -> None:
    payload = _complete_payload()
    failed_tuning = payload["records"][0]
    failed_tuning["outcome"] = "timeout"
    failed_tuning["failure_reason"] = "tuning execution exceeded the frozen timeout"
    for field in (
        "update_primitive_counts",
        "query_primitive_counts",
        "update_serialized_bytes",
        "query_serialized_bytes",
    ):
        failed_tuning[field] = None

    result = analyze_publication_results(payload)
    first = result["unit_effects"][0]

    assert first["selected_candidate_id"] == "tuned-fixed-policy/unavailable"
    assert first["selected_outcome"] == "ineligible"
    assert first["diagnostic_oracle_candidate_id"] == "padding-reuse"
    assert first["effect"] is None
    assert first["all_tuning_outcomes_complete"] is False
    assert result["all_candidate_outcomes_complete"] is False
    assert result["finite_corpus_decision_calculation_passed"] is False
    assert any(
        failure["phase"] == "tuning-prefix" and failure["candidate_id"] == "padding-reuse"
        for failure in result["failed_outcomes"]
    )


def test_a_missing_selected_pair_remains_an_explicit_null_point_without_imputation() -> None:
    payload = _complete_payload()
    first_cell = payload["records"][: len(REFERENCE_CANDIDATE_IDS) + len(FIXED_CANDIDATE_IDS)]
    selected_records = [
        record
        for record in first_cell
        if record["candidate_id"] == "padding-reuse" and record["phase"] == "held-out"
    ]
    assert len(selected_records) == 1
    for record in selected_records:
        record["outcome"] = "timeout"
        record["failure_reason"] = "candidate exceeded the frozen timeout"
        for field in (
            "update_primitive_counts",
            "query_primitive_counts",
            "update_serialized_bytes",
            "query_serialized_bytes",
        ):
            record[field] = None

    result = analyze_publication_results(payload)
    first = result["summaries"][0]

    assert first["unit_count"] == 15
    assert first["complete_effect_count"] == 14
    assert first["effect_median"] is None
    assert first["partition_resampling_stability_interval_95"] is None
    assert len(first["all_points"]) == 15
    assert first["all_points"][0]["effect"] is None
    assert result["summaries"][1]["finite_corpus_rho_gate_passed"] is True
    assert result["preregistered_finite_corpus_gate_passed"] is False


def test_zero_effects_are_kept_and_fail_the_strict_finite_corpus_rule() -> None:
    result = analyze_publication_results(_complete_payload(selected_multiplier=10))
    first = result["summaries"][0]

    assert first["complete_effect_count"] == 15
    assert first["effect_median"] == "0"
    assert first["positive_effect_count"] == 0
    assert first["all_15_unit_effects_positive"] is False
    assert first["finite_corpus_rho_gate_passed"] is False
    assert result["preregistered_finite_corpus_gate_passed"] is False


def test_fourteen_of_fifteen_positive_units_cannot_pass_the_fixed_corpus_rule() -> None:
    payload = _complete_payload()
    changed = False
    for record in payload["records"]:
        if (
            record["dataset_id"] == DATASET_IDS[0]
            and record["semantics"] == PRIMARY_CONFIRMATORY_FAMILY[0]
            and record["source_partition"] == 0
            and record["freshness_seconds"] == PRIMARY_CONFIRMATORY_FAMILY[1]
            and record["rho"] == RHO_VALUES[0]
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
        ):
            _set_encrypt_cost_per_observation(record, 12)
            changed = True
    assert changed

    result = analyze_publication_results(payload)
    summary = next(
        item
        for item in result["summaries"]
        if item["semantics"] == PRIMARY_CONFIRMATORY_FAMILY[0]
        and item["freshness_seconds"] == PRIMARY_CONFIRMATORY_FAMILY[1]
        and item["rho"] == RHO_VALUES[0]
    )

    assert summary["complete_effect_count"] == 15
    assert summary["effect_median"] == "0.2"
    assert summary["positive_effect_count"] == 14
    assert summary["all_15_unit_effects_positive"] is False
    assert summary["finite_corpus_rho_gate_passed"] is False


def test_negative_result_takes_the_frozen_methodology_fallback() -> None:
    result = analyze_publication_results(_complete_payload(selected_multiplier=12))

    assert result["summaries"][0]["effect_median"] == "-0.2"
    assert result["preregistered_finite_corpus_gate_passed"] is False
    assert result["calibrated_component_result_stable"] is False
    assert result["formal_performance_claim_allowed"] is False


def test_byte_cost_uses_the_exact_decimal_megabits_per_second_conversion() -> None:
    result = analyze_publication_results(_complete_payload(selected_update_bytes=125_000_000))
    first = result["unit_effects"][0]

    assert first["selected_cost_seconds"] == "9.08"
    assert first["comparator_cost_seconds"] == "10.1"
    assert first["selected_update_bytes_per_accepted_event_group"] == "125000000"


def test_nested_calibration_instability_withholds_the_headline() -> None:
    result = analyze_publication_results(
        _complete_payload(
            selected_update_bytes=50_000_000,
            calibration_repetitions=("0.01", "1.99"),
        )
    )

    assert result["finite_corpus_decision_calculation_passed"] is True
    assert result["preregistered_finite_corpus_gate_passed"] is False
    assert result["calibration_sensitivity_stable"] is False
    assert result["calibrated_component_result_stable"] is False
    assert any(
        verdict["adjacent_pairs_classification_stable"] is False
        for verdict in result["calibration_sensitivity"]
    )


def test_nested_calibration_reselects_the_tuning_winner_before_heldout_scoring() -> None:
    payload = _complete_payload(calibration_repetitions=("1", "1", "100"))
    _set_calibration_primitive_values(
        payload,
        "query_vector_pack",
        ("1", "100", "100"),
    )
    for record in payload["records"]:
        if record["candidate_id"] != "mini-cssc-delta":
            continue
        if record["phase"] == "tuning-prefix":
            update_counts = _primitive_counts(0)
            update_counts["query_vector_pack"] = record["update_count"]
            query_counts = _primitive_counts(0)
            query_counts["query_vector_pack"] = record["query_count"]
            record["update_primitive_counts"] = update_counts
            record["query_primitive_counts"] = query_counts
        elif record["record_kind"] == "fixed-candidate":
            _set_encrypt_cost_per_observation(record, 20)

    result = analyze_publication_results(payload)
    first = result["summaries"][0]

    assert first["effect_median"] == "0.2"
    assert Fraction(first["calibration_median_effect_stability_interval_95"][0]) < 0
    assert first["calibration_rho_gate_classification_stable"] is False
    assert result["calibration_sensitivity_stable"] is False
    assert result["calibrated_component_result_stable"] is False


def test_calibration_recomputes_each_fixed_unit_and_its_pareto_classification() -> None:
    payload = _complete_payload()
    _set_calibration_primitive_values(
        payload,
        "query_vector_pack",
        ("0.01", "0.01", "100"),
    )
    changed = False
    for record in payload["records"]:
        if (
            record["dataset_id"] == DATASET_IDS[0]
            and record["semantics"] == PRIMARY_CONFIRMATORY_FAMILY[0]
            and record["source_partition"] == 0
            and record["freshness_seconds"] == PRIMARY_CONFIRMATORY_FAMILY[1]
            and record["rho"] == "0.1"
            and record["phase"] == "held-out"
            and record["candidate_id"] == "padding-reuse"
        ):
            query_counts = _primitive_counts(8 * record["query_count"])
            query_counts["query_vector_pack"] = record["query_count"]
            record["query_primitive_counts"] = query_counts
            changed = True
    assert changed

    result = analyze_publication_results(payload)
    summary = next(
        item
        for item in result["summaries"]
        if item["semantics"] == PRIMARY_CONFIRMATORY_FAMILY[0]
        and item["freshness_seconds"] == PRIMARY_CONFIRMATORY_FAMILY[1]
        and item["rho"] == "0.1"
    )

    assert summary["finite_corpus_rho_gate_passed"] is True
    assert (
        summary["calibration_all_15_positive_match_count"] < CALIBRATION_CLASSIFICATION_REPETITIONS
    )
    assert (
        summary["calibration_all_units_nondominated_match_count"]
        < CALIBRATION_CLASSIFICATION_REPETITIONS
    )
    assert summary["calibration_rho_gate_match_count"] < CALIBRATION_CLASSIFICATION_REPETITIONS
    assert result["calibration_sensitivity_stable"] is False
    assert result["headline_stability_calculation_passed"] is False


def test_partition_resampling_reweights_paired_units_inside_each_dataset_stratum() -> None:
    payload = _complete_payload()
    dataset_ratio = {
        DATASET_IDS[0]: (9, 10),
        DATASET_IDS[1]: (10, 10),
        DATASET_IDS[2]: (11, 10),
    }
    for record in payload["records"]:
        if record["phase"] != "held-out":
            continue
        if record["candidate_id"] not in {"padding-reuse", COMPARATOR_CANDIDATE_ID}:
            continue
        numerator, denominator = dataset_ratio[record["dataset_id"]]
        comparator_count = (record["source_partition"] + 5) * 100
        count = (
            comparator_count
            if record["candidate_id"] == COMPARATOR_CANDIDATE_ID
            else comparator_count * numerator // denominator
        )
        _set_encrypt_cost_per_observation(record, count)

    result = analyze_publication_results(payload)
    first = result["summaries"][0]

    assert first["effect_median"] == "0"
    assert first["partition_resampling_stability_interval_95"] == ["0", "0"]
    assert [point["effect"] for point in first["all_points"]] == [
        *(["0.1"] * 5),
        *(["0"] * 5),
        *(["-0.1"] * 5),
    ]


def test_a_dominated_tuning_procedure_cannot_pass_the_primary_gate() -> None:
    payload = _complete_payload()
    for record in payload["records"]:
        if (
            record["phase"] == "held-out"
            and record["record_kind"] == "fixed-candidate"
            and record["candidate_id"] == "mini-cssc-delta"
        ):
            _set_encrypt_cost_per_observation(record, 7)

    result = analyze_publication_results(payload)

    assert result["all_candidate_outcomes_complete"] is True
    assert result["summaries"][0]["effect_median"] == "0.2"
    assert result["summaries"][0]["all_units_non_dominated"] is False
    assert result["summaries"][0]["finite_corpus_rho_gate_passed"] is False
    assert result["preregistered_finite_corpus_gate_passed"] is False


def test_bootstrap_and_nested_calibration_are_byte_reproducible(
    successful_analysis: dict[str, object],
) -> None:
    assert analyze_publication_results(_complete_payload()) == successful_analysis


def test_artifact_set_is_closed_and_canonical(
    successful_analysis: dict[str, object],
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "analysis"
    digests = write_publication_analysis_artifacts(output_dir, _complete_payload())
    artifacts = {
        path.name: path.read_bytes()
        for path in sorted(output_dir.iterdir(), key=lambda path: path.name)
    }

    assert set(artifacts) == {
        "publication-verdict.json",
        "publication-effects.csv",
        "publication-summary.csv",
        "SHA256SUMS",
    }
    assert digests == {
        filename: hashlib.sha256(content).hexdigest() for filename, content in artifacts.items()
    }
    assert artifacts["publication-verdict.json"].endswith(b"\n")
    assert json.loads(artifacts["publication-verdict.json"]) == successful_analysis
    assert artifacts["publication-effects.csv"].count(b"\n") == 541
    assert artifacts["publication-summary.csv"].count(b"\n") == 37
    assert artifacts["SHA256SUMS"].count(b"\n") == 3
    for line in artifacts["SHA256SUMS"].decode("ascii").splitlines():
        digest, filename = line.split("  ", maxsplit=1)
        assert hashlib.sha256(artifacts[filename]).hexdigest() == digest
    assert len(successful_analysis["canonical_input_sha256"]) == 64
    assert set(successful_analysis["canonical_input_sha256"]) <= set("0123456789abcdef")


def test_summary_csv_marks_the_primary_family_without_granting_authority(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "analysis"
    write_publication_analysis_artifacts(output_dir, _complete_payload())
    with (output_dir / "publication-summary.csv").open(
        newline="",
        encoding="utf-8",
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert "is_primary_confirmatory_family" in rows[0]
    assert {
        row["is_primary_confirmatory_family"]
        for row in rows
        if row["analysis_role"] == "sole-confirmatory-primary"
    } == {"true"}
    assert {
        row["is_primary_confirmatory_family"]
        for row in rows
        if row["analysis_role"] == "prespecified-secondary-robustness"
    } == {"false"}


def test_artifact_writer_refuses_even_an_empty_preexisting_output_directory(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "analysis"
    output_dir.mkdir()

    with pytest.raises(ValueError, match="must not already exist"):
        write_publication_analysis_artifacts(output_dir, _complete_payload())
