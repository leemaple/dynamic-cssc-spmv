from __future__ import annotations

import csv
import hashlib
import json
import warnings
from dataclasses import asdict, replace
from inspect import signature
from pathlib import Path

import pytest

import dynamic_cssc.day1_registry as registry
import dynamic_cssc.report as report
from dynamic_cssc.day1_registry import (
    Day1CandidateCatalog,
    Day1CandidateRegistrationError,
    RegistrationEvidence,
)
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.report import (
    CausalMetricRecord,
    validate_causal_payload,
    write_causal_plots,
    write_causal_records,
    write_causal_summary,
)
from dynamic_cssc.simulator import RotationInventory


def _registered_catalog() -> Day1CandidateCatalog:
    registration = RegistrationEvidence(
        schema_version="dynamic-cssc-day1-registration-evidence-v1",
        source_git_sha="1" * 40,
        run_id=123,
        correctness_artifact_sha256="2" * 64,
        accounting_evidence_sha256="3" * 64,
        policy_contract_sha256=("a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"),
    )
    return registry._build_day1_candidate_catalog(registration)


def _unavailable_catalog() -> Day1CandidateCatalog:
    raise Day1CandidateRegistrationError(
        "no repository-approved Day-1 composite registration anchor"
    )


@pytest.fixture(autouse=True)
def _authorized_report_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = _registered_catalog()
    monkeypatch.setattr(report, "repository_day1_candidate_catalog", lambda: catalog)


def test_public_causal_validator_owns_the_zero_argument_catalog_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def unavailable_catalog() -> object:
        nonlocal calls
        calls += 1
        raise Day1CandidateRegistrationError("registration authority unavailable")

    monkeypatch.setattr(
        report,
        "repository_day1_candidate_catalog",
        unavailable_catalog,
        raising=False,
    )

    assert tuple(signature(validate_causal_payload).parameters) == ("payload",)
    with pytest.raises(Day1CandidateRegistrationError, match="authority unavailable"):
        validate_causal_payload({})
    assert calls == 1


def test_fixed_causal_record_exposes_an_explicit_ablation_role() -> None:
    record = CausalMetricRecord(
        record_kind="fixed-candidate",
        candidate_id="packed-coo-client-lane-delta/capacity=128",
        label="packed-coo-client-lane-delta/capacity=128",
        strategy_kind="Packed-COO-Client-Lane-Delta",
        selection_source="fixed-candidate",
        metrics=StrategyMetrics(
            "Packed-COO-Client-Lane-Delta",
            "ablation",
            source="persistent-state-predicted",
        ),
        candidate_role="ablation",
    )

    assert record.candidate_role == "ablation"


def test_fixed_causal_record_reconciles_exact_rotation_counts_and_preserves_warmup_keys() -> None:
    record = replace(
        _fixed_record(),
        metrics=replace(_fixed_record().metrics, rotations=2),
        rotation_inventory=RotationInventory(((1, 2),), (1, 2)),
    )

    assert record.rotation_inventory.measured_counts_by_exact_index == ((1, 2),)
    assert record.rotation_inventory.required_indices == (1, 2)

    with pytest.raises(ValueError, match="rotation inventory.*metrics.rotations"):
        replace(record, metrics=replace(record.metrics, rotations=3))


def test_fixed_causal_record_requires_closed_update_accounting() -> None:
    with pytest.raises(ValueError, match="update_encryptions.*update_ciphertexts"):
        replace(
            _fixed_record(),
            metrics=replace(
                _fixed_record().metrics,
                update_encryptions=2,
                update_ciphertexts=1,
            ),
        )


def test_fixed_causal_record_requires_closed_query_accounting() -> None:
    with pytest.raises(ValueError, match="query_ciphertexts.*relinearizations"):
        replace(
            _fixed_record(),
            metrics=replace(
                _fixed_record().metrics,
                query_ciphertexts=1,
                cc_multiplications=1,
                relinearizations=0,
            ),
        )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"result_ciphertexts": 1}, "result_ciphertexts.*decryptions"),
        (
            {"blinding_mask_ciphertexts": 1},
            "blinding_encryptions.*blinding_mask_ciphertexts",
        ),
        (
            {"blinding_encryptions": 1, "blinding_mask_ciphertexts": 1},
            "blinding_additions.*blinding_encryptions",
        ),
    ],
)
def test_fixed_causal_record_requires_remaining_closed_accounting(
    changes: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(
            _fixed_record(),
            metrics=replace(_fixed_record().metrics, **changes),
        )


def test_fixed_causal_record_does_not_treat_structural_outcomes_as_all_updates() -> None:
    record = replace(
        _fixed_record(),
        metrics=replace(
            _fixed_record().metrics,
            updates=3,
            update_encryptions=1,
            update_ciphertexts=1,
            overflow_updates=2,
        ),
    )

    assert record.metrics.updates == 3
    assert record.metrics.absorbed_updates + record.metrics.overflow_updates == 2


def _fixed_record(
    candidate_id: str = "reserved-slack/beta=0.05",
    strategy_kind: str = "ReservedSlack-CSSC",
    candidate_role: str = "reference",
) -> CausalMetricRecord:
    return CausalMetricRecord(
        record_kind="fixed-candidate",
        candidate_id=candidate_id,
        label=candidate_id,
        strategy_kind=strategy_kind,
        selection_source="fixed-candidate",
        metrics=StrategyMetrics(
            strategy_kind,
            candidate_role,
            source="persistent-state-predicted",
        ),
        candidate_role=candidate_role,  # type: ignore[arg-type]
    )


def _tuned_record(
    candidate_id: str = "reserved-slack/beta=0.05",
    strategy_kind: str = "ReservedSlack-CSSC",
) -> CausalMetricRecord:
    return CausalMetricRecord(
        record_kind="tuned-fixed-policy",
        candidate_id=candidate_id,
        label="TunedFixedPolicy",
        strategy_kind=strategy_kind,
        selection_source="tuning-prefix-only",
        metrics=StrategyMetrics(
            "TunedFixedPolicy",
            "tuned-fixed-policy",
            source="tuning-prefix-frozen",
        ),
    )


def _oracle_record(
    candidate_id: str = "reserved-slack/beta=0.05",
    strategy_kind: str = "ReservedSlack-CSSC",
) -> CausalMetricRecord:
    return CausalMetricRecord(
        record_kind="diagnostic-oracle",
        candidate_id=candidate_id,
        label="BestFixed-Offline-Oracle",
        strategy_kind=strategy_kind,
        selection_source="held-out-hindsight-diagnostic-only",
        metrics=StrategyMetrics(
            "BestFixed-Offline-Oracle",
            "diagnostic-oracle",
            source="held-out-hindsight-diagnostic",
        ),
    )


def _auditable_report_fixture() -> tuple[
    list[CausalMetricRecord],
    dict[str, StrategyMetrics],
    UnitCosts,
    dict[str, object],
    str,
    str,
]:
    fixed_records: list[CausalMetricRecord] = []
    tuning_results: dict[str, StrategyMetrics] = {}
    selected_candidate_id = "reserved-slack/beta=0.05"
    oracle_candidate_id = "mini-cssc-delta"
    ablation_candidate_id = "packed-coo-client-lane-delta/capacity=128"
    for index, candidate in enumerate(_registered_catalog().candidates):
        held_out_encryptions = (
            0
            if candidate.candidate_id == ablation_candidate_id
            else 2
            if candidate.candidate_id == oracle_candidate_id
            else 200 + index
        )
        fixed_records.append(
            CausalMetricRecord(
                "fixed-candidate",
                candidate.candidate_id,
                candidate.candidate_id,
                candidate.strategy,
                "fixed-candidate",
                StrategyMetrics(
                    candidate.strategy,
                    candidate.role,
                    windows=4,
                    queries=8,
                    updates=16,
                    update_encryptions=held_out_encryptions,
                    update_ciphertexts=held_out_encryptions,
                    absorbed_updates=16,
                    source="persistent-state-predicted",
                ),
                candidate_role=candidate.role,
            )
        )
        if candidate.role != "reference":
            continue
        tuning_encryptions = 1 if candidate.candidate_id == selected_candidate_id else 100 + index
        tuning_results[candidate.candidate_id] = StrategyMetrics(
            candidate.strategy,
            "reference",
            windows=3,
            queries=6,
            updates=12,
            update_encryptions=tuning_encryptions,
            update_ciphertexts=tuning_encryptions,
            absorbed_updates=12,
            source="persistent-state-predicted",
        )

    fixed_by_id = {record.candidate_id: record for record in fixed_records}
    tuned_basis = fixed_by_id[selected_candidate_id]
    oracle_basis = fixed_by_id[oracle_candidate_id]
    tuned = CausalMetricRecord(
        "tuned-fixed-policy",
        selected_candidate_id,
        "TunedFixedPolicy",
        tuned_basis.strategy_kind,
        "tuning-prefix-only",
        replace(
            tuned_basis.metrics,
            strategy="TunedFixedPolicy",
            category="tuned-fixed-policy",
            source="tuning-prefix-frozen",
        ),
        rotation_inventory=tuned_basis.rotation_inventory,
    )
    oracle = CausalMetricRecord(
        "diagnostic-oracle",
        oracle_candidate_id,
        "BestFixed-Offline-Oracle",
        oracle_basis.strategy_kind,
        "held-out-hindsight-diagnostic-only",
        replace(
            oracle_basis.metrics,
            strategy="BestFixed-Offline-Oracle",
            category="diagnostic-oracle",
            source="held-out-hindsight-diagnostic",
        ),
        rotation_inventory=oracle_basis.rotation_inventory,
    )
    metadata: dict[str, object] = {
        "selected_candidate_id": selected_candidate_id,
        "oracle_candidate_id": oracle_candidate_id,
        "fixed_candidate_count": 14,
        "reference_candidate_count": 13,
        "ablation_candidate_count": 1,
        "complete_reference_set": True,
    }
    return (
        [*fixed_records, tuned, oracle],
        tuning_results,
        UnitCosts(),
        metadata,
        selected_candidate_id,
        oracle_candidate_id,
    )


def _placeholder_audit_kwargs() -> dict[str, object]:
    return {
        "tuning_results": {},
        "selected_candidate_id": "reserved-slack/beta=0.05",
        "oracle_candidate_id": "reserved-slack/beta=0.05",
    }


def _write_auditable_payload(tmp_path: Path) -> tuple[dict[str, object], Day1CandidateCatalog]:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    return payload, _registered_catalog()


def test_causal_schema_v2_emits_the_registered_14_13_1_16_completion_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _registered_catalog()
    authority_calls = 0

    def registered_catalog() -> Day1CandidateCatalog:
        nonlocal authority_calls
        authority_calls += 1
        return catalog

    monkeypatch.setattr(report, "repository_day1_candidate_catalog", registered_catalog)
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()

    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    validate_causal_payload(payload)

    reference_ids = sorted(candidate.candidate_id for candidate in catalog.selection_candidates)
    ablation_ids = sorted(candidate.candidate_id for candidate in catalog.ablation_candidates)
    fixed_ids = sorted(candidate.candidate_id for candidate in catalog.candidates)
    assert authority_calls == 2
    assert payload["schema"] == "day1-causal-predicted-v2"
    assert payload["complete_reference_set"] is True
    assert payload["gate_eligible"] is False
    assert payload["complete_cost_claim_allowed"] is False
    assert payload["security_claim_allowed"] is False
    assert payload["formal_performance_claim"] is False
    assert len(payload["records"]) == 16
    assert [record["candidate_id"] for record in payload["records"][:14]] == fixed_ids
    assert {
        record["candidate_id"]: record["candidate_role"] for record in payload["records"][:14]
    } == {
        **{candidate_id: "reference" for candidate_id in reference_ids},
        **{candidate_id: "ablation" for candidate_id in ablation_ids},
    }
    assert [item["candidate_id"] for item in payload["tuning_aggregates"]] == reference_ids
    assert payload["metadata"]["oracle_candidate_id"] in reference_ids
    assert payload["metadata"]["oracle_candidate_id"] not in ablation_ids
    proof = payload["completion_proof"]
    assert proof["schema"] == "day1-causal-completion-proof-v1"
    assert proof["registration"] == asdict(catalog.registration)
    assert proof["fixed_candidate_count"] == 14
    assert proof["reference_candidate_count"] == 13
    assert proof["ablation_candidate_count"] == 1
    assert proof["tuning_candidate_count"] == 13
    assert proof["record_count"] == 16
    assert proof["fixed_candidate_ids"] == fixed_ids
    assert proof["reference_candidate_ids"] == reference_ids
    assert proof["ablation_candidate_ids"] == ablation_ids
    assert proof["tuning_candidate_ids"] == reference_ids
    assert proof["accounting_invariants"] == [
        "metadata_units=ci_patch_entries+ci_full_sync_entries",
        "update_encryptions=update_ciphertexts+compaction_ciphertexts",
        "query_ciphertexts=cc_multiplications=relinearizations",
        "result_ciphertexts=decryptions",
        "blinding_encryptions=blinding_mask_ciphertexts+blinding_dummy_ciphertexts",
        "blinding_additions=blinding_encryptions",
        "rotations=sum(measured_counts_by_exact_index)",
    ]
    assert [item["candidate_id"] for item in proof["fixed_rotation_inventories"]] == fixed_ids
    assert all(
        set(item)
        == {
            "candidate_id",
            "measured_counts_by_exact_index",
            "required_indices",
        }
        for item in proof["fixed_rotation_inventories"]
    )


def _canonical_auditable_payload() -> dict[str, object]:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    decoded = report._decode_causal_inputs(
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
        candidate_catalog=_registered_catalog(),
    )
    return report._canonical_payload(decoded)


def test_public_validator_fails_closed_while_the_composite_registration_gate_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        report,
        "repository_day1_candidate_catalog",
        _unavailable_catalog,
    )
    with pytest.raises(
        Day1CandidateRegistrationError,
        match="no repository-approved Day-1 composite registration anchor",
    ):
        validate_causal_payload(_canonical_auditable_payload())


def test_all_public_causal_artifact_paths_fail_closed_without_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _canonical_auditable_payload()
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    audit = {
        "tuning_results": tuning_results,
        "selected_candidate_id": selected_id,
        "oracle_candidate_id": oracle_id,
    }
    monkeypatch.setattr(
        report,
        "repository_day1_candidate_catalog",
        _unavailable_catalog,
    )
    operations = (
        lambda: report.render_causal_artifacts(tmp_path / "render", payload),
        lambda: write_causal_records(tmp_path / "records", records, costs, metadata, **audit),
        lambda: write_causal_summary(tmp_path / "summary", records, costs, metadata, **audit),
        lambda: write_causal_plots(tmp_path / "plots", records, costs, **audit),
    )

    for operation in operations:
        with pytest.raises(
            Day1CandidateRegistrationError,
            match="no repository-approved Day-1 composite registration anchor",
        ):
            operation()
    assert not tmp_path.exists() or not any(tmp_path.iterdir())


def test_private_decoder_rejects_a_jointly_forged_ablation_role() -> None:
    payload = _canonical_auditable_payload()
    ablation = next(
        record
        for record in payload["records"]
        if record["candidate_id"] == "packed-coo-client-lane-delta/capacity=128"
    )
    ablation["candidate_role"] = "reference"
    ablation["category"] = "reference"

    with pytest.raises(ValueError, match="candidate_role.*registration"):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


def test_private_decoder_rejects_an_ablation_in_the_tuning_inventory() -> None:
    payload = _canonical_auditable_payload()
    payload["tuning_aggregates"][0]["candidate_id"] = "packed-coo-client-lane-delta/capacity=128"

    with pytest.raises(ValueError, match="tuning_aggregates candidate_ids"):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


def test_private_decoder_rejects_an_ablation_as_the_held_out_oracle() -> None:
    payload = _canonical_auditable_payload()
    payload["metadata"]["oracle_candidate_id"] = "packed-coo-client-lane-delta/capacity=128"

    with pytest.raises(ValueError, match="oracle_candidate_id.*reference"):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


def test_completion_proof_binds_every_fixed_rotation_inventory_exactly() -> None:
    payload = _canonical_auditable_payload()
    payload["completion_proof"]["fixed_rotation_inventories"][0]["required_indices"] = [17]

    with pytest.raises(ValueError, match="completion_proof.*required_indices"):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


def test_serialized_rotation_inventory_rejects_measured_keys_outside_requirements() -> None:
    payload = _canonical_auditable_payload()
    payload["records"][0]["rotation_inventory"] = {
        "measured_counts_by_exact_index": [[1, 1]],
        "required_indices": [],
    }

    with pytest.raises(ValueError, match="rotation_inventory.*canonical and complete"):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


@pytest.mark.parametrize(
    ("location", "field_name"),
    [
        ("payload", "gate_eligible"),
        ("payload", "complete_cost_claim_allowed"),
        ("payload", "security_claim_allowed"),
        ("payload", "formal_performance_claim"),
        ("metadata", "security_claim_allowed"),
        ("record", "formal_performance_claim"),
    ],
)
def test_private_decoder_keeps_all_gate_cost_security_and_performance_claims_false(
    location: str,
    field_name: str,
) -> None:
    payload = _canonical_auditable_payload()
    target = (
        payload
        if location == "payload"
        else payload["metadata"]
        if location == "metadata"
        else payload["records"][0]
    )
    target[field_name] = True

    with pytest.raises(ValueError, match=field_name):
        report._decode_causal_payload(
            payload,
            candidate_catalog=_registered_catalog(),
        )


def test_completion_proof_preserves_a_warmup_only_required_rotation_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _registered_catalog()
    monkeypatch.setattr(report, "repository_day1_candidate_catalog", lambda: catalog)
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    candidate_id = "padding-reuse"
    index = next(
        index
        for index, record in enumerate(records)
        if record.record_kind == "fixed-candidate" and record.candidate_id == candidate_id
    )
    records[index] = replace(
        records[index],
        rotation_inventory=RotationInventory((), (17,)),
    )

    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))

    fixed_record = next(
        record for record in payload["records"] if record["candidate_id"] == candidate_id
    )
    proof_inventory = next(
        item
        for item in payload["completion_proof"]["fixed_rotation_inventories"]
        if item["candidate_id"] == candidate_id
    )
    assert fixed_record["rotation_inventory"]["required_indices"] == [17]
    assert proof_inventory["required_indices"] == [17]


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "error_type", "message"),
    [
        ("record_kind", 1, TypeError, "record_kind"),
        ("record_kind", "other", ValueError, "record_kind"),
        ("candidate_id", True, TypeError, "candidate_id"),
        ("candidate_id", 1, TypeError, "candidate_id"),
        ("candidate_id", "", ValueError, "candidate_id"),
        ("label", True, TypeError, "label"),
        ("label", 1, TypeError, "label"),
        ("label", "", ValueError, "label"),
        ("label", "not-the-candidate", ValueError, "label"),
        ("strategy_kind", False, TypeError, "strategy_kind"),
        ("strategy_kind", 1, TypeError, "strategy_kind"),
        ("strategy_kind", "", ValueError, "strategy_kind"),
        ("strategy_kind", "PeriodicRepack", ValueError, "strategy_kind"),
        ("phase", 1, TypeError, "phase"),
        ("phase", True, TypeError, "phase"),
        ("phase", "tuning", ValueError, "phase"),
        ("selection_source", True, TypeError, "selection_source"),
        ("selection_source", 1, TypeError, "selection_source"),
        ("selection_source", "", ValueError, "selection_source"),
        ("selection_source", "tuning-prefix-only", ValueError, "selection_source"),
        ("gate_eligible", 0, TypeError, "gate_eligible"),
        ("gate_eligible", True, ValueError, "gate_eligible"),
        (
            "complete_cost_claim_allowed",
            0,
            TypeError,
            "complete_cost_claim_allowed",
        ),
        (
            "complete_cost_claim_allowed",
            True,
            ValueError,
            "complete_cost_claim_allowed",
        ),
    ],
)
def test_causal_record_rejects_noncanonical_schema_values(
    field_name: str,
    invalid_value: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        replace(_fixed_record(), **{field_name: invalid_value})


@pytest.mark.parametrize(
    ("record", "metrics_changes", "message"),
    [
        (_fixed_record(), {"category": "tuned-fixed-policy"}, "category"),
        (_fixed_record(), {"source": "predicted-proxy"}, "source"),
        (_tuned_record(), {"strategy": "ReservedSlack-CSSC"}, "strategy"),
        (_tuned_record(), {"category": "reference"}, "category"),
        (_tuned_record(), {"source": "predicted-proxy"}, "source"),
        (_oracle_record(), {"strategy": "PeriodicRepack"}, "strategy"),
        (_oracle_record(), {"category": "reference"}, "category"),
        (_oracle_record(), {"source": "predicted-proxy"}, "source"),
    ],
)
def test_causal_record_rejects_metrics_that_contradict_its_kind(
    record: CausalMetricRecord,
    metrics_changes: dict[str, object],
    message: str,
) -> None:
    contradictory_metrics = replace(record.metrics, **metrics_changes)

    with pytest.raises(ValueError, match=message):
        replace(record, metrics=contradictory_metrics)


def test_causal_writer_requires_aliases_to_join_their_fixed_basis(
    tmp_path: Path,
) -> None:
    records = [
        _fixed_record(),
        _tuned_record(strategy_kind="PeriodicRepack"),
        _oracle_record(),
    ]

    with pytest.raises(ValueError, match="basis.*strategy_kind"):
        write_causal_records(
            tmp_path,
            records,
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )


def test_causal_writer_revalidates_mutable_metrics_before_serializing(
    tmp_path: Path,
) -> None:
    record = _fixed_record()
    record.metrics.category = "diagnostic-oracle"

    with pytest.raises(ValueError, match="metrics.category"):
        write_causal_records(
            tmp_path,
            [record],
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )


def test_causal_writer_rejects_duplicate_fixed_candidate_ids(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="duplicate.*candidate_id"):
        write_causal_records(
            tmp_path,
            [_fixed_record(), _fixed_record()],
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )


def test_causal_writer_rejects_duplicate_tuned_aliases(tmp_path: Path) -> None:
    records = [
        _fixed_record(),
        _tuned_record(),
        _tuned_record(),
        _oracle_record(),
    ]

    with pytest.raises(ValueError, match="exactly one tuned-fixed-policy"):
        write_causal_records(
            tmp_path,
            records,
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_requires_exactly_one_oracle_alias(tmp_path: Path) -> None:
    records = [_fixed_record(), _tuned_record()]

    with pytest.raises(ValueError, match="exactly one diagnostic-oracle"):
        write_causal_records(
            tmp_path,
            records,
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_rejects_tuned_metrics_tampering(tmp_path: Path) -> None:
    tuned = _tuned_record()
    tuned.metrics.update_encryptions = 999

    with pytest.raises(ValueError, match="metrics.update_encryptions.*update_ciphertexts"):
        write_causal_records(
            tmp_path,
            [_fixed_record(), tuned, _oracle_record()],
            UnitCosts(),
            {},
            **_placeholder_audit_kwargs(),
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_recomputes_tuning_selection_and_rejects_wrong_id(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, _selected_id, oracle_id = _auditable_report_fixture()
    wrong_selected_id = "reserved-slack/beta=0.1"
    metadata["selected_candidate_id"] = wrong_selected_id

    with pytest.raises(ValueError, match="selected_candidate_id.*tuning aggregates"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=wrong_selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_recomputes_oracle_from_held_out_fixed_records(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, _oracle_id = _auditable_report_fixture()
    wrong_oracle_id = "reserved-slack/beta=0"
    metadata["oracle_candidate_id"] = wrong_oracle_id

    with pytest.raises(ValueError, match="oracle_candidate_id.*held-out fixed"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=wrong_oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_requires_selection_ids_to_join_metadata(tmp_path: Path) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata["selected_candidate_id"] = "candidate/12"

    with pytest.raises(ValueError, match="metadata.selected_candidate_id"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_rejects_a_mismatched_metadata_candidate_count(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata["fixed_candidate_count"] = 12

    with pytest.raises(ValueError, match="metadata.fixed_candidate_count.*14"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_does_not_mask_contradictory_causal_metadata(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata["measurement_kind"] = "measured"

    with pytest.raises(ValueError, match="metadata.measurement_kind"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_record_writer_requires_metadata_candidate_ids_to_join_fixed_records(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata["span80_by_candidate"] = {"candidate/00": {}}

    with pytest.raises(ValueError, match="span80_by_candidate.*fixed candidate_id"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_requires_alias_ids_to_join_selection_ids(tmp_path: Path) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    wrong_basis = records[4]
    records[14] = CausalMetricRecord(
        "tuned-fixed-policy",
        wrong_basis.candidate_id,
        "TunedFixedPolicy",
        wrong_basis.strategy_kind,
        "tuning-prefix-only",
        replace(
            wrong_basis.metrics,
            strategy="TunedFixedPolicy",
            category="tuned-fixed-policy",
            source="tuning-prefix-frozen",
        ),
    )

    with pytest.raises(ValueError, match="tuned-fixed-policy candidate_id.*selection"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_requires_all_thirteen_tuning_aggregates(tmp_path: Path) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    del tuning_results["reserved-slack/beta=0.4"]

    with pytest.raises(ValueError, match=r"tuning_results.*missing.*reserved-slack/beta=0\.4"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_requires_tuning_aggregates_to_join_fixed_identity(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    tuning_results["reserved-slack/beta=0.4"].strategy = "PeriodicRepack"

    with pytest.raises(
        ValueError,
        match=r"tuning_results.*reserved-slack/beta=0\.4.*fixed basis",
    ):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_serializes_replayable_costs_and_all_tuning_aggregates(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()

    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert payload["unit_costs"] == asdict(costs)
    assert [item["candidate_id"] for item in payload["tuning_aggregates"]] == sorted(tuning_results)
    assert len(payload["tuning_aggregates"]) == 13
    for aggregate in payload["tuning_aggregates"]:
        candidate_id = aggregate["candidate_id"]
        assert set(aggregate) == {"candidate_id", "metrics", "score"}
        assert aggregate["metrics"] == asdict(tuning_results[candidate_id])
        assert aggregate["score"] == tuning_results[candidate_id].predicted_time(costs)

    with (tmp_path / "metrics.csv").open(newline="", encoding="utf-8") as handle:
        held_out_rows = list(csv.DictReader(handle))
    for field_name, value in asdict(costs).items():
        assert {row[f"unit_cost_{field_name}"] for row in held_out_rows} == {str(value)}

    with (tmp_path / "tuning_aggregates.csv").open(newline="", encoding="utf-8") as handle:
        tuning_rows = list(csv.DictReader(handle))
    assert [row["candidate_id"] for row in tuning_rows] == sorted(tuning_results)
    assert len(tuning_rows) == 13
    assert "updates" in tuning_rows[0]
    assert "score" in tuning_rows[0]


def test_causal_writer_payload_roundtrips_through_public_validator(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    assert validate_causal_payload(payload) is None


def test_canonical_renderer_recreates_metrics_json_and_csv_bytes(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    rendered_dir = tmp_path / "rendered"
    payload, _catalog = _write_auditable_payload(source_dir)

    digests = report.render_causal_artifacts(rendered_dir, payload)

    for filename in ("metrics.json", "metrics.csv", "tuning_aggregates.csv"):
        source_bytes = (source_dir / filename).read_bytes()
        assert (rendered_dir / filename).read_bytes() == source_bytes
        assert digests[filename] == hashlib.sha256(source_bytes).hexdigest()


def test_canonical_renderer_recreates_summary_with_fail_closed_disclosures(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    rendered_dir = tmp_path / "rendered"
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata.update({"workload": "zipf", "windows_total": 4})
    write_causal_records(
        source_dir,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    write_causal_summary(
        source_dir,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((source_dir / "metrics.json").read_text(encoding="utf-8"))
    digests = report.render_causal_artifacts(rendered_dir, payload)

    source_bytes = (source_dir / "SUMMARY.md").read_bytes()
    assert (rendered_dir / "SUMMARY.md").read_bytes() == source_bytes
    assert digests["SUMMARY.md"] == hashlib.sha256(source_bytes).hexdigest()
    summary = source_bytes.decode("utf-8").lower()
    assert "predicted synthetic proxy" in summary
    assert "bandwidth" in summary and "deferred" in summary
    assert "complete_reference_set=true" in summary
    assert "performance/security gates remain hold" in summary


def test_canonical_renderer_recreates_deterministic_proxy_plots_with_disclosures(
    tmp_path: Path,
) -> None:
    from PIL import Image

    source_dir = tmp_path / "source"
    rendered_dir = tmp_path / "rendered"
    rendered_again_dir = tmp_path / "rendered-again"
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    write_causal_records(
        source_dir,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    write_causal_plots(
        source_dir,
        records,
        costs,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((source_dir / "metrics.json").read_text(encoding="utf-8"))
    digests = report.render_causal_artifacts(rendered_dir, payload)
    second_digests = report.render_causal_artifacts(rendered_again_dir, payload)

    for filename in ("ua_vs_qa_proxy.png", "t_rho_proxy.png"):
        source_bytes = (source_dir / filename).read_bytes()
        assert (rendered_dir / filename).read_bytes() == source_bytes
        assert (rendered_again_dir / filename).read_bytes() == source_bytes
        assert digests[filename] == second_digests[filename]
        with Image.open(rendered_dir / filename) as image:
            description = image.info["Description"].lower()
        assert "predicted synthetic proxy" in description
        assert "bandwidth" in description and "deferred" in description
        assert "complete_reference_set=true" in description
        assert "performance/security gates remain hold" in description


def test_canonical_renderer_zero_metrics_has_no_log_warning_and_is_deterministic(
    tmp_path: Path,
) -> None:
    payload, catalog = _write_auditable_payload(tmp_path / "source")
    numeric_metric_fields = set(asdict(StrategyMetrics("placeholder", "reference"))) - {
        "strategy",
        "category",
        "source",
        "windows",
        "queries",
        "updates",
    }
    for aggregate in payload["tuning_aggregates"]:
        for field_name in numeric_metric_fields:
            aggregate["metrics"][field_name] = 0
        aggregate["metrics"]["absorbed_updates"] = aggregate["metrics"]["updates"]
        aggregate["score"] = 0.0
    for record in payload["records"]:
        for field_name in numeric_metric_fields:
            record[field_name] = 0
        record["absorbed_updates"] = record["updates"]
        for field_name in (
            "predicted_update_time",
            "predicted_query_time",
            "predicted_query_time_per_query",
            "predicted_normalized_time",
            "update_ct_equivalents_per_update",
        ):
            record[field_name] = 0.0
    canonical_basis_id = min(candidate.candidate_id for candidate in catalog.selection_candidates)
    basis = next(
        record for record in payload["records"][:14] if record["candidate_id"] == canonical_basis_id
    )
    payload["metadata"]["selected_candidate_id"] = canonical_basis_id
    payload["metadata"]["oracle_candidate_id"] = canonical_basis_id
    for alias in payload["records"][14:]:
        alias["candidate_id"] = canonical_basis_id
        alias["strategy_kind"] = basis["strategy_kind"]

    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        first_digests = report.render_causal_artifacts(tmp_path / "first", payload)
        second_digests = report.render_causal_artifacts(tmp_path / "second", payload)

    assert first_digests["t_rho_proxy.png"] == second_digests["t_rho_proxy.png"]
    assert (tmp_path / "first" / "t_rho_proxy.png").read_bytes() == (
        tmp_path / "second" / "t_rho_proxy.png"
    ).read_bytes()


@pytest.mark.parametrize(
    "filename",
    ["SUMMARY.md", "metrics.csv", "tuning_aggregates.csv", "ua_vs_qa_proxy.png"],
)
def test_canonical_renderer_digest_exposes_false_derived_artifact_roundtrips(
    tmp_path: Path,
    filename: str,
) -> None:
    source_dir = tmp_path / "source"
    canonical_dir = tmp_path / "canonical"
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    write_causal_records(
        source_dir,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    write_causal_summary(
        source_dir,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    write_causal_plots(
        source_dir,
        records,
        costs,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )
    payload = json.loads((source_dir / "metrics.json").read_text(encoding="utf-8"))
    expected_digests = report.render_causal_artifacts(canonical_dir, payload)
    artifact_path = source_dir / filename
    artifact_path.write_bytes(artifact_path.read_bytes() + b"forged")

    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() != expected_digests[filename]
    assert artifact_path.read_bytes() != (canonical_dir / filename).read_bytes()


def test_causal_writer_canonicalizes_fixed_record_order_before_validation(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    unsorted_records = [*reversed(records[:14]), *records[14:]]

    write_causal_records(
        tmp_path,
        unsorted_records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    assert [record["candidate_id"] for record in payload["records"][:14]] == sorted(
        candidate.candidate_id for candidate in _registered_catalog().candidates
    )


def test_causal_payload_validator_rejects_extra_top_level_keys(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["unreviewed"] = True

    with pytest.raises(ValueError, match="payload keys.*extra.*unreviewed"):
        validate_causal_payload(payload)


def test_causal_payload_validator_requires_complete_unit_costs(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    del payload["unit_costs"]["encrypt"]

    with pytest.raises(ValueError, match="unit_costs keys.*missing.*encrypt"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_extra_tuning_metric_fields(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["tuning_aggregates"][0]["metrics"]["unpriced_work"] = 1

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\].metrics keys.*extra"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_missing_tuning_metric_fields(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    del payload["tuning_aggregates"][0]["metrics"]["blinding_dummy_ciphertexts"]

    with pytest.raises(
        ValueError,
        match=r"tuning_aggregates\[0\].metrics keys.*missing.*blinding_dummy_ciphertexts",
    ):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_missing_tuning_aggregate_fields(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    del payload["tuning_aggregates"][0]["score"]

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\] keys.*missing.*score"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_extra_record_fields(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["records"][0]["unreviewed"] = 1

    with pytest.raises(ValueError, match=r"records\[0\] keys.*extra.*unreviewed"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_missing_dummy_blinding_record_field(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    del payload["records"][0]["blinding_dummy_ciphertexts"]

    with pytest.raises(
        ValueError,
        match=r"records\[0\] keys.*missing.*blinding_dummy_ciphertexts",
    ):
        validate_causal_payload(payload)


def test_causal_payload_validator_recomputes_derived_record_fields(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["records"][0]["predicted_normalized_time"] += 1

    with pytest.raises(ValueError, match=r"records\[0\].predicted_normalized_time"):
        validate_causal_payload(payload)


def test_causal_payload_validator_recomputes_selected_candidate(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["metadata"]["selected_candidate_id"] = "reserved-slack/beta=0.1"

    with pytest.raises(ValueError, match="selected_candidate_id.*tuning_aggregates"):
        validate_causal_payload(payload)


def test_causal_payload_validator_recomputes_held_out_oracle(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["metadata"]["oracle_candidate_id"] = "reserved-slack/beta=0"

    with pytest.raises(ValueError, match="oracle_candidate_id.*held-out reference"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_tuning_score_tampering(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["tuning_aggregates"][0]["score"] += 1

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\].score"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_noncanonical_integral_score_type(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    original_score = payload["tuning_aggregates"][0]["score"]
    assert isinstance(original_score, float) and original_score.is_integer()
    payload["tuning_aggregates"][0]["score"] = int(original_score)

    with pytest.raises((TypeError, ValueError), match=r"tuning_aggregates\[0\]\.score"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_jointly_forged_costs_and_scores(
    tmp_path: Path,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    forged_encrypt_cost = 9.0
    payload["unit_costs"]["encrypt"] = forged_encrypt_cost
    for aggregate in payload["tuning_aggregates"]:
        aggregate["score"] = aggregate["metrics"]["update_encryptions"] * forged_encrypt_cost
    for record in payload["records"]:
        forged_update_time = record["update_encryptions"] * forged_encrypt_cost
        record["predicted_update_time"] = forged_update_time
        record["predicted_normalized_time"] = forged_update_time + record["predicted_query_time"]
        record["unit_cost_encrypt"] = forged_encrypt_cost

    with pytest.raises(ValueError, match=r"unit_costs\.encrypt.*frozen"):
        validate_causal_payload(payload)


def test_causal_payload_validator_requires_the_frozen_unit_cost_label(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["unit_costs"]["label"] = "self-consistent-but-unfrozen"
    for record in payload["records"]:
        record["unit_cost_label"] = "self-consistent-but-unfrozen"

    with pytest.raises(ValueError, match=r"unit_costs\.label.*frozen"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_alias_numeric_tampering(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["records"][14]["windows"] += 1

    with pytest.raises(ValueError, match="tuned-fixed-policy metrics.*fixed basis"):
        validate_causal_payload(payload)


@pytest.mark.parametrize("tampered_value", ["8.0", float("nan")])
def test_causal_payload_validator_rejects_invalid_unit_cost_types_and_values(
    tmp_path: Path,
    tampered_value: object,
) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["unit_costs"]["encrypt"] = tampered_value

    with pytest.raises((TypeError, ValueError), match="unit[_ ]costs.*finite"):
        validate_causal_payload(payload)


def test_causal_payload_validator_rejects_nonfinite_context_metadata(tmp_path: Path) -> None:
    payload, _catalog = _write_auditable_payload(tmp_path)
    payload["metadata"]["context_score"] = float("inf")

    with pytest.raises(ValueError, match="metadata.context_score.*finite"):
        validate_causal_payload(payload)


def test_causal_writer_rejects_nonfinite_unused_unit_cost_before_writing(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    costs = replace(costs, ciphertext_equivalent_bytes=float("nan"))

    with pytest.raises(ValueError, match="unit costs.*finite"):
        write_causal_records(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_summary_rejects_nonfinite_unscored_metric_before_writing(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    records[0].metrics.metadata_units = float("nan")  # type: ignore[assignment]

    with pytest.raises(ValueError, match="metrics.metadata_units.*finite"):
        write_causal_summary(
            tmp_path,
            records,
            costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_writer_detects_cost_vector_tampering_by_replaying_selection(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    tampered_costs = replace(costs, encrypt=0.0)

    with pytest.raises(ValueError, match="selected_candidate_id.*tuning aggregates"):
        write_causal_records(
            tmp_path,
            records,
            tampered_costs,
            metadata,
            tuning_results=tuning_results,
            selected_candidate_id=selected_id,
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_summary_exposes_costs_and_tuning_replay_evidence(tmp_path: Path) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()

    write_causal_summary(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    summary = (tmp_path / "SUMMARY.md").read_text(encoding="utf-8")
    assert "## Unit-cost vector" in summary
    assert all(field_name in summary for field_name in asdict(costs))
    assert "## Tuning-prefix aggregates" in summary
    assert all(candidate_id in summary for candidate_id in tuning_results)
    assert selected_id in summary
    assert oracle_id in summary


def test_causal_plot_writer_rejects_a_nonreproducible_selection(tmp_path: Path) -> None:
    records, tuning_results, costs, _metadata, _selected_id, oracle_id = _auditable_report_fixture()

    with pytest.raises(ValueError, match="selected_candidate_id.*tuning aggregates"):
        write_causal_plots(
            tmp_path,
            records,
            costs,
            tuning_results=tuning_results,
            selected_candidate_id="reserved-slack/beta=0.1",
            oracle_candidate_id=oracle_id,
        )

    assert not any(tmp_path.iterdir())


def test_causal_records_use_the_predicted_schema_and_three_explicit_kinds(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata.update({"workload": "zipf", "gate_eligible": False})

    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    with (tmp_path / "metrics.csv").open(newline="", encoding="utf-8") as handle:
        csv_records = list(csv.DictReader(handle))
    assert payload["schema"] == "day1-causal-predicted-v2"
    assert payload["state_model"] == "persistent-strategy-snapshots"
    assert payload["measurement_kind"] == "predicted-proxy"
    assert payload["gate_eligible"] is False
    assert payload["complete_cost_claim_allowed"] is False
    assert payload["complete_reference_set"] is True
    assert payload["security_claim_allowed"] is False
    assert payload["formal_performance_claim"] is False
    assert payload["metadata"]["gate_eligible"] is False
    assert [record["record_kind"] for record in payload["records"]] == [
        *(["fixed-candidate"] * 14),
        "tuned-fixed-policy",
        "diagnostic-oracle",
    ]
    fixed_ids = sorted(candidate.candidate_id for candidate in _registered_catalog().candidates)
    assert [record["candidate_id"] for record in payload["records"]] == [
        *fixed_ids,
        selected_id,
        oracle_id,
    ]
    assert [record["label"] for record in payload["records"]] == [
        *fixed_ids,
        "TunedFixedPolicy",
        "BestFixed-Offline-Oracle",
    ]
    join_fields = ("record_kind", "candidate_id", "label", "strategy_kind")
    assert [tuple(record[field] for field in join_fields) for record in csv_records] == [
        tuple(record[field] for field in join_fields) for record in payload["records"]
    ]
    assert all(record["phase"] == "held-out" for record in payload["records"])
    assert [record["selection_source"] for record in payload["records"]] == [
        *(["fixed-candidate"] * 14),
        "tuning-prefix-only",
        "held-out-hindsight-diagnostic-only",
    ]
    assert all("selected_candidate_id" not in record for record in payload["records"])
    assert all("oracle_candidate_id" not in record for record in payload["records"])
    assert all(record["measurement_kind"] == "predicted-proxy" for record in payload["records"])
    assert all(record["gate_eligible"] is False for record in payload["records"])
    assert all(record["complete_cost_claim_allowed"] is False for record in payload["records"])
    assert all(record["complete_reference_set"] is True for record in payload["records"])
    assert all(record["security_claim_allowed"] is False for record in payload["records"])
    assert all(record["formal_performance_claim"] is False for record in payload["records"])
    assert costs.label in json.dumps(payload)


def test_parameterized_fixed_candidate_ids_survive_the_json_csv_join(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    candidate_ids = sorted(candidate.candidate_id for candidate in _registered_catalog().candidates)

    write_causal_records(
        tmp_path,
        records,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    with (tmp_path / "metrics.csv").open(newline="", encoding="utf-8") as handle:
        csv_records = list(csv.DictReader(handle))
    json_candidate_ids = [record["candidate_id"] for record in payload["records"][:14]]
    csv_candidate_ids = [record["candidate_id"] for record in csv_records[:14]]
    assert json_candidate_ids == candidate_ids
    assert csv_candidate_ids == candidate_ids
    assert len(set(json_candidate_ids)) == 14


def test_causal_plots_label_fixed_points_and_aliases_with_basis_candidate_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from matplotlib.axes import Axes

    records, tuning_results, costs, _metadata, selected_id, oracle_id = _auditable_report_fixture()
    candidate_ids = [record.candidate_id for record in records[:14]]
    annotations: list[str] = []
    original_annotate = Axes.annotate

    def record_annotation(self: Axes, text: str, *args: object, **kwargs: object):
        annotations.append(text)
        return original_annotate(self, text, *args, **kwargs)

    monkeypatch.setattr(Axes, "annotate", record_annotation)

    write_causal_plots(
        tmp_path,
        records,
        costs,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    assert set(candidate_ids).issubset(annotations)
    assert f"TunedFixedPolicy [basis: {selected_id}]" in annotations
    assert f"BestFixed-Offline-Oracle [basis: {oracle_id}]" in annotations
    assert (tmp_path / "ua_vs_qa_proxy.png").is_file()
    assert (tmp_path / "t_rho_proxy.png").is_file()


def test_causal_summary_names_the_frozen_policy_and_diagnostic_oracle(
    tmp_path: Path,
) -> None:
    items, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    metadata.update(
        {
            "workload": "zipf",
            "windows_total": 10,
            "span80_by_candidate": {
                item.candidate_id: ({1: 0.25, 2: 0.125} if index == 0 else {})
                for index, item in enumerate(items[:14])
            },
        }
    )

    write_causal_summary(
        tmp_path,
        items,
        costs,
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=oracle_id,
    )

    summary = (tmp_path / "SUMMARY.md").read_text(encoding="utf-8")
    assert "day1-causal-predicted-v2" in summary
    assert "persistent-strategy-snapshots" in summary
    assert "TunedFixedPolicy" in summary
    assert "BestFixed-Offline-Oracle" in summary
    assert "Span80 audit by fixed candidate" in summary
    assert '"1": 0.25' in summary
    assert '"2": 0.125' in summary
    assert "gate_eligible=false" in summary
    assert "not-measured" in summary.lower()
    assert "online" not in summary.lower()
    assert "gate passed" not in summary.lower()
    assert "Hybrid" not in summary
