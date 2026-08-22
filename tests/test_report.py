from __future__ import annotations

import csv
import hashlib
import json
import warnings
from dataclasses import asdict, replace
from pathlib import Path

import pytest

import dynamic_cssc.report as report
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.report import (
    CausalMetricRecord,
    validate_causal_payload,
    write_causal_plots,
    write_causal_records,
    write_causal_summary,
)


def _fixed_record(
    candidate_id: str = "reserved-slack/beta=0.05",
    strategy_kind: str = "ReservedSlack-CSSC",
) -> CausalMetricRecord:
    return CausalMetricRecord(
        record_kind="fixed-candidate",
        candidate_id=candidate_id,
        label=candidate_id,
        strategy_kind=strategy_kind,
        selection_source="fixed-candidate",
        metrics=StrategyMetrics(
            strategy_kind,
            "reference",
            source="persistent-state-predicted",
        ),
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
    for index in range(13):
        candidate_id = f"candidate/{index:02d}"
        held_out_encryptions = 2 if index == 7 else 200 + index
        tuning_encryptions = 1 if index == 3 else 100 + index
        fixed_records.append(
            CausalMetricRecord(
                "fixed-candidate",
                candidate_id,
                candidate_id,
                "PaddingReuse-CSSC",
                "fixed-candidate",
                StrategyMetrics(
                    "PaddingReuse-CSSC",
                    "reference",
                    windows=4,
                    queries=8,
                    updates=16,
                    update_encryptions=held_out_encryptions,
                    source="persistent-state-predicted",
                ),
            )
        )
        tuning_results[candidate_id] = StrategyMetrics(
            "PaddingReuse-CSSC",
            "reference",
            windows=3,
            queries=6,
            updates=12,
            update_encryptions=tuning_encryptions,
            source="persistent-state-predicted",
        )

    selected_candidate_id = "candidate/03"
    oracle_candidate_id = "candidate/07"
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
    )
    metadata: dict[str, object] = {
        "selected_candidate_id": selected_candidate_id,
        "oracle_candidate_id": oracle_candidate_id,
        "fixed_candidate_count": 13,
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


def _write_auditable_payload(tmp_path: Path) -> tuple[dict[str, object], list[str]]:
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
    return payload, [record.candidate_id for record in reversed(records[:13])]


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
    tuned.metrics.updates = 999

    with pytest.raises(ValueError, match="tuned-fixed-policy metrics.*fixed basis"):
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
    wrong_selected_id = "candidate/04"
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
    wrong_oracle_id = "candidate/08"
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

    with pytest.raises(ValueError, match="metadata.fixed_candidate_count.*13"):
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
    records[13] = CausalMetricRecord(
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
    del tuning_results["candidate/12"]

    with pytest.raises(ValueError, match="tuning_results.*missing.*candidate/12"):
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
    tuning_results["candidate/12"].strategy = "PeriodicRepack"

    with pytest.raises(ValueError, match="tuning_results.*candidate/12.*fixed basis"):
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
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    assert (
        validate_causal_payload(
            payload,
            expected_candidate_ids=expected_candidate_ids,
        )
        is None
    )


def test_canonical_renderer_recreates_metrics_json_and_csv_bytes(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "source"
    rendered_dir = tmp_path / "rendered"
    payload, expected_candidate_ids = _write_auditable_payload(source_dir)

    digests = report.render_causal_artifacts(
        rendered_dir,
        payload,
        expected_candidate_ids=expected_candidate_ids,
    )

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
    expected_candidate_ids = [record.candidate_id for record in records[:13]]

    digests = report.render_causal_artifacts(
        rendered_dir,
        payload,
        expected_candidate_ids=expected_candidate_ids,
    )

    source_bytes = (source_dir / "SUMMARY.md").read_bytes()
    assert (rendered_dir / "SUMMARY.md").read_bytes() == source_bytes
    assert digests["SUMMARY.md"] == hashlib.sha256(source_bytes).hexdigest()
    summary = source_bytes.decode("utf-8").lower()
    assert "predicted synthetic proxy" in summary
    assert "bandwidth" in summary and "deferred" in summary
    assert "complete_reference_set=false" in summary
    assert "full-baseline hold" in summary


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
    expected_candidate_ids = [record.candidate_id for record in records[:13]]

    digests = report.render_causal_artifacts(
        rendered_dir,
        payload,
        expected_candidate_ids=expected_candidate_ids,
    )
    second_digests = report.render_causal_artifacts(
        rendered_again_dir,
        payload,
        expected_candidate_ids=reversed(expected_candidate_ids),
    )

    for filename in ("ua_vs_qa_proxy.png", "t_rho_proxy.png"):
        source_bytes = (source_dir / filename).read_bytes()
        assert (rendered_dir / filename).read_bytes() == source_bytes
        assert (rendered_again_dir / filename).read_bytes() == source_bytes
        assert digests[filename] == second_digests[filename]
        with Image.open(rendered_dir / filename) as image:
            description = image.info["Description"].lower()
        assert "predicted synthetic proxy" in description
        assert "bandwidth" in description and "deferred" in description
        assert "complete_reference_set=false" in description
        assert "full-baseline hold" in description


def test_canonical_renderer_zero_metrics_has_no_log_warning_and_is_deterministic(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path / "source")
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
        aggregate["score"] = 0.0
    for record in payload["records"]:
        for field_name in numeric_metric_fields:
            record[field_name] = 0
        for field_name in (
            "predicted_update_time",
            "predicted_query_time",
            "predicted_query_time_per_query",
            "predicted_normalized_time",
            "update_ct_equivalents_per_update",
        ):
            record[field_name] = 0.0
    canonical_basis_id = min(expected_candidate_ids)
    payload["metadata"]["selected_candidate_id"] = canonical_basis_id
    payload["metadata"]["oracle_candidate_id"] = canonical_basis_id
    payload["records"][13]["candidate_id"] = canonical_basis_id
    payload["records"][14]["candidate_id"] = canonical_basis_id

    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        first_digests = report.render_causal_artifacts(
            tmp_path / "first",
            payload,
            expected_candidate_ids=expected_candidate_ids,
        )
        second_digests = report.render_causal_artifacts(
            tmp_path / "second",
            payload,
            expected_candidate_ids=reversed(expected_candidate_ids),
        )

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
    expected_candidate_ids = [record.candidate_id for record in records[:13]]
    expected_digests = report.render_causal_artifacts(
        canonical_dir,
        payload,
        expected_candidate_ids=expected_candidate_ids,
    )
    artifact_path = source_dir / filename
    artifact_path.write_bytes(artifact_path.read_bytes() + b"forged")

    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() != expected_digests[filename]
    assert artifact_path.read_bytes() != (canonical_dir / filename).read_bytes()


def test_causal_writer_canonicalizes_fixed_record_order_before_validation(
    tmp_path: Path,
) -> None:
    records, tuning_results, costs, metadata, selected_id, oracle_id = _auditable_report_fixture()
    unsorted_records = [*reversed(records[:13]), *records[13:]]

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
    assert [record["candidate_id"] for record in payload["records"][:13]] == sorted(tuning_results)


def test_causal_payload_validator_rejects_extra_top_level_keys(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["unreviewed"] = True

    with pytest.raises(ValueError, match="payload keys.*extra.*unreviewed"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_duplicate_expected_candidate_ids(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    expected_candidate_ids.append(expected_candidate_ids[0])

    with pytest.raises(ValueError, match="expected_candidate_ids.*unique.*13"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_requires_complete_unit_costs(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    del payload["unit_costs"]["encrypt"]

    with pytest.raises(ValueError, match="unit_costs keys.*missing.*encrypt"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_extra_tuning_metric_fields(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["tuning_aggregates"][0]["metrics"]["unpriced_work"] = 1

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\].metrics keys.*extra"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_missing_tuning_metric_fields(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    del payload["tuning_aggregates"][0]["metrics"]["updates"]

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\].metrics keys.*missing"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_missing_tuning_aggregate_fields(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    del payload["tuning_aggregates"][0]["score"]

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\] keys.*missing.*score"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_extra_record_fields(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["records"][0]["unreviewed"] = 1

    with pytest.raises(ValueError, match=r"records\[0\] keys.*extra.*unreviewed"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_recomputes_derived_record_fields(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["records"][0]["predicted_normalized_time"] += 1

    with pytest.raises(ValueError, match=r"records\[0\].predicted_normalized_time"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_recomputes_selected_candidate(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["metadata"]["selected_candidate_id"] = "candidate/04"

    with pytest.raises(ValueError, match="selected_candidate_id.*tuning_aggregates"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_recomputes_held_out_oracle(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["metadata"]["oracle_candidate_id"] = "candidate/08"

    with pytest.raises(ValueError, match="oracle_candidate_id.*held-out fixed"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_tuning_score_tampering(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["tuning_aggregates"][0]["score"] += 1

    with pytest.raises(ValueError, match=r"tuning_aggregates\[0\].score"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_noncanonical_integral_score_type(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    original_score = payload["tuning_aggregates"][0]["score"]
    assert isinstance(original_score, float) and original_score.is_integer()
    payload["tuning_aggregates"][0]["score"] = int(original_score)

    with pytest.raises((TypeError, ValueError), match=r"tuning_aggregates\[0\]\.score"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_jointly_forged_costs_and_scores(
    tmp_path: Path,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
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
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_requires_the_frozen_unit_cost_label(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["unit_costs"]["label"] = "self-consistent-but-unfrozen"
    for record in payload["records"]:
        record["unit_cost_label"] = "self-consistent-but-unfrozen"

    with pytest.raises(ValueError, match=r"unit_costs\.label.*frozen"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_alias_numeric_tampering(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["records"][13]["updates"] = 999

    with pytest.raises(ValueError, match="tuned-fixed-policy metrics.*fixed basis"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


@pytest.mark.parametrize("tampered_value", ["8.0", float("nan")])
def test_causal_payload_validator_rejects_invalid_unit_cost_types_and_values(
    tmp_path: Path,
    tampered_value: object,
) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["unit_costs"]["encrypt"] = tampered_value

    with pytest.raises((TypeError, ValueError), match="unit[_ ]costs.*finite"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


def test_causal_payload_validator_rejects_nonfinite_context_metadata(tmp_path: Path) -> None:
    payload, expected_candidate_ids = _write_auditable_payload(tmp_path)
    payload["metadata"]["context_score"] = float("inf")

    with pytest.raises(ValueError, match="metadata.context_score.*finite"):
        validate_causal_payload(payload, expected_candidate_ids=expected_candidate_ids)


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
            selected_candidate_id="candidate/04",
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
    assert payload["schema"] == "day1-causal-predicted-v1"
    assert payload["state_model"] == "persistent-strategy-snapshots"
    assert payload["measurement_kind"] == "predicted-proxy"
    assert payload["gate_eligible"] is False
    assert payload["complete_cost_claim_allowed"] is False
    assert payload["metadata"]["gate_eligible"] is False
    assert [record["record_kind"] for record in payload["records"]] == [
        *(["fixed-candidate"] * 13),
        "tuned-fixed-policy",
        "diagnostic-oracle",
    ]
    fixed_ids = [f"candidate/{index:02d}" for index in range(13)]
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
        *(["fixed-candidate"] * 13),
        "tuning-prefix-only",
        "held-out-hindsight-diagnostic-only",
    ]
    assert all("selected_candidate_id" not in record for record in payload["records"])
    assert all("oracle_candidate_id" not in record for record in payload["records"])
    assert all(record["measurement_kind"] == "predicted-proxy" for record in payload["records"])
    assert all(record["gate_eligible"] is False for record in payload["records"])
    assert all(record["complete_cost_claim_allowed"] is False for record in payload["records"])
    assert costs.label in json.dumps(payload)


def test_parameterized_fixed_candidate_ids_survive_the_json_csv_join(
    tmp_path: Path,
) -> None:
    candidate_ids = [
        "padding-reuse",
        "mini-cssc-delta",
        "packed-coo-client-lane-delta/capacity=128",
        "strict-local-repack",
        "reserved-slack/beta=0",
        "reserved-slack/beta=0.05",
        "reserved-slack/beta=0.1",
        "reserved-slack/beta=0.2",
        "reserved-slack/beta=0.4",
        "periodic-repack/windows=1",
        "periodic-repack/windows=4",
        "periodic-repack/windows=16",
        "periodic-repack/windows=64",
    ]
    records = [
        _fixed_record(
            candidate_id,
            (
                "ReservedSlack-CSSC"
                if candidate_id.startswith("reserved-slack")
                else (
                    "PeriodicRepack"
                    if candidate_id.startswith("periodic-repack")
                    else "PaddingReuse-CSSC"
                )
            ),
        )
        for candidate_id in candidate_ids
    ]
    selected_id = min(candidate_ids)
    basis = next(record for record in records if record.candidate_id == selected_id)
    records.extend(
        [
            replace(
                _tuned_record(selected_id, basis.strategy_kind),
                metrics=replace(
                    basis.metrics,
                    strategy="TunedFixedPolicy",
                    category="tuned-fixed-policy",
                    source="tuning-prefix-frozen",
                ),
            ),
            replace(
                _oracle_record(selected_id, basis.strategy_kind),
                metrics=replace(
                    basis.metrics,
                    strategy="BestFixed-Offline-Oracle",
                    category="diagnostic-oracle",
                    source="held-out-hindsight-diagnostic",
                ),
            ),
        ]
    )
    tuning_results = {record.candidate_id: record.metrics for record in records[:13]}
    metadata = {
        "selected_candidate_id": selected_id,
        "oracle_candidate_id": selected_id,
        "fixed_candidate_count": 13,
    }

    write_causal_records(
        tmp_path,
        records,
        UnitCosts(),
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_id,
        oracle_candidate_id=selected_id,
    )

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    with (tmp_path / "metrics.csv").open(newline="", encoding="utf-8") as handle:
        csv_records = list(csv.DictReader(handle))
    json_candidate_ids = [record["candidate_id"] for record in payload["records"][:13]]
    csv_candidate_ids = [record["candidate_id"] for record in csv_records[:13]]
    assert json_candidate_ids == sorted(candidate_ids)
    assert csv_candidate_ids == sorted(candidate_ids)
    assert len(set(json_candidate_ids)) == 13


def test_causal_plots_label_fixed_points_and_aliases_with_basis_candidate_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from matplotlib.axes import Axes

    records, tuning_results, costs, _metadata, selected_id, oracle_id = _auditable_report_fixture()
    candidate_ids = [record.candidate_id for record in records[:13]]
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
                for index, item in enumerate(items[:13])
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
    assert "day1-causal-predicted-v1" in summary
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
