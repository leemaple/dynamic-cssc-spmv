from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path

import pytest

from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.report import (
    CausalMetricRecord,
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
    ]

    with pytest.raises(ValueError, match="basis.*strategy_kind"):
        write_causal_records(tmp_path, records, UnitCosts(), {})


def test_causal_writer_revalidates_mutable_metrics_before_serializing(
    tmp_path: Path,
) -> None:
    record = _fixed_record()
    record.metrics.category = "diagnostic-oracle"

    with pytest.raises(ValueError, match="metrics.category"):
        write_causal_records(tmp_path, [record], UnitCosts(), {})


def test_causal_writer_rejects_duplicate_fixed_candidate_ids(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="duplicate.*candidate_id"):
        write_causal_records(
            tmp_path,
            [_fixed_record(), _fixed_record()],
            UnitCosts(),
            {},
        )


def test_causal_records_use_the_predicted_schema_and_three_explicit_kinds(
    tmp_path: Path,
) -> None:
    selected = StrategyMetrics(
        "ReservedSlack-CSSC",
        "reference",
        windows=6,
        updates=12,
        update_encryptions=3,
        source="persistent-state-predicted",
    )
    periodic = StrategyMetrics(
        "PeriodicRepack",
        "reference",
        windows=6,
        updates=12,
        update_encryptions=4,
        source="persistent-state-predicted",
    )
    tuned = StrategyMetrics(
        "TunedFixedPolicy",
        "tuned-fixed-policy",
        windows=6,
        updates=12,
        update_encryptions=3,
        source="tuning-prefix-frozen",
    )
    oracle = StrategyMetrics(
        "BestFixed-Offline-Oracle",
        "diagnostic-oracle",
        windows=6,
        updates=12,
        update_encryptions=2,
        source="held-out-hindsight-diagnostic",
    )

    write_causal_records(
        tmp_path,
        [
            CausalMetricRecord(
                "fixed-candidate",
                "reserved-slack/beta=0.05",
                "reserved-slack/beta=0.05",
                "ReservedSlack-CSSC",
                "fixed-candidate",
                selected,
            ),
            CausalMetricRecord(
                "fixed-candidate",
                "periodic-repack/windows=1",
                "periodic-repack/windows=1",
                "PeriodicRepack",
                "fixed-candidate",
                periodic,
            ),
            CausalMetricRecord(
                "tuned-fixed-policy",
                "reserved-slack/beta=0.05",
                "TunedFixedPolicy",
                "ReservedSlack-CSSC",
                "tuning-prefix-only",
                tuned,
            ),
            CausalMetricRecord(
                "diagnostic-oracle",
                "periodic-repack/windows=1",
                "BestFixed-Offline-Oracle",
                "PeriodicRepack",
                "held-out-hindsight-diagnostic-only",
                oracle,
            ),
        ],
        UnitCosts(),
        {"workload": "zipf", "gate_eligible": True},
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
        "fixed-candidate",
        "fixed-candidate",
        "tuned-fixed-policy",
        "diagnostic-oracle",
    ]
    assert [record["candidate_id"] for record in payload["records"]] == [
        "reserved-slack/beta=0.05",
        "periodic-repack/windows=1",
        "reserved-slack/beta=0.05",
        "periodic-repack/windows=1",
    ]
    assert [record["label"] for record in payload["records"]] == [
        "reserved-slack/beta=0.05",
        "periodic-repack/windows=1",
        "TunedFixedPolicy",
        "BestFixed-Offline-Oracle",
    ]
    assert [record["strategy_kind"] for record in payload["records"]] == [
        "ReservedSlack-CSSC",
        "PeriodicRepack",
        "ReservedSlack-CSSC",
        "PeriodicRepack",
    ]
    join_fields = ("record_kind", "candidate_id", "label", "strategy_kind")
    assert [tuple(record[field] for field in join_fields) for record in csv_records] == [
        tuple(record[field] for field in join_fields) for record in payload["records"]
    ]
    assert all(record["phase"] == "held-out" for record in payload["records"])
    assert [record["selection_source"] for record in payload["records"]] == [
        "fixed-candidate",
        "fixed-candidate",
        "tuning-prefix-only",
        "held-out-hindsight-diagnostic-only",
    ]
    assert all("selected_candidate_id" not in record for record in payload["records"])
    assert all("oracle_candidate_id" not in record for record in payload["records"])
    assert all(record["measurement_kind"] == "predicted-proxy" for record in payload["records"])
    assert all(record["gate_eligible"] is False for record in payload["records"])
    assert all(record["complete_cost_claim_allowed"] is False for record in payload["records"])
    assert "normalized-proxy-not-measured" not in json.dumps(payload)


def test_parameterized_fixed_candidate_ids_survive_the_json_csv_join(
    tmp_path: Path,
) -> None:
    candidate_ids = [
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
                else "PeriodicRepack"
            ),
        )
        for candidate_id in candidate_ids
    ]

    write_causal_records(tmp_path, records, UnitCosts(), {})

    payload = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    with (tmp_path / "metrics.csv").open(newline="", encoding="utf-8") as handle:
        csv_records = list(csv.DictReader(handle))
    json_candidate_ids = [record["candidate_id"] for record in payload["records"]]
    csv_candidate_ids = [record["candidate_id"] for record in csv_records]
    assert json_candidate_ids == candidate_ids
    assert csv_candidate_ids == candidate_ids
    assert len(set(json_candidate_ids)) == 9


def test_causal_plots_label_fixed_points_and_aliases_with_basis_candidate_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from matplotlib.axes import Axes

    candidate_ids = [
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
    fixed_records = []
    for index, candidate_id in enumerate(candidate_ids, start=1):
        strategy_kind = (
            "ReservedSlack-CSSC" if candidate_id.startswith("reserved-slack") else "PeriodicRepack"
        )
        base = _fixed_record(candidate_id, strategy_kind)
        fixed_records.append(
            replace(
                base,
                metrics=replace(
                    base.metrics,
                    queries=2,
                    updates=2,
                    update_ciphertexts=index,
                    cc_multiplications=index,
                    rotations=index,
                ),
            )
        )
    tuned = _tuned_record("reserved-slack/beta=0.05")
    tuned = replace(
        tuned,
        metrics=replace(tuned.metrics, queries=2, updates=2),
    )
    oracle = _oracle_record(
        "periodic-repack/windows=4",
        "PeriodicRepack",
    )
    oracle = replace(
        oracle,
        metrics=replace(oracle.metrics, queries=2, updates=2),
    )
    annotations: list[str] = []
    original_annotate = Axes.annotate

    def record_annotation(self: Axes, text: str, *args: object, **kwargs: object):
        annotations.append(text)
        return original_annotate(self, text, *args, **kwargs)

    monkeypatch.setattr(Axes, "annotate", record_annotation)

    write_causal_plots(tmp_path, [*fixed_records, tuned, oracle], UnitCosts())

    assert set(candidate_ids).issubset(annotations)
    assert "TunedFixedPolicy [basis: reserved-slack/beta=0.05]" in annotations
    assert "BestFixed-Offline-Oracle [basis: periodic-repack/windows=4]" in annotations
    assert (tmp_path / "ua_vs_qa_proxy.png").is_file()
    assert (tmp_path / "t_rho_proxy.png").is_file()


def test_causal_summary_names_the_frozen_policy_and_diagnostic_oracle(
    tmp_path: Path,
) -> None:
    items = [
        _fixed_record("padding-reuse", "PaddingReuse-CSSC"),
        CausalMetricRecord(
            "tuned-fixed-policy",
            "padding-reuse",
            "TunedFixedPolicy",
            "PaddingReuse-CSSC",
            "tuning-prefix-only",
            StrategyMetrics(
                "TunedFixedPolicy",
                "tuned-fixed-policy",
                updates=1,
                source="tuning-prefix-frozen",
            ),
        ),
        CausalMetricRecord(
            "diagnostic-oracle",
            "padding-reuse",
            "BestFixed-Offline-Oracle",
            "PaddingReuse-CSSC",
            "held-out-hindsight-diagnostic-only",
            StrategyMetrics(
                "BestFixed-Offline-Oracle",
                "diagnostic-oracle",
                updates=1,
                source="held-out-hindsight-diagnostic",
            ),
        ),
    ]

    write_causal_summary(
        tmp_path,
        items,
        UnitCosts(),
        {
            "workload": "zipf",
            "windows_total": 10,
            "span80_by_candidate": {"padding-reuse": {1: 0.25, 2: 0.125}},
        },
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
    assert "measured" not in summary.lower()
    assert "online" not in summary.lower()
    assert "gate passed" not in summary.lower()
    assert "Hybrid" not in summary
