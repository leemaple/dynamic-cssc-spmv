from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .metrics import StrategyMetrics, UnitCosts

CAUSAL_SCHEMA = "day1-causal-predicted-v1"
CAUSAL_STATE_MODEL = "persistent-strategy-snapshots"
CAUSAL_MEASUREMENT_KIND = "predicted-proxy"
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


@dataclass(frozen=True, slots=True)
class CausalMetricRecord:
    record_kind: CausalRecordKind
    candidate_id: str
    label: str
    strategy_kind: str
    selection_source: str
    metrics: StrategyMetrics
    phase: Literal["held-out"] = "held-out"
    gate_eligible: Literal[False] = False
    complete_cost_claim_allowed: Literal[False] = False

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
        ):
            _require_nonempty_exact_str(getattr(self, field_name), field_name)
        _require_exact_false(self.gate_eligible, "gate_eligible")
        _require_exact_false(
            self.complete_cost_claim_allowed,
            "complete_cost_claim_allowed",
        )
        if self.record_kind not in _CAUSAL_RECORD_KINDS:
            raise ValueError("unknown causal record_kind")
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
        if self.metrics.strategy != expected_strategy:
            if self.record_kind == "fixed-candidate":
                raise ValueError("fixed-candidate strategy_kind must match metrics.strategy")
            raise ValueError(f"metrics.strategy contradicts record_kind {self.record_kind}")
        if self.metrics.category != expected_category:
            raise ValueError(f"metrics.category contradicts record_kind {self.record_kind}")
        if self.metrics.source != expected_metric_source:
            raise ValueError(f"metrics.source contradicts record_kind {self.record_kind}")


def _validate_causal_record_set(items: list[CausalMetricRecord]) -> None:
    fixed_by_candidate: dict[str, CausalMetricRecord] = {}
    for item in items:
        if not isinstance(item, CausalMetricRecord):
            raise TypeError("causal records must be CausalMetricRecord instances")
        item._validate()
        if item.record_kind != "fixed-candidate":
            continue
        if item.candidate_id in fixed_by_candidate:
            raise ValueError(f"duplicate fixed-candidate candidate_id: {item.candidate_id}")
        fixed_by_candidate[item.candidate_id] = item

    for item in items:
        if item.record_kind == "fixed-candidate":
            continue
        basis = fixed_by_candidate.get(item.candidate_id)
        if basis is None:
            raise ValueError(
                f"{item.record_kind} has no fixed basis candidate_id {item.candidate_id}"
            )
        if item.strategy_kind != basis.metrics.strategy:
            raise ValueError(
                f"{item.record_kind} basis strategy_kind does not match "
                f"fixed metrics.strategy for {item.candidate_id}"
            )


def _causal_record(item: CausalMetricRecord, costs: UnitCosts) -> dict[str, object]:
    record = item.metrics.to_record(costs)
    record.pop("unit_cost_label", None)
    record.update(
        {
            "schema": CAUSAL_SCHEMA,
            "state_model": CAUSAL_STATE_MODEL,
            "measurement_kind": CAUSAL_MEASUREMENT_KIND,
            "gate_eligible": item.gate_eligible,
            "complete_cost_claim_allowed": item.complete_cost_claim_allowed,
            "unit_cost_model": "normalized-predicted-proxy",
            "record_kind": item.record_kind,
            "candidate_id": item.candidate_id,
            "label": item.label,
            "strategy_kind": item.strategy_kind,
            "phase": item.phase,
            "selection_source": item.selection_source,
        }
    )
    return record


def write_causal_records(
    output_dir: Path,
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: dict[str, object],
) -> None:
    """Write Day-1 causal proxy records without implying a gate verdict."""

    _validate_causal_record_set(items)
    output_dir.mkdir(parents=True, exist_ok=True)
    causal_metadata = {
        **metadata,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
    }
    records = [_causal_record(item, costs) for item in items]
    payload = {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "metadata": causal_metadata,
        "records": records,
    }
    (output_dir / "metrics.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    if records:
        with (output_dir / "metrics.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)


def write_causal_summary(
    output_dir: Path,
    items: list[CausalMetricRecord],
    costs: UnitCosts,
    metadata: dict[str, object],
) -> None:
    _validate_causal_record_set(items)
    output_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Day-1 causal predicted report",
        "",
        f"- Schema: `{CAUSAL_SCHEMA}`",
        f"- State model: `{CAUSAL_STATE_MODEL}`",
        f"- Measurement kind: `{CAUSAL_MEASUREMENT_KIND}`",
        "- `gate_eligible=false`",
        "- `complete_cost_claim_allowed=false`",
        f"- Workload: `{metadata.get('workload')}`",
        f"- Publication windows: `{metadata.get('windows_total')}`",
        "",
        (
            "| Record kind | Fixed-policy basis | Strategy | Windows | Updates | "
            "Queries | Predicted normalized cost |"
        ),
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for item in items:
        metrics = item.metrics
        lines.append(
            f"| {item.record_kind} | {item.candidate_id} | "
            f"{metrics.strategy} | {metrics.windows} | {metrics.updates} | "
            f"{metrics.queries} | {metrics.predicted_time(costs):.2f} |"
        )
    span80_by_candidate = metadata.get("span80_by_candidate")
    if span80_by_candidate is not None:
        if not isinstance(span80_by_candidate, dict):
            raise TypeError("span80_by_candidate must be a mapping")
        fixed_candidate_ids = [
            item.candidate_id for item in items if item.record_kind == "fixed-candidate"
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
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


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
) -> None:
    """Plot causal records without discarding fixed-candidate identity."""

    import matplotlib.pyplot as plt

    _validate_causal_record_set(items)
    output_dir.mkdir(parents=True, exist_ok=True)
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
    axis.set_title("Predicted proxy: update amplification vs query cost")
    figure.tight_layout()
    figure.savefig(output_dir / "ua_vs_qa_proxy.png", dpi=160)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(10, 6))
    plotted = False
    for item, label in zip(items, labels, strict=True):
        metrics = item.metrics
        if metrics.updates == 0:
            continue
        rho = metrics.queries / metrics.updates
        per_update = metrics.predicted_update_time(costs) / metrics.updates
        value = per_update + rho * metrics.predicted_query_time_per_query(costs)
        axis.scatter([rho], [value], label=label)
        axis.annotate(label, (rho, value), fontsize=7)
        plotted = True
    if items and all(item.metrics.queries > 0 and item.metrics.updates > 0 for item in items):
        axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("Actual query/update ratio ρ from the event schedule")
    axis.set_ylabel("Predicted normalized cost per update at actual ρ")
    axis.set_title("Predicted proxy at the executed query/update ratio")
    if plotted:
        axis.legend(fontsize=7)
    figure.tight_layout()
    figure.savefig(output_dir / "t_rho_proxy.png", dpi=160)
    plt.close(figure)


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
