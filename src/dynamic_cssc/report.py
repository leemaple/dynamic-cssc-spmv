from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from .metrics import StrategyMetrics, UnitCosts


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


def write_plots(output_dir: Path, metrics: list[StrategyMetrics], costs: UnitCosts) -> None:
    import matplotlib.pyplot as plt

    names = [item.strategy for item in metrics]
    update_values = [item.update_ct_equivalents() for item in metrics]
    query_values = [
        (item.cc_multiplications + item.rotations) / item.queries
        if item.queries
        else 0.0
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
