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
        "| Strategy | Category | Update ct-equiv/update | Query ciphertexts | CC mults | Rotations | Predicted normalized cost |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in sorted(metrics, key=lambda candidate: candidate.predicted_time(costs)):
        lines.append(
            "| {strategy} | {category} | {ua:.4f} | {query} | {mult} | {rot} | {cost:.2f} |".format(
                strategy=item.strategy,
                category=item.category,
                ua=item.update_ct_equivalents(),
                query=item.query_ciphertexts,
                mult=item.cc_multiplications,
                rot=item.rotations,
                cost=item.predicted_time(costs),
            )
        )
    lines.extend(
        [
            "",
            "## Plain-language interpretation",
            "",
            "This report only checks that the accounting pipeline works and that all split-output F1-M strategies pay their mask, download, decryption, and client-merge costs. It is not evidence that any strategy is faster. The research gate is decided only after P0b/Day-2 supplies measured OpenFHE constants and the verdict is evaluated on a held-out real skewed stream.",
            "",
        ]
    )
    (output_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def write_plots(output_dir: Path, metrics: list[StrategyMetrics], costs: UnitCosts) -> None:
    import matplotlib.pyplot as plt

    names = [item.strategy for item in metrics]
    update_values = [item.update_ct_equivalents() for item in metrics]
    query_values = [item.cc_multiplications + item.rotations for item in metrics]

    figure, axis = plt.subplots(figsize=(10, 6))
    axis.scatter(query_values, update_values)
    for name, x_value, y_value in zip(names, query_values, update_values, strict=True):
        axis.annotate(name, (x_value, y_value), fontsize=7)
    axis.set_xlabel("Query operation proxy (CC multiplications + rotations)")
    axis.set_ylabel("Update ciphertext-equivalents per update")
    axis.set_title("Predicted proxy: update amplification vs query cost")
    figure.tight_layout()
    figure.savefig(output_dir / "ua_vs_qa_proxy.png", dpi=160)
    plt.close(figure)

    rhos = [0.01, 0.03, 0.1, 0.3, 1, 3, 10, 30, 100]
    figure, axis = plt.subplots(figsize=(10, 6))
    for item in metrics:
        update_cost = (
            item.update_encryptions + item.compaction_ciphertexts + item.blinding_encryptions
        ) * costs.encrypt
        per_query = (
            item.cc_multiplications * costs.eval_mult
            + item.rotations * costs.eval_rotate
            + (item.additions + item.blinding_additions) * costs.eval_add
            + item.decryptions * costs.decrypt
            + item.client_merges * costs.client_merge
        ) / max(1, item.windows)
        values = [update_cost + rho * per_query for rho in rhos]
        axis.plot(rhos, values, marker="o", label=item.strategy)
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("Query/update ratio ρ")
    axis.set_ylabel("Predicted normalized T(ρ)")
    axis.set_title("Predicted proxy only; replace with Day-2 measured constants")
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
