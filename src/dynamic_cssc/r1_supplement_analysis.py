"""Descriptive, independently reconstructed R1 records, including missing groups."""

from __future__ import annotations

import json
import statistics
import subprocess
from pathlib import Path

from dynamic_cssc.r1_supplement import (
    CLASS,
    CONFIG,
    PROTOCOL,
    PUBLIC_FILES,
    STUDY,
    TAG,
    file_hash,
    git,
    groups,
    load_protocol,
    registered_workload,
    save_new,
    verify_trace,
)
from dynamic_cssc.r1_workloads import balanced_strategy_order

METRICS = (
    "whole_process_ns",
    "initial_setup_and_publication_ns",
    "post_initial_lifecycle_ns",
    "publication_ns",
    "query_ns",
    "oracle_ns",
    "reconstruction_ns",
    "wire_total_bytes",
)


def inspect_group(folder: Path, group: dict, identity: dict) -> list[dict]:
    record = json.loads((folder / "group.json").read_bytes())
    if (
        record.get("schema_version") != "r1-supplement-group-v1"
        or record.get("evidence_class") != CLASS
        or record.get("campaign") != {**identity, **group}
        or record.get("status") != "pass"
    ):
        raise ValueError("group identity/class/status mismatch")
    expected_order = [
        {"name": f"repeat-{r}-{s}", "repetition": r, "strategy": s}
        for r in range(3)
        for s in balanced_strategy_order(group["group"], r)
    ]
    if record.get("executions") != expected_order:
        raise ValueError("group repetition/order mismatch")
    files = record["files"]
    allowed = {
        f"{item['name']}/{name}"
        for item in expected_order
        for name in ("events.jsonl", "summary.json", "native-stderr.log")
    }
    actual = {str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()}
    if set(files) != allowed or actual != allowed | {"group.json"}:
        raise ValueError("missing/extra/orphan public files")
    for name, metadata in files.items():
        path = folder / name
        if path.is_symlink() or metadata != {
            "sha256": file_hash(path),
            "bytes": path.stat().st_size,
        }:
            raise ValueError("public file digest/size mismatch")
        if path.name == "native-stderr.log" and path.stat().st_size:
            raise ValueError("successful native trace has unexpected stderr")
    environment = record["environment"]
    if (
        not environment.get("cpu_model")
        or not environment.get("openfhe_library_sha256")
        or len(environment.get("native_binary_sha256", "")) != 64
        or environment.get("python") != "3.12.13"
        or environment.get("omp_num_threads") != 1
        or environment.get("openblas_num_threads") != 1
    ):
        raise ValueError("environment inventory incomplete")
    # Only after formal identity + complete public inventory are admitted do
    # registered seeds enter the independent workload reconstruction.
    workload = registered_workload(group)
    return [
        {
            **group,
            "repetition": item["repetition"],
            "strategy": item["strategy"],
            "environment": environment,
            "metrics": verify_trace(
                folder / item["name"],
                workload,
                {**identity, **group, "repetition": item["repetition"]},
                item["strategy"],
            ),
        }
        for item in expected_order
    ]


def descriptive_tables(rows: list[dict]) -> list[dict]:
    result = []
    for group_id in sorted({row["group"] for row in rows}):
        members = [row for row in rows if row["group"] == group_id]
        expected = {(s, r) for s in ("repack", "padding", "strong") for r in range(3)}
        if len(members) != 9 or {(m["strategy"], m["repetition"]) for m in members} != expected:
            raise ValueError("numerical comparison requires a complete nine-trace group")
        stats = {}
        for strategy in ("repack", "padding", "strong"):
            subset = [row["metrics"] for row in members if row["strategy"] == strategy]
            stats[strategy] = {}
            for metric in METRICS:
                values = [row[metric] for row in subset]
                stats[strategy][metric] = {
                    "median": statistics.median(values),
                    "min": min(values),
                    "max": max(values),
                }
        for strategy in ("padding", "strong"):
            for metric in METRICS:
                baseline = stats["repack"][metric]["median"]
                measured = stats[strategy][metric]["median"]
                stats[strategy][metric]["paired_difference_to_repack"] = measured - baseline
                stats[strategy][metric]["paired_ratio_to_repack"] = (
                    measured / baseline if baseline else None
                )
        result.append({"group": group_id, "statistics": stats})
    return result


def collect(root: Path, output: Path, source: str, run_id: str) -> dict:
    plan = load_protocol()
    if not run_id.isdigit() or source != git("rev-parse", "HEAD"):
        raise ValueError("independent inspector source/run mismatch")
    if git("rev-parse", f"refs/tags/{TAG}^{{commit}}") != source:
        raise ValueError("independent inspector source is not frozen tag")
    identity = {
        "study_id": STUDY,
        "source_sha": source,
        "source_tree": git("rev-parse", "HEAD^{tree}"),
        "source_tag": TAG,
        "config_sha256": file_hash(CONFIG),
        "protocol_sha256": file_hash(PROTOCOL),
        "provider_run_id": run_id,
        "provider_attempt": 1,
    }
    provider_run = json.loads(
        subprocess.check_output(
            ["gh", "api", f"repos/leemaple/dynamic-cssc-spmv/actions/runs/{run_id}"]
        )
    )
    # GitHub's documented run path may append @ref. Preserve the original in
    # provider-run.json; source/tag/run/attempt checks remain separate anchors.
    workflow_path = provider_run["path"]
    if (
        str(provider_run["id"]) != run_id
        or provider_run["head_sha"] != source
        or provider_run["run_attempt"] != 1
        or provider_run["event"] != "push"
        or not isinstance(workflow_path, str)
        or workflow_path.partition("@")[0] != ".github/workflows/r1-native-supplement.yml"
    ):
        raise ValueError("provider campaign identity/attempt mismatch")
    provider = json.loads(
        subprocess.check_output(
            [
                "gh",
                "api",
                f"repos/leemaple/dynamic-cssc-spmv/actions/runs/{run_id}/jobs?filter=latest&per_page=100",
            ]
        )
    )
    jobs = {job["name"]: job for job in provider["jobs"] if job["name"].startswith("group-")}
    if len(jobs) != len([j for j in provider["jobs"] if j["name"].startswith("group-")]):
        raise ValueError("duplicate producer job identities")
    expected_names = {f"group-{i}" for i in range(24)}
    if set(jobs) - expected_names or any(j["status"] != "completed" for j in jobs.values()):
        raise ValueError("unexpected or nonterminal producer jobs")
    output.mkdir(parents=True, exist_ok=False)
    save_new(output / "provider-run.json", provider_run)
    save_new(output / "provider-jobs.json", provider)
    rows, coverage = [], []
    unexpected = (
        [p.name for p in root.iterdir() if p.name not in expected_names] if root.exists() else []
    )
    if unexpected:
        raise ValueError("unexpected artifact root")
    for group in groups(plan):
        name = f"group-{group['group']}"
        job = jobs.get(name)
        item = {**group, "provider_status": job["conclusion"] if job else "not-started/absent"}
        try:
            if job is None or job["conclusion"] != "success":
                raise ValueError("provider producer did not complete successfully")
            if job.get("head_sha") not in {None, source} or job.get("run_attempt") not in {None, 1}:
                raise ValueError("provider source/attempt mismatch")
            inspected = inspect_group(root / name, group, identity)
            rows.extend(inspected)
            item["admission"] = "pass"
        except (ValueError, KeyError, OSError, TypeError) as error:
            item["admission"] = "incomplete-or-rejected"
            item["reason"] = f"{type(error).__name__}: {error}"
            folder = root / name
            item["retained_public_files"] = [
                str(p.relative_to(folder))
                for p in sorted(folder.rglob("*"))
                if p.is_file() and (p.name in PUBLIC_FILES or p.name == "group.json")
            ]
        coverage.append(item)
    result = {
        "schema_version": "r1-supplement-independent-admission-v1",
        "campaign": identity,
        "complete": len(rows) == 216 and all(c["admission"] == "pass" for c in coverage),
        "admitted_traces": len(rows),
        "group_coverage": coverage,
        "scope": "independent global logical reconstruction; not decryption or timing replication",
    }
    save_new(output / "admission.json", result)
    save_new(output / "raw-records.json", rows)
    save_new(output / "descriptive-tables.json", descriptive_tables(rows))
    return result
