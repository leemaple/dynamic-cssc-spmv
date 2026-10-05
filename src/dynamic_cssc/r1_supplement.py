"""One tagged, post-review descriptive campaign; no retry/controller hierarchy.

Loading the prospective protocol does not generate inputs. A producer validates
its exact tag-created provider invocation before using a registered seed. The
independent inspector may regenerate only identities present in received formal
records; it never performs native execution.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import platform
import resource
import subprocess
import sys
from dataclasses import asdict
from importlib.metadata import distributions
from pathlib import Path

from dynamic_cssc.r1_native_lifecycle import _run_lifecycle_trace, canonical, digest
from dynamic_cssc.r1_workloads import _generate, balanced_strategy_order

STUDY = "iscai-sa038-post-review-native-v1"
TAG = "iscai-sa038-r1-native-formal-v1"
DOMAIN = "post-review-r1-formal-"
CLASS = "post-review-descriptive-native-producer"
CONFIG = Path("config/r1-native-supplement.json")
PROTOCOL = Path("docs/paper/r1-native-supplement-protocol.md")
PUBLIC_FILES = ("events.jsonl", "summary.json", "failure.json", "native-stderr.log")


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save_new(path: Path, value: object) -> None:
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def load_protocol() -> dict:
    plan = json.loads(CONFIG.read_bytes())
    fixed = {
        "study_id": STUDY,
        "source_tag": TAG,
        "rows": [256, 1024],
        "columns": 8193,
        "distributions": ["concentrated", "dispersed"],
        "queries_per_window": [1, 8],
        "windows": 8,
        "initial_entries_per_row": 8,
        "strategies": ["repack", "padding", "strong"],
        "segment_width": 128,
        "technical_repetitions": 3,
        "trace_timeout_seconds": 300,
        "job_timeout_minutes": 55,
        "max_parallel": 2,
        "address_space_bytes_per_process": 4 * 1024**3,
        "file_size_bytes_per_file": 256 * 1024**2,
        "thread_count": 1,
        "python_version": "3.12.13",
        "openfhe_commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "reruns": 0,
    }
    if set(plan) != {*fixed, "workload_seeds"} or any(plan[k] != v for k, v in fixed.items()):
        raise ValueError("supplement protocol factors/limits changed")
    seeds = plan["workload_seeds"]
    if seeds != [2026100501, 2026100502, 2026100503]:
        raise ValueError("prospective opaque seed inventory changed")
    return plan


def groups(plan: dict) -> tuple[dict, ...]:
    return tuple(
        dict(group=i, rows=rows, distribution=distribution, queries_per_window=h, seed=seed)
        for i, (rows, distribution, h, seed) in enumerate(
            itertools.product(
                plan["rows"],
                plan["distributions"],
                plan["queries_per_window"],
                plan["workload_seeds"],
            )
        )
    )


def require_producer(plan: dict, env=None) -> dict:
    """Cheap read-only admission before seed generation, not a security sandbox."""
    env = os.environ if env is None else env
    if (
        env.get("GITHUB_ACTIONS") != "true"
        or env.get("GITHUB_REPOSITORY") != "leemaple/dynamic-cssc-spmv"
        or env.get("GITHUB_EVENT_NAME") != "push"
        or env.get("GITHUB_REF") != f"refs/tags/{TAG}"
        or env.get("GITHUB_RUN_ATTEMPT") != "1"
        or not env.get("GITHUB_RUN_ID", "").isdigit()
    ):
        raise ValueError("formal producer requires the sole new-tag provider attempt")
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    source = git("rev-parse", "HEAD")
    if (
        event.get("created") is not True
        or event.get("deleted") is not False
        or event.get("ref") != f"refs/tags/{TAG}"
        or event.get("after") != source
        or env.get("GITHUB_SHA") != source
        or git("rev-parse", f"refs/tags/{TAG}^{{commit}}") != source
        or git("status", "--porcelain", "--untracked-files=no")
    ):
        raise ValueError("formal tag/source/event/clean-tree mismatch")
    if (
        platform.system() != "Linux"
        or platform.python_version() != plan["python_version"]
        or env.get("OMP_NUM_THREADS") != "1"
        or env.get("OPENBLAS_NUM_THREADS") != "1"
    ):
        raise ValueError("formal platform/Python/thread configuration mismatch")
    return {
        "study_id": STUDY,
        "source_sha": source,
        "source_tree": git("rev-parse", "HEAD^{tree}"),
        "source_tag": TAG,
        "config_sha256": file_hash(CONFIG),
        "protocol_sha256": file_hash(PROTOCOL),
        "provider_run_id": env["GITHUB_RUN_ID"],
        "provider_attempt": 1,
    }


def registered_workload(group: dict):
    """Internal: caller must have admitted a producer or an existing receipt."""
    return _generate(
        rows=group["rows"],
        distribution=group["distribution"],
        queries_per_window=group["queries_per_window"],
        identity=f"{DOMAIN}{STUDY}-seed{group['seed']}",
        input_domain=DOMAIN,
    )


def environment(executable: Path) -> dict:
    cpu = next(
        (
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        ),
        "unreported",
    )
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_model": cpu,
        "logical_cpu_count": os.cpu_count(),
        "os_release": Path("/etc/os-release").read_text(),
        "runner_image_os": os.environ.get("ImageOS"),  # noqa: SIM112 -- provider's name
        "runner_image_version": os.environ.get("ImageVersion"),  # noqa: SIM112
        "compiler": subprocess.check_output(["c++", "--version"], text=True).splitlines()[0],
        "native_binary_sha256": file_hash(executable),
        "packages": sorted((d.metadata["Name"], d.version) for d in distributions()),
        "openfhe_library_sha256": {
            str(p): file_hash(p)
            for p in sorted(Path("_openfhe/install").rglob("libOPENFHE*.so*"))
            if p.is_file() and not p.is_symlink()
        },
        "omp_num_threads": 1,
        "openblas_num_threads": 1,
    }


def run_trace(
    group_id: int, repetition: int, strategy: str, executable: Path, output: Path
) -> None:
    plan = load_protocol()
    identity = require_producer(plan)
    if type(group_id) is not int or not 0 <= group_id < 24:
        raise ValueError("group outside the frozen grid")
    if repetition not in range(3) or strategy not in plan["strategies"]:
        raise ValueError("trace outside the frozen grid")
    if output.exists() or output.is_symlink():
        raise ValueError("trace output already exists")
    group = groups(plan)[group_id]
    resource.setrlimit(resource.RLIMIT_AS, (plan["address_space_bytes_per_process"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (plan["file_size_bytes_per_file"],) * 2)
    workload = registered_workload(group)
    try:
        result = _run_lifecycle_trace(
            workload,
            strategy,
            executable,
            output,
            timeout_seconds=plan["trace_timeout_seconds"],
            input_domain=DOMAIN,
            evidence_class=CLASS,
        )
        result["campaign"] = {**identity, **group, "repetition": repetition}
        save_new(output / "summary.json", result)
    except Exception as error:
        output.mkdir(parents=True, exist_ok=True)
        save_new(
            output / "failure.json",
            {
                "campaign": {**identity, **group, "repetition": repetition},
                "strategy": strategy,
                "evidence_class": CLASS,
                "status": "failed",
                "error_type": type(error).__name__,
                "error": str(error),
            },
        )
        raise


def run_group(group_id: int, executable: Path, output: Path, entrypoint: Path) -> None:
    plan = load_protocol()
    identity = require_producer(plan)
    if type(group_id) is not int or not 0 <= group_id < 24:
        raise ValueError("group outside frozen grid")
    output.mkdir(parents=True, exist_ok=False)
    group = groups(plan)[group_id]
    record = {
        "schema_version": "r1-supplement-group-v1",
        "evidence_class": CLASS,
        "campaign": {**identity, **group},
        "environment": environment(executable),
        "executions": [],
        "status": "running",
    }
    if not record["environment"]["openfhe_library_sha256"]:
        raise ValueError("pinned native library inventory unavailable before seed generation")
    try:
        for repetition in range(3):
            for strategy in balanced_strategy_order(group_id, repetition):
                name = f"repeat-{repetition}-{strategy}"
                record["executions"].append(
                    {"name": name, "repetition": repetition, "strategy": strategy}
                )
                subprocess.run(
                    [
                        sys.executable,
                        str(entrypoint),
                        "trace",
                        "--group",
                        str(group_id),
                        "--repetition",
                        str(repetition),
                        "--strategy",
                        strategy,
                        "--executable",
                        str(executable),
                        "--output-dir",
                        str(output / name),
                    ],
                    check=True,
                    timeout=plan["trace_timeout_seconds"] + 30,
                )
        record["status"] = "pass"
    except Exception as error:
        record["status"] = "failed"
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        record["files"] = {
            str(path.relative_to(output)): {"sha256": file_hash(path), "bytes": path.stat().st_size}
            for name in PUBLIC_FILES
            for path in sorted(output.glob(f"*/{name}"))
        }
        save_new(output / "group.json", record)


def verify_trace(directory: Path, workload, campaign: dict, strategy: str) -> dict:
    """Independent dictionary dot products; never calls the producer's oracle."""
    summary = json.loads((directory / "summary.json").read_bytes())
    events = [json.loads(line) for line in (directory / "events.jsonl").read_bytes().splitlines()]
    if (
        summary.get("campaign") != campaign
        or summary.get("strategy") != strategy
        or summary.get("evidence_class") != CLASS
        or summary.get("status") != "pass"
        or summary.get("formal_authority") is not False
        or summary.get("workload_identity") != workload.identity
        or summary.get("workload_sha256") != digest(asdict(workload))
        or summary.get("complete_queries") != sum(map(len, workload.queries))
        or summary.get("consumed_query_batches") != summary["complete_queries"]
    ):
        raise ValueError("trace identity, workload or query count mismatch")
    expected_phases = ["setup", "initial-publication"]
    for queries in workload.queries:
        expected_phases.extend(["publication", *(["query"] * len(queries))])
    expected_phases.extend(["close", "summary"])
    if [event.get("phase") for event in events] != expected_phases:
        raise ValueError("trace phase/order/coverage mismatch")
    if {k: v for k, v in events[-1].items() if k != "phase"} != {
        k: v for k, v in summary.items() if k != "campaign"
    }:
        raise ValueError("summary differs from terminal event")
    logical = {(r, c): value for r, c, value in workload.initial}
    cursor, publication_ns, query_ns, oracle_ns, reconstruction_ns = 2, 0, 0, 0, 0
    for window, (updates, vectors) in enumerate(
        zip(workload.windows, workload.queries, strict=True)
    ):
        pub = events[cursor]
        if pub.get("window") != window:
            raise ValueError("publication window mismatch")
        publication_ns += pub["elapsed_ns"]
        cursor += 1
        for update in updates:
            key = update.row, update.col
            if logical.get(key, 0) != update.before:
                raise ValueError("independent logical update mismatch")
            if update.after:
                logical[key] = update.after
            else:
                del logical[key]
        for query, vector in enumerate(vectors):
            event = events[cursor]
            expected = [0] * workload.rows
            for (row, column), value in logical.items():
                expected[row] = (expected[row] + value * vector[column]) % 65537
            if (
                event.get("window") != window
                or event.get("query") != query
                or event.get("output") != expected
                or event.get("query_vector_sha256") != digest(vector)
                or event.get("all_slots_and_direct_oracle") != "pass"
            ):
                raise ValueError("independent global output/query identity mismatch")
            query_ns += event["elapsed_ns"]
            oracle_ns += event["oracle_ns"]
            reconstruction_ns += event["reconstruction_ns"]
            cursor += 1
    native_events = [e["native"] for e in events if "native" in e]
    if [e["sequence"] for e in native_events] != list(range(len(native_events))):
        raise ValueError("native receipt sequence mismatch")
    if any(e.get("status") != "pass" for e in native_events):
        raise ValueError("native receipt failure")
    for event in events[:-1]:
        native = event["native"]
        expected_op = {"initial-publication": "publish", "publication": "publish"}.get(
            event["phase"], event["phase"]
        )
        if native.get("op") != expected_op:
            raise ValueError("native operation/phase mismatch")
        for record in (event, native):
            for key, value in record.items():
                if key.endswith("_ns") and (type(value) is not int or value < 0):
                    raise ValueError("invalid timing observation")
        if expected_op == "publish" and (
            native["matrix_encryptions"] + native["matrix_reused"] != native["matrix_ciphertexts"]
            or native["old_plus_new_unique_matrix_serialized_bytes"]
            < max(native["old_matrix_serialized_bytes"], native["matrix_serialized_bytes"])
        ):
            raise ValueError("native matrix count/storage mismatch")
        if expected_op == "query" and (
            event["reconstruction_ns"] + event["oracle_ns"] > event["elapsed_ns"]
            or len([m for m in native["wire_objects"] if m["direction"] == "Cloud->B"])
            != native["decryptions"]
            or len([m for m in native["wire_objects"] if m["kind"] == "query-binding"]) != 1
        ):
            raise ValueError("query timing/return/control count mismatch")
    delta = summary["terminal_delta_lane_inventory"]
    if (
        delta["live"] + delta["tombstone"] + delta["unused"] != delta["page_capacity_lanes"]
        or delta["allocated_segment_lanes"] + delta["unallocated_page_tail"]
        != delta["page_capacity_lanes"]
    ):
        raise ValueError("delta inventory mismatch")
    whole, initial = summary["whole_process_ns"], summary["initial_setup_and_publication_ns"]
    if (
        whole < initial + publication_ns + query_ns
        or summary["post_initial_lifecycle_ns"] != whole - initial
    ):
        raise ValueError("whole/phase timing reconciliation failed")
    wire = {direction: 0 for direction in ("A->Cloud", "A->B", "B->Cloud", "Cloud->B")}
    phase_bytes = {
        phase: 0 for phase in ("setup", "initial-publication", "publication", "query", "close")
    }
    for event in events[:-1]:
        native = event["native"]
        for message in native.get("wire_objects", ()):
            if (
                message["direction"] not in wire
                or type(message["bytes"]) is not int
                or message["bytes"] <= 0
            ):
                raise ValueError("invalid wire direction/length")
            wire[message["direction"]] += message["bytes"]
            phase_bytes[event["phase"]] += message["bytes"]
    return {
        "whole_process_ns": whole,
        "initial_setup_and_publication_ns": initial,
        "post_initial_lifecycle_ns": whole - initial,
        "publication_ns": publication_ns,
        "query_ns": query_ns,
        "oracle_ns": oracle_ns,
        "reconstruction_ns": reconstruction_ns,
        "wire_total_bytes": sum(wire.values()),
        "wire_bytes_by_direction": wire,
        "wire_bytes_by_phase": phase_bytes,
        "terminal_base_lane_inventory": summary["terminal_base_lane_inventory"],
        "terminal_delta_lane_inventory": delta,
        "observed_process_high_water_sum": summary[
            "sum_of_observed_process_rss_high_water_marks_platform_units"
        ],
        "resource_samples": summary["resource_samples"],
        "ledger_bytes": summary["ledger_bytes"],
    }
