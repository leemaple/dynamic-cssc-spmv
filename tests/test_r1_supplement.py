"""Prospective controls and explicitly fake receipts. No registered seed runs."""

import json
from copy import deepcopy
from dataclasses import asdict

import pytest

import dynamic_cssc.r1_supplement as supplement
from dynamic_cssc.r1_native_lifecycle import canonical, digest, engineering_workload
from dynamic_cssc.r1_supplement_analysis import METRICS, descriptive_tables, inspect_group


def test_fixed_grid_arithmetic_without_generating_registered_inputs():
    plan = supplement.load_protocol()
    grid = supplement.groups(plan)
    assert len(grid) == 24
    assert sum(8 * g["queries_per_window"] * 9 for g in grid) == 7776
    assert (
        len({(g["rows"], g["distribution"], g["queries_per_window"], g["seed"]) for g in grid})
        == 24
    )
    assert 24 * plan["job_timeout_minutes"] / 60 == 22 < 40
    assert plan["reruns"] == 0


@pytest.mark.parametrize("env", [{}, {"GITHUB_ACTIONS": "true"}, {"GITHUB_RUN_ATTEMPT": "2"}])
def test_offline_wrong_invocations_reject_before_registered_generator(tmp_path, monkeypatch, env):
    monkeypatch.setattr(supplement.os, "environ", env)

    def forbidden(_):
        raise AssertionError("registered seed entered during a negative control")

    monkeypatch.setattr(supplement, "registered_workload", forbidden)
    with pytest.raises(ValueError, match="sole new-tag"):
        supplement.run_trace(0, 0, "strong", tmp_path / "never-executed", tmp_path / "trace")
    assert not (tmp_path / "trace").exists()


@pytest.fixture
def allowed_provider_fixture(tmp_path, monkeypatch):
    # A fake provider fixture only validates scalar admission. It NEVER calls
    # registered_workload or the native producer, even in its passing case.
    source = "f" * 40
    event = {
        "ref": f"refs/tags/{supplement.TAG}",
        "created": True,
        "deleted": False,
        "after": source,
    }
    path = tmp_path / "event.json"
    path.write_bytes(canonical(event))
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "leemaple/dynamic-cssc-spmv",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": event["ref"],
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "123",
        "GITHUB_EVENT_PATH": str(path),
        "GITHUB_SHA": source,
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
    }
    monkeypatch.setattr(supplement.platform, "system", lambda: "Linux")
    monkeypatch.setattr(supplement.platform, "python_version", lambda: "3.12.13")
    monkeypatch.setattr(supplement, "git", lambda *a: "" if a[0] == "status" else source)
    return env, event, path


def test_producer_guard_reads_exact_scalar_identity_only(allowed_provider_fixture):
    env, _, _ = allowed_provider_fixture
    receipt = supplement.require_producer(supplement.load_protocol(), env)
    assert receipt["source_sha"] == "f" * 40
    assert receipt["provider_attempt"] == 1


@pytest.mark.parametrize(
    "field,value", [("created", False), ("deleted", True), ("after", "e" * 40)]
)
def test_tag_event_rejection(allowed_provider_fixture, field, value):
    env, event, path = allowed_provider_fixture
    event[field] = value
    path.write_bytes(canonical(event))
    with pytest.raises(ValueError, match="tag/source/event"):
        supplement.require_producer(supplement.load_protocol(), env)


def test_existing_file_never_overwritten(tmp_path):
    path = tmp_path / "receipt.json"
    supplement.save_new(path, {"original": True})
    with pytest.raises(FileExistsError):
        supplement.save_new(path, {"original": False})
    assert path.read_bytes() == canonical({"original": True}) + b"\n"


def fake_trace_fixture(tmp_path):
    """Deliberately fake, tiny engineering-domain records for inspector tests."""
    workload = engineering_workload()
    events, sequence = [], 0

    def event(phase, **fields):
        nonlocal sequence
        op = "publish" if phase in {"publication", "initial-publication"} else phase
        native = {"status": "pass", "sequence": sequence, "op": op, "wire_objects": []}
        if op == "publish":
            native.update(
                matrix_encryptions=1,
                matrix_reused=0,
                matrix_ciphertexts=1,
                old_plus_new_unique_matrix_serialized_bytes=2,
                old_matrix_serialized_bytes=1,
                matrix_serialized_bytes=1,
            )
        if op == "query":
            native.update(
                decryptions=1,
                wire_objects=[
                    {"kind": "query-binding", "direction": "B->Cloud", "bytes": 1},
                    {"kind": "result", "direction": "Cloud->B", "bytes": 1},
                ],
            )
        events.append({"phase": phase, "native": native, **fields})
        sequence += 1

    event("setup")
    event("initial-publication", elapsed_ns=10)
    logical = {(r, c): value for r, c, value in workload.initial}
    for wi, (updates, vectors) in enumerate(zip(workload.windows, workload.queries, strict=True)):
        event("publication", window=wi, elapsed_ns=10)
        for u in updates:
            if u.after:
                logical[u.row, u.col] = u.after
            else:
                del logical[u.row, u.col]
        for qi, vector in enumerate(vectors):
            output = [
                sum(v * vector[c] for (r, c), v in logical.items() if r == row) % 65537
                for row in range(workload.rows)
            ]
            event(
                "query",
                window=wi,
                query=qi,
                elapsed_ns=10,
                reconstruction_ns=2,
                oracle_ns=3,
                output=output,
                query_vector_sha256=digest(vector),
                all_slots_and_direct_oracle="pass",
            )
    event("close")
    summary = {
        "strategy": "repack",
        "evidence_class": supplement.CLASS,
        "formal_authority": False,
        "status": "pass",
        "workload_identity": workload.identity,
        "workload_sha256": digest(asdict(workload)),
        "complete_queries": 4,
        "consumed_query_batches": 4,
        "terminal_delta_lane_inventory": {
            "live": 0,
            "tombstone": 0,
            "unused": 0,
            "allocated_segment_lanes": 0,
            "unallocated_page_tail": 0,
            "page_capacity_lanes": 0,
        },
        "terminal_base_lane_inventory": {"test-only": 1},
        "whole_process_ns": 100,
        "initial_setup_and_publication_ns": 20,
        "post_initial_lifecycle_ns": 80,
        "sum_of_observed_process_rss_high_water_marks_platform_units": 1,
        "resource_samples": {"test-only": True},
        "ledger_bytes": 1,
    }
    events.append({"phase": "summary", **summary})
    summary["campaign"] = {"test-only": True}
    (tmp_path / "summary.json").write_bytes(canonical(summary))
    (tmp_path / "events.jsonl").write_bytes(b"\n".join(canonical(e) for e in events) + b"\n")
    return workload, summary, events


def test_independent_reconstruction_checks_fake_fixture(tmp_path):
    workload, summary, _ = fake_trace_fixture(tmp_path)
    metrics = supplement.verify_trace(tmp_path, workload, summary["campaign"], "repack")
    assert metrics["whole_process_ns"] == 100 and metrics["wire_total_bytes"] == 8


@pytest.mark.parametrize("corruption", ["output", "order", "timing", "summary", "sequence"])
def test_independent_reconstruction_rejects_bad_records(tmp_path, corruption):
    workload, summary, events = fake_trace_fixture(tmp_path)
    if corruption == "output":
        events[3]["output"][0] += 1
    elif corruption == "order":
        events[3], events[2] = events[2], events[3]
    elif corruption == "timing":
        events[3]["oracle_ns"] = 100
    elif corruption == "summary":
        events[-1]["complete_queries"] = 5
    else:
        events[3]["native"]["sequence"] = 999
    (tmp_path / "events.jsonl").write_bytes(b"\n".join(canonical(e) for e in events) + b"\n")
    with pytest.raises(ValueError):
        supplement.verify_trace(tmp_path, workload, summary["campaign"], "repack")


def test_wrong_group_rejected_before_any_registered_generation(tmp_path, monkeypatch):
    supplement.save_new(tmp_path / "group.json", {"evidence_class": "engineering-sentinel"})

    def forbidden(_):
        raise AssertionError("invalid engineering artifact entered formal reconstruction")

    monkeypatch.setattr("dynamic_cssc.r1_supplement_analysis.registered_workload", forbidden)
    with pytest.raises(ValueError, match="group identity"):
        inspect_group(tmp_path, {"group": 0}, {"source_sha": "f" * 40})


def test_complete_groups_only_and_raw_repeats_not_pooled():
    rows = [
        {
            "group": 0,
            "strategy": strategy,
            "repetition": repeat,
            "metrics": dict.fromkeys(METRICS, 10 + repeat + i),
        }
        for i, strategy in enumerate(("repack", "padding", "strong"))
        for repeat in range(3)
    ]
    result = descriptive_tables(rows)[0]["statistics"]
    assert result["strong"]["whole_process_ns"]["paired_difference_to_repack"] == 2
    assert result["repack"]["whole_process_ns"] == {"median": 11, "min": 10, "max": 12}
    with pytest.raises(ValueError, match="complete nine-trace"):
        descriptive_tables(rows[:-1])
    duplicate = deepcopy(rows)
    duplicate[-1] = duplicate[0]
    with pytest.raises(ValueError, match="complete nine-trace"):
        descriptive_tables(duplicate)


def test_complete_fake_group_inventory_and_mutation_rejection(tmp_path, monkeypatch):
    from dynamic_cssc.r1_workloads import balanced_strategy_order

    group, identity = {"group": 0, "test-only": True}, {"source_sha": "f" * 40}
    executions = []
    for repetition in range(3):
        for strategy in balanced_strategy_order(0, repetition):
            name = f"repeat-{repetition}-{strategy}"
            folder = tmp_path / name
            folder.mkdir()
            workload, summary, events = fake_trace_fixture(folder)
            summary["campaign"] = {**identity, **group, "repetition": repetition}
            summary["strategy"] = strategy
            events[-1]["strategy"] = strategy
            (folder / "summary.json").write_bytes(canonical(summary))
            (folder / "events.jsonl").write_bytes(b"\n".join(canonical(e) for e in events) + b"\n")
            (folder / "native-stderr.log").touch()
            executions.append({"name": name, "repetition": repetition, "strategy": strategy})
    files = {
        str(p.relative_to(tmp_path)): {"sha256": supplement.file_hash(p), "bytes": p.stat().st_size}
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    record = {
        "schema_version": "r1-supplement-group-v1",
        "evidence_class": supplement.CLASS,
        "campaign": {**identity, **group},
        "status": "pass",
        "executions": executions,
        "files": files,
        "environment": {
            "cpu_model": "test-only",
            "openfhe_library_sha256": {"fake": "a" * 64},
            "native_binary_sha256": "b" * 64,
            "python": "3.12.13",
            "omp_num_threads": 1,
            "openblas_num_threads": 1,
        },
    }
    supplement.save_new(tmp_path / "group.json", record)
    monkeypatch.setattr(
        "dynamic_cssc.r1_supplement_analysis.registered_workload", lambda _: workload
    )
    assert len(inspect_group(tmp_path, group, identity)) == 9
    first = tmp_path / executions[0]["name"] / "summary.json"
    broken = json.loads(first.read_bytes())
    broken["whole_process_ns"] += 1
    first.write_bytes(canonical(broken))
    with pytest.raises(ValueError, match="digest/size"):
        inspect_group(tmp_path, group, identity)
