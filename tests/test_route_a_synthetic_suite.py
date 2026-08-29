from __future__ import annotations

import hashlib
import os
import shutil
import threading
import zipfile
from fractions import Fraction
from pathlib import Path

import dynamic_cssc.route_a_qualification_runtime as runtime_module
import dynamic_cssc.route_a_synthetic_suite as suite_module
from dynamic_cssc.route_a_qualification_runtime import (
    inspect_route_a_qualification_stage_artifact,
    route_a_stage_observer,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    inspect_route_a_synthetic_suite_handoff,
    inspect_route_a_synthetic_suite_replay,
    produce_route_a_synthetic_suite_handoff,
    replay_and_guard_route_a_synthetic_suite,
)
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=12345,
        provider_run_attempt=1,
    )


def _wrap_stage_artifact(
    *,
    stage: str,
    payload_path: Path,
    output: Path,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    output.mkdir()
    target_name = runtime_module._STAGE_PAYLOAD[stage]
    target = output / target_name
    shutil.copyfile(payload_path, target)
    payload = target.read_bytes()
    expected_stages = runtime_module._expected_stages(stage)
    ledger = canonical_route_a_document(
        {
            "entries": [
                {
                    "observed_monotonic_ns": 100 + ordinal,
                    "scratch_allocated_bytes": ordinal,
                    "sequence": ordinal,
                    "stage": name,
                }
                for ordinal, name in enumerate(expected_stages)
            ],
            "formal_authority_granted": False,
            "peak_scratch_allocated_bytes": len(expected_stages),
            "publication_evidence": False,
            "schema_version": runtime_module._STAGE_LEDGER_SCHEMA,
            "stage": stage,
        }
    )
    process = canonical_route_a_document(
        {
            "command_sha256": "4" * 64,
            "elapsed_nanoseconds": 1,
            "executable_sha256": "5" * 64,
            "formal_authority_granted": False,
            "operating_system": "Linux-test",
            "payload_byte_count": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "peak_rss_kib": 1,
            "peak_scratch_allocated_bytes": len(expected_stages),
            "process_id": 1,
            "process_start_time_ticks": 1,
            "publication_evidence": False,
            "return_code": 0,
            "schema_version": runtime_module._PROCESS_RECEIPT_SCHEMA,
            "scratch_cleanup_verified": True,
            "stage": stage,
            "stderr_byte_count": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_byte_count": 0,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "wait_api": "linux-wait4-ru_maxrss-kib-v1",
        }
    )
    (output / "owned-child-receipt.json").write_bytes(process)
    (output / "stage-ledger.json").write_bytes(ledger)
    manifest = runtime_module._manifest(
        stage=stage,
        lineage=lineage,
        members=(
            (target_name, (hashlib.sha256(payload).hexdigest(), len(payload))),
            ("owned-child-receipt.json", process),
            ("stage-ledger.json", ledger),
        ),
    )
    (output / "manifest.json").write_bytes(manifest)
    checksums = b"".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n".encode("ascii")
        for name, content in (
            (target_name, payload),
            ("owned-child-receipt.json", process),
            ("stage-ledger.json", ledger),
            ("manifest.json", manifest),
        )
    )
    (output / "checksums.sha256").write_bytes(checksums)


def test_suite_matrix_constants_match_the_preregistered_grid() -> None:
    assert suite_module._STRATEGIES == ROUTE_A_STRATEGY_CANDIDATES
    assert (
        Fraction(1, 100),
        Fraction(1, 10),
        Fraction(1),
    ) == suite_module._DIRECT_RHOS


def test_one_cell_suite_round_trips_through_independent_replay_without_private_output(
    monkeypatch,
    tmp_path: Path,
) -> None:
    # Component tests cover every strategy and direct rho.  This package-level
    # test narrows the matrix only to keep the local/CI contract test bounded.
    monkeypatch.setattr(suite_module, "_STRATEGIES", ("padding-reuse",))
    monkeypatch.setattr(suite_module, "_DIRECT_RHOS", (Fraction(1),))
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    lineage = _lineage()
    producer_scratch = tmp_path / "producer-scratch"
    replay_scratch = tmp_path / "replay-scratch"
    producer_scratch.mkdir(mode=0o700)
    replay_scratch.mkdir(mode=0o700)
    producer_path = (tmp_path / "producer.zip").absolute()
    replay_path = (tmp_path / "replay.zip").absolute()

    produce_route_a_synthetic_suite_handoff(
        trace,
        lineage=lineage,
        machine_plan_bytes=plan_bytes,
        scratch_root=producer_scratch.absolute(),
        output_path=producer_path,
    )
    producer = inspect_route_a_synthetic_suite_handoff(
        producer_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=plan_bytes,
    )
    assert len(producer.cell_archives) == 1
    assert len(producer.rho10_cells) == 1
    assert producer.rho10_cells[0].document["identity"]["rho"] == "10"
    assert producer.archive_sha256 == hashlib.sha256(producer_path.read_bytes()).hexdigest()

    replay_and_guard_route_a_synthetic_suite(
        trace,
        lineage=lineage,
        machine_plan_bytes=plan_bytes,
        producer_archive_path=producer_path,
        scratch_root=replay_scratch.absolute(),
        output_path=replay_path,
    )
    replay = inspect_route_a_synthetic_suite_replay(
        replay_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=plan_bytes,
    )

    assert len(replay.final_cells) == 1
    assert len(replay.replay_receipts) == 1
    assert len(replay.guard_receipts) == 1
    assert len(replay.rho10_cells) == 1
    assert replay.final_cells[0].document["measurements"]["replay_seconds"] is not None
    assert replay.rho10_cells[0].document["measurements"] == {
        "native_latency_seconds": None,
        "peak_rss_kib": None,
        "producer_result_assembly_seconds": None,
        "producer_state_transition_seconds": None,
        "replay_seconds": None,
        "scratch_allocated_bytes": None,
    }
    assert not any(producer_scratch.iterdir())
    assert not any(replay_scratch.iterdir())

    with zipfile.ZipFile(replay_path, "r") as archive:
        names = tuple(archive.namelist())
        retained = b"".join(archive.read(name) for name in names)
    assert not any(name.endswith(".zip") for name in names)
    assert b"SQLite format 3" not in retained
    assert b"private-preparations" not in retained
    assert b'"publication_evidence":true' not in retained
    assert b'"formal_authority_granted":true' not in retained

    q1_artifact = (tmp_path / "q1-artifact").absolute()
    q2_artifact = (tmp_path / "q2-artifact").absolute()
    _wrap_stage_artifact(
        stage="q1", payload_path=producer_path, output=q1_artifact, lineage=lineage
    )
    _wrap_stage_artifact(stage="q2", payload_path=replay_path, output=q2_artifact, lineage=lineage)
    q1 = inspect_route_a_qualification_stage_artifact(
        q1_artifact, expected_stage="q1", expected_lineage=lineage
    )
    q2 = inspect_route_a_qualification_stage_artifact(
        q2_artifact, expected_stage="q2", expected_lineage=lineage
    )
    assert q1.payload_sha256 == hashlib.sha256(producer_path.read_bytes()).hexdigest()
    assert q2.payload_sha256 == hashlib.sha256(replay_path.read_bytes()).hexdigest()


def test_stage_observer_waits_for_launcher_sample_acknowledgement() -> None:
    stage_read, stage_write = os.pipe()
    acknowledgement_read, acknowledgement_write = os.pipe()
    observer = route_a_stage_observer(stage_write, acknowledgement_read)
    completed: list[bool] = []

    def invoke() -> None:
        observer("source-trace-validated")
        completed.append(True)

    thread = threading.Thread(target=invoke)
    thread.start()
    event = os.read(stage_read, 4096)
    assert completed == []
    assert event == canonical_route_a_document(
        {
            "schema_version": runtime_module._STAGE_EVENT_SCHEMA,
            "sequence": 0,
            "stage": "source-trace-validated",
        }
    )
    os.write(acknowledgement_write, b"\x06")
    thread.join(timeout=1)
    assert completed == [True]
    for descriptor in (
        stage_read,
        stage_write,
        acknowledgement_read,
        acknowledgement_write,
    ):
        os.close(descriptor)
