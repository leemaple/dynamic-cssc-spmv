from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import stat
import zipfile
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.mask_ledger import PreparedF1MCommitmentError
from dynamic_cssc.ordinary_query_lifecycle import OrdinaryQueryLifecycleError
from dynamic_cssc.route_a_artifacts import (
    RouteAArtifactError,
    inspect_route_a_synthetic_cell_archive,
    produce_route_a_synthetic_cell_archive,
)
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_evaluation import (
    RouteAEvaluationError,
    evaluate_route_a_synthetic_cell,
)
from dynamic_cssc.route_a_guard import guard_route_a_synthetic_replay
from dynamic_cssc.route_a_replay import (
    RouteAReplayError,
    RouteASyntheticCellTarget,
    produce_route_a_synthetic_replay_archive,
    replay_route_a_synthetic_cell,
)
from dynamic_cssc.route_a_results import (
    ROUTE_A_MACHINE_PLAN_SHA256,
    canonical_route_a_document,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _repack_private_handoff_with_extra_commitment(
    archive_bytes: bytes,
    *,
    ledger_path: Path,
    under_existing_batch: bool,
) -> bytes:
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as source:
        ordered_names = tuple(source.namelist())
        members = {name: source.read(name) for name in ordered_names}

    ledger_path.write_bytes(members["private/mask-ledger.sqlite3"])
    connection = sqlite3.connect(ledger_path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        if under_existing_batch:
            existing = connection.execute(
                "SELECT commitment_token FROM prepared_f1m_batches "
                "ORDER BY commitment_token LIMIT 1"
            ).fetchone()
            if existing is None:  # pragma: no cover - producer owns at least one query
                raise AssertionError("producer ledger did not contain a commitment batch")
            commitment_token = existing[0]
            component_id = "offline-extra-component"
            output_block_id = "offline-extra-block"
        else:
            commitment_token = "f" * 64
            component_id = "offline-orphan-component"
            output_block_id = "offline-orphan-block"
        connection.execute(
            """
            INSERT INTO prepared_f1m_commitments (
                commitment_token,
                component_id,
                output_block_id,
                kind,
                value_count,
                values_digest
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                commitment_token,
                component_id,
                output_block_id,
                "random-zero-sum",
                1,
                "0" * 64,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    forged_ledger = ledger_path.read_bytes()
    members["private/mask-ledger.sqlite3"] = forged_ledger

    manifest = json.loads(members["manifest.json"])
    manifest["ledger_snapshot_sha256"] = hashlib.sha256(forged_ledger).hexdigest()
    for member in manifest["members"]:
        if member["path"] == "private/mask-ledger.sqlite3":
            member["byte_count"] = len(forged_ledger)
            member["sha256"] = hashlib.sha256(forged_ledger).hexdigest()
    members["manifest.json"] = canonical_route_a_document(manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as forged:
        for name in ordered_names:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            forged.writestr(info, members[name])
    return buffer.getvalue()


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_synthetic_cell_executes_every_query_and_separates_private_replay_material(
    candidate_id: str,
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    scratch = tmp_path / candidate_id.split("/", 1)[0]
    scratch.mkdir()

    run = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id=candidate_id,
        rho=Fraction(1, 100),
        shard_identity_sha256=hashlib.sha256(b"route-a-test-shard").hexdigest(),
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=scratch,
    )

    document = run.cell.document
    assert document["identity"]["strategy_candidate_id"] == candidate_id
    assert document["identity"]["rho"] == "1/100"
    assert document["counts"]["updates"] == 512
    assert document["counts"]["queries"] == 5
    assert sum(document["window_query_counts"]) == 5
    assert document["correctness"] == {
        "binding_acceptance": True,
        "claim_authority": False,
        "execution_performed": True,
        "oracle_equality": True,
        "source_rho": None,
    }
    assert document["bindings"]["machine_plan_sha256"] == (
        ROUTE_A_MACHINE_PLAN_SHA256
    )
    assert len(run.query_identity_documents) == 5
    assert len(run.preparation_digest_documents) == 5
    assert len(run.consumption_receipt_documents) == 5
    assert len(run.output_digest_documents) == 5
    assert len(run.private_preparation_documents) == 5
    assert run.window_trace_sha256 == hashlib.sha256(run.window_trace_bytes).hexdigest()
    assert run.ledger_snapshot_sha256 == hashlib.sha256(
        run.ledger_snapshot_bytes
    ).hexdigest()

    redacted = b"".join(
        (
            *run.query_identity_documents,
            *run.preparation_digest_documents,
            *run.consumption_receipt_documents,
            *run.output_digest_documents,
        )
    )
    assert b'"values"' not in redacted
    assert b'"vector"' not in redacted
    assert b'"mask"' not in redacted
    assert b'"values"' in b"".join(run.private_preparation_documents)
    assert run.scratch_high_water_bytes > 0


def test_synthetic_cell_archive_is_deterministic_private_non_evidence_handoff(
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    run = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=hashlib.sha256(b"route-a-archive-shard").hexdigest(),
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=scratch,
    )

    first = produce_route_a_synthetic_cell_archive(run)
    second = produce_route_a_synthetic_cell_archive(run)
    inspection = inspect_route_a_synthetic_cell_archive(first)

    assert first == second
    assert inspection.cell_run == run
    assert inspection.archive_sha256 == hashlib.sha256(first).hexdigest()

    source = zipfile.ZipFile(io.BytesIO(first))
    members = {name: source.read(name) for name in source.namelist()}
    manifest = json.loads(members["manifest.json"])
    assert manifest["private_preparation_bytes_included"] is True
    assert manifest["formal_evidence"] is False
    assert manifest["authority_granted"] is False
    assert manifest["retention_days"] == 1
    assert manifest["producer_timing_scope"].endswith(
        "accounting-before-cell-serialization"
    )
    assert manifest["scratch_observation_scope"].startswith(
        "allocated-st_blocks-times-512"
    )
    assert members["private/mask-ledger.sqlite3"] == run.ledger_snapshot_bytes
    assert b'"values"' in members["private/preparation-records.bin"]
    redacted_members = b"".join(
        members[name]
        for name in (
            "cell.json",
            "streams/consumption-receipts.jsonl",
            "streams/output-digests.jsonl",
            "streams/preparation-digests.jsonl",
            "streams/query-identities.jsonl",
            "window-trace.json",
        )
    )
    assert b'"values"' not in redacted_members
    assert b'"vector"' not in redacted_members
    members["streams/output-digests.jsonl"] = members[
        "streams/output-digests.jsonl"
    ].replace(b'"typed_output_sha256"', b'"typed_output_sha256_x"', 1)
    forged_buffer = io.BytesIO()
    with zipfile.ZipFile(forged_buffer, "w") as forged:
        for name, content in members.items():
            forged.writestr(name, content)
    with pytest.raises(RouteAArtifactError):
        inspect_route_a_synthetic_cell_archive(forged_buffer.getvalue())


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_synthetic_cell_replay_is_exact_read_only_and_preserves_producer_costs(
    candidate_id: str,
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    producer_scratch = tmp_path / "producer"
    replay_scratch = tmp_path / "replay"
    producer_scratch.mkdir()
    replay_scratch.mkdir()
    shard_sha256 = hashlib.sha256(b"route-a-replay-shard").hexdigest()
    producer = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id=candidate_id,
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=producer_scratch,
    )
    archive_bytes = produce_route_a_synthetic_cell_archive(producer)
    expected_target = RouteASyntheticCellTarget.for_synthetic_trace(
        trace,
        strategy_candidate_id=candidate_id,
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=0,
    )

    replay = replay_route_a_synthetic_cell(
        trace,
        archive_bytes=archive_bytes,
        expected_target=expected_target,
        machine_plan_bytes=plan_bytes,
        scratch_directory=replay_scratch,
    )

    assert producer.cell.document["measurements"]["replay_seconds"] is None
    producer_document = producer.cell.document
    final_document = replay.final_cell.document
    producer_measurements = producer_document["measurements"]
    final_measurements = final_document["measurements"]
    assert final_measurements["replay_seconds"] is not None
    assert {
        key: value for key, value in final_measurements.items() if key != "replay_seconds"
    } == {
        key: value for key, value in producer_measurements.items() if key != "replay_seconds"
    }
    assert replay.replay_run.query_identity_documents == (
        producer.query_identity_documents
    )
    assert replay.replay_run.output_digest_documents == producer.output_digest_documents
    assert replay.replay_run.preparation_digest_documents == (
        producer.preparation_digest_documents
    )
    assert replay.replay_run.consumption_receipt_documents == (
        producer.consumption_receipt_documents
    )
    assert replay.replay_run.private_preparation_documents == (
        producer.private_preparation_documents
    )
    assert replay.replay_run.ledger_snapshot_bytes == producer.ledger_snapshot_bytes
    assert (replay_scratch / "mask-ledger.sqlite3").read_bytes() == (
        producer.ledger_snapshot_bytes
    )
    assert replay.receipt["producer_cell_sha256"] == producer.cell.sha256
    assert replay.receipt["final_cell_sha256"] == replay.final_cell.sha256
    assert replay.receipt["formal_authority_granted"] is False
    assert replay.receipt["ledger_snapshot_read_only_verified"] is True
    assert replay.receipt["producer_ledger_snapshot_sha256"] == (
        producer.ledger_snapshot_sha256
    )
    assert replay.receipt["replay_ledger_snapshot_sha256"] == (
        producer.ledger_snapshot_sha256
    )
    assert replay.receipt["expected_target_sha256"] == expected_target.sha256
    assert replay.receipt["replay_timing_scope"] == (
        "function-entry-through-inspection-rehash-read-only-ledger-verification-"
        "typed-reexecution-oracle-and-final-comparison-before-receipt-serialization"
    )
    assert replay.receipt_sha256 == hashlib.sha256(replay.receipt_bytes).hexdigest()
    assert b'"values"' not in replay.receipt_bytes
    assert b'"vector"' not in replay.receipt_bytes

    replay_archive = produce_route_a_synthetic_replay_archive(replay)
    guard = guard_route_a_synthetic_replay(
        producer_archive_bytes=archive_bytes,
        replay_archive_bytes=replay_archive,
        expected_target=expected_target,
    )
    assert guard.receipt["accepted"] is True
    assert guard.receipt["formal_authority_granted"] is False
    assert guard.receipt["expected_target_sha256"] == expected_target.sha256
    assert guard.receipt["final_cell_sha256"] == replay.final_cell.sha256
    assert guard.receipt_sha256 == hashlib.sha256(guard.receipt_bytes).hexdigest()
    assert b'"values"' not in guard.receipt_bytes
    assert b'"vector"' not in guard.receipt_bytes


@pytest.mark.parametrize(
    ("under_existing_batch", "expected_error", "error_match", "cause_match"),
    (
        pytest.param(
            False,
            PreparedF1MCommitmentError,
            "foreign-key|commitment rows",
            None,
            id="orphan-token",
        ),
        pytest.param(
            True,
            OrdinaryQueryLifecycleError,
            "read-only replay ledger verification failed",
            "operands differ from the consumed ledger",
            id="existing-token-extra-row",
        ),
    ),
)
def test_replay_rejects_an_offline_extra_commitment_in_a_resealed_handoff(
    under_existing_batch: bool,
    expected_error: type[Exception],
    error_match: str,
    cause_match: str | None,
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    producer_scratch = tmp_path / "producer"
    replay_scratch = tmp_path / "replay"
    producer_scratch.mkdir()
    replay_scratch.mkdir()
    shard_sha256 = hashlib.sha256(b"route-a-orphan-ledger-shard").hexdigest()
    producer = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=producer_scratch,
    )
    forged_archive = _repack_private_handoff_with_extra_commitment(
        produce_route_a_synthetic_cell_archive(producer),
        ledger_path=tmp_path / "forged-ledger.sqlite3",
        under_existing_batch=under_existing_batch,
    )
    expected_target = RouteASyntheticCellTarget.for_synthetic_trace(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=0,
    )

    with pytest.raises(expected_error, match=error_match) as caught:
        replay_route_a_synthetic_cell(
            trace,
            archive_bytes=forged_archive,
            expected_target=expected_target,
            machine_plan_bytes=plan_bytes,
            scratch_directory=replay_scratch,
        )
    if cause_match is not None:
        assert isinstance(caught.value.__cause__, PreparedF1MCommitmentError)
        assert cause_match in str(caught.value.__cause__)


def test_private_replay_material_rejects_omission_reordering_and_duplication(
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    scratch = tmp_path / "producer"
    scratch.mkdir()
    producer = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=hashlib.sha256(b"route-a-splice-shard").hexdigest(),
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=scratch,
    )

    with pytest.raises(RouteAEvaluationError):
        replace(
            producer,
            private_preparation_documents=producer.private_preparation_documents[:-1],
        )
    with pytest.raises(RouteAEvaluationError):
        replace(
            producer,
            private_preparation_documents=tuple(
                reversed(producer.private_preparation_documents)
            ),
        )
    with pytest.raises(RouteAEvaluationError):
        replace(
            producer,
            private_preparation_documents=(
                producer.private_preparation_documents[0],
                *producer.private_preparation_documents[:-1],
            ),
        )


def test_replay_requires_an_external_exact_target_and_attempts_never_reuse_ids(
    tmp_path: Path,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    shard_sha256 = hashlib.sha256(b"route-a-target-shard").hexdigest()
    scratch = tmp_path / "producer"
    replay_scratch = tmp_path / "replay"
    scratch.mkdir()
    replay_scratch.mkdir()
    producer = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan_bytes,
        scratch_directory=scratch,
    )
    wrong_target = RouteASyntheticCellTarget.for_synthetic_trace(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256=shard_sha256,
        unit_attempt_ordinal=1,
    )

    with pytest.raises(RouteAReplayError, match="expected target"):
        replay_route_a_synthetic_cell(
            trace,
            archive_bytes=produce_route_a_synthetic_cell_archive(producer),
            expected_target=wrong_target,
            machine_plan_bytes=plan_bytes,
            scratch_directory=replay_scratch,
        )

    nominal = RouteAEvaluationLane.simulator(
        shard_identity_sha256=shard_sha256,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        unit_attempt_ordinal=0,
    )
    replacement = RouteAEvaluationLane.simulator(
        shard_identity_sha256=shard_sha256,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        unit_attempt_ordinal=1,
    )
    assert nominal.query_identity(0).query_id != replacement.query_identity(0).query_id
