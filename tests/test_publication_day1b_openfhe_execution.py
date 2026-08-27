from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_authority as day2_authority
import dynamic_cssc.day2_openfhe_key_plan as day2_key_plan
from dynamic_cssc.day1_registry import RegisteredCandidate
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runtime import OpenFHEQueryRuntimeError
from dynamic_cssc.publication_day1b_accounting import Day1BAccountingDomain
from dynamic_cssc.publication_day1b_openfhe_execution import (
    DAY1B_REPRESENTATIVE_OPENFHE_RECEIPT_SCHEMA,
    Day1BRepresentativeOpenFHEError,
    execute_day1b_representative_openfhe_query,
)
from dynamic_cssc.publication_day1b_replay_execution import (
    Day1BReplayExecutionError,
    claim_day1b_candidate_replay_capability,
    replay_and_seal_publication_day1b_candidate,
)
from dynamic_cssc.publication_schedule import (
    ExactPublicationWindow,
    ScheduledNetUpdate,
)
from dynamic_cssc.publication_traces import PUBLICATION_QUERY_VECTOR_SCHEMA

ROOT = Path(__file__).resolve().parents[1]
RUNNER_RELATIVE_PATH = "build/cpp/openfhe_query_runner"


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _query_vector() -> tuple[bytes, str]:
    content = _canonical_line(
        {
            "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
            "values": [1, 1, 0, -1],
        }
    )
    return content, hashlib.sha256(content).hexdigest()


def _window(
    index: int,
    phase: str,
    update: tuple[int, int, int, int],
    *,
    query_count: int,
) -> ExactPublicationWindow:
    return ExactPublicationWindow(
        index=index,
        phase=phase,
        accepted_group_start=index,
        accepted_group_end=index + 1,
        start_time=Fraction(index, 10),
        end_time=Fraction(index + 1, 10),
        set_count=1,
        updates=(ScheduledNetUpdate(*update),),
        query_count=query_count,
        reason="query" if query_count else "phase-boundary:warmup",
    )


def _windows() -> tuple[ExactPublicationWindow, ...]:
    return (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        _window(1, "tuning", (0, 1, 0, 2), query_count=7),
        _window(2, "heldout", (0, 0, 1, 0), query_count=11),
    )


def _candidate_and_domain(
    execution_kind: str,
) -> tuple[RegisteredCandidate, Day1BAccountingDomain]:
    if execution_kind == "ordinary":
        candidate = RegisteredCandidate(
            candidate_id="reserved-slack/beta=0.4",
            strategy="ReservedSlack-CSSC",
            role="reference",
            reserved_slack_beta=Decimal("0.4"),
        )
        effective_slots = 4
        partition_rows = 2
        strong_segment_width = 4
    else:
        candidate = RegisteredCandidate(
            candidate_id="packed-coo-cloud-segmented-delta/segment-width=128",
            strategy="Packed-COO-Cloud-Segmented-Delta",
            role="reference",
            reserved_slack_beta=Decimal("0"),
        )
        effective_slots = 128
        partition_rows = 4
        strong_segment_width = 128
    return candidate, Day1BAccountingDomain(
        rows=4,
        cols=4,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        matrix_value_bound=7,
        max_row_nnz=4,
        strong_segment_width=strong_segment_width,
    )


def _replay_capability(execution_kind: str):
    candidate, domain = _candidate_and_domain(execution_kind)
    content, digest = _query_vector()
    _accounting, capability = replay_and_seal_publication_day1b_candidate(
        candidate=candidate,
        windows=_windows(),
        domain=domain,
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
    )
    return capability


def _day2_key_plan_capability(execution_kind: str):
    indices = (2,) if execution_kind == "ordinary" else (1, 2, 4, 8, 16, 32, 64)
    content = _canonical_line(
        {
            "composite_decompositions": [],
            "day1a_authority_receipt_sha256": "6" * 64,
            "day1a_inventory_sha256": "7" * 64,
            "effective_slots": 4096,
            "eval_rotate_case_ids": [f"index={index}" for index in indices],
            "inventory_source_schema_version": (
                "dynamic-cssc-day1a-rotation-inventory-v1"
            ),
            "key_plan_kind": "direct-exact-index-v1",
            "planned_exact_indices": list(indices),
            "required_exact_indices": list(indices),
            "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        }
    )
    authority = day2_authority._mint_repository_calibration_authority(
        source_git_sha="1" * 40,
        outer_archive_sha256="2" * 64,
        raw_measurement_blocks_sha256="3" * 64,
        calibration_projection_sha256="4" * 64,
        rotation_key_plan_sha256=hashlib.sha256(content).hexdigest(),
        serialized_object_size_profile_sha256="5" * 64,
        ciphertext_bytes=100,
        f1m_random_zero_sum_ciphertext_bytes=101,
        f1m_encrypted_zero_dummy_ciphertext_bytes=102,
        serialized_rotation_key_inventory_bytes=103,
        serialized_eval_mult_key_bytes=104,
    )
    return day2_key_plan._issue_from_day2_authority(authority, content)


@pytest.mark.parametrize("execution_kind", ("ordinary", "strong"))
def test_real_runtime_composes_replay_plan_and_payload_receipts(
    tmp_path: Path,
    execution_kind: str,
) -> None:
    if not (ROOT / RUNNER_RELATIVE_PATH).is_file():
        pytest.skip("the real OpenFHE query runner has not been built")
    replay_capability = _replay_capability(execution_kind)
    key_plan_capability = _day2_key_plan_capability(execution_kind)
    scratch = tmp_path.resolve() / f"{execution_kind}-representative-runtime"

    executed = execute_day1b_representative_openfhe_query(
        candidate_replay_capability=replay_capability,
        day2_key_plan_capability=key_plan_capability,
        ledger=SQLiteMaskBindingLedger(
            tmp_path / f"{execution_kind}-representative-ledger.sqlite3"
        ),
        repository_root=ROOT,
        runner_relative_path=RUNNER_RELATIVE_PATH,
        scratch_root=scratch,
        timeout_seconds=300,
        resident_memory_limit_bytes=4 * 1024**3,
        scratch_limit_bytes=2 * 1024**3,
    )

    document = executed.receipt.to_document()
    assert document["schema_version"] == DAY1B_REPRESENTATIVE_OPENFHE_RECEIPT_SCHEMA
    assert document["representative_openfhe_execution_verified"] is True
    assert document["candidate_replay_continuity_verified"] is True
    assert document["anchored_day2_key_plan_verified"] is True
    assert document["runtime_receipt"]["execution_kind"] == execution_kind
    assert document["runtime_receipt"]["anchored_day2_key_plan_verified"] is True
    assert document["replay_execution_receipt"]["openfhe_execution_verified"] is False
    assert executed.openfhe_execution.verified_result.reconstructed_output == (3, 0, 0, 0)
    assert document["serialized_payload_count"] == len(
        executed.openfhe_execution.serialized_payloads
    )
    assert document["serialized_payload_count"] > 0
    assert document["serialized_payload_bytes"] > 0
    for denied in (
        "complete_cost_claim_allowed",
        "formal_authority_granted",
        "heldout_dispatch_authorized",
        "performance_claim_allowed",
        "production_execution_admissible",
        "publication_authority",
        "security_claim_allowed",
    ):
        assert document[denied] is False
    assert replay_capability._binding is None
    assert key_plan_capability._binding is None
    assert not scratch.exists()

    with pytest.raises(Day1BRepresentativeOpenFHEError, match="diverged"):
        replace(executed.receipt, query_id="retargeted-query")


def test_prelaunch_failure_consumes_both_private_capabilities(
    tmp_path: Path,
) -> None:
    replay_capability = _replay_capability("ordinary")
    key_plan_capability = _day2_key_plan_capability("ordinary")
    occupied_scratch = tmp_path.resolve() / "occupied-runtime-scratch"
    occupied_scratch.mkdir()

    with pytest.raises(OpenFHEQueryRuntimeError, match="absent path"):
        execute_day1b_representative_openfhe_query(
            candidate_replay_capability=replay_capability,
            day2_key_plan_capability=key_plan_capability,
            ledger=SQLiteMaskBindingLedger(tmp_path / "failed-ledger.sqlite3"),
            repository_root=ROOT,
            runner_relative_path=RUNNER_RELATIVE_PATH,
            scratch_root=occupied_scratch,
            timeout_seconds=300,
            resident_memory_limit_bytes=4 * 1024**3,
            scratch_limit_bytes=2 * 1024**3,
        )

    assert replay_capability._binding is None
    assert key_plan_capability._binding is None
    with pytest.raises(Day1BReplayExecutionError, match="absent or consumed"):
        claim_day1b_candidate_replay_capability(replay_capability)
    with pytest.raises(day2_key_plan.Day2OpenFHEKeyPlanError, match="absent or consumed"):
        day2_key_plan.claim_day2_openfhe_key_plan(key_plan_capability)


def test_replay_claim_failure_abandons_the_paired_key_plan(tmp_path: Path) -> None:
    replay_capability = _replay_capability("ordinary")
    claim_day1b_candidate_replay_capability(replay_capability)
    key_plan_capability = _day2_key_plan_capability("ordinary")

    with pytest.raises(Day1BReplayExecutionError, match="absent or consumed"):
        execute_day1b_representative_openfhe_query(
            candidate_replay_capability=replay_capability,
            day2_key_plan_capability=key_plan_capability,
            ledger=SQLiteMaskBindingLedger(tmp_path / "unused-ledger.sqlite3"),
            repository_root=ROOT,
            runner_relative_path=RUNNER_RELATIVE_PATH,
            scratch_root=tmp_path.resolve() / "unused-runtime-scratch",
            timeout_seconds=300,
            resident_memory_limit_bytes=4 * 1024**3,
            scratch_limit_bytes=2 * 1024**3,
        )

    assert key_plan_capability._binding is None
    with pytest.raises(day2_key_plan.Day2OpenFHEKeyPlanError, match="absent or consumed"):
        day2_key_plan.claim_day2_openfhe_key_plan(key_plan_capability)
