from __future__ import annotations

import hashlib
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.route_a_evaluation import evaluate_route_a_synthetic_cell
from dynamic_cssc.route_a_results import ROUTE_A_MACHINE_PLAN_SHA256
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_synthetic_cell_executes_every_query_and_emits_only_redacted_bindings(
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
    assert run.window_trace_sha256 == hashlib.sha256(run.window_trace_bytes).hexdigest()

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
    assert run.scratch_high_water_bytes > 0
