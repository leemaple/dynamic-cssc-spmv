from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.route_a_contract import (
    RouteAQueryVectorDomain,
    generate_route_a_query_vector,
)
from dynamic_cssc.route_a_evaluation import (
    RouteAEvaluationError,
    evaluate_route_a_synthetic_cell,
    replay_route_a_synthetic_cell_read_only,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_workloads import (
    generate_route_a_formal_trace,
    generate_route_a_qualification_trace,
    validate_route_a_synthetic_trace,
)

SENTINEL_PLAN_BYTES = b'{"sentinel_plan":true}\n'
SENTINEL_PROFILE = RouteAScientificProfile(
    profile_id="sentinel-only-stage2-test",
    qualification_seed=19_990_101,
    formal_seeds=(19_990_102, 19_990_103, 19_990_104),
    query_vector_seed=1_999_010_202,
    machine_plan_sha256=hashlib.sha256(SENTINEL_PLAN_BYTES).hexdigest(),
)


def test_one_profile_owns_workload_query_vector_and_plan_binding() -> None:
    trace = generate_route_a_qualification_trace(
        scale="M",
        qualification_seed=SENTINEL_PROFILE.qualification_seed,
        scientific_profile=SENTINEL_PROFILE,
    )
    vector = generate_route_a_query_vector(
        RouteAQueryVectorDomain.qualification_synthetic(
            scale="M",
            qualification_seed=SENTINEL_PROFILE.qualification_seed,
            scientific_profile=SENTINEL_PROFILE,
        )
    )

    assert validate_route_a_synthetic_trace(
        trace,
        scientific_profile=SENTINEL_PROFILE,
    ) is trace
    assert vector.suite_role == "qualification"
    assert vector.values[0] == 1
    assert vector.values[-1] == -1
    assert json.loads(vector.domain_bytes)["seed"] == SENTINEL_PROFILE.query_vector_seed
    SENTINEL_PROFILE.require_machine_plan_bytes(SENTINEL_PLAN_BYTES)


def test_cross_profile_trace_and_plan_substitution_fail_before_execution(tmp_path: Path) -> None:
    trace = generate_route_a_formal_trace(
        scale="S",
        formal_seed=SENTINEL_PROFILE.formal_seeds[0],
        scientific_profile=SENTINEL_PROFILE,
    )
    foreign_profile = RouteAScientificProfile(
        profile_id="foreign-sentinel-only",
        qualification_seed=19_980_101,
        formal_seeds=(19_980_102, 19_980_103, 19_980_104),
        query_vector_seed=1_998_010_202,
        machine_plan_sha256="f" * 64,
    )

    with pytest.raises(ValueError, match="formal trace scope"):
        validate_route_a_synthetic_trace(trace, scientific_profile=foreign_profile)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(RouteAEvaluationError, match="machine plan bytes"):
        evaluate_route_a_synthetic_cell(
            trace,
            strategy_candidate_id="padding-reuse",
            rho=Fraction(1, 100),
            shard_identity_sha256="a" * 64,
            unit_attempt_ordinal=0,
            machine_plan_bytes=b"foreign",
            scratch_directory=scratch,
            scientific_profile=SENTINEL_PROFILE,
        )
    assert list(scratch.iterdir()) == []


def test_sentinel_profile_runs_same_producer_and_read_only_replay_seam(tmp_path: Path) -> None:
    trace = generate_route_a_formal_trace(
        scale="S",
        formal_seed=SENTINEL_PROFILE.formal_seeds[0],
        scientific_profile=SENTINEL_PROFILE,
    )
    producer_scratch = tmp_path / "producer"
    replay_scratch = tmp_path / "replay"
    producer_scratch.mkdir()
    replay_scratch.mkdir()

    producer = evaluate_route_a_synthetic_cell(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256="b" * 64,
        unit_attempt_ordinal=0,
        machine_plan_bytes=SENTINEL_PLAN_BYTES,
        scratch_directory=producer_scratch,
        scientific_profile=SENTINEL_PROFILE,
    )
    replay = replay_route_a_synthetic_cell_read_only(
        trace,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 100),
        shard_identity_sha256="b" * 64,
        unit_attempt_ordinal=0,
        machine_plan_bytes=SENTINEL_PLAN_BYTES,
        scratch_directory=replay_scratch,
        private_preparation_documents=producer.private_preparation_documents,
        ledger_snapshot_bytes=producer.ledger_snapshot_bytes,
        scientific_profile=SENTINEL_PROFILE,
    )

    assert producer.cell.document["bindings"]["machine_plan_sha256"] == (
        SENTINEL_PROFILE.machine_plan_sha256
    )
    assert replay.cell.document["bindings"]["machine_plan_sha256"] == (
        SENTINEL_PROFILE.machine_plan_sha256
    )
    assert replay.cell.document["counts"] == producer.cell.document["counts"]
    assert replay.cell.document["primitive_counts"] == producer.cell.document[
        "primitive_counts"
    ]
    assert replay.output_digest_documents == producer.output_digest_documents
    assert replay.ledger_snapshot_bytes == producer.ledger_snapshot_bytes


@pytest.mark.parametrize(
    "formal_seeds",
    [
        (19_990_102, 19_990_102, 19_990_104),
        (19_990_101, 19_990_103, 19_990_104),
    ],
)
def test_profile_rejects_overlapping_or_duplicate_seed_domains(
    formal_seeds: tuple[int, int, int],
) -> None:
    with pytest.raises(ValueError, match="closed scalar domain"):
        RouteAScientificProfile(
            profile_id="invalid-sentinel",
            qualification_seed=19_990_101,
            formal_seeds=formal_seeds,
            query_vector_seed=1_999_010_202,
            machine_plan_sha256="e" * 64,
        )
