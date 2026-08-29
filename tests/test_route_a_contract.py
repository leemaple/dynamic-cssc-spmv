from __future__ import annotations

from fractions import Fraction

import pytest

from dynamic_cssc.route_a_contract import (
    RouteAEvaluationLane,
    RouteAQueryVectorDomain,
    generate_route_a_query_vector,
    route_a_query_batch_counts,
)


def test_synthetic_query_vector_matches_the_preregistered_known_answer() -> None:
    vector = generate_route_a_query_vector(
        RouteAQueryVectorDomain.formal_synthetic(scale="S", formal_seed=20260822)
    )

    assert vector.domain_sha256 == (
        "0a255c3005a21763f729d0ea03735ae6ba0536fd31dd32a12e33a63bfef06c6f"
    )
    assert vector.vector_sha256 == (
        "645f28ff14197d9b87c20153316d898783c21ead0aff7e40d31f4f2223e34eaf"
    )
    assert vector.values[:16] == (1, 1, 1, 1, -1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1)
    assert vector.values[-16:] == (1, -1, 0, 0, -1, 1, 1, 1, -1, 1, 1, 0, -1, 0, -1, -1)
    assert tuple(vector.values.count(value) for value in (-1, 0, 1)) == (2688, 2769, 2736)


def test_qualification_query_vector_domain_accepts_only_its_registered_scope() -> None:
    domain = RouteAQueryVectorDomain.qualification_synthetic(
        scale="M",
        qualification_seed=20260821,
    )

    assert domain.to_document()["formal_seed"] == 20260821
    assert domain.suite_role == "qualification"
    with pytest.raises(ValueError, match="qualification"):
        RouteAQueryVectorDomain.qualification_synthetic(
            scale="M",
            qualification_seed=20260822,
        )
    with pytest.raises(ValueError, match="qualification"):
        RouteAQueryVectorDomain.qualification_synthetic(
            scale="S",
            qualification_seed=20260821,
        )


def test_formal_query_vector_domain_rejects_the_qualification_seed() -> None:
    domain = RouteAQueryVectorDomain.formal_synthetic(
        scale="M",
        formal_seed=20260822,
    )

    assert domain.suite_role == "formal"
    with pytest.raises(ValueError, match="formal"):
        RouteAQueryVectorDomain.formal_synthetic(
            scale="M",
            formal_seed=20260821,
        )


def test_snap_query_vector_binds_raw_object_mapping_partition_and_semantics() -> None:
    vector = generate_route_a_query_vector(
        RouteAQueryVectorDomain.snap_a2q(
            object_sha256="a" * 64,
            mapping_sha256="b" * 64,
            partition=0,
            semantics="T1",
        )
    )

    assert vector.domain_sha256 == (
        "4fe6abe966b831861cf62a00952e1a19af0c8647d037db22c74e34f0e7b3ae25"
    )
    assert vector.vector_sha256 == (
        "66e7658c1729c91b20d9eb15cd8683015906d8ca1e34bededbd95ce75fede570"
    )
    assert vector.values[:8] == (1, -1, 0, 0, -1, 0, 1, 0)
    assert vector.values[-8:] == (1, 1, 1, 0, 1, 1, -1, -1)


def test_query_schedule_uses_the_exact_floor_difference_per_group() -> None:
    counts = route_a_query_batch_counts(20, Fraction(1, 10))

    assert counts == (0, 0, 0, 0, 0, 0, 0, 0, 0, 1) * 2
    assert sum(counts) == 2


def test_simulator_lane_and_query_id_match_known_canonical_digests() -> None:
    lane = RouteAEvaluationLane.simulator(
        shard_identity_sha256="a" * 64,
        strategy_candidate_id="padding-reuse",
        rho=Fraction(1, 10),
        unit_attempt_ordinal=0,
    )
    query = lane.query_identity(0)

    assert lane.sha256 == "beb89b705ec3b5efc14ccaefde3cef00e62a1d45c120f03c82e0e434cfcf96a7"
    assert query.query_id == "8556daa27eb8980faf081a23700dfdb63e9c92fcf8142d876351f49682e97ada"


def test_openfhe_lanes_close_warmup_and_three_recorded_process_namespaces() -> None:
    common = {
        "shard_identity_sha256": "b" * 64,
        "strategy_candidate_id": "packed-coo-cloud-segmented-delta/segment-width=128",
        "rho": Fraction(1),
        "unit_attempt_ordinal": 0,
    }
    warmup = RouteAEvaluationLane.openfhe_warmup(**common)
    recorded = tuple(
        RouteAEvaluationLane.openfhe_recorded(
            **common,
            process_ordinal=ordinal,
        )
        for ordinal in range(3)
    )

    assert warmup.to_document()["execution_process_role"] == "openfhe-warmup"
    assert warmup.to_document()["process_ordinal_or_null"] == 0
    assert tuple(lane.to_document()["process_ordinal_or_null"] for lane in recorded) == (
        0,
        1,
        2,
    )
    assert len({warmup.sha256, *(lane.sha256 for lane in recorded)}) == 4
    lane_query_ids = {
        warmup.query_identity(0).query_id,
        *(lane.query_identity(0).query_id for lane in recorded),
    }
    assert len(lane_query_ids) == 4
    with pytest.raises(ValueError, match="closed identity"):
        RouteAEvaluationLane.openfhe_recorded(**common, process_ordinal=3)


@pytest.mark.parametrize("ordinal", [True, False])
def test_openfhe_recorded_lane_rejects_boolean_ordinal(ordinal: bool) -> None:
    with pytest.raises(ValueError, match="closed identity"):
        RouteAEvaluationLane(
            shard_identity_sha256="b" * 64,
            strategy_candidate_id="padding-reuse",
            rho=Fraction(1),
            unit_attempt_ordinal=0,
            execution_process_role="openfhe-recorded",
            process_ordinal_or_null=ordinal,
        )
