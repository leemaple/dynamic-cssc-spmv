from __future__ import annotations

import hashlib
import json

import pytest

from dynamic_cssc.route_a_workloads import (
    generate_route_a_formal_trace,
    generate_route_a_qualification_trace,
)


def test_s_scale_seed_20260822_matches_the_preregistered_generator() -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)

    assert trace.initial_state_sha256 == (
        "45576775eeb4fde419ab1cc1e3701f958a7087e49997fb101702e21e28bdaf54"
    )
    assert len(trace.initial_nonzeros) == 256 * 8
    assert len(trace.accepted_groups) == 512
    assert [
        (
            group.accepted_ordinal,
            group.transitions[0].row,
            group.transitions[0].column,
            group.transitions[0].before,
            group.transitions[0].after,
            group.transitions[0].cause,
        )
        for group in trace.accepted_groups[:10]
    ] == [
        (0, 255, 3978, 3, 2, "modify"),
        (1, 155, 5792, 7, 6, "modify"),
        (2, 78, 270, 0, 5, "insert"),
        (3, 227, 390, 2, 4, "modify"),
        (4, 95, 2301, 0, 4, "insert"),
        (5, 101, 3992, 4, 3, "modify"),
        (6, 57, 4122, 4, 6, "modify"),
        (7, 60, 3685, 0, 3, "insert"),
        (8, 32, 5683, 0, 2, "insert"),
        (9, 140, 5310, 0, 5, "insert"),
    ]
    assert trace.accepted_groups[-1].logical_time_numerator == 511
    assert trace.accepted_groups[-1].logical_time_denominator == 100


def test_qualification_trace_accepts_only_its_registered_scope() -> None:
    trace = generate_route_a_qualification_trace(
        scale="M",
        qualification_seed=20260821,
    )

    assert trace.formal_seed == 20260821
    assert trace.suite_role == "qualification"
    assert len(trace.accepted_groups) == 2048
    with pytest.raises(ValueError, match="qualification"):
        generate_route_a_qualification_trace(
            scale="M",
            qualification_seed=20260822,
        )
    with pytest.raises(ValueError, match="qualification"):
        generate_route_a_qualification_trace(
            scale="S",
            qualification_seed=20260821,
        )


def test_formal_trace_rejects_the_qualification_seed() -> None:
    trace = generate_route_a_formal_trace(scale="M", formal_seed=20260822)

    assert trace.suite_role == "formal"
    with pytest.raises(ValueError, match="formal"):
        generate_route_a_formal_trace(scale="M", formal_seed=20260821)


def test_synthetic_event_trace_has_one_closed_canonical_source_identity() -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)

    assert hashlib.sha256(trace.event_trace_bytes).hexdigest() == trace.event_trace_sha256
    assert trace.event_trace_bytes.endswith(b"\n")
    document = json.loads(trace.event_trace_bytes)
    assert set(document) == {
        "accepted_group_count",
        "columns",
        "formal_seed",
        "initial_state_sha256",
        "ordered_groups",
        "rows",
        "scale",
        "schema_version",
    }
    assert document["schema_version"] == (
        "dynamic-cssc-route-a-synthetic-event-trace-v1"
    )
    assert document["initial_state_sha256"] == trace.initial_state_sha256
    assert document["accepted_group_count"] == 512
    assert set(document["ordered_groups"][0]) == {
        "accepted_group_ordinal",
        "logical_time_denominator",
        "logical_time_numerator",
        "ordered_set_transitions",
    }
    assert document["ordered_groups"][0]["ordered_set_transitions"] == [
        {
            "after": 2,
            "before": 3,
            "cause": "modify",
            "column": 3978,
            "row": 255,
        }
    ]
