from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.publication_day1b_aggregate_bounds import (
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
)
from dynamic_cssc.publication_day1b_expected_counts import (
    Day1BControllerExpectedCounts,
    Day1BControllerExpectedCountsError,
    Day1BControllerExpectedPhaseCounts,
    canonical_day1b_fixed_width_metadata_size_classes,
    require_formal_day1b_f1m_worker_zero,
    require_formal_day1b_fixed_width_metadata_size_classes,
)


def _phase(
    phase: str,
    *,
    one_time_count: int,
) -> Day1BControllerExpectedPhaseCounts:
    logical = (2, 3, 1, 4, 4, 5, 6, 4, one_time_count)
    worker = (2, 3, 1, 4, 4, 0, 0, 4, one_time_count)
    return Day1BControllerExpectedPhaseCounts(
        phase=phase,
        update_primitive_counts=(1,) + (0,) * (len(PRIMITIVE_NAMES) - 1),
        query_primitive_counts=(0, 1) + (0,) * (len(PRIMITIVE_NAMES) - 2),
        logical_protocol_object_counts=logical,
        worker_streamed_protocol_object_counts=worker,
    )


def _expected_counts() -> Day1BControllerExpectedCounts:
    return Day1BControllerExpectedCounts(
        candidate_id="padding-reuse",
        candidate_policy_sha256="a" * 64,
        accounting_sha256="b" * 64,
        primitive_names=PRIMITIVE_NAMES,
        serialized_categories=SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
        phases=(
            _phase("tuning-prefix", one_time_count=1),
            _phase("held-out", one_time_count=0),
        ),
        fixed_width_metadata_size_classes=(
            canonical_day1b_fixed_width_metadata_size_classes()
        ),
    )


def test_expected_counts_round_trip_is_exact_and_digest_stable() -> None:
    expected = _expected_counts()

    reopened = Day1BControllerExpectedCounts.from_document(expected.to_document())

    assert reopened == expected
    assert reopened.expected_counts_sha256 == expected.expected_counts_sha256


@pytest.mark.parametrize(
    "field",
    ("update_primitive_counts", "query_primitive_counts"),
)
def test_phase_counts_reject_noncanonical_primitive_dimensions(field: str) -> None:
    phase = _phase("held-out", one_time_count=0)

    with pytest.raises(
        Day1BControllerExpectedCountsError,
        match=f"{len(PRIMITIVE_NAMES)} entries",
    ):
        replace(phase, **{field: (0,) * (len(PRIMITIVE_NAMES) - 1)})


@pytest.mark.parametrize(
    "field",
    (
        "logical_protocol_object_counts",
        "worker_streamed_protocol_object_counts",
    ),
)
def test_phase_counts_reject_noncanonical_category_dimensions(field: str) -> None:
    phase = _phase("held-out", one_time_count=0)

    with pytest.raises(
        Day1BControllerExpectedCountsError,
        match=f"{len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES)} entries",
    ):
        replace(
            phase,
            **{
                field: (0,) * (len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES) - 1),
            },
        )


def test_expected_counts_reject_partial_f1m_worker_multiplicity() -> None:
    phase = _phase("held-out", one_time_count=0)
    changed_worker = list(phase.worker_streamed_protocol_object_counts)
    changed_worker[5] = 1

    with pytest.raises(
        Day1BControllerExpectedCountsError,
        match="F1-M worker multiplicity",
    ):
        replace(
            _expected_counts(),
            phases=(
                _phase("tuning-prefix", one_time_count=1),
                replace(
                    phase,
                    worker_streamed_protocol_object_counts=tuple(changed_worker),
                ),
            ),
        )


def test_formal_expected_counts_reject_materialized_f1m_worker_mode() -> None:
    expected = _expected_counts()
    held_out = expected.phases[1]
    changed_worker = list(held_out.worker_streamed_protocol_object_counts)
    changed_worker[5] = held_out.logical_protocol_object_counts[5]
    materialized_mode = replace(
        expected,
        phases=(
            expected.phases[0],
            replace(
                held_out,
                worker_streamed_protocol_object_counts=tuple(changed_worker),
            ),
        ),
    )

    with pytest.raises(
        Day1BControllerExpectedCountsError,
        match="formal F1-M worker multiplicity must remain zero",
    ):
        require_formal_day1b_f1m_worker_zero(materialized_mode)


def test_expected_counts_digest_commits_to_controller_multiplicity() -> None:
    expected = _expected_counts()
    held_out = expected.phases[1]
    changed_logical = list(held_out.logical_protocol_object_counts)
    changed_worker = list(held_out.worker_streamed_protocol_object_counts)
    changed_logical[0] += 1
    changed_worker[0] += 1
    changed = replace(
        expected,
        phases=(
            expected.phases[0],
            replace(
                held_out,
                logical_protocol_object_counts=tuple(changed_logical),
                worker_streamed_protocol_object_counts=tuple(changed_worker),
            ),
        ),
    )

    assert changed.expected_counts_sha256 != expected.expected_counts_sha256


def test_formal_expected_counts_bind_all_fixed_width_metadata_size_classes() -> None:
    expected = _expected_counts()

    require_formal_day1b_fixed_width_metadata_size_classes(expected)

    assert tuple(
        (
            item.category,
            item.transaction,
            item.serialized_byte_count,
        )
        for item in expected.fixed_width_metadata_size_classes
    ) == (
        ("update-column-index-synchronization", "update", 64),
        ("update-version-plan-metadata", "update", 144),
        ("query-version-plan-metadata", "query", 136),
    )


def test_formal_expected_counts_reject_missing_metadata_size_class() -> None:
    expected = _expected_counts()

    with pytest.raises(
        Day1BControllerExpectedCountsError,
        match="formal fixed-width metadata size classes changed",
    ):
        require_formal_day1b_fixed_width_metadata_size_classes(
            replace(
                expected,
                fixed_width_metadata_size_classes=(
                    expected.fixed_width_metadata_size_classes[:-1]
                ),
            )
        )


@pytest.mark.parametrize("mutation", ("missing-transaction", "wrong-transaction"))
def test_expected_counts_parser_rejects_metadata_descriptor_splice(
    mutation: str,
) -> None:
    document = _expected_counts().to_document()
    size_class = document["fixed_width_metadata_size_classes"][0]
    if mutation == "missing-transaction":
        del size_class["transaction"]
        message = "keys are not exact"
    else:
        size_class["transaction"] = "query"
        message = "differs from canonical framing"

    with pytest.raises(Day1BControllerExpectedCountsError, match=message):
        Day1BControllerExpectedCounts.from_document(document)
