from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction

import pytest

import dynamic_cssc.publication_day1b_replay_execution as replay_execution_module
from dynamic_cssc.day1_registry import RegisteredCandidate
from dynamic_cssc.publication_day1b_accounting import (
    Day1BAccountingDomain,
    Day1BQueryWindowAccounting,
    PublicationDay1BAccounting,
    replay_publication_day1b_candidate_cell,
)
from dynamic_cssc.publication_day1b_layout_execution import (
    Day1BQueryLayoutExecution,
)
from dynamic_cssc.publication_day1b_replay_execution import (
    DAY1B_REPRESENTATIVE_SELECTION_RULE,
    Day1BCandidateReplayCapability,
    Day1BReplayExecutionError,
    abandon_day1b_candidate_replay_capability,
    claim_day1b_candidate_replay_capability,
    describe_day1b_candidate_replay_capability,
    replay_and_seal_publication_day1b_candidate,
)
from dynamic_cssc.publication_schedule import (
    ExactPublicationWindow,
    ScheduledNetUpdate,
)
from dynamic_cssc.publication_traces import PUBLICATION_QUERY_VECTOR_SCHEMA


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _query_vector() -> tuple[bytes, str]:
    content = _canonical_bytes(
        {
            "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
            "values": [1, 1, 0, -1],
        }
    )
    return content, hashlib.sha256(content).hexdigest()


def _domain() -> Day1BAccountingDomain:
    return Day1BAccountingDomain(
        rows=4,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=7,
        max_row_nnz=4,
        strong_segment_width=4,
    )


def _strong_domain() -> Day1BAccountingDomain:
    return Day1BAccountingDomain(
        rows=4,
        cols=4,
        effective_slots=128,
        partition_rows=4,
        matrix_value_bound=7,
        max_row_nnz=4,
        strong_segment_width=128,
    )


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


def _ordinary_candidate() -> RegisteredCandidate:
    return RegisteredCandidate(
        candidate_id="reserved-slack/beta=0.4",
        strategy="ReservedSlack-CSSC",
        role="reference",
        reserved_slack_beta=Decimal("0.4"),
    )


def _strong_candidate() -> RegisteredCandidate:
    return RegisteredCandidate(
        candidate_id="packed-coo-cloud-segmented-delta/segment-width=128",
        strategy="Packed-COO-Cloud-Segmented-Delta",
        role="reference",
        reserved_slack_beta=Decimal("0"),
    )


def _ablation_candidate() -> RegisteredCandidate:
    return RegisteredCandidate(
        candidate_id="packed-coo-client-lane-delta/capacity=128",
        strategy="Packed-COO-Client-Lane-Delta",
        role="ablation",
        packed_coo_segment_capacity=128,
    )


def _collector(
    candidate: RegisteredCandidate | None = None,
) -> replay_execution_module._Day1BQueryExecutionCollector:
    content, digest = _query_vector()
    return replay_execution_module._Day1BQueryExecutionCollector(
        candidate=_ordinary_candidate() if candidate is None else candidate,
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
        modulus=65537,
    )


def _capture_pairs(
    candidate: RegisteredCandidate,
) -> tuple[
    PublicationDay1BAccounting,
    list[tuple[Day1BQueryWindowAccounting, Day1BQueryLayoutExecution]],
]:
    pairs: list[tuple[Day1BQueryWindowAccounting, Day1BQueryLayoutExecution]] = []
    accounting = replay_publication_day1b_candidate_cell(
        candidate=candidate,
        windows=_windows(),
        domain=_domain(),
        query_execution_sink=lambda descriptor, execution: pairs.append(
            (descriptor, execution)
        ),
    )
    return accounting, pairs


def test_collector_seals_one_same_replay_ordinary_representative() -> None:
    content, digest = _query_vector()
    accounting, capability = replay_and_seal_publication_day1b_candidate(
        candidate=_ordinary_candidate(),
        windows=_windows(),
        domain=_domain(),
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
    )
    receipt = describe_day1b_candidate_replay_capability(capability)

    assert receipt.query_execution_binding_count == 2
    assert receipt.representative_phase == "tuning-prefix"
    assert receipt.representative_window_index == 1
    assert receipt.query_window_stream_sha256 == accounting.query_window_stream_sha256
    assert receipt.accounting_sha256 == accounting.accounting_sha256
    document = receipt.to_document()
    assert document["representative_selection_rule"] == (
        DAY1B_REPRESENTATIVE_SELECTION_RULE
    )
    assert document["candidate_replay_continuity_verified"] is True
    assert document["candidate_role"] == "reference"
    assert document["retained_phases"] == ["tuning-prefix", "held-out"]
    assert document["plaintext_modulus"] == 65537
    assert document["typed_query_layout_verified"] is True
    assert document["representative_expected_output_verified"] is True
    assert document["openfhe_execution_verified"] is False
    assert document["production_execution_admissible"] is False
    assert document["formal_authority_granted"] is False
    assert document["publication_authority"] is False
    assert document["heldout_dispatch_authorized"] is False

    representative = claim_day1b_candidate_replay_capability(capability)
    assert representative.execution.execution_kind == "ordinary"
    assert representative.descriptor.window_index == 1
    assert representative.binding.logical_query_multiplicity == 7
    assert representative.binding.retained_private_bundle_count == 1
    assert representative.binding.openfhe_execution_count == 0
    assert representative.expected_output == (3, 0, 0, 0)
    assert capability._binding is None
    with pytest.raises(Day1BReplayExecutionError, match="absent or consumed"):
        claim_day1b_candidate_replay_capability(capability)


def test_collector_derives_the_same_independent_oracle_for_strong() -> None:
    content, digest = _query_vector()
    _accounting, capability = replay_and_seal_publication_day1b_candidate(
        candidate=_strong_candidate(),
        windows=_windows(),
        domain=_strong_domain(),
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
    )

    representative = claim_day1b_candidate_replay_capability(capability)

    assert representative.execution.execution_kind == "strong"
    assert representative.expected_output == (3, 0, 0, 0)
    assert representative.binding.phase == "tuning-prefix"
    assert representative.binding.query_vector_sha256 == _query_vector()[1]


def test_collector_selects_first_heldout_query_for_the_ablation() -> None:
    content, digest = _query_vector()
    _accounting, capability = replay_and_seal_publication_day1b_candidate(
        candidate=_ablation_candidate(),
        windows=_windows(),
        domain=_strong_domain(),
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
    )

    representative = claim_day1b_candidate_replay_capability(capability)

    assert representative.binding.phase == "held-out"
    assert representative.descriptor.window_index == 2
    assert representative.binding.logical_query_multiplicity == 11
    assert representative.expected_output == (2, 0, 0, 0)


def test_collector_rejects_an_adjacent_descriptor_execution_splice() -> None:
    _accounting, pairs = _capture_pairs(_ordinary_candidate())
    collector = _collector()

    with pytest.raises(Day1BReplayExecutionError, match="not one pair"):
        collector.accept(pairs[0][0], pairs[1][1])


def test_collector_rejects_a_missing_query_window_against_accounting() -> None:
    accounting, pairs = _capture_pairs(_ordinary_candidate())
    collector = _collector()
    collector.accept(*pairs[0])

    with pytest.raises(Day1BReplayExecutionError, match="does not close"):
        collector.finish(accounting)


def test_private_collector_rejects_accounting_candidate_retarget() -> None:
    accounting, pairs = _capture_pairs(_ordinary_candidate())
    collector = _collector()
    for pair in pairs:
        collector.accept(*pair)

    with pytest.raises(Day1BReplayExecutionError, match="does not close"):
        collector.finish(
            replace(
                accounting,
                candidate_id="periodic-repack/windows=4",
                candidate_policy_sha256="f" * 64,
            )
        )


def test_repository_wrapper_owns_role_accounting_modulus_and_typed_sink() -> None:
    parameters = inspect.signature(
        replay_and_seal_publication_day1b_candidate
    ).parameters

    assert tuple(parameters) == (
        "candidate",
        "windows",
        "domain",
        "query_vector_canonical_bytes",
        "query_vector_sha256",
        "query_window_sink",
    )
    for forbidden in (
        "accounting",
        "candidate_role",
        "modulus",
        "query_execution_sink",
        "retained_phases",
    ):
        assert forbidden not in parameters

    content, digest = _query_vector()
    with pytest.raises(ValueError, match="frozen Day 1 policy"):
        replay_and_seal_publication_day1b_candidate(
            candidate=replace(_ordinary_candidate(), role="ablation"),
            windows=_windows(),
            domain=_domain(),
            query_vector_canonical_bytes=content,
            query_vector_sha256=digest,
        )


def test_collector_is_one_shot_and_capability_is_not_caller_constructible() -> None:
    content, digest = _query_vector()
    _accounting, capability = replay_and_seal_publication_day1b_candidate(
        candidate=_ordinary_candidate(),
        windows=_windows(),
        domain=_domain(),
        query_vector_canonical_bytes=content,
        query_vector_sha256=digest,
    )

    with pytest.raises(TypeError, match="collector-minted"):
        Day1BCandidateReplayCapability()
    with pytest.raises(TypeError, match="not a caller boolean"):
        bool(capability)
    abandon_day1b_candidate_replay_capability(capability)
    assert capability._binding is None
    with pytest.raises(Day1BReplayExecutionError, match="absent or consumed"):
        describe_day1b_candidate_replay_capability(capability)


def test_collector_rejects_noncanonical_or_rehashed_query_vector_bytes() -> None:
    content, digest = _query_vector()
    with pytest.raises(Day1BReplayExecutionError, match="not canonical JSON"):
        replay_execution_module._Day1BQueryExecutionCollector(
            candidate=_ordinary_candidate(),
            query_vector_canonical_bytes=content[:-1],
            query_vector_sha256=hashlib.sha256(content[:-1]).hexdigest(),
            modulus=65537,
        )
    with pytest.raises(Day1BReplayExecutionError, match="differ from their digest"):
        replay_execution_module._Day1BQueryExecutionCollector(
            candidate=_ordinary_candidate(),
            query_vector_canonical_bytes=content,
            query_vector_sha256="0" * 64,
            modulus=65537,
        )
    with pytest.raises(Day1BReplayExecutionError, match="frozen plaintext modulus"):
        replay_execution_module._Day1BQueryExecutionCollector(
            candidate=_ordinary_candidate(),
            query_vector_canonical_bytes=content,
            query_vector_sha256=digest,
            modulus=97,
        )
    assert digest != "0" * 64
