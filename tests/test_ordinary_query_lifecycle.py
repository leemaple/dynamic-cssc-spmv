from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from dynamic_cssc.cssc import publish_component
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.mask_ledger import (
    PreparedF1MCommitmentError,
    SQLiteMaskBindingLedger,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA,
    ORDINARY_PRIVATE_PLAN_SCHEMA,
    ORDINARY_QUERY_PREPARATION_SCHEMA,
    OrdinaryExecutionBundle,
    OrdinaryQueryLifecycleError,
    authorize_ordinary_execution,
    bind_ordinary_execution,
    canonical_ordinary_private_plan_bytes,
    canonical_ordinary_private_plan_payload,
    canonical_ordinary_query_preparation_bytes,
    canonical_ordinary_query_preparation_payload,
    claim_ordinary_execution,
    decode_ordinary_query_preparation_bytes,
    execute_ordinary_plaintext,
    prepare_ordinary_query,
    replay_ordinary_plaintext_read_only,
)
from dynamic_cssc.query_compiler import compile_query
from dynamic_cssc.strategy_state import advance_publication, initialize_strategy


def _single_source_bundle() -> OrdinaryExecutionBundle:
    component = publish_component(
        {(0, 1): 3, (1, 2): 4},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-base",
    )
    return bind_ordinary_execution(compile_query((component,), f1m_policy="overlap-only"))


def _overlap_bundle() -> OrdinaryExecutionBundle:
    first = publish_component(
        {(0, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-a",
    )
    second = publish_component(
        {(0, 1): 3, (1, 2): 4},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-b",
    )
    return bind_ordinary_execution(
        compile_query((second, first), f1m_policy="overlap-only")
    )


def test_single_source_private_query_executes_once_without_overlap_masks(
    tmp_path: Path,
) -> None:
    bundle = _single_source_bundle()
    ledger_path = tmp_path / "ordinary-ledger.sqlite3"
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-query-1",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=SQLiteMaskBindingLedger(ledger_path),
    )

    assert prepared.f1m_operands == ()
    assert execute_ordinary_plaintext(
        bundle,
        prepared,
        modulus=97,
        ledger=SQLiteMaskBindingLedger(ledger_path),
    ) == (21, 44)
    with pytest.raises(OrdinaryQueryLifecycleError, match="commitment consumption"):
        execute_ordinary_plaintext(
            bundle,
            prepared,
            modulus=97,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )


def test_closed_read_only_ledger_accepts_consumed_batch_without_commitment_rows(
    tmp_path: Path,
) -> None:
    bundle = _single_source_bundle()
    vector = (5, 7, 11, 13)
    ledger_path = tmp_path / "ordinary-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-zero-commitment-replay",
        vector=vector,
        modulus=97,
        ledger=ledger,
    )
    assert prepared.f1m_operands == ()
    preparation_bytes = canonical_ordinary_query_preparation_bytes(bundle, prepared)
    assert execute_ordinary_plaintext(
        bundle,
        prepared,
        modulus=97,
        ledger=ledger,
    ) == (21, 44)
    frozen_ledger_bytes = ledger_path.read_bytes()

    replay_ledger = SQLiteMaskBindingLedger.open_existing_read_only(ledger_path)
    decoded = decode_ordinary_query_preparation_bytes(
        bundle,
        preparation_bytes,
        expected_query_id=prepared.query_id,
        expected_vector=vector,
    )
    assert replay_ordinary_plaintext_read_only(
        bundle,
        decoded,
        modulus=97,
        ledger=replay_ledger,
    ) == (21, 44)
    replay_ledger.verify_closed_consumed_prepared_f1m_ledger(
        commitment_tokens=(prepared.ledger_commitment_token,),
        reservation_bindings=(),
    )
    assert ledger_path.read_bytes() == frozen_ledger_bytes


def test_overlap_masks_are_bound_cancel_and_reconstruct_exactly(tmp_path: Path) -> None:
    bundle = _overlap_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-overlap-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=ledger,
    )

    assert len(prepared.f1m_operands) == 2
    assert {operand.kind for operand in prepared.f1m_operands} == {"random-zero-sum"}
    assert sum(operand.values[0] for operand in prepared.f1m_operands) % 97 == 0
    assert execute_ordinary_plaintext(
        bundle,
        prepared,
        modulus=97,
        ledger=ledger,
    ) == (31, 44)


def test_execution_authorization_consumes_ledger_and_is_single_use(tmp_path: Path) -> None:
    bundle = _overlap_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-authorized-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=ledger,
    )

    capability = authorize_ordinary_execution(bundle, prepared, ledger=ledger)
    receipt = claim_ordinary_execution(capability, bundle, prepared)
    document = receipt.to_document()

    assert document["schema_version"] == ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA
    assert document["query_id"] == prepared.query_id
    assert document["ledger_commitment_token"] == prepared.ledger_commitment_token
    assert document["query_preparation_sha256"] == hashlib.sha256(
        canonical_ordinary_query_preparation_bytes(bundle, prepared)
    ).hexdigest()
    assert len(document["authorization_transition_sha256"]) == 64
    with pytest.raises(OrdinaryQueryLifecycleError, match="absent or consumed"):
        claim_ordinary_execution(capability, bundle, prepared)
    with pytest.raises(OrdinaryQueryLifecycleError, match="commitment consumption"):
        authorize_ordinary_execution(bundle, prepared, ledger=ledger)


def test_client_lane_candidate_uses_the_same_private_lifecycle(tmp_path: Path) -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 2},
        rows=1,
        cols=4,
        effective_slots=4,
        packed_coo_segment_capacity=2,
    )
    transition = advance_publication(
        state,
        PublicationWindow(
            index=0,
            start_time=0.0,
            end_time=1.0,
            updates=(NetUpdate(row=0, col=1, before=0, after=3),),
            query_count=1,
            reason="test-window",
        ),
    )
    assert transition.state.coo_segments
    bundle = bind_ordinary_execution(
        compile_query(
            (transition.state.base,),
            client_lane_segments=transition.state.coo_segments,
            f1m_policy="overlap-only",
        )
    )
    ledger = SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-client-lane-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=ledger,
    )

    assert execute_ordinary_plaintext(
        bundle,
        prepared,
        modulus=97,
        ledger=ledger,
    ) == (31,)


def test_private_plan_changes_with_hidden_global_columns_while_cloud_plan_does_not() -> None:
    first = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-base",
    )
    second = publish_component(
        {(0, 3): 2},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-base",
    )
    first_bundle = bind_ordinary_execution(compile_query((first,)))
    second_bundle = bind_ordinary_execution(compile_query((second,)))

    assert first_bundle.compiled.cloud_program_digest == second_bundle.compiled.cloud_program_digest
    assert first_bundle.compiled.output_plan_digest == second_bundle.compiled.output_plan_digest
    assert first_bundle.private_plan_digest != second_bundle.private_plan_digest


def test_private_plan_and_preparation_have_closed_canonical_schemas(tmp_path: Path) -> None:
    bundle = _overlap_bundle()
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-canonical-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3"),
    )

    private_payload = canonical_ordinary_private_plan_payload(bundle)
    private_bytes = canonical_ordinary_private_plan_bytes(bundle)
    preparation_payload = canonical_ordinary_query_preparation_payload(bundle, prepared)
    preparation_bytes = canonical_ordinary_query_preparation_bytes(bundle, prepared)

    assert private_payload["format"] == ORDINARY_PRIVATE_PLAN_SCHEMA
    assert preparation_payload["format"] == ORDINARY_QUERY_PREPARATION_SCHEMA
    assert json.loads(private_bytes) == private_payload
    assert json.loads(preparation_bytes) == preparation_payload
    assert hashlib.sha256(private_bytes).hexdigest() == bundle.private_plan_digest
    assert preparation_payload["bindings"]["private_plan_digest"] == bundle.private_plan_digest
    assert preparation_payload["ledger_commitment_token"] == prepared.ledger_commitment_token


def test_exact_preparation_decodes_and_replays_against_an_immutable_consumed_ledger(
    tmp_path: Path,
) -> None:
    bundle = _overlap_bundle()
    ledger_path = tmp_path / "ordinary-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    vector = (5, 7, 11, 13)
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-read-only-replay",
        vector=vector,
        modulus=97,
        ledger=ledger,
    )
    preparation_bytes = canonical_ordinary_query_preparation_bytes(bundle, prepared)
    assert execute_ordinary_plaintext(bundle, prepared, modulus=97, ledger=ledger) == (31, 44)
    frozen_ledger_bytes = ledger_path.read_bytes()

    replay_ledger = SQLiteMaskBindingLedger.open_existing_read_only(ledger_path)
    decoded = decode_ordinary_query_preparation_bytes(
        bundle,
        preparation_bytes,
        expected_query_id=prepared.query_id,
        expected_vector=vector,
    )
    assert decoded == prepared
    assert replay_ordinary_plaintext_read_only(
        bundle,
        decoded,
        modulus=97,
        ledger=replay_ledger,
    ) == (31, 44)
    replay_ledger.verify_closed_consumed_prepared_f1m_ledger(
        commitment_tokens=(prepared.ledger_commitment_token,),
        reservation_bindings=tuple(
            operand.binding
            for operand in prepared.f1m_operands
            if operand.kind == "random-zero-sum"
        ),
    )
    assert ledger_path.read_bytes() == frozen_ledger_bytes
    with pytest.raises(RuntimeError, match="read-only"):
        replay_ledger.reserve_all(
            tuple(
                operand.binding
                for operand in prepared.f1m_operands
                if operand.kind == "random-zero-sum"
            )
        )


def test_preparation_decoder_rejects_noncanonical_or_retargeted_bytes(
    tmp_path: Path,
) -> None:
    bundle = _overlap_bundle()
    vector = (5, 7, 11, 13)
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-decode-tamper",
        vector=vector,
        modulus=97,
        ledger=SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3"),
    )
    canonical = canonical_ordinary_query_preparation_bytes(bundle, prepared)
    retargeted = canonical.replace(
        b'"query_id":"ordinary-decode-tamper"',
        b'"query_id":"ordinary-decode-forged"',
        1,
    )

    with pytest.raises(OrdinaryQueryLifecycleError):
        decode_ordinary_query_preparation_bytes(
            bundle,
            retargeted,
            expected_query_id=prepared.query_id,
            expected_vector=vector,
        )
    with pytest.raises(OrdinaryQueryLifecycleError, match="canonical"):
        decode_ordinary_query_preparation_bytes(
            bundle,
            canonical + b" ",
            expected_query_id=prepared.query_id,
            expected_vector=vector,
        )


def test_read_only_replay_rejects_unconsumed_and_extra_ledger_batches(
    tmp_path: Path,
) -> None:
    bundle = _overlap_bundle()
    vector = (5, 7, 11, 13)
    ledger_path = tmp_path / "ordinary-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    unconsumed = prepare_ordinary_query(
        bundle,
        query_id="ordinary-unconsumed-replay",
        vector=vector,
        modulus=97,
        ledger=ledger,
    )
    read_only = SQLiteMaskBindingLedger.open_existing_read_only(ledger_path)
    with pytest.raises(OrdinaryQueryLifecycleError, match="read-only replay ledger"):
        replay_ordinary_plaintext_read_only(
            bundle,
            unconsumed,
            modulus=97,
            ledger=read_only,
        )

    assert execute_ordinary_plaintext(
        bundle,
        unconsumed,
        modulus=97,
        ledger=ledger,
    ) == (31, 44)
    extra = prepare_ordinary_query(
        bundle,
        query_id="ordinary-extra-replay",
        vector=vector,
        modulus=97,
        ledger=ledger,
    )
    assert execute_ordinary_plaintext(bundle, extra, modulus=97, ledger=ledger) == (31, 44)
    closed_read_only = SQLiteMaskBindingLedger.open_existing_read_only(ledger_path)
    with pytest.raises(PreparedF1MCommitmentError, match="missing, extra"):
        closed_read_only.verify_closed_consumed_prepared_f1m_ledger(
            commitment_tokens=(unconsumed.ledger_commitment_token,),
            reservation_bindings=tuple(
                operand.binding
                for operand in unconsumed.f1m_operands
                if operand.kind == "random-zero-sum"
            ),
        )


def test_tampered_private_operand_fails_before_consuming_valid_batch(tmp_path: Path) -> None:
    bundle = _overlap_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-tamper-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=ledger,
    )
    first = prepared.f1m_operands[0]
    tampered_values = ((first.values[0] + 1) % 97, *first.values[1:])
    tampered = replace(
        prepared,
        f1m_operands=(replace(first, values=tampered_values), *prepared.f1m_operands[1:]),
    )

    with pytest.raises(OrdinaryQueryLifecycleError, match="do not cancel"):
        execute_ordinary_plaintext(bundle, tampered, modulus=97, ledger=ledger)
    assert execute_ordinary_plaintext(bundle, prepared, modulus=97, ledger=ledger) == (31, 44)


def test_duplicate_query_binding_is_rejected_by_persistent_reservation(tmp_path: Path) -> None:
    bundle = _overlap_bundle()
    ledger_path = tmp_path / "ordinary-ledger.sqlite3"
    arguments = {
        "query_id": "ordinary-duplicate-query",
        "vector": (5, 7, 11, 13),
        "modulus": 97,
    }
    prepare_ordinary_query(
        bundle,
        **arguments,
        ledger=SQLiteMaskBindingLedger(ledger_path),
    )

    with pytest.raises(OrdinaryQueryLifecycleError, match="overlap-mask preparation"):
        prepare_ordinary_query(
            bundle,
            **arguments,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )


def test_uniform_f1m_compilation_cannot_enter_the_ordinary_lifecycle() -> None:
    component = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="ordinary-version-1",
        component_prefix="ordinary-base",
    )

    with pytest.raises(OrdinaryQueryLifecycleError, match="overlap-only"):
        bind_ordinary_execution(
            compile_query((component,), f1m_policy="uniform-random-or-zero")
        )


def test_bundle_and_preparation_reject_cross_binding_substitution(tmp_path: Path) -> None:
    bundle = _single_source_bundle()
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-binding-query",
        vector=(5, 7, 11, 13),
        modulus=97,
        ledger=SQLiteMaskBindingLedger(tmp_path / "ordinary-ledger.sqlite3"),
    )

    with pytest.raises(OrdinaryQueryLifecycleError, match="execution bundle binding"):
        canonical_ordinary_query_preparation_payload(
            bundle,
            replace(prepared, private_plan_digest="f" * 64),
        )
    with pytest.raises(OrdinaryQueryLifecycleError, match="execution bundle binding"):
        canonical_ordinary_query_preparation_payload(
            bundle,
            replace(prepared, query_id=""),
        )
