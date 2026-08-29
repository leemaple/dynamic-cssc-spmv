from __future__ import annotations

import hashlib
import sqlite3
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import build_ordinary_openfhe_query_request
from dynamic_cssc.ordinary_query_lifecycle import OrdinaryQueryLifecycleError
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_native_case import (
    RouteANativeCasePlan,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_native_invocation import (
    RouteANativeInvocationError,
    authorize_route_a_native_invocation,
    claim_route_a_native_producer_capability,
    prepare_route_a_native_invocation,
    replay_route_a_native_invocation_read_only,
    require_route_a_native_producer_capability_consumed,
)
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace
from dynamic_cssc.strong_execution import StrongExecutionError

ROOT = Path(__file__).resolve().parents[1]
MACHINE_PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
SHARD_ID = "2" * 64


@pytest.fixture(scope="module")
def ordinary_case() -> RouteANativeCasePlan:
    return compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id="periodic-repack/windows=1",
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )


@pytest.fixture(scope="module")
def strong_case() -> RouteANativeCasePlan:
    return compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id=("packed-coo-cloud-segmented-delta/segment-width=128"),
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )


def _warmup_lane(case: RouteANativeCasePlan) -> RouteAEvaluationLane:
    return RouteAEvaluationLane.openfhe_warmup(
        shard_identity_sha256=SHARD_ID,
        strategy_candidate_id=case.strategy_candidate_id,
        rho=Fraction(1),
        unit_attempt_ordinal=0,
    )


def _recorded_lane(
    case: RouteANativeCasePlan,
    process_ordinal: int,
) -> RouteAEvaluationLane:
    return RouteAEvaluationLane.openfhe_recorded(
        shard_identity_sha256=SHARD_ID,
        strategy_candidate_id=case.strategy_candidate_id,
        rho=Fraction(1),
        unit_attempt_ordinal=0,
        process_ordinal=process_ordinal,
    )


def test_every_native_process_gets_a_fresh_query_namespace(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    lanes = (
        _warmup_lane(ordinary_case),
        *(_recorded_lane(ordinary_case, ordinal) for ordinal in range(3)),
    )
    prepared = tuple(
        prepare_route_a_native_invocation(
            ordinary_case,
            lane,
            ledger=SQLiteMaskBindingLedger(tmp_path / f"lane-{ordinal}.sqlite3"),
        )
        for ordinal, lane in enumerate(lanes)
    )

    assert len({item.lane.sha256 for item in prepared}) == 4
    assert len({item.query_identity.query_id for item in prepared}) == 4
    assert len({item.preparation_sha256 for item in prepared}) == 4
    request_sha256s = {
        hashlib.sha256(
            build_ordinary_openfhe_query_request(
                ordinary_case.execution_bundle,  # type: ignore[arg-type]
                item.prepared_query,  # type: ignore[arg-type]
                repository_root=ROOT,
            )
        ).hexdigest()
        for item in prepared
    }
    assert len(request_sha256s) == 4
    assert all(
        item.query_identity == item.lane.query_identity(ordinary_case.terminal_global_query_ordinal)
        for item in prepared
    )


@pytest.mark.parametrize("case_fixture", ["ordinary_case", "strong_case"])
def test_authorization_is_single_use_and_q4_replay_is_byte_read_only(
    case_fixture: str,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    case: RouteANativeCasePlan = request.getfixturevalue(case_fixture)
    lane = _recorded_lane(case, 0)
    ledger_path = tmp_path / "consumed-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_route_a_native_invocation(case, lane, ledger=ledger)
    capability = authorize_route_a_native_invocation(prepared, ledger=ledger)
    authorized = claim_route_a_native_producer_capability(capability)
    require_route_a_native_producer_capability_consumed(capability)
    frozen_ledger_bytes = ledger_path.read_bytes()

    replay = replay_route_a_native_invocation_read_only(
        case,
        lane,
        preparation_bytes=prepared.preparation_bytes,
        authorization_receipt_bytes=authorized.authorization_receipt_bytes,
        consumed_ledger_path=ledger_path,
    )

    assert ledger_path.read_bytes() == frozen_ledger_bytes
    assert replay.preparation_sha256 == prepared.preparation_sha256
    assert replay.ledger_snapshot_sha256 == authorized.consumed_ledger_snapshot_sha256
    assert replay.typed_oracle_sha256 == authorized.typed_oracle_sha256
    with pytest.raises(
        (OrdinaryQueryLifecycleError, StrongExecutionError),
        match="commitment consumption failed",
    ):
        authorize_route_a_native_invocation(prepared, ledger=ledger)


def test_native_producer_capability_is_opaque_and_single_use(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    lane = _recorded_lane(ordinary_case, 1)
    ledger = SQLiteMaskBindingLedger(tmp_path / "producer-capability.sqlite3")
    prepared = prepare_route_a_native_invocation(ordinary_case, lane, ledger=ledger)
    capability = authorize_route_a_native_invocation(prepared, ledger=ledger)

    with pytest.raises(TypeError, match="not a caller boolean"):
        bool(capability)
    claimed = claim_route_a_native_producer_capability(capability)
    assert claimed.prepared is prepared
    with pytest.raises(RouteANativeInvocationError, match="consumed"):
        claim_route_a_native_producer_capability(capability)


def test_q4_replay_rejects_retargeting_and_noncanonical_receipt(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    producer_lane = _recorded_lane(ordinary_case, 0)
    ledger_path = tmp_path / "consumed-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_route_a_native_invocation(
        ordinary_case,
        producer_lane,
        ledger=ledger,
    )
    authorized = claim_route_a_native_producer_capability(
        authorize_route_a_native_invocation(prepared, ledger=ledger)
    )

    with pytest.raises(OrdinaryQueryLifecycleError):
        replay_route_a_native_invocation_read_only(
            ordinary_case,
            _recorded_lane(ordinary_case, 1),
            preparation_bytes=prepared.preparation_bytes,
            authorization_receipt_bytes=authorized.authorization_receipt_bytes,
            consumed_ledger_path=ledger_path,
        )
    with pytest.raises(RouteANativeInvocationError, match="binding changed"):
        replay_route_a_native_invocation_read_only(
            ordinary_case,
            producer_lane,
            preparation_bytes=prepared.preparation_bytes,
            authorization_receipt_bytes=authorized.authorization_receipt_bytes + b" ",
            consumed_ledger_path=ledger_path,
        )


def test_q4_replay_rejects_an_orphan_commitment_row(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    lane = _recorded_lane(ordinary_case, 2)
    ledger_path = tmp_path / "consumed-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_route_a_native_invocation(ordinary_case, lane, ledger=ledger)
    authorized = claim_route_a_native_producer_capability(
        authorize_route_a_native_invocation(prepared, ledger=ledger)
    )
    connection = sqlite3.connect(ledger_path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
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
            ("f" * 64, "orphan", "block", "encrypted-zero-dummy", 1, "e" * 64),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="foreign-key violation"):
        replay_route_a_native_invocation_read_only(
            ordinary_case,
            lane,
            preparation_bytes=prepared.preparation_bytes,
            authorization_receipt_bytes=authorized.authorization_receipt_bytes,
            consumed_ledger_path=ledger_path,
        )


def test_q4_replay_rejects_the_discarded_warmup_lane(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    lane = _warmup_lane(ordinary_case)
    ledger_path = tmp_path / "warmup-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_route_a_native_invocation(ordinary_case, lane, ledger=ledger)
    authorized = claim_route_a_native_producer_capability(
        authorize_route_a_native_invocation(prepared, ledger=ledger)
    )

    with pytest.raises(RouteANativeInvocationError, match="recorded process lane"):
        replay_route_a_native_invocation_read_only(
            ordinary_case,
            lane,
            preparation_bytes=prepared.preparation_bytes,
            authorization_receipt_bytes=authorized.authorization_receipt_bytes,
            consumed_ledger_path=ledger_path,
        )
