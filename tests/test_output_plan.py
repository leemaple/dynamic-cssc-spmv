from __future__ import annotations

import inspect
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import dynamic_cssc.output_plan as output_plan_module
from dynamic_cssc.mask_ledger import (
    ConsumedPreparedF1MCommitmentError,
    DuplicateMaskBindingError,
    PreparedF1MCommitment,
    PreparedF1MCommitmentError,
    SQLiteMaskBindingLedger,
)
from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputPlanError,
    OutputShare,
    analyze_output_plan,
    prepare_f1m_masks,
)


def _overlap_plan() -> OutputPlan:
    return OutputPlan(
        logical_output_size=1,
        slot_count=1,
        shares=(
            OutputShare("base", "out", ((0, 0),)),
            OutputShare("delta", "out", ((0, 0),)),
        ),
    )


def test_public_mask_api_owns_its_randomness_source() -> None:
    assert "randbelow" not in inspect.signature(prepare_f1m_masks).parameters


def test_mask_binding_is_consumed_before_random_draw_and_survives_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = tmp_path / "mask-bindings.sqlite3"
    plan = _overlap_plan()

    def crash_during_sampling(_: int) -> int:
        raise RuntimeError("simulated crash after reservation")

    monkeypatch.setattr(output_plan_module.secrets, "randbelow", crash_during_sampling)
    with pytest.raises(RuntimeError, match="simulated crash"):
        prepare_f1m_masks(
            plan,
            query_id="query-crash",
            version_id="version-1",
            modulus=17,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )

    draws_after_restart = 0

    def count_draws(_: int) -> int:
        nonlocal draws_after_restart
        draws_after_restart += 1
        return 1

    monkeypatch.setattr(output_plan_module.secrets, "randbelow", count_draws)
    with pytest.raises(DuplicateMaskBindingError):
        prepare_f1m_masks(
            plan,
            query_id="query-crash",
            version_id="version-1",
            modulus=17,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )
    assert draws_after_restart == 0


def test_concurrent_reservation_of_one_binding_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "mask-bindings.sqlite3"
    ledgers = (SQLiteMaskBindingLedger(ledger_path), SQLiteMaskBindingLedger(ledger_path))
    start = Barrier(2)
    binding = ("query-9", "version-4", "0" * 64, "base", "out")

    def reserve(ledger: SQLiteMaskBindingLedger) -> str:
        start.wait()
        try:
            ledger.reserve_all((binding,))
        except DuplicateMaskBindingError:
            return "duplicate"
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(reserve, ledgers))

    assert sorted(outcomes) == ["duplicate", "reserved"]


def test_batch_reservation_rolls_back_new_bindings_when_one_is_consumed(
    tmp_path: Path,
) -> None:
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3")
    consumed = ("query-1", "version-1", "1" * 64, "base", "out")
    new = ("query-2", "version-1", "1" * 64, "delta", "out")
    ledger.reserve_all((consumed,))

    with pytest.raises(DuplicateMaskBindingError):
        ledger.reserve_all((new, consumed))

    ledger.reserve_all((new,))


def test_mask_binding_identity_uses_all_five_fields(tmp_path: Path) -> None:
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3")
    digest = "2" * 64
    original = ("query-1", "version-1", digest, "base", "out")
    ledger.reserve_all(
        (
            original,
            ("query-2", "version-1", digest, "base", "out"),
            ("query-1", "version-2", digest, "base", "out"),
            ("query-1", "version-1", "3" * 64, "base", "out"),
            ("query-1", "version-1", digest, "delta", "out"),
            ("query-1", "version-1", digest, "base", "other"),
        )
    )

    with pytest.raises(DuplicateMaskBindingError):
        ledger.reserve_all((original,))


def test_prepared_f1m_schema_contains_only_binding_mask_commitment_and_state(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "mask-bindings.sqlite3"
    SQLiteMaskBindingLedger(ledger_path)

    connection = sqlite3.connect(ledger_path)
    try:
        batch_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(prepared_f1m_batches)")
        }
        commitment_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(prepared_f1m_commitments)")
        }
    finally:
        connection.close()

    assert batch_columns == {
        "commitment_token",
        "query_id",
        "version_id",
        "output_plan_digest",
        "private_plan_digest",
        "execution_binding_digest",
        "modulus",
        "consumed",
    }
    assert commitment_columns == {
        "commitment_token",
        "component_id",
        "output_block_id",
        "kind",
        "value_count",
        "values_digest",
    }


def test_prepared_f1m_verification_has_one_atomic_winner_across_restarts(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "mask-bindings.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    commitment = PreparedF1MCommitment(
        query_id="query-atomic",
        version_id="version-1",
        output_plan_digest="4" * 64,
        component_id="base",
        output_block_id="out",
        kind="random-zero-sum",
        values=(3, 14),
    )
    ledger.reserve_all((commitment.binding,))
    token = ledger.commit_prepared_f1m(
        (commitment,),
        query_id=commitment.query_id,
        version_id=commitment.version_id,
        output_plan_digest=commitment.output_plan_digest,
        private_plan_digest="5" * 64,
        execution_binding_digest="6" * 64,
        modulus=17,
    )
    ledgers = (SQLiteMaskBindingLedger(ledger_path), SQLiteMaskBindingLedger(ledger_path))
    start = Barrier(2)

    def verify_once(restarted: SQLiteMaskBindingLedger) -> str:
        start.wait()
        try:
            restarted.verify_and_consume_prepared_f1m(
                (commitment,),
                commitment_token=token,
                query_id=commitment.query_id,
                version_id=commitment.version_id,
                output_plan_digest=commitment.output_plan_digest,
                private_plan_digest="5" * 64,
                execution_binding_digest="6" * 64,
                modulus=17,
            )
        except ConsumedPreparedF1MCommitmentError:
            return "consumed"
        return "verified"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(verify_once, ledgers))

    assert sorted(outcomes) == ["consumed", "verified"]


def test_legacy_prepared_batch_schema_migrates_without_authorizing_unknown_execution_binding(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "mask-bindings.sqlite3"
    legacy_token = "a" * 64
    connection = sqlite3.connect(ledger_path)
    try:
        connection.execute(
            """
            CREATE TABLE prepared_f1m_batches (
                commitment_token TEXT NOT NULL PRIMARY KEY,
                query_id TEXT NOT NULL,
                version_id TEXT NOT NULL,
                output_plan_digest TEXT NOT NULL,
                private_plan_digest TEXT NOT NULL,
                modulus TEXT NOT NULL,
                consumed INTEGER NOT NULL CHECK (consumed IN (0, 1)),
                UNIQUE (query_id, version_id, output_plan_digest)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            INSERT INTO prepared_f1m_batches (
                commitment_token,
                query_id,
                version_id,
                output_plan_digest,
                private_plan_digest,
                modulus,
                consumed
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (legacy_token, "query-legacy", "version-1", "4" * 64, "5" * 64, "17"),
        )
        connection.commit()
    finally:
        connection.close()

    ledger = SQLiteMaskBindingLedger(ledger_path)
    with pytest.raises(PreparedF1MCommitmentError, match="execution binding"):
        ledger.verify_and_consume_prepared_f1m(
            (),
            commitment_token=legacy_token,
            query_id="query-legacy",
            version_id="version-1",
            output_plan_digest="4" * 64,
            private_plan_digest="5" * 64,
            execution_binding_digest="6" * 64,
            modulus=17,
        )

    connection = sqlite3.connect(ledger_path)
    try:
        legacy_state = connection.execute(
            """
            SELECT execution_binding_digest, consumed
            FROM prepared_f1m_batches
            WHERE commitment_token = ?
            """,
            (legacy_token,),
        ).fetchone()
    finally:
        connection.close()
    assert legacy_state == (None, 0)

    new_token = ledger.commit_prepared_f1m(
        (),
        query_id="query-new",
        version_id="version-1",
        output_plan_digest="4" * 64,
        private_plan_digest="5" * 64,
        execution_binding_digest="6" * 64,
        modulus=17,
    )
    ledger.verify_and_consume_prepared_f1m(
        (),
        commitment_token=new_token,
        query_id="query-new",
        version_id="version-1",
        output_plan_digest="4" * 64,
        private_plan_digest="5" * 64,
        execution_binding_digest="6" * 64,
        modulus=17,
    )


def test_disjoint_output_blocks_are_concatenated_without_masks() -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base-left", "rows-0-1", ((0, 0), (1, 1))),
            OutputShare("base-right", "rows-2-3", ((0, 2), (1, 3))),
        ),
    )

    analysis = analyze_output_plan(plan)

    assert analysis.reconstruction_mode == "concatenate"
    assert analysis.result_ciphertexts == 2
    assert analysis.masked_result_ciphertexts == 0
    assert analysis.overlap_coordinates == 0
    assert analysis.mask_random_elements == 0
    assert analysis.mask_mapped_elements == 0
    assert analysis.client_reorder_elements == 4
    assert analysis.client_modular_additions == 0


def test_uncovered_logical_coordinates_reconstruct_as_implicit_zero() -> None:
    plan = OutputPlan(
        logical_output_size=3,
        slot_count=2,
        shares=(OutputShare("base", "row-1", ((0, 1),)),),
    )

    analysis = analyze_output_plan(plan)

    assert analysis.reconstruction_mode == "concatenate"
    assert analysis.result_ciphertexts == 1
    assert analysis.implicit_zero_coordinates == 2
    assert analysis.client_reorder_elements == 1
    assert analysis.masked_result_ciphertexts == 0


def test_all_zero_output_plan_returns_no_ciphertexts() -> None:
    analysis = analyze_output_plan(
        OutputPlan(logical_output_size=4, slot_count=2, shares=())
    )

    assert analysis.result_ciphertexts == 0
    assert analysis.implicit_zero_coordinates == 4
    assert analysis.client_reorder_elements == 0
    assert analysis.masked_result_ciphertexts == 0


def test_overlapping_shares_receive_physical_zero_sum_masks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base", "all", ((0, 0), (1, 1), (2, 2), (3, 3))),
            OutputShare("delta", "all", ((0, 3), (1, 2), (2, 1), (3, 0))),
        ),
    )
    samples = iter((1, 2, 3, 4))
    monkeypatch.setattr(output_plan_module.secrets, "randbelow", lambda _: next(samples))

    masks = prepare_f1m_masks(
        plan,
        query_id="query-7",
        version_id="version-3",
        modulus=17,
        ledger=SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3"),
    )

    assert [(mask.component_id, mask.output_block_id) for mask in masks] == [
        ("base", "all"),
        ("delta", "all"),
    ]
    assert masks[0].values == (1, 2, 3, 4)
    assert masks[1].values == (13, 14, 15, 16)
    assert masks[0].binding == (
        "query-7",
        "version-3",
        masks[0].output_plan_digest,
        "base",
        "all",
    )
    analysis = analyze_output_plan(plan)
    assert analysis.masked_result_ciphertexts == 2
    assert analysis.mask_random_elements == 4
    assert analysis.mask_mapped_elements == 8
    assert analysis.client_modular_additions == 4


def test_partial_overlap_masks_only_the_contributing_ciphertexts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base-left", "rows-0-1", ((0, 0), (1, 1))),
            OutputShare("delta", "row-1", ((3, 1),)),
            OutputShare("base-right", "rows-2-3", ((0, 2), (1, 3))),
        ),
    )
    monkeypatch.setattr(output_plan_module.secrets, "randbelow", lambda _: 6)

    masks = prepare_f1m_masks(
        plan,
        query_id="q",
        version_id="v",
        modulus=17,
        ledger=SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3"),
    )

    assert [(mask.component_id, mask.values) for mask in masks] == [
        ("base-left", (0, 6, 0, 0)),
        ("delta", (0, 0, 0, 11)),
    ]
    analysis = analyze_output_plan(plan)
    assert analysis.result_ciphertexts == 3
    assert analysis.masked_result_ciphertexts == 2
    assert analysis.mask_random_elements == 1
    assert analysis.mask_mapped_elements == 2
    assert analysis.client_reorder_elements == 5
    assert analysis.client_modular_additions == 1


def test_three_contributors_use_two_random_values_and_one_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = OutputPlan(
        logical_output_size=1,
        slot_count=2,
        shares=(
            OutputShare("a", "out", ((0, 0),)),
            OutputShare("b", "out", ((1, 0),)),
            OutputShare("c", "out", ((0, 0),)),
        ),
    )
    samples = iter((5, 7))
    monkeypatch.setattr(output_plan_module.secrets, "randbelow", lambda _: next(samples))

    masks = prepare_f1m_masks(
        plan,
        query_id="q",
        version_id="v",
        modulus=17,
        ledger=SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3"),
    )

    assert [mask.values for mask in masks] == [(5, 0), (0, 7), (5, 0)]
    assert analyze_output_plan(plan).mask_random_elements == 2


def test_digest_is_canonical_but_changes_with_output_semantics() -> None:
    plan = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("z", "right", ((1, 1),)),
            OutputShare("a", "left", ((3, 0),)),
        ),
    )
    reordered = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("a", "left", ((3, 0),)),
            OutputShare("z", "right", ((1, 1),)),
        ),
    )
    changed_slot = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("a", "left", ((2, 0),)),
            OutputShare("z", "right", ((1, 1),)),
        ),
    )

    digest = analyze_output_plan(plan).output_plan_digest

    assert digest == "3954eda197eebd8d32ccb6dd477c6515be3dc38a6a29b9f1240894e60edbf196"
    assert digest == analyze_output_plan(reordered).output_plan_digest
    assert digest != analyze_output_plan(changed_slot).output_plan_digest
    assert len(digest) == 64


@pytest.mark.parametrize(
    "plan",
    [
        OutputPlan(1, 1, (OutputShare("base", "out", ((0, 0), (0, 0))),)),
        OutputPlan(1, 1, (OutputShare("base id", "out", ((0, 0),)),)),
        OutputPlan(
            1,
            1,
            (
                OutputShare("base", "out", ((0, 0),)),
                OutputShare("base", "out", ((0, 0),)),
            ),
        ),
    ],
)
def test_ambiguous_output_plans_are_rejected(plan: OutputPlan) -> None:
    with pytest.raises(OutputPlanError):
        analyze_output_plan(plan)


def test_os_randomness_result_must_be_an_element_of_z_t(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = OutputPlan(
        logical_output_size=1,
        slot_count=1,
        shares=(
            OutputShare("base", "out", ((0, 0),)),
            OutputShare("delta", "out", ((0, 0),)),
        ),
    )
    monkeypatch.setattr(output_plan_module.secrets, "randbelow", lambda _: 17)

    with pytest.raises(OutputPlanError, match="outside Z_t"):
        prepare_f1m_masks(
            plan,
            query_id="q",
            version_id="v",
            modulus=17,
            ledger=SQLiteMaskBindingLedger(tmp_path / "mask-bindings.sqlite3"),
        )
