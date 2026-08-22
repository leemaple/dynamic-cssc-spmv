from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from dynamic_cssc.cloud_execution_plan import (
    canonical_cloud_program_payload,
    canonical_execution_binding_payload,
)
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.output_plan import canonical_output_plan_payload
from dynamic_cssc.strong_execution import (
    F1MOperandKind,
    PreparedQueryOperand,
    StrongExecutionBundle,
    canonical_private_plan_payload,
    compile_strong_execution,
    execute_strong_plaintext,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import (
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
)

ROWS = 4096
COLS = 8193
EFFECTIVE_SLOTS = 4096
PHYSICAL_BATCH_SIZE = 8192
SEGMENT_WIDTH = 128
ACTIVE_DELTA_PAYLOAD = 127
PLAINTEXT_MODULUS = 65537
RING_DIMENSION = 8192
VERSION_ID = "strong-whole-query-witness-v2"
QUERY_ID = "strong-whole-query-witness-query-v2"
OPENFHE_VERSION = "1.5.1"
OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
WHOLE_QUERY_CONTRACT_FORMAT = "dynamic-cssc-strong-whole-query-contract-v2"
PREPARED_QUERY_CONTRACT_FORMAT = "dynamic-cssc-prepared-strong-query-contract-v2"

_BASE_STATE = {
    (0, 0): 2,
    (0, 1): 3,
    (0, 8192): 4,
    (4095, 7): 5,
}
_DELTA_ENTRIES = tuple(StrongEntry(0, 100 + offset, 1) for offset in range(127))


class _WitnessOnlyPreparedLedger:
    """Audit-only adapter; it provides no persistence, crash, or concurrency evidence."""

    def __init__(self) -> None:
        self._reserved = ()
        self._commitments = ()
        self._consumed = False

    def reserve_all(self, bindings: object) -> None:
        self._reserved = tuple(bindings)  # type: ignore[arg-type]

    def commit_prepared_f1m(self, commitments: object, **_: object) -> str:
        self._commitments = tuple(commitments)  # type: ignore[arg-type]
        return "f" * 64

    def verify_and_consume_prepared_f1m(
        self,
        commitments: object,
        **_: object,
    ) -> None:
        if self._consumed or tuple(commitments) != self._commitments:  # type: ignore[arg-type]
            raise RuntimeError("fixed witness prepared F1-M commitment mismatch")
        self._consumed = True


@dataclass(frozen=True, slots=True)
class StrongWholeQueryFixture:
    bundle: StrongExecutionBundle
    vector: tuple[int, ...]
    modulus: int
    query_operands: tuple[PreparedQueryOperand, ...]
    f1m_kinds: tuple[F1MOperandKind, ...]
    typed_plaintext_centered_output: tuple[int, ...]
    direct_centered_output: tuple[int, ...]

    @property
    def query_values_by_ciphertext(self) -> dict[str, tuple[int, ...]]:
        return {operand.ciphertext_id: operand.values for operand in self.query_operands}


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_prepared_query_contract(
    fixture: StrongWholeQueryFixture,
) -> dict[str, object]:
    """Serialize the fixed prepared query while redacting fresh F1-M values."""

    bundle = fixture.bundle
    return {
        "bindings": {
            "cloud_program_digest": bundle.cloud_program_digest,
            "execution_binding_digest": bundle.execution_binding_digest,
            "output_plan_digest": bundle.output_plan_digest,
            "private_plan_digest": bundle.private_plan_digest,
        },
        "f1m_operands": [
            {
                "ciphertext_id": route.f1m_ciphertext_id,
                "component_id": route.component_id,
                "kind": kind,
                "output_block_id": route.output_block_id,
                "result_id": route.result_id,
                "values_policy": (
                    "fresh-random-zero-sum-redacted"
                    if kind == "random-zero-sum"
                    else "exact-encrypted-zero"
                ),
            }
            for route, kind in zip(bundle.result_routes, fixture.f1m_kinds, strict=True)
        ],
        "format": PREPARED_QUERY_CONTRACT_FORMAT,
        "modulus": fixture.modulus,
        "query_id": QUERY_ID,
        "query_operands": [
            {
                "ciphertext_id": operand.ciphertext_id,
                "values": list(operand.values),
            }
            for operand in fixture.query_operands
        ],
        "vector_length": len(fixture.vector),
        "vector_nonzero_entries": [
            [column, value] for column, value in enumerate(fixture.vector) if value != 0
        ],
        "version_id": VERSION_ID,
    }


def canonical_whole_query_contract(
    fixture: StrongWholeQueryFixture,
) -> dict[str, object]:
    """Serialize all typed and private plans bound by the fixed witness."""

    bundle = fixture.bundle
    return {
        "cloud_program": canonical_cloud_program_payload(bundle.cloud_plan.program),
        "execution_binding": canonical_execution_binding_payload(bundle.cloud_plan.binding),
        "format": WHOLE_QUERY_CONTRACT_FORMAT,
        "output_plan": canonical_output_plan_payload(bundle.output_plan),
        "prepared_query": canonical_prepared_query_contract(fixture),
        "private_plan": canonical_private_plan_payload(bundle),
    }


def strong_whole_query_bindings(
    fixture: StrongWholeQueryFixture,
) -> dict[str, str]:
    bundle = fixture.bundle
    prepared_contract = canonical_prepared_query_contract(fixture)
    whole_query_contract = canonical_whole_query_contract(fixture)
    if fixture.typed_plaintext_centered_output != fixture.direct_centered_output:
        raise ValueError("typed plaintext and direct SpMV witness oracles disagree")
    return {
        "cloud_program_digest": bundle.cloud_program_digest,
        "execution_binding_digest": bundle.execution_binding_digest,
        "expected_centered_output_digest": _canonical_digest(list(fixture.direct_centered_output)),
        "output_plan_digest": bundle.output_plan_digest,
        "prepared_query_contract_digest": _canonical_digest(prepared_contract),
        "private_plan_digest": bundle.private_plan_digest,
        "whole_query_contract_digest": _canonical_digest(whole_query_contract),
    }


def _centered(values: tuple[int, ...], modulus: int) -> tuple[int, ...]:
    midpoint = modulus // 2
    return tuple(value - modulus if value > midpoint else value for value in values)


def _query_vector() -> tuple[int, ...]:
    vector = [0] * COLS
    vector[0] = 1
    vector[1] = 2
    vector[7] = 4
    vector[8192] = -3
    for column in range(100, 100 + ACTIVE_DELTA_PAYLOAD):
        vector[column] = 1
    return tuple(vector)


def _direct_spmv(vector: tuple[int, ...]) -> tuple[int, ...]:
    output = [0] * ROWS
    for (row, column), value in _BASE_STATE.items():
        output[row] += value * vector[column]
    for entry in _DELTA_ENTRIES:
        output[entry.row] += entry.value * vector[entry.col]
    modular = tuple(value % PLAINTEXT_MODULUS for value in output)
    return _centered(modular, PLAINTEXT_MODULUS)


def build_strong_whole_query_fixture() -> StrongWholeQueryFixture:
    """Build and execute the fixed Phase 2 whole-query witness fixture."""

    base = publish_component(
        _BASE_STATE,
        rows=ROWS,
        cols=COLS,
        effective_slots=EFFECTIVE_SLOTS,
        partition_rows=2048,
        version_id=VERSION_ID,
        component_prefix="base",
    )
    empty_delta = initialize_segmented_delta(
        rows=ROWS,
        cols=COLS,
        effective_slots=EFFECTIVE_SLOTS,
        segment_width=SEGMENT_WIDTH,
        matrix_value_bound=16,
        version_id="strong-whole-query-witness-empty-v1",
    )
    delta = advance_segmented_delta(
        empty_delta,
        delta_updates=(),
        overflow_entries=_DELTA_ENTRIES,
        version_id=VERSION_ID,
    ).state
    bundle = compile_strong_execution(base, delta)
    vector = _query_vector()
    ledger = _WitnessOnlyPreparedLedger()
    prepared = prepare_strong_query(
        bundle,
        query_id=QUERY_ID,
        vector=vector,
        modulus=PLAINTEXT_MODULUS,
        ledger=ledger,
    )
    typed_output = execute_strong_plaintext(
        bundle,
        prepared,
        modulus=PLAINTEXT_MODULUS,
        ledger=ledger,
    )
    return StrongWholeQueryFixture(
        bundle=bundle,
        vector=vector,
        modulus=PLAINTEXT_MODULUS,
        query_operands=prepared.query_operands,
        f1m_kinds=tuple(operand.kind for operand in prepared.f1m_operands),
        typed_plaintext_centered_output=_centered(typed_output, PLAINTEXT_MODULUS),
        direct_centered_output=_direct_spmv(vector),
    )
