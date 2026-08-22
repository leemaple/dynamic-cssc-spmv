from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, TypeAlias

from dynamic_cssc.output_plan import OutputPlan, analyze_output_plan

if TYPE_CHECKING:
    from dynamic_cssc.cloud_execution_plan import CloudExecutionPlan
    from dynamic_cssc.query_compiler import CompiledQuery, F1MPolicy

Coordinate: TypeAlias = tuple[int, int]
ShareIdentity: TypeAlias = tuple[str, str]
PlaintextVector: TypeAlias = tuple[int, ...]


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise ValueError(f"{field} must be a positive strict integer")
    return value


def _modulus(value: object) -> int:
    if not _is_strict_int(value) or value < 2:
        raise ValueError("modulus must be a strict integer of at least two")
    return value


def _vector(
    value: object,
    *,
    length: int,
    field: str,
) -> PlaintextVector:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field} must be an integer sequence")
    if len(value) != length:
        raise ValueError(f"{field} must have length {length}")
    if not all(_is_strict_int(element) for element in value):
        raise ValueError(f"{field} must contain strict integers")
    return tuple(value)


def direct_spmv(
    matrix: Mapping[Coordinate, int],
    vector: Sequence[int],
    *,
    rows: int,
    cols: int,
    modulus: int,
) -> PlaintextVector:
    """Evaluate a sparse matrix directly in the global column-address domain."""

    rows = _positive_int(rows, "rows")
    cols = _positive_int(cols, "cols")
    modulus = _modulus(modulus)
    if not isinstance(matrix, Mapping):
        raise ValueError("matrix must be a coordinate-to-value mapping")
    dense_vector = _vector(vector, length=cols, field="vector")
    result = [0] * rows
    for coordinate, value in matrix.items():
        if (
            not isinstance(coordinate, tuple)
            or len(coordinate) != 2
            or not all(_is_strict_int(axis) for axis in coordinate)
        ):
            raise ValueError("matrix coordinates must be strict integer pairs")
        row, global_col = coordinate
        if not 0 <= row < rows or not 0 <= global_col < cols:
            raise ValueError("matrix coordinate is outside the matrix")
        if not _is_strict_int(value) or value == 0:
            raise ValueError("matrix values must be nonzero strict integers")
        result[row] = (result[row] + value * dense_vector[global_col]) % modulus
    return tuple(result)


def reconstruct_output(
    plan: OutputPlan,
    returned_shares: Mapping[ShareIdentity, Sequence[int]],
    *,
    modulus: int,
) -> PlaintextVector:
    """Reconstruct logical rows solely through OutputShare identities and mappings."""

    modulus = _modulus(modulus)
    analyze_output_plan(plan)
    if not isinstance(returned_shares, Mapping):
        raise ValueError("returned_shares must be an OutputShare-identity mapping")
    expected_ids = {(share.component_id, share.output_block_id) for share in plan.shares}
    if set(returned_shares) != expected_ids:
        raise ValueError("returned share identities must exactly match the OutputPlan")
    result = [0] * plan.logical_output_size
    for share in plan.shares:
        share_id = (share.component_id, share.output_block_id)
        lanes = _vector(
            returned_shares[share_id],
            length=plan.slot_count,
            field=f"returned share {share_id!r}",
        )
        for physical_lane, logical_coordinate in share.slot_to_logical:
            result[logical_coordinate] = (
                result[logical_coordinate] + lanes[physical_lane]
            ) % modulus
    return tuple(result)


def execute_cloud_plan(
    plan: CloudExecutionPlan,
    *,
    ciphertext_inputs: Mapping[str, Sequence[int]],
    plaintext_masks: Mapping[str, Sequence[int]],
    modulus: int,
) -> dict[str, PlaintextVector]:
    """Execute a strict uniform-F1M Cloud plan over plaintext modular vectors."""

    from dynamic_cssc.cloud_execution_plan import validate_cloud_execution_plan

    modulus = _modulus(modulus)
    validate_cloud_execution_plan(plan)
    return _execute_validated_cloud_plan(
        plan,
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks=plaintext_masks,
        modulus=modulus,
    )


def execute_compiled_query(
    compiled: CompiledQuery,
    *,
    expected_f1m_policy: F1MPolicy,
    ciphertext_inputs: Mapping[str, Sequence[int]],
    plaintext_masks: Mapping[str, Sequence[int]],
    modulus: int,
) -> dict[str, PlaintextVector]:
    """Execute a validated CompiledQuery only under the caller-authorized F1M policy."""

    from dynamic_cssc.query_compiler import (
        CompiledQuery,
        QueryCompilerError,
        is_canonical_f1m_policy,
        validate_compiled_query,
    )

    if not isinstance(compiled, CompiledQuery):
        raise QueryCompilerError("compiled must be a CompiledQuery")
    if not is_canonical_f1m_policy(compiled.f1m_policy):
        raise QueryCompilerError("CompiledQuery f1m_policy is unsupported")
    if not is_canonical_f1m_policy(expected_f1m_policy):
        raise QueryCompilerError("expected_f1m_policy is unsupported")
    if expected_f1m_policy != compiled.f1m_policy:
        raise QueryCompilerError("expected_f1m_policy does not match the CompiledQuery policy")
    modulus = _modulus(modulus)
    validate_compiled_query(compiled)
    return _execute_validated_cloud_plan(
        compiled.cloud_plan,
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks=plaintext_masks,
        modulus=modulus,
    )


def _execute_validated_cloud_plan(
    plan: CloudExecutionPlan,
    *,
    ciphertext_inputs: Mapping[str, Sequence[int]],
    plaintext_masks: Mapping[str, Sequence[int]],
    modulus: int,
) -> dict[str, PlaintextVector]:
    """Execute a plan whose policy and binding were validated at its public seam."""

    from dynamic_cssc.cloud_execution_plan import (
        AddCiphertexts,
        AddF1MMask,
        MultiplyCiphertexts,
        MultiplyPlaintextMask,
        Relinearize,
        ReturnResult,
        Rotate,
    )

    program = plan.program
    if not isinstance(ciphertext_inputs, Mapping):
        raise ValueError("ciphertext_inputs must be a mapping")
    if not isinstance(plaintext_masks, Mapping):
        raise ValueError("plaintext_masks must be a mapping")
    expected_ciphertexts = {operand.ciphertext_id for operand in program.ciphertext_inputs}
    expected_masks = {operand.mask_id for operand in program.plaintext_masks}
    if any(
        abs(openfhe_index) >= program.slot_count
        for _, openfhe_index in program.rotation_catalog.entries
    ):
        raise ValueError("single-effective-row v1 rotation index is outside the slot range")
    if set(ciphertext_inputs) != expected_ciphertexts:
        raise ValueError("ciphertext input IDs must exactly match the typed plan")
    if set(plaintext_masks) != expected_masks:
        raise ValueError("plaintext mask IDs must exactly match the typed plan")

    ciphertexts = {
        operand.ciphertext_id: tuple(
            value % modulus
            for value in _vector(
                ciphertext_inputs[operand.ciphertext_id],
                length=operand.length,
                field=f"ciphertext input {operand.ciphertext_id!r}",
            )
        )
        for operand in program.ciphertext_inputs
    }
    masks: dict[str, PlaintextVector] = {}
    for operand in program.plaintext_masks:
        supplied = _vector(
            plaintext_masks[operand.mask_id],
            length=operand.length,
            field=f"plaintext mask {operand.mask_id!r}",
        )
        if supplied != operand.values:
            raise ValueError("supplied values must equal the committed plaintext mask")
        masks[operand.mask_id] = tuple(value % modulus for value in supplied)
    rotations = dict(program.rotation_catalog.entries)
    results: dict[str, PlaintextVector] = {}

    def pointwise(
        left: PlaintextVector,
        right: PlaintextVector,
        operation: str,
    ) -> PlaintextVector:
        if operation == "multiply":
            return tuple(
                (left_value * right_value) % modulus
                for left_value, right_value in zip(left, right, strict=True)
            )
        return tuple(
            (left_value + right_value) % modulus
            for left_value, right_value in zip(left, right, strict=True)
        )

    for node in program.nodes:
        if isinstance(node, MultiplyCiphertexts):
            ciphertexts[node.result_id] = pointwise(
                ciphertexts[node.left_id], ciphertexts[node.right_id], "multiply"
            )
        elif isinstance(node, Relinearize):
            ciphertexts[node.result_id] = ciphertexts[node.ciphertext_id]
        elif isinstance(node, Rotate):
            if rotations.get(node.logical_shift) != node.openfhe_index:
                raise ValueError("rotation does not match the plan's exact catalog")
            source = ciphertexts[node.ciphertext_id]
            ciphertexts[node.result_id] = tuple(
                source[(lane + node.openfhe_index) % len(source)] for lane in range(len(source))
            )
        elif isinstance(node, MultiplyPlaintextMask):
            ciphertexts[node.result_id] = pointwise(
                ciphertexts[node.ciphertext_id], masks[node.mask_id], "multiply"
            )
        elif isinstance(node, AddCiphertexts):
            ciphertexts[node.result_id] = pointwise(
                ciphertexts[node.left_id], ciphertexts[node.right_id], "add"
            )
        elif isinstance(node, AddF1MMask):
            ciphertexts[node.result_id] = pointwise(
                ciphertexts[node.ciphertext_id],
                ciphertexts[node.mask_ciphertext_id],
                "add",
            )
        elif isinstance(node, ReturnResult):
            results[node.result_id] = ciphertexts[node.ciphertext_id]
        else:  # pragma: no cover - typed validation rejects this before execution
            raise ValueError("typed Cloud plan contains an unsupported node")
    return results
