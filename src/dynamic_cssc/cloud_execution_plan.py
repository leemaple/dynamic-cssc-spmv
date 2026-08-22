from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Literal, TypeAlias

CLOUD_PROGRAM_FORMAT = "dynamic-cssc-cloud-program-v1"
EXECUTION_BINDING_FORMAT = "dynamic-cssc-execution-binding-v1"
CLOUD_EXECUTION_PLAN_FORMAT = "dynamic-cssc-cloud-execution-plan-v1"
CLOUD_PLAN_DIGEST_ALGORITHM = "sha256-canonical-json-v1"

CiphertextRole: TypeAlias = Literal["value", "query", "f1m-mask"]
PlaintextMaskRole: TypeAlias = Literal["selection"]
F1MMaskRole: TypeAlias = Literal["opaque-zero-sum"]


class CloudExecutionPlanError(ValueError):
    """Raised when a cloud-visible execution plan violates the protocol contract."""


@dataclass(frozen=True, slots=True)
class CiphertextInput:
    ciphertext_id: str
    role: CiphertextRole
    length: int


@dataclass(frozen=True, slots=True)
class PlaintextMask:
    mask_id: str
    role: PlaintextMaskRole
    length: int
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class MultiplyCiphertexts:
    result_id: str
    left_id: str
    right_id: str


@dataclass(frozen=True, slots=True)
class Relinearize:
    result_id: str
    ciphertext_id: str


@dataclass(frozen=True, slots=True)
class Rotate:
    result_id: str
    ciphertext_id: str
    logical_shift: int
    openfhe_index: int


@dataclass(frozen=True, slots=True)
class MultiplyPlaintextMask:
    result_id: str
    ciphertext_id: str
    mask_id: str


@dataclass(frozen=True, slots=True)
class AddCiphertexts:
    result_id: str
    left_id: str
    right_id: str


@dataclass(frozen=True, slots=True)
class AddF1MMask:
    result_id: str
    ciphertext_id: str
    mask_ciphertext_id: str
    mask_role: F1MMaskRole


@dataclass(frozen=True, slots=True)
class ReturnResult:
    result_id: str
    ciphertext_id: str


CloudNode: TypeAlias = (
    MultiplyCiphertexts
    | Relinearize
    | Rotate
    | MultiplyPlaintextMask
    | AddCiphertexts
    | AddF1MMask
    | ReturnResult
)


@dataclass(frozen=True, slots=True)
class RotationCatalog:
    entries: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class CloudProgram:
    format: str
    slot_count: int
    ciphertext_inputs: tuple[CiphertextInput, ...]
    plaintext_masks: tuple[PlaintextMask, ...]
    nodes: tuple[CloudNode, ...]
    result_ids: tuple[str, ...]
    rotation_catalog: RotationCatalog


@dataclass(frozen=True, slots=True)
class ExecutionBinding:
    format: str
    version_id: str
    output_plan_digest: str
    cloud_program_digest: str


@dataclass(frozen=True, slots=True)
class CloudExecutionPlan:
    program: CloudProgram
    binding: ExecutionBinding


@dataclass(frozen=True, slots=True)
class CloudPlanCounts:
    ciphertext_inputs: int
    ciphertext_inputs_by_role: tuple[tuple[str, int], ...]
    plaintext_masks: int
    multiply_ciphertexts: int
    relinearizations: int
    rotations: int
    rotations_by_exact_index: tuple[tuple[int, int], ...]
    multiply_plaintext_masks: int
    add_ciphertexts: int
    add_f1m_masks: int
    returned_ciphertexts: int


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise CloudExecutionPlanError(f"{field} must be a positive integer")
    return value


def _require_id(value: object, field: str) -> str:
    invalid_character = isinstance(value, str) and any(
        not 0x21 <= ord(character) <= 0x7E for character in value
    )
    if not isinstance(value, str) or not value or invalid_character:
        raise CloudExecutionPlanError(f"{field} must be a non-empty printable ASCII identifier")
    return value


def _require_tuple(value: object, field: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        raise CloudExecutionPlanError(f"{field} must be a tuple")
    return value


def _validate_rotation_catalog(catalog: RotationCatalog) -> dict[int, int]:
    if not isinstance(catalog, RotationCatalog):
        raise CloudExecutionPlanError("rotation_catalog must be a RotationCatalog")
    _require_tuple(catalog.entries, "rotation_catalog.entries")
    rotations: dict[int, int] = {}
    for entry in catalog.entries:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise CloudExecutionPlanError("rotation catalog entries must be integer pairs")
        logical_shift, openfhe_index = entry
        if not _is_strict_int(logical_shift) or logical_shift == 0:
            raise CloudExecutionPlanError("logical_shift must be a non-zero integer")
        if not _is_strict_int(openfhe_index) or openfhe_index == 0:
            raise CloudExecutionPlanError("openfhe_index must be a non-zero integer")
        if logical_shift in rotations:
            raise CloudExecutionPlanError("rotation catalog logical shifts must be unique")
        rotations[logical_shift] = openfhe_index
    return rotations


def build_fixed_stride_cloud_program(
    *,
    page_count: int,
    effective_slots: int,
    segment_width: int,
) -> CloudProgram:
    """Build the fixed public schedule from page count and uniform page shape only."""

    if not _is_strict_int(page_count) or page_count < 0:
        raise CloudExecutionPlanError("page_count must be a non-negative integer")
    effective_slots = _require_positive_int(effective_slots, "effective_slots")
    if (
        not _is_strict_int(segment_width)
        or segment_width < 2
        or segment_width > effective_slots
        or segment_width & (segment_width - 1)
    ):
        raise CloudExecutionPlanError(
            "segment_width must be a power of two in [2, effective_slots]"
        )

    shifts: list[int] = []
    shift = 1
    while shift < segment_width:
        shifts.append(shift)
        shift *= 2
    selection_values = tuple(
        1
        if lane < effective_slots // segment_width * segment_width and lane % segment_width == 0
        else 0
        for lane in range(effective_slots)
    )
    ciphertext_inputs: list[CiphertextInput] = []
    plaintext_masks: list[PlaintextMask] = []
    nodes: list[CloudNode] = []
    result_ids: list[str] = []
    for page_ordinal in range(page_count):
        ordinal = f"{page_ordinal:06d}"
        value_id = f"ct-value-{ordinal}"
        query_id = f"ct-query-{ordinal}"
        f1m_id = f"ct-f1m-{ordinal}"
        selection_id = f"pt-selection-{ordinal}"
        ciphertext_inputs.extend(
            (
                CiphertextInput(value_id, "value", effective_slots),
                CiphertextInput(query_id, "query", effective_slots),
                CiphertextInput(f1m_id, "f1m-mask", effective_slots),
            )
        )
        plaintext_masks.append(
            PlaintextMask(selection_id, "selection", effective_slots, selection_values)
        )

        product_id = f"ssa-product-{ordinal}"
        relinearized_id = f"ssa-relinearized-{ordinal}"
        nodes.extend(
            (
                MultiplyCiphertexts(product_id, value_id, query_id),
                Relinearize(relinearized_id, product_id),
            )
        )
        accumulated_id = relinearized_id
        for logical_shift in shifts:
            rotated_id = f"ssa-rotate-{ordinal}-{logical_shift:06d}"
            sum_id = f"ssa-sum-{ordinal}-{logical_shift * 2:06d}"
            nodes.extend(
                (
                    Rotate(
                        rotated_id,
                        accumulated_id,
                        logical_shift,
                        logical_shift,
                    ),
                    AddCiphertexts(sum_id, accumulated_id, rotated_id),
                )
            )
            accumulated_id = sum_id
        selected_id = f"ssa-selected-{ordinal}"
        masked_id = f"ssa-masked-{ordinal}"
        result_id = f"page-{ordinal}"
        nodes.extend(
            (
                MultiplyPlaintextMask(selected_id, accumulated_id, selection_id),
                AddF1MMask(masked_id, selected_id, f1m_id, "opaque-zero-sum"),
                ReturnResult(result_id, masked_id),
            )
        )
        result_ids.append(result_id)

    program = CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=effective_slots,
        ciphertext_inputs=tuple(ciphertext_inputs),
        plaintext_masks=tuple(plaintext_masks),
        nodes=tuple(nodes),
        result_ids=tuple(result_ids),
        rotation_catalog=RotationCatalog(
            tuple((logical_shift, logical_shift) for logical_shift in shifts) if page_count else ()
        ),
    )
    validate_cloud_program(program)
    return program


def validate_cloud_program(program: CloudProgram) -> None:
    """Validate the strict uniform-F1M public program contract."""

    _validate_cloud_program(program, required_masked_result_ids=None)


def _validate_cloud_program(
    program: CloudProgram,
    *,
    required_masked_result_ids: frozenset[str] | None,
) -> None:
    """Validate the typed DAG and an exact result-level F1M schedule.

    ``None`` preserves the original strict contract: every returned result has one F1M
    addition.  A concrete set is used only by the common compiler after deriving that set
    from its private OutputPlan and result routes.
    """

    if not isinstance(program, CloudProgram):
        raise CloudExecutionPlanError("program must be a CloudProgram")
    if program.format != CLOUD_PROGRAM_FORMAT:
        raise CloudExecutionPlanError(f"program format must be {CLOUD_PROGRAM_FORMAT}")
    slot_count = _require_positive_int(program.slot_count, "slot_count")
    _require_tuple(program.ciphertext_inputs, "ciphertext_inputs")
    _require_tuple(program.plaintext_masks, "plaintext_masks")
    _require_tuple(program.nodes, "nodes")
    _require_tuple(program.result_ids, "result_ids")
    rotations = _validate_rotation_catalog(program.rotation_catalog)

    ciphertext_lengths: dict[str, int] = {}
    ciphertext_roles: dict[str, str] = {}
    plaintext_lengths: dict[str, int] = {}
    declared_ids: set[str] = set()
    for operand in program.ciphertext_inputs:
        if not isinstance(operand, CiphertextInput):
            raise CloudExecutionPlanError("ciphertext_inputs must contain CiphertextInput values")
        ciphertext_id = _require_id(operand.ciphertext_id, "ciphertext_id")
        if ciphertext_id in declared_ids:
            raise CloudExecutionPlanError("all operand and SSA identifiers must be unique")
        if operand.role not in ("value", "query", "f1m-mask"):
            raise CloudExecutionPlanError("ciphertext input has an unsupported role")
        length = _require_positive_int(operand.length, "ciphertext input length")
        if length != slot_count:
            raise CloudExecutionPlanError("ciphertext input length must equal slot_count")
        declared_ids.add(ciphertext_id)
        ciphertext_lengths[ciphertext_id] = length
        ciphertext_roles[ciphertext_id] = operand.role

    for operand in program.plaintext_masks:
        if not isinstance(operand, PlaintextMask):
            raise CloudExecutionPlanError("plaintext_masks must contain PlaintextMask values")
        mask_id = _require_id(operand.mask_id, "mask_id")
        if mask_id in declared_ids:
            raise CloudExecutionPlanError("all operand and SSA identifiers must be unique")
        if operand.role != "selection":
            raise CloudExecutionPlanError("plaintext mask has an unsupported role")
        length = _require_positive_int(operand.length, "plaintext mask length")
        if length != slot_count:
            raise CloudExecutionPlanError("plaintext mask length must equal slot_count")
        _require_tuple(operand.values, "plaintext mask values")
        if len(operand.values) != length:
            raise CloudExecutionPlanError("plaintext mask values length must equal length")
        if any(not _is_strict_int(value) or value not in (0, 1) for value in operand.values):
            raise CloudExecutionPlanError("selection plaintext mask values must be strict 0/1")
        declared_ids.add(mask_id)
        plaintext_lengths[mask_id] = length

    operand_ids = set(declared_ids)

    node_by_result: dict[str, CloudNode] = {}
    dependencies: dict[str, tuple[str, ...]] = {}
    return_nodes: list[ReturnResult] = []
    f1m_return_counts: Counter[str] = Counter()

    def require_ciphertext(ciphertext_id: object, field: str) -> int:
        resolved_id = _require_id(ciphertext_id, field)
        if resolved_id not in ciphertext_lengths:
            raise CloudExecutionPlanError(f"{field} must reference a previously defined ciphertext")
        return ciphertext_lengths[resolved_id]

    def define_result(result_id: object, length: int, node: CloudNode) -> str:
        resolved_id = _require_id(result_id, "result_id")
        if resolved_id in declared_ids:
            raise CloudExecutionPlanError("all operand and SSA identifiers must be unique")
        declared_ids.add(resolved_id)
        ciphertext_lengths[resolved_id] = length
        ciphertext_roles[resolved_id] = "computed"
        node_by_result[resolved_id] = node
        return resolved_id

    for node in program.nodes:
        if isinstance(node, MultiplyCiphertexts):
            left_length = require_ciphertext(node.left_id, "left_id")
            right_length = require_ciphertext(node.right_id, "right_id")
            if left_length != right_length:
                raise CloudExecutionPlanError("ciphertext multiplication lengths must match")
            if {ciphertext_roles[node.left_id], ciphertext_roles[node.right_id]} != {
                "query",
                "value",
            }:
                raise CloudExecutionPlanError(
                    "MultiplyCiphertexts operands must have value and query roles"
                )
            result_id = define_result(node.result_id, left_length, node)
            dependencies[result_id] = (node.left_id, node.right_id)
        elif isinstance(node, Relinearize):
            length = require_ciphertext(node.ciphertext_id, "ciphertext_id")
            if not isinstance(node_by_result.get(node.ciphertext_id), MultiplyCiphertexts):
                raise CloudExecutionPlanError(
                    "Relinearize input must be a direct MultiplyCiphertexts result"
                )
            result_id = define_result(node.result_id, length, node)
            dependencies[result_id] = (node.ciphertext_id,)
        elif isinstance(node, Rotate):
            length = require_ciphertext(node.ciphertext_id, "ciphertext_id")
            if not _is_strict_int(node.logical_shift) or node.logical_shift == 0:
                raise CloudExecutionPlanError("Rotate.logical_shift must be a non-zero integer")
            if not _is_strict_int(node.openfhe_index) or node.openfhe_index == 0:
                raise CloudExecutionPlanError("Rotate.openfhe_index must be a non-zero integer")
            if rotations.get(node.logical_shift) != node.openfhe_index:
                raise CloudExecutionPlanError(
                    "Rotate must use the exact logical-shift/OpenFHE-index catalog entry"
                )
            result_id = define_result(node.result_id, length, node)
            dependencies[result_id] = (node.ciphertext_id,)
        elif isinstance(node, MultiplyPlaintextMask):
            length = require_ciphertext(node.ciphertext_id, "ciphertext_id")
            mask_id = _require_id(node.mask_id, "mask_id")
            if mask_id not in plaintext_lengths:
                raise CloudExecutionPlanError("mask_id must reference a declared plaintext mask")
            if plaintext_lengths[mask_id] != length:
                raise CloudExecutionPlanError("ciphertext and plaintext mask lengths must match")
            result_id = define_result(node.result_id, length, node)
            dependencies[result_id] = (node.ciphertext_id, node.mask_id)
        elif isinstance(node, AddCiphertexts):
            left_length = require_ciphertext(node.left_id, "left_id")
            right_length = require_ciphertext(node.right_id, "right_id")
            if left_length != right_length:
                raise CloudExecutionPlanError("ciphertext addition lengths must match")
            result_id = define_result(node.result_id, left_length, node)
            dependencies[result_id] = (node.left_id, node.right_id)
        elif isinstance(node, AddF1MMask):
            length = require_ciphertext(node.ciphertext_id, "ciphertext_id")
            mask_length = require_ciphertext(node.mask_ciphertext_id, "mask_ciphertext_id")
            if ciphertext_roles[node.mask_ciphertext_id] != "f1m-mask":
                raise CloudExecutionPlanError(
                    "mask_ciphertext_id must reference an f1m-mask ciphertext input"
                )
            if node.mask_role != "opaque-zero-sum":
                raise CloudExecutionPlanError("AddF1MMask has an unsupported mask role")
            if length != mask_length:
                raise CloudExecutionPlanError("result and F1M mask lengths must match")
            result_id = define_result(node.result_id, length, node)
            dependencies[result_id] = (node.ciphertext_id, node.mask_ciphertext_id)
        elif isinstance(node, ReturnResult):
            return_id = _require_id(node.result_id, "result_id")
            require_ciphertext(node.ciphertext_id, "ciphertext_id")
            if return_id in declared_ids:
                raise CloudExecutionPlanError("all operand and SSA identifiers must be unique")
            producer = node_by_result.get(node.ciphertext_id)
            requires_mask = (
                required_masked_result_ids is None or return_id in required_masked_result_ids
            )
            if requires_mask and not isinstance(producer, AddF1MMask):
                raise CloudExecutionPlanError(
                    "each ReturnResult must directly return one AddF1MMask result"
                    if required_masked_result_ids is None
                    else "each required result must directly return one AddF1MMask result"
                )
            if not requires_mask and isinstance(producer, AddF1MMask):
                raise CloudExecutionPlanError("a nonrequired result must not add an F1M mask")
            if not requires_mask and not isinstance(
                producer,
                (Relinearize, MultiplyPlaintextMask, AddCiphertexts),
            ):
                raise CloudExecutionPlanError(
                    "an unmasked result must return a final evaluated ciphertext"
                )
            declared_ids.add(return_id)
            return_nodes.append(node)
            if isinstance(producer, AddF1MMask):
                f1m_return_counts[node.ciphertext_id] += 1
        else:
            raise CloudExecutionPlanError("nodes contain an unsupported node type")

    expected_result_ids = tuple(node.result_id for node in return_nodes)
    for result_id in program.result_ids:
        _require_id(result_id, "result_ids entry")
    if program.result_ids != expected_result_ids:
        raise CloudExecutionPlanError(
            "result_ids must exactly match ReturnResult identifiers in program order"
        )
    if required_masked_result_ids is not None:
        for result_id in required_masked_result_ids:
            _require_id(result_id, "required masked result ID")
        if not required_masked_result_ids <= set(program.result_ids):
            raise CloudExecutionPlanError(
                "required masked result IDs must be a subset of returned result IDs"
            )
    f1m_result_ids = {
        result_id for result_id, node in node_by_result.items() if isinstance(node, AddF1MMask)
    }
    if any(f1m_return_counts[result_id] != 1 for result_id in f1m_result_ids):
        raise CloudExecutionPlanError("each AddF1MMask result must be returned exactly once")
    f1m_operand_uses = Counter(
        node.mask_ciphertext_id for node in node_by_result.values() if isinstance(node, AddF1MMask)
    )
    f1m_operand_ids = {
        operand.ciphertext_id for operand in program.ciphertext_inputs if operand.role == "f1m-mask"
    }
    if any(f1m_operand_uses[operand_id] != 1 for operand_id in f1m_operand_ids):
        raise CloudExecutionPlanError("each F1M mask operand must be consumed exactly once")

    consumers: dict[str, list[CloudNode]] = {}
    for consumer_result_id, dependency_ids in dependencies.items():
        consumer = node_by_result[consumer_result_id]
        for dependency_id in dependency_ids:
            consumers.setdefault(dependency_id, []).append(consumer)
    for operand in program.ciphertext_inputs:
        operand_consumers = consumers.get(operand.ciphertext_id, [])
        if operand.role in ("value", "query") and (
            len(operand_consumers) != 1 or not isinstance(operand_consumers[0], MultiplyCiphertexts)
        ):
            raise CloudExecutionPlanError(
                "value and query operands must each be consumed by one MultiplyCiphertexts node"
            )
        if operand.role == "f1m-mask" and (
            len(operand_consumers) != 1
            or not isinstance(operand_consumers[0], AddF1MMask)
            or operand_consumers[0].mask_ciphertext_id != operand.ciphertext_id
        ):
            raise CloudExecutionPlanError(
                "F1M mask operands may only be consumed as one AddF1MMask mask operand"
            )
    for result_id, node in node_by_result.items():
        if isinstance(node, MultiplyCiphertexts):
            result_consumers = consumers.get(result_id, [])
            if len(result_consumers) != 1 or not isinstance(result_consumers[0], Relinearize):
                raise CloudExecutionPlanError(
                    "each MultiplyCiphertexts result must feed one direct Relinearize"
                )

    live_ids = {node.ciphertext_id for node in return_nodes}
    worklist = list(live_ids)
    while worklist:
        result_id = worklist.pop()
        for dependency_id in dependencies.get(result_id, ()):
            if dependency_id in node_by_result and dependency_id not in live_ids:
                live_ids.add(dependency_id)
                worklist.append(dependency_id)
    dead_results = set(node_by_result) - live_ids
    if dead_results:
        raise CloudExecutionPlanError("every computation node must contribute to a returned result")
    used_operand_ids = {
        dependency_id
        for dependency_ids in dependencies.values()
        for dependency_id in dependency_ids
        if dependency_id in operand_ids
    }
    if used_operand_ids != operand_ids:
        raise CloudExecutionPlanError("every declared operand must contribute to a returned result")


def _node_payload(node: CloudNode) -> dict[str, object]:
    if isinstance(node, MultiplyCiphertexts):
        return {
            "left_id": node.left_id,
            "op": "multiply-ciphertexts",
            "result_id": node.result_id,
            "right_id": node.right_id,
        }
    if isinstance(node, Relinearize):
        return {
            "ciphertext_id": node.ciphertext_id,
            "op": "relinearize",
            "result_id": node.result_id,
        }
    if isinstance(node, Rotate):
        return {
            "ciphertext_id": node.ciphertext_id,
            "logical_shift": node.logical_shift,
            "openfhe_index": node.openfhe_index,
            "op": "rotate",
            "result_id": node.result_id,
        }
    if isinstance(node, MultiplyPlaintextMask):
        return {
            "ciphertext_id": node.ciphertext_id,
            "mask_id": node.mask_id,
            "op": "multiply-plaintext-mask",
            "result_id": node.result_id,
        }
    if isinstance(node, AddCiphertexts):
        return {
            "left_id": node.left_id,
            "op": "add-ciphertexts",
            "result_id": node.result_id,
            "right_id": node.right_id,
        }
    if isinstance(node, AddF1MMask):
        return {
            "ciphertext_id": node.ciphertext_id,
            "mask_ciphertext_id": node.mask_ciphertext_id,
            "mask_role": node.mask_role,
            "op": "add-f1m-mask",
            "result_id": node.result_id,
        }
    if isinstance(node, ReturnResult):
        return {
            "ciphertext_id": node.ciphertext_id,
            "op": "return-result",
            "result_id": node.result_id,
        }
    raise CloudExecutionPlanError("cannot serialize an unsupported node type")


def _masked_return_result_ids(program: CloudProgram) -> frozenset[str]:
    f1m_results = {node.result_id for node in program.nodes if isinstance(node, AddF1MMask)}
    return frozenset(
        node.result_id
        for node in program.nodes
        if isinstance(node, ReturnResult) and node.ciphertext_id in f1m_results
    )


def canonical_cloud_program_payload(program: CloudProgram) -> dict[str, object]:
    """Return the exact closed-key public program payload."""

    _validate_cloud_program(
        program,
        required_masked_result_ids=_masked_return_result_ids(program),
    )
    return {
        "ciphertext_inputs": [
            {
                "ciphertext_id": operand.ciphertext_id,
                "length": operand.length,
                "role": operand.role,
            }
            for operand in sorted(program.ciphertext_inputs, key=lambda item: item.ciphertext_id)
        ],
        "format": program.format,
        "nodes": [_node_payload(node) for node in program.nodes],
        "plaintext_masks": [
            {
                "length": operand.length,
                "mask_id": operand.mask_id,
                "role": operand.role,
                "values": list(operand.values),
            }
            for operand in sorted(program.plaintext_masks, key=lambda item: item.mask_id)
        ],
        "result_ids": list(program.result_ids),
        "rotation_catalog": [
            {"logical_shift": logical_shift, "openfhe_index": openfhe_index}
            for logical_shift, openfhe_index in sorted(program.rotation_catalog.entries)
        ],
        "slot_count": program.slot_count,
    }


def canonical_cloud_program_bytes(program: CloudProgram) -> bytes:
    return json.dumps(
        canonical_cloud_program_payload(program),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def validate_fixed_stride_cloud_program(
    program: CloudProgram,
    *,
    page_count: int,
    effective_slots: int,
    segment_width: int,
) -> None:
    """Require the exact canonical program emitted by the production builder."""

    expected = build_fixed_stride_cloud_program(
        page_count=page_count,
        effective_slots=effective_slots,
        segment_width=segment_width,
    )
    if canonical_cloud_program_bytes(program) != canonical_cloud_program_bytes(expected):
        raise CloudExecutionPlanError("program does not match the fixed-stride canonical program")


def cloud_program_digest(program: CloudProgram) -> str:
    return hashlib.sha256(canonical_cloud_program_bytes(program)).hexdigest()


def _require_sha256_digest(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CloudExecutionPlanError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def validate_execution_binding(binding: ExecutionBinding) -> None:
    """Validate the public version/output-plan/program commitment tuple."""

    if not isinstance(binding, ExecutionBinding):
        raise CloudExecutionPlanError("binding must be an ExecutionBinding")
    if binding.format != EXECUTION_BINDING_FORMAT:
        raise CloudExecutionPlanError(f"binding format must be {EXECUTION_BINDING_FORMAT}")
    _require_id(binding.version_id, "version_id")
    _require_sha256_digest(binding.output_plan_digest, "output_plan_digest")
    _require_sha256_digest(binding.cloud_program_digest, "cloud_program_digest")


def canonical_execution_binding_payload(
    binding: ExecutionBinding,
) -> dict[str, object]:
    validate_execution_binding(binding)
    return {
        "cloud_program_digest": binding.cloud_program_digest,
        "format": binding.format,
        "output_plan_digest": binding.output_plan_digest,
        "version_id": binding.version_id,
    }


def canonical_execution_binding_bytes(binding: ExecutionBinding) -> bytes:
    return json.dumps(
        canonical_execution_binding_payload(binding),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def execution_binding_digest(binding: ExecutionBinding) -> str:
    return hashlib.sha256(canonical_execution_binding_bytes(binding)).hexdigest()


def validate_cloud_execution_plan(plan: CloudExecutionPlan) -> None:
    """Validate the strict uniform-F1M plan and its atomic execution binding."""

    if not isinstance(plan, CloudExecutionPlan):
        raise CloudExecutionPlanError("plan must be a CloudExecutionPlan")
    validate_cloud_program(plan.program)
    validate_execution_binding(plan.binding)
    if plan.binding.cloud_program_digest != cloud_program_digest(plan.program):
        raise CloudExecutionPlanError(
            "binding cloud_program_digest does not match the canonical program"
        )


def _validate_cloud_execution_plan_with_masked_results(
    plan: CloudExecutionPlan,
    *,
    required_masked_result_ids: frozenset[str],
) -> None:
    """Validate an exact overlap-only mask set derived at the CompiledQuery seam."""

    if not isinstance(plan, CloudExecutionPlan):
        raise CloudExecutionPlanError("plan must be a CloudExecutionPlan")
    _validate_cloud_program(
        plan.program,
        required_masked_result_ids=required_masked_result_ids,
    )
    validate_execution_binding(plan.binding)
    if plan.binding.cloud_program_digest != cloud_program_digest(plan.program):
        raise CloudExecutionPlanError(
            "binding cloud_program_digest does not match the canonical program"
        )


def _validate_cloud_execution_plan_for_serialization(plan: CloudExecutionPlan) -> None:
    _validate_cloud_execution_plan_with_masked_results(
        plan,
        required_masked_result_ids=_masked_return_result_ids(plan.program),
    )


def canonical_cloud_visible_payload(plan: CloudExecutionPlan) -> dict[str, object]:
    """Return the complete closed-key payload observable by the Cloud."""

    _validate_cloud_execution_plan_for_serialization(plan)
    return {
        "binding": canonical_execution_binding_payload(plan.binding),
        "format": CLOUD_EXECUTION_PLAN_FORMAT,
        "program": canonical_cloud_program_payload(plan.program),
    }


def canonical_cloud_visible_bytes(plan: CloudExecutionPlan) -> bytes:
    return json.dumps(
        canonical_cloud_visible_payload(plan),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def analyze_cloud_plan(plan: CloudExecutionPlan) -> CloudPlanCounts:
    """Fold exact operand-role and typed-node counts from a validated plan."""

    _validate_cloud_execution_plan_for_serialization(plan)
    node_counts = Counter(type(node) for node in plan.program.nodes)
    input_role_counts = Counter(operand.role for operand in plan.program.ciphertext_inputs)
    rotation_index_counts = Counter(
        node.openfhe_index for node in plan.program.nodes if isinstance(node, Rotate)
    )
    return CloudPlanCounts(
        ciphertext_inputs=len(plan.program.ciphertext_inputs),
        ciphertext_inputs_by_role=tuple(sorted(input_role_counts.items())),
        plaintext_masks=len(plan.program.plaintext_masks),
        multiply_ciphertexts=node_counts[MultiplyCiphertexts],
        relinearizations=node_counts[Relinearize],
        rotations=node_counts[Rotate],
        rotations_by_exact_index=tuple(sorted(rotation_index_counts.items())),
        multiply_plaintext_masks=node_counts[MultiplyPlaintextMask],
        add_ciphertexts=node_counts[AddCiphertexts],
        add_f1m_masks=node_counts[AddF1MMask],
        returned_ciphertexts=node_counts[ReturnResult],
    )
