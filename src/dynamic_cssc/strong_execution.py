from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.cloud_execution_plan import (
    CLOUD_PROGRAM_FORMAT,
    EXECUTION_BINDING_FORMAT,
    AddCiphertexts,
    AddF1MMask,
    CiphertextInput,
    CloudExecutionPlan,
    CloudPlanCounts,
    CloudProgram,
    ExecutionBinding,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    PlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    RotationCatalog,
    analyze_cloud_plan,
    cloud_program_digest,
    execution_binding_digest,
    validate_cloud_execution_plan,
)
from dynamic_cssc.cssc import OutputBlockLayout, PublishedComponent, ValueChunk, output_plan_for
from dynamic_cssc.mask_ledger import (
    PreparedF1MCommitment,
    PreparedF1MCommitmentLedger,
)
from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputPlanAnalysis,
    PreparedMask,
    analyze_output_plan,
    prepare_f1m_masks,
)
from dynamic_cssc.plaintext_oracle import execute_cloud_plan, reconstruct_output
from dynamic_cssc.strong_packed_coo import (
    STRONG_COMPONENT_ID,
    SegmentedDeltaState,
    client_b_page_metadata,
    decode_segmented_delta,
    post_aggregation_output_shares,
)

OperandSourceKind = Literal["base-chunk", "delta-page"]
F1MOperandKind = Literal["random-zero-sum", "encrypted-zero-dummy"]


class StrongExecutionError(ValueError):
    """Raised when a whole-query strong execution bundle is inconsistent."""


@dataclass(frozen=True, slots=True)
class PrivateOperandSpec:
    value_ciphertext_id: str
    query_ciphertext_id: str
    source_kind: OperandSourceKind
    source_ordinal: int
    result_id: str
    values: tuple[int, ...]
    global_column_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PrivateResultRoute:
    result_id: str
    f1m_ciphertext_id: str
    component_id: str
    output_block_id: str

    @property
    def output_share_id(self) -> tuple[str, str]:
        return self.component_id, self.output_block_id


@dataclass(frozen=True, slots=True)
class F1MOperandCounts:
    random_zero_sum_ciphertexts: int
    encrypted_zero_dummy_ciphertexts: int
    random_elements: int
    ciphertext_additions: int


@dataclass(frozen=True, slots=True)
class StrongExecutionBundle:
    base: PublishedComponent
    delta: SegmentedDeltaState
    cloud_plan: CloudExecutionPlan
    output_plan: OutputPlan
    result_routes: tuple[PrivateResultRoute, ...]
    value_operand_specs: tuple[PrivateOperandSpec, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    cloud_counts: CloudPlanCounts
    output_analysis: OutputPlanAnalysis
    f1m_counts: F1MOperandCounts


@dataclass(frozen=True, slots=True)
class PreparedQueryOperand:
    ciphertext_id: str
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PreparedF1MOperand:
    ciphertext_id: str
    result_id: str
    kind: F1MOperandKind
    query_id: str
    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    values: tuple[int, ...]

    @property
    def binding(self) -> tuple[str, str, str, str, str]:
        return (
            self.query_id,
            self.version_id,
            self.output_plan_digest,
            self.component_id,
            self.output_block_id,
        )


@dataclass(frozen=True, slots=True)
class PreparedStrongQuery:
    query_id: str
    version_id: str
    modulus: int
    vector: tuple[int, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    ledger_commitment_token: str
    query_operands: tuple[PreparedQueryOperand, ...]
    f1m_operands: tuple[PreparedF1MOperand, ...]


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _validate_base_component(base: PublishedComponent) -> None:
    invalid = StrongExecutionError("base PublishedComponent is invalid")
    spec = base.layout_spec
    if (
        not _valid_id(base.component_id)
        or not _valid_id(base.version_id)
        or not all(
            _is_strict_int(value) and value > 0
            for value in (spec.rows, spec.cols, spec.effective_slots, spec.partition_rows)
        )
        or spec.partition_rows > spec.effective_slots
        or not isinstance(base.blocks, tuple)
        or not isinstance(base._coordinate_slots, tuple)
        or not isinstance(base._available_slots, tuple)
    ):
        raise invalid

    expected_block_ranges = tuple(
        (start, min(spec.rows, start + spec.partition_rows))
        for start in range(0, spec.rows, spec.partition_rows)
    )
    if len(base.blocks) != len(expected_block_ranges):
        raise invalid
    block_ids: set[str] = set()
    chunk_ids: set[str] = set()
    scanned_coordinates: dict[tuple[int, int], tuple[str, str, int]] = {}
    scanned_available: list[tuple[int, str, tuple[str, str, int]]] = []
    lane_kinds = {"actual", "tombstone", "natural-padding", "reserved", "tail"}
    for block, expected_range in zip(base.blocks, expected_block_ranges, strict=True):
        if (
            not isinstance(block, OutputBlockLayout)
            or not _valid_id(block.output_block_id)
            or block.output_block_id in block_ids
            or (block.logical_row_start, block.logical_row_stop) != expected_range
            or not isinstance(block.row_map, tuple)
            or set(block.row_map) != set(range(*expected_range))
            or len(block.row_map) != expected_range[1] - expected_range[0]
            or not isinstance(block.physical_row_capacities, tuple)
            or len(block.physical_row_capacities) != len(block.row_map)
            or any(
                not _is_strict_int(capacity) or not 0 <= capacity <= spec.cols
                for capacity in block.physical_row_capacities
            )
            or not isinstance(block.chunks, tuple)
        ):
            raise invalid
        block_ids.add(block.output_block_id)
        max_width = max(block.physical_row_capacities, default=0)
        next_column = 0
        materialized_width = {row: 0 for row in block.row_map}
        for chunk in block.chunks:
            if (
                not isinstance(chunk, ValueChunk)
                or not _valid_id(chunk.chunk_id)
                or chunk.chunk_id in chunk_ids
                or not all(
                    _is_strict_int(value)
                    for value in (
                        chunk.start_column,
                        chunk.width,
                        chunk.height,
                        chunk.used_slots,
                        chunk.reserved_slots,
                        chunk.rectangular_slots,
                    )
                )
                or chunk.start_column != next_column
                or chunk.width <= 0
                or chunk.height <= 0
                or chunk.rectangular_slots != chunk.width * chunk.height
                or chunk.rectangular_slots > spec.effective_slots
                or chunk.height
                != sum(capacity > chunk.start_column for capacity in block.physical_row_capacities)
                or chunk.width
                != min(max_width - chunk.start_column, spec.effective_slots // chunk.height)
            ):
                raise invalid
            lane_arrays = (
                chunk.values,
                chunk.column_indices,
                chunk.slot_coordinates,
                chunk.slot_owner_rows,
                chunk.slot_kinds,
            )
            if any(not isinstance(values, tuple) for values in lane_arrays) or any(
                len(values) != spec.effective_slots for values in lane_arrays
            ):
                raise invalid
            chunk_ids.add(chunk.chunk_id)
            used_slots = 0
            reserved_slots = 0
            for lane, (value, column, coordinate, owner, kind) in enumerate(
                zip(*lane_arrays, strict=True)
            ):
                if (
                    kind not in lane_kinds
                    or not _is_strict_int(value)
                    or not _is_strict_int(column)
                ):
                    raise invalid
                location = (base.component_id, chunk.chunk_id, lane)
                if lane < chunk.rectangular_slots:
                    physical_row = lane % chunk.height
                    expected_owner = block.row_map[physical_row]
                    rank = chunk.start_column + lane // chunk.height
                    expected_materialized = rank < block.physical_row_capacities[physical_row]
                    if owner != expected_owner:
                        raise invalid
                    if expected_materialized and kind not in {"actual", "tombstone", "reserved"}:
                        raise invalid
                    if not expected_materialized and kind != "natural-padding":
                        raise invalid
                elif kind != "tail" or owner is not None:
                    raise invalid

                if kind == "actual":
                    if (
                        owner is None
                        or coordinate != (owner, column)
                        or value == 0
                        or not 0 <= owner < spec.rows
                        or not 0 <= column < spec.cols
                        or coordinate in scanned_coordinates
                    ):
                        raise invalid
                    scanned_coordinates[coordinate] = location
                    materialized_width[owner] = max(
                        materialized_width[owner],
                        chunk.start_column + lane // chunk.height + 1,
                    )
                    used_slots += 1
                elif kind == "tombstone":
                    if (
                        owner is None
                        or coordinate is not None
                        or value != 0
                        or not 0 <= column < spec.cols
                    ):
                        raise invalid
                    materialized_width[owner] = max(
                        materialized_width[owner],
                        chunk.start_column + lane // chunk.height + 1,
                    )
                    scanned_available.append((owner, kind, location))
                elif kind in {"natural-padding", "reserved"}:
                    if owner is None or coordinate is not None or value != 0 or column != -1:
                        raise invalid
                    if kind == "reserved":
                        materialized_width[owner] = max(
                            materialized_width[owner],
                            chunk.start_column + lane // chunk.height + 1,
                        )
                        reserved_slots += 1
                    scanned_available.append((owner, kind, location))
                elif owner is not None or coordinate is not None or value != 0 or column != -1:
                    raise invalid
            if chunk.used_slots != used_slots or chunk.reserved_slots != reserved_slots:
                raise invalid
            next_column += chunk.width
        if next_column != max_width or block.physical_row_capacities != tuple(
            materialized_width[row] for row in block.row_map
        ):
            raise invalid
    if (
        tuple(sorted(scanned_coordinates.items())) != base._coordinate_slots
        or tuple(scanned_available) != base._available_slots
    ):
        raise invalid


def _validate_dimensions(base: PublishedComponent, delta: SegmentedDeltaState) -> None:
    if not isinstance(base, PublishedComponent):
        raise StrongExecutionError("base must be a PublishedComponent")
    if not isinstance(delta, SegmentedDeltaState):
        raise StrongExecutionError("delta must be a SegmentedDeltaState")
    _validate_base_component(base)
    try:
        decode_segmented_delta(delta)
    except (AssertionError, ValueError) as error:
        raise StrongExecutionError("delta state is invalid") from error
    if base.version_id != delta.version_id:
        raise StrongExecutionError("base and delta version_id must match")
    if (
        base.layout_spec.rows,
        base.layout_spec.cols,
        base.layout_spec.effective_slots,
    ) != (delta.rows, delta.cols, delta.effective_slots):
        raise StrongExecutionError("base and delta matrix and slot dimensions must match")
    if base.component_id == STRONG_COMPONENT_ID:
        raise StrongExecutionError("base component_id collides with the strong delta")
    base_coordinates = set(base.coord_to_slot)
    delta_coordinates = set(decode_segmented_delta(delta))
    if base_coordinates & delta_coordinates:
        raise StrongExecutionError("active base and delta coordinates must be disjoint")


def _canonical_private_plan_payload(
    specs: tuple[PrivateOperandSpec, ...],
    routes: tuple[PrivateResultRoute, ...],
    output_plan_digest: str,
) -> dict[str, object]:
    return {
        "format": "dynamic-cssc-private-strong-plan-v1",
        "output_plan_digest": output_plan_digest,
        "operands": [
            {
                "global_column_indices": list(spec.global_column_indices),
                "query_ciphertext_id": spec.query_ciphertext_id,
                "result_id": spec.result_id,
                "source_kind": spec.source_kind,
                "source_ordinal": spec.source_ordinal,
                "value_ciphertext_id": spec.value_ciphertext_id,
                "values": list(spec.values),
            }
            for spec in specs
        ],
        "routes": [
            {
                "component_id": route.component_id,
                "f1m_ciphertext_id": route.f1m_ciphertext_id,
                "output_block_id": route.output_block_id,
                "result_id": route.result_id,
            }
            for route in routes
        ],
    }


def canonical_private_plan_payload(bundle: StrongExecutionBundle) -> dict[str, object]:
    """Serialize private whole-query operands and routes for audit evidence.

    This payload contains global ColumnIndex data and is not Cloud-visible.
    """

    _validate_bundle(bundle)
    return _canonical_private_plan_payload(
        bundle.value_operand_specs,
        bundle.result_routes,
        bundle.output_plan_digest,
    )


def _private_plan_digest(
    specs: tuple[PrivateOperandSpec, ...],
    routes: tuple[PrivateResultRoute, ...],
    output_plan_digest: str,
) -> str:
    payload = _canonical_private_plan_payload(specs, routes, output_plan_digest)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _compile(base: PublishedComponent, delta: SegmentedDeltaState) -> StrongExecutionBundle:
    _validate_dimensions(base, delta)
    slot_count = base.layout_spec.effective_slots
    base_plan = output_plan_for((base,))
    output_plan = OutputPlan(
        logical_output_size=base_plan.logical_output_size,
        slot_count=base_plan.slot_count,
        shares=(*base_plan.shares, *post_aggregation_output_shares(delta)),
    )
    output_analysis = analyze_output_plan(output_plan)

    ciphertext_inputs: list[CiphertextInput] = []
    plaintext_masks: list[PlaintextMask] = []
    nodes = []
    result_ids: list[str] = []
    specs: list[PrivateOperandSpec] = []
    routes: list[PrivateResultRoute] = []
    rotation_shifts: set[int] = set()
    operand_ordinal = 0
    result_ordinal = 0

    for block in base.blocks:
        if not block.chunks:
            continue
        selected_ids: list[str] = []
        block_specs: list[PrivateOperandSpec] = []
        for chunk in block.chunks:
            ordinal = f"{operand_ordinal:06d}"
            value_id = f"ct-value-{ordinal}"
            query_id = f"ct-query-{ordinal}"
            product_id = f"ssa-product-{ordinal}"
            relinearized_id = f"ssa-relinearized-{ordinal}"
            ciphertext_inputs.extend(
                (
                    CiphertextInput(value_id, "value", slot_count),
                    CiphertextInput(query_id, "query", slot_count),
                )
            )
            nodes.extend(
                (
                    MultiplyCiphertexts(product_id, value_id, query_id),
                    Relinearize(relinearized_id, product_id),
                )
            )
            accumulated_id = relinearized_id
            for local_column in range(1, chunk.width):
                shift = local_column * chunk.height
                rotation_shifts.add(shift)
                rotated_id = f"ssa-rotate-{ordinal}-{local_column:06d}"
                sum_id = f"ssa-column-sum-{ordinal}-{local_column:06d}"
                nodes.extend(
                    (
                        Rotate(rotated_id, relinearized_id, shift, shift),
                        AddCiphertexts(sum_id, accumulated_id, rotated_id),
                    )
                )
                accumulated_id = sum_id
            mask_id = f"pt-selection-{ordinal}"
            selected_id = f"ssa-selected-{ordinal}"
            plaintext_masks.append(
                PlaintextMask(
                    mask_id,
                    "selection",
                    slot_count,
                    tuple(1 if lane < chunk.height else 0 for lane in range(slot_count)),
                )
            )
            nodes.append(MultiplyPlaintextMask(selected_id, accumulated_id, mask_id))
            selected_ids.append(selected_id)
            block_specs.append(
                PrivateOperandSpec(
                    value_ciphertext_id=value_id,
                    query_ciphertext_id=query_id,
                    source_kind="base-chunk",
                    source_ordinal=operand_ordinal,
                    result_id="",
                    values=chunk.values,
                    global_column_indices=chunk.column_indices,
                )
            )
            operand_ordinal += 1

        accumulated_id = selected_ids[0]
        for cross_ordinal, selected_id in enumerate(selected_ids[1:], start=1):
            sum_id = f"ssa-result-sum-{result_ordinal:06d}-{cross_ordinal:06d}"
            nodes.append(AddCiphertexts(sum_id, accumulated_id, selected_id))
            accumulated_id = sum_id
        result_id = f"result-{result_ordinal:06d}"
        f1m_id = f"ct-f1m-{result_ordinal:06d}"
        masked_id = f"ssa-masked-{result_ordinal:06d}"
        ciphertext_inputs.append(CiphertextInput(f1m_id, "f1m-mask", slot_count))
        nodes.extend(
            (
                AddF1MMask(masked_id, accumulated_id, f1m_id, "opaque-zero-sum"),
                ReturnResult(result_id, masked_id),
            )
        )
        result_ids.append(result_id)
        routes.append(
            PrivateResultRoute(
                result_id=result_id,
                f1m_ciphertext_id=f1m_id,
                component_id=base.component_id,
                output_block_id=block.output_block_id,
            )
        )
        specs.extend(
            PrivateOperandSpec(
                value_ciphertext_id=spec.value_ciphertext_id,
                query_ciphertext_id=spec.query_ciphertext_id,
                source_kind=spec.source_kind,
                source_ordinal=spec.source_ordinal,
                result_id=result_id,
                values=spec.values,
                global_column_indices=spec.global_column_indices,
            )
            for spec in block_specs
        )
        result_ordinal += 1

    page_metadata = client_b_page_metadata(delta)
    page_values = [[0] * slot_count for _ in page_metadata]
    for segment in delta.segments:
        for offset, entry in enumerate(segment.entries):
            if entry is not None:
                page_values[segment.page_ordinal][segment.slot_start + offset] = entry.value
    for page_ordinal, metadata in enumerate(page_metadata):
        ordinal = f"{operand_ordinal:06d}"
        value_id = f"ct-value-{ordinal}"
        query_id = f"ct-query-{ordinal}"
        product_id = f"ssa-product-{ordinal}"
        relinearized_id = f"ssa-relinearized-{ordinal}"
        ciphertext_inputs.extend(
            (
                CiphertextInput(value_id, "value", slot_count),
                CiphertextInput(query_id, "query", slot_count),
            )
        )
        nodes.extend(
            (
                MultiplyCiphertexts(product_id, value_id, query_id),
                Relinearize(relinearized_id, product_id),
            )
        )
        accumulated_id = relinearized_id
        shift = 1
        while shift < delta.segment_width:
            rotation_shifts.add(shift)
            rotated_id = f"ssa-rotate-{ordinal}-{shift:06d}"
            sum_id = f"ssa-segment-sum-{ordinal}-{shift * 2:06d}"
            nodes.extend(
                (
                    Rotate(rotated_id, accumulated_id, shift, shift),
                    AddCiphertexts(sum_id, accumulated_id, rotated_id),
                )
            )
            accumulated_id = sum_id
            shift *= 2
        mask_id = f"pt-selection-{ordinal}"
        selected_id = f"ssa-selected-{ordinal}"
        plaintext_masks.append(
            PlaintextMask(
                mask_id,
                "selection",
                slot_count,
                tuple(
                    1
                    if lane < delta.segments_per_page * delta.segment_width
                    and lane % delta.segment_width == 0
                    else 0
                    for lane in range(slot_count)
                ),
            )
        )
        nodes.append(MultiplyPlaintextMask(selected_id, accumulated_id, mask_id))
        result_id = f"result-{result_ordinal:06d}"
        f1m_id = f"ct-f1m-{result_ordinal:06d}"
        masked_id = f"ssa-masked-{result_ordinal:06d}"
        ciphertext_inputs.append(CiphertextInput(f1m_id, "f1m-mask", slot_count))
        nodes.extend(
            (
                AddF1MMask(masked_id, selected_id, f1m_id, "opaque-zero-sum"),
                ReturnResult(result_id, masked_id),
            )
        )
        result_ids.append(result_id)
        routes.append(
            PrivateResultRoute(
                result_id=result_id,
                f1m_ciphertext_id=f1m_id,
                component_id=STRONG_COMPONENT_ID,
                output_block_id=metadata.page_id,
            )
        )
        specs.append(
            PrivateOperandSpec(
                value_ciphertext_id=value_id,
                query_ciphertext_id=query_id,
                source_kind="delta-page",
                source_ordinal=page_ordinal,
                result_id=result_id,
                values=tuple(page_values[page_ordinal]),
                global_column_indices=metadata.global_column_indices,
            )
        )
        operand_ordinal += 1
        result_ordinal += 1

    program = CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=slot_count,
        ciphertext_inputs=tuple(ciphertext_inputs),
        plaintext_masks=tuple(plaintext_masks),
        nodes=tuple(nodes),
        result_ids=tuple(result_ids),
        rotation_catalog=RotationCatalog(
            tuple((shift, shift) for shift in sorted(rotation_shifts))
        ),
    )
    program_digest = cloud_program_digest(program)
    cloud_plan = CloudExecutionPlan(
        program=program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id=base.version_id,
            output_plan_digest=output_analysis.output_plan_digest,
            cloud_program_digest=program_digest,
        ),
    )
    validate_cloud_execution_plan(cloud_plan)
    cloud_counts = analyze_cloud_plan(cloud_plan)
    random_ciphertexts = output_analysis.masked_result_ciphertexts
    return StrongExecutionBundle(
        base=base,
        delta=delta,
        cloud_plan=cloud_plan,
        output_plan=output_plan,
        result_routes=tuple(routes),
        value_operand_specs=tuple(specs),
        cloud_program_digest=program_digest,
        output_plan_digest=output_analysis.output_plan_digest,
        execution_binding_digest=execution_binding_digest(cloud_plan.binding),
        private_plan_digest=_private_plan_digest(
            tuple(specs), tuple(routes), output_analysis.output_plan_digest
        ),
        cloud_counts=cloud_counts,
        output_analysis=output_analysis,
        f1m_counts=F1MOperandCounts(
            random_zero_sum_ciphertexts=random_ciphertexts,
            encrypted_zero_dummy_ciphertexts=len(routes) - random_ciphertexts,
            random_elements=output_analysis.mask_random_elements,
            ciphertext_additions=cloud_counts.add_f1m_masks,
        ),
    )


def compile_strong_execution(
    base: PublishedComponent,
    delta: SegmentedDeltaState,
) -> StrongExecutionBundle:
    """Compile the actual CSSC base and anonymous strong delta as one bound query plan."""

    return _compile(base, delta)


def _validate_bundle(bundle: StrongExecutionBundle) -> None:
    if not isinstance(bundle, StrongExecutionBundle):
        raise StrongExecutionError("bundle must be a StrongExecutionBundle")
    expected = _compile(bundle.base, bundle.delta)
    if bundle != expected:
        raise StrongExecutionError("bundle does not match its deterministically derived plans")


def _validated_vector(vector: object, *, length: int) -> tuple[int, ...]:
    if not isinstance(vector, tuple) or len(vector) != length:
        raise StrongExecutionError(f"vector must be a tuple of length {length}")
    if not all(_is_strict_int(value) for value in vector):
        raise StrongExecutionError("vector must contain strict integers")
    return vector


def prepare_strong_query(
    bundle: StrongExecutionBundle,
    *,
    query_id: str,
    vector: tuple[int, ...],
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> PreparedStrongQuery:
    """Prepare private global-CI query operands and one bound F1-M operand per result."""

    _validate_bundle(bundle)
    dense_vector = _validated_vector(vector, length=bundle.base.layout_spec.cols)
    if not _is_strict_int(modulus) or modulus < 2:
        raise StrongExecutionError("modulus must be a strict integer of at least two")
    random_masks = prepare_f1m_masks(
        bundle.output_plan,
        query_id=query_id,
        version_id=bundle.base.version_id,
        modulus=modulus,
        ledger=ledger,
    )
    random_by_share = {(mask.component_id, mask.output_block_id): mask for mask in random_masks}
    query_operands = tuple(
        PreparedQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                dense_vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in bundle.value_operand_specs
    )
    f1m_operands = []
    for route in bundle.result_routes:
        mask: PreparedMask | None = random_by_share.get(route.output_share_id)
        f1m_operands.append(
            PreparedF1MOperand(
                ciphertext_id=route.f1m_ciphertext_id,
                result_id=route.result_id,
                kind="random-zero-sum" if mask is not None else "encrypted-zero-dummy",
                query_id=query_id,
                version_id=bundle.base.version_id,
                output_plan_digest=bundle.output_plan_digest,
                component_id=route.component_id,
                output_block_id=route.output_block_id,
                values=mask.values if mask is not None else (0,) * bundle.output_plan.slot_count,
            )
        )
    prepared_f1m_operands = tuple(f1m_operands)
    ledger_commitment_token = ledger.commit_prepared_f1m(
        _prepared_f1m_commitments(prepared_f1m_operands),
        query_id=query_id,
        version_id=bundle.base.version_id,
        output_plan_digest=bundle.output_plan_digest,
        private_plan_digest=bundle.private_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        modulus=modulus,
    )
    return PreparedStrongQuery(
        query_id=query_id,
        version_id=bundle.base.version_id,
        modulus=modulus,
        vector=dense_vector,
        cloud_program_digest=bundle.cloud_program_digest,
        output_plan_digest=bundle.output_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        private_plan_digest=bundle.private_plan_digest,
        ledger_commitment_token=ledger_commitment_token,
        query_operands=query_operands,
        f1m_operands=prepared_f1m_operands,
    )


def _prepared_f1m_commitments(
    operands: tuple[PreparedF1MOperand, ...],
) -> tuple[PreparedF1MCommitment, ...]:
    return tuple(
        PreparedF1MCommitment(
            query_id=operand.query_id,
            version_id=operand.version_id,
            output_plan_digest=operand.output_plan_digest,
            component_id=operand.component_id,
            output_block_id=operand.output_block_id,
            kind=operand.kind,
            values=operand.values,
        )
        for operand in operands
    )


def _validate_prepared(bundle: StrongExecutionBundle, prepared: PreparedStrongQuery) -> None:
    if not isinstance(prepared, PreparedStrongQuery):
        raise StrongExecutionError("prepared must be a PreparedStrongQuery")
    if (
        prepared.version_id != bundle.base.version_id
        or prepared.cloud_program_digest != bundle.cloud_program_digest
        or prepared.output_plan_digest != bundle.output_plan_digest
        or prepared.execution_binding_digest != bundle.execution_binding_digest
        or prepared.private_plan_digest != bundle.private_plan_digest
    ):
        raise StrongExecutionError("prepared query does not match the execution bundle binding")
    vector = _validated_vector(prepared.vector, length=bundle.base.layout_spec.cols)
    expected_queries = tuple(
        PreparedQueryOperand(
            spec.query_ciphertext_id,
            tuple(
                vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in bundle.value_operand_specs
    )
    if prepared.query_operands != expected_queries:
        raise StrongExecutionError("prepared query operands do not match private global CI")

    multiplicity: Counter[int] = Counter(
        logical for share in bundle.output_plan.shares for _, logical in share.slot_to_logical
    )
    overlap = {logical for logical, count in multiplicity.items() if count > 1}
    share_by_id = {
        (share.component_id, share.output_block_id): share for share in bundle.output_plan.shares
    }
    if len(prepared.f1m_operands) != len(bundle.result_routes):
        raise StrongExecutionError("prepared query must contain one F1-M operand per result")
    values_by_share: dict[tuple[str, str], tuple[int, ...]] = {}
    for operand, route in zip(prepared.f1m_operands, bundle.result_routes, strict=True):
        expected_kind: F1MOperandKind = (
            "random-zero-sum"
            if any(
                logical in overlap
                for _, logical in share_by_id[route.output_share_id].slot_to_logical
            )
            else "encrypted-zero-dummy"
        )
        if (
            operand.ciphertext_id != route.f1m_ciphertext_id
            or operand.result_id != route.result_id
            or operand.kind != expected_kind
            or operand.query_id != prepared.query_id
            or operand.version_id != bundle.base.version_id
            or operand.output_plan_digest != bundle.output_plan_digest
            or (operand.component_id, operand.output_block_id) != route.output_share_id
            or len(operand.values) != bundle.output_plan.slot_count
            or any(
                not _is_strict_int(value) or not 0 <= value < prepared.modulus
                for value in operand.values
            )
        ):
            raise StrongExecutionError("prepared F1-M operand does not match its result binding")
        if operand.kind == "encrypted-zero-dummy" and any(operand.values):
            raise StrongExecutionError("encrypted-zero dummy F1-M operand must be exactly zero")
        share = share_by_id[route.output_share_id]
        mapped_overlap_lanes = {
            lane for lane, logical in share.slot_to_logical if logical in overlap
        }
        if any(
            value and lane not in mapped_overlap_lanes for lane, value in enumerate(operand.values)
        ):
            raise StrongExecutionError("random F1-M values may occupy only overlapping lanes")
        values_by_share[route.output_share_id] = operand.values
    for logical in overlap:
        total = 0
        for share in bundle.output_plan.shares:
            for lane, coordinate in share.slot_to_logical:
                if coordinate == logical:
                    total += values_by_share[(share.component_id, share.output_block_id)][lane]
        if total % prepared.modulus:
            raise StrongExecutionError("random F1-M values must sum to zero per coordinate")


def execute_strong_plaintext(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> tuple[int, ...]:
    """Execute the exact typed whole-query DAG, privately route shares, and reconstruct."""

    _validate_bundle(bundle)
    if not _is_strict_int(modulus) or modulus < 2 or modulus != prepared.modulus:
        raise StrongExecutionError("execution modulus must match the prepared query modulus")
    _validate_prepared(bundle, prepared)
    ledger.verify_and_consume_prepared_f1m(
        _prepared_f1m_commitments(prepared.f1m_operands),
        commitment_token=prepared.ledger_commitment_token,
        query_id=prepared.query_id,
        version_id=prepared.version_id,
        output_plan_digest=prepared.output_plan_digest,
        private_plan_digest=bundle.private_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        modulus=prepared.modulus,
    )
    ciphertext_inputs = {
        spec.value_ciphertext_id: spec.values for spec in bundle.value_operand_specs
    }
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.query_operands}
    )
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.f1m_operands}
    )
    returned = execute_cloud_plan(
        bundle.cloud_plan,
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks={
            mask.mask_id: mask.values for mask in bundle.cloud_plan.program.plaintext_masks
        },
        modulus=modulus,
    )
    returned_shares = {
        route.output_share_id: returned[route.result_id] for route in bundle.result_routes
    }
    return reconstruct_output(bundle.output_plan, returned_shares, modulus=modulus)
