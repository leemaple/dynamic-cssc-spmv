from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, TypeAlias, TypeGuard

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
    _validate_cloud_execution_plan_with_masked_results,
    analyze_cloud_plan,
    cloud_program_digest,
    execution_binding_digest,
    validate_cloud_execution_plan,
)
from dynamic_cssc.cssc import (
    LayoutSpec,
    OutputBlockLayout,
    PublishedComponent,
    ValueChunk,
    output_plan_for,
)
from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputPlanAnalysis,
    OutputShare,
    analyze_output_plan,
)
from dynamic_cssc.strategy_state import PackedCOOEntry, PackedCOOSegment
from dynamic_cssc.strong_packed_coo import (
    STRONG_COMPONENT_ID,
    SegmentedDeltaState,
    client_b_page_metadata,
    decode_segmented_delta,
    post_aggregation_output_shares,
)

CLIENT_LANE_COMPONENT_ID = "packed-coo-delta"
QUERY_PRIVATE_PLAN_FORMAT = "dynamic-cssc-common-ordinary-private-plan-v1"

F1MPolicy: TypeAlias = Literal["overlap-only", "uniform-random-or-zero"]
OperandSourceKind: TypeAlias = Literal[
    "published-chunk", "segmented-delta-page", "client-lane-segment"
]


def is_canonical_f1m_policy(value: object) -> TypeGuard[F1MPolicy]:
    """Return whether value is an exact built-in string in the F1M policy domain."""

    return type(value) is str and value in (
        "overlap-only",
        "uniform-random-or-zero",
    )


class QueryCompilerError(ValueError):
    """Raised when typed query sources cannot produce one safe bound query."""


@dataclass(frozen=True, slots=True)
class OperandSpec:
    value_ciphertext_id: str
    query_ciphertext_id: str
    source_kind: OperandSourceKind
    source_ordinal: int
    result_id: str
    values: tuple[int, ...]
    global_column_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ResultRoute:
    result_id: str
    f1m_ciphertext_id: str | None
    component_id: str
    output_block_id: str

    @property
    def output_share_id(self) -> tuple[str, str]:
        return self.component_id, self.output_block_id


@dataclass(frozen=True, slots=True)
class CompiledQuery:
    components: tuple[PublishedComponent, ...]
    segmented_delta: SegmentedDeltaState | None
    client_lane_segments: tuple[PackedCOOSegment, ...]
    f1m_policy: F1MPolicy
    cloud_plan: CloudExecutionPlan
    output_plan: OutputPlan
    operand_specs: tuple[OperandSpec, ...]
    result_routes: tuple[ResultRoute, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    cloud_counts: CloudPlanCounts
    output_analysis: OutputPlanAnalysis

    @property
    def private_plan_digest(self) -> str:
        payload = _query_private_plan_payload(
            version_id=self.cloud_plan.binding.version_id,
            cloud_program_digest_value=self.cloud_program_digest,
            output_plan_digest_value=self.output_plan_digest,
            execution_binding_digest_value=self.execution_binding_digest,
            f1m_policy=self.f1m_policy,
            operand_specs=self.operand_specs,
            result_routes=self.result_routes,
        )
        return _query_private_plan_digest(payload)


def _query_private_plan_payload(
    *,
    version_id: str,
    cloud_program_digest_value: str,
    output_plan_digest_value: str,
    execution_binding_digest_value: str,
    f1m_policy: F1MPolicy,
    operand_specs: tuple[OperandSpec, ...],
    result_routes: tuple[ResultRoute, ...],
) -> dict[str, object]:
    return {
        "bindings": {
            "cloud_program_digest": cloud_program_digest_value,
            "execution_binding_digest": execution_binding_digest_value,
            "output_plan_digest": output_plan_digest_value,
            "version_id": version_id,
        },
        "f1m_policy": f1m_policy,
        "format": QUERY_PRIVATE_PLAN_FORMAT,
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
            for spec in operand_specs
        ],
        "routes": [
            {
                "component_id": route.component_id,
                "f1m_ciphertext_id": route.f1m_ciphertext_id,
                "output_block_id": route.output_block_id,
                "result_id": route.result_id,
            }
            for route in result_routes
        ],
    }


def _query_private_plan_digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_query_private_plan_payload(compiled: CompiledQuery) -> dict[str, object]:
    """Return the private operand/route plan already bound by the compiler."""

    if type(compiled) is not CompiledQuery:
        raise QueryCompilerError("compiled must be an exact CompiledQuery")
    payload = _query_private_plan_payload(
        version_id=compiled.cloud_plan.binding.version_id,
        cloud_program_digest_value=compiled.cloud_program_digest,
        output_plan_digest_value=compiled.output_plan_digest,
        execution_binding_digest_value=compiled.execution_binding_digest,
        f1m_policy=compiled.f1m_policy,
        operand_specs=compiled.operand_specs,
        result_routes=compiled.result_routes,
    )
    return payload


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _validate_component(component: PublishedComponent) -> None:
    invalid = QueryCompilerError("PublishedComponent is invalid")
    if not isinstance(component, PublishedComponent):
        raise invalid
    spec = component.layout_spec
    if (
        not isinstance(spec, LayoutSpec)
        or not _valid_id(component.component_id)
        or not _valid_id(component.version_id)
        or not all(
            _is_strict_int(value) and value > 0
            for value in (spec.rows, spec.cols, spec.effective_slots, spec.partition_rows)
        )
        or spec.partition_rows > spec.effective_slots
        or not isinstance(component.blocks, tuple)
        or not isinstance(component._coordinate_slots, tuple)
        or not isinstance(component._available_slots, tuple)
    ):
        raise invalid

    expected_ranges = tuple(
        (start, min(spec.rows, start + spec.partition_rows))
        for start in range(0, spec.rows, spec.partition_rows)
    )
    if len(component.blocks) != len(expected_ranges):
        raise invalid
    block_ids: set[str] = set()
    chunk_ids: set[str] = set()
    scanned_coordinates: dict[tuple[int, int], tuple[str, str, int]] = {}
    scanned_available: list[tuple[int, str, tuple[str, str, int]]] = []
    lane_kinds = {"actual", "tombstone", "natural-padding", "reserved", "tail"}
    for block, expected_range in zip(component.blocks, expected_ranges, strict=True):
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
                != min(
                    max_width - chunk.start_column,
                    spec.effective_slots // chunk.height,
                )
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
                location = (component.component_id, chunk.chunk_id, lane)
                if lane < chunk.rectangular_slots:
                    physical_row = lane % chunk.height
                    expected_owner = block.row_map[physical_row]
                    rank = chunk.start_column + lane // chunk.height
                    materialized = rank < block.physical_row_capacities[physical_row]
                    if owner != expected_owner:
                        raise invalid
                    if materialized and kind not in {"actual", "tombstone", "reserved"}:
                        raise invalid
                    if not materialized and kind != "natural-padding":
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
        tuple(sorted(scanned_coordinates.items())) != component._coordinate_slots
        or tuple(scanned_available) != component._available_slots
    ):
        raise invalid


def _validated_sources(
    components: object,
    segmented_delta: object,
    client_lane_segments: object,
    f1m_policy: object,
) -> tuple[
    tuple[PublishedComponent, ...],
    SegmentedDeltaState | None,
    tuple[PackedCOOSegment, ...],
    F1MPolicy,
]:
    if not isinstance(components, tuple) or not components:
        raise QueryCompilerError("components must be a non-empty tuple")
    if any(not isinstance(component, PublishedComponent) for component in components):
        raise QueryCompilerError("components must contain PublishedComponent values")
    if not isinstance(client_lane_segments, tuple) or any(
        not isinstance(segment, PackedCOOSegment) for segment in client_lane_segments
    ):
        raise QueryCompilerError("client_lane_segments must be a tuple of PackedCOOSegment values")
    if segmented_delta is not None and client_lane_segments:
        raise QueryCompilerError("segmented_delta and client_lane_segments are mutually exclusive")
    if segmented_delta is not None and not isinstance(segmented_delta, SegmentedDeltaState):
        raise QueryCompilerError("segmented_delta must be a SegmentedDeltaState or None")
    if not is_canonical_f1m_policy(f1m_policy):
        raise QueryCompilerError("f1m_policy is unsupported")

    ordered_components = tuple(sorted(components, key=lambda item: item.component_id))
    if len({component.component_id for component in ordered_components}) != len(ordered_components):
        raise QueryCompilerError("component IDs must be unique")
    for component in ordered_components:
        _validate_component(component)
    reference = ordered_components[0]
    dimensions = (
        reference.layout_spec.rows,
        reference.layout_spec.cols,
        reference.layout_spec.effective_slots,
    )
    if any(component.version_id != reference.version_id for component in ordered_components):
        raise QueryCompilerError("all sources must have the same version_id")
    if any(
        (
            component.layout_spec.rows,
            component.layout_spec.cols,
            component.layout_spec.effective_slots,
        )
        != dimensions
        for component in ordered_components
    ):
        raise QueryCompilerError("all sources must have the same matrix and slot dimensions")

    coordinates: set[tuple[int, int]] = set()
    for component in ordered_components:
        component_coordinates = set(component.coord_to_slot)
        if coordinates & component_coordinates:
            raise QueryCompilerError("active source coordinates must not overlap")
        coordinates.update(component_coordinates)

    if segmented_delta is not None:
        try:
            delta_coordinates = set(decode_segmented_delta(segmented_delta))
        except (AssertionError, ValueError) as error:
            raise QueryCompilerError("segmented_delta is invalid") from error
        if segmented_delta.version_id != reference.version_id:
            raise QueryCompilerError("all sources must have the same version_id")
        if (
            segmented_delta.rows,
            segmented_delta.cols,
            segmented_delta.effective_slots,
        ) != dimensions:
            raise QueryCompilerError("all sources must have the same matrix and slot dimensions")
        if STRONG_COMPONENT_ID in {component.component_id for component in ordered_components}:
            raise QueryCompilerError("component ID collides with segmented delta")
        if coordinates & delta_coordinates:
            raise QueryCompilerError("active source coordinates must not overlap")

    ordered_segments = tuple(sorted(client_lane_segments, key=lambda item: item.segment_id))
    if len({segment.segment_id for segment in ordered_segments}) != len(ordered_segments):
        raise QueryCompilerError("client-lane segment IDs must be unique")
    if ordered_segments and CLIENT_LANE_COMPONENT_ID in {
        component.component_id for component in ordered_components
    }:
        raise QueryCompilerError("component ID collides with client-lane source")
    for segment in ordered_segments:
        if (
            not _valid_id(segment.segment_id)
            or segment.version_id != reference.version_id
            or not _is_strict_int(segment.capacity)
            or not 0 < segment.capacity <= reference.layout_spec.effective_slots
            or not isinstance(segment.entries, tuple)
            or len(segment.entries) != segment.capacity
        ):
            raise QueryCompilerError("client-lane segment is invalid")
        for entry in segment.entries:
            if entry is None:
                continue
            if (
                not isinstance(entry, PackedCOOEntry)
                or not isinstance(entry.coordinate, tuple)
                or len(entry.coordinate) != 2
                or not all(_is_strict_int(axis) for axis in entry.coordinate)
                or not _is_strict_int(entry.value)
                or not 0 <= entry.coordinate[0] < dimensions[0]
                or not 0 <= entry.coordinate[1] < dimensions[1]
            ):
                raise QueryCompilerError("client-lane segment is invalid")
            if entry.value == 0:
                continue
            if entry.coordinate in coordinates:
                raise QueryCompilerError("active source coordinates must not overlap")
            coordinates.add(entry.coordinate)
    return ordered_components, segmented_delta, ordered_segments, f1m_policy


def _append_cssc_reduction(
    nodes: list[object],
    *,
    ordinal: str,
    source_id: str,
    width: int,
    height: int,
    rotation_shifts: set[int],
) -> str:
    """Corrected CSSC-compatible stored-power/prefix total-sum schedule."""

    if width == 1:
        return source_id
    powers: dict[int, str] = {1: source_id}
    span = 1
    while 2 * span <= width:
        shift = span * height
        rotation_shifts.add(shift)
        rotated_id = f"ssa-rotate-{ordinal}-{span:06d}"
        sum_id = f"ssa-column-sum-{ordinal}-{span:06d}"
        nodes.extend(
            (
                Rotate(rotated_id, powers[span], shift, shift),
                AddCiphertexts(sum_id, powers[span], rotated_id),
            )
        )
        powers[2 * span] = sum_id
        span *= 2

    prefix = span
    accumulated_id = powers[span]
    bit = span // 2
    while bit:
        if width & bit:
            shift = prefix * height
            rotation_shifts.add(shift)
            rotated_id = f"ssa-rotate-{ordinal}-{prefix:06d}"
            sum_id = f"ssa-column-sum-{ordinal}-{prefix:06d}"
            nodes.extend(
                (
                    Rotate(rotated_id, powers[bit], shift, shift),
                    AddCiphertexts(sum_id, accumulated_id, rotated_id),
                )
            )
            accumulated_id = sum_id
            prefix += bit
        bit //= 2
    return accumulated_id


def _required_overlap_mask_result_ids(
    output_plan: OutputPlan,
    result_routes: tuple[ResultRoute, ...],
) -> frozenset[str]:
    multiplicity: dict[int, int] = {}
    for share in output_plan.shares:
        for _, logical in share.slot_to_logical:
            multiplicity[logical] = multiplicity.get(logical, 0) + 1
    required_share_ids = {
        (share.component_id, share.output_block_id)
        for share in output_plan.shares
        if any(multiplicity[logical] > 1 for _, logical in share.slot_to_logical)
    }
    return frozenset(
        route.result_id for route in result_routes if route.output_share_id in required_share_ids
    )


def _validate_compiled_parts(compiled: CompiledQuery) -> None:
    share_ids = {
        (share.component_id, share.output_block_id) for share in compiled.output_plan.shares
    }
    route_share_ids = {route.output_share_id for route in compiled.result_routes}
    if (
        len(compiled.result_routes) != len(route_share_ids)
        or route_share_ids != share_ids
        or tuple(route.result_id for route in compiled.result_routes)
        != compiled.cloud_plan.program.result_ids
    ):
        raise QueryCompilerError("result routes must exactly cover the OutputPlan and returns")
    overlap_ids = _required_overlap_mask_result_ids(compiled.output_plan, compiled.result_routes)
    required_ids = (
        frozenset(compiled.cloud_plan.program.result_ids)
        if compiled.f1m_policy == "uniform-random-or-zero"
        else overlap_ids
    )
    expected_route_mask_ids = {
        route.result_id for route in compiled.result_routes if route.f1m_ciphertext_id is not None
    }
    if expected_route_mask_ids != set(required_ids):
        raise QueryCompilerError("result routes do not match the exact F1M policy")
    try:
        if compiled.f1m_policy == "uniform-random-or-zero":
            validate_cloud_execution_plan(compiled.cloud_plan)
        else:
            _validate_cloud_execution_plan_with_masked_results(
                compiled.cloud_plan,
                required_masked_result_ids=required_ids,
            )
    except ValueError as error:
        raise QueryCompilerError("cloud plan does not match the exact F1M policy") from error


def validate_compiled_query(compiled: CompiledQuery) -> None:
    """Validate value integrity for the compilation's own declared F1M policy.

    This can accept independently valid compilations whose declared policies happen to
    produce identical plans. Execution authorization separately binds an expected policy.
    """

    if not isinstance(compiled, CompiledQuery):
        raise QueryCompilerError("compiled must be a CompiledQuery")
    if not is_canonical_f1m_policy(compiled.f1m_policy):
        raise QueryCompilerError("CompiledQuery f1m_policy is unsupported")
    _validate_compiled_parts(compiled)
    expected = compile_query(
        compiled.components,
        segmented_delta=compiled.segmented_delta,
        client_lane_segments=compiled.client_lane_segments,
        f1m_policy=compiled.f1m_policy,
    )
    if compiled != expected:
        raise QueryCompilerError("CompiledQuery is not its deterministic canonical compilation")


def compile_query(
    components: tuple[PublishedComponent, ...],
    *,
    segmented_delta: SegmentedDeltaState | None = None,
    client_lane_segments: tuple[PackedCOOSegment, ...] = (),
    f1m_policy: F1MPolicy = "overlap-only",
) -> CompiledQuery:
    """Compile all typed result sources into one canonical, version-bound query."""

    components, segmented_delta, client_lane_segments, f1m_policy = _validated_sources(
        components, segmented_delta, client_lane_segments, f1m_policy
    )
    reference = components[0]
    slot_count = reference.layout_spec.effective_slots
    base_plan = output_plan_for(components)
    extra_shares: tuple[OutputShare, ...] = ()
    if segmented_delta is not None:
        extra_shares = post_aggregation_output_shares(segmented_delta)
    elif client_lane_segments:
        extra_shares = tuple(
            OutputShare(
                component_id=CLIENT_LANE_COMPONENT_ID,
                output_block_id=segment.segment_id,
                slot_to_logical=tuple(
                    (lane, entry.coordinate[0])
                    for lane, entry in enumerate(segment.entries)
                    if entry is not None and entry.value != 0
                ),
            )
            for segment in client_lane_segments
            if any(entry is not None and entry.value != 0 for entry in segment.entries)
        )
    output_plan = OutputPlan(
        logical_output_size=base_plan.logical_output_size,
        slot_count=base_plan.slot_count,
        shares=(*base_plan.shares, *extra_shares),
    )
    output_analysis = analyze_output_plan(output_plan)
    multiplicity: dict[int, int] = {}
    for share in output_plan.shares:
        for _, logical in share.slot_to_logical:
            multiplicity[logical] = multiplicity.get(logical, 0) + 1
    masked_share_ids = {
        (share.component_id, share.output_block_id)
        for share in output_plan.shares
        if any(multiplicity[logical] > 1 for _, logical in share.slot_to_logical)
    }

    ciphertext_inputs: list[CiphertextInput] = []
    plaintext_masks: list[PlaintextMask] = []
    nodes: list[object] = []
    result_ids: list[str] = []
    operand_specs: list[OperandSpec] = []
    routes: list[ResultRoute] = []
    rotation_shifts: set[int] = set()
    operand_ordinal = 0
    result_ordinal = 0

    def append_operand(
        *, values: tuple[int, ...], columns: tuple[int, ...]
    ) -> tuple[str, str, str, str]:
        nonlocal operand_ordinal
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
        operand_ordinal += 1
        return ordinal, value_id, query_id, relinearized_id

    def finish_result(
        accumulated_id: str,
        *,
        component_id: str,
        output_block_id: str,
    ) -> tuple[str, str | None]:
        nonlocal result_ordinal
        result_id = f"result-{result_ordinal:06d}"
        share_id = (component_id, output_block_id)
        needs_mask = f1m_policy == "uniform-random-or-zero" or share_id in masked_share_ids
        f1m_id: str | None = None
        returned_id = accumulated_id
        if needs_mask:
            f1m_id = f"ct-f1m-{result_ordinal:06d}"
            masked_id = f"ssa-masked-{result_ordinal:06d}"
            ciphertext_inputs.append(CiphertextInput(f1m_id, "f1m-mask", slot_count))
            nodes.append(AddF1MMask(masked_id, accumulated_id, f1m_id, "opaque-zero-sum"))
            returned_id = masked_id
        nodes.append(ReturnResult(result_id, returned_id))
        result_ids.append(result_id)
        routes.append(ResultRoute(result_id, f1m_id, component_id, output_block_id))
        result_ordinal += 1
        return result_id, f1m_id

    for component in components:
        for block in component.blocks:
            if not block.chunks:
                continue
            selected_ids: list[str] = []
            pending_specs: list[tuple[str, str, int, tuple[int, ...], tuple[int, ...]]] = []
            for chunk in block.chunks:
                source_ordinal = operand_ordinal
                ordinal, value_id, query_id, relinearized_id = append_operand(
                    values=chunk.values, columns=chunk.column_indices
                )
                accumulated_id = _append_cssc_reduction(
                    nodes,
                    ordinal=ordinal,
                    source_id=relinearized_id,
                    width=chunk.width,
                    height=chunk.height,
                    rotation_shifts=rotation_shifts,
                )
                if chunk.height < slot_count:
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
                    accumulated_id = selected_id
                selected_ids.append(accumulated_id)
                pending_specs.append(
                    (value_id, query_id, source_ordinal, chunk.values, chunk.column_indices)
                )
            accumulated_id = selected_ids[0]
            for cross_ordinal, selected_id in enumerate(selected_ids[1:], start=1):
                sum_id = f"ssa-result-sum-{result_ordinal:06d}-{cross_ordinal:06d}"
                nodes.append(AddCiphertexts(sum_id, accumulated_id, selected_id))
                accumulated_id = sum_id
            result_id, _ = finish_result(
                accumulated_id,
                component_id=component.component_id,
                output_block_id=block.output_block_id,
            )
            operand_specs.extend(
                OperandSpec(
                    value_ciphertext_id=value_id,
                    query_ciphertext_id=query_id,
                    source_kind="published-chunk",
                    source_ordinal=source_ordinal,
                    result_id=result_id,
                    values=values,
                    global_column_indices=columns,
                )
                for value_id, query_id, source_ordinal, values, columns in pending_specs
            )

    if segmented_delta is not None:
        metadata_by_page = client_b_page_metadata(segmented_delta)
        page_values = [[0] * slot_count for _ in metadata_by_page]
        for segment in segmented_delta.segments:
            for offset, entry in enumerate(segment.entries):
                if entry is not None:
                    page_values[segment.page_ordinal][segment.slot_start + offset] = entry.value
        for page_ordinal, metadata in enumerate(metadata_by_page):
            ordinal, value_id, query_id, relinearized_id = append_operand(
                values=tuple(page_values[page_ordinal]),
                columns=metadata.global_column_indices,
            )
            accumulated_id = relinearized_id
            shift = 1
            while shift < segmented_delta.segment_width:
                rotation_shifts.add(shift)
                rotated_id = f"ssa-rotate-{ordinal}-{shift:06d}"
                sum_id = f"ssa-segment-sum-{ordinal}-{2 * shift:06d}"
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
                        if lane < segmented_delta.segments_per_page * segmented_delta.segment_width
                        and lane % segmented_delta.segment_width == 0
                        else 0
                        for lane in range(slot_count)
                    ),
                )
            )
            nodes.append(MultiplyPlaintextMask(selected_id, accumulated_id, mask_id))
            result_id, _ = finish_result(
                selected_id,
                component_id=STRONG_COMPONENT_ID,
                output_block_id=metadata.page_id,
            )
            operand_specs.append(
                OperandSpec(
                    value_id,
                    query_id,
                    "segmented-delta-page",
                    page_ordinal,
                    result_id,
                    tuple(page_values[page_ordinal]),
                    metadata.global_column_indices,
                )
            )

    for source_ordinal, segment in enumerate(client_lane_segments):
        active = tuple(
            (lane, entry)
            for lane, entry in enumerate(segment.entries)
            if entry is not None and entry.value != 0
        )
        if not active:
            continue
        values = tuple(
            segment.entries[lane].value if lane < segment.capacity and segment.entries[lane] else 0
            for lane in range(slot_count)
        )
        columns = tuple(
            segment.entries[lane].coordinate[1]
            if lane < segment.capacity and segment.entries[lane]
            else -1
            for lane in range(slot_count)
        )
        _, value_id, query_id, relinearized_id = append_operand(values=values, columns=columns)
        result_id, _ = finish_result(
            relinearized_id,
            component_id=CLIENT_LANE_COMPONENT_ID,
            output_block_id=segment.segment_id,
        )
        operand_specs.append(
            OperandSpec(
                value_id,
                query_id,
                "client-lane-segment",
                source_ordinal,
                result_id,
                values,
                columns,
            )
        )

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
            version_id=reference.version_id,
            output_plan_digest=output_analysis.output_plan_digest,
            cloud_program_digest=program_digest,
        ),
    )
    cloud_counts = analyze_cloud_plan(cloud_plan)
    operand_specs_tuple = tuple(operand_specs)
    result_routes_tuple = tuple(routes)
    binding_digest = execution_binding_digest(cloud_plan.binding)
    compiled = CompiledQuery(
        components=components,
        segmented_delta=segmented_delta,
        client_lane_segments=client_lane_segments,
        f1m_policy=f1m_policy,
        cloud_plan=cloud_plan,
        output_plan=output_plan,
        operand_specs=operand_specs_tuple,
        result_routes=result_routes_tuple,
        cloud_program_digest=program_digest,
        output_plan_digest=output_analysis.output_plan_digest,
        execution_binding_digest=binding_digest,
        cloud_counts=cloud_counts,
        output_analysis=output_analysis,
    )
    _validate_compiled_parts(compiled)
    return compiled
