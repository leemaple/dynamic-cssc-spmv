from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from math import ceil, isfinite
from typing import Literal, TypeAlias

from dynamic_cssc.cssc import (
    LaneKind,
    PublishedComponent,
    SlotLocation,
    output_plan_for,
    publish_component,
)
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.output_plan import OutputPlan, OutputShare, analyze_output_plan

Coordinate: TypeAlias = tuple[int, int]
StrategyKind: TypeAlias = Literal[
    "PaddingReuse-CSSC",
    "ReservedSlack-CSSC",
    "Mini-CSSC-Delta",
    "Packed-COO-HYB-Delta",
    "Strict-LocalRepack",
    "PeriodicRepack",
]
ManagedLaneKind: TypeAlias = Literal[
    "tombstone", "natural-padding", "reserved"
]

STRATEGIES: tuple[StrategyKind, ...] = (
    "PaddingReuse-CSSC",
    "ReservedSlack-CSSC",
    "Mini-CSSC-Delta",
    "Packed-COO-HYB-Delta",
    "Strict-LocalRepack",
    "PeriodicRepack",
)


@dataclass(frozen=True, slots=True)
class StrategyConfig:
    rows: int
    cols: int
    effective_slots: int
    partition_rows: int
    matrix_value_bound: int
    max_row_nnz: int
    reserved_slack_beta: float
    periodic_repack_windows: int
    packed_coo_segment_capacity: int


@dataclass(frozen=True, slots=True)
class FreeLane:
    row: int
    kind: ManagedLaneKind
    location: SlotLocation
    retained_column: int | None = None


@dataclass(frozen=True, slots=True)
class PackedCOOEntry:
    coordinate: Coordinate
    value: int


@dataclass(frozen=True, slots=True)
class PackedCOOSegment:
    """Fixed input lanes plus the explicit segmented-aggregation output layout."""

    segment_id: str
    version_id: str
    capacity: int
    entries: tuple[PackedCOOEntry | None, ...]
    output_row_map: tuple[int, ...]
    entry_lane_to_output_slot: tuple[int | None, ...]


@dataclass(frozen=True, slots=True)
class StrategyState:
    strategy: StrategyKind
    config: StrategyConfig
    version_ordinal: int
    version_id: str
    logical: dict[Coordinate, int]
    base: PublishedComponent
    delta: PublishedComponent | None
    delta_logical: dict[Coordinate, int]
    coo_segments: tuple[PackedCOOSegment, ...]
    free_lanes: tuple[FreeLane, ...]
    windows_since_repack: int
    repack_count: int


@dataclass(frozen=True, slots=True)
class TransitionFacts:
    updates: int
    query_count: int
    value_patch_chunks: int = 0
    ci_patch_entries: int = 0
    ci_full_sync_entries: int = 0
    rebuilt_ciphertexts: int = 0
    delta_ciphertexts: int = 0
    delta_rebuilt_ciphertexts: int = 0
    absorbed_tombstone: int = 0
    absorbed_natural_padding: int = 0
    absorbed_reserved: int = 0
    overflow: int = 0
    patched_chunk_ids: tuple[tuple[str, str], ...] = ()
    rebuilt_output_block_ids: tuple[str, ...] = ()
    active_component_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Transition:
    state: StrategyState
    facts: TransitionFacts
    output_plan: OutputPlan


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise ValueError(f"{field} must be a positive strict integer")
    return value


def _validate_config(
    strategy: object,
    *,
    rows: object,
    cols: object,
    effective_slots: object,
    partition_rows: object,
    matrix_value_bound: object,
    max_row_nnz: object,
    reserved_slack_beta: object,
    periodic_repack_windows: object,
    packed_coo_segment_capacity: object,
) -> tuple[StrategyKind, StrategyConfig]:
    if strategy not in STRATEGIES:
        raise ValueError(f"strategy must be one of {STRATEGIES}")
    rows = _positive_int(rows, "rows")
    cols = _positive_int(cols, "cols")
    effective_slots = _positive_int(effective_slots, "effective_slots")
    if partition_rows is None:
        partition_rows = effective_slots
    partition_rows = _positive_int(partition_rows, "partition_rows")
    if partition_rows > effective_slots:
        raise ValueError("partition_rows must not exceed effective_slots")
    matrix_value_bound = _positive_int(matrix_value_bound, "matrix_value_bound")
    max_row_nnz = _positive_int(max_row_nnz, "max_row_nnz")
    periodic_repack_windows = _positive_int(
        periodic_repack_windows, "periodic_repack_windows"
    )
    packed_coo_segment_capacity = _positive_int(
        packed_coo_segment_capacity, "packed_coo_segment_capacity"
    )
    if strategy == "Packed-COO-HYB-Delta" and (
        packed_coo_segment_capacity > effective_slots
    ):
        raise ValueError(
            "packed_coo_segment_capacity must not exceed effective_slots"
        )
    if (
        isinstance(reserved_slack_beta, bool)
        or not isinstance(reserved_slack_beta, (int, float))
        or not isfinite(float(reserved_slack_beta))
        or reserved_slack_beta < 0
    ):
        raise ValueError("reserved_slack_beta must be a finite nonnegative number")
    return strategy, StrategyConfig(
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        matrix_value_bound=matrix_value_bound,
        max_row_nnz=max_row_nnz,
        reserved_slack_beta=float(reserved_slack_beta),
        periodic_repack_windows=periodic_repack_windows,
        packed_coo_segment_capacity=packed_coo_segment_capacity,
    )


def _validate_logical(
    logical: object, config: StrategyConfig
) -> dict[Coordinate, int]:
    if not isinstance(logical, dict):
        raise ValueError("logical state must be a coordinate-to-value dict")
    result: dict[Coordinate, int] = {}
    row_counts: Counter[int] = Counter()
    for coordinate, value in logical.items():
        if (
            not isinstance(coordinate, tuple)
            or len(coordinate) != 2
            or not all(_is_strict_int(axis) for axis in coordinate)
        ):
            raise ValueError("logical coordinates must contain strict integer pairs")
        row, col = coordinate
        if not 0 <= row < config.rows or not 0 <= col < config.cols:
            raise ValueError("logical coordinate is outside the matrix")
        if (
            not _is_strict_int(value)
            or value == 0
            or abs(value) > config.matrix_value_bound
        ):
            raise ValueError("logical value violates the matrix value bound")
        result[coordinate] = value
        row_counts[row] += 1
    if any(count > config.max_row_nnz for count in row_counts.values()):
        raise ValueError("logical state violates the row nonzero bound")
    return result


def _reserved_capacities(
    logical: dict[Coordinate, int], config: StrategyConfig
) -> tuple[int, ...]:
    row_counts: Counter[int] = Counter(row for row, _ in logical)
    capacities = tuple(
        row_counts[row]
        + ceil(config.reserved_slack_beta * max(1, row_counts[row]))
        for row in range(config.rows)
    )
    if any(capacity > config.cols for capacity in capacities):
        raise ValueError("reserved slack capacity exceeds the matrix column count")
    return capacities


def _free_lanes(component: PublishedComponent) -> tuple[FreeLane, ...]:
    lanes: list[FreeLane] = []
    for chunk in component.chunks:
        for slot, (kind, row, col) in enumerate(
            zip(
                chunk.slot_kinds,
                chunk.slot_owner_rows,
                chunk.column_indices,
                strict=True,
            )
        ):
            if kind not in {"tombstone", "natural-padding", "reserved"}:
                continue
            if row is None:
                raise AssertionError("a reusable lane must have a logical row owner")
            lanes.append(
                FreeLane(
                    row=row,
                    kind=kind,
                    location=(component.component_id, chunk.chunk_id, slot),
                    retained_column=col if kind == "tombstone" else None,
                )
            )
    return tuple(
        sorted(
            lanes,
            key=lambda lane: (
                lane.row,
                {"tombstone": 0, "natural-padding": 1, "reserved": 2}[lane.kind],
                lane.location,
            ),
        )
    )


def _reindex_component(component: PublishedComponent) -> PublishedComponent:
    placements: list[tuple[Coordinate, SlotLocation]] = []
    available: list[tuple[int, LaneKind, SlotLocation]] = []
    blocks = []
    for block in component.blocks:
        chunks = []
        for chunk in block.chunks:
            kinds = tuple(chunk.slot_kinds)
            chunks.append(
                replace(
                    chunk,
                    used_slots=sum(kind == "actual" for kind in kinds),
                    reserved_slots=sum(kind == "reserved" for kind in kinds),
                )
            )
            for slot, (kind, row, coordinate) in enumerate(
                zip(
                    kinds,
                    chunk.slot_owner_rows,
                    chunk.slot_coordinates,
                    strict=True,
                )
            ):
                location = (component.component_id, chunk.chunk_id, slot)
                if kind == "actual":
                    if coordinate is None:
                        raise AssertionError("an actual lane must own a coordinate")
                    placements.append((coordinate, location))
                elif kind in {"tombstone", "natural-padding", "reserved"}:
                    if row is None:
                        raise AssertionError("a reusable lane must own a row")
                    available.append((row, kind, location))
        blocks.append(replace(block, chunks=tuple(chunks)))
    return replace(
        component,
        blocks=tuple(blocks),
        _coordinate_slots=tuple(sorted(placements)),
        _available_slots=tuple(available),
    )


def _patch_lane(
    component: PublishedComponent,
    location: SlotLocation,
    *,
    coordinate: Coordinate | None,
    value: int,
    column_index: int,
    kind: LaneKind,
) -> PublishedComponent:
    if location[0] != component.component_id:
        raise AssertionError("slot location belongs to another component")
    found = False
    blocks = []
    for block in component.blocks:
        chunks = []
        extended_row: int | None = None
        for chunk in block.chunks:
            if chunk.chunk_id != location[1]:
                chunks.append(chunk)
                continue
            slot = location[2]
            if not 0 <= slot < component.layout_spec.effective_slots:
                raise AssertionError("slot location is outside the ciphertext")
            values = list(chunk.values)
            columns = list(chunk.column_indices)
            coordinates = list(chunk.slot_coordinates)
            kinds = list(chunk.slot_kinds)
            previous_kind = kinds[slot]
            values[slot] = value
            columns[slot] = column_index
            coordinates[slot] = coordinate
            kinds[slot] = kind
            if previous_kind == "natural-padding" and kind == "actual":
                extended_row = chunk.slot_owner_rows[slot]
                if extended_row is None:
                    raise AssertionError("natural padding must have a row owner")
            chunks.append(
                replace(
                    chunk,
                    values=tuple(values),
                    column_indices=tuple(columns),
                    slot_coordinates=tuple(coordinates),
                    slot_kinds=tuple(kinds),
                )
            )
            found = True
        capacities = list(block.physical_row_capacities)
        if extended_row is not None:
            physical_row = block.row_map.index(extended_row)
            capacities[physical_row] += 1
        blocks.append(
            replace(
                block,
                physical_row_capacities=tuple(capacities),
                chunks=tuple(chunks),
            )
        )
    if not found:
        raise AssertionError("slot location does not name an active chunk")
    return _reindex_component(replace(component, blocks=tuple(blocks)))


def _chunk_block_ids(component: PublishedComponent) -> dict[str, str]:
    return {
        chunk.chunk_id: block.output_block_id
        for block in component.blocks
        for chunk in block.chunks
    }


def _point_patch_base(
    state: StrategyState,
    updates: tuple[NetUpdate, ...],
    *,
    allow_reserved: bool,
) -> tuple[
    PublishedComponent,
    set[tuple[str, str]],
    list[SlotLocation],
    Counter[str],
    list[Coordinate],
]:
    base = state.base
    patched_chunks: set[tuple[str, str]] = set()
    ci_patch_locations: list[SlotLocation] = []
    absorbed: Counter[str] = Counter()
    overflow: list[Coordinate] = []

    modifications = tuple(
        update
        for update in updates
        if update.before != 0 and update.after != 0 and not update.is_noop
    )
    deletions = tuple(
        update for update in updates if update.before != 0 and update.after == 0
    )
    insertions = tuple(
        update for update in updates if update.before == 0 and update.after != 0
    )

    for update in modifications:
        coordinate = (update.row, update.col)
        location = base.coord_to_slot.get(coordinate)
        if location is None:
            raise AssertionError("a base modification must name an actual lane")
        base = _patch_lane(
            base,
            location,
            coordinate=coordinate,
            value=update.after,
            column_index=update.col,
            kind="actual",
        )
        patched_chunks.add((location[0], location[1]))

    for update in deletions:
        coordinate = (update.row, update.col)
        location = base.coord_to_slot.get(coordinate)
        if location is None:
            raise AssertionError("a base deletion must name an actual lane")
        base = _patch_lane(
            base,
            location,
            coordinate=None,
            value=0,
            column_index=update.col,
            kind="tombstone",
        )
        patched_chunks.add((location[0], location[1]))

    allowed_kinds = {"tombstone", "natural-padding"}
    if allow_reserved:
        allowed_kinds.add("reserved")
    for update in insertions:
        lane = next(
            (
                item
                for item in _free_lanes(base)
                if item.row == update.row and item.kind in allowed_kinds
            ),
            None,
        )
        if lane is None:
            overflow.append((update.row, update.col))
            continue
        base = _patch_lane(
            base,
            lane.location,
            coordinate=(update.row, update.col),
            value=update.after,
            column_index=update.col,
            kind="actual",
        )
        absorbed[lane.kind] += 1
        ci_patch_locations.append(lane.location)
        patched_chunks.add((lane.location[0], lane.location[1]))
    return base, patched_chunks, ci_patch_locations, absorbed, overflow


def _physical_capacities_for(
    state: StrategyState, logical: dict[Coordinate, int]
) -> tuple[int, ...] | None:
    if state.strategy == "ReservedSlack-CSSC":
        return _reserved_capacities(logical, state.config)
    return None


def _rebuild_base_blocks(
    state: StrategyState,
    patched_base: PublishedComponent,
    logical: dict[Coordinate, int],
    dirty_blocks: set[int],
    version_id: str,
) -> tuple[PublishedComponent, int, int, tuple[str, ...]]:
    published = publish_component(
        logical,
        rows=state.config.rows,
        cols=state.config.cols,
        effective_slots=state.config.effective_slots,
        partition_rows=state.config.partition_rows,
        physical_capacities=_physical_capacities_for(state, logical),
        version_id=version_id,
        component_prefix=patched_base.component_id,
    )
    blocks = tuple(
        new_block if index in dirty_blocks else old_block
        for index, (old_block, new_block) in enumerate(
            zip(patched_base.blocks, published.blocks, strict=True)
        )
    )
    rebuilt = tuple(published.blocks[index] for index in sorted(dirty_blocks))
    component = _reindex_component(
        replace(patched_base, version_id=version_id, blocks=blocks)
    )
    return (
        component,
        sum(len(block.chunks) for block in rebuilt),
        sum(len(chunk.column_indices) for block in rebuilt for chunk in block.chunks),
        tuple(block.output_block_id for block in rebuilt),
    )


def initialize_strategy(
    strategy: StrategyKind,
    initial_state: dict[Coordinate, int],
    *,
    rows: int,
    cols: int,
    effective_slots: int,
    partition_rows: int | None = None,
    matrix_value_bound: int = 7,
    max_row_nnz: int = 4096,
    reserved_slack_beta: float = 0.10,
    periodic_repack_windows: int = 4,
    packed_coo_segment_capacity: int = 128,
) -> StrategyState:
    """Create one strategy-owned publication state without sharing mutable layout state."""

    strategy, config = _validate_config(
        strategy,
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        matrix_value_bound=matrix_value_bound,
        max_row_nnz=max_row_nnz,
        reserved_slack_beta=reserved_slack_beta,
        periodic_repack_windows=periodic_repack_windows,
        packed_coo_segment_capacity=packed_coo_segment_capacity,
    )
    logical = _validate_logical(initial_state, config)
    capacities = (
        _reserved_capacities(logical, config)
        if strategy == "ReservedSlack-CSSC"
        else None
    )
    base = publish_component(
        logical,
        rows=config.rows,
        cols=config.cols,
        effective_slots=config.effective_slots,
        partition_rows=config.partition_rows,
        physical_capacities=capacities,
        version_id="v00000000",
        component_prefix="base",
    )
    state = StrategyState(
        strategy=strategy,
        config=config,
        version_ordinal=0,
        version_id="v00000000",
        logical=dict(logical),
        base=base,
        delta=None,
        delta_logical={},
        coo_segments=(),
        free_lanes=_free_lanes(base),
        windows_since_repack=0,
        repack_count=0,
    )
    assert_strategy_invariants(state)
    return state


def _decode_component(component: PublishedComponent) -> dict[Coordinate, int]:
    decoded: dict[Coordinate, int] = {}
    for chunk in component.chunks:
        for kind, coordinate, value in zip(
            chunk.slot_kinds, chunk.slot_coordinates, chunk.values, strict=True
        ):
            if kind != "actual":
                continue
            if coordinate is None or value == 0 or coordinate in decoded:
                raise AssertionError("published actual lanes must decode uniquely")
            decoded[coordinate] = value
    return decoded


def decode_state(state: StrategyState) -> dict[Coordinate, int]:
    """Decode the exact logical matrix represented by active strategy components."""

    decoded = _decode_component(state.base)
    if state.delta is not None:
        for coordinate, value in _decode_component(state.delta).items():
            if coordinate in decoded:
                raise AssertionError("base and delta coordinates must be disjoint")
            decoded[coordinate] = value
    for segment in state.coo_segments:
        for entry in segment.entries:
            if entry is None or entry.value == 0:
                continue
            if entry.coordinate in decoded:
                raise AssertionError("base and COO coordinates must be disjoint")
            decoded[entry.coordinate] = entry.value
    return decoded


def assert_strategy_invariants(state: StrategyState) -> None:
    """Raise AssertionError unless the publication state is exact and version-consistent."""

    if not _is_strict_int(state.version_ordinal) or state.version_ordinal < 0:
        raise AssertionError("version ordinal must be a nonnegative strict integer")
    if state.version_id != f"v{state.version_ordinal:08d}":
        raise AssertionError("version identifier must match its ordinal")
    if not _is_strict_int(state.windows_since_repack) or state.windows_since_repack < 0:
        raise AssertionError("windows-since-repack must be a nonnegative integer")
    if not _is_strict_int(state.repack_count) or state.repack_count < 0:
        raise AssertionError("repack count must be a nonnegative integer")
    if state.strategy != "PeriodicRepack" and state.windows_since_repack != 0:
        raise AssertionError("only PeriodicRepack may retain a publication-window counter")
    if (
        state.strategy == "PeriodicRepack"
        and state.windows_since_repack >= state.config.periodic_repack_windows
    ):
        raise AssertionError("PeriodicRepack must fold when its period expires")
    if state.base.version_id != state.version_id:
        raise AssertionError("base component version must match the strategy version")
    if state.delta is not None and state.delta.version_id != state.version_id:
        raise AssertionError("delta component version must match the strategy version")
    if any(segment.version_id != state.version_id for segment in state.coo_segments):
        raise AssertionError("COO segment versions must match the strategy version")
    for component in (state.base,) if state.delta is None else (state.base, state.delta):
        _assert_component_invariants(component, state.config)
    if state.strategy not in {"Mini-CSSC-Delta", "PeriodicRepack"} and state.delta:
        raise AssertionError("only CSSC-delta strategies may own a delta component")
    if state.strategy != "Packed-COO-HYB-Delta" and state.coo_segments:
        raise AssertionError("only Packed-COO may own fixed COO segments")
    segment_ids: set[str] = set()
    coo_coordinates: set[Coordinate] = set()
    for segment in state.coo_segments:
        if segment.segment_id in segment_ids:
            raise AssertionError("COO segment identifiers must be unique")
        segment_ids.add(segment.segment_id)
        if segment.capacity != state.config.packed_coo_segment_capacity or (
            len(segment.entries) != segment.capacity
        ):
            raise AssertionError("COO segments must retain their fixed capacity")
        for entry in segment.entries:
            if entry is None:
                continue
            if entry.value != 0 and entry.coordinate in coo_coordinates:
                raise AssertionError("COO coordinates must have one physical owner")
            if entry.value != 0:
                coo_coordinates.add(entry.coordinate)
            row, col = entry.coordinate
            if not 0 <= row < state.config.rows or not 0 <= col < state.config.cols:
                raise AssertionError("COO coordinate is outside the matrix")
            if (
                not _is_strict_int(entry.value)
                or abs(entry.value) > state.config.matrix_value_bound
            ):
                raise AssertionError("COO value violates the matrix value bound")
        output_row_map, lane_map = _coo_output_layout(segment.entries)
        if (
            segment.output_row_map != output_row_map
            or segment.entry_lane_to_output_slot != lane_map
        ):
            raise AssertionError("COO output layout must match its physical entry lanes")
    if state.delta_logical != (
        _decode_component(state.delta) if state.delta is not None else {
            entry.coordinate: entry.value
            for segment in state.coo_segments
            for entry in segment.entries
            if entry is not None and entry.value != 0
        }
    ):
        raise AssertionError("persistent delta metadata must match its layout")
    if state.free_lanes != _free_lanes(state.base):
        raise AssertionError("free-lane metadata must match the base component")
    if decode_state(state) != state.logical:
        raise AssertionError("decoded components must equal the logical matrix")
    _validate_logical(state.logical, state.config)


def _assert_component_invariants(
    component: PublishedComponent, config: StrategyConfig
) -> None:
    spec = component.layout_spec
    if (
        spec.rows,
        spec.cols,
        spec.effective_slots,
        spec.partition_rows,
    ) != (
        config.rows,
        config.cols,
        config.effective_slots,
        config.partition_rows,
    ):
        raise AssertionError("component layout specification must match strategy config")
    scanned: dict[Coordinate, SlotLocation] = {}
    for block in component.blocks:
        materialized_width = {row: 0 for row in block.row_map}
        for chunk in block.chunks:
            for slot, (kind, owner) in enumerate(
                zip(chunk.slot_kinds, chunk.slot_owner_rows, strict=True)
            ):
                if kind not in {"actual", "tombstone", "reserved"}:
                    continue
                if owner not in materialized_width:
                    raise AssertionError("materialized lane owner must belong to its block")
                rank = chunk.start_column + slot // chunk.height
                materialized_width[owner] = max(
                    materialized_width[owner], rank + 1
                )
        if block.physical_row_capacities != tuple(
            materialized_width[row] for row in block.row_map
        ):
            raise AssertionError(
                "physical row capacities must match materialized lane ranks"
            )
    for chunk in component.chunks:
        lane_lengths = {
            len(chunk.values),
            len(chunk.column_indices),
            len(chunk.slot_coordinates),
            len(chunk.slot_owner_rows),
            len(chunk.slot_kinds),
        }
        if lane_lengths != {config.effective_slots}:
            raise AssertionError("each component chunk must contain full-length lane arrays")
        for slot, (kind, value, col, coordinate, owner) in enumerate(
            zip(
                chunk.slot_kinds,
                chunk.values,
                chunk.column_indices,
                chunk.slot_coordinates,
                chunk.slot_owner_rows,
                strict=True,
            )
        ):
            location = (component.component_id, chunk.chunk_id, slot)
            if kind == "actual":
                if (
                    owner is None
                    or coordinate != (owner, col)
                    or not 0 <= owner < config.rows
                    or not 0 <= col < config.cols
                    or not _is_strict_int(value)
                    or value == 0
                    or abs(value) > config.matrix_value_bound
                ):
                    raise AssertionError("actual lane metadata is inconsistent")
                if coordinate in scanned:
                    raise AssertionError("actual coordinates must have one physical lane")
                scanned[coordinate] = location
            elif kind == "tombstone":
                if (
                    owner is None
                    or coordinate is not None
                    or value != 0
                    or not 0 <= col < config.cols
                ):
                    raise AssertionError("tombstone must retain only its old ColumnIndex")
            elif kind in {"natural-padding", "reserved"}:
                if owner is None or coordinate is not None or value != 0 or col != -1:
                    raise AssertionError("free CSSC lane metadata is inconsistent")
            elif kind == "tail":
                if owner is not None or coordinate is not None or value != 0 or col != -1:
                    raise AssertionError("tail lanes must be unowned and inert")
            else:
                raise AssertionError(f"unknown component lane kind: {kind}")
    if component.coord_to_slot != scanned:
        raise AssertionError("component coordinate index must match its actual lanes")


def _validated_candidate(
    state: StrategyState, window: PublicationWindow
) -> dict[Coordinate, int]:
    if not isinstance(window, PublicationWindow):
        raise ValueError("window must be a PublicationWindow")
    seen: set[Coordinate] = set()
    candidate = dict(state.logical)
    for update in window.updates:
        if not isinstance(update, NetUpdate):
            raise ValueError("window updates must contain NetUpdate values")
        if not all(
            _is_strict_int(value)
            for value in (update.row, update.col, update.before, update.after)
        ):
            raise ValueError("update fields must be strict integers")
        coordinate = (update.row, update.col)
        if coordinate in seen:
            raise ValueError("window updates must have unique coordinates")
        seen.add(coordinate)
        if not 0 <= update.row < state.config.rows or not (
            0 <= update.col < state.config.cols
        ):
            raise ValueError("update coordinate is outside the matrix")
        if state.logical.get(coordinate, 0) != update.before:
            raise ValueError("update.before does not match the published logical state")
        if abs(update.after) > state.config.matrix_value_bound:
            raise ValueError("update.after violates the matrix value bound")
        if update.after == 0:
            candidate.pop(coordinate, None)
        else:
            candidate[coordinate] = update.after
    return _validate_logical(candidate, state.config)


def advance_publication(
    state: StrategyState, window: PublicationWindow
) -> Transition:
    """Atomically advance one strategy by one causally closed publication window."""

    assert_strategy_invariants(state)
    candidate = _validated_candidate(state, window)
    if not _is_strict_int(window.query_count) or window.query_count < 0:
        raise ValueError("window.query_count must be a nonnegative strict integer")
    if not window.updates:
        plan = _output_plan_for_state(state)
        return Transition(
            state=state,
            facts=TransitionFacts(
                updates=0,
                query_count=window.query_count,
                delta_ciphertexts=_delta_ciphertext_count(state),
                active_component_ids=_active_component_ids(state),
            ),
            output_plan=plan,
        )

    version_ordinal = state.version_ordinal + 1
    version_id = f"v{version_ordinal:08d}"
    if state.strategy in {"PaddingReuse-CSSC", "ReservedSlack-CSSC"}:
        patched, patched_chunks, ci_locations, absorbed, overflow = (
            _point_patch_base(
                state,
                window.updates,
                allow_reserved=state.strategy == "ReservedSlack-CSSC",
            )
        )
        dirty_blocks = {
            row // state.config.partition_rows for row, _ in overflow
        }
        rebuilt_ciphertexts = 0
        ci_full_sync_entries = 0
        rebuilt_output_block_ids: tuple[str, ...] = ()
        if dirty_blocks:
            block_by_chunk = _chunk_block_ids(patched)
            patched_chunks = {
                chunk_id
                for chunk_id in patched_chunks
                if int(block_by_chunk[chunk_id[1]].rsplit("h", 1)[1])
                not in dirty_blocks
            }
            ci_locations = [
                location
                for location in ci_locations
                if int(block_by_chunk[location[1]].rsplit("h", 1)[1])
                not in dirty_blocks
            ]
            (
                base,
                rebuilt_ciphertexts,
                ci_full_sync_entries,
                rebuilt_output_block_ids,
            ) = _rebuild_base_blocks(
                state, patched, candidate, dirty_blocks, version_id
            )
        else:
            base = _reindex_component(replace(patched, version_id=version_id))
        new_state = replace(
            state,
            version_ordinal=version_ordinal,
            version_id=version_id,
            logical=dict(candidate),
            base=base,
            free_lanes=_free_lanes(base),
            repack_count=state.repack_count + bool(dirty_blocks),
        )
        assert_strategy_invariants(new_state)
        facts = TransitionFacts(
            updates=len(window.updates),
            query_count=window.query_count,
            value_patch_chunks=len(patched_chunks),
            ci_patch_entries=len(ci_locations),
            ci_full_sync_entries=ci_full_sync_entries,
            rebuilt_ciphertexts=rebuilt_ciphertexts,
            absorbed_tombstone=absorbed["tombstone"],
            absorbed_natural_padding=absorbed["natural-padding"],
            absorbed_reserved=absorbed["reserved"],
            overflow=len(overflow),
            patched_chunk_ids=tuple(sorted(patched_chunks)),
            rebuilt_output_block_ids=rebuilt_output_block_ids,
            active_component_ids=(base.component_id,),
        )
        return Transition(new_state, facts, _checked_output_plan((base,)))
    if state.strategy in {"Mini-CSSC-Delta", "PeriodicRepack"}:
        if (
            state.strategy == "PeriodicRepack"
            and state.windows_since_repack + 1
            >= state.config.periodic_repack_windows
        ):
            return _fold_periodic(
                state,
                window,
                candidate,
                version_ordinal=version_ordinal,
                version_id=version_id,
            )
        return _advance_cssc_delta(
            state,
            window,
            candidate,
            version_ordinal=version_ordinal,
            version_id=version_id,
        )
    if state.strategy == "Strict-LocalRepack":
        return _advance_local_repack(
            state,
            window,
            candidate,
            version_ordinal=version_ordinal,
            version_id=version_id,
        )
    if state.strategy == "Packed-COO-HYB-Delta":
        return _advance_packed_coo(
            state,
            window,
            candidate,
            version_ordinal=version_ordinal,
            version_id=version_id,
        )
    raise NotImplementedError(
        f"publication transition is not implemented for {state.strategy}"
    )


def _checked_output_plan(components: tuple[PublishedComponent, ...]) -> OutputPlan:
    plan = output_plan_for(components)
    analyze_output_plan(plan)
    return plan


def _delta_ciphertext_count(state: StrategyState) -> int:
    if state.delta is not None:
        return len(state.delta.chunks)
    return sum(
        any(entry is not None and entry.value != 0 for entry in segment.entries)
        for segment in state.coo_segments
    )


def _active_component_ids(state: StrategyState) -> tuple[str, ...]:
    component_ids = [state.base.component_id]
    if state.delta is not None:
        component_ids.append(state.delta.component_id)
    if any(
        any(entry is not None and entry.value != 0 for entry in segment.entries)
        for segment in state.coo_segments
    ):
        component_ids.append("packed-coo-delta")
    return tuple(component_ids)


def _output_plan_for_state(state: StrategyState) -> OutputPlan:
    if state.strategy == "Packed-COO-HYB-Delta":
        return _packed_coo_output_plan(state)
    components = (state.base,) if state.delta is None else (state.base, state.delta)
    return _checked_output_plan(components)


def _split_base_and_delta_updates(
    state: StrategyState, updates: tuple[NetUpdate, ...]
) -> tuple[tuple[NetUpdate, ...], tuple[NetUpdate, ...]]:
    base_updates: list[NetUpdate] = []
    delta_updates: list[NetUpdate] = []
    for update in updates:
        coordinate = (update.row, update.col)
        if update.before != 0 and coordinate in state.delta_logical:
            delta_updates.append(update)
        else:
            base_updates.append(update)
    return tuple(base_updates), tuple(delta_updates)


def _publish_delta(
    state: StrategyState,
    delta_logical: dict[Coordinate, int],
    *,
    version_id: str,
    component_prefix: str,
) -> PublishedComponent | None:
    if not delta_logical:
        return None
    return publish_component(
        delta_logical,
        rows=state.config.rows,
        cols=state.config.cols,
        effective_slots=state.config.effective_slots,
        partition_rows=state.config.partition_rows,
        version_id=version_id,
        component_prefix=component_prefix,
    )


def _advance_cssc_delta(
    state: StrategyState,
    window: PublicationWindow,
    candidate: dict[Coordinate, int],
    *,
    version_ordinal: int,
    version_id: str,
) -> Transition:
    base_updates, delta_updates = _split_base_and_delta_updates(
        state, window.updates
    )
    patched, patched_chunks, ci_locations, absorbed, overflow = _point_patch_base(
        state,
        base_updates,
        allow_reserved=False,
    )
    delta_logical = dict(state.delta_logical)
    delta_changed = False
    for update in delta_updates:
        coordinate = (update.row, update.col)
        if update.after == 0:
            delta_logical.pop(coordinate)
        else:
            delta_logical[coordinate] = update.after
        delta_changed = delta_changed or not update.is_noop
    for coordinate in overflow:
        delta_logical[coordinate] = candidate[coordinate]
        delta_changed = True

    component_prefix = (
        "mini-delta"
        if state.strategy == "Mini-CSSC-Delta"
        else "periodic-delta"
    )
    if delta_changed:
        delta = _publish_delta(
            state,
            delta_logical,
            version_id=version_id,
            component_prefix=component_prefix,
        )
        delta_rebuilt_ciphertexts = len(delta.chunks) if delta is not None else 0
        delta_ci_sync = (
            sum(len(chunk.column_indices) for chunk in delta.chunks)
            if delta is not None
            else 0
        )
    else:
        delta = (
            replace(state.delta, version_id=version_id)
            if state.delta is not None
            else None
        )
        delta_rebuilt_ciphertexts = 0
        delta_ci_sync = 0
    base = _reindex_component(replace(patched, version_id=version_id))
    new_state = replace(
        state,
        version_ordinal=version_ordinal,
        version_id=version_id,
        logical=dict(candidate),
        base=base,
        delta=delta,
        delta_logical=dict(delta_logical),
        free_lanes=_free_lanes(base),
        windows_since_repack=(
            state.windows_since_repack + 1
            if state.strategy == "PeriodicRepack"
            else state.windows_since_repack
        ),
    )
    assert_strategy_invariants(new_state)
    components = (base,) if delta is None else (base, delta)
    facts = TransitionFacts(
        updates=len(window.updates),
        query_count=window.query_count,
        value_patch_chunks=len(patched_chunks),
        ci_patch_entries=len(ci_locations),
        ci_full_sync_entries=delta_ci_sync,
        delta_ciphertexts=len(delta.chunks) if delta is not None else 0,
        delta_rebuilt_ciphertexts=delta_rebuilt_ciphertexts,
        absorbed_tombstone=absorbed["tombstone"],
        absorbed_natural_padding=absorbed["natural-padding"],
        overflow=len(overflow),
        patched_chunk_ids=tuple(sorted(patched_chunks)),
        active_component_ids=tuple(component.component_id for component in components),
    )
    return Transition(new_state, facts, _checked_output_plan(components))


def _advance_local_repack(
    state: StrategyState,
    window: PublicationWindow,
    candidate: dict[Coordinate, int],
    *,
    version_ordinal: int,
    version_id: str,
) -> Transition:
    dirty_blocks = {
        update.row // state.config.partition_rows for update in window.updates
    }
    base, rebuilt, ci_sync, block_ids = _rebuild_base_blocks(
        state,
        state.base,
        candidate,
        dirty_blocks,
        version_id,
    )
    new_state = replace(
        state,
        version_ordinal=version_ordinal,
        version_id=version_id,
        logical=dict(candidate),
        base=base,
        free_lanes=_free_lanes(base),
        repack_count=state.repack_count + 1,
    )
    assert_strategy_invariants(new_state)
    return Transition(
        state=new_state,
        facts=TransitionFacts(
            updates=len(window.updates),
            query_count=window.query_count,
            ci_full_sync_entries=ci_sync,
            rebuilt_ciphertexts=rebuilt,
            rebuilt_output_block_ids=block_ids,
            active_component_ids=(base.component_id,),
        ),
        output_plan=_checked_output_plan((base,)),
    )


def _fold_periodic(
    state: StrategyState,
    window: PublicationWindow,
    candidate: dict[Coordinate, int],
    *,
    version_ordinal: int,
    version_id: str,
) -> Transition:
    base_updates, _delta_updates = _split_base_and_delta_updates(
        state, window.updates
    )
    _patched, _chunks, _ci, absorbed, overflow = _point_patch_base(
        state,
        base_updates,
        allow_reserved=False,
    )
    base = publish_component(
        candidate,
        rows=state.config.rows,
        cols=state.config.cols,
        effective_slots=state.config.effective_slots,
        partition_rows=state.config.partition_rows,
        version_id=version_id,
        component_prefix="base",
    )
    new_state = replace(
        state,
        version_ordinal=version_ordinal,
        version_id=version_id,
        logical=dict(candidate),
        base=base,
        delta=None,
        delta_logical={},
        free_lanes=_free_lanes(base),
        windows_since_repack=0,
        repack_count=state.repack_count + 1,
    )
    assert_strategy_invariants(new_state)
    return Transition(
        state=new_state,
        facts=TransitionFacts(
            updates=len(window.updates),
            query_count=window.query_count,
            ci_full_sync_entries=sum(
                len(chunk.column_indices) for chunk in base.chunks
            ),
            rebuilt_ciphertexts=len(base.chunks),
            absorbed_tombstone=absorbed["tombstone"],
            absorbed_natural_padding=absorbed["natural-padding"],
            overflow=len(overflow),
            rebuilt_output_block_ids=tuple(
                block.output_block_id for block in base.blocks
            ),
            active_component_ids=(base.component_id,),
        ),
        output_plan=_checked_output_plan((base,)),
    )


def _packed_coo_output_plan(state: StrategyState) -> OutputPlan:
    base_plan = _checked_output_plan((state.base,))
    shares = list(base_plan.shares)
    for segment in state.coo_segments:
        if not segment.output_row_map:
            continue
        shares.append(
            OutputShare(
                component_id="packed-coo-delta",
                output_block_id=segment.segment_id,
                slot_to_logical=tuple(enumerate(segment.output_row_map)),
            )
        )
    plan = OutputPlan(
        logical_output_size=state.config.rows,
        slot_count=state.config.effective_slots,
        shares=tuple(shares),
    )
    analyze_output_plan(plan)
    return plan


def _coo_output_layout(
    entries: tuple[PackedCOOEntry | None, ...],
) -> tuple[tuple[int, ...], tuple[int | None, ...]]:
    """Map entry lanes to first-occurrence row groups emitted by segment reduction."""

    output_rows: list[int] = []
    output_slot_by_row: dict[int, int] = {}
    lane_map: list[int | None] = []
    for entry in entries:
        if entry is None or entry.value == 0:
            lane_map.append(None)
            continue
        row = entry.coordinate[0]
        if row not in output_slot_by_row:
            output_slot_by_row[row] = len(output_rows)
            output_rows.append(row)
        lane_map.append(output_slot_by_row[row])
    return tuple(output_rows), tuple(lane_map)


def _make_coo_segment(
    *,
    segment_id: str,
    version_id: str,
    capacity: int,
    entries: tuple[PackedCOOEntry | None, ...],
) -> PackedCOOSegment:
    output_row_map, lane_map = _coo_output_layout(entries)
    return PackedCOOSegment(
        segment_id=segment_id,
        version_id=version_id,
        capacity=capacity,
        entries=entries,
        output_row_map=output_row_map,
        entry_lane_to_output_slot=lane_map,
    )


def _advance_packed_coo(
    state: StrategyState,
    window: PublicationWindow,
    candidate: dict[Coordinate, int],
    *,
    version_ordinal: int,
    version_id: str,
) -> Transition:
    base_updates, delta_updates = _split_base_and_delta_updates(
        state, window.updates
    )
    patched, patched_chunks, ci_locations, absorbed, overflow = _point_patch_base(
        state,
        base_updates,
        allow_reserved=False,
    )
    mutable_segments = [list(segment.entries) for segment in state.coo_segments]
    changed_segments: set[int] = set()

    def locate(coordinate: Coordinate) -> tuple[int, int]:
        for segment_index, entries in enumerate(mutable_segments):
            for slot, entry in enumerate(entries):
                if (
                    entry is not None
                    and entry.value != 0
                    and entry.coordinate == coordinate
                ):
                    return segment_index, slot
        raise AssertionError("persistent COO coordinate has no physical segment lane")

    for update in delta_updates:
        coordinate = (update.row, update.col)
        segment_index, slot = locate(coordinate)
        mutable_segments[segment_index][slot] = (
            PackedCOOEntry(coordinate=coordinate, value=0)
            if update.after == 0
            else PackedCOOEntry(coordinate=coordinate, value=update.after)
        )
        if not update.is_noop:
            changed_segments.add(segment_index)

    reused_coo_lanes = 0
    remaining: list[Coordinate] = []
    for coordinate in overflow:
        empty = next(
            (
                (segment_index, slot)
                for segment_index, entries in enumerate(mutable_segments)
                for slot, entry in enumerate(entries)
                if entry is None or entry.value == 0
            ),
            None,
        )
        if empty is None:
            remaining.append(coordinate)
            continue
        segment_index, slot = empty
        mutable_segments[segment_index][slot] = PackedCOOEntry(
            coordinate=coordinate,
            value=candidate[coordinate],
        )
        changed_segments.add(segment_index)
        reused_coo_lanes += 1

    capacity = state.config.packed_coo_segment_capacity
    new_segment_count = 0
    for offset in range(0, len(remaining), capacity):
        coordinates = remaining[offset : offset + capacity]
        entries: list[PackedCOOEntry | None] = [
            PackedCOOEntry(coordinate=coordinate, value=candidate[coordinate])
            for coordinate in coordinates
        ]
        entries.extend([None] * (capacity - len(entries)))
        mutable_segments.append(entries)
        changed_segments.add(len(mutable_segments) - 1)
        new_segment_count += 1

    segments = tuple(
        _make_coo_segment(
            segment_id=(
                state.coo_segments[index].segment_id
                if index < len(state.coo_segments)
                else f"segment-{index:06d}"
            ),
            version_id=version_id,
            capacity=capacity,
            entries=tuple(entries),
        )
        for index, entries in enumerate(mutable_segments)
    )
    delta_logical = {
        entry.coordinate: entry.value
        for segment in segments
        for entry in segment.entries
        if entry is not None and entry.value != 0
    }
    base = _reindex_component(replace(patched, version_id=version_id))
    new_state = replace(
        state,
        version_ordinal=version_ordinal,
        version_id=version_id,
        logical=dict(candidate),
        base=base,
        delta_logical=delta_logical,
        coo_segments=segments,
        free_lanes=_free_lanes(base),
    )
    assert_strategy_invariants(new_state)
    facts = TransitionFacts(
        updates=len(window.updates),
        query_count=window.query_count,
        value_patch_chunks=len(patched_chunks),
        ci_patch_entries=len(ci_locations) + reused_coo_lanes,
        ci_full_sync_entries=new_segment_count * capacity,
        delta_ciphertexts=sum(
            any(entry is not None and entry.value != 0 for entry in segment.entries)
            for segment in segments
        ),
        delta_rebuilt_ciphertexts=len(changed_segments),
        absorbed_tombstone=absorbed["tombstone"],
        absorbed_natural_padding=absorbed["natural-padding"],
        overflow=len(overflow),
        patched_chunk_ids=tuple(sorted(patched_chunks)),
        active_component_ids=_active_component_ids(new_state),
    )
    return Transition(new_state, facts, _packed_coo_output_plan(new_state))
