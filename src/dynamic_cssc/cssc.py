from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, TypeAlias

from .output_plan import OutputPlan, OutputShare

Coordinate: TypeAlias = tuple[int, int]
SlotLocation: TypeAlias = tuple[str, str, int]
LaneKind: TypeAlias = Literal[
    "actual", "tombstone", "natural-padding", "reserved", "tail"
]


@dataclass(frozen=True, slots=True)
class LayoutSpec:
    rows: int
    cols: int
    effective_slots: int
    partition_rows: int


@dataclass(frozen=True, slots=True)
class ValueChunk:
    """One full ciphertext payload in column-major CSSC rectangle order."""

    chunk_id: str
    start_column: int
    width: int
    height: int
    used_slots: int
    reserved_slots: int
    rectangular_slots: int
    values: tuple[int, ...]
    column_indices: tuple[int, ...]
    slot_coordinates: tuple[Coordinate | None, ...]
    slot_owner_rows: tuple[int | None, ...]
    slot_kinds: tuple[LaneKind, ...]

    @property
    def aggregation_rotations_proxy(self) -> int:
        if self.width <= 1:
            return 0
        return self.width.bit_length() - 1 + self.width.bit_count() - 1


@dataclass(frozen=True, slots=True)
class OutputBlockLayout:
    output_block_id: str
    logical_row_start: int
    logical_row_stop: int
    row_map: tuple[int, ...]
    physical_row_capacities: tuple[int, ...]
    chunks: tuple[ValueChunk, ...]


@dataclass(frozen=True, slots=True)
class PublishedComponent:
    component_id: str
    version_id: str
    layout_spec: LayoutSpec
    blocks: tuple[OutputBlockLayout, ...]
    _coordinate_slots: tuple[tuple[Coordinate, SlotLocation], ...]
    _available_slots: tuple[tuple[int, LaneKind, SlotLocation], ...]

    @property
    def chunks(self) -> tuple[ValueChunk, ...]:
        return tuple(chunk for block in self.blocks for chunk in block.chunks)

    @property
    def ciphertext_count(self) -> int:
        return len(self.chunks)

    @property
    def query_ciphertext_count(self) -> int:
        return self.ciphertext_count

    @property
    def coord_to_slot(self) -> dict[Coordinate, SlotLocation]:
        return dict(self._coordinate_slots)

    def _slots_by_row(self, kind: LaneKind) -> dict[int, tuple[SlotLocation, ...]]:
        rows: dict[int, list[SlotLocation]] = {}
        for row, lane_kind, location in self._available_slots:
            if lane_kind == kind:
                rows.setdefault(row, []).append(location)
        return {row: tuple(locations) for row, locations in rows.items()}

    @property
    def reserved_slots_by_row(self) -> dict[int, tuple[SlotLocation, ...]]:
        return self._slots_by_row("reserved")

    @property
    def natural_padding_slots_by_row(self) -> dict[int, tuple[SlotLocation, ...]]:
        return self._slots_by_row("natural-padding")


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_id(value: object, field: str) -> str:
    invalid_character = isinstance(value, str) and any(
        not 0x21 <= ord(character) <= 0x7E for character in value
    )
    if not isinstance(value, str) or not value or invalid_character:
        raise ValueError(f"{field} must be a non-empty printable ASCII identifier")
    return value


def _validate_sparse_state(
    state: Mapping[Coordinate, int], *, rows: int, cols: int
) -> tuple[tuple[Coordinate, int], ...]:
    if not isinstance(state, Mapping):
        raise ValueError("state must be a coordinate-to-value mapping")
    entries: list[tuple[Coordinate, int]] = []
    for coordinate, value in state.items():
        if (
            not isinstance(coordinate, tuple)
            or len(coordinate) != 2
            or not all(_is_strict_int(axis) for axis in coordinate)
        ):
            raise ValueError("state coordinates must be (row, global_col) integer pairs")
        row, global_col = coordinate
        if not 0 <= row < rows:
            raise ValueError("state row is outside the matrix")
        if not 0 <= global_col < cols:
            raise ValueError("state global column is outside the matrix")
        if not _is_strict_int(value) or value == 0:
            raise ValueError("state values must be nonzero integers")
        entries.append(((row, global_col), value))
    return tuple(sorted(entries))


def _physical_capacities(
    entries_by_row: Sequence[Sequence[tuple[int, int]]],
    physical_capacities: Sequence[int] | None,
    *,
    rows: int,
    cols: int,
) -> tuple[int, ...]:
    actual = tuple(len(entries) for entries in entries_by_row)
    if physical_capacities is None:
        return actual
    if not isinstance(physical_capacities, Sequence) or isinstance(
        physical_capacities, (str, bytes)
    ):
        raise ValueError("physical_capacities must be a per-row sequence")
    if len(physical_capacities) != rows:
        raise ValueError("physical_capacities must have exactly one entry per row")
    result = []
    for row, (capacity, used) in enumerate(zip(physical_capacities, actual, strict=True)):
        if not _is_strict_int(capacity) or not used <= capacity <= cols:
            raise ValueError(
                f"physical capacity for row {row} must be an integer in [{used}, {cols}]"
            )
        result.append(capacity)
    return tuple(result)


_VALIDATED_SPARSE_STATE_TOKEN = object()


def publish_component(
    state: Mapping[Coordinate, int],
    *,
    rows: int,
    cols: int,
    effective_slots: int,
    version_id: str,
    component_prefix: str,
    partition_rows: int | None = None,
    physical_capacities: Sequence[int] | None = None,
    _validation_capability: object | None = None,
) -> PublishedComponent:
    """Publish exact CSSC value/ColumnIndex metadata for one matrix component.

    Global matrix columns remain unchanged. Rows are horizontally partitioned before each
    partition is sorted by physical capacity. Every returned chunk is padded to exactly
    ``effective_slots`` lanes and stores its rectangle in column-major order.
    """

    rows = _require_positive_int(rows, "rows")
    cols = _require_positive_int(cols, "cols")
    effective_slots = _require_positive_int(effective_slots, "effective_slots")
    version_id = _require_id(version_id, "version_id")
    component_id = _require_id(component_prefix, "component_prefix")
    if partition_rows is None:
        partition_rows = effective_slots
    if (
        not _is_strict_int(partition_rows)
        or partition_rows <= 0
        or partition_rows > effective_slots
    ):
        raise ValueError("partition_rows must be in (0, effective_slots]")

    if _validation_capability is None:
        entries = _validate_sparse_state(state, rows=rows, cols=cols)
    elif _validation_capability is _VALIDATED_SPARSE_STATE_TOKEN and type(state) is dict:
        entries = tuple(sorted(state.items()))
    else:
        raise TypeError("validated sparse publication requires a repository-minted capability")
    entries_by_row: list[list[tuple[int, int]]] = [[] for _ in range(rows)]
    for (row, global_col), value in entries:
        entries_by_row[row].append((global_col, value))
    capacities = _physical_capacities(
        entries_by_row,
        physical_capacities,
        rows=rows,
        cols=cols,
    )

    blocks: list[OutputBlockLayout] = []
    placements: list[tuple[Coordinate, SlotLocation]] = []
    available_slots: list[tuple[int, LaneKind, SlotLocation]] = []
    for block_index, logical_start in enumerate(range(0, rows, partition_rows)):
        logical_stop = min(rows, logical_start + partition_rows)
        row_map = tuple(
            sorted(
                range(logical_start, logical_stop),
                key=lambda row: (-capacities[row], row),
            )
        )
        physical_row_capacities = tuple(capacities[row] for row in row_map)
        output_block_id = f"{component_id}-h{block_index:06d}"
        chunks: list[ValueChunk] = []
        max_width = max(physical_row_capacities, default=0)
        column = 0
        chunk_index = 0
        while column < max_width:
            height = sum(capacity > column for capacity in physical_row_capacities)
            width = min(max_width - column, effective_slots // height)
            chunk_id = f"{output_block_id}-c{chunk_index:06d}"
            values = [0] * effective_slots
            column_indices = [-1] * effective_slots
            slot_coordinates: list[Coordinate | None] = [None] * effective_slots
            slot_owner_rows: list[int | None] = [None] * effective_slots
            slot_kinds: list[LaneKind] = ["tail"] * effective_slots
            used_slots = 0
            reserved_slots = 0
            for local_column in range(width):
                rank = column + local_column
                for physical_row in range(height):
                    logical_row = row_map[physical_row]
                    slot = local_column * height + physical_row
                    location = (component_id, chunk_id, slot)
                    slot_owner_rows[slot] = logical_row
                    if rank >= capacities[logical_row]:
                        slot_kinds[slot] = "natural-padding"
                        available_slots.append(
                            (logical_row, "natural-padding", location)
                        )
                        continue
                    row_entries = entries_by_row[logical_row]
                    if rank >= len(row_entries):
                        slot_kinds[slot] = "reserved"
                        available_slots.append((logical_row, "reserved", location))
                        reserved_slots += 1
                        continue
                    global_col, value = row_entries[rank]
                    coordinate = (logical_row, global_col)
                    values[slot] = value
                    column_indices[slot] = global_col
                    slot_coordinates[slot] = coordinate
                    slot_kinds[slot] = "actual"
                    placements.append((coordinate, location))
                    used_slots += 1
            chunks.append(
                ValueChunk(
                    chunk_id=chunk_id,
                    start_column=column,
                    width=width,
                    height=height,
                    used_slots=used_slots,
                    reserved_slots=reserved_slots,
                    rectangular_slots=height * width,
                    values=tuple(values),
                    column_indices=tuple(column_indices),
                    slot_coordinates=tuple(slot_coordinates),
                    slot_owner_rows=tuple(slot_owner_rows),
                    slot_kinds=tuple(slot_kinds),
                )
            )
            column += width
            chunk_index += 1
        blocks.append(
            OutputBlockLayout(
                output_block_id=output_block_id,
                logical_row_start=logical_start,
                logical_row_stop=logical_stop,
                row_map=row_map,
                physical_row_capacities=physical_row_capacities,
                chunks=tuple(chunks),
            )
        )

    return PublishedComponent(
        component_id=component_id,
        version_id=version_id,
        layout_spec=LayoutSpec(
            rows=rows,
            cols=cols,
            effective_slots=effective_slots,
            partition_rows=partition_rows,
        ),
        blocks=tuple(blocks),
        _coordinate_slots=tuple(sorted(placements)),
        _available_slots=tuple(available_slots),
    )


def _publish_validated_component(
    state: dict[Coordinate, int],
    *,
    rows: int,
    cols: int,
    effective_slots: int,
    version_id: str,
    component_prefix: str,
    partition_rows: int | None = None,
    physical_capacities: Sequence[int] | None = None,
) -> PublishedComponent:
    """Publish a state already proved valid by the strategy transition boundary."""

    return publish_component(
        state,
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        version_id=version_id,
        component_prefix=component_prefix,
        partition_rows=partition_rows,
        physical_capacities=physical_capacities,
        _validation_capability=_VALIDATED_SPARSE_STATE_TOKEN,
    )


def output_plan_for(components: Sequence[PublishedComponent]) -> OutputPlan:
    """Build a version-matched plan; rows without contributors reconstruct as zero."""

    if not isinstance(components, Sequence) or isinstance(components, (str, bytes)):
        raise ValueError("components must be a sequence of PublishedComponent values")
    if not components:
        raise ValueError("components must not be empty")
    if any(not isinstance(component, PublishedComponent) for component in components):
        raise ValueError("components must contain PublishedComponent values")

    reference = components[0]
    component_ids: set[str] = set()
    shares: list[OutputShare] = []
    for component in components:
        if component.component_id in component_ids:
            raise ValueError("component IDs must be unique within an OutputPlan")
        component_ids.add(component.component_id)
        if component.version_id != reference.version_id:
            raise ValueError("all components must have the same version_id")
        component_matrix = (
            component.layout_spec.rows,
            component.layout_spec.cols,
            component.layout_spec.effective_slots,
        )
        reference_matrix = (
            reference.layout_spec.rows,
            reference.layout_spec.cols,
            reference.layout_spec.effective_slots,
        )
        if component_matrix != reference_matrix:
            raise ValueError("all components must have the same matrix and slot dimensions")
        for block in component.blocks:
            if not block.chunks:
                continue
            active_row_map = tuple(
                logical_row
                for logical_row, capacity in zip(
                    block.row_map,
                    block.physical_row_capacities,
                    strict=True,
                )
                if capacity > 0
            )
            if not active_row_map:
                continue
            shares.append(
                OutputShare(
                    component_id=component.component_id,
                    output_block_id=block.output_block_id,
                    slot_to_logical=tuple(enumerate(active_row_map)),
                )
            )
    return OutputPlan(
        logical_output_size=reference.layout_spec.rows,
        slot_count=reference.layout_spec.effective_slots,
        shares=tuple(shares),
    )


@dataclass(frozen=True, slots=True)
class CSSCChunk:
    chunk_id: int
    start_column: int
    width: int
    height: int
    used_slots: int
    rectangular_slots: int
    padding_by_physical_row: tuple[int, ...]

    @property
    def utilization(self) -> float:
        return self.used_slots / self.rectangular_slots if self.rectangular_slots else 1.0

    @property
    def aggregation_rotations_proxy(self) -> int:
        if self.width <= 1:
            return 0
        return self.width.bit_length() - 1 + self.width.bit_count() - 1


@dataclass(frozen=True, slots=True)
class CSSCLayout:
    logical_row_order: tuple[int, ...]
    physical_row_lengths: tuple[int, ...]
    chunks: tuple[CSSCChunk, ...]
    padding_chunk_ids_by_logical_row: tuple[tuple[int, ...], ...]
    value_chunk_ids_by_coordinate_rank: tuple[tuple[int, ...], ...]
    effective_slots: int

    @property
    def ciphertext_count(self) -> int:
        return len(self.chunks)

    @property
    def query_ciphertext_count(self) -> int:
        return len(self.chunks)

    @property
    def rotation_count_proxy(self) -> int:
        return sum(chunk.aggregation_rotations_proxy for chunk in self.chunks)


def build_cssc_layout(row_lengths: list[int], effective_slots: int) -> CSSCLayout:
    """Build a deterministic rectangular-chunk proxy of the published CSSC layout.

    Rows are sorted by descending length. Consecutive left-aligned columns are grouped into
    the widest rectangle whose height × width fits one ciphertext. This module is explicitly
    a Day-1 counting model; OpenFHE measurements are kept separate.
    """

    if effective_slots <= 0:
        raise ValueError("effective_slots must be positive")
    if any(length < 0 for length in row_lengths):
        raise ValueError("row lengths must be nonnegative")

    order = tuple(sorted(range(len(row_lengths)), key=lambda row: (-row_lengths[row], row)))
    physical_lengths = tuple(row_lengths[row] for row in order)
    max_width = max(physical_lengths, default=0)
    column_heights = [
        sum(length > column for length in physical_lengths)
        for column in range(max_width)
    ]

    padding_by_logical: list[list[int]] = [[] for _ in row_lengths]
    value_chunks_by_logical: list[list[int]] = [[] for _ in row_lengths]
    chunks: list[CSSCChunk] = []
    column = 0
    chunk_id = 0

    while column < max_width:
        height = column_heights[column]
        if height <= 0:
            break
        width = min(max_width - column, effective_slots // height)
        if width <= 0:
            raise ValueError(
                f"column height {height} exceeds effective slot capacity {effective_slots}"
            )
        used = sum(column_heights[column : column + width])
        padding_counts = [0] * height
        for physical_row in range(height):
            logical_row = order[physical_row]
            row_length = physical_lengths[physical_row]
            for local_column in range(width):
                absolute_column = column + local_column
                if absolute_column < row_length:
                    value_chunks_by_logical[logical_row].append(chunk_id)
                else:
                    padding_counts[physical_row] += 1
                    padding_by_logical[logical_row].append(chunk_id)
        chunks.append(
            CSSCChunk(
                chunk_id=chunk_id,
                start_column=column,
                width=width,
                height=height,
                used_slots=used,
                rectangular_slots=height * width,
                padding_by_physical_row=tuple(padding_counts),
            )
        )
        column += width
        chunk_id += 1

    return CSSCLayout(
        logical_row_order=order,
        physical_row_lengths=physical_lengths,
        chunks=tuple(chunks),
        padding_chunk_ids_by_logical_row=tuple(tuple(items) for items in padding_by_logical),
        value_chunk_ids_by_coordinate_rank=tuple(
            tuple(items) for items in value_chunks_by_logical
        ),
        effective_slots=effective_slots,
    )
