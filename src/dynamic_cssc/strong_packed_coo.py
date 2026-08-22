from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from dynamic_cssc.events import NetUpdate
from dynamic_cssc.output_plan import OutputShare

STRONG_COMPONENT_ID = "strong-packed-coo-delta"


@dataclass(frozen=True, slots=True)
class StrongEntry:
    row: int
    col: int
    value: int

    @property
    def coordinate(self) -> tuple[int, int]:
        return self.row, self.col


@dataclass(frozen=True, slots=True)
class StrongSegment:
    segment_id: str
    segment_ordinal: int
    page_ordinal: int
    slot_start: int
    owner_row: int
    entries: tuple[StrongEntry | None, ...]


@dataclass(frozen=True, slots=True)
class SegmentedDeltaState:
    rows: int
    cols: int
    effective_slots: int
    segment_width: int
    matrix_value_bound: int
    version_id: str
    segments: tuple[StrongSegment, ...]

    @property
    def segments_per_page(self) -> int:
        return self.effective_slots // self.segment_width


@dataclass(frozen=True, slots=True)
class SegmentedDeltaTransition:
    state: SegmentedDeltaState
    changed_page_ids: tuple[str, ...]
    ci_patch_entries: int
    ci_full_sync_entries: int
    new_segment_count: int
    new_page_count: int


@dataclass(frozen=True, slots=True)
class CloudPageShape:
    page_id: str
    page_ordinal: int
    slot_count: int
    segment_width: int
    segment_count: int


@dataclass(frozen=True, slots=True)
class ClientBPageMetadata:
    page_id: str
    version_id: str
    global_column_indices: tuple[int, ...]


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise ValueError(f"{field} must be a positive strict integer")
    return value


def _require_id(value: object, field: str) -> str:
    invalid_character = isinstance(value, str) and any(
        not 0x21 <= ord(character) <= 0x7E for character in value
    )
    if not isinstance(value, str) or not value or invalid_character:
        raise ValueError(f"{field} must be a non-empty printable ASCII identifier")
    return value


def _page_id(page_ordinal: int) -> str:
    return f"page-{page_ordinal:06d}"


def _segment_id(segment_ordinal: int) -> str:
    return f"segment-{segment_ordinal:06d}"


def _validated_entry(entry: object, state: SegmentedDeltaState) -> StrongEntry:
    if not isinstance(entry, StrongEntry):
        raise ValueError("overflow_entries must contain StrongEntry values")
    if not all(_is_strict_int(value) for value in (entry.row, entry.col, entry.value)):
        raise ValueError("entry fields must be strict integers")
    if not 0 <= entry.row < state.rows or not 0 <= entry.col < state.cols:
        raise ValueError("entry coordinate is outside the matrix")
    if entry.value == 0 or abs(entry.value) > state.matrix_value_bound:
        raise ValueError("entry value violates the matrix value bound")
    return entry


def initialize_segmented_delta(
    *,
    rows: int,
    cols: int,
    effective_slots: int,
    segment_width: int,
    matrix_value_bound: int,
    version_id: str,
) -> SegmentedDeltaState:
    rows = _positive_int(rows, "rows")
    cols = _positive_int(cols, "cols")
    effective_slots = _positive_int(effective_slots, "effective_slots")
    matrix_value_bound = _positive_int(matrix_value_bound, "matrix_value_bound")
    if (
        not _is_strict_int(segment_width)
        or segment_width < 2
        or segment_width > effective_slots
        or segment_width & (segment_width - 1)
    ):
        raise ValueError("segment_width must be a power of two in [2, effective_slots]")
    return SegmentedDeltaState(
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        segment_width=segment_width,
        matrix_value_bound=matrix_value_bound,
        version_id=_require_id(version_id, "version_id"),
        segments=(),
    )


def advance_segmented_delta(
    state: SegmentedDeltaState,
    *,
    delta_updates: tuple[NetUpdate, ...],
    overflow_entries: tuple[StrongEntry, ...],
    version_id: str,
) -> SegmentedDeltaTransition:
    if not isinstance(state, SegmentedDeltaState):
        raise ValueError("state must be a SegmentedDeltaState")
    version_id = _require_id(version_id, "version_id")
    if version_id == state.version_id:
        raise ValueError("version_id must advance")
    if not isinstance(delta_updates, tuple):
        raise ValueError("delta_updates must be a tuple")
    if not isinstance(overflow_entries, tuple):
        raise ValueError("overflow_entries must be a tuple")

    decoded = decode_segmented_delta(state)
    seen: set[tuple[int, int]] = set()
    mutable = [list(segment.entries) for segment in state.segments]
    changed_segments: set[int] = set()
    for update in delta_updates:
        if not isinstance(update, NetUpdate):
            raise ValueError("delta_updates must contain NetUpdate values")
        if not all(
            _is_strict_int(value) for value in (update.row, update.col, update.before, update.after)
        ):
            raise ValueError("update fields must be strict integers")
        coordinate = (update.row, update.col)
        if coordinate in seen:
            raise ValueError("updates and overflow entries must have unique coordinates")
        seen.add(coordinate)
        if not 0 <= update.row < state.rows or not 0 <= update.col < state.cols:
            raise ValueError("update coordinate is outside the matrix")
        if update.before == update.after:
            raise ValueError("delta_updates must not contain no-op updates")
        if decoded.get(coordinate) != update.before:
            raise ValueError("update.before does not match the active delta")
        if abs(update.after) > state.matrix_value_bound:
            raise ValueError("update.after violates the matrix value bound")
        location = next(
            (
                (segment_index, slot)
                for segment_index, entries in enumerate(mutable)
                for slot, entry in enumerate(entries)
                if entry is not None and entry.value != 0 and entry.coordinate == coordinate
            ),
            None,
        )
        if location is None:
            raise AssertionError("active delta coordinate has no physical lane")
        segment_index, slot = location
        mutable[segment_index][slot] = StrongEntry(update.row, update.col, update.after)
        changed_segments.add(segment_index)

    validated_overflow = []
    for raw_entry in overflow_entries:
        entry = _validated_entry(raw_entry, state)
        if entry.coordinate in seen or entry.coordinate in decoded:
            raise ValueError("updates and overflow entries must have unique new coordinates")
        seen.add(entry.coordinate)
        validated_overflow.append(entry)

    unplaced_by_row: dict[int, list[StrongEntry]] = {}
    for entry in sorted(validated_overflow, key=lambda item: item.coordinate):
        exact_tombstone = next(
            (
                (segment_index, slot)
                for segment_index, (segment, entries) in enumerate(
                    zip(state.segments, mutable, strict=True)
                )
                for slot, resident in enumerate(entries)
                if segment.owner_row == entry.row
                and resident is not None
                and resident.value == 0
                and resident.coordinate == entry.coordinate
            ),
            None,
        )
        location = exact_tombstone or next(
            (
                (segment_index, slot)
                for segment_index, (segment, entries) in enumerate(
                    zip(state.segments, mutable, strict=True)
                )
                for slot, resident in enumerate(entries)
                if segment.owner_row == entry.row and (resident is None or resident.value == 0)
            ),
            None,
        )
        if location is None:
            unplaced_by_row.setdefault(entry.row, []).append(entry)
            continue
        segment_index, slot = location
        mutable[segment_index][slot] = entry
        changed_segments.add(segment_index)

    segments_per_page = state.segments_per_page
    for row in sorted(unplaced_by_row):
        entries = unplaced_by_row[row]
        for offset in range(0, len(entries), state.segment_width):
            segment_entries = entries[offset : offset + state.segment_width]
            segment_entries.extend([None] * (state.segment_width - len(segment_entries)))
            segment_ordinal = len(mutable)
            mutable.append(segment_entries)
            changed_segments.add(segment_ordinal)

    segments = tuple(
        StrongSegment(
            segment_id=_segment_id(segment_ordinal),
            segment_ordinal=segment_ordinal,
            page_ordinal=segment_ordinal // segments_per_page,
            slot_start=(segment_ordinal % segments_per_page) * state.segment_width,
            owner_row=(
                state.segments[segment_ordinal].owner_row
                if segment_ordinal < len(state.segments)
                else next(entry.row for entry in entries if entry is not None)
            ),
            entries=tuple(entries),
        )
        for segment_ordinal, entries in enumerate(mutable)
    )
    new_state = replace(state, version_id=version_id, segments=segments)
    _assert_state_invariants(new_state)
    old_metadata = {
        metadata.page_id: metadata.global_column_indices
        for metadata in client_b_page_metadata(state)
    }
    new_metadata = client_b_page_metadata(new_state)
    new_page_count = sum(metadata.page_id not in old_metadata for metadata in new_metadata)
    ci_patch_entries = sum(
        old_column != new_column
        for metadata in new_metadata
        if metadata.page_id in old_metadata
        for old_column, new_column in zip(
            old_metadata[metadata.page_id],
            metadata.global_column_indices,
            strict=True,
        )
    )
    changed_pages = tuple(
        _page_id(page_ordinal)
        for page_ordinal in sorted(
            {segment_ordinal // segments_per_page for segment_ordinal in changed_segments}
        )
    )
    return SegmentedDeltaTransition(
        state=new_state,
        changed_page_ids=changed_pages,
        ci_patch_entries=ci_patch_entries,
        ci_full_sync_entries=new_page_count * state.effective_slots,
        new_segment_count=len(segments) - len(state.segments),
        new_page_count=new_page_count,
    )


def decode_segmented_delta(state: SegmentedDeltaState) -> dict[tuple[int, int], int]:
    _assert_state_invariants(state)
    decoded: dict[tuple[int, int], int] = {}
    for segment in state.segments:
        for entry in segment.entries:
            if entry is None or entry.value == 0:
                continue
            if entry.coordinate in decoded:
                raise AssertionError("active delta coordinates must be unique")
            decoded[entry.coordinate] = entry.value
    return decoded


def cloud_page_shapes(state: SegmentedDeltaState) -> tuple[CloudPageShape, ...]:
    _assert_state_invariants(state)
    page_count = (len(state.segments) + state.segments_per_page - 1) // state.segments_per_page
    return tuple(
        CloudPageShape(
            page_id=_page_id(page_ordinal),
            page_ordinal=page_ordinal,
            slot_count=state.effective_slots,
            segment_width=state.segment_width,
            segment_count=state.segments_per_page,
        )
        for page_ordinal in range(page_count)
    )


def client_b_page_metadata(
    state: SegmentedDeltaState,
) -> tuple[ClientBPageMetadata, ...]:
    """Return private global-CI vectors for Client B, never the Cloud."""

    columns_by_page = [[-1] * state.effective_slots for _ in cloud_page_shapes(state)]
    for segment in state.segments:
        page_columns = columns_by_page[segment.page_ordinal]
        for offset, entry in enumerate(segment.entries):
            if entry is not None:
                page_columns[segment.slot_start + offset] = entry.col
    return tuple(
        ClientBPageMetadata(
            page_id=_page_id(page_ordinal),
            version_id=state.version_id,
            global_column_indices=tuple(columns),
        )
        for page_ordinal, columns in enumerate(columns_by_page)
    )


def post_aggregation_output_shares(
    state: SegmentedDeltaState,
) -> tuple[OutputShare, ...]:
    _assert_state_invariants(state)
    allocated_by_page: dict[int, list[tuple[int, int]]] = {}
    for segment in state.segments:
        allocated_by_page.setdefault(segment.page_ordinal, []).append(
            (segment.slot_start, segment.owner_row)
        )
    return tuple(
        OutputShare(
            component_id=STRONG_COMPONENT_ID,
            output_block_id=_page_id(page_ordinal),
            slot_to_logical=tuple(allocated_by_page[page_ordinal]),
        )
        for page_ordinal in sorted(allocated_by_page)
    )


def _assert_state_invariants(state: SegmentedDeltaState) -> None:
    if not isinstance(state, SegmentedDeltaState):
        raise ValueError("state must be a SegmentedDeltaState")
    if not all(
        _is_strict_int(value) and value > 0
        for value in (
            state.rows,
            state.cols,
            state.effective_slots,
            state.matrix_value_bound,
        )
    ):
        raise AssertionError("state dimensions and value bound must be positive integers")
    if (
        not _is_strict_int(state.segment_width)
        or state.segment_width < 2
        or state.segment_width > state.effective_slots
        or state.segment_width & (state.segment_width - 1)
    ):
        raise AssertionError("state segment width must be a fitting power of two")
    try:
        _require_id(state.version_id, "version_id")
    except ValueError as error:
        raise AssertionError("state version ID is invalid") from error
    if not isinstance(state.segments, tuple):
        raise AssertionError("state segments must be a tuple")
    seen: Counter[tuple[int, int]] = Counter()
    for ordinal, segment in enumerate(state.segments):
        if not isinstance(segment, StrongSegment):
            raise AssertionError("state segments must contain StrongSegment values")
        if segment.segment_ordinal != ordinal or segment.segment_id != _segment_id(ordinal):
            raise AssertionError("segment IDs must encode only the physical ordinal")
        if segment.page_ordinal != ordinal // state.segments_per_page:
            raise AssertionError("segment page must match its physical ordinal")
        if segment.slot_start != (ordinal % state.segments_per_page) * state.segment_width:
            raise AssertionError("segment leader lane must match its physical ordinal")
        if len(segment.entries) != state.segment_width:
            raise AssertionError("segments must have the frozen fixed width")
        if not 0 <= segment.owner_row < state.rows:
            raise AssertionError("segment owner is outside the matrix")
        for entry in segment.entries:
            if entry is None:
                continue
            if (
                not isinstance(entry, StrongEntry)
                or not all(_is_strict_int(value) for value in (entry.row, entry.col, entry.value))
                or not 0 <= entry.row < state.rows
                or not 0 <= entry.col < state.cols
                or abs(entry.value) > state.matrix_value_bound
            ):
                raise AssertionError("segment entry is outside the state bounds")
            if entry.row != segment.owner_row:
                raise AssertionError("one segment must belong to one logical row")
            if entry.value != 0:
                seen[entry.coordinate] += 1
    if any(count != 1 for count in seen.values()):
        raise AssertionError("active delta coordinates must be unique")
