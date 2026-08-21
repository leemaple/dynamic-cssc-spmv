from __future__ import annotations

from dataclasses import dataclass


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
