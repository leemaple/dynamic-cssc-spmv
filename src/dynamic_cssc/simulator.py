from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import ceil, log2

from .cssc import CSSCLayout, build_cssc_layout
from .events import NetUpdate, PublicationWindow
from .metrics import StrategyMetrics, UnitCosts


@dataclass(frozen=True, slots=True)
class SimulationConfig:
    rows: int
    effective_slots: int
    partition_rows: int
    reserved_slack_beta: float = 0.10
    periodic_repack_period: int = 4
    packed_coo_segment_capacity: int = 128


@dataclass(frozen=True, slots=True)
class WindowShape:
    modifications: tuple[NetUpdate, ...]
    deletions: tuple[NetUpdate, ...]
    insertions: tuple[NetUpdate, ...]
    absorbed_by_tombstone: int
    absorbed_by_padding: int
    absorbed_by_reserved_slack: int
    overflow_by_row: tuple[int, ...]
    dirty_rows: frozenset[int]

    @property
    def overflow_total(self) -> int:
        return sum(self.overflow_by_row)

    @property
    def absorbed_total(self) -> int:
        return (
            self.absorbed_by_tombstone
            + self.absorbed_by_padding
            + self.absorbed_by_reserved_slack
        )


def _partition(row: int, partition_rows: int) -> int:
    return row // partition_rows


def classify_window(
    window: PublicationWindow,
    base_state: dict[tuple[int, int], int],
    layout: CSSCLayout,
    *,
    reserved_slack_beta: float,
) -> WindowShape:
    modifications: list[NetUpdate] = []
    deletions: list[NetUpdate] = []
    insertions: list[NetUpdate] = []
    tombstone_by_row: dict[int, int] = defaultdict(int)

    for update in window.updates:
        base_value = base_state.get((update.row, update.col), 0)
        if base_value != 0 and update.after == 0:
            deletions.append(update)
            tombstone_by_row[update.row] += 1
        elif base_value != 0 and update.after != base_value:
            modifications.append(update)
        elif base_value == 0 and update.after != 0:
            insertions.append(update)

    padding = [len(slots) for slots in layout.padding_chunk_ids_by_logical_row]
    base_lengths = [0] * len(layout.logical_row_order)
    for row, length in zip(layout.logical_row_order, layout.physical_row_lengths, strict=True):
        base_lengths[row] = length
    reserved = [ceil(reserved_slack_beta * max(1, length)) for length in base_lengths]
    overflow = [0] * len(base_lengths)
    absorbed_tombstone = 0
    absorbed_padding = 0
    absorbed_reserved = 0

    for update in insertions:
        row = update.row
        if tombstone_by_row[row] > 0:
            tombstone_by_row[row] -= 1
            absorbed_tombstone += 1
        elif padding[row] > 0:
            padding[row] -= 1
            absorbed_padding += 1
        elif reserved[row] > 0:
            reserved[row] -= 1
            absorbed_reserved += 1
        else:
            overflow[row] += 1

    return WindowShape(
        modifications=tuple(modifications),
        deletions=tuple(deletions),
        insertions=tuple(insertions),
        absorbed_by_tombstone=absorbed_tombstone,
        absorbed_by_padding=absorbed_padding,
        absorbed_by_reserved_slack=absorbed_reserved,
        overflow_by_row=tuple(overflow),
        dirty_rows=frozenset(update.row for update in window.updates),
    )


def _touched_value_chunks(shape: WindowShape, layout: CSSCLayout) -> int:
    touched: set[int] = set()
    for update in (*shape.modifications, *shape.deletions):
        candidates = layout.value_chunk_ids_by_coordinate_rank[update.row]
        if candidates:
            touched.add(candidates[0])
    # Absorbed insertions patch a value/CI chunk. The proxy conservatively counts one touched
    # chunk per affected row, capped by the static chunk count.
    absorbed_rows = {
        update.row
        for update in shape.insertions
        if shape.absorbed_total > 0
    }
    for row in absorbed_rows:
        padding_chunks = layout.padding_chunk_ids_by_logical_row[row]
        if padding_chunks:
            touched.add(padding_chunks[0])
    return len(touched)


def _split_output_blinding(result_ciphertexts: int) -> tuple[int, int, int]:
    if result_ciphertexts <= 1:
        return 0, 0, 0
    return result_ciphertexts, result_ciphertexts, result_ciphertexts


def _base_query_metrics(layout: CSSCLayout) -> tuple[int, int, int]:
    return (
        layout.query_ciphertext_count,
        layout.ciphertext_count,
        layout.rotation_count_proxy,
    )


def evaluate_window(
    window: PublicationWindow,
    shape: WindowShape,
    base_row_lengths: list[int],
    layout: CSSCLayout,
    config: SimulationConfig,
) -> dict[str, StrategyMetrics]:
    updates = len(window.updates)
    base_query_ct, base_mults, base_rots = _base_query_metrics(layout)
    dirty_partitions = {
        _partition(row, config.partition_rows) for row in shape.dirty_rows
    }
    partition_count = max(1, ceil(config.rows / config.partition_rows))
    base_result_ct = partition_count
    touched_chunks = _touched_value_chunks(shape, layout)
    overflow_total = shape.overflow_total
    absorbed_total = shape.absorbed_total

    results: dict[str, StrategyMetrics] = {}

    padding = StrategyMetrics("PaddingReuse-CSSC", "reference", windows=1, updates=updates)
    padding.absorbed_updates = absorbed_total
    padding.overflow_updates = overflow_total
    padding.update_encryptions = touched_chunks
    padding.update_ciphertexts = touched_chunks
    if overflow_total:
        repack_ct = sum(
            build_cssc_layout(
                base_row_lengths[
                    partition * config.partition_rows : (partition + 1) * config.partition_rows
                ],
                config.effective_slots,
            ).ciphertext_count
            for partition in dirty_partitions
        )
        padding.compaction_ciphertexts = repack_ct
        padding.update_encryptions += repack_ct
    padding.query_ciphertexts = base_query_ct
    padding.result_ciphertexts = base_result_ct
    padding.cc_multiplications = base_mults
    padding.rotations = base_rots
    padding.decryptions = base_result_ct
    results[padding.strategy] = padding

    reserved = StrategyMetrics("ReservedSlack-CSSC", "reference", windows=1, updates=updates)
    reserved.absorbed_updates = absorbed_total
    reserved.overflow_updates = overflow_total
    reserved.update_encryptions = touched_chunks
    reserved.update_ciphertexts = touched_chunks
    reserved.query_ciphertexts = base_query_ct
    reserved.result_ciphertexts = base_result_ct
    reserved.cc_multiplications = base_mults
    reserved.rotations = base_rots
    reserved.decryptions = base_result_ct
    results[reserved.strategy] = reserved

    delta_layout = build_cssc_layout(list(shape.overflow_by_row), config.effective_slots)
    mini = StrategyMetrics("Mini-CSSC-Delta", "reference", windows=1, updates=updates)
    mini.absorbed_updates = absorbed_total
    mini.overflow_updates = overflow_total
    mini.update_encryptions = touched_chunks + delta_layout.ciphertext_count
    mini.update_ciphertexts = touched_chunks + delta_layout.ciphertext_count
    mini.query_ciphertexts = base_query_ct + delta_layout.query_ciphertext_count
    mini.result_ciphertexts = base_result_ct + (1 if overflow_total else 0)
    mini.cc_multiplications = base_mults + delta_layout.ciphertext_count
    mini.rotations = base_rots + delta_layout.rotation_count_proxy
    mini.decryptions = mini.result_ciphertexts
    mini.client_merges = 1 if overflow_total else 0
    masks, mask_enc, mask_add = _split_output_blinding(mini.result_ciphertexts)
    mini.blinding_mask_ciphertexts = masks
    mini.blinding_encryptions = mask_enc
    mini.blinding_additions = mask_add
    results[mini.strategy] = mini

    coo_ct = ceil(overflow_total / max(1, config.packed_coo_segment_capacity)) if overflow_total else 0
    coo = StrategyMetrics("Packed-COO-HYB-Delta", "reference", windows=1, updates=updates)
    coo.absorbed_updates = absorbed_total
    coo.overflow_updates = overflow_total
    coo.update_encryptions = touched_chunks + coo_ct
    coo.update_ciphertexts = touched_chunks + coo_ct
    coo.query_ciphertexts = base_query_ct + coo_ct
    coo.result_ciphertexts = base_result_ct + (coo_ct if coo_ct else 0)
    coo.cc_multiplications = base_mults + coo_ct
    coo.rotations = base_rots + coo_ct * ceil(log2(max(1, config.packed_coo_segment_capacity)))
    coo.additions = coo.rotations
    coo.decryptions = coo.result_ciphertexts
    coo.client_merges = 1 if coo_ct else 0
    masks, mask_enc, mask_add = _split_output_blinding(coo.result_ciphertexts)
    coo.blinding_mask_ciphertexts = masks
    coo.blinding_encryptions = mask_enc
    coo.blinding_additions = mask_add
    results[coo.strategy] = coo

    local = StrategyMetrics("Strict-LocalRepack", "reference", windows=1, updates=updates)
    repack_ct = sum(
        build_cssc_layout(
            base_row_lengths[
                partition * config.partition_rows : (partition + 1) * config.partition_rows
            ],
            config.effective_slots,
        ).ciphertext_count
        for partition in dirty_partitions
    )
    local.update_encryptions = repack_ct
    local.update_ciphertexts = repack_ct
    local.compaction_ciphertexts = repack_ct
    local.query_ciphertexts = base_query_ct
    local.result_ciphertexts = base_result_ct
    local.cc_multiplications = base_mults
    local.rotations = base_rots
    local.decryptions = base_result_ct
    results[local.strategy] = local

    periodic = StrategyMetrics("PeriodicRepack", "reference", windows=1, updates=updates)
    if window.index % max(1, config.periodic_repack_period) == 0:
        periodic.update_encryptions = repack_ct
        periodic.update_ciphertexts = repack_ct
        periodic.compaction_ciphertexts = repack_ct
    periodic.query_ciphertexts = base_query_ct
    periodic.result_ciphertexts = base_result_ct
    periodic.cc_multiplications = base_mults
    periodic.rotations = base_rots
    periodic.decryptions = base_result_ct
    results[periodic.strategy] = periodic

    return results


def simulate(
    windows: list[PublicationWindow],
    initial_state: dict[tuple[int, int], int],
    config: SimulationConfig,
    *,
    costs: UnitCosts | None = None,
) -> list[StrategyMetrics]:
    costs = costs or UnitCosts()
    row_lengths = [0] * config.rows
    for row, _col in initial_state:
        row_lengths[row] += 1
    layout = build_cssc_layout(row_lengths, config.effective_slots)
    aggregates: dict[str, StrategyMetrics] = {}

    for window in windows:
        shape = classify_window(
            window,
            initial_state,
            layout,
            reserved_slack_beta=config.reserved_slack_beta,
        )
        window_results = evaluate_window(window, shape, row_lengths, layout, config)
        for name, metrics in window_results.items():
            if name not in aggregates:
                aggregates[name] = StrategyMetrics(name, metrics.category)
            aggregates[name].merge(metrics)

    # Causal proxy selector: choose the fixed strategy with the lowest historical normalized
    # cost at each stage. It is intentionally labeled as a proxy until a full stateful selector
    # and switching costs are implemented.
    if aggregates:
        selected = min(aggregates.values(), key=lambda item: item.predicted_time(costs))
        hybrid = StrategyMetrics("Hybrid-Selector-Proxy", "candidate")
        hybrid.merge(selected)
        hybrid.strategy = "Hybrid-Selector-Proxy"
        hybrid.category = "candidate"
        aggregates[hybrid.strategy] = hybrid

    return sorted(aggregates.values(), key=lambda item: item.strategy)
