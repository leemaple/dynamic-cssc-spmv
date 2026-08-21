from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import ceil, log2

from .cssc import CSSCLayout, build_cssc_layout
from .events import NetUpdate, PublicationWindow
from .metrics import StrategyMetrics, UnitCosts
from .output_plan import OutputPlan, OutputShare, analyze_output_plan


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


def _shares_for_coordinates(
    component_id: str,
    output_block_prefix: str,
    coordinates: list[int],
    slot_count: int,
) -> list[OutputShare]:
    shares = []
    for offset in range(0, len(coordinates), slot_count):
        block = coordinates[offset : offset + slot_count]
        shares.append(
            OutputShare(
                component_id=component_id,
                output_block_id=f"{output_block_prefix}-{offset // slot_count}",
                slot_to_logical=tuple(enumerate(block)),
            )
        )
    return shares


def _base_output_shares(config: SimulationConfig) -> list[OutputShare]:
    if config.partition_rows <= 0 or config.partition_rows > config.effective_slots:
        raise ValueError("partition_rows must be in (0, effective_slots]")
    return _shares_for_coordinates(
        "base",
        "horizontal",
        list(range(config.rows)),
        config.partition_rows,
    )


def _mini_output_plan(shape: WindowShape, config: SimulationConfig) -> OutputPlan:
    shares = _base_output_shares(config)
    overflow_coordinates = [
        row for row, count in enumerate(shape.overflow_by_row) if count > 0
    ]
    shares.extend(
        _shares_for_coordinates(
            "mini-delta",
            "overflow",
            overflow_coordinates,
            config.effective_slots,
        )
    )
    return OutputPlan(config.rows, config.effective_slots, tuple(shares))


def _coo_output_plan(shape: WindowShape, config: SimulationConfig) -> OutputPlan:
    shares = _base_output_shares(config)
    entries = [
        row
        for row, count in enumerate(shape.overflow_by_row)
        for _ in range(count)
    ]
    capacity = max(1, config.packed_coo_segment_capacity)
    output_index = 0
    for offset in range(0, len(entries), capacity):
        coordinates = sorted(set(entries[offset : offset + capacity]))
        segment_shares = _shares_for_coordinates(
            "packed-coo-delta",
            f"segment-{output_index}",
            coordinates,
            config.effective_slots,
        )
        shares.extend(segment_shares)
        output_index += len(segment_shares)
    return OutputPlan(config.rows, config.effective_slots, tuple(shares))


def _apply_output_plan_accounting(
    metrics: StrategyMetrics, plan: OutputPlan, queries: int
) -> None:
    analysis = analyze_output_plan(plan)
    metrics.result_ciphertexts = queries * analysis.result_ciphertexts
    metrics.blinding_mask_ciphertexts = queries * analysis.masked_result_ciphertexts
    metrics.blinding_encryptions = queries * analysis.masked_result_ciphertexts
    metrics.blinding_additions = queries * analysis.masked_result_ciphertexts
    metrics.decryptions = queries * analysis.result_ciphertexts
    metrics.client_merges = queries * analysis.client_modular_additions
    metrics.mask_random_elements = queries * analysis.mask_random_elements
    metrics.mask_mapped_elements = queries * analysis.mask_mapped_elements
    metrics.client_reorder_elements = queries * analysis.client_reorder_elements


def _cssc_query_metrics(layout: CSSCLayout) -> tuple[int, int, int, int, int]:
    rotations = layout.rotation_count_proxy
    chunk_count = len(layout.chunks)
    # Algorithm 4 masks every chunk before merging. The executable operation plan
    # omits only an identity mask: a chunk whose height fills all effective slots
    # has no invalid output lanes after its row-wise reduction.
    plaintext_masks = sum(
        chunk.height < layout.effective_slots for chunk in layout.chunks
    )
    return (
        layout.query_ciphertext_count,
        layout.ciphertext_count,
        rotations,
        rotations + max(0, chunk_count - 1),
        plaintext_masks,
    )


def evaluate_window(
    window: PublicationWindow,
    shape: WindowShape,
    base_row_lengths: list[int],
    layout: CSSCLayout,
    config: SimulationConfig,
) -> dict[str, StrategyMetrics]:
    updates = len(window.updates)
    queries = window.query_count
    base_query_ct, base_mults, base_rots, base_adds, base_masks = (
        _cssc_query_metrics(layout)
    )
    dirty_partitions = {
        _partition(row, config.partition_rows) for row in shape.dirty_rows
    }
    base_output_plan = OutputPlan(
        config.rows,
        config.effective_slots,
        tuple(_base_output_shares(config)),
    )
    touched_chunks = _touched_value_chunks(shape, layout)
    overflow_total = shape.overflow_total
    absorbed_total = shape.absorbed_total

    results: dict[str, StrategyMetrics] = {}

    padding = StrategyMetrics(
        "PaddingReuse-CSSC", "reference", windows=1, queries=queries, updates=updates
    )
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
    padding.query_ciphertexts = queries * base_query_ct
    padding.cc_multiplications = queries * base_mults
    padding.rotations = queries * base_rots
    padding.additions = queries * base_adds
    padding.plaintext_masks = queries * base_masks
    _apply_output_plan_accounting(padding, base_output_plan, queries)
    results[padding.strategy] = padding

    reserved = StrategyMetrics(
        "ReservedSlack-CSSC", "reference", windows=1, queries=queries, updates=updates
    )
    reserved.absorbed_updates = absorbed_total
    reserved.overflow_updates = overflow_total
    reserved.update_encryptions = touched_chunks
    reserved.update_ciphertexts = touched_chunks
    reserved.query_ciphertexts = queries * base_query_ct
    reserved.cc_multiplications = queries * base_mults
    reserved.rotations = queries * base_rots
    reserved.additions = queries * base_adds
    reserved.plaintext_masks = queries * base_masks
    _apply_output_plan_accounting(reserved, base_output_plan, queries)
    results[reserved.strategy] = reserved

    delta_layout = build_cssc_layout(list(shape.overflow_by_row), config.effective_slots)
    delta_query_ct, delta_mults, delta_rots, delta_adds, delta_masks = (
        _cssc_query_metrics(delta_layout)
    )
    mini = StrategyMetrics(
        "Mini-CSSC-Delta", "reference", windows=1, queries=queries, updates=updates
    )
    mini.absorbed_updates = absorbed_total
    mini.overflow_updates = overflow_total
    mini.update_encryptions = touched_chunks + delta_layout.ciphertext_count
    mini.update_ciphertexts = touched_chunks + delta_layout.ciphertext_count
    mini.query_ciphertexts = queries * (base_query_ct + delta_query_ct)
    mini.cc_multiplications = queries * (base_mults + delta_mults)
    mini.rotations = queries * (base_rots + delta_rots)
    mini.additions = queries * (base_adds + delta_adds)
    mini.plaintext_masks = queries * (base_masks + delta_masks)
    _apply_output_plan_accounting(mini, _mini_output_plan(shape, config), queries)
    results[mini.strategy] = mini

    coo_ct = (
        ceil(overflow_total / max(1, config.packed_coo_segment_capacity))
        if overflow_total
        else 0
    )
    coo = StrategyMetrics(
        "Packed-COO-HYB-Delta", "reference", windows=1, queries=queries, updates=updates
    )
    coo.absorbed_updates = absorbed_total
    coo.overflow_updates = overflow_total
    coo.update_encryptions = touched_chunks + coo_ct
    coo.update_ciphertexts = touched_chunks + coo_ct
    coo.query_ciphertexts = queries * (base_query_ct + coo_ct)
    coo.cc_multiplications = queries * (base_mults + coo_ct)
    coo_delta_rotations = coo_ct * ceil(
        log2(max(1, config.packed_coo_segment_capacity))
    )
    coo.rotations = queries * (base_rots + coo_delta_rotations)
    coo.additions = queries * (base_adds + coo_delta_rotations)
    coo.plaintext_masks = queries * base_masks
    _apply_output_plan_accounting(coo, _coo_output_plan(shape, config), queries)
    results[coo.strategy] = coo

    local = StrategyMetrics(
        "Strict-LocalRepack", "reference", windows=1, queries=queries, updates=updates
    )
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
    local.query_ciphertexts = queries * base_query_ct
    local.cc_multiplications = queries * base_mults
    local.rotations = queries * base_rots
    local.additions = queries * base_adds
    local.plaintext_masks = queries * base_masks
    _apply_output_plan_accounting(local, base_output_plan, queries)
    results[local.strategy] = local

    periodic = StrategyMetrics(
        "PeriodicRepack", "reference", windows=1, queries=queries, updates=updates
    )
    if window.index % max(1, config.periodic_repack_period) == 0:
        periodic.update_encryptions = repack_ct
        periodic.update_ciphertexts = repack_ct
        periodic.compaction_ciphertexts = repack_ct
    periodic.query_ciphertexts = queries * base_query_ct
    periodic.cc_multiplications = queries * base_mults
    periodic.rotations = queries * base_rots
    periodic.additions = queries * base_adds
    periodic.plaintext_masks = queries * base_masks
    _apply_output_plan_accounting(periodic, base_output_plan, queries)
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

    # This deliberately looks across the full evaluation suffix. It is a diagnostic lower
    # bound, not an online selector or candidate contribution.
    if aggregates:
        selected = min(aggregates.values(), key=lambda item: item.predicted_time(costs))
        oracle = StrategyMetrics(
            "BestFixed-Offline-Oracle",
            "diagnostic-oracle",
            source="held-out-hindsight-diagnostic",
        )
        oracle.merge(selected)
        aggregates[oracle.strategy] = oracle

    return sorted(aggregates.values(), key=lambda item: item.strategy)
