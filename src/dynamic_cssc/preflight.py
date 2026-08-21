from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .cssc import PublishedComponent, output_plan_for, publish_component
from .output_plan import analyze_output_plan


class Day1PreflightError(RuntimeError):
    """Raised when the mandatory real-layout Day 1 preflight fails."""


@dataclass(frozen=True, slots=True)
class PreflightReport:
    status: str
    rows: int
    cols: int
    effective_slots: int
    output_shares: int
    observed_global_column_index: int
    modulo_alias_column_index: int
    global_gather_value: int
    modulo_alias_value: int
    reconstructed_matches_direct: bool
    reconstructed_high_row_value: int


def _strict_positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise Day1PreflightError(f"{field} must be a positive integer")
    return value


def _evaluate_layout(component: PublishedComponent, query: list[int]) -> list[int]:
    result = [0] * component.layout_spec.rows
    for chunk in component.chunks:
        slot_vectors = (
            chunk.values,
            chunk.column_indices,
            chunk.slot_coordinates,
        )
        if any(len(vector) != component.layout_spec.effective_slots for vector in slot_vectors):
            raise Day1PreflightError("CSSC chunk vectors must fill effective_slots")
        for value, global_col, coordinate in zip(*slot_vectors, strict=True):
            if coordinate is None:
                if global_col != -1 or value != 0:
                    raise Day1PreflightError("non-actual lanes must encode (value=0, CI=-1)")
                continue
            if not 0 <= global_col < len(query):
                raise Day1PreflightError("actual lane has an invalid global ColumnIndex")
            logical_row, coordinate_col = coordinate
            if coordinate_col != global_col:
                raise Day1PreflightError("coordinate and ColumnIndex disagree")
            result[logical_row] += value * query[global_col]
    return result


def _direct_spmv(
    state: Mapping[tuple[int, int], int], query: list[int], rows: int
) -> list[int]:
    result = [0] * rows
    for (row, global_col), value in state.items():
        result[row] += value * query[global_col]
    return result


def run_day1_preflight(manifest: Mapping[str, Any]) -> PreflightReport:
    """Fail closed unless the frozen multi-output/global-CI example is exact."""

    try:
        frozen = manifest["synthetic_preflight"]
    except (KeyError, TypeError) as error:
        raise Day1PreflightError("manifest is missing synthetic_preflight") from error
    if not isinstance(frozen, Mapping) or frozen.get("required_before_day1") is not True:
        raise Day1PreflightError("synthetic_preflight must be required before Day 1")
    rows = _strict_positive_int(frozen.get("rows"), "synthetic_preflight.rows")
    cols = _strict_positive_int(frozen.get("cols"), "synthetic_preflight.cols")
    effective_slots = _strict_positive_int(
        frozen.get("effective_slots"), "synthetic_preflight.effective_slots"
    )
    if (rows, cols, effective_slots) != (257, 521, 256):
        raise Day1PreflightError("synthetic_preflight dimensions changed")

    high_row = rows - 1
    high_col = cols - 1
    alias_col = high_col % effective_slots
    state = {(row, row): 1 for row in range(rows - 1)}
    state[(high_row, high_col)] = 1
    query = [0] * cols
    query[high_col] = 1
    query[alias_col] = 0

    component = publish_component(
        state,
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        partition_rows=effective_slots,
        version_id="preflight-v1",
        component_prefix="preflight-base",
    )
    plan = output_plan_for((component,))
    analysis = analyze_output_plan(plan)
    reconstructed = _evaluate_layout(component, query)
    direct = _direct_spmv(state, query, rows)
    high_ci_observed = any(
        high_col in chunk.column_indices for chunk in component.chunks
    )
    checks = {
        "two horizontal Output Shares": len(plan.shares) == 2,
        "disjoint horizontal reconstruction": (
            analysis.reconstruction_mode == "concatenate"
            and analysis.masked_result_ciphertexts == 0
        ),
        "global ColumnIndex 520": high_ci_observed,
        "global gather differs from modulo alias": (
            query[high_col] == 1 and query[alias_col] == 0
        ),
        "layout evaluation equals direct SpMV": reconstructed == direct,
        "high-row result": reconstructed[high_row] == 1,
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise Day1PreflightError("Day 1 preflight failed: " + ", ".join(failures))

    return PreflightReport(
        status="pass",
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        output_shares=len(plan.shares),
        observed_global_column_index=high_col,
        modulo_alias_column_index=alias_col,
        global_gather_value=query[high_col],
        modulo_alias_value=query[alias_col],
        reconstructed_matches_direct=True,
        reconstructed_high_row_value=reconstructed[high_row],
    )
