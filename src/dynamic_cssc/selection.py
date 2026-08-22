from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from math import isfinite
from typing import Literal, TypeAlias

from .metrics import StrategyMetrics, UnitCosts

ExperimentSplit: TypeAlias = tuple[Fraction, Fraction, Fraction]
CandidateStrategy: TypeAlias = Literal[
    "PaddingReuse-CSSC",
    "ReservedSlack-CSSC",
    "Mini-CSSC-Delta",
    "Packed-COO-Client-Lane-Delta",
    "Strict-LocalRepack",
    "PeriodicRepack",
]
FROZEN_RESERVED_SLACK_BETAS = (
    Decimal("0"),
    Decimal("0.05"),
    Decimal("0.10"),
    Decimal("0.20"),
    Decimal("0.40"),
)
FROZEN_PERIODIC_REPACK_WINDOWS = (1, 4, 16, 64)


@dataclass(frozen=True, slots=True)
class FixedCandidate:
    candidate_id: str
    strategy: CandidateStrategy
    reserved_slack_beta: Decimal | None = None
    periodic_repack_windows: int | None = None
    packed_coo_segment_capacity: int | None = None


def parse_experiment_split(values: Mapping[str, object]) -> ExperimentSplit:
    """Parse warmup/tuning/held-out shares without binary floating-point drift."""

    parsed: list[Fraction] = []
    for name in ("warmup", "tuning", "held_out"):
        try:
            value = values[name]
        except KeyError as error:
            raise ValueError(f"experiment split is missing {name}") from error
        if isinstance(value, bool):
            raise ValueError(f"split.{name} must be a decimal fraction")
        try:
            parsed.append(Fraction(str(value)))
        except (ValueError, ZeroDivisionError) as error:
            raise ValueError(f"split.{name} must be a decimal fraction") from error

    warmup, tuning, held_out = parsed
    split = (warmup, tuning, held_out)
    if any(value < 0 for value in split):
        raise ValueError("experiment split fractions must be nonnegative")
    if sum(split) != 1:
        raise ValueError("experiment split fractions must sum to one")
    return split


def split_boundaries(window_count: int, split: ExperimentSplit) -> tuple[int, int]:
    warmup, tuning, _held_out = split
    warmup_end = int(window_count * warmup)
    tuning_end = int(window_count * (warmup + tuning))
    if tuning_end <= warmup_end:
        raise ValueError("the tuning split must contain at least one publication window")
    if tuning_end >= window_count:
        raise ValueError("the held-out split must contain at least one publication window")
    return warmup_end, tuning_end


def _canonical_nonnegative_decimal(value: object, field: str) -> tuple[str, Decimal]:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite nonnegative decimal")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{field} must be a finite nonnegative decimal") from error
    if not decimal_value.is_finite() or decimal_value < 0:
        raise ValueError(f"{field} must be a finite nonnegative decimal")
    label = format(decimal_value.normalize(), "f")
    if "." in label:
        label = label.rstrip("0").rstrip(".")
    if label == "-0":
        label = "0"
    return label, decimal_value


def build_fixed_candidates(
    *,
    reserved_slack_betas: Iterable[object],
    periodic_repack_windows: Iterable[object],
) -> tuple[FixedCandidate, ...]:
    """Build only the frozen singleton and one-parameter Day-1 candidate families."""

    try:
        beta_values = tuple(reserved_slack_betas)
        period_values = tuple(periodic_repack_windows)
    except TypeError as error:
        raise ValueError("candidate parameter grids must be iterable") from error
    if len(beta_values) != 5:
        raise ValueError("reserved_slack_betas must contain exactly five values")
    if len(period_values) != 4:
        raise ValueError("periodic_repack_windows must contain exactly four values")

    parsed_betas = tuple(
        _canonical_nonnegative_decimal(value, "reserved_slack_beta") for value in beta_values
    )
    if tuple(value for _label, value in parsed_betas) != FROZEN_RESERVED_SLACK_BETAS:
        raise ValueError(
            "reserved_slack_betas must equal the frozen canonical grid [0, 0.05, 0.10, 0.20, 0.40]"
        )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in period_values
    ):
        raise ValueError("periodic_repack_windows must contain positive integers")
    if period_values != FROZEN_PERIODIC_REPACK_WINDOWS:
        raise ValueError(
            "periodic_repack_windows must equal the frozen canonical grid [1, 4, 16, 64]"
        )

    candidates = [
        FixedCandidate("padding-reuse", "PaddingReuse-CSSC"),
        FixedCandidate("mini-cssc-delta", "Mini-CSSC-Delta"),
        FixedCandidate(
            "packed-coo-client-lane-delta/capacity=128",
            "Packed-COO-Client-Lane-Delta",
            packed_coo_segment_capacity=128,
        ),
        FixedCandidate("strict-local-repack", "Strict-LocalRepack"),
    ]
    for label, decimal_value in parsed_betas:
        candidates.append(
            FixedCandidate(
                f"reserved-slack/beta={label}",
                "ReservedSlack-CSSC",
                reserved_slack_beta=decimal_value,
            )
        )
    for value in period_values:
        candidates.append(
            FixedCandidate(
                f"periodic-repack/windows={value}",
                "PeriodicRepack",
                periodic_repack_windows=value,
            )
        )

    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("canonical candidate_id values must be globally unique")
    return tuple(candidates)


def select_tuned_fixed_candidate(
    candidates: Iterable[FixedCandidate],
    tuning_metrics: Mapping[str, StrategyMetrics],
    costs: UnitCosts,
) -> FixedCandidate:
    """Freeze the lowest finite tuning-prefix cost with a stable ID tie-break."""

    candidate_list = tuple(candidates)
    candidate_ids = [candidate.candidate_id for candidate in candidate_list]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("selector candidates must have unique candidate_id values")
    missing = sorted(set(candidate_ids) - tuning_metrics.keys())
    if missing:
        raise ValueError(f"tuning metrics are missing candidates: {missing}")

    ranked = []
    for candidate in candidate_list:
        predicted_time = tuning_metrics[candidate.candidate_id].predicted_time(costs)
        if isfinite(predicted_time):
            ranked.append((predicted_time, candidate.candidate_id, candidate))
    if not ranked:
        raise ValueError("no candidate has a finite tuning predicted_time")
    return min(ranked, key=lambda item: (item[0], item[1]))[2]
