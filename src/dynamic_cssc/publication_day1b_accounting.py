"""Streaming, window-weighted accounting for one Day 1B candidate cell.

The exact accepted-event schedule may assign millions of query arrivals to a
cell.  This module advances candidate state once per Publication Window,
compiles at most one typed query plan for a query-bearing window, and applies
the schedule's exact integer query multiplicity to operation counts.  It never
claims to materialize per-query masks, ledger transitions, or ciphertexts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Literal, cast

from dynamic_cssc.day1_registry import RegisteredCandidate
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.metrics import StrategyMetrics
from dynamic_cssc.publication_primitive_accounting import (
    PublicationPrimitiveAccounting,
    publication_primitive_accounting,
)
from dynamic_cssc.publication_schedule import ExactPublicationWindow, ScheduledNetUpdate
from dynamic_cssc.selection import (
    FROZEN_PERIODIC_REPACK_WINDOWS,
    FROZEN_RESERVED_SLACK_BETAS,
    build_fixed_candidates,
)
from dynamic_cssc.simulator import (
    QueryPlanAccounting,
    WindowAccounting,
    account_strong_transition,
    account_transition,
)
from dynamic_cssc.strategy_state import (
    StrategyKind,
    StrategyState,
    StrongStrategyState,
    advance_publication,
    advance_strong_publication,
    initialize_strategy,
    initialize_strong_strategy,
)

DAY1B_ACCOUNTING_SCHEMA = "dynamic-cssc-publication-day1b-accounting-v1"
DAY1B_QUERY_WINDOW_SCHEMA = "dynamic-cssc-publication-day1b-query-window-accounting-v2"
DAY1B_PHASE_ACCOUNTING_SCHEMA = "dynamic-cssc-publication-day1b-phase-accounting-v1"
DAY1B_ACCOUNTING_EXECUTION_BASIS = "window-weighted-equivalence-v1"

SourcePhase = Literal["warmup", "tuning", "heldout"]
WorkerPhase = Literal["warmup", "tuning-prefix", "held-out"]
_SOURCE_PHASES: tuple[SourcePhase, ...] = ("warmup", "tuning", "heldout")
_WORKER_PHASES: tuple[WorkerPhase, ...] = ("warmup", "tuning-prefix", "held-out")
_WORKER_PHASE_BY_SOURCE: dict[SourcePhase, WorkerPhase] = dict(
    zip(_SOURCE_PHASES, _WORKER_PHASES, strict=True)
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_ID = re.compile(r"v[0-9]{8}\Z")


class PublicationDay1BAccountingError(ValueError):
    """Raised when a candidate or exact window stream leaves the frozen domain."""


def _canonical_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise PublicationDay1BAccountingError(
            "Day 1B accounting value is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _strict_positive(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise PublicationDay1BAccountingError(f"{field} must be a positive strict integer")
    return value


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise PublicationDay1BAccountingError(f"{field} must be exact lowercase sha256")
    return value


@dataclass(frozen=True, slots=True)
class Day1BAccountingDomain:
    rows: int
    cols: int
    effective_slots: int
    partition_rows: int
    matrix_value_bound: int
    max_row_nnz: int
    strong_segment_width: int = 128

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            _strict_positive(getattr(self, field), f"domain.{field}")
        if self.partition_rows > self.effective_slots:
            raise PublicationDay1BAccountingError(
                "domain.partition_rows must not exceed effective_slots"
            )
        if self.max_row_nnz > self.cols:
            raise PublicationDay1BAccountingError(
                "domain.max_row_nnz must not exceed the fixed column count"
            )
        if (
            self.strong_segment_width < 2
            or self.strong_segment_width > self.effective_slots
            or self.strong_segment_width & (self.strong_segment_width - 1)
        ):
            raise PublicationDay1BAccountingError(
                "domain.strong_segment_width must be an admitted power of two"
            )

    def to_document(self) -> dict[str, int]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


PUBLICATION_DAY1B_ACCOUNTING_DOMAIN = Day1BAccountingDomain(
    rows=4096,
    cols=8193,
    effective_slots=4096,
    partition_rows=4096,
    matrix_value_bound=7,
    max_row_nnz=4096,
    strong_segment_width=128,
)


def _canonical_candidate_policies() -> dict[str, tuple[object, ...]]:
    fixed = build_fixed_candidates(
        reserved_slack_betas=FROZEN_RESERVED_SLACK_BETAS,
        periodic_repack_windows=FROZEN_PERIODIC_REPACK_WINDOWS,
    )
    policies = {
        candidate.candidate_id: (
            candidate.strategy,
            (
                "ablation"
                if candidate.candidate_id == "packed-coo-client-lane-delta/capacity=128"
                else "reference"
            ),
            candidate.reserved_slack_beta,
            candidate.periodic_repack_windows,
            candidate.packed_coo_segment_capacity,
        )
        for candidate in fixed
    }
    policies["packed-coo-cloud-segmented-delta/segment-width=128"] = (
        "Packed-COO-Cloud-Segmented-Delta",
        "reference",
        Decimal("0"),
        None,
        None,
    )
    return policies


_CANONICAL_CANDIDATE_POLICIES = _canonical_candidate_policies()


def _candidate_document(candidate: RegisteredCandidate) -> dict[str, object]:
    if type(candidate) is not RegisteredCandidate:
        raise TypeError("candidate must be an exact RegisteredCandidate")
    observed = (
        candidate.strategy,
        candidate.role,
        candidate.reserved_slack_beta,
        candidate.periodic_repack_windows,
        candidate.packed_coo_segment_capacity,
    )
    if _CANONICAL_CANDIDATE_POLICIES.get(candidate.candidate_id) != observed:
        raise PublicationDay1BAccountingError(
            "candidate does not equal one exact frozen Day 1 policy"
        )
    return {
        "candidate_id": candidate.candidate_id,
        "candidate_role": candidate.role,
        "packed_coo_segment_capacity": candidate.packed_coo_segment_capacity,
        "periodic_repack_windows": candidate.periodic_repack_windows,
        "reserved_slack_beta": (
            None
            if candidate.reserved_slack_beta is None
            else format(candidate.reserved_slack_beta, "f")
        ),
        "strategy": candidate.strategy,
    }


@dataclass(frozen=True, slots=True)
class Day1BQueryWindowAccounting:
    phase: WorkerPhase
    window_index: int
    accepted_group_start: int
    accepted_group_end: int
    start_time: Fraction
    end_time: Fraction
    set_count: int
    net_update_count: int
    first_global_query_ordinal: int
    query_count: int
    rotations_per_query: tuple[tuple[int, int], ...]
    query_plan: QueryPlanAccounting

    def __post_init__(self) -> None:
        if self.phase not in _WORKER_PHASES:
            raise PublicationDay1BAccountingError("query-window phase is not frozen")
        for field in (
            "window_index",
            "accepted_group_start",
            "set_count",
            "net_update_count",
            "first_global_query_ordinal",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise PublicationDay1BAccountingError(
                    f"query-window {field} must be a nonnegative strict integer"
                )
        if (
            type(self.accepted_group_end) is not int
            or self.accepted_group_end <= self.accepted_group_start
        ):
            raise PublicationDay1BAccountingError("query-window accepted range is empty")
        _strict_positive(self.query_count, "query-window query_count")
        if (
            type(self.start_time) is not Fraction
            or type(self.end_time) is not Fraction
            or self.end_time < self.start_time
        ):
            raise PublicationDay1BAccountingError("query-window time range is not exact")
        if type(self.rotations_per_query) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not int
            or item[0] == 0
            or type(item[1]) is not int
            or item[1] <= 0
            for item in self.rotations_per_query
        ):
            raise PublicationDay1BAccountingError(
                "query-window rotation inventory is malformed"
            )
        if tuple(sorted(self.rotations_per_query)) != self.rotations_per_query:
            raise PublicationDay1BAccountingError(
                "query-window rotation inventory is not canonical"
            )
        if len({index for index, _count in self.rotations_per_query}) != len(
            self.rotations_per_query
        ):
            raise PublicationDay1BAccountingError(
                "query-window rotation indices are not unique"
            )
        if type(self.query_plan) is not QueryPlanAccounting:
            raise PublicationDay1BAccountingError(
                "query-window plan must be exact typed accounting"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "end_time": {
                "denominator": self.end_time.denominator,
                "numerator": self.end_time.numerator,
            },
            "first_global_query_ordinal": self.first_global_query_ordinal,
            "net_update_count": self.net_update_count,
            "phase": self.phase,
            "query_count": self.query_count,
            "query_plan": self.query_plan.to_document(),
            "rotations_per_query": [list(item) for item in self.rotations_per_query],
            "schema_version": DAY1B_QUERY_WINDOW_SCHEMA,
            "set_count": self.set_count,
            "start_time": {
                "denominator": self.start_time.denominator,
                "numerator": self.start_time.numerator,
            },
            "window_index": self.window_index,
        }


@dataclass(frozen=True, slots=True)
class Day1BPhaseAccounting:
    phase: WorkerPhase
    accepted_group_start: int
    accepted_group_end: int
    realized_window_count: int
    realized_set_count: int
    realized_net_update_count: int
    realized_query_count: int
    query_window_count: int
    query_window_stream_sha256: str
    strategy_metrics_sha256: str
    update_primitive_counts: tuple[int, ...]
    query_primitive_counts: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.phase not in _WORKER_PHASES:
            raise PublicationDay1BAccountingError("phase accounting name is not frozen")
        if (
            type(self.accepted_group_start) is not int
            or type(self.accepted_group_end) is not int
            or self.accepted_group_end <= self.accepted_group_start
        ):
            raise PublicationDay1BAccountingError("phase accepted range is empty")
        for field in (
            "realized_window_count",
            "realized_set_count",
            "realized_net_update_count",
            "realized_query_count",
            "query_window_count",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise PublicationDay1BAccountingError(
                    f"phase {field} must be a nonnegative strict integer"
                )
        for field in ("query_window_stream_sha256", "strategy_metrics_sha256"):
            _require_sha256(getattr(self, field), f"phase {field}")
        PublicationPrimitiveAccounting(
            update_counts=self.update_primitive_counts,
            query_counts=self.query_primitive_counts,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "phase": self.phase,
            "query_primitive_counts": list(self.query_primitive_counts),
            "query_window_count": self.query_window_count,
            "query_window_stream_sha256": self.query_window_stream_sha256,
            "realized_net_update_count": self.realized_net_update_count,
            "realized_query_count": self.realized_query_count,
            "realized_set_count": self.realized_set_count,
            "realized_window_count": self.realized_window_count,
            "schema_version": DAY1B_PHASE_ACCOUNTING_SCHEMA,
            "strategy_metrics_sha256": self.strategy_metrics_sha256,
            "update_primitive_counts": list(self.update_primitive_counts),
        }


@dataclass(frozen=True, slots=True)
class PublicationDay1BAccounting:
    candidate_id: str
    candidate_policy_sha256: str
    domain: Day1BAccountingDomain
    phases: tuple[Day1BPhaseAccounting, ...]
    window_stream_sha256: str
    query_window_stream_sha256: str
    realized_window_count: int
    realized_query_window_count: int
    realized_query_count: int
    terminal_version_id: str
    terminal_logical_state_sha256: str
    state_reset_count: int = 0

    def __post_init__(self) -> None:
        if type(self.candidate_id) is not str or not self.candidate_id:
            raise PublicationDay1BAccountingError("accounting candidate_id is empty")
        if type(self.domain) is not Day1BAccountingDomain:
            raise PublicationDay1BAccountingError("accounting domain type is not exact")
        if tuple(phase.phase for phase in self.phases) != _WORKER_PHASES:
            raise PublicationDay1BAccountingError("accounting phase order is not exact")
        for field in (
            "candidate_policy_sha256",
            "window_stream_sha256",
            "query_window_stream_sha256",
            "terminal_logical_state_sha256",
        ):
            _require_sha256(getattr(self, field), f"accounting {field}")
        for field in (
            "realized_window_count",
            "realized_query_window_count",
            "realized_query_count",
            "state_reset_count",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise PublicationDay1BAccountingError(
                    f"accounting {field} must be a nonnegative strict integer"
                )
        if self.state_reset_count != 0:
            raise PublicationDay1BAccountingError("Day 1B state resets are forbidden")
        if (
            type(self.terminal_version_id) is not str
            or _VERSION_ID.fullmatch(self.terminal_version_id) is None
        ):
            raise PublicationDay1BAccountingError("terminal version identity is empty")

    def _body_document(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "domain": self.domain.to_document(),
            "execution_basis": DAY1B_ACCOUNTING_EXECUTION_BASIS,
            "phases": [phase.to_document() for phase in self.phases],
            "query_window_stream_sha256": self.query_window_stream_sha256,
            "realized_query_count": self.realized_query_count,
            "realized_query_window_count": self.realized_query_window_count,
            "realized_window_count": self.realized_window_count,
            "schema_version": DAY1B_ACCOUNTING_SCHEMA,
            "state_reset_count": self.state_reset_count,
            "terminal_logical_state_sha256": self.terminal_logical_state_sha256,
            "terminal_version_id": self.terminal_version_id,
            "window_stream_sha256": self.window_stream_sha256,
        }

    @property
    def accounting_sha256(self) -> str:
        return _sha256(self._body_document())

    def to_document(self) -> dict[str, object]:
        body = self._body_document()
        return {**body, "accounting_sha256": _sha256(body)}


class _SequenceHasher:
    __slots__ = ("_count", "_hasher", "_schema")

    def __init__(self, schema: str) -> None:
        self._schema = schema
        self._hasher = hashlib.sha256()
        self._count = 0

    def add(self, value: object) -> None:
        self._hasher.update(_canonical_bytes(value))
        self._count += 1

    @property
    def count(self) -> int:
        return self._count

    def root_sha256(self) -> str:
        return _sha256(
            {
                "element_count": self._count,
                "element_stream_sha256": self._hasher.hexdigest(),
                "schema_version": self._schema,
            }
        )


class _PhaseAccumulator:
    __slots__ = (
        "accepted_group_end",
        "accepted_group_start",
        "metrics",
        "phase",
        "query_hasher",
        "query_window_count",
        "set_count",
        "window_count",
    )

    def __init__(self, phase: WorkerPhase, strategy: str, role: str) -> None:
        self.phase = phase
        self.metrics = StrategyMetrics(
            strategy=strategy,
            category=role,
            source="persistent-state-predicted",
        )
        self.window_count = 0
        self.set_count = 0
        self.query_window_count = 0
        self.accepted_group_start: int | None = None
        self.accepted_group_end: int | None = None
        self.query_hasher = _SequenceHasher(
            "dynamic-cssc-publication-day1b-phase-query-window-stream-v1"
        )

    def add_window(self, window: ExactPublicationWindow, accounting: WindowAccounting) -> None:
        if self.accepted_group_start is None:
            self.accepted_group_start = window.accepted_group_start
        elif window.accepted_group_start != self.accepted_group_end:
            raise PublicationDay1BAccountingError(
                "publication windows must cover a contiguous accepted-group phase"
            )
        self.accepted_group_end = window.accepted_group_end
        self.window_count += 1
        self.set_count += window.set_count
        self.metrics.merge(accounting.metrics)

    def finish(self, effective_slots: int) -> Day1BPhaseAccounting:
        if self.accepted_group_start is None or self.accepted_group_end is None:
            raise PublicationDay1BAccountingError("every Day 1B phase must contain a window")
        if self.metrics.windows != self.window_count:
            raise AssertionError("phase metric window count does not reconcile")
        primitive = publication_primitive_accounting(
            self.metrics,
            effective_slots=effective_slots,
        )
        return Day1BPhaseAccounting(
            phase=self.phase,
            accepted_group_start=self.accepted_group_start,
            accepted_group_end=self.accepted_group_end,
            realized_window_count=self.window_count,
            realized_set_count=self.set_count,
            realized_net_update_count=self.metrics.updates,
            realized_query_count=self.metrics.queries,
            query_window_count=self.query_window_count,
            query_window_stream_sha256=self.query_hasher.root_sha256(),
            strategy_metrics_sha256=_sha256(asdict(self.metrics)),
            update_primitive_counts=primitive.update_counts,
            query_primitive_counts=primitive.query_counts,
        )


def _exact_window_document(window: ExactPublicationWindow) -> dict[str, object]:
    return {
        "accepted_group_end": window.accepted_group_end,
        "accepted_group_start": window.accepted_group_start,
        "end_time": [window.end_time.numerator, window.end_time.denominator],
        "index": window.index,
        "phase": window.phase,
        "query_count": window.query_count,
        "reason": window.reason,
        "set_count": window.set_count,
        "start_time": [window.start_time.numerator, window.start_time.denominator],
        "updates": [
            [update.row, update.col, update.before, update.after] for update in window.updates
        ],
    }


def _adapt_window(window: ExactPublicationWindow) -> PublicationWindow:
    return PublicationWindow(
        index=window.index,
        start_time=float(window.start_time),
        end_time=float(window.end_time),
        updates=tuple(
            NetUpdate(update.row, update.col, update.before, update.after)
            for update in window.updates
        ),
        query_count=window.query_count,
        reason=window.reason,
    )


def _initialize_candidate_state(
    candidate: RegisteredCandidate,
    domain: Day1BAccountingDomain,
) -> StrategyState | StrongStrategyState:
    if candidate.strategy == "Packed-COO-Cloud-Segmented-Delta":
        if domain.strong_segment_width != 128:
            raise PublicationDay1BAccountingError(
                "the strong candidate identity requires exact segment width 128"
            )
        return initialize_strong_strategy(
            {},
            rows=domain.rows,
            cols=domain.cols,
            effective_slots=domain.effective_slots,
            partition_rows=domain.partition_rows,
            matrix_value_bound=domain.matrix_value_bound,
            max_row_nnz=domain.max_row_nnz,
            reserved_slack_beta=0.0,
            segment_width=domain.strong_segment_width,
        )
    return initialize_strategy(
        cast(StrategyKind, candidate.strategy),
        {},
        rows=domain.rows,
        cols=domain.cols,
        effective_slots=domain.effective_slots,
        partition_rows=domain.partition_rows,
        matrix_value_bound=domain.matrix_value_bound,
        max_row_nnz=domain.max_row_nnz,
        reserved_slack_beta=float(candidate.reserved_slack_beta or Decimal("0")),
        periodic_repack_windows=candidate.periodic_repack_windows or 4,
        packed_coo_segment_capacity=candidate.packed_coo_segment_capacity or 128,
    )


def replay_publication_day1b_candidate_cell(
    *,
    candidate: RegisteredCandidate,
    windows: Iterable[ExactPublicationWindow],
    domain: Day1BAccountingDomain = PUBLICATION_DAY1B_ACCOUNTING_DOMAIN,
    query_window_sink: Callable[[Day1BQueryWindowAccounting], None] | None = None,
) -> PublicationDay1BAccounting:
    """Replay one candidate continuously and stream one descriptor per query window."""

    candidate_document = _candidate_document(candidate)
    if type(domain) is not Day1BAccountingDomain:
        raise TypeError("domain must be an exact Day1BAccountingDomain")
    if query_window_sink is not None and not callable(query_window_sink):
        raise TypeError("query_window_sink must be callable or None")
    try:
        iterator = iter(windows)
    except TypeError as error:
        raise TypeError("windows must be an iterable of exact publication windows") from error

    state = _initialize_candidate_state(candidate, domain)
    phase_accumulators = {
        phase: _PhaseAccumulator(worker, candidate.strategy, candidate.role)
        for phase, worker in zip(_SOURCE_PHASES, _WORKER_PHASES, strict=True)
    }
    window_hasher = _SequenceHasher("dynamic-cssc-publication-day1b-window-stream-v1")
    query_hasher = _SequenceHasher(
        "dynamic-cssc-publication-day1b-query-window-stream-v1"
    )
    previous_window_index = -1
    previous_phase_index = 0
    previous_accepted_group_end = 0
    global_query_ordinal = 0

    for window in iterator:
        if type(window) is not ExactPublicationWindow:
            raise PublicationDay1BAccountingError(
                "window stream must contain exact ExactPublicationWindow values"
            )
        if window.phase not in _SOURCE_PHASES:
            raise PublicationDay1BAccountingError("window phase is not frozen")
        phase = cast(SourcePhase, window.phase)
        phase_index = _SOURCE_PHASES.index(phase)
        if type(window.index) is not int or window.index != previous_window_index + 1:
            raise PublicationDay1BAccountingError("window indices must be contiguous from zero")
        if phase_index < previous_phase_index:
            raise PublicationDay1BAccountingError("window phases cannot regress")
        if window.accepted_group_start != previous_accepted_group_end:
            raise PublicationDay1BAccountingError(
                "window stream must cover contiguous accepted-group ranges"
            )
        if (
            type(window.start_time) is not Fraction
            or type(window.end_time) is not Fraction
            or window.end_time < window.start_time
            or type(window.accepted_group_start) is not int
            or type(window.accepted_group_end) is not int
            or window.accepted_group_end <= window.accepted_group_start
            or type(window.set_count) is not int
            or window.set_count < 0
            or type(window.query_count) is not int
            or window.query_count < 0
            or type(window.updates) is not tuple
            or window.set_count < len(window.updates)
            or any(type(update) is not ScheduledNetUpdate for update in window.updates)
            or type(window.reason) is not str
            or not window.reason
        ):
            raise PublicationDay1BAccountingError("window exact fields are malformed")

        adapted = _adapt_window(window)
        if candidate.strategy == "Packed-COO-Cloud-Segmented-Delta":
            if type(state) is not StrongStrategyState:
                raise AssertionError("strong candidate state type changed")
            transition = advance_strong_publication(state, adapted)
            accounting = account_strong_transition(transition)
            state = transition.state
        else:
            if type(state) is not StrategyState:
                raise AssertionError("ordinary candidate state type changed")
            transition = advance_publication(state, adapted)
            accounting = account_transition(transition)
            state = transition.state

        accumulator = phase_accumulators[phase]
        accumulator.add_window(window, accounting)
        window_hasher.add(_exact_window_document(window))
        if window.query_count:
            if accounting.query_plan is None:
                raise AssertionError("query-bearing window lost its typed query plan")
            descriptor = Day1BQueryWindowAccounting(
                phase=_WORKER_PHASE_BY_SOURCE[phase],
                window_index=window.index,
                accepted_group_start=window.accepted_group_start,
                accepted_group_end=window.accepted_group_end,
                start_time=window.start_time,
                end_time=window.end_time,
                set_count=window.set_count,
                net_update_count=len(window.updates),
                first_global_query_ordinal=global_query_ordinal,
                query_count=window.query_count,
                rotations_per_query=accounting.rotations_per_query,
                query_plan=accounting.query_plan,
            )
            document = descriptor.to_document()
            accumulator.query_hasher.add(document)
            accumulator.query_window_count += 1
            query_hasher.add(document)
            if query_window_sink is not None:
                query_window_sink(descriptor)
        elif accounting.query_plan is not None or accounting.rotations_per_query:
            raise AssertionError("zero-query window created query accounting")

        global_query_ordinal += window.query_count
        previous_window_index = window.index
        previous_phase_index = phase_index
        previous_accepted_group_end = window.accepted_group_end

    phases = tuple(
        phase_accumulators[phase].finish(domain.effective_slots) for phase in _SOURCE_PHASES
    )
    if any(
        before.accepted_group_end != after.accepted_group_start
        for before, after in zip(phases, phases[1:], strict=False)
    ):
        raise PublicationDay1BAccountingError("phase ranges are not exactly contiguous")
    if sum(phase.realized_query_count for phase in phases) != global_query_ordinal:
        raise AssertionError("phase query totals do not reconcile")
    logical = state.logical
    logical_state_document = [
        [row, col, value] for (row, col), value in sorted(logical.items())
    ]
    result = PublicationDay1BAccounting(
        candidate_id=candidate.candidate_id,
        candidate_policy_sha256=_sha256(candidate_document),
        domain=domain,
        phases=phases,
        window_stream_sha256=window_hasher.root_sha256(),
        query_window_stream_sha256=query_hasher.root_sha256(),
        realized_window_count=window_hasher.count,
        realized_query_window_count=query_hasher.count,
        realized_query_count=global_query_ordinal,
        terminal_version_id=state.version_id,
        terminal_logical_state_sha256=_sha256(
            {
                "entries": logical_state_document,
                "schema_version": "dynamic-cssc-publication-day1b-terminal-logical-state-v1",
            }
        ),
    )
    if result.realized_window_count != sum(phase.realized_window_count for phase in phases):
        raise AssertionError("phase window totals do not reconcile")
    if result.realized_query_window_count != sum(
        phase.query_window_count for phase in phases
    ):
        raise AssertionError("phase query-window totals do not reconcile")
    return result


__all__ = (
    "DAY1B_ACCOUNTING_EXECUTION_BASIS",
    "DAY1B_ACCOUNTING_SCHEMA",
    "DAY1B_PHASE_ACCOUNTING_SCHEMA",
    "DAY1B_QUERY_WINDOW_SCHEMA",
    "Day1BAccountingDomain",
    "Day1BPhaseAccounting",
    "Day1BQueryWindowAccounting",
    "PUBLICATION_DAY1B_ACCOUNTING_DOMAIN",
    "PublicationDay1BAccounting",
    "PublicationDay1BAccountingError",
    "replay_publication_day1b_candidate_cell",
)
