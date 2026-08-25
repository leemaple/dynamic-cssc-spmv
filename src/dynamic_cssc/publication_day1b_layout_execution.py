"""Streaming-only typed query layouts for the Day 1B execution adapter.

The weighted accounting replay emits at most one value for each query-bearing
Publication Window.  A value carries the exact compiler output that produced
the compact accounting preimage, but grants no runtime, dispatch, formal, or
publication authority.  Callers must consume it synchronously; this module is
not a retained bundle registry.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from dynamic_cssc.query_compiler import CompiledQuery
from dynamic_cssc.simulator import F1MRouteAccounting, QueryPlanAccounting
from dynamic_cssc.strong_execution import StrongExecutionBundle

_PHASES = ("warmup", "tuning-prefix", "held-out")


class Day1BLayoutExecutionError(ValueError):
    """One streamed layout no longer matches its compact accounting plan."""


def _strong_f1m_routes(bundle: StrongExecutionBundle) -> tuple[F1MRouteAccounting, ...]:
    multiplicity: Counter[int] = Counter(
        logical
        for share in bundle.output_plan.shares
        for _lane, logical in share.slot_to_logical
    )
    masked_share_ids = frozenset(
        (share.component_id, share.output_block_id)
        for share in bundle.output_plan.shares
        if any(
            multiplicity[logical] > 1
            for _lane, logical in share.slot_to_logical
        )
    )
    return tuple(
        F1MRouteAccounting(
            result_id=route.result_id,
            result_ordinal=result_ordinal,
            f1m_route_ordinal=result_ordinal,
            component_id=route.component_id,
            output_block_id=route.output_block_id,
            kind=(
                "random-zero-sum"
                if route.output_share_id in masked_share_ids
                else "encrypted-zero-dummy"
            ),
        )
        for result_ordinal, route in enumerate(bundle.result_routes)
    )


def _ordinary_f1m_routes(compiled: CompiledQuery) -> tuple[F1MRouteAccounting, ...]:
    routed = tuple(
        (result_ordinal, route)
        for result_ordinal, route in enumerate(compiled.result_routes)
        if route.f1m_ciphertext_id is not None
    )
    return tuple(
        F1MRouteAccounting(
            result_id=route.result_id,
            result_ordinal=result_ordinal,
            f1m_route_ordinal=f1m_route_ordinal,
            component_id=route.component_id,
            output_block_id=route.output_block_id,
            kind="random-zero-sum",
        )
        for f1m_route_ordinal, (result_ordinal, route) in enumerate(routed)
    )


@dataclass(frozen=True, slots=True)
class Day1BQueryLayoutExecution:
    """One query-bearing window and the exact typed layout compiled for it."""

    phase: str
    window_index: int
    accepted_group_start: int
    accepted_group_end: int
    first_global_query_ordinal: int
    query_count: int
    query_plan: QueryPlanAccounting
    ordinary_compilation: CompiledQuery | None = None
    strong_bundle: StrongExecutionBundle | None = None

    def __post_init__(self) -> None:
        if self.phase not in _PHASES:
            raise Day1BLayoutExecutionError("layout execution phase is not frozen")
        for field in (
            "window_index",
            "accepted_group_start",
            "first_global_query_ordinal",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise Day1BLayoutExecutionError(
                    f"layout execution {field} must be a nonnegative strict integer"
                )
        if (
            type(self.accepted_group_end) is not int
            or self.accepted_group_end <= self.accepted_group_start
        ):
            raise Day1BLayoutExecutionError(
                "layout execution accepted-group range is empty"
            )
        if type(self.query_count) is not int or self.query_count <= 0:
            raise Day1BLayoutExecutionError(
                "layout execution query_count must be a positive strict integer"
            )
        if type(self.query_plan) is not QueryPlanAccounting:
            raise Day1BLayoutExecutionError(
                "layout execution requires exact typed query accounting"
            )

        ordinary_present = self.ordinary_compilation is not None
        strong_present = self.strong_bundle is not None
        if ordinary_present == strong_present:
            raise Day1BLayoutExecutionError(
                "layout execution requires exactly one ordinary or strong bundle"
            )
        if ordinary_present:
            if type(self.ordinary_compilation) is not CompiledQuery:
                raise TypeError("ordinary layout execution must carry one exact compilation")
            compiled = self.ordinary_compilation
            assert compiled is not None
            if compiled.f1m_policy != "overlap-only":
                raise Day1BLayoutExecutionError(
                    "ordinary layout execution changed its F1-M policy"
                )
            version_id = compiled.cloud_plan.binding.version_id
            cloud_program_digest = compiled.cloud_program_digest
            output_plan_digest = compiled.output_plan_digest
            execution_binding_digest = compiled.execution_binding_digest
            private_plan_digest = compiled.private_plan_digest
            returned_share_count = len(compiled.result_routes)
            routes = _ordinary_f1m_routes(compiled)
        else:
            if type(self.strong_bundle) is not StrongExecutionBundle:
                raise TypeError("strong layout execution must carry one exact bundle")
            bundle = self.strong_bundle
            assert bundle is not None
            version_id = bundle.cloud_plan.binding.version_id
            cloud_program_digest = bundle.cloud_program_digest
            output_plan_digest = bundle.output_plan_digest
            execution_binding_digest = bundle.execution_binding_digest
            private_plan_digest = bundle.private_plan_digest
            returned_share_count = len(bundle.result_routes)
            routes = _strong_f1m_routes(bundle)

        plan = self.query_plan
        if (
            plan.version_id != version_id
            or plan.cloud_program_digest != cloud_program_digest
            or plan.output_plan_digest != output_plan_digest
            or plan.execution_binding_digest != execution_binding_digest
            or plan.private_plan_digest != private_plan_digest
            or plan.returned_share_count != returned_share_count
            or plan.f1m_routes != routes
        ):
            raise Day1BLayoutExecutionError(
                "layout execution bundle differs from its compact query plan"
            )

    @property
    def execution_kind(self) -> str:
        return "ordinary" if self.ordinary_compilation is not None else "strong"


__all__ = (
    "Day1BLayoutExecutionError",
    "Day1BQueryLayoutExecution",
)
