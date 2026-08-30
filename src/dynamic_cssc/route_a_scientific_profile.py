"""Closed scientific-value adapter for Route A-compatible executions.

The profile is deliberately not an authority object.  It centralizes the only
values that vary between the permanently closed predecessor, sentinel-only
Stage-2 tests, and a later capability-bound follow-up execution: workload
seeds, the query-vector seed, and the materialized machine-plan digest.
Strategy semantics, schemas, scheduling, accounting, and evidence validation
do not vary at this seam.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final, Literal

__all__ = (
    "PREDECESSOR_ROUTE_A_PROFILE",
    "RouteAScientificProfile",
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCALES = frozenset({"S", "M"})


@dataclass(frozen=True, slots=True)
class RouteAScientificProfile:
    """One closed set of scientific scalar values behind a small interface."""

    profile_id: str
    qualification_seed: int
    formal_seeds: tuple[int, int, int]
    query_vector_seed: int
    machine_plan_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.profile_id) is not str
            or not self.profile_id
            or not self.profile_id.isascii()
            or type(self.qualification_seed) is not int
            or self.qualification_seed < 0
            or type(self.formal_seeds) is not tuple
            or len(self.formal_seeds) != 3
            or any(type(seed) is not int or seed < 0 for seed in self.formal_seeds)
            or len(set(self.formal_seeds)) != 3
            or self.qualification_seed in self.formal_seeds
            or type(self.query_vector_seed) is not int
            or self.query_vector_seed < 0
            or type(self.machine_plan_sha256) is not str
            or _LOWER_SHA256.fullmatch(self.machine_plan_sha256) is None
        ):
            raise ValueError("Route A scientific profile is not one closed scalar domain")

    def require_trace_scope(
        self,
        *,
        suite_role: Literal["qualification", "formal"],
        scale: str,
        seed: int,
    ) -> None:
        """Reject a workload or query-vector domain outside this exact profile."""

        qualification = (
            suite_role == "qualification"
            and scale == "M"
            and type(seed) is int
            and seed == self.qualification_seed
        )
        formal = (
            suite_role == "formal"
            and scale in _SCALES
            and type(seed) is int
            and seed in self.formal_seeds
        )
        if not (qualification or formal):
            raise ValueError("trace scope is outside the selected Route A scientific profile")

    def require_machine_plan_bytes(self, machine_plan_bytes: bytes) -> None:
        """Bind exact retained plan bytes without exposing a skip-validation flag."""

        if (
            type(machine_plan_bytes) is not bytes
            or hashlib.sha256(machine_plan_bytes).hexdigest() != self.machine_plan_sha256
        ):
            raise ValueError("machine plan bytes differ from the scientific profile")


PREDECESSOR_ROUTE_A_PROFILE: Final = RouteAScientificProfile(
    profile_id="route-a-predecessor-2026-08",
    qualification_seed=20_260_821,
    formal_seeds=(20_260_822, 20_260_823, 20_260_824),
    query_vector_seed=2_026_082_302,
    machine_plan_sha256="ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c",
)
