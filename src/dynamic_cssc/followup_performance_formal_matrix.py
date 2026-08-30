"""Single typed enumeration of the frozen seventeen-unit formal campaign."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES

__all__ = (
    "FollowupFormalUnitSpec",
    "followup_formal_unit_specs",
)

FollowupFormalUnitKind = Literal[
    "formal-acquisition",
    "formal-native",
    "formal-synthetic",
    "formal-ordered-event",
]
FollowupFormalSegment = Literal[
    "acquisition-and-ordered",
    "native",
    "synthetic",
]


@dataclass(frozen=True, slots=True)
class FollowupFormalUnitSpec:
    ordinal: int
    unit_kind: FollowupFormalUnitKind
    segment: FollowupFormalSegment
    reservation_minutes: int
    scale: str | None = None
    formal_seed: int | None = None
    formal_seed_ordinal: int | None = None
    strategy_candidate_id: str | None = None
    strategy_ordinal: int | None = None
    partition: int | None = None
    semantics: str | None = None

    @property
    def job_token(self) -> str:
        if self.unit_kind == "formal-acquisition":
            suffix = "acquisition"
        elif self.unit_kind == "formal-native":
            suffix = f"native-strategy-{self.strategy_ordinal}-{self.scale}"
        elif self.unit_kind == "formal-synthetic":
            suffix = f"synthetic-{self.scale}-seed-{self.formal_seed_ordinal}"
        else:
            suffix = f"ordered-partition-{self.partition}-{self.semantics}"
        return f"formal-{self.ordinal:02d}-{suffix}"

    @property
    def producer_job_name(self) -> str:
        return f"{self.job_token}-producer"

    @property
    def guard_job_name(self) -> str:
        return f"{self.job_token}-independent-replay-and-guard"


def followup_formal_unit_specs(
    scientific_profile: RouteAScientificProfile,
) -> tuple[FollowupFormalUnitSpec, ...]:
    """Return acquisition, native, synthetic, then ordered units in exact order."""

    if type(scientific_profile) is not RouteAScientificProfile:
        raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
    specs: list[FollowupFormalUnitSpec] = [
        FollowupFormalUnitSpec(
            ordinal=0,
            unit_kind="formal-acquisition",
            segment="acquisition-and-ordered",
            reservation_minutes=20,
        )
    ]
    native_seed = scientific_profile.formal_seeds[0]
    for strategy_ordinal, strategy in enumerate(ROUTE_A_STRATEGY_CANDIDATES):
        for scale in ("S", "M"):
            specs.append(
                FollowupFormalUnitSpec(
                    ordinal=len(specs),
                    unit_kind="formal-native",
                    segment="native",
                    reservation_minutes=25,
                    scale=scale,
                    formal_seed=native_seed,
                    formal_seed_ordinal=0,
                    strategy_candidate_id=strategy,
                    strategy_ordinal=strategy_ordinal,
                )
            )
    for scale in ("S", "M"):
        for seed_ordinal, formal_seed in enumerate(
            tuple(sorted(scientific_profile.formal_seeds))
        ):
            specs.append(
                FollowupFormalUnitSpec(
                    ordinal=len(specs),
                    unit_kind="formal-synthetic",
                    segment="synthetic",
                    reservation_minutes=50,
                    scale=scale,
                    formal_seed=formal_seed,
                    formal_seed_ordinal=seed_ordinal,
                )
            )
    for partition in (0, 1):
        for semantics in ("T1", "T2"):
            specs.append(
                FollowupFormalUnitSpec(
                    ordinal=len(specs),
                    unit_kind="formal-ordered-event",
                    segment="acquisition-and-ordered",
                    reservation_minutes=40,
                    partition=partition,
                    semantics=semantics,
                )
            )
    if (
        len(specs) != 17
        or tuple(spec.ordinal for spec in specs) != tuple(range(17))
        or sum(spec.reservation_minutes for spec in specs) != 630
    ):
        raise AssertionError("follow-up formal matrix changed")
    return tuple(specs)
