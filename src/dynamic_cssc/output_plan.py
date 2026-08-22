from __future__ import annotations

import hashlib
import json
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.mask_ledger import MaskBinding, MaskBindingLedger

OUTPUT_PLAN_FORMAT = "dynamic-cssc-output-plan-v1"
OUTPUT_PLAN_DIGEST_ALGORITHM = "sha256-canonical-json-v1"


class OutputPlanError(ValueError):
    """Raised when an output plan cannot be reconstructed unambiguously."""


@dataclass(frozen=True, slots=True)
class OutputShare:
    component_id: str
    output_block_id: str
    slot_to_logical: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class OutputPlan:
    logical_output_size: int
    slot_count: int
    shares: tuple[OutputShare, ...]


@dataclass(frozen=True, slots=True)
class OutputPlanAnalysis:
    output_plan_digest: str
    reconstruction_mode: Literal["concatenate", "coordinate-sum"]
    result_ciphertexts: int
    masked_result_ciphertexts: int
    implicit_zero_coordinates: int
    overlap_coordinates: int
    mask_random_elements: int
    mask_mapped_elements: int
    client_reorder_elements: int
    client_modular_additions: int


@dataclass(frozen=True, slots=True)
class PreparedMask:
    query_id: str
    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    values: tuple[int, ...]

    @property
    def binding(self) -> tuple[str, str, str, str, str]:
        return (
            self.query_id,
            self.version_id,
            self.output_plan_digest,
            self.component_id,
            self.output_block_id,
        )


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_positive_int(value: object, field: str) -> int:
    if not _is_strict_int(value) or value <= 0:
        raise OutputPlanError(f"{field} must be a positive integer")
    return value


def _require_id(value: object, field: str) -> str:
    invalid_character = isinstance(value, str) and any(
        not 0x21 <= ord(char) <= 0x7E for char in value
    )
    if not isinstance(value, str) or not value or invalid_character:
        raise OutputPlanError(f"{field} must be a non-empty printable ASCII identifier")
    return value


def canonical_output_plan_payload(plan: OutputPlan) -> dict[str, object]:
    """Serialize an OutputPlan canonically for audit and evidence binding.

    This includes private reconstruction routes and is not a Cloud-visible payload.
    """

    _validate(plan)
    shares = []
    for share in sorted(plan.shares, key=lambda item: (item.component_id, item.output_block_id)):
        shares.append(
            {
                "component_id": share.component_id,
                "output_block_id": share.output_block_id,
                "slot_to_logical": [
                    [physical_slot, logical_coordinate]
                    for physical_slot, logical_coordinate in sorted(share.slot_to_logical)
                ],
            }
        )
    return {
        "format": OUTPUT_PLAN_FORMAT,
        "logical_output_size": plan.logical_output_size,
        "slot_count": plan.slot_count,
        "shares": shares,
    }


def _validate(plan: OutputPlan) -> Counter[int]:
    logical_output_size = _require_positive_int(plan.logical_output_size, "logical_output_size")
    slot_count = _require_positive_int(plan.slot_count, "slot_count")
    if not isinstance(plan.shares, tuple):
        raise OutputPlanError("shares must be a tuple")

    share_ids: set[tuple[str, str]] = set()
    logical_multiplicity: Counter[int] = Counter()
    for share in plan.shares:
        if not isinstance(share, OutputShare):
            raise OutputPlanError("shares must contain OutputShare values")
        component_id = _require_id(share.component_id, "component_id")
        output_block_id = _require_id(share.output_block_id, "output_block_id")
        share_id = (component_id, output_block_id)
        if share_id in share_ids:
            raise OutputPlanError("component_id/output_block_id pairs must be unique")
        share_ids.add(share_id)
        if not isinstance(share.slot_to_logical, tuple) or not share.slot_to_logical:
            raise OutputPlanError("each output share must map at least one physical slot")

        physical_slots: set[int] = set()
        for mapping in share.slot_to_logical:
            if not isinstance(mapping, tuple) or len(mapping) != 2:
                raise OutputPlanError("slot_to_logical entries must be integer pairs")
            physical_slot, logical_coordinate = mapping
            if not _is_strict_int(physical_slot) or not 0 <= physical_slot < slot_count:
                raise OutputPlanError("physical slot is outside the output share")
            if physical_slot in physical_slots:
                raise OutputPlanError("physical slots must be unique within an output share")
            physical_slots.add(physical_slot)
            if not _is_strict_int(logical_coordinate) or not (
                0 <= logical_coordinate < logical_output_size
            ):
                raise OutputPlanError("logical coordinate is outside the output vector")
            logical_multiplicity[logical_coordinate] += 1

    return logical_multiplicity


def analyze_output_plan(plan: OutputPlan) -> OutputPlanAnalysis:
    """Validate a plan and derive its reconstruction, masking, and accounting facts."""

    multiplicity = _validate(plan)
    implicit_zero_coordinates = plan.logical_output_size - len(multiplicity)
    overlap_coordinates = {coordinate for coordinate, count in multiplicity.items() if count > 1}
    masked_share_ids = {
        (share.component_id, share.output_block_id)
        for share in plan.shares
        if any(logical in overlap_coordinates for _, logical in share.slot_to_logical)
    }
    payload = canonical_output_plan_payload(plan)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    client_modular_additions = sum(count - 1 for count in multiplicity.values())
    return OutputPlanAnalysis(
        output_plan_digest=hashlib.sha256(canonical).hexdigest(),
        reconstruction_mode="coordinate-sum" if overlap_coordinates else "concatenate",
        result_ciphertexts=len(plan.shares),
        masked_result_ciphertexts=len(masked_share_ids),
        implicit_zero_coordinates=implicit_zero_coordinates,
        overlap_coordinates=len(overlap_coordinates),
        mask_random_elements=sum(
            multiplicity[coordinate] - 1 for coordinate in overlap_coordinates
        ),
        mask_mapped_elements=sum(multiplicity[coordinate] for coordinate in overlap_coordinates),
        client_reorder_elements=sum(multiplicity.values()),
        client_modular_additions=client_modular_additions,
    )


def prepare_f1m_masks(
    plan: OutputPlan,
    *,
    query_id: str,
    version_id: str,
    modulus: int,
    ledger: MaskBindingLedger,
) -> tuple[PreparedMask, ...]:
    """Prepare masks with the operating-system CSPRNG for overlapping coordinates."""

    query_id = _require_id(query_id, "query_id")
    version_id = _require_id(version_id, "version_id")
    if not _is_strict_int(modulus) or modulus < 2:
        raise OutputPlanError("modulus must be an integer of at least two")
    analysis = analyze_output_plan(plan)
    contributors: dict[int, list[tuple[str, str, int]]] = {}
    for share in plan.shares:
        for physical_slot, logical_coordinate in share.slot_to_logical:
            contributors.setdefault(logical_coordinate, []).append(
                (share.component_id, share.output_block_id, physical_slot)
            )

    masked_share_ids = sorted(
        {
            (component_id, output_block_id)
            for lanes in contributors.values()
            if len(lanes) > 1
            for component_id, output_block_id, _ in lanes
        }
    )
    bindings: tuple[MaskBinding, ...] = tuple(
        (
            query_id,
            version_id,
            analysis.output_plan_digest,
            component_id,
            output_block_id,
        )
        for component_id, output_block_id in masked_share_ids
    )
    ledger.reserve_all(bindings)

    values_by_share: dict[tuple[str, str], list[int]] = {}
    for logical_coordinate in sorted(contributors):
        lanes = sorted(contributors[logical_coordinate])
        if len(lanes) == 1:
            continue
        random_values = []
        for _ in lanes[:-1]:
            sample = secrets.randbelow(modulus)
            if not _is_strict_int(sample) or not 0 <= sample < modulus:
                raise OutputPlanError("randbelow returned a value outside Z_t")
            random_values.append(sample)
        lane_values = (*random_values, (-sum(random_values)) % modulus)
        for (component_id, output_block_id, physical_slot), value in zip(
            lanes, lane_values, strict=True
        ):
            share_id = (component_id, output_block_id)
            values_by_share.setdefault(share_id, [0] * plan.slot_count)[physical_slot] = value

    return tuple(
        PreparedMask(
            query_id=query_id,
            version_id=version_id,
            output_plan_digest=analysis.output_plan_digest,
            component_id=component_id,
            output_block_id=output_block_id,
            values=tuple(values_by_share[(component_id, output_block_id)]),
        )
        for component_id, output_block_id in sorted(values_by_share)
    )
