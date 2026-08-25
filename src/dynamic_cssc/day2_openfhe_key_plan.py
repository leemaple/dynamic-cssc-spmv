"""Single-use OpenFHE key-plan capability bound to final Day 2 evidence.

The caller may present canonical ``rotation-key-plan.json`` bytes, but cannot
present an authority object or an authorization flag.  The repository seam
obtains the final Day 2 authority itself and mints a capability only when the
bytes are the exact preimage of the post-run anchored plan digest.  The
capability authorizes that key plan alone; it grants no runtime, dispatch,
cost, publication, performance, or security authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass

from dynamic_cssc.day2_calibration_authority import (
    Day2CalibrationAuthority,
    Day2CalibrationAuthorityError,
    repository_day2_calibration_authority,
)
from dynamic_cssc.openfhe_query_runner import (
    OpenFHEKeyGenerationPlan,
    OpenFHEQueryRunnerError,
    pre_admission_day2_openfhe_key_generation_plan,
)

DAY2_OPENFHE_KEY_PLAN_RECEIPT_SCHEMA = (
    "dynamic-cssc-publication-day2-anchored-openfhe-key-plan-receipt-v1"
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Day2OpenFHEKeyPlanError(ValueError):
    """The anchored Day 2 key plan could not cross its repository seam."""


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
        raise Day2OpenFHEKeyPlanError(
            "Day 2 key-plan receipt is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day2OpenFHEKeyPlanError(f"{field} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class Day2OpenFHEKeyPlanReceipt:
    day2_source_git_sha: str
    day2_outer_archive_sha256: str
    rotation_key_plan_sha256: str
    day1a_authority_receipt_sha256: str
    day1a_inventory_sha256: str
    required_exact_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.day2_source_git_sha) is not str
            or _LOWER_GIT_SHA.fullmatch(self.day2_source_git_sha) is None
        ):
            raise Day2OpenFHEKeyPlanError(
                "anchored Day 2 source must be one lowercase Git SHA"
            )
        for field in (
            "day2_outer_archive_sha256",
            "rotation_key_plan_sha256",
            "day1a_authority_receipt_sha256",
            "day1a_inventory_sha256",
        ):
            _require_sha256(getattr(self, field), f"anchored key plan {field}")
        indices = self.required_exact_indices
        if (
            type(indices) is not tuple
            or not indices
            or any(type(index) is not int for index in indices)
            or indices != tuple(sorted(set(indices)))
            or any(index == 0 or not -4095 <= index <= 4095 for index in indices)
            or len({index % 4096 for index in indices}) != len(indices)
        ):
            raise Day2OpenFHEKeyPlanError(
                "anchored key plan has a noncanonical exact-index inventory"
            )

    def _body_document(self) -> dict[str, object]:
        return {
            "complete_cost_claim_allowed": False,
            "day1a_authority_receipt_sha256": self.day1a_authority_receipt_sha256,
            "day1a_inventory_sha256": self.day1a_inventory_sha256,
            "day2_direct_key_plan_authorized": True,
            "day2_outer_archive_sha256": self.day2_outer_archive_sha256,
            "day2_source_git_sha": self.day2_source_git_sha,
            "formal_authority_granted": False,
            "heldout_dispatch_authorized": False,
            "performance_claim_allowed": False,
            "publication_authority": False,
            "required_exact_indices": list(self.required_exact_indices),
            "rotation_key_plan_sha256": self.rotation_key_plan_sha256,
            "runtime_admission_granted": False,
            "schema_version": DAY2_OPENFHE_KEY_PLAN_RECEIPT_SCHEMA,
            "security_claim_allowed": False,
            "status": "verified-anchored-key-plan-only",
        }

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._body_document())).hexdigest()

    def to_document(self) -> dict[str, object]:
        body = self._body_document()
        return {**body, "key_plan_receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True, slots=True)
class ClaimedDay2OpenFHEKeyPlan:
    """Claimed plan carrier; a caller-created instance is never authority."""

    receipt: Day2OpenFHEKeyPlanReceipt
    key_generation_plan: OpenFHEKeyGenerationPlan


@dataclass(frozen=True, slots=True)
class _Day2OpenFHEKeyPlanBinding:
    receipt: Day2OpenFHEKeyPlanReceipt
    key_generation_plan: OpenFHEKeyGenerationPlan


class Day2OpenFHEKeyPlanCapability:
    """Opaque single-use capability minted from the final repository anchor."""

    __slots__ = ("_binding", "_claimed", "_lock")

    def __new__(cls) -> Day2OpenFHEKeyPlanCapability:
        raise TypeError("Day 2 OpenFHE key-plan capabilities are repository-minted")

    def __bool__(self) -> bool:
        raise TypeError("Day 2 OpenFHE key-plan capability is not a caller boolean")


def _authority_identity(
    authority: Day2CalibrationAuthority,
) -> tuple[str, str, str]:
    if type(authority) is not Day2CalibrationAuthority:
        raise Day2OpenFHEKeyPlanError(
            "Day 2 key plan requires exact repository calibration authority"
        )
    return (
        authority.source_git_sha,
        authority.outer_archive_sha256,
        authority.rotation_key_plan_sha256,
    )


def _issue_from_day2_authority(
    authority: Day2CalibrationAuthority,
    rotation_key_plan_bytes: bytes,
) -> Day2OpenFHEKeyPlanCapability:
    source_git_sha, outer_archive_sha256, anchored_plan_sha256 = (
        _authority_identity(authority)
    )
    try:
        plan = pre_admission_day2_openfhe_key_generation_plan(
            rotation_key_plan_bytes
        )
    except (OpenFHEQueryRunnerError, TypeError, ValueError) as error:
        raise Day2OpenFHEKeyPlanError(
            "Day 2 rotation key plan is not the exact canonical plan"
        ) from error
    if plan.rotation_key_plan_sha256 != anchored_plan_sha256:
        raise Day2OpenFHEKeyPlanError(
            "Day 2 rotation key plan differs from final repository authority"
        )
    document = json.loads(plan.rotation_key_plan_bytes.decode("ascii"))
    receipt = Day2OpenFHEKeyPlanReceipt(
        day2_source_git_sha=source_git_sha,
        day2_outer_archive_sha256=outer_archive_sha256,
        rotation_key_plan_sha256=plan.rotation_key_plan_sha256,
        day1a_authority_receipt_sha256=document[
            "day1a_authority_receipt_sha256"
        ],
        day1a_inventory_sha256=document["day1a_inventory_sha256"],
        required_exact_indices=plan.required_exact_indices,
    )
    capability = object.__new__(Day2OpenFHEKeyPlanCapability)
    object.__setattr__(
        capability,
        "_binding",
        _Day2OpenFHEKeyPlanBinding(
            receipt=receipt,
            key_generation_plan=plan,
        ),
    )
    object.__setattr__(capability, "_claimed", False)
    object.__setattr__(capability, "_lock", threading.Lock())
    return capability


def issue_repository_day2_openfhe_key_plan(
    rotation_key_plan_bytes: bytes,
) -> Day2OpenFHEKeyPlanCapability:
    """Mint one exact anchored plan without accepting caller authority."""

    try:
        before = repository_day2_calibration_authority()
    except (Day2CalibrationAuthorityError, OSError) as error:
        raise Day2OpenFHEKeyPlanError(
            f"final repository Day 2 authority is unavailable: {error}"
        ) from error
    capability = _issue_from_day2_authority(before, rotation_key_plan_bytes)
    try:
        after = repository_day2_calibration_authority()
    except (Day2CalibrationAuthorityError, OSError) as error:
        abandon_day2_openfhe_key_plan(capability)
        raise Day2OpenFHEKeyPlanError(
            f"final repository Day 2 authority is unavailable: {error}"
        ) from error
    if _authority_identity(after) != _authority_identity(before):
        abandon_day2_openfhe_key_plan(capability)
        raise Day2OpenFHEKeyPlanError(
            "final repository Day 2 authority changed while issuing the key plan"
        )
    return capability


def _live_binding(
    capability: Day2OpenFHEKeyPlanCapability,
    *,
    consume: bool,
) -> _Day2OpenFHEKeyPlanBinding:
    if type(capability) is not Day2OpenFHEKeyPlanCapability:
        raise TypeError("key plan must be one exact repository-minted capability")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise Day2OpenFHEKeyPlanError(
            "Day 2 OpenFHE key-plan capability is not authoritative"
        )
    with lock:
        if getattr(capability, "_claimed", None) is not False:
            raise Day2OpenFHEKeyPlanError(
                "Day 2 OpenFHE key-plan capability is absent or consumed"
            )
        if consume:
            object.__setattr__(capability, "_claimed", True)
        binding = getattr(capability, "_binding", None)
    try:
        if type(binding) is not _Day2OpenFHEKeyPlanBinding:
            raise Day2OpenFHEKeyPlanError(
                "Day 2 OpenFHE key-plan capability is not authoritative"
            )
        try:
            rebuilt = pre_admission_day2_openfhe_key_generation_plan(
                binding.key_generation_plan.rotation_key_plan_bytes
            )
        except (OpenFHEQueryRunnerError, TypeError, ValueError) as error:
            raise Day2OpenFHEKeyPlanError(
                "Day 2 OpenFHE key-plan capability lost its canonical plan"
            ) from error
        document = json.loads(rebuilt.rotation_key_plan_bytes.decode("ascii"))
        receipt = binding.receipt
        if (
            rebuilt != binding.key_generation_plan
            or rebuilt.rotation_key_plan_sha256 != receipt.rotation_key_plan_sha256
            or rebuilt.required_exact_indices != receipt.required_exact_indices
            or document["day1a_authority_receipt_sha256"]
            != receipt.day1a_authority_receipt_sha256
            or document["day1a_inventory_sha256"]
            != receipt.day1a_inventory_sha256
        ):
            raise Day2OpenFHEKeyPlanError(
                "Day 2 OpenFHE key-plan capability differs from its receipt"
            )
    finally:
        if consume:
            with lock:
                object.__setattr__(capability, "_binding", None)
    return binding


def describe_day2_openfhe_key_plan(
    capability: Day2OpenFHEKeyPlanCapability,
) -> Day2OpenFHEKeyPlanReceipt:
    """Describe an unconsumed plan receipt without exposing its exact bytes."""

    return _live_binding(capability, consume=False).receipt


def claim_day2_openfhe_key_plan(
    capability: Day2OpenFHEKeyPlanCapability,
) -> ClaimedDay2OpenFHEKeyPlan:
    """Consume the capability and return its exact typed runner plan."""

    binding = _live_binding(capability, consume=True)
    return ClaimedDay2OpenFHEKeyPlan(
        receipt=binding.receipt,
        key_generation_plan=binding.key_generation_plan,
    )


def abandon_day2_openfhe_key_plan(
    capability: Day2OpenFHEKeyPlanCapability,
) -> None:
    """Consume an unused plan capability and release its retained plan bytes."""

    _live_binding(capability, consume=True)


__all__ = (
    "DAY2_OPENFHE_KEY_PLAN_RECEIPT_SCHEMA",
    "ClaimedDay2OpenFHEKeyPlan",
    "Day2OpenFHEKeyPlanCapability",
    "Day2OpenFHEKeyPlanError",
    "Day2OpenFHEKeyPlanReceipt",
    "abandon_day2_openfhe_key_plan",
    "claim_day2_openfhe_key_plan",
    "describe_day2_openfhe_key_plan",
    "issue_repository_day2_openfhe_key_plan",
)
