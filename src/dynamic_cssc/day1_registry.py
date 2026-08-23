from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal, TypeAlias, get_args

from .evidence_compatibility import (
    DAY1_REGISTRATION_ANCHOR_PATH,
    EvidenceCompatibilityError,
    EvidenceRole,
    read_current_role_evidence_data,
    verify_repository_anchor_history,
)
from .selection import (
    FROZEN_PERIODIC_REPACK_WINDOWS,
    FROZEN_RESERVED_SLACK_BETAS,
    CandidateStrategy,
    build_fixed_candidates,
)
from .strong_reference_receipt import (
    StrongReferenceReceiptError,
    repository_historical_strong_source_attestation,
    repository_strong_reference_capability,
)

__all__ = (
    "CandidateRole",
    "Day1CandidateCatalog",
    "Day1CandidateRegistrationError",
    "RegisteredCandidate",
    "RegistrationEvidence",
    "repository_day1_candidate_catalog",
)


class Day1CandidateRegistrationError(ValueError):
    """Raised when the repository cannot admit the complete Day-1 catalog."""


CandidateRole: TypeAlias = Literal["reference", "ablation"]
_CANDIDATE_STRATEGIES = frozenset(get_args(CandidateStrategy))


@dataclass(frozen=True, slots=True)
class RegisteredCandidate:
    """One immutable Day-1 candidate with its causal-selection role."""

    candidate_id: str
    strategy: CandidateStrategy
    role: CandidateRole
    reserved_slack_beta: Decimal | None = None
    periodic_repack_windows: int | None = None
    packed_coo_segment_capacity: int | None = None

    def __post_init__(self) -> None:
        if type(self.strategy) is not str or self.strategy not in _CANDIDATE_STRATEGIES:
            raise ValueError("registered candidate strategy is not recognized")
        if type(self.role) is not str or self.role not in {"reference", "ablation"}:
            raise ValueError("registered candidate role must be reference or ablation")


@dataclass(frozen=True, slots=True)
class RegistrationEvidence:
    """Descriptive identities for one composite registration evidence bundle."""

    schema_version: str
    source_git_sha: str
    run_id: int
    correctness_artifact_sha256: str
    accounting_evidence_sha256: str
    policy_contract_sha256: str


@dataclass(frozen=True, slots=True)
class Day1CandidateCatalog:
    """Complete emitted Day-1 roster plus its descriptive registration evidence."""

    candidates: tuple[RegisteredCandidate, ...]
    registration: RegistrationEvidence

    def __post_init__(self) -> None:
        if type(self.registration) is not RegistrationEvidence:
            raise ValueError("catalog registration must be RegistrationEvidence")
        if self.candidates != _canonical_registered_candidates():
            raise ValueError("catalog candidates must equal the canonical Day-1 roster")

    @property
    def selection_candidates(self) -> tuple[RegisteredCandidate, ...]:
        return tuple(candidate for candidate in self.candidates if candidate.role == "reference")

    @property
    def ablation_candidates(self) -> tuple[RegisteredCandidate, ...]:
        return tuple(candidate for candidate in self.candidates if candidate.role == "ablation")


_REGISTRATION_SCHEMA_VERSION = "dynamic-cssc-day1-registration-evidence-v1"
_STRONG_POLICY_CONTRACT = (
    ("schema_version", "dynamic-cssc-day1-strong-policy-contract-v1"),
    ("candidate_id", "packed-coo-cloud-segmented-delta/segment-width=128"),
    ("strategy", "Packed-COO-Cloud-Segmented-Delta"),
    ("segment_width", 128),
    ("fold", "never"),
    ("compaction", "none"),
    ("base_reserved_slack_beta", "0"),
)
_STRONG_POLICY_CONTRACT_SHA256 = hashlib.sha256(
    json.dumps(
        dict(_STRONG_POLICY_CONTRACT),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
).hexdigest()
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRATION_FIELDS = tuple(RegistrationEvidence.__dataclass_fields__)


def _parse_registration_evidence(
    payload: object,
) -> RegistrationEvidence:
    """Parse a closed composite artifact into a non-authoritative projection."""

    if type(payload) is not dict or set(payload) != set(_REGISTRATION_FIELDS):
        raise Day1CandidateRegistrationError(
            "registration evidence keys must exactly match the closed schema"
        )
    if payload["schema_version"] != _REGISTRATION_SCHEMA_VERSION:
        raise Day1CandidateRegistrationError("registration schema version is not approved")
    if (
        type(payload["source_git_sha"]) is not str
        or _LOWER_GIT_SHA.fullmatch(payload["source_git_sha"]) is None
    ):
        raise Day1CandidateRegistrationError("registration source_git_sha is invalid")
    if type(payload["run_id"]) is not int or payload["run_id"] <= 0:
        raise Day1CandidateRegistrationError("registration run_id is invalid")
    for field in _REGISTRATION_FIELDS[3:]:
        value = payload[field]
        if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
            raise Day1CandidateRegistrationError(f"registration {field} is invalid")
    if payload["policy_contract_sha256"] != _STRONG_POLICY_CONTRACT_SHA256:
        raise Day1CandidateRegistrationError(
            "registration evidence does not bind the frozen strong policy"
        )
    return RegistrationEvidence(**payload)


def _build_day1_candidate_catalog(
    registration: RegistrationEvidence,
) -> Day1CandidateCatalog:
    """Build canonical value semantics after authority has already been established."""

    if type(registration) is not RegistrationEvidence:
        raise Day1CandidateRegistrationError(
            "catalog registration must be descriptive RegistrationEvidence"
        )
    payload = {field: getattr(registration, field) for field in _REGISTRATION_FIELDS}
    _parse_registration_evidence(payload)

    return Day1CandidateCatalog(
        candidates=_canonical_registered_candidates(),
        registration=registration,
    )


def _canonical_registered_candidates() -> tuple[RegisteredCandidate, ...]:
    legacy = build_fixed_candidates(
        reserved_slack_betas=FROZEN_RESERVED_SLACK_BETAS,
        periodic_repack_windows=FROZEN_PERIODIC_REPACK_WINDOWS,
    )
    candidates = tuple(
        RegisteredCandidate(
            candidate_id=candidate.candidate_id,
            strategy=candidate.strategy,
            role=(
                "ablation"
                if candidate.candidate_id == "packed-coo-client-lane-delta/capacity=128"
                else "reference"
            ),
            reserved_slack_beta=candidate.reserved_slack_beta,
            periodic_repack_windows=candidate.periodic_repack_windows,
            packed_coo_segment_capacity=candidate.packed_coo_segment_capacity,
        )
        for candidate in legacy
    ) + (
        RegisteredCandidate(
            candidate_id="packed-coo-cloud-segmented-delta/segment-width=128",
            strategy="Packed-COO-Cloud-Segmented-Delta",
            role="reference",
            reserved_slack_beta=Decimal("0"),
        ),
    )
    return candidates


def repository_day1_candidate_catalog() -> Day1CandidateCatalog:
    """Admit the complete catalog only from repository-owned evidence."""

    repository_root = Path(__file__).resolve().parents[2]
    try:
        anchor_blobs = read_current_role_evidence_data(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise Day1CandidateRegistrationError(
            f"repository Day1 registration anchor data is unavailable: {error}"
        ) from error
    if len(anchor_blobs) != 1 or anchor_blobs[0].path != DAY1_REGISTRATION_ANCHOR_PATH:
        raise Day1CandidateRegistrationError(
            "repository Day1 registration anchor path set is not exact"
        )
    anchor_bytes = anchor_blobs[0].content
    if anchor_bytes == (
        b'{"anchors":[],"schema_version":"dynamic-cssc-day1-registration-anchor-set-v1"}\n'
    ):
        raise Day1CandidateRegistrationError(
            "no repository-approved Day-1 composite registration anchor is installed; "
            "correctness evidence alone cannot admit accounting, schema, and policy evidence"
        )
    try:
        correctness = repository_strong_reference_capability()
        strong_source = repository_historical_strong_source_attestation()
        history = verify_repository_anchor_history(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
    except (EvidenceCompatibilityError, StrongReferenceReceiptError) as error:
        raise Day1CandidateRegistrationError(
            f"repository Day1 composite registration verification failed: {error}"
        ) from error
    if (
        correctness.authority_state != "historical-descriptive-only"
        or correctness.formal_authority_granted is not False
        or correctness.candidate_registration_allowed is not False
        or correctness.complete_reference_set is not False
    ):
        raise Day1CandidateRegistrationError(
            "historical strong correctness identity must remain descriptive and claims-false"
        )
    if (
        strong_source.formal_authority_granted is not False
        or strong_source.source_git_sha != correctness.source_git_sha
    ):
        raise Day1CandidateRegistrationError(
            "historical strong correctness artifact and Git source identity are not closed"
        )
    registration = _parse_registration_evidence(history.registration_evidence)
    if registration.source_git_sha != history.experiment_source_git_sha:
        raise Day1CandidateRegistrationError(
            "registration artifact source does not match the verified experiment snapshot"
        )
    if registration.correctness_artifact_sha256 != correctness.artifact_sha256:
        raise Day1CandidateRegistrationError(
            "Day1 composite registration does not bind the historical correctness artifact"
        )
    registration_bytes = (
        json.dumps(
            history.registration_evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    if hashlib.sha256(registration_bytes).hexdigest() != history.artifact_sha256:
        raise Day1CandidateRegistrationError(
            "Day1 registration artifact digest changed after repository verification"
        )
    try:
        final_history = verify_repository_anchor_history(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
        final_correctness = repository_strong_reference_capability()
        final_strong_source = repository_historical_strong_source_attestation()
    except (EvidenceCompatibilityError, StrongReferenceReceiptError) as error:
        raise Day1CandidateRegistrationError(
            f"repository Day1 registration changed before catalog construction: {error}"
        ) from error
    if (
        final_history != history
        or final_correctness != correctness
        or final_strong_source != strong_source
    ):
        raise Day1CandidateRegistrationError(
            "repository correctness or registration evidence changed before catalog construction"
        )
    return _build_day1_candidate_catalog(registration)
