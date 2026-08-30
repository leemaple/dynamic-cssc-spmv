"""Closed provider-progress state machine for one follow-up formal campaign.

The documents produced here are authority-false receipts.  Positive authority
remains live in the controller and is consumed exactly once by the provider CAS
that installs ``campaign-open``.  Every later document is one immutable state
transition in that same campaign, not a bearer capability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final, Literal

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_BASELINE_SHA256,
    FOLLOWUP_STAGE1_PLAN_SHA256,
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
    followup_formal_unit_specs,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FOLLOWUP_FORMAL_PROGRESS_REF",
    "FOLLOWUP_PROVIDER_FAILURE_CLASSES",
    "FollowupCampaignError",
    "FollowupCampaignSelection",
    "FollowupCampaignRunAdmissionReceipt",
    "FollowupCampaignState",
    "arm_followup_campaign_watch",
    "bind_followup_campaign_run",
    "close_followup_campaign_no_go",
    "commit_followup_campaign_unit",
    "followup_formal_campaign_id",
    "followup_formal_matrix_sha256",
    "followup_campaign_artifact_binding_scope",
    "inspect_followup_campaign_state",
    "inspect_followup_campaign_run_admission",
    "inspect_followup_campaign_selection",
    "open_followup_campaign_state",
    "record_followup_provider_failure",
    "reserve_followup_campaign_unit",
    "build_followup_campaign_selection",
    "build_followup_campaign_run_admission_receipt",
)

FOLLOWUP_FORMAL_PROGRESS_REF: Final = (
    "refs/tags/dynamic-cssc-followup-performance-formal-authority-v1"
)
FOLLOWUP_PROVIDER_FAILURE_CLASSES: Final = frozenset(
    {
        "actions-internal-service-error",
        "hosted-runner-assignment-failure",
        "hosted-runner-loss-or-shutdown",
    }
)

_SCHEMA: Final = "dynamic-cssc-followup-performance-campaign-state-v1"
_SELECTION_SCHEMA: Final = (
    "dynamic-cssc-followup-performance-campaign-selection-v1"
)
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STATES = frozenset(
    {
        "campaign-open",
        "unit-reserved",
        "run-bound",
        "watch-armed",
        "unit-committed",
        "unit-provider-failed",
        "campaign-no-go",
    }
)
_NO_GO_REASONS = frozenset(
    {
        "artifact-invalid",
        "budget-exhausted",
        "cas-failed-or-ambiguous",
        "dispatch-failed-or-ambiguous",
        "identity-invalid",
        "nonretryable-provider-failure",
        "provider-observation-failed",
        "retry-budget-insufficient",
        "scientific-or-guard-failure",
        "watcher-failed-or-incomplete",
    }
)
_UNIT_KINDS = frozenset(
    {"formal-acquisition", "formal-native", "formal-ordered-event", "formal-synthetic"}
)
_FIXED_FIELDS = frozenset(
    {
        "artifact_id_or_null",
        "artifact_name_or_null",
        "artifact_provider_digest_or_null",
        "authority",
        "campaign_id",
        "compatibility_receipt_sha256",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "formal_matrix_sha256",
        "provider_failure_class_or_null",
        "provider_failure_evidence_sha256_or_null",
        "provider_run_attempt_or_null",
        "provider_run_id_or_null",
        "publication_evidence_admitted",
        "qualification_q6_artifact_digest",
        "qualification_q6_artifact_id",
        "qualification_run_id",
        "retry_used",
        "schema_version",
        "scientific_plan_sha256",
        "sequence",
        "stage1_plan_sha256",
        "state",
        "study_id",
        "terminal_reason_code_or_null",
        "unit_attempt_ordinal_or_null",
        "unit_kind_or_null",
        "unit_ordinal_or_null",
        "unit_output_envelope_sha256_or_null",
        "watcher_receipt_sha256_or_null",
        "watcher_session_sha256_or_null",
    }
)

CampaignStateName = Literal[
    "campaign-open",
    "unit-reserved",
    "run-bound",
    "watch-armed",
    "unit-committed",
    "unit-provider-failed",
    "campaign-no-go",
]


class FollowupCampaignError(FollowupContractError):
    """One formal-campaign state or transition failed closed."""


def _validate_state_projection(value: dict[str, object]) -> None:
    state = value["state"]
    unit_fields = (
        value["unit_ordinal_or_null"],
        value["unit_kind_or_null"],
        value["unit_attempt_ordinal_or_null"],
    )
    run_fields = (
        value["provider_run_id_or_null"],
        value["provider_run_attempt_or_null"],
    )
    artifact_fields = (
        value["artifact_id_or_null"],
        value["artifact_name_or_null"],
        value["artifact_provider_digest_or_null"],
        value["unit_output_envelope_sha256_or_null"],
    )
    failure_fields = (
        value["provider_failure_class_or_null"],
        value["provider_failure_evidence_sha256_or_null"],
    )
    if state == "campaign-open":
        if (
            value["sequence"] != 0
            or value["retry_used"] is not False
            or any(field is not None for field in (*unit_fields, *run_fields))
            or any(field is not None for field in artifact_fields)
            or any(field is not None for field in failure_fields)
            or value["watcher_session_sha256_or_null"] is not None
            or value["watcher_receipt_sha256_or_null"] is not None
            or value["terminal_reason_code_or_null"] is not None
        ):
            raise FollowupCampaignError("campaign-open projection changed")
        return
    if state == "campaign-no-go":
        if value["terminal_reason_code_or_null"] is None:
            raise FollowupCampaignError("campaign NO-GO lacks its terminal reason")
        return
    if (
        any(field is None for field in unit_fields)
        or value["unit_kind_or_null"] not in _UNIT_KINDS
        or value["terminal_reason_code_or_null"] is not None
    ):
        raise FollowupCampaignError("active unit projection changed")
    if state == "unit-reserved":
        if (
            any(field is not None for field in run_fields)
            or any(field is not None for field in artifact_fields)
            or any(field is not None for field in failure_fields)
            or value["watcher_session_sha256_or_null"] is not None
            or value["watcher_receipt_sha256_or_null"] is not None
        ):
            raise FollowupCampaignError("unit reservation projection changed")
        return
    if any(field is None for field in run_fields):
        raise FollowupCampaignError("run-bearing campaign state lacks its provider run")
    if state == "run-bound":
        if (
            value["watcher_session_sha256_or_null"] is not None
            or value["watcher_receipt_sha256_or_null"] is not None
            or any(field is not None for field in artifact_fields)
            or any(field is not None for field in failure_fields)
        ):
            raise FollowupCampaignError("run binding projection changed")
        return
    if value["watcher_session_sha256_or_null"] is None:
        raise FollowupCampaignError("watched campaign state lacks its watcher session")
    if state == "watch-armed":
        if (
            value["watcher_receipt_sha256_or_null"] is not None
            or any(field is not None for field in artifact_fields)
            or any(field is not None for field in failure_fields)
        ):
            raise FollowupCampaignError("watch-armed projection changed")
        return
    if value["watcher_receipt_sha256_or_null"] is None:
        raise FollowupCampaignError("terminal unit state lacks its watcher receipt")
    if state == "unit-committed":
        if any(field is None for field in artifact_fields) or any(
            field is not None for field in failure_fields
        ):
            raise FollowupCampaignError("committed unit projection changed")
        return
    if state == "unit-provider-failed" and (
        any(field is not None for field in artifact_fields)
        or any(field is None for field in failure_fields)
    ):
        raise FollowupCampaignError("provider-failed unit projection changed")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _require_sha(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupCampaignError(f"{field} is not one lowercase SHA-256")
    return value


def _require_git_sha(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise FollowupCampaignError(f"{field} is not one lowercase Git SHA-1")
    return value


def _require_positive(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupCampaignError(f"{field} is not one positive integer")
    return value


def followup_formal_matrix_sha256(
    scientific_profile: RouteAScientificProfile,
) -> str:
    """Digest the exact ordered 17-unit matrix and its frozen reservations."""

    specs = followup_formal_unit_specs(scientific_profile)
    return _sha256(
        _canonical_json_bytes(
            [
                {
                    "formal_seed_or_null": spec.formal_seed,
                    "formal_seed_ordinal_or_null": spec.formal_seed_ordinal,
                    "job_token": spec.job_token,
                    "ordinal": spec.ordinal,
                    "partition_or_null": spec.partition,
                    "reservation_minutes": spec.reservation_minutes,
                    "scale_or_null": spec.scale,
                    "segment": spec.segment,
                    "semantics_or_null": spec.semantics,
                    "strategy_candidate_id_or_null": spec.strategy_candidate_id,
                    "strategy_ordinal_or_null": spec.strategy_ordinal,
                    "unit_kind": spec.unit_kind,
                }
                for spec in specs
            ]
        )
    )


def followup_formal_campaign_id(
    *,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    compatibility_receipt_sha256: str,
    qualification_run_id: int,
    qualification_q6_artifact_id: int,
    qualification_q6_artifact_digest: str,
    formal_matrix_sha256: str,
) -> str:
    """Derive the stable identity of the sole logical formal campaign."""

    _require_git_sha(experiment_source_s1_sha, field="experiment source S1")
    _require_git_sha(evidence_freeze_s2_sha, field="evidence freeze S2")
    _require_sha(compatibility_receipt_sha256, field="compatibility receipt")
    _require_positive(qualification_run_id, field="qualification run ID")
    _require_positive(qualification_q6_artifact_id, field="qualification q6 artifact ID")
    if (
        type(qualification_q6_artifact_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(qualification_q6_artifact_digest) is None
    ):
        raise FollowupCampaignError("qualification q6 digest is not a provider SHA-256")
    _require_sha(formal_matrix_sha256, field="formal matrix")
    return _sha256(
        _canonical_json_bytes(
            {
                "compatibility_receipt_sha256": compatibility_receipt_sha256,
                "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
                "experiment_source_S1_sha": experiment_source_s1_sha,
                "formal_matrix_sha256": formal_matrix_sha256,
                "qualification_q6_artifact_digest": qualification_q6_artifact_digest,
                "qualification_q6_artifact_id": qualification_q6_artifact_id,
                "qualification_run_id": qualification_run_id,
                "scientific_plan_sha256": FOLLOWUP_BASELINE_SHA256,
                "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
                "study_id": FOLLOWUP_STUDY_ID,
            }
        )
    )


def followup_campaign_artifact_binding_scope(
    *,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
) -> dict[str, object]:
    """Return the shared outer-identity projection for every formal artifact."""

    _require_sha(campaign_id, field="campaign ID")
    _require_sha(campaign_run_admission_sha256, field="campaign run admission")
    if type(formal_unit_ordinal) is not int or not 0 <= formal_unit_ordinal < 17:
        raise FollowupCampaignError("formal unit ordinal is outside 0..16")
    return {
        "campaign_id": campaign_id,
        "campaign_run_admission_sha256": campaign_run_admission_sha256,
        "formal_unit_ordinal": formal_unit_ordinal,
    }


@dataclass(frozen=True, slots=True)
class FollowupCampaignState:
    """One canonical authority-false progress receipt."""

    document: dict[str, object]
    document_bytes: bytes
    sha256: str

    @property
    def state(self) -> str:
        value = self.document["state"]
        assert type(value) is str
        return value

    @property
    def sequence(self) -> int:
        value = self.document["sequence"]
        assert type(value) is int
        return value


@dataclass(frozen=True, slots=True)
class FollowupCampaignSelection:
    """The exact final-successful-attempt choice for all seventeen units."""

    document: dict[str, object]
    document_bytes: bytes
    sha256: str

    @property
    def campaign_id(self) -> str:
        value = self.document["campaign_id"]
        assert type(value) is str
        return value

    @property
    def units(self) -> tuple[dict[str, object], ...]:
        value = self.document["units"]
        assert type(value) is list
        return tuple(value)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class FollowupCampaignRunAdmissionReceipt:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def build_followup_campaign_run_admission_receipt(
    armed: FollowupCampaignState,
    *,
    reservation_oid: str,
    watch_armed_oid: str,
) -> FollowupCampaignRunAdmissionReceipt:
    """Derive the receipt shared by the controller and in-run admission gate."""

    if type(armed) is not FollowupCampaignState or armed.state != "watch-armed":
        raise FollowupCampaignError("run admission receipt lacks a watch-armed state")
    _require_git_sha(reservation_oid, field="reservation OID")
    _require_git_sha(watch_armed_oid, field="watch-armed OID")
    document = armed.document
    if (
        type(document["provider_run_id_or_null"]) is not int
        or document["provider_run_attempt_or_null"] != 1
        or type(document["unit_attempt_ordinal_or_null"]) is not int
        or type(document["unit_ordinal_or_null"]) is not int
    ):
        raise FollowupCampaignError("watch-armed state lacks one exact run identity")
    receipt = {
        "authority": False,
        "campaign_id": document["campaign_id"],
        "progress_state_sha256": armed.sha256,
        "provider_run_attempt": 1,
        "provider_run_id": document["provider_run_id_or_null"],
        "publication_evidence_admitted": False,
        "reservation_oid": reservation_oid,
        "schema_version": (
            "dynamic-cssc-followup-performance-campaign-run-admission-v1"
        ),
        "study_id": document["study_id"],
        "unit_attempt_ordinal": document["unit_attempt_ordinal_or_null"],
        "unit_ordinal": document["unit_ordinal_or_null"],
        "watch_armed_oid": watch_armed_oid,
    }
    receipt_bytes = _canonical_json_bytes(receipt)
    return FollowupCampaignRunAdmissionReceipt(
        document=receipt,
        document_bytes=receipt_bytes,
        sha256=_sha256(receipt_bytes),
    )


def _new_state(base: dict[str, object], **changes: object) -> FollowupCampaignState:
    document = dict(base)
    document.update(changes)
    document_bytes = _canonical_json_bytes(document)
    return inspect_followup_campaign_state(document_bytes)


def inspect_followup_campaign_state(content: bytes) -> FollowupCampaignState:
    """Parse and close one state receipt without trusting its caller."""

    value = _parse_ascii_json(content, label="follow-up campaign state")
    if type(value) is not dict or set(value) != _FIXED_FIELDS:
        raise FollowupCampaignError("campaign state field set changed")
    if _canonical_json_bytes(value) != content:
        raise FollowupCampaignError("campaign state is not canonical JSON")
    if (
        value.get("schema_version") != _SCHEMA
        or value.get("study_id") != FOLLOWUP_STUDY_ID
        or value.get("stage1_plan_sha256") != FOLLOWUP_STAGE1_PLAN_SHA256
        or value.get("scientific_plan_sha256") != FOLLOWUP_BASELINE_SHA256
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or value.get("state") not in _STATES
        or type(value.get("sequence")) is not int
        or value["sequence"] < 0
        or type(value.get("retry_used")) is not bool
    ):
        raise FollowupCampaignError("campaign state lineage or scalar domain changed")
    _require_sha(value.get("campaign_id"), field="campaign ID")
    _require_sha(value.get("compatibility_receipt_sha256"), field="compatibility receipt")
    _require_git_sha(value.get("experiment_source_S1_sha"), field="experiment source S1")
    _require_git_sha(value.get("evidence_freeze_S2_sha"), field="evidence freeze S2")
    _require_sha(value.get("formal_matrix_sha256"), field="formal matrix")
    _require_positive(value.get("qualification_run_id"), field="qualification run ID")
    _require_positive(
        value.get("qualification_q6_artifact_id"),
        field="qualification q6 artifact ID",
    )
    q6_digest = value.get("qualification_q6_artifact_digest")
    if type(q6_digest) is not str or _PROVIDER_DIGEST.fullmatch(q6_digest) is None:
        raise FollowupCampaignError("qualification q6 artifact digest changed")
    expected_campaign_id = followup_formal_campaign_id(
        experiment_source_s1_sha=value["experiment_source_S1_sha"],  # type: ignore[arg-type]
        evidence_freeze_s2_sha=value["evidence_freeze_S2_sha"],  # type: ignore[arg-type]
        compatibility_receipt_sha256=value["compatibility_receipt_sha256"],  # type: ignore[arg-type]
        qualification_run_id=value["qualification_run_id"],  # type: ignore[arg-type]
        qualification_q6_artifact_id=value["qualification_q6_artifact_id"],  # type: ignore[arg-type]
        qualification_q6_artifact_digest=q6_digest,
        formal_matrix_sha256=value["formal_matrix_sha256"],  # type: ignore[arg-type]
    )
    if value["campaign_id"] != expected_campaign_id:
        raise FollowupCampaignError("campaign ID does not reproduce")

    nullable_sha_fields = (
        "provider_failure_evidence_sha256_or_null",
        "unit_output_envelope_sha256_or_null",
        "watcher_receipt_sha256_or_null",
        "watcher_session_sha256_or_null",
    )
    for field in nullable_sha_fields:
        if value[field] is not None:
            _require_sha(value[field], field=field)
    artifact_digest = value["artifact_provider_digest_or_null"]
    if artifact_digest is not None and (
        type(artifact_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(artifact_digest) is None
    ):
        raise FollowupCampaignError("artifact provider digest changed")
    for field in ("artifact_id_or_null", "provider_run_id_or_null"):
        if value[field] is not None:
            _require_positive(value[field], field=field)
    if value["provider_run_attempt_or_null"] not in {None, 1}:
        raise FollowupCampaignError("provider run attempt is not the initial attempt")
    if value["unit_attempt_ordinal_or_null"] not in {None, 1, 2}:
        raise FollowupCampaignError("outer unit attempt changed")
    ordinal = value["unit_ordinal_or_null"]
    if ordinal is not None and (type(ordinal) is not int or not 0 <= ordinal < 17):
        raise FollowupCampaignError("unit ordinal is outside 0..16")
    if value["provider_failure_class_or_null"] not in {
        None,
        *FOLLOWUP_PROVIDER_FAILURE_CLASSES,
    }:
        raise FollowupCampaignError("provider failure class changed")
    if value["terminal_reason_code_or_null"] not in {None, *_NO_GO_REASONS}:
        raise FollowupCampaignError("terminal reason code changed")
    _validate_state_projection(value)
    return FollowupCampaignState(
        document=value,
        document_bytes=content,
        sha256=_sha256(content),
    )


def inspect_followup_campaign_run_admission(
    reservation_bytes: bytes,
    run_binding_bytes: bytes,
    watch_armed_bytes: bytes,
    *,
    scientific_profile: RouteAScientificProfile,
    expected_campaign_id: str,
    expected_unit_ordinal: int,
    expected_unit_attempt_ordinal: int,
    expected_provider_run_id: int,
) -> FollowupCampaignState:
    """Close the exact reserve→bind→watch chain before any formal seed."""

    reservation = inspect_followup_campaign_state(reservation_bytes)
    binding = inspect_followup_campaign_state(run_binding_bytes)
    armed = inspect_followup_campaign_state(watch_armed_bytes)
    specs = followup_formal_unit_specs(scientific_profile)
    if (
        reservation.document["campaign_id"] != expected_campaign_id
        or type(expected_unit_ordinal) is not int
        or not 0 <= expected_unit_ordinal < len(specs)
        or reservation.document["unit_ordinal_or_null"] != expected_unit_ordinal
        or reservation.document["unit_kind_or_null"]
        != specs[expected_unit_ordinal].unit_kind
        or reservation.document["unit_attempt_ordinal_or_null"]
        != expected_unit_attempt_ordinal
        or reservation.document["formal_matrix_sha256"]
        != followup_formal_matrix_sha256(scientific_profile)
    ):
        raise FollowupCampaignError("campaign reservation does not bind the expected unit")
    expected_binding = bind_followup_campaign_run(
        reservation,
        provider_run_id=expected_provider_run_id,
    )
    if binding.document_bytes != expected_binding.document_bytes:
        raise FollowupCampaignError("campaign run binding is not the exact next transition")
    watcher_session = armed.document["watcher_session_sha256_or_null"]
    if type(watcher_session) is not str:
        raise FollowupCampaignError("campaign watch is not armed")
    expected_armed = arm_followup_campaign_watch(
        binding,
        watcher_session_sha256=watcher_session,
    )
    if armed.document_bytes != expected_armed.document_bytes:
        raise FollowupCampaignError("campaign watch arm is not the exact next transition")
    return armed


def build_followup_campaign_selection(
    committed_states: tuple[FollowupCampaignState, ...],
    campaign_run_admission_sha256s: tuple[str, ...],
    *,
    scientific_profile: RouteAScientificProfile,
) -> FollowupCampaignSelection:
    """Close the unique final-successful attempt selected for every formal unit."""

    if (
        type(committed_states) is not tuple
        or type(campaign_run_admission_sha256s) is not tuple
        or len(committed_states) != 17
        or len(campaign_run_admission_sha256s) != 17
        or any(type(state) is not FollowupCampaignState for state in committed_states)
    ):
        raise FollowupCampaignError(
            "campaign selection requires exactly seventeen committed states"
        )
    specs = followup_formal_unit_specs(scientific_profile)
    expected_matrix = followup_formal_matrix_sha256(scientific_profile)
    first = committed_states[0]
    campaign_id = first.document["campaign_id"]
    common_fields = (
        "campaign_id",
        "compatibility_receipt_sha256",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "formal_matrix_sha256",
        "qualification_q6_artifact_digest",
        "qualification_q6_artifact_id",
        "qualification_run_id",
    )
    units: list[dict[str, object]] = []
    replacement_ordinal: int | None = None
    previous_sequence = -1
    run_ids: set[int] = set()
    artifact_ids: set[int] = set()
    artifact_names: set[str] = set()
    artifact_digests: set[str] = set()
    admissions: set[str] = set()
    for spec, state, admission_sha in zip(
        specs,
        committed_states,
        campaign_run_admission_sha256s,
        strict=True,
    ):
        _require_sha(admission_sha, field="campaign run admission")
        document = state.document
        attempt = document["unit_attempt_ordinal_or_null"]
        run_id = document["provider_run_id_or_null"]
        artifact_id = document["artifact_id_or_null"]
        artifact_name = document["artifact_name_or_null"]
        artifact_digest = document["artifact_provider_digest_or_null"]
        envelope_sha = document["unit_output_envelope_sha256_or_null"]
        if (
            state.state != "unit-committed"
            or document["unit_ordinal_or_null"] != spec.ordinal
            or document["unit_kind_or_null"] != spec.unit_kind
            or document["provider_run_attempt_or_null"] != 1
            or document["formal_matrix_sha256"] != expected_matrix
            or any(document[field] != first.document[field] for field in common_fields)
            or state.sequence <= previous_sequence
            or type(attempt) is not int
            or attempt not in {1, 2}
            or type(run_id) is not int
            or type(artifact_id) is not int
            or type(artifact_name) is not str
            or type(artifact_digest) is not str
            or type(envelope_sha) is not str
        ):
            raise FollowupCampaignError(
                "campaign selection contains a nonfinal or mismatched unit"
            )
        if attempt == 2:
            if replacement_ordinal is not None:
                raise FollowupCampaignError("campaign selection uses more than one retry")
            replacement_ordinal = spec.ordinal
        expected_retry_used = replacement_ordinal is not None
        if document["retry_used"] is not expected_retry_used:
            raise FollowupCampaignError("campaign retry state is not monotonic")
        if (
            run_id in run_ids
            or artifact_id in artifact_ids
            or artifact_name in artifact_names
            or artifact_digest in artifact_digests
            or admission_sha in admissions
        ):
            raise FollowupCampaignError(
                "campaign selection reuses a run, artifact, or admission identity"
            )
        run_ids.add(run_id)
        artifact_ids.add(artifact_id)
        artifact_names.add(artifact_name)
        artifact_digests.add(artifact_digest)
        admissions.add(admission_sha)
        units.append(
            {
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_provider_digest": artifact_digest,
                "campaign_run_admission_sha256": admission_sha,
                "committed_state_sequence": state.sequence,
                "committed_state_sha256": state.sha256,
                "formal_unit_ordinal": spec.ordinal,
                "provider_run_attempt": 1,
                "provider_run_id": run_id,
                "unit_attempt_ordinal": attempt,
                "unit_kind": spec.unit_kind,
                "unit_output_envelope_sha256": envelope_sha,
            }
        )
        previous_sequence = state.sequence
    document = {
        "authority": False,
        "campaign_id": campaign_id,
        "compatibility_receipt_sha256": first.document[
            "compatibility_receipt_sha256"
        ],
        "evidence_freeze_S2_sha": first.document["evidence_freeze_S2_sha"],
        "experiment_source_S1_sha": first.document["experiment_source_S1_sha"],
        "formal_matrix_sha256": expected_matrix,
        "formal_unit_count": 17,
        "publication_evidence_admitted": False,
        "replacement_attempt_used": replacement_ordinal is not None,
        "replacement_unit_ordinal_or_null": replacement_ordinal,
        "schema_version": _SELECTION_SCHEMA,
        "study_id": FOLLOWUP_STUDY_ID,
        "units": units,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupCampaignSelection(
        document=document,
        document_bytes=document_bytes,
        sha256=_sha256(document_bytes),
    )


def inspect_followup_campaign_selection(
    content: bytes,
    committed_state_bytes: tuple[bytes, ...],
    *,
    scientific_profile: RouteAScientificProfile,
) -> FollowupCampaignSelection:
    """Rebuild a selection from its exact committed state receipts."""

    if type(committed_state_bytes) is not tuple:
        raise FollowupCampaignError("committed state byte set is not a tuple")
    states = tuple(inspect_followup_campaign_state(value) for value in committed_state_bytes)
    value = _parse_ascii_json(content, label="follow-up campaign selection")
    if type(value) is not dict or _canonical_json_bytes(value) != content:
        raise FollowupCampaignError("campaign selection is not canonical JSON")
    units = value.get("units")
    if type(units) is not list or any(type(unit) is not dict for unit in units):
        raise FollowupCampaignError("campaign selection unit set changed")
    admissions = tuple(
        unit.get("campaign_run_admission_sha256")  # type: ignore[union-attr]
        for unit in units
    )
    if any(type(admission) is not str for admission in admissions):
        raise FollowupCampaignError("campaign selection admission digest changed")
    expected = build_followup_campaign_selection(
        states,
        admissions,  # type: ignore[arg-type]
        scientific_profile=scientific_profile,
    )
    if content != expected.document_bytes:
        raise FollowupCampaignError("campaign selection differs from committed states")
    return expected


def open_followup_campaign_state(
    *,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    compatibility_receipt_sha256: str,
    qualification_run_id: int,
    qualification_q6_artifact_id: int,
    qualification_q6_artifact_digest: str,
    scientific_profile: RouteAScientificProfile,
) -> FollowupCampaignState:
    """Create the state installed by the sole formal-capability CAS."""

    matrix_sha256 = followup_formal_matrix_sha256(scientific_profile)
    campaign_id = followup_formal_campaign_id(
        experiment_source_s1_sha=experiment_source_s1_sha,
        evidence_freeze_s2_sha=evidence_freeze_s2_sha,
        compatibility_receipt_sha256=compatibility_receipt_sha256,
        qualification_run_id=qualification_run_id,
        qualification_q6_artifact_id=qualification_q6_artifact_id,
        qualification_q6_artifact_digest=qualification_q6_artifact_digest,
        formal_matrix_sha256=matrix_sha256,
    )
    return _new_state(
        {
            "artifact_id_or_null": None,
            "artifact_name_or_null": None,
            "artifact_provider_digest_or_null": None,
            "authority": False,
            "campaign_id": campaign_id,
            "compatibility_receipt_sha256": compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
            "experiment_source_S1_sha": experiment_source_s1_sha,
            "formal_matrix_sha256": matrix_sha256,
            "provider_failure_class_or_null": None,
            "provider_failure_evidence_sha256_or_null": None,
            "provider_run_attempt_or_null": None,
            "provider_run_id_or_null": None,
            "publication_evidence_admitted": False,
            "qualification_q6_artifact_digest": qualification_q6_artifact_digest,
            "qualification_q6_artifact_id": qualification_q6_artifact_id,
            "qualification_run_id": qualification_run_id,
            "retry_used": False,
            "schema_version": _SCHEMA,
            "scientific_plan_sha256": FOLLOWUP_BASELINE_SHA256,
            "sequence": 0,
            "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
            "state": "campaign-open",
            "study_id": FOLLOWUP_STUDY_ID,
            "terminal_reason_code_or_null": None,
            "unit_attempt_ordinal_or_null": None,
            "unit_kind_or_null": None,
            "unit_ordinal_or_null": None,
            "unit_output_envelope_sha256_or_null": None,
            "watcher_receipt_sha256_or_null": None,
            "watcher_session_sha256_or_null": None,
        }
    )


def reserve_followup_campaign_unit(
    previous: FollowupCampaignState,
    spec: FollowupFormalUnitSpec,
    *,
    unit_attempt_ordinal: int,
) -> FollowupCampaignState:
    """Reserve the next nominal unit or the sole eligible replacement."""

    if type(previous) is not FollowupCampaignState or type(spec) is not FollowupFormalUnitSpec:
        raise TypeError("campaign reservation requires exact state and unit spec")
    if unit_attempt_ordinal == 1:
        if previous.state == "campaign-open":
            expected_ordinal = 0
        elif previous.state == "unit-committed":
            prior = previous.document["unit_ordinal_or_null"]
            assert type(prior) is int
            expected_ordinal = prior + 1
        else:
            raise FollowupCampaignError("nominal unit cannot follow this campaign state")
        if previous.document["retry_used"] is not False and previous.state == "campaign-open":
            raise FollowupCampaignError("campaign opened with a consumed retry")
        if spec.ordinal != expected_ordinal or spec.ordinal >= 17:
            raise FollowupCampaignError("nominal unit order changed")
        retry_used = previous.document["retry_used"]
    elif unit_attempt_ordinal == 2:
        if (
            previous.state != "unit-provider-failed"
            or previous.document["retry_used"] is not False
            or previous.document["unit_ordinal_or_null"] != spec.ordinal
        ):
            raise FollowupCampaignError("replacement lacks one eligible failed predecessor")
        retry_used = True
    else:
        raise FollowupCampaignError("outer unit attempt is outside 1..2")
    return _new_state(
        previous.document,
        artifact_id_or_null=None,
        artifact_name_or_null=None,
        artifact_provider_digest_or_null=None,
        provider_failure_class_or_null=None,
        provider_failure_evidence_sha256_or_null=None,
        provider_run_attempt_or_null=None,
        provider_run_id_or_null=None,
        retry_used=retry_used,
        sequence=previous.sequence + 1,
        state="unit-reserved",
        terminal_reason_code_or_null=None,
        unit_attempt_ordinal_or_null=unit_attempt_ordinal,
        unit_kind_or_null=spec.unit_kind,
        unit_ordinal_or_null=spec.ordinal,
        unit_output_envelope_sha256_or_null=None,
        watcher_receipt_sha256_or_null=None,
        watcher_session_sha256_or_null=None,
    )


def bind_followup_campaign_run(
    previous: FollowupCampaignState,
    *,
    provider_run_id: int,
) -> FollowupCampaignState:
    """Bind the exact provider run returned by the one allowed dispatch POST."""

    if type(previous) is not FollowupCampaignState or previous.state != "unit-reserved":
        raise FollowupCampaignError("run binding does not follow a reservation")
    _require_positive(provider_run_id, field="provider run ID")
    return _new_state(
        previous.document,
        provider_run_attempt_or_null=1,
        provider_run_id_or_null=provider_run_id,
        sequence=previous.sequence + 1,
        state="run-bound",
    )


def arm_followup_campaign_watch(
    previous: FollowupCampaignState,
    *,
    watcher_session_sha256: str,
) -> FollowupCampaignState:
    """Make seed execution possible only after the mandatory watcher exists."""

    if type(previous) is not FollowupCampaignState or previous.state != "run-bound":
        raise FollowupCampaignError("watch arm does not follow one exact run binding")
    _require_sha(watcher_session_sha256, field="watcher session")
    return _new_state(
        previous.document,
        sequence=previous.sequence + 1,
        state="watch-armed",
        watcher_session_sha256_or_null=watcher_session_sha256,
    )


def commit_followup_campaign_unit(
    previous: FollowupCampaignState,
    *,
    watcher_receipt_sha256: str,
    artifact_id: int,
    artifact_name: str,
    artifact_provider_digest: str,
    unit_output_envelope_sha256: str,
) -> FollowupCampaignState:
    """Commit one terminally successful, guarded, independently watched unit."""

    if type(previous) is not FollowupCampaignState or previous.state != "watch-armed":
        raise FollowupCampaignError("unit commit does not follow one armed watcher")
    _require_sha(watcher_receipt_sha256, field="watcher receipt")
    _require_positive(artifact_id, field="artifact ID")
    if type(artifact_name) is not str or not artifact_name.startswith(
        "followup-performance-v1-"
    ):
        raise FollowupCampaignError("artifact name is outside the follow-up namespace")
    if (
        type(artifact_provider_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(artifact_provider_digest) is None
    ):
        raise FollowupCampaignError("artifact digest is not a provider SHA-256")
    _require_sha(unit_output_envelope_sha256, field="unit output envelope")
    return _new_state(
        previous.document,
        artifact_id_or_null=artifact_id,
        artifact_name_or_null=artifact_name,
        artifact_provider_digest_or_null=artifact_provider_digest,
        sequence=previous.sequence + 1,
        state="unit-committed",
        unit_output_envelope_sha256_or_null=unit_output_envelope_sha256,
        watcher_receipt_sha256_or_null=watcher_receipt_sha256,
    )


def record_followup_provider_failure(
    previous: FollowupCampaignState,
    *,
    provider_failure_class: str,
    provider_failure_evidence_sha256: str,
    watcher_receipt_sha256: str,
) -> FollowupCampaignState:
    """Record the only failure class that may lead to one replacement."""

    if type(previous) is not FollowupCampaignState or previous.state != "watch-armed":
        raise FollowupCampaignError("provider failure does not follow one armed watcher")
    if provider_failure_class not in FOLLOWUP_PROVIDER_FAILURE_CLASSES:
        raise FollowupCampaignError("provider failure is not replacement-eligible")
    _require_sha(provider_failure_evidence_sha256, field="provider failure evidence")
    _require_sha(watcher_receipt_sha256, field="watcher receipt")
    if previous.document["retry_used"] is not False:
        raise FollowupCampaignError("the sole provider retry was already consumed")
    return _new_state(
        previous.document,
        provider_failure_class_or_null=provider_failure_class,
        provider_failure_evidence_sha256_or_null=provider_failure_evidence_sha256,
        sequence=previous.sequence + 1,
        state="unit-provider-failed",
        watcher_receipt_sha256_or_null=watcher_receipt_sha256,
    )


def close_followup_campaign_no_go(
    previous: FollowupCampaignState,
    *,
    terminal_reason_code: str,
) -> FollowupCampaignState:
    """Close the campaign irreversibly without admitting publication evidence."""

    if type(previous) is not FollowupCampaignState or previous.state in {
        "campaign-no-go",
    }:
        raise FollowupCampaignError("campaign cannot close twice")
    if terminal_reason_code not in _NO_GO_REASONS:
        raise FollowupCampaignError("campaign NO-GO reason is outside its closed domain")
    return _new_state(
        previous.document,
        sequence=previous.sequence + 1,
        state="campaign-no-go",
        terminal_reason_code_or_null=terminal_reason_code,
    )
