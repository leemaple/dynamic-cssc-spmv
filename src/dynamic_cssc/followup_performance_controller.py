"""Live, fail-closed authority controller for the follow-up performance study.

Provider artifacts remain authority-false.  The only positive authority values
created here are two opaque, short-lived, single-use in-process capabilities:
one can dispatch the sole qualification and the other can open the sole formal
campaign.  Neither capability can be serialized or claimed independently of
the provider mutation it authorizes.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
import threading
import time
import weakref
import zipfile
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from dynamic_cssc.followup_performance_artifacts import (
    expected_followup_qualification_artifact_name,
    inspect_followup_qualification_artifact,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_BASELINE_SHA256,
    FOLLOWUP_STAGE1_PLAN_SHA256,
    FOLLOWUP_STUDY_ID,
    FollowupScientificPlan,
    inspect_followup_stage1,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_control_artifacts import (
    FollowupControlKind,
    inspect_followup_control_artifact,
)
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
    followup_formal_unit_specs,
)
from dynamic_cssc.followup_performance_lineage import (
    inspect_followup_registration_archive,
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.followup_performance_qualification_binding import (
    inspect_followup_qualification_watch_binding,
)
from dynamic_cssc.route_a_controller import (
    RouteALiveJobSnapshot,
    RouteALiveQualificationObservation,
    RouteALiveRunSnapshot,
    RouteAQualificationRequest,
    RouteAQualificationWatchResult,
    watch_route_a_qualification,
)
from dynamic_cssc.route_a_postrun_admission import (
    RouteAPostrunAdmissionInspection,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupArtifactSnapshot",
    "FollowupControlObservation",
    "FollowupControllerError",
    "FollowupDispatchPrerequisites",
    "FollowupFormalAdmissionRequest",
    "FollowupFormalCampaignOpening",
    "FollowupFormalDispatchCapability",
    "FollowupFormalLiveJobSnapshot",
    "FollowupFormalLiveObservation",
    "FollowupFormalLiveProvider",
    "FollowupFormalLiveRunSnapshot",
    "FollowupFormalWatchResult",
    "FollowupJobSnapshot",
    "FollowupPrerequisiteObservation",
    "FollowupProviderAuthoritySnapshot",
    "FollowupPrerequisiteProvider",
    "FollowupQualificationDispatchCapability",
    "FollowupQualificationOpening",
    "FollowupQualificationObservation",
    "FollowupQualificationProvider",
    "FollowupQualificationWatchResult",
    "FollowupRunSnapshot",
    "abandon_followup_formal_capability",
    "abandon_followup_qualification_capability",
    "authorize_followup_formal_campaign",
    "authorize_followup_qualification_dispatch",
    "consume_followup_qualification_capability",
    "consume_followup_formal_campaign_capability",
    "watch_followup_formal_campaign",
    "watch_followup_qualification",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_OBSERVATION_AGE = timedelta(seconds=30)
_COMPUTATIONAL_LIMIT = timedelta(minutes=45)
_Q6_JOB_LIMIT = timedelta(minutes=5)
_Q6_WALL_LIMIT = timedelta(minutes=10)
_TOTAL_PATH_LIMIT = timedelta(minutes=55)
_NATIVE_SCREEN_SECONDS = 9_000
_MAX_CONTROL_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_Q6_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_EXTRACTED_FILES = 64
_MAX_EXTRACTED_BYTES = 32 * 1024 * 1024
_FORMAL_TERMINAL_JOB = "formal-terminal-admission"
_FORMAL_AGGREGATE_JOB = "formal-aggregate"
_FORMAL_LAUNCH_JOB = "formal-launch-admission"
_FORMAL_TERMINAL_LIMIT = timedelta(minutes=30)
_PROVIDER_AUTHORITY_REFS = {
    "qualification": (
        "refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1"
    ),
    "formal": "refs/tags/dynamic-cssc-followup-performance-formal-authority-v1",
}

_QUALIFICATION_WORKFLOW = ".github/workflows/followup-performance-qualification.yml"
_FORMAL_WORKFLOW = ".github/workflows/followup-performance-formal.yml"
_QUALIFICATION_JOB_NAMES = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)

_CONTROL_ORDER: tuple[FollowupControlKind | Literal["registration"], ...] = (
    "ci",
    "pre-s1",
    "registration",
    "source-anchor",
    "independent-review",
)
_CONTROL_RUN_FIELDS = {
    "ci": "ci_run_id",
    "pre-s1": "pre_s1_run_id",
    "registration": "registration_run_id",
    "source-anchor": "source_anchor_run_id",
    "independent-review": "independent_review_run_id",
}
_CONTROL_WORKFLOWS = {
    "ci": ".github/workflows/followup-performance-ci.yml",
    "pre-s1": ".github/workflows/followup-performance-pre-s1.yml",
    "registration": ".github/workflows/followup-performance-registration.yml",
    "source-anchor": ".github/workflows/followup-performance-source-anchor.yml",
    "independent-review": ".github/workflows/followup-performance-independent-review.yml",
}
_CONTROL_JOBS = {
    "ci": "exact-head-linux-ci",
    "pre-s1": "pre-s1-resource-validation",
    "registration": "Produce and independently reinspect follow-up registration",
    "source-anchor": "source-anchor",
    "independent-review": "independent-review",
}
_CONTROL_DETAILS: dict[FollowupControlKind, dict[str, str]] = {
    "ci": {
        "full_test_suite": "success",
        "python_compile": "success",
        "ruff_and_diff_check": "success",
    },
    "pre-s1": {
        "followup_contract_tests": "success",
        "openfhe_ordinary_and_strong_smokes": "success",
        "pinned_openfhe_build": "success",
        "publication_authority": "absent",
    },
    "source-anchor": {
        "anchor_transition": "single-direct-child",
        "behavior_sets": "byte-identical",
        "changed_path": "config/followup-performance-registration-anchors.json",
        "qualification_authority": "absent",
    },
    "independent-review": {
        "bounded_implementation_diff": "pass",
        "publication_authority": "absent",
        "unresolved_p0_or_p1": "zero",
    },
}


class FollowupControllerError(RuntimeError):
    """One local, provider, artifact, timing, or authority check failed closed."""


@dataclass(frozen=True, slots=True)
class FollowupRunSnapshot:
    database_id: int
    workflow_path: str
    event: str
    head_sha: str
    head_branch: str
    attempt: int
    status: str
    conclusion: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class FollowupJobSnapshot:
    database_id: int
    name: str
    started_at: datetime
    completed_at: datetime
    status: str
    conclusion: str


@dataclass(frozen=True, slots=True)
class FollowupArtifactSnapshot:
    database_id: int
    name: str
    digest: str
    size_in_bytes: int
    expired: bool
    workflow_run_id: int
    workflow_run_head_sha: str


@dataclass(frozen=True, slots=True)
class FollowupProviderAuthoritySnapshot:
    ref_name: str
    target_oid: str
    commit_message: str
    tree_oid: str
    claim_tree_oid: str
    parent_oids: tuple[str, ...]


FollowupObservedControlKind = FollowupControlKind | Literal["registration"]


@dataclass(frozen=True, slots=True)
class FollowupControlObservation:
    kind: FollowupObservedControlKind
    run: FollowupRunSnapshot
    jobs: tuple[FollowupJobSnapshot, ...]
    artifact: FollowupArtifactSnapshot
    provider_archive_bytes: bytes


@dataclass(frozen=True, slots=True)
class FollowupPrerequisiteObservation:
    observed_at: datetime
    controls: tuple[FollowupControlObservation, ...]
    qualification_run_ids: tuple[int, ...]
    formal_run_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class FollowupQualificationObservation:
    observed_at: datetime
    run: FollowupRunSnapshot
    jobs: tuple[FollowupJobSnapshot, ...]
    artifacts: tuple[FollowupArtifactSnapshot, ...]
    q6_provider_archive_bytes: bytes
    authority_binding: FollowupProviderAuthoritySnapshot


@dataclass(frozen=True, slots=True)
class FollowupQualificationWatchResult:
    """Follow-up namespace wrapper around the unchanged stop-loss decision."""

    inherited: RouteAQualificationWatchResult
    qualification_decision: Literal[
        "qualification-go",
        "qualification-no-go",
        "q5-prefix-only",
    ] = "q5-prefix-only"
    q6_started_at: datetime | None = None
    q6_completed_at: datetime | None = None
    total_threshold_at: datetime | None = None
    q6_wall_threshold_at: datetime | None = None
    q6_controller_observed_at: datetime | None = None
    q6_cancellation_requested_at: datetime | None = None
    q6_cancellation_acknowledged_at: datetime | None = None
    q6_provider_terminal_updated_at: datetime | None = None
    q6_provider_terminal_conclusion: str | None = None
    q6_watch_decided_at: datetime | None = None
    q6_cancellation_error: str | None = None
    final_reason: str | None = None

    @property
    def document(self) -> dict[str, object]:
        inner = self.inherited.document
        inner_bytes = (
            json.dumps(
                inner,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        return {
            "authority": False,
            "final_reason_or_null": self.final_reason,
            "formal_execution_authorized": False,
            "inherited_stop_loss_record": inner,
            "inherited_stop_loss_record_sha256": hashlib.sha256(inner_bytes).hexdigest(),
            "q6_cancellation_acknowledged_at_or_null": (
                None
                if self.q6_cancellation_acknowledged_at is None
                else _render_time(self.q6_cancellation_acknowledged_at)
            ),
            "q6_cancellation_error_or_null": self.q6_cancellation_error,
            "q6_cancellation_requested_at_or_null": (
                None
                if self.q6_cancellation_requested_at is None
                else _render_time(self.q6_cancellation_requested_at)
            ),
            "q6_completed_at_or_null": (
                None
                if self.q6_completed_at is None
                else _render_time(self.q6_completed_at)
            ),
            "q6_controller_observed_at_or_null": (
                None
                if self.q6_controller_observed_at is None
                else _render_time(self.q6_controller_observed_at)
            ),
            "q6_provider_terminal_conclusion_or_null": (
                self.q6_provider_terminal_conclusion
            ),
            "q6_provider_terminal_updated_at_or_null": (
                None
                if self.q6_provider_terminal_updated_at is None
                else _render_time(self.q6_provider_terminal_updated_at)
            ),
            "q6_started_at_or_null": (
                None
                if self.q6_started_at is None
                else _render_time(self.q6_started_at)
            ),
            "q6_wall_threshold_at_or_null": (
                None
                if self.q6_wall_threshold_at is None
                else _render_time(self.q6_wall_threshold_at)
            ),
            "q6_watch_decided_at_or_null": (
                None
                if self.q6_watch_decided_at is None
                else _render_time(self.q6_watch_decided_at)
            ),
            "qualification_decision": self.qualification_decision,
            "schema_version": "dynamic-cssc-followup-performance-live-stop-loss-v2",
            "study_id": FOLLOWUP_STUDY_ID,
            "total_threshold_at_or_null": (
                None
                if self.total_threshold_at is None
                else _render_time(self.total_threshold_at)
            ),
        }


@dataclass(frozen=True, slots=True)
class FollowupFormalLiveRunSnapshot:
    database_id: int
    workflow_path: str
    event: str
    head_sha: str
    head_branch: str
    attempt: int
    status: str
    conclusion: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class FollowupFormalLiveJobSnapshot:
    database_id: int
    name: str
    started_at: datetime | None
    completed_at: datetime | None
    status: str
    conclusion: str | None


@dataclass(frozen=True, slots=True)
class FollowupFormalLiveObservation:
    observed_at: datetime
    provider_observed_at: datetime
    run: FollowupFormalLiveRunSnapshot
    jobs: tuple[FollowupFormalLiveJobSnapshot, ...]
    authority_binding: FollowupProviderAuthoritySnapshot


@dataclass(frozen=True, slots=True)
class FollowupFormalWatchResult:
    document: dict[str, object]


@dataclass(frozen=True, slots=True)
class FollowupDispatchPrerequisites:
    expected_s1_git_sha: str
    expected_s2_git_sha: str
    expected_compatibility_receipt_sha256: str
    ci_run_id: int
    pre_s1_run_id: int
    registration_run_id: int
    source_anchor_run_id: int
    independent_review_run_id: int


@dataclass(frozen=True, slots=True)
class FollowupFormalAdmissionRequest:
    prerequisites: FollowupDispatchPrerequisites
    qualification_run_id: int


@dataclass(frozen=True, slots=True)
class FollowupFormalCampaignOpening:
    """Authority-false inputs left after the live capability is consumed."""

    experiment_source_s1_sha: str
    evidence_freeze_s2_sha: str
    compatibility_receipt_sha256: str
    qualification_run_id: int
    qualification_q6_artifact_id: int
    qualification_q6_artifact_digest: str


@dataclass(frozen=True, slots=True)
class FollowupQualificationOpening:
    """Authority-false inputs left after qualification authority is consumed."""

    experiment_source_s1_sha: str
    evidence_freeze_s2_sha: str
    compatibility_receipt_sha256: str


class FollowupPrerequisiteProvider(Protocol):
    def read_prerequisites(
        self,
        run_ids: tuple[int, ...],
    ) -> FollowupPrerequisiteObservation: ...


class FollowupQualificationProvider(Protocol):
    def read_qualification(
        self,
        run_id: int,
    ) -> FollowupQualificationObservation: ...


class FollowupFormalLiveProvider(Protocol):
    def read_live_formal(self, run_id: int) -> FollowupFormalLiveObservation: ...

    def cancel_formal(self, run_id: int) -> None: ...


@dataclass(frozen=True, slots=True)
class _FrozenPrerequisites:
    expected_s1_git_sha: str
    expected_s2_git_sha: str
    expected_compatibility_receipt_sha256: str
    control_run_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _LocalAuthority:
    scientific: FollowupScientificPlan
    compatibility_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _CapabilityBinding:
    kind: Literal["qualification", "formal"]
    prerequisites: _FrozenPrerequisites
    qualification_run_id: int | None
    scientific_plan_sha256: str
    controller_observed_at: datetime
    expires_at: datetime
    q6_artifact_id: int | None
    q6_artifact_digest: str | None


class _CapabilityToken:
    __slots__ = ()


class FollowupQualificationDispatchCapability:
    """Opaque one-shot authority for only the sole qualification dispatch."""

    __slots__ = ("_binding_token", "_lock", "__weakref__")

    def __new__(cls) -> FollowupQualificationDispatchCapability:
        raise TypeError("follow-up qualification capabilities are controller-minted")

    def __bool__(self) -> bool:
        raise TypeError("follow-up qualification capability is not a Boolean")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("follow-up qualification capability cannot be serialized")


class FollowupFormalDispatchCapability:
    """Opaque one-shot authority for only the sole formal campaign."""

    __slots__ = ("_binding_token", "_lock", "__weakref__")

    def __new__(cls) -> FollowupFormalDispatchCapability:
        raise TypeError("follow-up formal capabilities are controller-minted")

    def __bool__(self) -> bool:
        raise TypeError("follow-up formal capability is not a Boolean")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("follow-up formal capability cannot be serialized")


@dataclass(frozen=True, slots=True)
class _IssuedCapability:
    capability_ref: weakref.ReferenceType[object]
    binding_token: _CapabilityToken
    binding: _CapabilityBinding


_ISSUED_CAPABILITIES: dict[int, _IssuedCapability] = {}
_ISSUED_CAPABILITIES_LOCK = threading.Lock()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_utc(value: datetime, field: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None:
        raise FollowupControllerError(f"{field} is not one timezone-aware datetime")
    normalized = value.astimezone(UTC)
    if normalized.utcoffset() != timedelta(0):  # pragma: no cover - UTC invariant
        raise FollowupControllerError(f"{field} did not normalize to UTC")
    return normalized


def _seconds(value: timedelta, field: str) -> int:
    seconds = value.total_seconds()
    if seconds < 0 or not seconds.is_integer():
        raise FollowupControllerError(f"{field} is not a nonnegative whole-second duration")
    return int(seconds)


def _render_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _validate_provider_authority_binding(
    snapshot: FollowupProviderAuthoritySnapshot,
    *,
    kind: Literal["qualification", "formal"],
    expected_s1: str,
    expected_s2: str,
    expected_compatibility: str,
    expected_run_id: int,
    expected_qualification_run_id: int | None,
) -> None:
    """Close the provider CAS witness independently of the workflow that wrote it."""

    if (
        type(snapshot) is not FollowupProviderAuthoritySnapshot
        or snapshot.ref_name != _PROVIDER_AUTHORITY_REFS[kind]
        or _LOWER_GIT_SHA.fullmatch(snapshot.target_oid) is None
        or _LOWER_GIT_SHA.fullmatch(snapshot.tree_oid) is None
        or _LOWER_GIT_SHA.fullmatch(snapshot.claim_tree_oid) is None
        or snapshot.tree_oid != snapshot.claim_tree_oid
        or snapshot.parent_oids != (expected_s2,)
        or type(snapshot.commit_message) is not str
    ):
        raise FollowupControllerError("provider authority binding topology changed")
    if kind == "qualification":
        try:
            watched = inspect_followup_qualification_watch_binding(
                snapshot.commit_message.encode("ascii")
            )
        except (UnicodeEncodeError, ValueError) as error:
            raise FollowupControllerError(
                "provider qualification watch binding changed"
            ) from error
        document = watched.document
        if (
            document["experiment_source_S1_sha"] != expected_s1
            or document["evidence_freeze_S2_sha"] != expected_s2
            or document["claim_oid"] != expected_s2
            or document["compatibility_receipt_sha256"] != expected_compatibility
            or document["provider_run_id"] != expected_run_id
            or not str(document["workflow_ref"]).endswith(
                f"/{_QUALIFICATION_WORKFLOW}@refs/heads/main"
            )
        ):
            raise FollowupControllerError(
                "provider qualification watch binding content changed"
            )
        return
    try:
        document = json.loads(snapshot.commit_message)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise FollowupControllerError("provider authority binding is not JSON") from error
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    workflow = _QUALIFICATION_WORKFLOW if kind == "qualification" else _FORMAL_WORKFLOW
    expected = {
        "authority": False,
        "authority_kind": kind,
        "claim_oid": expected_s2,
        "compatibility_receipt_sha256": expected_compatibility,
        "evidence_freeze_S2_sha": expected_s2,
        "expected_qualification_run_id_or_null": expected_qualification_run_id,
        "experiment_source_S1_sha": expected_s1,
        "provider_run_attempt": 1,
        "provider_run_id": expected_run_id,
        "schema_version": (
            "dynamic-cssc-followup-performance-provider-run-binding-v1"
        ),
        "study_id": FOLLOWUP_STUDY_ID,
    }
    if (
        canonical != snapshot.commit_message
        or type(document) is not dict
        or set(document) != {*expected, "workflow_ref"}
        or any(document.get(field) != value for field, value in expected.items())
        or type(document.get("workflow_ref")) is not str
        or not document["workflow_ref"].endswith(f"/{workflow}@refs/heads/main")
    ):
        raise FollowupControllerError("provider authority binding content changed")


def _freeze_prerequisites(
    request: FollowupDispatchPrerequisites,
) -> _FrozenPrerequisites:
    if type(request) is not FollowupDispatchPrerequisites:
        raise TypeError("request must be an exact FollowupDispatchPrerequisites")
    values = tuple(
        getattr(request, _CONTROL_RUN_FIELDS[kind]) for kind in _CONTROL_ORDER
    )
    if (
        type(request.expected_s1_git_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(request.expected_s1_git_sha) is None
        or type(request.expected_s2_git_sha) is not str
        or _LOWER_GIT_SHA.fullmatch(request.expected_s2_git_sha) is None
        or request.expected_s1_git_sha == request.expected_s2_git_sha
        or type(request.expected_compatibility_receipt_sha256) is not str
        or _LOWER_SHA256.fullmatch(request.expected_compatibility_receipt_sha256) is None
        or any(type(run_id) is not int or run_id <= 0 for run_id in values)
        or len(set(values)) != len(values)
    ):
        raise FollowupControllerError("follow-up prerequisite identity is invalid")
    return _FrozenPrerequisites(
        expected_s1_git_sha=request.expected_s1_git_sha,
        expected_s2_git_sha=request.expected_s2_git_sha,
        expected_compatibility_receipt_sha256=(
            request.expected_compatibility_receipt_sha256
        ),
        control_run_ids=values,
    )


def _inspect_local_authority(
    repository_root: Path,
    request: _FrozenPrerequisites,
) -> _LocalAuthority:
    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be a pathlib.Path")
    root = repository_root.resolve(strict=True)
    stage1 = inspect_followup_stage1(root)
    if stage1.stage1_plan_sha256 != FOLLOWUP_STAGE1_PLAN_SHA256:
        raise FollowupControllerError("follow-up Stage-1 plan identity changed")
    scientific = materialize_followup_scientific_plan(root)
    if scientific.machine_plan_sha256 != FOLLOWUP_BASELINE_SHA256:
        raise FollowupControllerError("follow-up materialized scientific plan changed")
    compatibility = verify_followup_s1_s2_compatibility(
        root,
        s1=request.expected_s1_git_sha,
        s2=request.expected_s2_git_sha,
    )
    if compatibility.sha256 != request.expected_compatibility_receipt_sha256:
        raise FollowupControllerError("follow-up compatibility receipt digest changed")
    return _LocalAuthority(
        scientific=scientific,
        compatibility_receipt_sha256=compatibility.sha256,
    )


def _validate_fresh_observation(observed_at: datetime, controller_now: datetime) -> None:
    observed_at = _require_utc(observed_at, "provider observation")
    age = controller_now - observed_at
    if age < timedelta(0) or age > _MAX_OBSERVATION_AGE:
        raise FollowupControllerError("follow-up provider observation is stale")


def _validate_run(
    run: FollowupRunSnapshot,
    *,
    expected_run_id: int,
    expected_workflow: str,
    expected_s2: str,
) -> None:
    if type(run) is not FollowupRunSnapshot:
        raise FollowupControllerError("provider run snapshot type changed")
    created_at = _require_utc(run.created_at, "provider run createdAt")
    updated_at = _require_utc(run.updated_at, "provider run updatedAt")
    if (
        type(run.database_id) is not int
        or run.database_id != expected_run_id
        or type(run.workflow_path) is not str
        or run.workflow_path != expected_workflow
        or type(run.event) is not str
        or run.event != "workflow_dispatch"
        or type(run.head_sha) is not str
        or run.head_sha != expected_s2
        or type(run.head_branch) is not str
        or run.head_branch != "main"
        or type(run.attempt) is not int
        or run.attempt != 1
        or type(run.status) is not str
        or run.status != "completed"
        or type(run.conclusion) is not str
        or run.conclusion != "success"
        or created_at > updated_at
    ):
        raise FollowupControllerError("provider run is not the exact terminal success")


def _validate_job_set(
    jobs: tuple[FollowupJobSnapshot, ...],
    *,
    expected_names: tuple[str, ...],
) -> tuple[FollowupJobSnapshot, ...]:
    if (
        type(jobs) is not tuple
        or any(type(job) is not FollowupJobSnapshot for job in jobs)
        or tuple(job.name for job in jobs) != expected_names
    ):
        raise FollowupControllerError("provider job set is missing, extra, or reordered")
    identifiers: set[int] = set()
    previous_completed: datetime | None = None
    for job in jobs:
        started_at = _require_utc(job.started_at, f"{job.name} startedAt")
        completed_at = _require_utc(job.completed_at, f"{job.name} completedAt")
        if (
            type(job.database_id) is not int
            or job.database_id <= 0
            or job.database_id in identifiers
            or type(job.status) is not str
            or job.status != "completed"
            or type(job.conclusion) is not str
            or job.conclusion != "success"
            or completed_at < started_at
            or (previous_completed is not None and started_at < previous_completed)
        ):
            raise FollowupControllerError("provider jobs are not exact serial successes")
        identifiers.add(job.database_id)
        previous_completed = completed_at
    return jobs


def _validate_provider_artifact(
    artifact: FollowupArtifactSnapshot,
    archive_bytes: bytes,
    *,
    expected_run_id: int,
    expected_head_sha: str,
    maximum_bytes: int,
) -> None:
    if (
        type(artifact) is not FollowupArtifactSnapshot
        or type(artifact.database_id) is not int
        or artifact.database_id <= 0
        or type(artifact.name) is not str
        or not artifact.name
        or type(artifact.digest) is not str
        or _PROVIDER_DIGEST.fullmatch(artifact.digest) is None
        or type(artifact.size_in_bytes) is not int
        or artifact.size_in_bytes <= 0
        or artifact.expired is not False
        or artifact.workflow_run_id != expected_run_id
        or artifact.workflow_run_head_sha != expected_head_sha
        or type(archive_bytes) is not bytes
        or not archive_bytes
        or len(archive_bytes) > maximum_bytes
        or artifact.size_in_bytes != len(archive_bytes)
        or artifact.digest != "sha256:" + hashlib.sha256(archive_bytes).hexdigest()
    ):
        raise FollowupControllerError("provider artifact identity, digest, or bytes changed")


@contextmanager
def _extracted_provider_archive(
    archive_bytes: bytes,
    *,
    maximum_bytes: int,
):
    if type(archive_bytes) is not bytes or not 0 < len(archive_bytes) <= maximum_bytes:
        raise FollowupControllerError("provider archive violates its retained-byte bound")
    with tempfile.TemporaryDirectory(prefix="followup-provider-") as temporary_name:
        root = Path(temporary_name)
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                members = archive.infolist()
                if (
                    archive.comment
                    or not members
                    or len(members) > _MAX_EXTRACTED_FILES
                    or len({member.filename for member in members}) != len(members)
                ):
                    raise FollowupControllerError("provider archive member set is invalid")
                total = 0
                for member in members:
                    name = member.filename
                    pure = PurePosixPath(name)
                    mode = member.external_attr >> 16
                    if (
                        not name
                        or "\\" in name
                        or pure.is_absolute()
                        or any(part in {"", ".", ".."} for part in pure.parts)
                        or member.flag_bits & 0x1
                        or member.compress_type
                        not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or (member.is_dir() and stat.S_IFMT(mode) not in {0, stat.S_IFDIR})
                        or (
                            not member.is_dir()
                            and stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        )
                    ):
                        raise FollowupControllerError("provider archive member is unsafe")
                    target = root.joinpath(*pure.parts)
                    if member.is_dir():
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    if member.file_size <= 0:
                        raise FollowupControllerError("provider archive contains an empty file")
                    total += member.file_size
                    if total > _MAX_EXTRACTED_BYTES:
                        raise FollowupControllerError("provider archive expands beyond its bound")
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    descriptor = os.open(
                        target,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0),
                        0o400,
                    )
                    try:
                        written = 0
                        with archive.open(member, "r") as source:
                            while block := source.read(1024 * 1024):
                                written += len(block)
                                if written > member.file_size:
                                    raise FollowupControllerError(
                                        "provider archive member exceeded its declared size"
                                    )
                                view = memoryview(block)
                                while view:
                                    count = os.write(descriptor, view)
                                    if count <= 0:  # pragma: no cover - os.write advances or raises
                                        raise FollowupControllerError(
                                            "provider archive extraction stalled"
                                        )
                                    view = view[count:]
                        if written != member.file_size:
                            raise FollowupControllerError(
                                "provider archive member was truncated"
                            )
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            if isinstance(error, FollowupControllerError):
                raise
            raise FollowupControllerError("provider archive is not a readable ZIP") from error
        yield root


def _expected_control_run_id(
    request: _FrozenPrerequisites,
    kind: FollowupObservedControlKind,
) -> int:
    return request.control_run_ids[_CONTROL_ORDER.index(kind)]


def _inspect_control_observation(
    repository_root: Path,
    observation: FollowupControlObservation,
    request: _FrozenPrerequisites,
) -> None:
    if (
        type(observation) is not FollowupControlObservation
        or observation.kind not in _CONTROL_ORDER
    ):
        raise FollowupControllerError("control observation kind changed")
    kind = observation.kind
    expected_run_id = _expected_control_run_id(request, kind)
    _validate_run(
        observation.run,
        expected_run_id=expected_run_id,
        expected_workflow=_CONTROL_WORKFLOWS[kind],
        expected_s2=request.expected_s2_git_sha,
    )
    jobs = _validate_job_set(
        observation.jobs,
        expected_names=(_CONTROL_JOBS[kind],),
    )
    if (
        observation.run.created_at > jobs[0].started_at
        or observation.run.updated_at < jobs[0].completed_at
    ):
        raise FollowupControllerError("control run timestamps do not contain its job")
    _validate_provider_artifact(
        observation.artifact,
        observation.provider_archive_bytes,
        expected_run_id=expected_run_id,
        expected_head_sha=request.expected_s2_git_sha,
        maximum_bytes=_MAX_CONTROL_ARCHIVE_BYTES,
    )
    with _extracted_provider_archive(
        observation.provider_archive_bytes,
        maximum_bytes=_MAX_CONTROL_ARCHIVE_BYTES,
    ) as root:
        if kind == "registration":
            members = tuple(path for path in root.rglob("*") if path.is_file())
            if len(members) != 1 or members[0].relative_to(root).as_posix() != (
                "followup-registration.zip"
            ):
                raise FollowupControllerError("registration provider wrapper changed")
            archive_bytes = members[0].read_bytes()
            inspection = inspect_followup_registration_archive(
                repository_root,
                s1=request.expected_s1_git_sha,
                s2=request.expected_s2_git_sha,
                archive_bytes=archive_bytes,
            )
            if (
                observation.artifact.name != inspection.artifact_name
                or inspection.compatibility_receipt_sha256
                != request.expected_compatibility_receipt_sha256
            ):
                raise FollowupControllerError("registration identity changed")
            return
        inspection = inspect_followup_control_artifact(root, expected_kind=kind)
        receipt = inspection.receipt
        if (
            observation.artifact.name != inspection.artifact_name
            or receipt.get("experiment_source_S1_sha") != request.expected_s1_git_sha
            or receipt.get("evidence_freeze_S2_sha") != request.expected_s2_git_sha
            or receipt.get("compatibility_receipt_sha256")
            != request.expected_compatibility_receipt_sha256
            or receipt.get("provider_run_id") != expected_run_id
            or receipt.get("provider_run_attempt") != 1
            or receipt.get("details") != _CONTROL_DETAILS[kind]
        ):
            raise FollowupControllerError("control receipt differs from its frozen prerequisite")


def _validate_prerequisite_observation(
    repository_root: Path,
    observation: FollowupPrerequisiteObservation,
    request: _FrozenPrerequisites,
    controller_now: datetime,
    *,
    expected_qualification_run_ids: tuple[int, ...],
) -> None:
    if type(observation) is not FollowupPrerequisiteObservation:
        raise FollowupControllerError("prerequisite provider returned the wrong type")
    _validate_fresh_observation(observation.observed_at, controller_now)
    if (
        type(observation.controls) is not tuple
        or tuple(control.kind for control in observation.controls) != _CONTROL_ORDER
        or type(observation.qualification_run_ids) is not tuple
        or observation.qualification_run_ids != expected_qualification_run_ids
        or type(observation.formal_run_ids) is not tuple
        or observation.formal_run_ids
        or any(type(run_id) is not int or run_id <= 0 for run_id in expected_qualification_run_ids)
    ):
        raise FollowupControllerError(
            "control set or one-shot workflow-run inventory changed"
        )
    for control in observation.controls:
        _inspect_control_observation(repository_root, control, request)


def _read_prerequisites(
    provider: FollowupPrerequisiteProvider,
    request: _FrozenPrerequisites,
) -> FollowupPrerequisiteObservation:
    try:
        observation = provider.read_prerequisites(request.control_run_ids)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError("prerequisite provider observation failed") from error
    if type(observation) is not FollowupPrerequisiteObservation:
        raise FollowupControllerError("prerequisite provider returned the wrong snapshot type")
    return observation


def _discard_capability(
    capability_id: int,
    capability_ref: weakref.ReferenceType[object],
) -> None:
    with _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.get(capability_id)
        if issued is not None and issued.capability_ref is capability_ref:
            _ISSUED_CAPABILITIES.pop(capability_id, None)


def _mint_capability(
    capability_type: type[
        FollowupQualificationDispatchCapability | FollowupFormalDispatchCapability
    ],
    binding: _CapabilityBinding,
) -> FollowupQualificationDispatchCapability | FollowupFormalDispatchCapability:
    token = _CapabilityToken()
    capability = object.__new__(capability_type)
    object.__setattr__(capability, "_binding_token", token)
    object.__setattr__(capability, "_lock", threading.Lock())
    capability_id = id(capability)
    capability_ref = weakref.ref(
        capability,
        lambda dead_ref: _discard_capability(capability_id, dead_ref),
    )
    with _ISSUED_CAPABILITIES_LOCK:
        _ISSUED_CAPABILITIES[capability_id] = _IssuedCapability(
            capability_ref=capability_ref,
            binding_token=token,
            binding=binding,
        )
    return capability


def _consume_capability(
    capability: FollowupQualificationDispatchCapability | FollowupFormalDispatchCapability,
    *,
    expected_type: type[
        FollowupQualificationDispatchCapability | FollowupFormalDispatchCapability
    ],
    expected_kind: Literal["qualification", "formal"],
) -> _CapabilityBinding:
    if type(capability) is not expected_type:
        raise TypeError("capability has the wrong follow-up authority type")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise FollowupControllerError("follow-up capability is not authoritative")
    with lock, _ISSUED_CAPABILITIES_LOCK:
        issued = _ISSUED_CAPABILITIES.pop(id(capability), None)
        if issued is None or issued.capability_ref() is not capability:
            raise FollowupControllerError("follow-up capability is absent or consumed")
        presented_token = getattr(capability, "_binding_token", None)
        object.__setattr__(capability, "_binding_token", None)
    if (
        type(issued) is not _IssuedCapability
        or type(issued.binding) is not _CapabilityBinding
        or issued.binding.kind != expected_kind
        or presented_token is not issued.binding_token
    ):
        raise FollowupControllerError("follow-up capability is not authoritative")
    return issued.binding


def authorize_followup_qualification_dispatch(
    repository_root: Path,
    provider: FollowupPrerequisiteProvider,
    request: FollowupDispatchPrerequisites,
) -> FollowupQualificationDispatchCapability:
    """Freshly validate all pre-dispatch controls and mint one qualification capability."""

    frozen = _freeze_prerequisites(request)
    local = _inspect_local_authority(repository_root, frozen)
    observation = _read_prerequisites(provider, frozen)
    now = _require_utc(_utc_now(), "qualification controller observation")
    _validate_prerequisite_observation(
        repository_root.resolve(strict=True),
        observation,
        frozen,
        now,
        expected_qualification_run_ids=(),
    )
    capability = _mint_capability(
        FollowupQualificationDispatchCapability,
        _CapabilityBinding(
            kind="qualification",
            prerequisites=frozen,
            qualification_run_id=None,
            scientific_plan_sha256=local.scientific.machine_plan_sha256,
            controller_observed_at=now,
            expires_at=_require_utc(observation.observed_at, "prerequisite observation")
            + _MAX_OBSERVATION_AGE,
            q6_artifact_id=None,
            q6_artifact_digest=None,
        ),
    )
    assert type(capability) is FollowupQualificationDispatchCapability
    return capability


def _validate_binding_claim(
    binding: _CapabilityBinding,
    frozen: _FrozenPrerequisites,
) -> None:
    if (
        binding.prerequisites != frozen
        or binding.scientific_plan_sha256 != FOLLOWUP_BASELINE_SHA256
    ):
        raise FollowupControllerError("follow-up capability binding does not match")
    claimed_at = _require_utc(_utc_now(), "follow-up capability consumption")
    if claimed_at < binding.controller_observed_at or claimed_at > binding.expires_at:
        raise FollowupControllerError("follow-up capability expired before dispatch")


def consume_followup_qualification_capability(
    capability: FollowupQualificationDispatchCapability,
    request: FollowupDispatchPrerequisites,
) -> FollowupQualificationOpening:
    """Consume live authority and return only watch-bindable qualification facts."""

    binding = _consume_capability(
        capability,
        expected_type=FollowupQualificationDispatchCapability,
        expected_kind="qualification",
    )
    frozen = _freeze_prerequisites(request)
    _validate_binding_claim(binding, frozen)
    return FollowupQualificationOpening(
        experiment_source_s1_sha=frozen.expected_s1_git_sha,
        evidence_freeze_s2_sha=frozen.expected_s2_git_sha,
        compatibility_receipt_sha256=frozen.expected_compatibility_receipt_sha256,
    )


def _validate_followup_live_qualification(
    observation: RouteALiveQualificationObservation,
    *,
    run_id: int,
    expected_s2: str,
    controller_now: datetime,
) -> tuple[
    RouteALiveRunSnapshot,
    dict[str, RouteALiveJobSnapshot],
    datetime,
]:
    if type(observation) is not RouteALiveQualificationObservation:
        raise FollowupControllerError("follow-up qualification observation type changed")
    _validate_fresh_observation(observation.observed_at, controller_now)
    provider_now = _require_utc(
        observation.provider_observed_at,
        "qualification provider Date",
    )
    run = observation.run
    if (
        type(run) is not RouteALiveRunSnapshot
        or run.database_id != run_id
        or run.event != "workflow_dispatch"
        or run.head_sha != expected_s2
        or run.head_branch != "main"
        or run.attempt != 1
        or run.status not in {"queued", "in_progress", "completed"}
        or (run.status == "completed") != (run.conclusion is not None)
        or _require_utc(run.created_at, "qualification run createdAt")
        > _require_utc(run.updated_at, "qualification run updatedAt")
        or _require_utc(run.updated_at, "qualification run updatedAt")
        > provider_now
    ):
        raise FollowupControllerError("follow-up qualification run identity changed")
    jobs = observation.jobs
    if type(jobs) is not tuple or any(
        type(job) is not RouteALiveJobSnapshot for job in jobs
    ):
        raise FollowupControllerError("follow-up qualification job set changed")
    names = tuple(job.name for job in jobs)
    if names != _QUALIFICATION_JOB_NAMES[: len(names)] or len(names) != len(set(names)):
        raise FollowupControllerError("follow-up qualification jobs are not one prefix")
    by_name: dict[str, RouteALiveJobSnapshot] = {}
    identifiers: set[int] = set()
    previous_completed: datetime | None = None
    for job in jobs:
        started = (
            None
            if job.started_at is None
            else _require_utc(job.started_at, f"{job.name} startedAt")
        )
        completed = (
            None
            if job.completed_at is None
            else _require_utc(job.completed_at, f"{job.name} completedAt")
        )
        if (
            type(job.database_id) is not int
            or job.database_id <= 0
            or job.database_id in identifiers
            or job.status not in {"queued", "in_progress", "completed", "waiting", "pending"}
            or (job.status != "completed" and job.conclusion is not None)
            or (job.status == "completed")
            != (completed is not None and job.conclusion is not None)
            or (completed is not None and started is None)
            or (started is not None and started > provider_now)
            or (completed is not None and (completed < started or completed > provider_now))
            or (
                previous_completed is not None
                and started is not None
                and started < previous_completed
            )
        ):
            raise FollowupControllerError(
                "follow-up qualification job lifecycle changed"
            )
        identifiers.add(job.database_id)
        by_name[job.name] = job
        if completed is not None:
            previous_completed = completed
    return run, by_name, provider_now


def _followup_qualification_result(
    inherited: RouteAQualificationWatchResult,
    *,
    decision: Literal["qualification-go", "qualification-no-go"],
    reason: str,
    q6_started_at: datetime | None = None,
    q6_completed_at: datetime | None = None,
    total_threshold_at: datetime | None = None,
    q6_wall_threshold_at: datetime | None = None,
    q6_controller_observed_at: datetime | None = None,
    q6_cancellation_requested_at: datetime | None = None,
    q6_cancellation_acknowledged_at: datetime | None = None,
    q6_provider_terminal_updated_at: datetime | None = None,
    q6_provider_terminal_conclusion: str | None = None,
    q6_watch_decided_at: datetime | None = None,
    q6_cancellation_error: str | None = None,
) -> FollowupQualificationWatchResult:
    return FollowupQualificationWatchResult(
        inherited=inherited,
        qualification_decision=decision,
        q6_started_at=q6_started_at,
        q6_completed_at=q6_completed_at,
        total_threshold_at=total_threshold_at,
        q6_wall_threshold_at=q6_wall_threshold_at,
        q6_controller_observed_at=q6_controller_observed_at,
        q6_cancellation_requested_at=q6_cancellation_requested_at,
        q6_cancellation_acknowledged_at=q6_cancellation_acknowledged_at,
        q6_provider_terminal_updated_at=q6_provider_terminal_updated_at,
        q6_provider_terminal_conclusion=q6_provider_terminal_conclusion,
        q6_watch_decided_at=q6_watch_decided_at,
        q6_cancellation_error=q6_cancellation_error,
        final_reason=reason,
    )


def watch_followup_qualification(
    provider: object,
    request: FollowupFormalAdmissionRequest,
    *,
    poll_interval_seconds: int = 15,
    wait: Callable[[float], None] = time.sleep,
) -> FollowupQualificationWatchResult:
    """Enforce the unchanged 45-minute prefix and the complete 55-minute gate."""

    if type(request) is not FollowupFormalAdmissionRequest:
        raise TypeError("request must be an exact FollowupFormalAdmissionRequest")
    frozen = _freeze_prerequisites(request.prerequisites)
    run_id = request.qualification_run_id
    if type(run_id) is not int or run_id <= 0:
        raise FollowupControllerError("qualification run ID is invalid")
    try:
        inherited = watch_route_a_qualification(
            provider,  # type: ignore[arg-type]
            RouteAQualificationRequest(
                run_id=run_id,
                expected_s2_git_sha=frozen.expected_s2_git_sha,
                expected_head_branch="main",
                expected_run_attempt=1,
            ),
            poll_interval_seconds=poll_interval_seconds,
            wait=wait,
        )
    except (RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "follow-up qualification 45-minute stop-loss failed closed"
        ) from error
    if inherited.decision != "combined-guard-success-before-threshold":
        return _followup_qualification_result(
            inherited,
            decision="qualification-no-go",
            q6_completed_at=None,
            total_threshold_at=(
                None
                if inherited.q1_started_at is None
                else inherited.q1_started_at + _TOTAL_PATH_LIMIT
            ),
            reason=inherited.decision,
        )
    if inherited.q1_started_at is None or inherited.q5_completed_at is None:
        raise FollowupControllerError(
            "successful qualification prefix lacks q1/q5 timestamps"
        )
    q1_started = _require_utc(inherited.q1_started_at, "qualification q1 startedAt")
    q5_completed = _require_utc(
        inherited.q5_completed_at,
        "qualification q5 completedAt",
    )
    total_threshold = q1_started + _TOTAL_PATH_LIMIT
    q6_wall_threshold = q5_completed + _Q6_WALL_LIMIT
    local_fail_safe: datetime | None = None
    cancellation_requested = False
    cancellation_requested_at: datetime | None = None
    cancellation_acknowledged_at: datetime | None = None
    cancellation_deadline: datetime | None = None
    last_q6_started_at: datetime | None = None
    last_q6_completed_at: datetime | None = None
    reason = "qualification q6 did not close"
    while True:
        try:
            observation = provider.read_live_qualification(run_id)  # type: ignore[attr-defined]
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            controller_now = _require_utc(
                _utc_now(),
                "qualification controller failed observation",
            )
            if (
                not cancellation_requested
                and local_fail_safe is not None
                and controller_now < local_fail_safe
            ):
                wait(
                    min(
                        float(poll_interval_seconds),
                        (local_fail_safe - controller_now).total_seconds(),
                    )
                )
                continue
            run = None
            by_name: dict[str, RouteALiveJobSnapshot] = {}
            provider_now = None
            reason = "qualification provider observation failed after q5"
        else:
            controller_now = _require_utc(
                _utc_now(),
                "qualification controller observation",
            )
            run, by_name, provider_now = _validate_followup_live_qualification(
                observation,
                run_id=run_id,
                expected_s2=frozen.expected_s2_git_sha,
                controller_now=controller_now,
            )
            q1 = by_name.get(_QUALIFICATION_JOB_NAMES[0])
            q5 = by_name.get(_QUALIFICATION_JOB_NAMES[4])
            q6 = by_name.get(_QUALIFICATION_JOB_NAMES[5])
            if q6 is not None:
                last_q6_started_at = q6.started_at
                last_q6_completed_at = q6.completed_at
            if (
                q1 is None
                or q1.started_at != q1_started
                or q5 is None
                or q5.completed_at != q5_completed
                or q5.conclusion != "success"
            ):
                raise FollowupControllerError(
                    "qualification q1/q5 identity changed after prefix success"
                )
            provider_deadline = min(total_threshold, q6_wall_threshold)
            if q6 is not None and q6.started_at is not None:
                provider_deadline = min(
                    provider_deadline,
                    q6.started_at + _Q6_JOB_LIMIT,
                )
            remaining = max(timedelta(0), provider_deadline - provider_now)
            candidate_local = controller_now + remaining
            if local_fail_safe is None or candidate_local < local_fail_safe:
                local_fail_safe = candidate_local
            q6_success = (
                q6 is not None
                and q6.status == "completed"
                and q6.conclusion == "success"
                and q6.started_at is not None
                and q6.completed_at is not None
                and q6.completed_at - q6.started_at <= _Q6_JOB_LIMIT
                and q6.completed_at <= q6_wall_threshold
                and q6.completed_at <= total_threshold
            )
            six_success = len(by_name) == 6 and all(
                job.status == "completed" and job.conclusion == "success"
                for job in by_name.values()
            )
            if run.status == "completed":
                if run.conclusion == "success" and q6_success and six_success:
                    assert q6 is not None and q6.completed_at is not None
                    return _followup_qualification_result(
                        inherited,
                        decision="qualification-go",
                        q6_started_at=q6.started_at,
                        q6_completed_at=q6.completed_at,
                        total_threshold_at=total_threshold,
                        q6_wall_threshold_at=q6_wall_threshold,
                        q6_controller_observed_at=controller_now,
                        q6_provider_terminal_updated_at=run.updated_at,
                        q6_provider_terminal_conclusion=run.conclusion,
                        q6_watch_decided_at=controller_now,
                        reason="q1-through-q6 succeeded inside both frozen gates",
                    )
                return _followup_qualification_result(
                    inherited,
                    decision="qualification-no-go",
                    q6_started_at=None if q6 is None else q6.started_at,
                    q6_completed_at=None if q6 is None else q6.completed_at,
                    total_threshold_at=total_threshold,
                    q6_wall_threshold_at=q6_wall_threshold,
                    q6_controller_observed_at=controller_now,
                    q6_cancellation_requested_at=cancellation_requested_at,
                    q6_cancellation_acknowledged_at=(
                        cancellation_acknowledged_at
                    ),
                    q6_provider_terminal_updated_at=run.updated_at,
                    q6_provider_terminal_conclusion=run.conclusion,
                    q6_watch_decided_at=controller_now,
                    reason=(
                        reason
                        if cancellation_requested
                        else "qualification terminal state did not close q6 GO"
                    ),
                )
            failed = any(
                job.status == "completed" and job.conclusion != "success"
                for job in by_name.values()
            )
            if not failed and provider_now < provider_deadline and (
                local_fail_safe is None or controller_now < local_fail_safe
            ):
                wait(
                    min(
                        float(poll_interval_seconds),
                        (provider_deadline - provider_now).total_seconds(),
                        (
                            float(poll_interval_seconds)
                            if local_fail_safe is None
                            else (local_fail_safe - controller_now).total_seconds()
                        ),
                    )
                )
                continue
            reason = (
                "qualification q6 failed"
                if failed
                else "qualification 55-minute or q6 gate reached"
            )
        if not cancellation_requested:
            cancellation_requested_at = controller_now
            try:
                provider.cancel_qualification(run_id)  # type: ignore[attr-defined]
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                cancellation_failed_at = _require_utc(
                    _utc_now(),
                    "qualification q6 failed cancellation decision",
                )
                return _followup_qualification_result(
                    inherited,
                    decision="qualification-no-go",
                    q6_started_at=last_q6_started_at,
                    q6_completed_at=last_q6_completed_at,
                    total_threshold_at=total_threshold,
                    q6_wall_threshold_at=q6_wall_threshold,
                    q6_controller_observed_at=controller_now,
                    q6_cancellation_requested_at=cancellation_requested_at,
                    q6_watch_decided_at=cancellation_failed_at,
                    q6_cancellation_error="provider-cancel-request-failed",
                    reason=f"{reason}; cancellation request failed",
                )
            cancellation_requested = True
            cancellation_acknowledged_at = _require_utc(
                _utc_now(),
                "qualification q6 cancellation acknowledgement",
            )
            cancellation_deadline = (
                cancellation_acknowledged_at + timedelta(minutes=10)
            )
        if run is not None and run.status == "completed":
            return _followup_qualification_result(
                inherited,
                decision="qualification-no-go",
                q6_started_at=last_q6_started_at,
                q6_completed_at=last_q6_completed_at,
                total_threshold_at=total_threshold,
                q6_wall_threshold_at=q6_wall_threshold,
                q6_controller_observed_at=controller_now,
                q6_cancellation_requested_at=cancellation_requested_at,
                q6_cancellation_acknowledged_at=cancellation_acknowledged_at,
                q6_provider_terminal_updated_at=run.updated_at,
                q6_provider_terminal_conclusion=run.conclusion,
                q6_watch_decided_at=controller_now,
                reason=reason,
            )
        if cancellation_deadline is not None and controller_now >= cancellation_deadline:
            return _followup_qualification_result(
                inherited,
                decision="qualification-no-go",
                q6_started_at=last_q6_started_at,
                q6_completed_at=last_q6_completed_at,
                total_threshold_at=total_threshold,
                q6_wall_threshold_at=q6_wall_threshold,
                q6_controller_observed_at=controller_now,
                q6_cancellation_requested_at=cancellation_requested_at,
                q6_cancellation_acknowledged_at=cancellation_acknowledged_at,
                q6_watch_decided_at=controller_now,
                q6_cancellation_error=(
                    "provider-terminal-state-not-observed-within-ten-minutes"
                ),
                reason=f"{reason}; provider terminal state was not observed",
            )
        wait(float(poll_interval_seconds))


def _validate_qualification_jobs(
    jobs: tuple[FollowupJobSnapshot, ...],
) -> tuple[FollowupJobSnapshot, ...]:
    jobs = _validate_job_set(jobs, expected_names=_QUALIFICATION_JOB_NAMES)
    q1, _q2, q3, q4, q5, q6 = jobs
    if q5.completed_at - q1.started_at > _COMPUTATIONAL_LIMIT:
        raise FollowupControllerError("qualification exceeded its 45-minute gate")
    if q6.completed_at - q6.started_at > _Q6_JOB_LIMIT:
        raise FollowupControllerError("qualification q6 exceeded its five-minute job limit")
    if q6.completed_at - q5.completed_at > _Q6_WALL_LIMIT:
        raise FollowupControllerError("qualification q6 missed its ten-minute wall deadline")
    if q6.completed_at - q1.started_at > _TOTAL_PATH_LIMIT:
        raise FollowupControllerError("qualification exceeded its 55-minute total gate")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native qualification job")
        for job in (q3, q4, q5)
    )
    if 6 * native_seconds > _NATIVE_SCREEN_SECONDS:
        raise FollowupControllerError("qualification failed the native planning screen")
    return jobs


def _job_record(job: FollowupJobSnapshot) -> dict[str, object]:
    return {
        "completedAt": _render_time(job.completed_at),
        "conclusion": job.conclusion,
        "databaseId": job.database_id,
        "name": job.name,
        "startedAt": _render_time(job.started_at),
        "status": job.status,
    }


def _parse_record_time(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp") from error
    if _render_time(parsed) != value:
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp")
    return parsed


def _validate_q6_record(
    inspection: RouteAPostrunAdmissionInspection,
    run: FollowupRunSnapshot,
    jobs: tuple[FollowupJobSnapshot, ...],
) -> None:
    if type(inspection) is not RouteAPostrunAdmissionInspection:
        raise FollowupControllerError("q6 inherited inspection type changed")
    record = inspection.record
    run_record = record.get("run")
    q6_record = record.get("q6")
    q1, _q2, q3, q4, q5, q6 = jobs
    computational_seconds = _seconds(q5.completed_at - q1.started_at, "critical path")
    native_seconds = sum(
        _seconds(job.completed_at - job.started_at, "native qualification job")
        for job in (q3, q4, q5)
    )
    expected_run = {
        "attempt": run.attempt,
        "databaseId": run.database_id,
        "event": run.event,
        "headBranch": run.head_branch,
        "headSha": run.head_sha,
    }
    expected_q6 = {
        "databaseId": q6.database_id,
        "name": q6.name,
        "startedAt": _render_time(q6.started_at),
    }
    observed_at = _parse_record_time(record.get("record_observed_utc"), "q6 observation")
    deadline = _parse_record_time(record.get("frozen_q6_deadline_utc"), "q6 deadline")
    if (
        type(record) is not dict
        or type(run_record) is not dict
        or type(q6_record) is not dict
        or record.get("run") != expected_run
        or record.get("jobs_q1_through_q5") != [_job_record(job) for job in jobs[:5]]
        or record.get("q6") != expected_q6
        or observed_at < q6.started_at
        or observed_at > q6.completed_at
        or deadline != q5.completed_at + _Q6_WALL_LIMIT
        or record.get("qualification_computational_seconds") != computational_seconds
        or record.get("native_c_q_seconds") != native_seconds
        or record.get("native_six_c_q_seconds") != 6 * native_seconds
        or record.get("computational_45_minute_gate") != "pass"
        or record.get("native_planning_screen") != "pass"
        or record.get("authority") is not False
        or record.get("formal_execution_authorized") is not False
        or record.get("cancellation_ledger") is not None
    ):
        raise FollowupControllerError("q6 record does not match final provider state")


def _validate_qualification_observation(
    repository_root: Path,
    observation: FollowupQualificationObservation,
    request: FollowupFormalAdmissionRequest,
    frozen: _FrozenPrerequisites,
    local: _LocalAuthority,
    controller_now: datetime,
) -> FollowupArtifactSnapshot:
    if type(observation) is not FollowupQualificationObservation:
        raise FollowupControllerError("qualification provider returned the wrong type")
    _validate_fresh_observation(observation.observed_at, controller_now)
    _validate_run(
        observation.run,
        expected_run_id=request.qualification_run_id,
        expected_workflow=_QUALIFICATION_WORKFLOW,
        expected_s2=frozen.expected_s2_git_sha,
    )
    _validate_provider_authority_binding(
        observation.authority_binding,
        kind="qualification",
        expected_s1=frozen.expected_s1_git_sha,
        expected_s2=frozen.expected_s2_git_sha,
        expected_compatibility=frozen.expected_compatibility_receipt_sha256,
        expected_run_id=request.qualification_run_id,
        expected_qualification_run_id=None,
    )
    jobs = _validate_qualification_jobs(observation.jobs)
    if (
        observation.run.created_at > jobs[0].started_at
        or observation.run.updated_at < jobs[-1].completed_at
    ):
        raise FollowupControllerError("qualification run timestamps do not contain its jobs")
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=frozen.expected_s1_git_sha,
        workflow_head_sha=frozen.expected_s2_git_sha,
        compatibility_receipt_sha256=frozen.expected_compatibility_receipt_sha256,
        provider_run_id=request.qualification_run_id,
        provider_run_attempt=1,
    )
    expected_names = tuple(
        expected_followup_qualification_artifact_name(
            stage=stage,
            lineage=lineage,
            scientific_profile=local.scientific.scientific_profile,
        )
        for stage in ("q1", "q2", "q3", "q4", "q5", "q6")
    )
    if (
        type(observation.artifacts) is not tuple
        or any(type(artifact) is not FollowupArtifactSnapshot for artifact in observation.artifacts)
        or len(observation.artifacts) != 6
    ):
        raise FollowupControllerError("qualification artifact set is not the exact six")
    by_name = {artifact.name: artifact for artifact in observation.artifacts}
    identifiers = {artifact.database_id for artifact in observation.artifacts}
    if len(by_name) != 6 or len(identifiers) != 6 or set(by_name) != set(expected_names):
        raise FollowupControllerError(
            "qualification artifact names are missing, extra, or duplicated"
        )
    for artifact in observation.artifacts:
        if (
            type(artifact.database_id) is not int
            or artifact.database_id <= 0
            or type(artifact.digest) is not str
            or _PROVIDER_DIGEST.fullmatch(artifact.digest) is None
            or type(artifact.size_in_bytes) is not int
            or artifact.size_in_bytes <= 0
            or artifact.expired is not False
            or artifact.workflow_run_id != request.qualification_run_id
            or artifact.workflow_run_head_sha != frozen.expected_s2_git_sha
        ):
            raise FollowupControllerError("qualification provider artifact binding changed")
    q6 = by_name[expected_names[-1]]
    _validate_provider_artifact(
        q6,
        observation.q6_provider_archive_bytes,
        expected_run_id=request.qualification_run_id,
        expected_head_sha=frozen.expected_s2_git_sha,
        maximum_bytes=_MAX_Q6_ARCHIVE_BYTES,
    )
    with _extracted_provider_archive(
        observation.q6_provider_archive_bytes,
        maximum_bytes=_MAX_Q6_ARCHIVE_BYTES,
    ) as root:
        outer = inspect_followup_qualification_artifact(
            root,
            stage="q6",
            lineage=lineage,
            scientific_profile=local.scientific.scientific_profile,
            machine_plan_bytes=local.scientific.machine_plan_bytes,
            repository_root=repository_root,
        )
        if outer.artifact_name != q6.name:
            raise FollowupControllerError("q6 outer identity differs from provider name")
        _validate_q6_record(outer.inherited, observation.run, jobs)  # type: ignore[arg-type]
    return q6


def authorize_followup_formal_campaign(
    repository_root: Path,
    prerequisite_provider: FollowupPrerequisiteProvider,
    qualification_provider: FollowupQualificationProvider,
    request: FollowupFormalAdmissionRequest,
) -> FollowupFormalDispatchCapability:
    """Freshly close q1--q6 and every control before minting formal authority."""

    if type(request) is not FollowupFormalAdmissionRequest:
        raise TypeError("request must be an exact FollowupFormalAdmissionRequest")
    if type(request.qualification_run_id) is not int or request.qualification_run_id <= 0:
        raise FollowupControllerError("qualification run ID is invalid")
    frozen = _freeze_prerequisites(request.prerequisites)
    root = repository_root.resolve(strict=True)
    local = _inspect_local_authority(root, frozen)
    prerequisite_observation = _read_prerequisites(prerequisite_provider, frozen)
    try:
        qualification_observation = qualification_provider.read_qualification(
            request.qualification_run_id
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError("qualification provider observation failed") from error
    now = _require_utc(_utc_now(), "formal controller observation")
    _validate_prerequisite_observation(
        root,
        prerequisite_observation,
        frozen,
        now,
        expected_qualification_run_ids=(request.qualification_run_id,),
    )
    q6 = _validate_qualification_observation(
        root,
        qualification_observation,
        request,
        frozen,
        local,
        now,
    )
    expires_at = min(
        _require_utc(prerequisite_observation.observed_at, "prerequisite observation"),
        _require_utc(qualification_observation.observed_at, "qualification observation"),
    ) + _MAX_OBSERVATION_AGE
    capability = _mint_capability(
        FollowupFormalDispatchCapability,
        _CapabilityBinding(
            kind="formal",
            prerequisites=frozen,
            qualification_run_id=request.qualification_run_id,
            scientific_plan_sha256=local.scientific.machine_plan_sha256,
            controller_observed_at=now,
            expires_at=expires_at,
            q6_artifact_id=q6.database_id,
            q6_artifact_digest=q6.digest,
        ),
    )
    assert type(capability) is FollowupFormalDispatchCapability
    return capability


def consume_followup_formal_campaign_capability(
    capability: FollowupFormalDispatchCapability,
    request: FollowupFormalAdmissionRequest,
) -> FollowupFormalCampaignOpening:
    """Consume live authority and return only CAS-bound opening facts."""

    binding = _consume_capability(
        capability,
        expected_type=FollowupFormalDispatchCapability,
        expected_kind="formal",
    )
    if type(request) is not FollowupFormalAdmissionRequest:
        raise TypeError("request must be an exact FollowupFormalAdmissionRequest")
    frozen = _freeze_prerequisites(request.prerequisites)
    _validate_binding_claim(binding, frozen)
    if (
        type(request.qualification_run_id) is not int
        or request.qualification_run_id <= 0
        or binding.qualification_run_id != request.qualification_run_id
        or type(binding.q6_artifact_id) is not int
        or binding.q6_artifact_id <= 0
        or type(binding.q6_artifact_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(binding.q6_artifact_digest) is None
    ):
        raise FollowupControllerError("formal capability qualification binding changed")
    return FollowupFormalCampaignOpening(
        experiment_source_s1_sha=frozen.expected_s1_git_sha,
        evidence_freeze_s2_sha=frozen.expected_s2_git_sha,
        compatibility_receipt_sha256=frozen.expected_compatibility_receipt_sha256,
        qualification_run_id=request.qualification_run_id,
        qualification_q6_artifact_id=binding.q6_artifact_id,
        qualification_q6_artifact_digest=binding.q6_artifact_digest,
    )


def _formal_live_job_document(job: FollowupFormalLiveJobSnapshot) -> dict[str, object]:
    return {
        "completedAt": (
            None if job.completed_at is None else _render_time(job.completed_at)
        ),
        "conclusion": job.conclusion,
        "databaseId": job.database_id,
        "name": job.name,
        "startedAt": None if job.started_at is None else _render_time(job.started_at),
        "status": job.status,
    }


def _validate_formal_live_job(job: FollowupFormalLiveJobSnapshot) -> None:
    if (
        type(job) is not FollowupFormalLiveJobSnapshot
        or type(job.database_id) is not int
        or job.database_id <= 0
        or type(job.name) is not str
        or not job.name
        or job.status not in {"queued", "in_progress", "completed", "waiting", "pending"}
    ):
        raise FollowupControllerError("formal live job snapshot changed")
    started = (
        None
        if job.started_at is None
        else _require_utc(job.started_at, f"{job.name} startedAt")
    )
    completed = (
        None
        if job.completed_at is None
        else _require_utc(job.completed_at, f"{job.name} completedAt")
    )
    if (
        (completed is not None and started is None)
        or (started is not None and completed is not None and completed < started)
        or (job.status == "completed" and (completed is None or job.conclusion is None))
        or (job.status != "completed" and job.conclusion is not None)
    ):
        raise FollowupControllerError("formal live job lifecycle changed")


def _formal_expected_job_names(
    specs: tuple[FollowupFormalUnitSpec, ...],
) -> tuple[str, ...]:
    return (
        _FORMAL_LAUNCH_JOB,
        *(
            name
            for spec in specs
            for name in (spec.producer_job_name, spec.guard_job_name)
        ),
        _FORMAL_TERMINAL_JOB,
        _FORMAL_AGGREGATE_JOB,
    )


def _validate_formal_live_observation(
    observation: FollowupFormalLiveObservation,
    *,
    run_id: int,
    expected_s1: str,
    expected_s2: str,
    expected_compatibility: str,
    controller_now: datetime,
    specs: tuple[FollowupFormalUnitSpec, ...],
    qualification_run_id: int,
) -> dict[str, FollowupFormalLiveJobSnapshot]:
    if type(observation) is not FollowupFormalLiveObservation:
        raise FollowupControllerError("formal provider returned the wrong snapshot type")
    _validate_fresh_observation(observation.observed_at, controller_now)
    provider_now = _require_utc(
        observation.provider_observed_at,
        "formal provider observation",
    )
    if provider_now > controller_now + _MAX_OBSERVATION_AGE:
        raise FollowupControllerError("formal provider clock is implausibly ahead")
    run = observation.run
    if (
        type(run) is not FollowupFormalLiveRunSnapshot
        or run.database_id != run_id
        or run.workflow_path != _FORMAL_WORKFLOW
        or run.event != "workflow_dispatch"
        or run.head_sha != expected_s2
        or run.head_branch != "main"
        or run.attempt != 1
        or run.status not in {"queued", "in_progress", "completed"}
        or (run.status == "completed") != (run.conclusion is not None)
    ):
        raise FollowupControllerError("formal live run identity or lifecycle changed")
    created = _require_utc(run.created_at, "formal run createdAt")
    updated = _require_utc(run.updated_at, "formal run updatedAt")
    if updated < created:
        raise FollowupControllerError("formal live run timestamps changed")
    _validate_provider_authority_binding(
        observation.authority_binding,
        kind="formal",
        expected_s1=expected_s1,
        expected_s2=expected_s2,
        expected_compatibility=expected_compatibility,
        expected_run_id=run_id,
        expected_qualification_run_id=qualification_run_id,
    )
    expected_names = set(_formal_expected_job_names(specs))
    by_name: dict[str, FollowupFormalLiveJobSnapshot] = {}
    identifiers: set[int] = set()
    for job in observation.jobs:
        _validate_formal_live_job(job)
        if (
            job.name not in expected_names
            or job.name in by_name
            or job.database_id in identifiers
        ):
            raise FollowupControllerError("formal live job set is extra or duplicated")
        by_name[job.name] = job
        identifiers.add(job.database_id)
    return by_name


def _successful(job: FollowupFormalLiveJobSnapshot | None) -> bool:
    return (
        job is not None
        and job.status == "completed"
        and job.conclusion == "success"
        and job.started_at is not None
        and job.completed_at is not None
    )


def _started(job: FollowupFormalLiveJobSnapshot | None) -> bool:
    return job is not None and job.started_at is not None


def _terminal_non_success(job: FollowupFormalLiveJobSnapshot | None) -> bool:
    return job is not None and job.status == "completed" and job.conclusion != "success"


def _assess_formal_prefix(
    by_name: dict[str, FollowupFormalLiveJobSnapshot],
    *,
    provider_now: datetime,
    specs: tuple[FollowupFormalUnitSpec, ...],
) -> tuple[str, str, int | None]:
    launch = by_name.get(_FORMAL_LAUNCH_JOB)
    if _terminal_non_success(launch):
        return "no-go", "formal launch admission did not succeed", None
    if not _successful(launch):
        if any(
            _started(by_name.get(name))
            for name in _formal_expected_job_names(specs)[1:]
        ):
            return "no-go", "a formal job started before launch admission", None
        return "active", "waiting for formal launch admission", None

    previous_completed = launch.completed_at
    assert previous_completed is not None
    for spec in specs:
        producer = by_name.get(spec.producer_job_name)
        guard = by_name.get(spec.guard_job_name)
        if _started(producer) and producer.started_at < previous_completed:  # type: ignore[union-attr]
            return "no-go", "formal producer overlapped its predecessor", spec.ordinal
        if _started(guard):
            if not _successful(producer):
                return "no-go", "formal guard started before producer success", spec.ordinal
            assert producer is not None and producer.completed_at is not None
            if guard.started_at < producer.completed_at:  # type: ignore[union-attr]
                return "no-go", "formal replay overlapped its producer", spec.ordinal
        later_names = tuple(
            name
            for later in specs[spec.ordinal + 1 :]
            for name in (later.producer_job_name, later.guard_job_name)
        ) + (_FORMAL_TERMINAL_JOB, _FORMAL_AGGREGATE_JOB)
        if not _successful(guard) and any(
            _started(by_name.get(name)) for name in later_names
        ):
            return "no-go", "formal jobs departed from strict serial order", spec.ordinal
        if _terminal_non_success(producer) or _terminal_non_success(guard):
            return "no-go", "one formal unit job did not succeed", spec.ordinal
        if producer is None or producer.started_at is None:
            return "active", "waiting for formal producer", spec.ordinal
        deadline = producer.started_at + timedelta(minutes=spec.reservation_minutes)
        if _successful(guard):
            assert guard is not None and guard.completed_at is not None
            if guard.completed_at > deadline:
                return "no-go", "formal unit exceeded its combined reservation", spec.ordinal
            previous_completed = guard.completed_at
            continue
        if provider_now >= deadline:
            return "no-go", "formal unit reached its combined reservation", spec.ordinal
        return "active", "formal unit is within its combined reservation", spec.ordinal

    terminal = by_name.get(_FORMAL_TERMINAL_JOB)
    aggregate = by_name.get(_FORMAL_AGGREGATE_JOB)
    if _terminal_non_success(terminal):
        return "no-go", "formal terminal admission did not succeed", None
    if not _successful(terminal):
        if _started(aggregate):
            return "no-go", "aggregate started before terminal admission", None
        if (
            terminal is not None
            and terminal.started_at is not None
            and provider_now >= terminal.started_at + _FORMAL_TERMINAL_LIMIT
        ):
            return "no-go", "formal terminal admission reached its reservation", None
        return "active", "waiting for formal terminal admission", None
    if _terminal_non_success(aggregate):
        return "no-go", "formal aggregate did not succeed", None
    if not _successful(aggregate):
        return "active", "waiting for formal aggregate", None
    return "success", "formal units, terminal admission, and aggregate succeeded", None


def _formal_watch_document(
    observation: FollowupFormalLiveObservation,
    *,
    decision: str,
    reason: str,
    current_unit_ordinal: int | None,
    cancellation_requested_at: datetime | None,
) -> dict[str, object]:
    run = observation.run
    return {
        "authority": False,
        "cancellation": (
            None
            if cancellation_requested_at is None
            else {
                "provider_request_submitted": True,
                "requestedAt": _render_time(cancellation_requested_at),
            }
        ),
        "current_unit_ordinal_or_null": current_unit_ordinal,
        "decision": decision,
        "formal_campaign_provider_run_id": run.database_id,
        "formal_execution_authorized": False,
        "jobs": [
            _formal_live_job_document(job)
            for job in sorted(observation.jobs, key=lambda value: value.name)
        ],
        "provider_observed_at": _render_time(observation.provider_observed_at),
        "provider_authority_binding": {
            "claim_tree_oid": observation.authority_binding.claim_tree_oid,
            "commit_message": observation.authority_binding.commit_message,
            "parent_oids": list(observation.authority_binding.parent_oids),
            "ref_name": observation.authority_binding.ref_name,
            "target_oid": observation.authority_binding.target_oid,
            "tree_oid": observation.authority_binding.tree_oid,
        },
        "publication_evidence_admitted": False,
        "reason": reason,
        "run": {
            "conclusion": run.conclusion,
            "createdAt": _render_time(run.created_at),
            "headBranch": run.head_branch,
            "headSha": run.head_sha,
            "runAttempt": run.attempt,
            "status": run.status,
            "updatedAt": _render_time(run.updated_at),
            "workflowPath": run.workflow_path,
        },
        "schema_version": "dynamic-cssc-followup-performance-formal-watch-v1",
        "study_id": FOLLOWUP_STUDY_ID,
    }


def watch_followup_formal_campaign(
    repository_root: Path,
    provider: FollowupFormalLiveProvider,
    request: FollowupFormalAdmissionRequest,
    formal_run_id: int,
    *,
    poll_interval_seconds: int = 15,
    wait: Callable[[float], None] = time.sleep,
) -> FollowupFormalWatchResult:
    """Enforce each combined unit reservation until one exact campaign terminates."""

    if type(request) is not FollowupFormalAdmissionRequest:
        raise TypeError("request must be an exact FollowupFormalAdmissionRequest")
    if type(formal_run_id) is not int or formal_run_id <= 0:
        raise FollowupControllerError("formal run ID is invalid")
    if type(poll_interval_seconds) is not int or not 1 <= poll_interval_seconds <= 300:
        raise FollowupControllerError("formal poll interval is outside 1..300 seconds")
    frozen = _freeze_prerequisites(request.prerequisites)
    local = _inspect_local_authority(repository_root, frozen)
    specs = followup_formal_unit_specs(local.scientific.scientific_profile)
    cancellation_reason: str | None = None
    cancellation_requested_at: datetime | None = None
    while True:
        try:
            observation = provider.read_live_formal(formal_run_id)
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            raise FollowupControllerError("formal provider observation failed") from error
        controller_now = _require_utc(_utc_now(), "formal controller observation")
        by_name = _validate_formal_live_observation(
            observation,
            run_id=formal_run_id,
            expected_s1=frozen.expected_s1_git_sha,
            expected_s2=frozen.expected_s2_git_sha,
            expected_compatibility=frozen.expected_compatibility_receipt_sha256,
            controller_now=controller_now,
            specs=specs,
            qualification_run_id=request.qualification_run_id,
        )
        state, reason, current_unit = _assess_formal_prefix(
            by_name,
            provider_now=observation.provider_observed_at,
            specs=specs,
        )
        if state == "no-go" and cancellation_requested_at is None:
            try:
                provider.cancel_formal(formal_run_id)
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
                raise FollowupControllerError("formal stop-loss cancellation failed") from error
            cancellation_reason = reason
            cancellation_requested_at = observation.provider_observed_at
        if observation.run.status == "completed":
            if (
                observation.run.conclusion == "success"
                and state == "success"
                and cancellation_requested_at is None
            ):
                decision = "terminal-success-candidate"
                final_reason = reason
            else:
                decision = "terminal-no-go"
                final_reason = cancellation_reason or reason
            return FollowupFormalWatchResult(
                document=_formal_watch_document(
                    observation,
                    decision=decision,
                    reason=final_reason,
                    current_unit_ordinal=current_unit,
                    cancellation_requested_at=cancellation_requested_at,
                )
            )
        wait(float(poll_interval_seconds))


def abandon_followup_qualification_capability(
    capability: FollowupQualificationDispatchCapability,
) -> None:
    """Consume an unused qualification capability without provider mutation."""

    _consume_capability(
        capability,
        expected_type=FollowupQualificationDispatchCapability,
        expected_kind="qualification",
    )


def abandon_followup_formal_capability(
    capability: FollowupFormalDispatchCapability,
) -> None:
    """Consume an unused formal capability without provider mutation."""

    _consume_capability(
        capability,
        expected_type=FollowupFormalDispatchCapability,
        expected_kind="formal",
    )
