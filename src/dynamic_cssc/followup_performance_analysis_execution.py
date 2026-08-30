"""Deep module for the sole isolated S3 analysis transaction."""

from __future__ import annotations

import hashlib
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisClaim,
    FollowupAnalysisRunAdmission,
    FollowupAnalysisWatchBinding,
    build_followup_analysis_claim,
    build_followup_analysis_run_admission,
    build_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    build_followup_campaign_transport,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    _canonical_json_bytes,
    _parse_ascii_json,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_controller import FollowupControllerError
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_s3_analysis_compatibility,
)
from dynamic_cssc.followup_performance_terminal_evidence import (
    inspect_followup_terminal_evidence_bundle,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
)

__all__ = (
    "FollowupAnalysisArtifactBinding",
    "FollowupAnalysisExecutionProvider",
    "FollowupAnalysisExecutionResult",
    "FollowupAnalysisPhaseReceipt",
    "FollowupAnalysisWatch",
    "FollowupAnalysisWatchOutcome",
    "build_followup_analysis_watch_outcome",
    "execute_followup_analysis",
    "inspect_followup_analysis_phase_receipt",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ANALYSIS_ARTIFACT = re.compile(
    r"followup-performance-v1-analysis-[a-z0-9-]+\Z"
)
_PHASE_SCHEMA = "dynamic-cssc-followup-performance-analysis-phase-receipt-v1"
_WATCH_SCHEMA = "dynamic-cssc-followup-performance-analysis-watcher-receipt-v1"


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupControllerError(f"{field} is not a lowercase SHA-256")
    return value


def _render_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FollowupControllerError("analysis watcher time lacks UTC")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class FollowupAnalysisArtifactBinding:
    provider_artifact_id: int
    artifact_name: str
    provider_digest: str
    size_in_bytes: int

    @property
    def document(self) -> dict[str, object]:
        return {
            "artifact_name": self.artifact_name,
            "provider_artifact_id": self.provider_artifact_id,
            "provider_digest": self.provider_digest,
            "size_in_bytes": self.size_in_bytes,
        }


def _analysis_artifact(
    value: FollowupAnalysisArtifactBinding,
) -> FollowupAnalysisArtifactBinding:
    if (
        type(value) is not FollowupAnalysisArtifactBinding
        or type(value.provider_artifact_id) is not int
        or value.provider_artifact_id <= 0
        or type(value.artifact_name) is not str
        or _ANALYSIS_ARTIFACT.fullmatch(value.artifact_name) is None
        or type(value.provider_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(value.provider_digest) is None
        or type(value.size_in_bytes) is not int
        or value.size_in_bytes <= 0
    ):
        raise FollowupControllerError("analysis artifact provider binding changed")
    return value


@dataclass(frozen=True, slots=True)
class FollowupAnalysisPhaseReceipt:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def inspect_followup_analysis_phase_receipt(
    content: bytes,
    *,
    expected_analysis_compatibility_receipt_sha256: str,
) -> FollowupAnalysisPhaseReceipt:
    _sha256(
        expected_analysis_compatibility_receipt_sha256,
        field="expected analysis compatibility receipt",
    )
    if type(content) is not bytes or not content or len(content) > 64 * 1024:
        raise FollowupControllerError("analysis phase receipt bytes changed")
    value = _parse_ascii_json(content, label="analysis phase receipt")
    if (
        type(value) is not dict
        or set(value)
        != {
            "analysis_compatibility_receipt_sha256",
            "analysis_sha256",
            "artifact_name",
            "schema_version",
            "unit_identity_sha256",
        }
        or value.get("schema_version") != _PHASE_SCHEMA
        or value.get("analysis_compatibility_receipt_sha256")
        != expected_analysis_compatibility_receipt_sha256
        or type(value.get("artifact_name")) is not str
        or _ANALYSIS_ARTIFACT.fullmatch(value["artifact_name"]) is None
    ):
        raise FollowupControllerError("analysis phase receipt projection changed")
    _sha256(value.get("analysis_sha256"), field="analysis payload")
    _sha256(value.get("unit_identity_sha256"), field="analysis unit identity")
    canonical = _canonical_json_bytes(value)
    return FollowupAnalysisPhaseReceipt(
        document=value,
        document_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FollowupAnalysisWatchOutcome:
    provider_run_id: int
    watcher_session_sha256: str
    watcher_receipt_sha256: str
    watcher_receipt_bytes: bytes
    provider_run_json: bytes
    provider_jobs_json: bytes
    provider_artifacts_json: bytes
    provider_phase_receipt_bytes_or_null: bytes | None
    provider_observed_at: datetime
    decision: Literal["success", "no-go"]
    job_started_at_or_null: datetime | None
    job_completed_at_or_null: datetime | None
    runner_seconds_or_null: int | None
    analysis_artifact_or_null: FollowupAnalysisArtifactBinding | None
    cancellation_requested_at_or_null: datetime | None
    cancellation_acknowledged_at_or_null: datetime | None
    no_go_reason_or_null: str | None


def build_followup_analysis_watch_outcome(
    *,
    claim: FollowupAnalysisClaim,
    provider_run_id: int,
    watcher_session_sha256: str,
    provider_run_json: bytes,
    provider_jobs_json: bytes,
    provider_artifacts_json: bytes,
    provider_phase_receipt_bytes_or_null: bytes | None,
    provider_observed_at: datetime,
    decision: Literal["success", "no-go"],
    job_started_at_or_null: datetime | None,
    job_completed_at_or_null: datetime | None,
    analysis_artifact_or_null: FollowupAnalysisArtifactBinding | None,
    cancellation_requested_at_or_null: datetime | None,
    cancellation_acknowledged_at_or_null: datetime | None,
    no_go_reason_or_null: str | None,
) -> FollowupAnalysisWatchOutcome:
    if (
        type(claim) is not FollowupAnalysisClaim
        or type(provider_run_id) is not int
        or provider_run_id <= 0
    ):
        raise FollowupControllerError("analysis watcher identity changed")
    _sha256(watcher_session_sha256, field="analysis watcher session")
    for content in (
        provider_run_json,
        provider_jobs_json,
        provider_artifacts_json,
    ):
        if type(content) is not bytes or not content or len(content) > 8 * 1024 * 1024:
            raise FollowupControllerError("analysis provider evidence bytes changed")
    provider_time = _render_time(provider_observed_at)
    started = (
        None
        if job_started_at_or_null is None
        else _render_time(job_started_at_or_null)
    )
    completed = (
        None
        if job_completed_at_or_null is None
        else _render_time(job_completed_at_or_null)
    )
    requested = (
        None
        if cancellation_requested_at_or_null is None
        else _render_time(cancellation_requested_at_or_null)
    )
    acknowledged = (
        None
        if cancellation_acknowledged_at_or_null is None
        else _render_time(cancellation_acknowledged_at_or_null)
    )
    if (requested is None) != (acknowledged is None):
        raise FollowupControllerError("analysis cancellation ledger changed")
    runner_seconds: int | None = None
    phase: FollowupAnalysisPhaseReceipt | None = None
    if decision == "success":
        if (
            job_started_at_or_null is None
            or job_completed_at_or_null is None
            or job_completed_at_or_null < job_started_at_or_null
            or cancellation_requested_at_or_null is not None
            or no_go_reason_or_null is not None
            or provider_phase_receipt_bytes_or_null is None
            or analysis_artifact_or_null is None
        ):
            raise FollowupControllerError("successful analysis watcher changed")
        runner_seconds = int(
            (job_completed_at_or_null - job_started_at_or_null).total_seconds()
        )
        limit = claim.document["analysis_runner_seconds_limit"]
        if type(limit) is not int or not 0 <= runner_seconds <= limit:
            raise FollowupControllerError("analysis shared terminal budget was exceeded")
        artifact = _analysis_artifact(analysis_artifact_or_null)
        phase = inspect_followup_analysis_phase_receipt(
            provider_phase_receipt_bytes_or_null,
            expected_analysis_compatibility_receipt_sha256=claim.document[
                "analysis_compatibility_receipt_sha256"
            ],  # type: ignore[arg-type]
        )
        if phase.document["artifact_name"] != artifact.artifact_name:
            raise FollowupControllerError(
                "analysis phase receipt does not bind provider artifact"
            )
    elif decision == "no-go":
        if (
            type(no_go_reason_or_null) is not str
            or not no_go_reason_or_null
            or provider_phase_receipt_bytes_or_null is not None
            or analysis_artifact_or_null is not None
        ):
            raise FollowupControllerError("analysis NO-GO watcher changed")
        if (
            job_started_at_or_null is not None
            and job_completed_at_or_null is not None
            and job_completed_at_or_null >= job_started_at_or_null
        ):
            runner_seconds = int(
                (job_completed_at_or_null - job_started_at_or_null).total_seconds()
            )
    else:  # pragma: no cover
        raise FollowupControllerError("analysis watcher decision changed")
    receipt = {
        "analysis_artifact_or_null": (
            None
            if analysis_artifact_or_null is None
            else analysis_artifact_or_null.document
        ),
        "analysis_claim_sha256": claim.sha256,
        "analysis_runner_seconds_limit": claim.document[
            "analysis_runner_seconds_limit"
        ],
        "artifacts_api_sha256": hashlib.sha256(provider_artifacts_json).hexdigest(),
        "authority": False,
        "campaign_id": claim.document["campaign_id"],
        "cancellation_acknowledged_at_or_null": acknowledged,
        "cancellation_requested_at_or_null": requested,
        "decision": decision,
        "job_completed_at_or_null": completed,
        "job_started_at_or_null": started,
        "jobs_api_sha256": hashlib.sha256(provider_jobs_json).hexdigest(),
        "no_go_reason_or_null": no_go_reason_or_null,
        "provider_observed_at": provider_time,
        "provider_run_id": provider_run_id,
        "publication_evidence_admitted": False,
        "run_api_sha256": hashlib.sha256(provider_run_json).hexdigest(),
        "runner_seconds_or_null": runner_seconds,
        "schema_version": _WATCH_SCHEMA,
        "study_id": FOLLOWUP_STUDY_ID,
        "terminal_runner_seconds": claim.document["terminal_runner_seconds"],
        "terminal_segment_seconds_or_null": (
            None
            if runner_seconds is None
            else claim.document["terminal_runner_seconds"] + runner_seconds  # type: ignore[operator]
        ),
        "analysis_phase_receipt_sha256_or_null": (
            None if phase is None else phase.sha256
        ),
        "watcher_session_sha256": watcher_session_sha256,
    }
    receipt_bytes = _canonical_json_bytes(receipt)
    return FollowupAnalysisWatchOutcome(
        provider_run_id=provider_run_id,
        watcher_session_sha256=watcher_session_sha256,
        watcher_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        watcher_receipt_bytes=receipt_bytes,
        provider_run_json=provider_run_json,
        provider_jobs_json=provider_jobs_json,
        provider_artifacts_json=provider_artifacts_json,
        provider_phase_receipt_bytes_or_null=(
            None if phase is None else phase.document_bytes
        ),
        provider_observed_at=provider_observed_at,
        decision=decision,
        job_started_at_or_null=job_started_at_or_null,
        job_completed_at_or_null=job_completed_at_or_null,
        runner_seconds_or_null=runner_seconds,
        analysis_artifact_or_null=analysis_artifact_or_null,
        cancellation_requested_at_or_null=cancellation_requested_at_or_null,
        cancellation_acknowledged_at_or_null=cancellation_acknowledged_at_or_null,
        no_go_reason_or_null=no_go_reason_or_null,
    )


class FollowupAnalysisWatch(Protocol):
    @property
    def session_sha256(self) -> str: ...

    def wait(self) -> FollowupAnalysisWatchOutcome: ...


class FollowupAnalysisExecutionProvider(Protocol):
    @property
    def analysis_workflow_ref(self) -> str: ...

    def open_analysis(self, claim: FollowupAnalysisClaim) -> tuple[str, str]: ...

    def dispatch_analysis_run(self, *, inputs: dict[str, str]) -> int: ...

    def start_analysis_watch(
        self,
        *,
        provider_run_id: int,
        claim: FollowupAnalysisClaim,
    ) -> FollowupAnalysisWatch: ...

    def install_analysis_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupAnalysisWatchBinding,
    ) -> str: ...

    def install_analysis_outcome(
        self,
        *,
        expected_binding_oid: str,
        expected_tree_oid: str,
        outcome: FollowupAnalysisWatchOutcome,
    ) -> str: ...

    def cancel_analysis_run(self, provider_run_id: int) -> None: ...


@dataclass(frozen=True, slots=True)
class FollowupAnalysisExecutionResult:
    decision: Literal["publication-results-ready", "no-go"]
    provider_run_id: int
    claim_oid: str
    binding_oid: str
    outcome_oid: str
    claim: FollowupAnalysisClaim
    watch_binding: FollowupAnalysisWatchBinding
    run_admission: FollowupAnalysisRunAdmission
    watch_outcome: FollowupAnalysisWatchOutcome
    evidence_root: Path


def _terminal_artifact(value: object) -> FollowupTerminalArtifactBinding:
    if type(value) is not dict:
        raise FollowupControllerError("terminal evidence artifact changed")
    try:
        return FollowupTerminalArtifactBinding(
            provider_artifact_id=value["provider_artifact_id"],  # type: ignore[arg-type]
            artifact_name=value["artifact_name"],  # type: ignore[arg-type]
            provider_digest=value["provider_digest"],  # type: ignore[arg-type]
            size_in_bytes=value["size_in_bytes"],  # type: ignore[arg-type]
        )
    except KeyError as error:
        raise FollowupControllerError(
            "terminal evidence artifact changed"
        ) from error


def _best_effort_cancel(
    provider: FollowupAnalysisExecutionProvider,
    provider_run_id: int | None,
) -> None:
    if provider_run_id is None:
        return
    with suppress(AttributeError, OSError, RuntimeError, TypeError, ValueError):
        provider.cancel_analysis_run(provider_run_id)


def execute_followup_analysis(
    *,
    repository_root: Path,
    campaign_evidence_root: Path,
    terminal_evidence_root: Path,
    analysis_source_s3_sha: str,
    expected_analysis_compatibility_receipt_sha256: str,
    provider: FollowupAnalysisExecutionProvider,
    evidence_root: Path,
) -> FollowupAnalysisExecutionResult:
    """Verify terminal success, then dispatch and close the sole S3 analysis."""

    scientific = materialize_followup_scientific_plan(repository_root)
    terminal = inspect_followup_terminal_evidence_bundle(terminal_evidence_root)
    watcher = terminal.watcher_receipt
    if (
        watcher.get("decision") != "success"
        or terminal.phase_receipt is None
        or type(watcher.get("runner_seconds_or_null")) is not int
        or not 0 <= watcher["runner_seconds_or_null"] < 30 * 60
        or type(terminal.controller.get("outcome_oid")) is not str
        or _LOWER_GIT_SHA.fullmatch(terminal.controller["outcome_oid"]) is None
    ):
        raise FollowupControllerError("analysis lacks one successful terminal outcome")
    transport = build_followup_campaign_transport(
        campaign_evidence_root,
        scientific_profile=scientific.scientific_profile,
    )
    if (
        terminal.claim.document["campaign_transport_sha256"] != transport.sha256
        or terminal.claim.document["campaign_transport_member_count"]
        != transport.member_count
        or terminal.claim.document["campaign_transport_expanded_bytes"]
        != transport.expanded_bytes
    ):
        raise FollowupControllerError("analysis campaign transport changed")
    compatibility = verify_followup_s1_s2_s3_analysis_compatibility(
        repository_root,
        s1=terminal.claim.document["experiment_source_S1_sha"],  # type: ignore[arg-type]
        s2=terminal.claim.document["evidence_freeze_S2_sha"],  # type: ignore[arg-type]
        s3=analysis_source_s3_sha,
    )
    if compatibility.sha256 != expected_analysis_compatibility_receipt_sha256:
        raise FollowupControllerError("analysis compatibility receipt changed")
    terminal_artifact = _terminal_artifact(
        watcher.get("terminal_artifact_or_null")
    )
    aggregate_artifact = _terminal_artifact(
        watcher.get("aggregate_artifact_or_null")
    )
    claim = build_followup_analysis_claim(
        campaign_id=terminal.claim.document["campaign_id"],  # type: ignore[arg-type]
        experiment_source_s1_sha=terminal.claim.document[
            "experiment_source_S1_sha"
        ],  # type: ignore[arg-type]
        evidence_freeze_s2_sha=terminal.claim.document[
            "evidence_freeze_S2_sha"
        ],  # type: ignore[arg-type]
        analysis_source_s3_sha=analysis_source_s3_sha,
        registration_compatibility_receipt_sha256=terminal.claim.document[
            "compatibility_receipt_sha256"
        ],  # type: ignore[arg-type]
        analysis_compatibility_receipt_sha256=compatibility.sha256,
        terminal_outcome_oid=terminal.controller["outcome_oid"],  # type: ignore[arg-type]
        terminal_provider_run_id=terminal.binding.document[
            "provider_run_id"
        ],  # type: ignore[arg-type]
        terminal_run_admission_sha256=terminal.admission.sha256,
        terminal_watcher_receipt_sha256=hashlib.sha256(
            _canonical_json_bytes(watcher)
        ).hexdigest(),
        terminal_runner_seconds=watcher["runner_seconds_or_null"],  # type: ignore[arg-type]
        campaign_transport_sha256=transport.sha256,
        campaign_transport_member_count=transport.member_count,
        campaign_transport_expanded_bytes=transport.expanded_bytes,
        terminal_artifact=terminal_artifact,
        aggregate_artifact=aggregate_artifact,
    )
    from dynamic_cssc.followup_performance_analysis_evidence import (
        FollowupAnalysisEvidenceJournal,
    )

    journal = FollowupAnalysisEvidenceJournal(
        evidence_root,
        claim=claim,
        transport=transport,
    )
    try:
        claim_oid, tree_oid = provider.open_analysis(claim)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "analysis provider claim failed or was ambiguous"
        ) from error
    if (
        type(claim_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(claim_oid) is None
        or type(tree_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
    ):
        raise FollowupControllerError("analysis provider claim identity changed")
    run_id: int | None = None
    try:
        run_id = provider.dispatch_analysis_run(
            inputs={
                "expected_analysis_claim_oid": claim_oid,
                "expected_analysis_compatibility_receipt_sha256": (
                    compatibility.sha256
                ),
                "expected_campaign_id": claim.document["campaign_id"],
                "expected_registration_compatibility_receipt_sha256": (
                    claim.document["registration_compatibility_receipt_sha256"]
                ),
                "expected_s1_git_sha": claim.document["experiment_source_S1_sha"],
                "expected_s2_git_sha": claim.document["evidence_freeze_S2_sha"],
                "expected_s3_git_sha": claim.document["analysis_source_S3_sha"],
            }  # type: ignore[arg-type]
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "analysis dispatch failed or was ambiguous"
        ) from error
    if type(run_id) is not int or run_id <= 0:
        raise FollowupControllerError("analysis dispatch did not return one run ID")
    try:
        watch = provider.start_analysis_watch(
            provider_run_id=run_id,
            claim=claim,
        )
        session_sha256 = watch.session_sha256
        _sha256(session_sha256, field="analysis watcher session")
        binding = build_followup_analysis_watch_binding(
            claim,
            claim_oid=claim_oid,
            provider_run_id=run_id,
            watcher_session_sha256=session_sha256,
            workflow_ref=provider.analysis_workflow_ref,
        )
        binding_oid = provider.install_analysis_watch_binding(
            expected_claim_oid=claim_oid,
            expected_tree_oid=tree_oid,
            binding=binding,
        )
        if (
            type(binding_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(binding_oid) is None
        ):
            raise FollowupControllerError("analysis watch binding OID changed")
        admission = build_followup_analysis_run_admission(
            claim,
            binding,
            binding_oid=binding_oid,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError(
            "analysis watcher could not be armed before provider admission"
        ) from error
    try:
        outcome = watch.wait()
        if (
            type(outcome) is not FollowupAnalysisWatchOutcome
            or outcome.provider_run_id != run_id
            or outcome.watcher_session_sha256 != session_sha256
        ):
            raise FollowupControllerError("analysis watcher outcome changed")
        outcome_oid = provider.install_analysis_outcome(
            expected_binding_oid=binding_oid,
            expected_tree_oid=tree_oid,
            outcome=outcome,
        )
        if (
            type(outcome_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(outcome_oid) is None
        ):
            raise FollowupControllerError("analysis outcome OID changed")
        journal.finalize(
            provider_run_id=run_id,
            claim_oid=claim_oid,
            binding_oid=binding_oid,
            outcome_oid=outcome_oid,
            binding=binding,
            admission=admission,
            outcome=outcome,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError("analysis outcome failed closed") from error
    return FollowupAnalysisExecutionResult(
        decision=(
            "publication-results-ready"
            if outcome.decision == "success"
            else "no-go"
        ),
        provider_run_id=run_id,
        claim_oid=claim_oid,
        binding_oid=binding_oid,
        outcome_oid=outcome_oid,
        claim=claim,
        watch_binding=binding,
        run_admission=admission,
        watch_outcome=outcome,
        evidence_root=journal.root,
    )
