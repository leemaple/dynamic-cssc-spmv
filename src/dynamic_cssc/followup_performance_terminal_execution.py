"""Atomic terminal dispatch, mandatory watch, and authority-false closure.

The seventeen-unit campaign is not publication evidence by itself.  This
module owns the only transition from a deeply inspected campaign journal to
one terminal admission/aggregate run.  The external watcher is started before
its provider binding is installed, and every non-success closes NO-GO without
retry.
"""

from __future__ import annotations

import hashlib
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from dynamic_cssc.followup_performance_campaign_execution import (
    FollowupCampaignExecutionResult,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
    build_followup_campaign_transport,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_controller import FollowupControllerError
from dynamic_cssc.followup_performance_terminal_binding import (
    FollowupTerminalClaim,
    FollowupTerminalRunAdmission,
    FollowupTerminalWatchBinding,
    build_followup_terminal_claim,
    build_followup_terminal_run_admission,
    build_followup_terminal_watch_binding,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FollowupTerminalArtifactBinding",
    "FollowupTerminalExecutionProvider",
    "FollowupTerminalExecutionResult",
    "FollowupTerminalPhaseReceipt",
    "FollowupTerminalWatch",
    "FollowupTerminalWatchOutcome",
    "build_followup_terminal_watch_outcome",
    "execute_followup_terminal",
    "inspect_followup_terminal_phase_receipt",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TERMINAL_ARTIFACT = re.compile(
    r"followup-performance-v1-formal-terminal-admission-[a-z0-9-]+\Z"
)
_AGGREGATE_ARTIFACT = re.compile(
    r"followup-performance-v1-formal-aggregate-[a-z0-9-]+\Z"
)
_WATCH_RECEIPT_SCHEMA = (
    "dynamic-cssc-followup-performance-terminal-watcher-receipt-v1"
)
_PHASE_RECEIPT_SCHEMA = (
    "dynamic-cssc-followup-performance-terminal-phase-receipt-v1"
)
_TERMINAL_LIMIT_SECONDS = 30 * 60


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupControllerError(f"{field} is not a lowercase SHA-256")
    return value


def _render_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FollowupControllerError("terminal watcher time lacks UTC")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class FollowupTerminalArtifactBinding:
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


def _artifact(
    value: FollowupTerminalArtifactBinding,
    *,
    expected_name: re.Pattern[str],
    label: str,
) -> FollowupTerminalArtifactBinding:
    if (
        type(value) is not FollowupTerminalArtifactBinding
        or type(value.provider_artifact_id) is not int
        or value.provider_artifact_id <= 0
        or type(value.artifact_name) is not str
        or expected_name.fullmatch(value.artifact_name) is None
        or type(value.provider_digest) is not str
        or _PROVIDER_DIGEST.fullmatch(value.provider_digest) is None
        or type(value.size_in_bytes) is not int
        or value.size_in_bytes <= 0
    ):
        raise FollowupControllerError(f"{label} provider binding changed")
    return value


@dataclass(frozen=True, slots=True)
class FollowupTerminalPhaseReceipt:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def inspect_followup_terminal_phase_receipt(
    content: bytes,
    *,
    expected_formal_timing_ledger_sha256: str,
) -> FollowupTerminalPhaseReceipt:
    """Parse the sole canonical receipt printed before provider uploads."""

    _sha256(
        expected_formal_timing_ledger_sha256,
        field="expected formal timing ledger",
    )
    if type(content) is not bytes or not content or len(content) > 64 * 1024:
        raise FollowupControllerError("terminal phase receipt bytes changed")
    value = _parse_ascii_json(content, label="terminal phase receipt")
    if (
        type(value) is not dict
        or set(value) != {"aggregate", "schema_version", "terminal"}
        or value.get("schema_version") != _PHASE_RECEIPT_SCHEMA
    ):
        raise FollowupControllerError("terminal phase receipt projection changed")
    terminal = value.get("terminal")
    aggregate = value.get("aggregate")
    if (
        type(terminal) is not dict
        or set(terminal)
        != {
            "artifact_name",
            "formal_artifact_set_sha256",
            "formal_timing_ledger_sha256",
            "unit_identity_sha256",
        }
        or type(aggregate) is not dict
        or set(aggregate)
        != {"aggregate_sha256", "artifact_name", "unit_identity_sha256"}
        or type(terminal.get("artifact_name")) is not str
        or _TERMINAL_ARTIFACT.fullmatch(terminal["artifact_name"]) is None
        or type(aggregate.get("artifact_name")) is not str
        or _AGGREGATE_ARTIFACT.fullmatch(aggregate["artifact_name"]) is None
        or terminal.get("formal_timing_ledger_sha256")
        != expected_formal_timing_ledger_sha256
    ):
        raise FollowupControllerError("terminal phase receipt identity changed")
    for field, candidate in (
        ("formal artifact set", terminal.get("formal_artifact_set_sha256")),
        ("terminal unit identity", terminal.get("unit_identity_sha256")),
        ("aggregate payload", aggregate.get("aggregate_sha256")),
        ("aggregate unit identity", aggregate.get("unit_identity_sha256")),
    ):
        _sha256(candidate, field=field)
    canonical = _canonical_json_bytes(value)
    return FollowupTerminalPhaseReceipt(
        document=value,
        document_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FollowupTerminalWatchOutcome:
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
    terminal_artifact_or_null: FollowupTerminalArtifactBinding | None
    aggregate_artifact_or_null: FollowupTerminalArtifactBinding | None
    cancellation_requested_at_or_null: datetime | None
    cancellation_acknowledged_at_or_null: datetime | None
    no_go_reason_or_null: str | None


def build_followup_terminal_watch_outcome(
    *,
    claim: FollowupTerminalClaim,
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
    terminal_artifact_or_null: FollowupTerminalArtifactBinding | None,
    aggregate_artifact_or_null: FollowupTerminalArtifactBinding | None,
    cancellation_requested_at_or_null: datetime | None,
    cancellation_acknowledged_at_or_null: datetime | None,
    no_go_reason_or_null: str | None,
) -> FollowupTerminalWatchOutcome:
    """Construct the closed watcher receipt from raw provider observations."""

    if (
        type(claim) is not FollowupTerminalClaim
        or type(provider_run_id) is not int
        or provider_run_id <= 0
    ):
        raise FollowupControllerError("terminal watcher identity changed")
    _sha256(watcher_session_sha256, field="terminal watcher session")
    for content in (
        provider_run_json,
        provider_jobs_json,
        provider_artifacts_json,
    ):
        if type(content) is not bytes or not content or len(content) > 8 * 1024 * 1024:
            raise FollowupControllerError("terminal provider evidence bytes changed")
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
        raise FollowupControllerError("terminal cancellation ledger changed")
    runner_seconds: int | None = None
    phase: FollowupTerminalPhaseReceipt | None = None
    if decision == "success":
        if (
            job_started_at_or_null is None
            or job_completed_at_or_null is None
            or job_completed_at_or_null < job_started_at_or_null
            or cancellation_requested_at_or_null is not None
            or no_go_reason_or_null is not None
            or provider_phase_receipt_bytes_or_null is None
            or terminal_artifact_or_null is None
            or aggregate_artifact_or_null is None
        ):
            raise FollowupControllerError("successful terminal watcher changed")
        runner_seconds = int(
            (job_completed_at_or_null - job_started_at_or_null).total_seconds()
        )
        if not 0 <= runner_seconds <= _TERMINAL_LIMIT_SECONDS:
            raise FollowupControllerError("terminal runner budget was exceeded")
        terminal_artifact = _artifact(
            terminal_artifact_or_null,
            expected_name=_TERMINAL_ARTIFACT,
            label="terminal admission artifact",
        )
        aggregate_artifact = _artifact(
            aggregate_artifact_or_null,
            expected_name=_AGGREGATE_ARTIFACT,
            label="terminal aggregate artifact",
        )
        if terminal_artifact.provider_artifact_id == aggregate_artifact.provider_artifact_id:
            raise FollowupControllerError("terminal provider artifacts are duplicated")
        phase = inspect_followup_terminal_phase_receipt(
            provider_phase_receipt_bytes_or_null,
            expected_formal_timing_ledger_sha256=claim.document[
                "formal_timing_ledger_sha256"
            ],  # type: ignore[arg-type]
        )
        terminal_name = phase.document["terminal"]["artifact_name"]  # type: ignore[index]
        aggregate_name = phase.document["aggregate"]["artifact_name"]  # type: ignore[index]
        if (
            terminal_artifact.artifact_name != terminal_name
            or aggregate_artifact.artifact_name != aggregate_name
        ):
            raise FollowupControllerError(
                "terminal phase receipt does not bind provider artifacts"
            )
    elif decision == "no-go":
        if (
            type(no_go_reason_or_null) is not str
            or not no_go_reason_or_null
            or provider_phase_receipt_bytes_or_null is not None
            or terminal_artifact_or_null is not None
            or aggregate_artifact_or_null is not None
        ):
            raise FollowupControllerError("terminal NO-GO watcher changed")
        if (
            job_started_at_or_null is not None
            and job_completed_at_or_null is not None
            and job_completed_at_or_null >= job_started_at_or_null
        ):
            runner_seconds = int(
                (job_completed_at_or_null - job_started_at_or_null).total_seconds()
            )
    else:  # pragma: no cover - protected by the Literal call sites
        raise FollowupControllerError("terminal watcher decision changed")
    receipt_document = {
        "aggregate_artifact_or_null": (
            None
            if aggregate_artifact_or_null is None
            else aggregate_artifact_or_null.document
        ),
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
        "schema_version": _WATCH_RECEIPT_SCHEMA,
        "study_id": FOLLOWUP_STUDY_ID,
        "terminal_artifact_or_null": (
            None
            if terminal_artifact_or_null is None
            else terminal_artifact_or_null.document
        ),
        "terminal_claim_sha256": claim.sha256,
        "terminal_phase_receipt_sha256_or_null": (
            None if phase is None else phase.sha256
        ),
        "watcher_session_sha256": watcher_session_sha256,
    }
    receipt_bytes = _canonical_json_bytes(receipt_document)
    return FollowupTerminalWatchOutcome(
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
        terminal_artifact_or_null=terminal_artifact_or_null,
        aggregate_artifact_or_null=aggregate_artifact_or_null,
        cancellation_requested_at_or_null=cancellation_requested_at_or_null,
        cancellation_acknowledged_at_or_null=cancellation_acknowledged_at_or_null,
        no_go_reason_or_null=no_go_reason_or_null,
    )


class FollowupTerminalWatch(Protocol):
    @property
    def session_sha256(self) -> str: ...

    def wait(self) -> FollowupTerminalWatchOutcome: ...


class FollowupTerminalExecutionProvider(Protocol):
    @property
    def terminal_workflow_ref(self) -> str: ...

    def open_terminal(
        self,
        claim: FollowupTerminalClaim,
        transport: FollowupCampaignTransport,
    ) -> tuple[str, str]: ...

    def dispatch_terminal_run(self, *, inputs: dict[str, str]) -> int: ...

    def start_terminal_watch(
        self,
        *,
        provider_run_id: int,
        claim: FollowupTerminalClaim,
    ) -> FollowupTerminalWatch: ...

    def install_terminal_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupTerminalWatchBinding,
    ) -> str: ...

    def install_terminal_outcome(
        self,
        *,
        expected_binding_oid: str,
        expected_tree_oid: str,
        outcome: FollowupTerminalWatchOutcome,
    ) -> str: ...

    def cancel_terminal_run(self, provider_run_id: int) -> None: ...


@dataclass(frozen=True, slots=True)
class FollowupTerminalExecutionResult:
    decision: Literal["ready-for-analysis", "no-go"]
    provider_run_id: int
    claim_oid: str
    binding_oid: str
    outcome_oid: str
    claim: FollowupTerminalClaim
    watch_binding: FollowupTerminalWatchBinding
    run_admission: FollowupTerminalRunAdmission
    watch_outcome: FollowupTerminalWatchOutcome
    evidence_root: Path


def _best_effort_cancel(
    provider: FollowupTerminalExecutionProvider,
    provider_run_id: int | None,
) -> None:
    if provider_run_id is None:
        return
    with suppress(AttributeError, OSError, RuntimeError, TypeError, ValueError):
        provider.cancel_terminal_run(provider_run_id)


def execute_followup_terminal(
    campaign: FollowupCampaignExecutionResult,
    *,
    scientific_profile: RouteAScientificProfile,
    provider: FollowupTerminalExecutionProvider,
    evidence_root: Path,
) -> FollowupTerminalExecutionResult:
    """Run the sole terminal admission/aggregate transaction after 17 units."""

    if (
        type(campaign) is not FollowupCampaignExecutionResult
        or campaign.decision != "ready-for-terminal"
        or campaign.selection is None
        or campaign.timing is None
        or type(scientific_profile) is not RouteAScientificProfile
        or _LOWER_GIT_SHA.fullmatch(campaign.progress_oid) is None
    ):
        raise FollowupControllerError("terminal campaign input changed")
    transport = build_followup_campaign_transport(
        campaign.evidence_root,
        scientific_profile=scientific_profile,
    )
    state = campaign.final_state.document
    claim = build_followup_terminal_claim(
        campaign_id=state["campaign_id"],  # type: ignore[arg-type]
        experiment_source_s1_sha=state["experiment_source_S1_sha"],  # type: ignore[arg-type]
        evidence_freeze_s2_sha=state["evidence_freeze_S2_sha"],  # type: ignore[arg-type]
        compatibility_receipt_sha256=state[
            "compatibility_receipt_sha256"
        ],  # type: ignore[arg-type]
        final_progress_oid=campaign.progress_oid,
        campaign_selection_sha256=campaign.selection.sha256,
        formal_timing_ledger_sha256=campaign.timing.sha256,
        campaign_transport_sha256=transport.sha256,
        campaign_transport_member_count=transport.member_count,
        campaign_transport_expanded_bytes=transport.expanded_bytes,
    )
    from dynamic_cssc.followup_performance_terminal_evidence import (
        FollowupTerminalEvidenceJournal,
    )

    journal = FollowupTerminalEvidenceJournal(
        evidence_root,
        claim=claim,
        transport=transport,
    )
    try:
        claim_oid, tree_oid = provider.open_terminal(claim, transport)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "terminal provider claim failed or was ambiguous"
        ) from error
    if (
        type(claim_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(claim_oid) is None
        or type(tree_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
    ):
        raise FollowupControllerError("terminal provider claim identity changed")
    run_id: int | None = None
    try:
        run_id = provider.dispatch_terminal_run(
            inputs={
                "expected_campaign_id": claim.document["campaign_id"],
                "expected_compatibility_receipt_sha256": claim.document[
                    "compatibility_receipt_sha256"
                ],
                "expected_s1_git_sha": claim.document[
                    "experiment_source_S1_sha"
                ],
                "expected_s2_git_sha": claim.document["evidence_freeze_S2_sha"],
                "expected_terminal_claim_oid": claim_oid,
            }  # type: ignore[arg-type]
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "terminal dispatch failed or was ambiguous"
        ) from error
    if type(run_id) is not int or run_id <= 0:
        raise FollowupControllerError("terminal dispatch did not return one run ID")
    try:
        watcher = provider.start_terminal_watch(
            provider_run_id=run_id,
            claim=claim,
        )
        session_sha256 = watcher.session_sha256
        _sha256(session_sha256, field="terminal watcher session")
        binding = build_followup_terminal_watch_binding(
            claim,
            claim_oid=claim_oid,
            provider_run_id=run_id,
            watcher_session_sha256=session_sha256,
            workflow_ref=provider.terminal_workflow_ref,
        )
        binding_oid = provider.install_terminal_watch_binding(
            expected_claim_oid=claim_oid,
            expected_tree_oid=tree_oid,
            binding=binding,
        )
        if (
            type(binding_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(binding_oid) is None
        ):
            raise FollowupControllerError("terminal watch binding OID changed")
        admission = build_followup_terminal_run_admission(
            claim,
            binding,
            binding_oid=binding_oid,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError(
            "terminal watcher could not be armed before provider admission"
        ) from error
    try:
        outcome = watcher.wait()
        if (
            type(outcome) is not FollowupTerminalWatchOutcome
            or outcome.provider_run_id != run_id
            or outcome.watcher_session_sha256 != session_sha256
        ):
            raise FollowupControllerError("terminal watcher outcome changed")
        outcome_oid = provider.install_terminal_outcome(
            expected_binding_oid=binding_oid,
            expected_tree_oid=tree_oid,
            outcome=outcome,
        )
        if (
            type(outcome_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(outcome_oid) is None
        ):
            raise FollowupControllerError("terminal outcome OID changed")
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
        raise FollowupControllerError("terminal outcome failed closed") from error
    return FollowupTerminalExecutionResult(
        decision=(
            "ready-for-analysis" if outcome.decision == "success" else "no-go"
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
