"""Strictly serial execution and durable evidence for the 17-unit campaign."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.followup_performance_campaign import (
    FollowupCampaignSelection,
    FollowupCampaignState,
    build_followup_campaign_selection,
    close_followup_campaign_no_go,
)
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupAcquisitionRunBinding,
    FollowupBoundUnitResult,
    FollowupCampaignControlError,
    FollowupCampaignProvider,
    dispatch_bind_watch,
)
from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
    followup_formal_unit_specs,
)
from dynamic_cssc.followup_performance_formal_timing import (
    FollowupFormalRunEvidence,
    FollowupFormalTimingLedger,
    inspect_followup_formal_attempt_runner_seconds,
    inspect_followup_formal_timing_campaign,
)
from dynamic_cssc.followup_performance_watcher_receipt import (
    FollowupFormalWatcherReceiptError,
    inspect_followup_formal_watcher_receipt,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FollowupCampaignExecutionResult",
    "FollowupCampaignJournal",
    "execute_followup_formal_campaign",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SEGMENT_LIMIT_SECONDS = {
    "acquisition-and-ordered": 180 * 60,
    "native": 150 * 60,
    "synthetic": 300 * 60,
}
_TERMINAL_RESERVATION_SECONDS = 30 * 60
_RETRY_RESERVATION_SECONDS = 60 * 60
_CAMPAIGN_ACCEPTANCE_SECONDS = 12 * 60 * 60


def _write_new(path: Path, content: bytes) -> None:
    if type(content) is not bytes or not content:
        raise FollowupCampaignControlError("campaign evidence content is empty")
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:  # pragma: no cover - os.write advances or raises
                raise FollowupCampaignControlError(
                    "campaign evidence write stalled"
                )
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _direct_empty_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute():
        raise FollowupCampaignControlError("campaign evidence path is not absolute")
    if create:
        if path.exists() or path.is_symlink():
            raise FollowupCampaignControlError(
                "campaign evidence root already exists"
            )
        parent = path.parent.resolve(strict=True)
        observed = parent.lstat()
        if parent.is_symlink() or not stat.S_ISDIR(observed.st_mode):
            raise FollowupCampaignControlError(
                "campaign evidence parent is not direct"
            )
        path.mkdir(mode=0o700)
    observed = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupCampaignControlError(
            "campaign evidence root is not a direct directory"
        )
    return path


class FollowupCampaignJournal:
    """Append-only local projection of provider facts needed by terminal review."""

    def __init__(
        self,
        root: Path,
        *,
        opened: FollowupCampaignState,
        initial_progress_oid: str,
        evidence_tree_oid: str,
    ) -> None:
        if (
            type(opened) is not FollowupCampaignState
            or opened.state != "campaign-open"
            or _LOWER_GIT_SHA.fullmatch(initial_progress_oid) is None
            or _LOWER_GIT_SHA.fullmatch(evidence_tree_oid) is None
        ):
            raise FollowupCampaignControlError(
                "campaign journal opening identity changed"
            )
        self.root = _direct_empty_directory(root, create=True)
        self._attempts = self.root / "attempts"
        self._attempts.mkdir(mode=0o700)
        _write_new(self.root / "campaign-open.json", opened.document_bytes)
        _write_new(
            self.root / "campaign-open-controller.json",
            _canonical_json_bytes(
                {
                    "authority": False,
                    "campaign_id": opened.document["campaign_id"],
                    "evidence_tree_oid": evidence_tree_oid,
                    "initial_progress_oid": initial_progress_oid,
                    "publication_evidence_admitted": False,
                    "schema_version": (
                        "dynamic-cssc-followup-performance-campaign-open-controller-v1"
                    ),
                }
            ),
        )

    def record_attempt(
        self,
        result: FollowupBoundUnitResult,
        *,
        evidence_tree_oid: str,
    ) -> None:
        if (
            type(result) is not FollowupBoundUnitResult
            or _LOWER_GIT_SHA.fullmatch(evidence_tree_oid) is None
        ):
            raise FollowupCampaignControlError(
                "campaign journal attempt identity changed"
            )
        terminal = result.terminal_state.document
        ordinal = terminal["unit_ordinal_or_null"]
        attempt = terminal["unit_attempt_ordinal_or_null"]
        if type(ordinal) is not int or type(attempt) is not int:
            raise FollowupCampaignControlError(
                "campaign terminal attempt lacks its ordinal"
            )
        target = self._attempts / f"{ordinal:02d}-attempt-{attempt}"
        target.mkdir(mode=0o700)
        files = {
            "artifacts.json": result.outcome.provider_artifacts_json,
            "binding-state.json": result.binding_state.document_bytes,
            "jobs.json": result.outcome.provider_jobs_json,
            "reservation-state.json": result.reservation_state.document_bytes,
            "run-admission.json": result.run_admission.document_bytes,
            "run.json": result.outcome.provider_run_json,
            "terminal-state.json": result.terminal_state.document_bytes,
            "watch-armed-state.json": result.watch_armed_state.document_bytes,
            "watcher-receipt.json": result.outcome.watcher_receipt_bytes,
        }
        if result.outcome.provider_guard_receipt_bytes_or_null is not None:
            files["guard-receipt.json"] = (
                result.outcome.provider_guard_receipt_bytes_or_null
            )
        if result.outcome.provider_failure_evidence_bytes_or_null is not None:
            files["provider-failure.json"] = (
                result.outcome.provider_failure_evidence_bytes_or_null
            )
        for name, content in files.items():
            _write_new(target / name, content)
        _write_new(
            target / "controller.json",
            _canonical_json_bytes(
                {
                    "authority": False,
                    "binding_oid": result.binding_oid,
                    "campaign_run_admission_sha256": result.run_admission.sha256,
                    "decision": result.outcome.decision,
                    "evidence_tree_oid": evidence_tree_oid,
                    "provider_run_id": result.provider_run_id,
                    "publication_evidence_admitted": False,
                    "reservation_oid": result.reservation_oid,
                    "schema_version": (
                        "dynamic-cssc-followup-performance-attempt-controller-v1"
                    ),
                    "terminal_oid": result.terminal_oid,
                    "terminal_state_sha256": result.terminal_state.sha256,
                    "watch_armed_oid": result.watch_armed_oid,
                }
            ),
        )

    def record_no_go(
        self,
        state: FollowupCampaignState,
        *,
        progress_oid: str,
    ) -> None:
        if (
            type(state) is not FollowupCampaignState
            or state.state != "campaign-no-go"
            or _LOWER_GIT_SHA.fullmatch(progress_oid) is None
        ):
            raise FollowupCampaignControlError("campaign NO-GO journal changed")
        _write_new(self.root / "campaign-no-go.json", state.document_bytes)
        _write_new(
            self.root / "campaign-no-go-controller.json",
            _canonical_json_bytes(
                {
                    "authority": False,
                    "campaign_id": state.document["campaign_id"],
                    "progress_oid": progress_oid,
                    "publication_evidence_admitted": False,
                    "schema_version": (
                        "dynamic-cssc-followup-performance-campaign-no-go-controller-v1"
                    ),
                    "terminal_reason_code": state.document[
                        "terminal_reason_code_or_null"
                    ],
                }
            ),
        )

    def finalize(
        self,
        *,
        selection: FollowupCampaignSelection,
        timing: FollowupFormalTimingLedger,
        committed_states: tuple[FollowupCampaignState, ...],
    ) -> None:
        if (
            type(selection) is not FollowupCampaignSelection
            or type(timing) is not FollowupFormalTimingLedger
            or type(committed_states) is not tuple
            or len(committed_states) != 17
        ):
            raise FollowupCampaignControlError(
                "campaign journal finalization changed"
            )
        committed_root = self.root / "committed-states"
        committed_root.mkdir(mode=0o700)
        for ordinal, state in enumerate(committed_states):
            if (
                type(state) is not FollowupCampaignState
                or state.state != "unit-committed"
                or state.document["unit_ordinal_or_null"] != ordinal
            ):
                raise FollowupCampaignControlError(
                    "campaign committed-state sequence changed"
                )
            _write_new(committed_root / f"{ordinal:02d}.json", state.document_bytes)
        _write_new(self.root / "selection.json", selection.document_bytes)
        _write_new(self.root / "timing-ledger.json", timing.document_bytes)


@dataclass(frozen=True, slots=True)
class FollowupCampaignExecutionResult:
    decision: Literal["ready-for-terminal", "no-go"]
    final_state: FollowupCampaignState
    progress_oid: str
    selection: FollowupCampaignSelection | None
    timing: FollowupFormalTimingLedger | None
    evidence_root: Path


def _artifact_count(content: bytes) -> int:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupCampaignControlError(
            "provider artifact inventory is unreadable"
        ) from error
    if (
        type(value) is not dict
        or type(value.get("artifacts")) is not list
        or type(value.get("total_count")) is not int
        or value["total_count"] != len(value["artifacts"])
    ):
        raise FollowupCampaignControlError(
            "provider artifact inventory is incomplete"
        )
    return value["total_count"]


def _acquisition_binding(
    committed: tuple[FollowupCampaignState, ...],
    admissions: tuple[str, ...],
) -> FollowupAcquisitionRunBinding:
    if len(committed) < 1 or len(admissions) < 1:
        raise FollowupCampaignControlError(
            "ordered unit lacks a committed acquisition"
        )
    acquisition = committed[0].document
    return FollowupAcquisitionRunBinding(
        artifact_name=acquisition["artifact_name_or_null"],  # type: ignore[arg-type]
        provider_run_id=acquisition["provider_run_id_or_null"],  # type: ignore[arg-type]
        provider_artifact_id=acquisition["artifact_id_or_null"],  # type: ignore[arg-type]
        provider_artifact_digest=acquisition[
            "artifact_provider_digest_or_null"
        ],  # type: ignore[arg-type]
        campaign_run_admission_sha256=admissions[0],
        unit_attempt_ordinal=acquisition[
            "unit_attempt_ordinal_or_null"
        ],  # type: ignore[arg-type]
    )


def _reserve_is_safe(
    specs: tuple[FollowupFormalUnitSpec, ...],
    *,
    next_ordinal: int,
    segment_seconds: dict[str, int],
    retry_seconds: int,
    retry_used: bool,
) -> bool:
    remaining_by_segment = {
        segment: sum(
            spec.reservation_minutes * 60
            for spec in specs[next_ordinal:]
            if spec.segment == segment
        )
        for segment in _SEGMENT_LIMIT_SECONDS
    }
    if any(
        segment_seconds[segment] + remaining_by_segment[segment] > limit
        for segment, limit in _SEGMENT_LIMIT_SECONDS.items()
    ):
        return False
    ordinary = sum(segment_seconds.values()) + sum(
        spec.reservation_minutes * 60 for spec in specs[next_ordinal:]
    )
    return (
        ordinary
        + _TERMINAL_RESERVATION_SECONDS
        + (
            max(retry_seconds, 0)
            if retry_used
            else _RETRY_RESERVATION_SECONDS
        )
        <= _CAMPAIGN_ACCEPTANCE_SECONDS
    )


def _close_no_go(
    previous: FollowupCampaignState,
    *,
    previous_oid: str,
    evidence_tree_oid: str,
    reason: str,
    provider: FollowupCampaignProvider,
    journal: FollowupCampaignJournal,
) -> FollowupCampaignExecutionResult:
    terminal = close_followup_campaign_no_go(
        previous,
        terminal_reason_code=reason,
    )
    terminal_oid = provider.install_campaign_state(
        expected_oid=previous_oid,
        expected_tree_oid=evidence_tree_oid,
        state=terminal,
    )
    journal.record_no_go(terminal, progress_oid=terminal_oid)
    return FollowupCampaignExecutionResult(
        decision="no-go",
        final_state=terminal,
        progress_oid=terminal_oid,
        selection=None,
        timing=None,
        evidence_root=journal.root,
    )


def execute_followup_formal_campaign(
    opened: FollowupCampaignState,
    *,
    progress_oid: str,
    evidence_tree_oid: str,
    scientific_profile: RouteAScientificProfile,
    provider: FollowupCampaignProvider,
    evidence_root: Path,
) -> FollowupCampaignExecutionResult:
    """Run exactly 17 serial units, the optional sole replacement, then close."""

    if (
        type(opened) is not FollowupCampaignState
        or opened.state != "campaign-open"
        or type(scientific_profile) is not RouteAScientificProfile
        or _LOWER_GIT_SHA.fullmatch(progress_oid) is None
        or _LOWER_GIT_SHA.fullmatch(evidence_tree_oid) is None
    ):
        raise FollowupCampaignControlError("formal campaign opening changed")
    specs = followup_formal_unit_specs(scientific_profile)
    journal = FollowupCampaignJournal(
        evidence_root,
        opened=opened,
        initial_progress_oid=progress_oid,
        evidence_tree_oid=evidence_tree_oid,
    )
    previous = opened
    current_oid = progress_oid
    committed: list[FollowupCampaignState] = []
    admissions: list[str] = []
    timing_evidence: list[FollowupFormalRunEvidence] = []
    segment_seconds = {segment: 0 for segment in _SEGMENT_LIMIT_SECONDS}
    retry_seconds = 0
    for spec in specs:
        if not _reserve_is_safe(
            specs,
            next_ordinal=spec.ordinal,
            segment_seconds=segment_seconds,
            retry_seconds=retry_seconds,
            retry_used=previous.document["retry_used"] is True,
        ):
            return _close_no_go(
                previous,
                previous_oid=current_oid,
                evidence_tree_oid=evidence_tree_oid,
                reason="budget-exhausted",
                provider=provider,
                journal=journal,
            )
        acquisition = (
            _acquisition_binding(tuple(committed), tuple(admissions))
            if spec.unit_kind == "formal-ordered-event"
            else None
        )
        result = dispatch_bind_watch(
            previous,
            progress_oid=current_oid,
            evidence_tree_oid=evidence_tree_oid,
            spec=spec,
            unit_attempt_ordinal=1,
            provider=provider,
            acquisition=acquisition,
        )
        journal.record_attempt(result, evidence_tree_oid=evidence_tree_oid)
        timing_evidence.append(
            FollowupFormalRunEvidence(
                unit_ordinal=spec.ordinal,
                unit_attempt_ordinal=1,
                run_json=result.outcome.provider_run_json,
                jobs_json=result.outcome.provider_jobs_json,
                watcher_receipt_json=result.outcome.watcher_receipt_bytes,
                terminal_campaign_state_bytes=result.terminal_state.document_bytes,
            )
        )
        attempt_seconds = inspect_followup_formal_attempt_runner_seconds(
            result.outcome.provider_jobs_json,
            expected_run_id=result.provider_run_id,
            spec=spec,
        )
        if result.terminal_state.state == "campaign-no-go":
            journal.record_no_go(
                result.terminal_state,
                progress_oid=result.terminal_oid,
            )
            return FollowupCampaignExecutionResult(
                decision="no-go",
                final_state=result.terminal_state,
                progress_oid=result.terminal_oid,
                selection=None,
                timing=None,
                evidence_root=journal.root,
            )
        if result.terminal_state.state == "unit-provider-failed":
            try:
                failed_receipt = inspect_followup_formal_watcher_receipt(
                    result.outcome.watcher_receipt_bytes
                )
            except FollowupFormalWatcherReceiptError:
                return _close_no_go(
                    result.terminal_state,
                    previous_oid=result.terminal_oid,
                    evidence_tree_oid=evidence_tree_oid,
                    reason="nonretryable-provider-failure",
                    provider=provider,
                    journal=journal,
                )
            if (
                failed_receipt.document["decision"] != "provider-failure"
                or failed_receipt.cancellation_ledger is not None
            ):
                return _close_no_go(
                    result.terminal_state,
                    previous_oid=result.terminal_oid,
                    evidence_tree_oid=evidence_tree_oid,
                    reason="nonretryable-provider-failure",
                    provider=provider,
                    journal=journal,
                )
            ordinary_unspent = max(
                spec.reservation_minutes * 60
                - min(attempt_seconds, spec.reservation_minutes * 60),
                0,
            )
            retry_remaining = _RETRY_RESERVATION_SECONDS - retry_seconds - max(
                attempt_seconds - spec.reservation_minutes * 60,
                0,
            )
            acquisition_retry_safe = not (
                spec.unit_kind == "formal-acquisition"
                and _artifact_count(result.outcome.provider_artifacts_json) != 0
            )
            if (
                not acquisition_retry_safe
                or retry_remaining < 0
                or ordinary_unspent + retry_remaining
                < spec.reservation_minutes * 60
            ):
                return _close_no_go(
                    result.terminal_state,
                    previous_oid=result.terminal_oid,
                    evidence_tree_oid=evidence_tree_oid,
                    reason="retry-budget-insufficient",
                    provider=provider,
                    journal=journal,
                )
            replacement = dispatch_bind_watch(
                result.terminal_state,
                progress_oid=result.terminal_oid,
                evidence_tree_oid=evidence_tree_oid,
                spec=spec,
                unit_attempt_ordinal=2,
                provider=provider,
                acquisition=acquisition,
            )
            journal.record_attempt(replacement, evidence_tree_oid=evidence_tree_oid)
            timing_evidence.append(
                FollowupFormalRunEvidence(
                    unit_ordinal=spec.ordinal,
                    unit_attempt_ordinal=2,
                    run_json=replacement.outcome.provider_run_json,
                    jobs_json=replacement.outcome.provider_jobs_json,
                    watcher_receipt_json=replacement.outcome.watcher_receipt_bytes,
                    terminal_campaign_state_bytes=(
                        replacement.terminal_state.document_bytes
                    ),
                )
            )
            attempt_seconds += inspect_followup_formal_attempt_runner_seconds(
                replacement.outcome.provider_jobs_json,
                expected_run_id=replacement.provider_run_id,
                spec=spec,
            )
            result = replacement
            if result.terminal_state.state != "unit-committed":
                if result.terminal_state.state != "campaign-no-go":
                    return _close_no_go(
                        result.terminal_state,
                        previous_oid=result.terminal_oid,
                        evidence_tree_oid=evidence_tree_oid,
                        reason="nonretryable-provider-failure",
                        provider=provider,
                        journal=journal,
                    )
                journal.record_no_go(
                    result.terminal_state,
                    progress_oid=result.terminal_oid,
                )
                return FollowupCampaignExecutionResult(
                    decision="no-go",
                    final_state=result.terminal_state,
                    progress_oid=result.terminal_oid,
                    selection=None,
                    timing=None,
                    evidence_root=journal.root,
                )
        if result.terminal_state.state != "unit-committed":
            raise FollowupCampaignControlError(
                "formal unit did not reach one closed terminal state"
            )
        ordinary_charge = min(
            attempt_seconds,
            spec.reservation_minutes * 60,
        )
        retry_charge = max(
            attempt_seconds - spec.reservation_minutes * 60,
            0,
        )
        segment_seconds[spec.segment] += ordinary_charge
        retry_seconds += retry_charge
        if (
            segment_seconds[spec.segment]
            > _SEGMENT_LIMIT_SECONDS[spec.segment]
            or retry_seconds > _RETRY_RESERVATION_SECONDS
        ):
            return _close_no_go(
                result.terminal_state,
                previous_oid=result.terminal_oid,
                evidence_tree_oid=evidence_tree_oid,
                reason="budget-exhausted",
                provider=provider,
                journal=journal,
            )
        committed.append(result.terminal_state)
        admissions.append(result.run_admission.sha256)
        previous = result.terminal_state
        current_oid = result.terminal_oid
    try:
        selection = build_followup_campaign_selection(
            tuple(committed),
            tuple(admissions),
            scientific_profile=scientific_profile,
        )
        timing = inspect_followup_formal_timing_campaign(
            tuple(timing_evidence),
            campaign_selection=selection,
            scientific_profile=scientific_profile,
        )
        journal.finalize(
            selection=selection,
            timing=timing,
            committed_states=tuple(committed),
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return _close_no_go(
            previous,
            previous_oid=current_oid,
            evidence_tree_oid=evidence_tree_oid,
            reason="identity-invalid",
            provider=provider,
            journal=journal,
        )
    return FollowupCampaignExecutionResult(
        decision="ready-for-terminal",
        final_state=previous,
        progress_oid=current_oid,
        selection=selection,
        timing=timing,
        evidence_root=journal.root,
    )
