"""Consume, dispatch, watch, bind, and supervise the sole qualification."""

from __future__ import annotations

import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from dynamic_cssc.followup_performance_controller import (
    FollowupControllerError,
    FollowupDispatchPrerequisites,
    FollowupQualificationDispatchCapability,
    FollowupQualificationOpening,
    FollowupQualificationWatchResult,
    consume_followup_qualification_capability,
)
from dynamic_cssc.followup_performance_qualification_binding import (
    FollowupQualificationRunAdmission,
    FollowupQualificationWatchBinding,
    build_followup_qualification_run_admission,
    build_followup_qualification_watch_binding,
)
from dynamic_cssc.followup_performance_qualification_evidence import (
    FollowupQualificationEvidenceJournal,
    FollowupQualificationProviderEvidence,
)

__all__ = (
    "FollowupQualificationExecutionProvider",
    "FollowupQualificationExecutionResult",
    "FollowupQualificationWatch",
    "execute_followup_qualification",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FollowupQualificationWatch(Protocol):
    @property
    def session_sha256(self) -> str: ...

    def wait(self) -> FollowupQualificationWatchResult: ...


class FollowupQualificationExecutionProvider(Protocol):
    @property
    def qualification_workflow_ref(self) -> str: ...

    def open_qualification(
        self,
        opening: FollowupQualificationOpening,
    ) -> tuple[str, str]: ...

    def dispatch_qualification_run(self, *, inputs: dict[str, str]) -> int: ...

    def start_qualification_watch(
        self,
        *,
        provider_run_id: int,
        request: FollowupDispatchPrerequisites,
    ) -> FollowupQualificationWatch: ...

    def install_qualification_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupQualificationWatchBinding,
    ) -> str: ...

    def cancel_qualification(self, provider_run_id: int) -> None: ...

    def read_qualification_terminal_evidence(
        self,
        provider_run_id: int,
    ) -> FollowupQualificationProviderEvidence: ...


@dataclass(frozen=True, slots=True)
class FollowupQualificationExecutionResult:
    provider_run_id: int
    claim_oid: str
    binding_oid: str
    watch_binding: FollowupQualificationWatchBinding
    run_admission: FollowupQualificationRunAdmission
    watch_result: FollowupQualificationWatchResult
    evidence_root: Path


def _best_effort_cancel(
    provider: FollowupQualificationExecutionProvider,
    provider_run_id: int | None,
) -> None:
    if provider_run_id is None:
        return
    with suppress(AttributeError, OSError, RuntimeError, TypeError, ValueError):
        provider.cancel_qualification(provider_run_id)


def execute_followup_qualification(
    capability: FollowupQualificationDispatchCapability,
    request: FollowupDispatchPrerequisites,
    provider: FollowupQualificationExecutionProvider,
    *,
    evidence_root: Path,
) -> FollowupQualificationExecutionResult:
    """Perform the only allowed claim→dispatch→watch→CAS→terminal sequence."""

    journal = FollowupQualificationEvidenceJournal(evidence_root)
    opening = consume_followup_qualification_capability(capability, request)
    try:
        claim_oid, tree_oid = provider.open_qualification(opening)
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "qualification provider claim failed or was ambiguous"
        ) from error
    if (
        type(claim_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(claim_oid) is None
        or claim_oid != opening.evidence_freeze_s2_sha
        or type(tree_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
    ):
        raise FollowupControllerError("qualification provider claim identity changed")

    run_id: int | None = None
    try:
        run_id = provider.dispatch_qualification_run(
            inputs={
                "expected_authority_claim_oid": claim_oid,
                "expected_compatibility_receipt_sha256": (
                    opening.compatibility_receipt_sha256
                ),
                "expected_s1_git_sha": opening.experiment_source_s1_sha,
                "expected_s2_git_sha": opening.evidence_freeze_s2_sha,
            }
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "qualification dispatch failed or was ambiguous"
        ) from error
    if type(run_id) is not int or run_id <= 0:
        raise FollowupControllerError(
            "qualification dispatch did not return one exact run ID"
        )

    try:
        watcher = provider.start_qualification_watch(
            provider_run_id=run_id,
            request=request,
        )
        session_sha256 = watcher.session_sha256
        if (
            type(session_sha256) is not str
            or _LOWER_SHA256.fullmatch(session_sha256) is None
        ):
            raise FollowupControllerError(
                "qualification watcher session identity changed"
            )
        binding = build_followup_qualification_watch_binding(
            experiment_source_s1_sha=opening.experiment_source_s1_sha,
            evidence_freeze_s2_sha=opening.evidence_freeze_s2_sha,
            compatibility_receipt_sha256=opening.compatibility_receipt_sha256,
            provider_run_id=run_id,
            watcher_session_sha256=session_sha256,
            workflow_ref=provider.qualification_workflow_ref,
        )
        binding_oid = provider.install_qualification_watch_binding(
            expected_claim_oid=claim_oid,
            expected_tree_oid=tree_oid,
            binding=binding,
        )
        if (
            type(binding_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(binding_oid) is None
        ):
            raise FollowupControllerError(
                "qualification watch binding OID changed"
            )
        admission = build_followup_qualification_run_admission(
            binding,
            binding_oid=binding_oid,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError(
            "qualification watcher could not be armed before seed admission"
        ) from error

    try:
        watch_result = watcher.wait()
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError(
            "mandatory qualification watcher failed closed"
        ) from error
    if type(watch_result) is not FollowupQualificationWatchResult:
        _best_effort_cancel(provider, run_id)
        raise FollowupControllerError("qualification watcher result type changed")
    try:
        provider_evidence = provider.read_qualification_terminal_evidence(run_id)
        if type(provider_evidence) is not FollowupQualificationProviderEvidence:
            raise FollowupControllerError(
                "qualification provider evidence type changed"
            )
        journal.finalize(
            provider_run_id=run_id,
            claim_oid=claim_oid,
            binding_oid=binding_oid,
            watch_binding=binding,
            run_admission=admission,
            watch_result=watch_result,
            provider=provider_evidence,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise FollowupControllerError(
            "qualification terminal evidence could not be closed"
        ) from error
    return FollowupQualificationExecutionResult(
        provider_run_id=run_id,
        claim_oid=claim_oid,
        binding_oid=binding_oid,
        watch_binding=binding,
        run_admission=admission,
        watch_result=watch_result,
        evidence_root=journal.root,
    )
