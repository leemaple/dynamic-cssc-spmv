"""Durable controller and provider evidence for isolated S3 analysis."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisClaim,
    FollowupAnalysisRunAdmission,
    FollowupAnalysisWatchBinding,
    build_followup_analysis_run_admission,
    inspect_followup_analysis_claim,
    inspect_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_analysis_execution import (
    FollowupAnalysisWatchOutcome,
    inspect_followup_analysis_phase_receipt,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_controller import FollowupControllerError
from dynamic_cssc.followup_performance_formal_artifacts import (
    _direct_directory,
    _stable_read,
)

__all__ = (
    "FollowupAnalysisEvidenceBundle",
    "FollowupAnalysisEvidenceJournal",
    "inspect_followup_analysis_evidence_bundle",
)

_ANALYSIS_WORKFLOW = ".github/workflows/followup-performance-analysis.yml"
_ANALYSIS_JOB = "isolated-descriptive-analysis"
_BASE_MEMBERS = {
    "analysis-claim.json",
    "campaign-transport.json",
    "controller.json",
    "provider-artifacts.json",
    "provider-jobs.json",
    "provider-run.json",
    "run-admission.json",
    "watch-binding.json",
    "watcher-receipt.json",
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _render_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FollowupControllerError("analysis evidence time lacks UTC")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, *, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise FollowupControllerError(f"{field} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise FollowupControllerError(f"{field} is not canonical UTC") from error
    if _render_time(parsed) != value:
        raise FollowupControllerError(f"{field} is not canonical UTC")
    return parsed


def _write_new(path: Path, content: bytes) -> None:
    if type(content) is not bytes or not content:
        raise FollowupControllerError("analysis evidence content is empty")
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
            if count <= 0:  # pragma: no cover
                raise FollowupControllerError("analysis evidence write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new_root(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FollowupControllerError(
            "analysis evidence root must be a new absolute path"
        )
    parent = path.parent.resolve(strict=True)
    observed = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupControllerError(
            "analysis evidence parent is not a direct directory"
        )
    path.mkdir(mode=0o700)
    return path


def _object(content: bytes, *, label: str) -> dict[str, object]:
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict:
        raise FollowupControllerError(f"{label} is not one object")
    return value


def _read(path: Path, *, label: str) -> bytes:
    try:
        return _stable_read(path, maximum=8 * 1024 * 1024)
    except OSError as error:
        raise FollowupControllerError(f"{label} is unreadable") from error


class FollowupAnalysisEvidenceJournal:
    """Open before provider mutation and finalize once after outcome CAS."""

    def __init__(
        self,
        root: Path,
        *,
        claim: FollowupAnalysisClaim,
        transport: FollowupCampaignTransport,
    ) -> None:
        if (
            type(claim) is not FollowupAnalysisClaim
            or type(transport) is not FollowupCampaignTransport
            or claim.document.get("campaign_transport_sha256") != transport.sha256
            or claim.document.get("campaign_transport_member_count")
            != transport.member_count
            or claim.document.get("campaign_transport_expanded_bytes")
            != transport.expanded_bytes
        ):
            raise FollowupControllerError("analysis evidence opening changed")
        self.root = _new_root(root)
        self._claim = claim
        self._closed = False
        _write_new(self.root / "analysis-claim.json", claim.document_bytes)
        _write_new(
            self.root / "campaign-transport.json",
            _canonical_json_bytes(
                {
                    "authority": False,
                    "expanded_bytes": transport.expanded_bytes,
                    "member_count": transport.member_count,
                    "publication_evidence_admitted": False,
                    "schema_version": (
                        "dynamic-cssc-followup-performance-campaign-transport-record-v1"
                    ),
                    "sha256": transport.sha256,
                    "study_id": FOLLOWUP_STUDY_ID,
                }
            ),
        )

    def finalize(
        self,
        *,
        provider_run_id: int,
        claim_oid: str,
        binding_oid: str,
        outcome_oid: str,
        binding: FollowupAnalysisWatchBinding,
        admission: FollowupAnalysisRunAdmission,
        outcome: FollowupAnalysisWatchOutcome,
    ) -> None:
        if self._closed:
            raise FollowupControllerError("analysis evidence journal is closed")
        if (
            type(provider_run_id) is not int
            or provider_run_id <= 0
            or type(binding) is not FollowupAnalysisWatchBinding
            or type(admission) is not FollowupAnalysisRunAdmission
            or type(outcome) is not FollowupAnalysisWatchOutcome
            or binding.document.get("provider_run_id") != provider_run_id
            or admission.document.get("provider_run_id") != provider_run_id
            or outcome.provider_run_id != provider_run_id
            or binding.document.get("claim_oid") != claim_oid
            or admission.document.get("binding_oid") != binding_oid
        ):
            raise FollowupControllerError("analysis evidence identity changed")
        files = {
            "provider-artifacts.json": outcome.provider_artifacts_json,
            "provider-jobs.json": outcome.provider_jobs_json,
            "provider-run.json": outcome.provider_run_json,
            "run-admission.json": admission.document_bytes,
            "watch-binding.json": binding.document_bytes,
            "watcher-receipt.json": outcome.watcher_receipt_bytes,
        }
        if outcome.provider_phase_receipt_bytes_or_null is not None:
            files["phase-receipt.json"] = (
                outcome.provider_phase_receipt_bytes_or_null
            )
        for name, content in files.items():
            _write_new(self.root / name, content)
        controller = {
            "analysis_phase_receipt_sha256_or_null": (
                None
                if outcome.provider_phase_receipt_bytes_or_null is None
                else _sha256(outcome.provider_phase_receipt_bytes_or_null)
            ),
            "authority": False,
            "binding_oid": binding_oid,
            "campaign_id": self._claim.document["campaign_id"],
            "claim_oid": claim_oid,
            "decision": outcome.decision,
            "outcome_oid": outcome_oid,
            "provider_artifacts_json_sha256": _sha256(
                outcome.provider_artifacts_json
            ),
            "provider_jobs_json_sha256": _sha256(outcome.provider_jobs_json),
            "provider_observed_at": _render_time(outcome.provider_observed_at),
            "provider_run_id": provider_run_id,
            "provider_run_json_sha256": _sha256(outcome.provider_run_json),
            "publication_evidence_admitted": False,
            "run_admission_sha256": admission.sha256,
            "schema_version": (
                "dynamic-cssc-followup-performance-analysis-evidence-controller-v1"
            ),
            "study_id": FOLLOWUP_STUDY_ID,
            "watch_binding_sha256": binding.sha256,
            "watcher_receipt_sha256": outcome.watcher_receipt_sha256,
        }
        _write_new(self.root / "controller.json", _canonical_json_bytes(controller))
        self._closed = True


@dataclass(frozen=True, slots=True)
class FollowupAnalysisEvidenceBundle:
    root: Path
    claim: FollowupAnalysisClaim
    binding: FollowupAnalysisWatchBinding
    admission: FollowupAnalysisRunAdmission
    watcher_receipt: dict[str, object]
    phase_receipt: dict[str, object] | None
    controller: dict[str, object]


def _provider_rows(
    jobs: dict[str, object], artifacts: dict[str, object]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    job_rows = jobs.get("jobs")
    artifact_rows = artifacts.get("artifacts")
    if (
        type(job_rows) is not list
        or jobs.get("total_count") != len(job_rows)
        or len(job_rows) > 1
        or any(type(row) is not dict for row in job_rows)
        or type(artifact_rows) is not list
        or artifacts.get("total_count") != len(artifact_rows)
        or len(artifact_rows) > 1
        or any(type(row) is not dict for row in artifact_rows)
    ):
        raise FollowupControllerError("analysis provider inventory changed")
    return job_rows, artifact_rows  # type: ignore[return-value]


def _rebind_success(
    *,
    claim: FollowupAnalysisClaim,
    watcher: dict[str, object],
    run: dict[str, object],
    job_rows: list[dict[str, object]],
    artifact_rows: list[dict[str, object]],
    phase_content: bytes | None,
) -> dict[str, object]:
    if (
        run.get("conclusion") != "success"
        or len(job_rows) != 1
        or job_rows[0].get("name") != _ANALYSIS_JOB
        or job_rows[0].get("status") != "completed"
        or job_rows[0].get("conclusion") != "success"
        or len(artifact_rows) != 1
        or phase_content is None
        or watcher.get("no_go_reason_or_null") is not None
    ):
        raise FollowupControllerError("analysis success closure changed")
    started = _parse_time(
        job_rows[0].get("started_at"), field="analysis job startedAt"
    )
    completed = _parse_time(
        job_rows[0].get("completed_at"), field="analysis job completedAt"
    )
    seconds = int((completed - started).total_seconds())
    limit = claim.document["analysis_runner_seconds_limit"]
    terminal_seconds = claim.document["terminal_runner_seconds"]
    if (
        type(limit) is not int
        or type(terminal_seconds) is not int
        or completed < started
        or seconds > limit
        or terminal_seconds + seconds > 30 * 60
        or watcher.get("job_started_at_or_null") != _render_time(started)
        or watcher.get("job_completed_at_or_null") != _render_time(completed)
        or watcher.get("runner_seconds_or_null") != seconds
        or watcher.get("terminal_segment_seconds_or_null")
        != terminal_seconds + seconds
    ):
        raise FollowupControllerError("analysis shared time gate changed")
    expected_receipt = claim.document[
        "analysis_compatibility_receipt_sha256"
    ]
    if type(expected_receipt) is not str:
        raise FollowupControllerError("analysis compatibility identity changed")
    phase = inspect_followup_analysis_phase_receipt(
        phase_content,
        expected_analysis_compatibility_receipt_sha256=expected_receipt,
    )
    if watcher.get("analysis_phase_receipt_sha256_or_null") != phase.sha256:
        raise FollowupControllerError("analysis phase receipt hash changed")
    receipt_artifact = watcher.get("analysis_artifact_or_null")
    provider = artifact_rows[0]
    workflow_run = provider.get("workflow_run")
    if (
        type(receipt_artifact) is not dict
        or type(workflow_run) is not dict
        or receipt_artifact
        != {
            "artifact_name": provider.get("name"),
            "provider_artifact_id": provider.get("id"),
            "provider_digest": provider.get("digest"),
            "size_in_bytes": provider.get("size_in_bytes"),
        }
        or phase.document["artifact_name"] != provider.get("name")
        or provider.get("expired") is not False
        or workflow_run.get("id") != watcher["provider_run_id"]
        or workflow_run.get("head_sha")
        != claim.document["analysis_source_S3_sha"]
    ):
        raise FollowupControllerError("analysis provider artifact changed")
    return phase.document


def inspect_followup_analysis_evidence_bundle(
    root: Path,
) -> FollowupAnalysisEvidenceBundle:
    """Rebind the controller record to exact provider analysis facts."""

    root = _direct_directory(root, label="follow-up analysis evidence root")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) not in (
        _BASE_MEMBERS,
        _BASE_MEMBERS | {"phase-receipt.json"},
    ):
        raise FollowupControllerError("analysis evidence member set changed")
    contents = {name: _read(path, label=name) for name, path in entries.items()}
    claim = inspect_followup_analysis_claim(contents["analysis-claim.json"])
    binding = inspect_followup_analysis_watch_binding(
        contents["watch-binding.json"]
    )
    admission_document = _object(
        contents["run-admission.json"], label="analysis run admission"
    )
    binding_oid = admission_document.get("binding_oid")
    if type(binding_oid) is not str:
        raise FollowupControllerError("analysis admission binding OID changed")
    admission = build_followup_analysis_run_admission(
        claim,
        binding,
        binding_oid=binding_oid,
    )
    if admission.document_bytes != contents["run-admission.json"]:
        raise FollowupControllerError("analysis run admission changed")
    transport = _object(
        contents["campaign-transport.json"], label="campaign transport record"
    )
    watcher = _object(
        contents["watcher-receipt.json"], label="analysis watcher receipt"
    )
    controller = _object(contents["controller.json"], label="analysis controller")
    run = _object(contents["provider-run.json"], label="analysis provider run")
    jobs = _object(contents["provider-jobs.json"], label="analysis provider jobs")
    artifacts = _object(
        contents["provider-artifacts.json"], label="analysis provider artifacts"
    )
    if (
        _canonical_json_bytes(transport) != contents["campaign-transport.json"]
        or transport.get("sha256") != claim.document["campaign_transport_sha256"]
        or transport.get("member_count")
        != claim.document["campaign_transport_member_count"]
        or transport.get("expanded_bytes")
        != claim.document["campaign_transport_expanded_bytes"]
        or transport.get("authority") is not False
        or transport.get("publication_evidence_admitted") is not False
    ):
        raise FollowupControllerError("analysis campaign transport changed")
    if (
        _canonical_json_bytes(watcher) != contents["watcher-receipt.json"]
        or watcher.get("schema_version")
        != "dynamic-cssc-followup-performance-analysis-watcher-receipt-v1"
        or watcher.get("study_id") != FOLLOWUP_STUDY_ID
        or watcher.get("authority") is not False
        or watcher.get("publication_evidence_admitted") is not False
        or watcher.get("analysis_claim_sha256") != claim.sha256
        or watcher.get("analysis_runner_seconds_limit")
        != claim.document["analysis_runner_seconds_limit"]
        or watcher.get("terminal_runner_seconds")
        != claim.document["terminal_runner_seconds"]
        or watcher.get("watcher_session_sha256")
        != binding.document["watcher_session_sha256"]
        or watcher.get("provider_run_id") != binding.document["provider_run_id"]
        or watcher.get("run_api_sha256") != _sha256(contents["provider-run.json"])
        or watcher.get("jobs_api_sha256")
        != _sha256(contents["provider-jobs.json"])
        or watcher.get("artifacts_api_sha256")
        != _sha256(contents["provider-artifacts.json"])
    ):
        raise FollowupControllerError("analysis watcher receipt changed")
    provider_run_id = binding.document["provider_run_id"]
    if (
        run.get("id") != provider_run_id
        or run.get("path") != _ANALYSIS_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != claim.document["analysis_source_S3_sha"]
        or run.get("head_branch") != "main"
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or type(run.get("conclusion")) is not str
    ):
        raise FollowupControllerError("analysis provider run changed")
    job_rows, artifact_rows = _provider_rows(jobs, artifacts)
    for row in job_rows:
        if (
            row.get("name") != _ANALYSIS_JOB
            or row.get("run_id") != provider_run_id
            or row.get("run_attempt") != 1
        ):
            raise FollowupControllerError("analysis provider job changed")
    decision = watcher.get("decision")
    phase_document: dict[str, object] | None = None
    if decision == "success":
        if "phase-receipt.json" not in contents:
            raise FollowupControllerError("analysis phase receipt is absent")
        phase_document = _rebind_success(
            claim=claim,
            watcher=watcher,
            run=run,
            job_rows=job_rows,
            artifact_rows=artifact_rows,
            phase_content=contents["phase-receipt.json"],
        )
    elif decision == "no-go":
        if (
            type(watcher.get("no_go_reason_or_null")) is not str
            or "phase-receipt.json" in contents
            or watcher.get("analysis_phase_receipt_sha256_or_null") is not None
            or watcher.get("analysis_artifact_or_null") is not None
        ):
            raise FollowupControllerError("analysis NO-GO closure changed")
    else:
        raise FollowupControllerError("analysis decision changed")
    expected_controller = {
        "analysis_phase_receipt_sha256_or_null": watcher.get(
            "analysis_phase_receipt_sha256_or_null"
        ),
        "authority": False,
        "binding_oid": binding_oid,
        "campaign_id": claim.document["campaign_id"],
        "claim_oid": binding.document["claim_oid"],
        "decision": decision,
        "outcome_oid": controller.get("outcome_oid"),
        "provider_artifacts_json_sha256": _sha256(
            contents["provider-artifacts.json"]
        ),
        "provider_jobs_json_sha256": _sha256(contents["provider-jobs.json"]),
        "provider_observed_at": watcher.get("provider_observed_at"),
        "provider_run_id": provider_run_id,
        "provider_run_json_sha256": _sha256(contents["provider-run.json"]),
        "publication_evidence_admitted": False,
        "run_admission_sha256": admission.sha256,
        "schema_version": (
            "dynamic-cssc-followup-performance-analysis-evidence-controller-v1"
        ),
        "study_id": FOLLOWUP_STUDY_ID,
        "watch_binding_sha256": binding.sha256,
        "watcher_receipt_sha256": _sha256(contents["watcher-receipt.json"]),
    }
    if (
        controller != expected_controller
        or _canonical_json_bytes(controller) != contents["controller.json"]
    ):
        raise FollowupControllerError("analysis controller record changed")
    _parse_time(
        controller["provider_observed_at"], field="analysis provider observedAt"
    )
    return FollowupAnalysisEvidenceBundle(
        root=root,
        claim=claim,
        binding=binding,
        admission=admission,
        watcher_receipt=watcher,
        phase_receipt=phase_document,
        controller=controller,
    )
