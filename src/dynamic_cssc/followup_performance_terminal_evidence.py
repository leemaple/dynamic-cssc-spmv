"""Durable controller and provider evidence for terminal campaign closure."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

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
from dynamic_cssc.followup_performance_terminal_binding import (
    FollowupTerminalClaim,
    FollowupTerminalRunAdmission,
    FollowupTerminalWatchBinding,
    build_followup_terminal_run_admission,
    inspect_followup_terminal_claim,
    inspect_followup_terminal_watch_binding,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalWatchOutcome,
    inspect_followup_terminal_phase_receipt,
)

__all__ = (
    "FollowupTerminalEvidenceBundle",
    "FollowupTerminalEvidenceJournal",
    "inspect_followup_terminal_evidence_bundle",
)

_TERMINAL_WORKFLOW = ".github/workflows/followup-performance-terminal.yml"
_TERMINAL_JOB = "formal-terminal-admission-and-aggregate"
_BASE_MEMBERS = {
    "campaign-transport.json",
    "controller.json",
    "provider-artifacts.json",
    "provider-jobs.json",
    "provider-run.json",
    "run-admission.json",
    "terminal-claim.json",
    "watch-binding.json",
    "watcher-receipt.json",
}


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _render_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FollowupControllerError("terminal evidence time lacks UTC")
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
        raise FollowupControllerError("terminal evidence content is empty")
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
                raise FollowupControllerError("terminal evidence write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new_root(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FollowupControllerError(
            "terminal evidence root must be a new absolute path"
        )
    parent = path.parent.resolve(strict=True)
    observed = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupControllerError(
            "terminal evidence parent is not a direct directory"
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


class FollowupTerminalEvidenceJournal:
    """Open before provider mutation and finalize once after outcome CAS."""

    def __init__(
        self,
        root: Path,
        *,
        claim: FollowupTerminalClaim,
        transport: FollowupCampaignTransport,
    ) -> None:
        if (
            type(claim) is not FollowupTerminalClaim
            or type(transport) is not FollowupCampaignTransport
            or claim.document.get("campaign_transport_sha256") != transport.sha256
            or claim.document.get("campaign_transport_member_count")
            != transport.member_count
            or claim.document.get("campaign_transport_expanded_bytes")
            != transport.expanded_bytes
        ):
            raise FollowupControllerError("terminal evidence opening changed")
        self.root = _new_root(root)
        self._claim = claim
        self._closed = False
        _write_new(self.root / "terminal-claim.json", claim.document_bytes)
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
        binding: FollowupTerminalWatchBinding,
        admission: FollowupTerminalRunAdmission,
        outcome: FollowupTerminalWatchOutcome,
    ) -> None:
        if self._closed:
            raise FollowupControllerError("terminal evidence journal is closed")
        if (
            type(provider_run_id) is not int
            or provider_run_id <= 0
            or type(binding) is not FollowupTerminalWatchBinding
            or type(admission) is not FollowupTerminalRunAdmission
            or type(outcome) is not FollowupTerminalWatchOutcome
            or binding.document.get("provider_run_id") != provider_run_id
            or admission.document.get("provider_run_id") != provider_run_id
            or outcome.provider_run_id != provider_run_id
            or binding.document.get("claim_oid") != claim_oid
            or admission.document.get("binding_oid") != binding_oid
        ):
            raise FollowupControllerError("terminal evidence identity changed")
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
                "dynamic-cssc-followup-performance-terminal-evidence-controller-v1"
            ),
            "study_id": FOLLOWUP_STUDY_ID,
            "terminal_phase_receipt_sha256_or_null": (
                None
                if outcome.provider_phase_receipt_bytes_or_null is None
                else _sha256(outcome.provider_phase_receipt_bytes_or_null)
            ),
            "watch_binding_sha256": binding.sha256,
            "watcher_receipt_sha256": outcome.watcher_receipt_sha256,
        }
        _write_new(self.root / "controller.json", _canonical_json_bytes(controller))
        self._closed = True


@dataclass(frozen=True, slots=True)
class FollowupTerminalEvidenceBundle:
    root: Path
    claim: FollowupTerminalClaim
    binding: FollowupTerminalWatchBinding
    admission: FollowupTerminalRunAdmission
    watcher_receipt: dict[str, object]
    phase_receipt: dict[str, object] | None
    controller: dict[str, object]


def inspect_followup_terminal_evidence_bundle(
    root: Path,
) -> FollowupTerminalEvidenceBundle:
    """Rebind the controller record to exact provider terminal facts."""

    root = _direct_directory(root, label="follow-up terminal evidence root")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) not in (
        _BASE_MEMBERS,
        _BASE_MEMBERS | {"phase-receipt.json"},
    ):
        raise FollowupControllerError("terminal evidence member set changed")
    contents = {name: _read(path, label=name) for name, path in entries.items()}
    claim = inspect_followup_terminal_claim(contents["terminal-claim.json"])
    binding = inspect_followup_terminal_watch_binding(
        contents["watch-binding.json"]
    )
    admission_document = _object(
        contents["run-admission.json"], label="terminal run admission"
    )
    binding_oid = admission_document.get("binding_oid")
    if type(binding_oid) is not str:
        raise FollowupControllerError("terminal admission binding OID changed")
    admission = build_followup_terminal_run_admission(
        claim,
        binding,
        binding_oid=binding_oid,
    )
    if admission.document_bytes != contents["run-admission.json"]:
        raise FollowupControllerError("terminal run admission changed")
    transport = _object(
        contents["campaign-transport.json"], label="campaign transport record"
    )
    watcher = _object(
        contents["watcher-receipt.json"], label="terminal watcher receipt"
    )
    controller = _object(contents["controller.json"], label="terminal controller")
    run = _object(contents["provider-run.json"], label="terminal provider run")
    jobs = _object(contents["provider-jobs.json"], label="terminal provider jobs")
    artifacts = _object(
        contents["provider-artifacts.json"], label="terminal provider artifacts"
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
        raise FollowupControllerError("campaign transport record changed")
    if (
        _canonical_json_bytes(watcher) != contents["watcher-receipt.json"]
        or watcher.get("schema_version")
        != "dynamic-cssc-followup-performance-terminal-watcher-receipt-v1"
        or watcher.get("study_id") != FOLLOWUP_STUDY_ID
        or watcher.get("authority") is not False
        or watcher.get("publication_evidence_admitted") is not False
        or watcher.get("terminal_claim_sha256") != claim.sha256
        or watcher.get("watcher_session_sha256")
        != binding.document["watcher_session_sha256"]
        or watcher.get("provider_run_id") != binding.document["provider_run_id"]
        or watcher.get("run_api_sha256")
        != _sha256(contents["provider-run.json"])
        or watcher.get("jobs_api_sha256")
        != _sha256(contents["provider-jobs.json"])
        or watcher.get("artifacts_api_sha256")
        != _sha256(contents["provider-artifacts.json"])
    ):
        raise FollowupControllerError("terminal watcher receipt changed")
    provider_run_id = binding.document["provider_run_id"]
    if (
        run.get("id") != provider_run_id
        or run.get("path") != _TERMINAL_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != claim.document["evidence_freeze_S2_sha"]
        or run.get("head_branch") != "main"
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or type(run.get("conclusion")) is not str
    ):
        raise FollowupControllerError("terminal provider run changed")
    job_rows = jobs.get("jobs")
    artifact_rows = artifacts.get("artifacts")
    if (
        type(job_rows) is not list
        or jobs.get("total_count") != len(job_rows)
        or len(job_rows) > 1
        or any(type(row) is not dict for row in job_rows)
        or type(artifact_rows) is not list
        or artifacts.get("total_count") != len(artifact_rows)
        or len(artifact_rows) > 2
        or any(type(row) is not dict for row in artifact_rows)
    ):
        raise FollowupControllerError("terminal provider inventory changed")
    decision = watcher.get("decision")
    phase_document: dict[str, object] | None = None
    if decision == "success":
        if (
            run.get("conclusion") != "success"
            or len(job_rows) != 1
            or job_rows[0].get("name") != _TERMINAL_JOB
            or job_rows[0].get("status") != "completed"
            or job_rows[0].get("conclusion") != "success"
            or len(artifact_rows) != 2
            or "phase-receipt.json" not in contents
            or watcher.get("no_go_reason_or_null") is not None
        ):
            raise FollowupControllerError("terminal success closure changed")
        started = _parse_time(
            job_rows[0].get("started_at"), field="terminal job startedAt"
        )
        completed = _parse_time(
            job_rows[0].get("completed_at"), field="terminal job completedAt"
        )
        seconds = int((completed - started).total_seconds())
        if (
            completed < started
            or seconds > 30 * 60
            or watcher.get("job_started_at_or_null") != _render_time(started)
            or watcher.get("job_completed_at_or_null") != _render_time(completed)
            or watcher.get("runner_seconds_or_null") != seconds
        ):
            raise FollowupControllerError("terminal time gate changed")
        phase = inspect_followup_terminal_phase_receipt(
            contents["phase-receipt.json"],
            expected_formal_timing_ledger_sha256=claim.document[
                "formal_timing_ledger_sha256"
            ],  # type: ignore[arg-type]
        )
        if watcher.get("terminal_phase_receipt_sha256_or_null") != phase.sha256:
            raise FollowupControllerError("terminal phase receipt hash changed")
        phase_document = phase.document
        by_name = {
            row.get("name"): row
            for row in artifact_rows
            if type(row.get("name")) is str
        }
        for receipt_field, phase_role in (
            ("terminal_artifact_or_null", "terminal"),
            ("aggregate_artifact_or_null", "aggregate"),
        ):
            receipt_artifact = watcher.get(receipt_field)
            phase_value = phase.document[phase_role]
            if type(receipt_artifact) is not dict or type(phase_value) is not dict:
                raise FollowupControllerError("terminal artifact receipt changed")
            name = phase_value.get("artifact_name")
            provider = by_name.get(name)
            workflow_run = None if provider is None else provider.get("workflow_run")
            if (
                type(provider) is not dict
                or type(workflow_run) is not dict
                or receipt_artifact
                != {
                    "artifact_name": name,
                    "provider_artifact_id": provider.get("id"),
                    "provider_digest": provider.get("digest"),
                    "size_in_bytes": provider.get("size_in_bytes"),
                }
                or provider.get("expired") is not False
                or workflow_run.get("id") != provider_run_id
                or workflow_run.get("head_sha")
                != claim.document["evidence_freeze_S2_sha"]
            ):
                raise FollowupControllerError("terminal provider artifact changed")
    elif decision == "no-go":
        if (
            type(watcher.get("no_go_reason_or_null")) is not str
            or "phase-receipt.json" in contents
            or watcher.get("terminal_phase_receipt_sha256_or_null") is not None
            or watcher.get("terminal_artifact_or_null") is not None
            or watcher.get("aggregate_artifact_or_null") is not None
        ):
            raise FollowupControllerError("terminal NO-GO closure changed")
    else:
        raise FollowupControllerError("terminal decision changed")
    expected_controller = {
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
            "dynamic-cssc-followup-performance-terminal-evidence-controller-v1"
        ),
        "study_id": FOLLOWUP_STUDY_ID,
        "terminal_phase_receipt_sha256_or_null": watcher.get(
            "terminal_phase_receipt_sha256_or_null"
        ),
        "watch_binding_sha256": binding.sha256,
        "watcher_receipt_sha256": _sha256(contents["watcher-receipt.json"]),
    }
    if (
        controller != expected_controller
        or _canonical_json_bytes(controller) != contents["controller.json"]
    ):
        raise FollowupControllerError("terminal controller record changed")
    _parse_time(
        controller["provider_observed_at"], field="terminal provider observedAt"
    )
    return FollowupTerminalEvidenceBundle(
        root=root,
        claim=claim,
        binding=binding,
        admission=admission,
        watcher_receipt=watcher,
        phase_receipt=phase_document,
        controller=controller,
    )
