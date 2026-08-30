"""Durable, authority-false evidence for the sole follow-up qualification."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_controller import (
    FollowupControllerError,
    FollowupQualificationWatchResult,
)
from dynamic_cssc.followup_performance_formal_artifacts import (
    _direct_directory,
    _stable_read,
)
from dynamic_cssc.followup_performance_qualification_binding import (
    FollowupQualificationRunAdmission,
    FollowupQualificationWatchBinding,
    build_followup_qualification_run_admission,
    inspect_followup_qualification_watch_binding,
)

__all__ = (
    "FollowupQualificationEvidenceBundle",
    "FollowupQualificationEvidenceJournal",
    "FollowupQualificationProviderEvidence",
    "inspect_followup_qualification_evidence_bundle",
)

_QUALIFICATION_WORKFLOW_PATH = (
    ".github/workflows/followup-performance-qualification.yml"
)
_QUALIFICATION_JOB_NAMES = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
_MEMBERS = {
    "controller.json",
    "provider-artifacts.json",
    "provider-jobs.json",
    "provider-run.json",
    "run-admission.json",
    "stop-loss.json",
    "watch-binding.json",
}


@dataclass(frozen=True, slots=True)
class FollowupQualificationProviderEvidence:
    observed_at: datetime
    run_json: bytes
    jobs_json: bytes
    artifacts_json: bytes


@dataclass(frozen=True, slots=True)
class FollowupQualificationEvidenceBundle:
    root: Path
    watch_binding: FollowupQualificationWatchBinding
    run_admission: FollowupQualificationRunAdmission
    stop_loss: dict[str, object]
    provider: FollowupQualificationProviderEvidence
    controller: dict[str, object]


def _render_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FollowupControllerError("qualification evidence time lacks UTC")
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
        raise FollowupControllerError("qualification evidence content is empty")
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
                raise FollowupControllerError("qualification evidence write stalled")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new_direct_root(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FollowupControllerError(
            "qualification evidence root must be a new absolute path"
        )
    parent = path.parent.resolve(strict=True)
    observed = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise FollowupControllerError(
            "qualification evidence parent is not a direct directory"
        )
    path.mkdir(mode=0o700)
    return path


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class FollowupQualificationEvidenceJournal:
    """Create a new directory before dispatch and close it exactly once."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise FollowupControllerError("qualification evidence root type changed")
        self.root = _new_direct_root(root)
        self._closed = False

    def finalize(
        self,
        *,
        provider_run_id: int,
        claim_oid: str,
        binding_oid: str,
        watch_binding: FollowupQualificationWatchBinding,
        run_admission: FollowupQualificationRunAdmission,
        watch_result: FollowupQualificationWatchResult,
        provider: FollowupQualificationProviderEvidence,
    ) -> None:
        if self._closed:
            raise FollowupControllerError("qualification evidence journal is closed")
        if (
            type(provider_run_id) is not int
            or provider_run_id <= 0
            or type(watch_binding) is not FollowupQualificationWatchBinding
            or type(run_admission) is not FollowupQualificationRunAdmission
            or type(watch_result) is not FollowupQualificationWatchResult
            or type(provider) is not FollowupQualificationProviderEvidence
            or watch_binding.document.get("provider_run_id") != provider_run_id
            or run_admission.document.get("provider_run_id") != provider_run_id
            or watch_binding.document.get("claim_oid") != claim_oid
            or run_admission.document.get("binding_oid") != binding_oid
        ):
            raise FollowupControllerError("qualification evidence identity changed")
        for content in (provider.run_json, provider.jobs_json, provider.artifacts_json):
            if type(content) is not bytes or not content or len(content) > 8 * 1024 * 1024:
                raise FollowupControllerError(
                    "qualification provider evidence bytes changed"
                )
        stop_loss_bytes = _canonical_json_bytes(watch_result.document)
        files = {
            "provider-artifacts.json": provider.artifacts_json,
            "provider-jobs.json": provider.jobs_json,
            "provider-run.json": provider.run_json,
            "run-admission.json": run_admission.document_bytes,
            "stop-loss.json": stop_loss_bytes,
            "watch-binding.json": watch_binding.document_bytes,
        }
        for name, content in files.items():
            _write_new(self.root / name, content)
        controller = {
            "authority": False,
            "binding_oid": binding_oid,
            "claim_oid": claim_oid,
            "formal_execution_authorized": False,
            "provider_artifacts_json_sha256": _sha256(provider.artifacts_json),
            "provider_jobs_json_sha256": _sha256(provider.jobs_json),
            "provider_observed_at": _render_time(provider.observed_at),
            "provider_run_id": provider_run_id,
            "provider_run_json_sha256": _sha256(provider.run_json),
            "publication_evidence_admitted": False,
            "qualification_decision": watch_result.qualification_decision,
            "run_admission_sha256": run_admission.sha256,
            "schema_version": (
                "dynamic-cssc-followup-performance-qualification-evidence-controller-v1"
            ),
            "stop_loss_sha256": _sha256(stop_loss_bytes),
            "study_id": FOLLOWUP_STUDY_ID,
            "watch_binding_sha256": watch_binding.sha256,
        }
        _write_new(self.root / "controller.json", _canonical_json_bytes(controller))
        self._closed = True


def _read(path: Path, *, label: str) -> bytes:
    try:
        return _stable_read(path, maximum=8 * 1024 * 1024)
    except OSError as error:
        raise FollowupControllerError(f"{label} is unreadable") from error


def _object(content: bytes, *, label: str) -> dict[str, object]:
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict:
        raise FollowupControllerError(f"{label} is not one object")
    return value


def inspect_followup_qualification_evidence_bundle(
    root: Path,
) -> FollowupQualificationEvidenceBundle:
    """Independently close the controller record against raw provider facts."""

    root = _direct_directory(root, label="follow-up qualification evidence root")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) != _MEMBERS:
        raise FollowupControllerError("qualification evidence member set changed")
    contents = {name: _read(path, label=name) for name, path in entries.items()}
    binding = inspect_followup_qualification_watch_binding(
        contents["watch-binding.json"]
    )
    admission = build_followup_qualification_run_admission(
        binding,
        binding_oid=_object(
            contents["run-admission.json"], label="qualification run admission"
        ).get("binding_oid"),  # type: ignore[arg-type]
    )
    if admission.document_bytes != contents["run-admission.json"]:
        raise FollowupControllerError("qualification run admission changed")
    stop_loss = _object(contents["stop-loss.json"], label="qualification stop loss")
    controller = _object(contents["controller.json"], label="qualification controller")
    run = _object(contents["provider-run.json"], label="qualification provider run")
    jobs = _object(contents["provider-jobs.json"], label="qualification provider jobs")
    artifacts = _object(
        contents["provider-artifacts.json"], label="qualification provider artifacts"
    )
    provider_run_id = binding.document["provider_run_id"]
    expected_controller = {
        "authority": False,
        "binding_oid": admission.document["binding_oid"],
        "claim_oid": binding.document["claim_oid"],
        "formal_execution_authorized": False,
        "provider_artifacts_json_sha256": _sha256(contents["provider-artifacts.json"]),
        "provider_jobs_json_sha256": _sha256(contents["provider-jobs.json"]),
        "provider_observed_at": controller.get("provider_observed_at"),
        "provider_run_id": provider_run_id,
        "provider_run_json_sha256": _sha256(contents["provider-run.json"]),
        "publication_evidence_admitted": False,
        "qualification_decision": stop_loss.get("qualification_decision"),
        "run_admission_sha256": admission.sha256,
        "schema_version": (
            "dynamic-cssc-followup-performance-qualification-evidence-controller-v1"
        ),
        "stop_loss_sha256": _sha256(contents["stop-loss.json"]),
        "study_id": FOLLOWUP_STUDY_ID,
        "watch_binding_sha256": binding.sha256,
    }
    if (
        controller != expected_controller
        or _canonical_json_bytes(controller) != contents["controller.json"]
        or stop_loss.get("schema_version")
        != "dynamic-cssc-followup-performance-live-stop-loss-v2"
        or stop_loss.get("study_id") != FOLLOWUP_STUDY_ID
        or stop_loss.get("authority") is not False
        or stop_loss.get("formal_execution_authorized") is not False
        or run.get("id") != provider_run_id
        or run.get("path") != _QUALIFICATION_WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != binding.document["evidence_freeze_S2_sha"]
        or run.get("head_branch") != "main"
        or run.get("run_attempt") != 1
        or run.get("status") != "completed"
        or type(run.get("conclusion")) is not str
    ):
        raise FollowupControllerError("qualification evidence closure changed")
    rows = jobs.get("jobs")
    artifact_rows = artifacts.get("artifacts")
    if (
        type(rows) is not list
        or jobs.get("total_count") != len(rows)
        or len(rows) > 6
        or any(type(row) is not dict for row in rows)
        or tuple(row.get("name") for row in rows) != _QUALIFICATION_JOB_NAMES[: len(rows)]
        or type(artifact_rows) is not list
        or artifacts.get("total_count") != len(artifact_rows)
        or len(artifact_rows) > 6
        or any(type(row) is not dict for row in artifact_rows)
    ):
        raise FollowupControllerError("qualification provider inventory changed")
    if stop_loss.get("qualification_decision") == "qualification-go":
        if (
            run.get("conclusion") != "success"
            or len(rows) != 6
            or any(
                row.get("status") != "completed" or row.get("conclusion") != "success"
                for row in rows
            )
            or len(artifact_rows) != 6
        ):
            raise FollowupControllerError("qualification GO provider closure changed")
    elif stop_loss.get("qualification_decision") != "qualification-no-go":
        raise FollowupControllerError("qualification decision changed")
    observed_at = _parse_time(
        controller["provider_observed_at"], field="qualification provider observedAt"
    )
    return FollowupQualificationEvidenceBundle(
        root=root,
        watch_binding=binding,
        run_admission=admission,
        stop_loss=stop_loss,
        provider=FollowupQualificationProviderEvidence(
            observed_at=observed_at,
            run_json=contents["provider-run.json"],
            jobs_json=contents["provider-jobs.json"],
            artifacts_json=contents["provider-artifacts.json"],
        ),
        controller=controller,
    )
