"""Authority-false binding shared by qualification controller and seed gate."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    _canonical_json_bytes,
)

__all__ = (
    "FollowupQualificationBindingError",
    "FollowupQualificationRunAdmission",
    "FollowupQualificationWatchBinding",
    "build_followup_qualification_run_admission",
    "build_followup_qualification_watch_binding",
    "inspect_followup_qualification_watch_binding",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WORKFLOW_SUFFIX = (
    "/.github/workflows/followup-performance-qualification.yml@refs/heads/main"
)
_BINDING_SCHEMA = (
    "dynamic-cssc-followup-performance-qualification-watch-binding-v1"
)
_ADMISSION_SCHEMA = (
    "dynamic-cssc-followup-performance-qualification-run-admission-v1"
)


class FollowupQualificationBindingError(FollowupContractError):
    """A qualification run was not bound to one already-running watcher."""


@dataclass(frozen=True, slots=True)
class FollowupQualificationWatchBinding:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class FollowupQualificationRunAdmission:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def _require_git_sha(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise FollowupQualificationBindingError(f"{field} is not a lowercase Git SHA")
    return value


def _require_sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupQualificationBindingError(f"{field} is not a lowercase SHA-256")
    return value


def _binding(value: dict[str, object]) -> FollowupQualificationWatchBinding:
    expected_fields = {
        "authority",
        "authority_kind",
        "claim_oid",
        "compatibility_receipt_sha256",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "provider_run_attempt",
        "provider_run_id",
        "publication_evidence_admitted",
        "schema_version",
        "state",
        "study_id",
        "watcher_session_sha256",
        "workflow_ref",
    }
    if (
        type(value) is not dict
        or set(value) != expected_fields
        or value.get("authority") is not False
        or value.get("authority_kind") != "qualification"
        or value.get("publication_evidence_admitted") is not False
        or value.get("schema_version") != _BINDING_SCHEMA
        or value.get("state") != "watch-armed"
        or value.get("study_id") != FOLLOWUP_STUDY_ID
        or type(value.get("provider_run_id")) is not int
        or value["provider_run_id"] <= 0
        or value.get("provider_run_attempt") != 1
        or type(value.get("workflow_ref")) is not str
        or not value["workflow_ref"].endswith(_WORKFLOW_SUFFIX)
    ):
        raise FollowupQualificationBindingError(
            "qualification watch binding projection changed"
        )
    s1 = _require_git_sha(value.get("experiment_source_S1_sha"), field="S1")
    s2 = _require_git_sha(value.get("evidence_freeze_S2_sha"), field="S2")
    if value.get("claim_oid") != s2 or s1 == s2:
        raise FollowupQualificationBindingError(
            "qualification watch binding lineage changed"
        )
    _require_sha256(
        value.get("compatibility_receipt_sha256"),
        field="compatibility receipt",
    )
    _require_sha256(
        value.get("watcher_session_sha256"),
        field="watcher session",
    )
    content = _canonical_json_bytes(value)
    return FollowupQualificationWatchBinding(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_followup_qualification_watch_binding(
    *,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    compatibility_receipt_sha256: str,
    provider_run_id: int,
    watcher_session_sha256: str,
    workflow_ref: str,
) -> FollowupQualificationWatchBinding:
    """Build the exact commit message installed only after the watch has started."""

    return _binding(
        {
            "authority": False,
            "authority_kind": "qualification",
            "claim_oid": evidence_freeze_s2_sha,
            "compatibility_receipt_sha256": compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
            "experiment_source_S1_sha": experiment_source_s1_sha,
            "provider_run_attempt": 1,
            "provider_run_id": provider_run_id,
            "publication_evidence_admitted": False,
            "schema_version": _BINDING_SCHEMA,
            "state": "watch-armed",
            "study_id": FOLLOWUP_STUDY_ID,
            "watcher_session_sha256": watcher_session_sha256,
            "workflow_ref": workflow_ref,
        }
    )


def inspect_followup_qualification_watch_binding(
    content: bytes,
) -> FollowupQualificationWatchBinding:
    """Parse only canonical, duplicate-free binding bytes."""

    if type(content) is not bytes or not content or len(content) > 16 * 1024:
        raise FollowupQualificationBindingError(
            "qualification watch binding bytes changed"
        )
    try:
        pairs: list[tuple[str, object]] = json.loads(
            content.decode("ascii"),
            object_pairs_hook=lambda rows: rows,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupQualificationBindingError(
                    f"qualification watch binding contains {token}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupQualificationBindingError(
            "qualification watch binding is not ASCII JSON"
        ) from error
    if type(pairs) is not list or any(
        type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
        for row in pairs
    ):
        raise FollowupQualificationBindingError(
            "qualification watch binding is not one object"
        )
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FollowupQualificationBindingError(
                "qualification watch binding contains a duplicate key"
            )
        value[key] = item
    binding = _binding(value)
    if binding.document_bytes != content:
        raise FollowupQualificationBindingError(
            "qualification watch binding is not canonical"
        )
    return binding


def build_followup_qualification_run_admission(
    binding: FollowupQualificationWatchBinding,
    *,
    binding_oid: str,
) -> FollowupQualificationRunAdmission:
    """Derive the receipt independently reproduced by the in-run seed gate."""

    if type(binding) is not FollowupQualificationWatchBinding:
        raise FollowupQualificationBindingError(
            "qualification run admission lacks its exact binding"
        )
    _require_git_sha(binding_oid, field="binding OID")
    document = {
        "authority": False,
        "binding_oid": binding_oid,
        "binding_sha256": binding.sha256,
        "compatibility_receipt_sha256": binding.document[
            "compatibility_receipt_sha256"
        ],
        "evidence_freeze_S2_sha": binding.document["evidence_freeze_S2_sha"],
        "experiment_source_S1_sha": binding.document["experiment_source_S1_sha"],
        "provider_run_attempt": 1,
        "provider_run_id": binding.document["provider_run_id"],
        "publication_evidence_admitted": False,
        "schema_version": _ADMISSION_SCHEMA,
        "study_id": FOLLOWUP_STUDY_ID,
        "watcher_session_sha256": binding.document["watcher_session_sha256"],
    }
    content = _canonical_json_bytes(document)
    return FollowupQualificationRunAdmission(
        document=document,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )
