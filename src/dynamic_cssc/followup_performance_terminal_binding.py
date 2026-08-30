"""Provider claim and mandatory-watch binding for terminal admission."""

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
    "FollowupTerminalBindingError",
    "FollowupTerminalClaim",
    "FollowupTerminalRunAdmission",
    "FollowupTerminalWatchBinding",
    "build_followup_terminal_claim",
    "build_followup_terminal_run_admission",
    "build_followup_terminal_watch_binding",
    "inspect_followup_terminal_claim",
    "inspect_followup_terminal_watch_binding",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_WORKFLOW_SUFFIX = (
    "/.github/workflows/followup-performance-terminal.yml@refs/heads/main"
)
_CLAIM_SCHEMA = "dynamic-cssc-followup-performance-terminal-claim-v1"
_BINDING_SCHEMA = "dynamic-cssc-followup-performance-terminal-watch-binding-v1"
_ADMISSION_SCHEMA = "dynamic-cssc-followup-performance-terminal-run-admission-v1"


class FollowupTerminalBindingError(FollowupContractError):
    """The terminal run is not bound to one closed campaign and watcher."""


@dataclass(frozen=True, slots=True)
class FollowupTerminalClaim:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class FollowupTerminalWatchBinding:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class FollowupTerminalRunAdmission:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def _git_sha(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise FollowupTerminalBindingError(f"{field} is not a lowercase Git SHA")
    return value


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupTerminalBindingError(f"{field} is not a lowercase SHA-256")
    return value


def _claim(value: dict[str, object]) -> FollowupTerminalClaim:
    expected = {
        "authority",
        "campaign_id",
        "campaign_selection_sha256",
        "campaign_transport_expanded_bytes",
        "campaign_transport_member_count",
        "campaign_transport_sha256",
        "compatibility_receipt_sha256",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "final_progress_oid",
        "formal_timing_ledger_sha256",
        "publication_evidence_admitted",
        "schema_version",
        "state",
        "study_id",
    }
    if (
        type(value) is not dict
        or set(value) != expected
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or value.get("schema_version") != _CLAIM_SCHEMA
        or value.get("state") != "terminal-claimed"
        or value.get("study_id") != FOLLOWUP_STUDY_ID
        or type(value.get("campaign_transport_member_count")) is not int
        or not 1 <= value["campaign_transport_member_count"] <= 512
        or type(value.get("campaign_transport_expanded_bytes")) is not int
        or not 1 <= value["campaign_transport_expanded_bytes"] <= 96 * 1024 * 1024
    ):
        raise FollowupTerminalBindingError("terminal claim projection changed")
    s1 = _git_sha(value.get("experiment_source_S1_sha"), field="S1")
    s2 = _git_sha(value.get("evidence_freeze_S2_sha"), field="S2")
    if s1 == s2:
        raise FollowupTerminalBindingError("terminal claim lineage changed")
    _git_sha(value.get("final_progress_oid"), field="final progress OID")
    for field in (
        "campaign_id",
        "campaign_selection_sha256",
        "campaign_transport_sha256",
        "compatibility_receipt_sha256",
        "formal_timing_ledger_sha256",
    ):
        _sha256(value.get(field), field=field)
    content = _canonical_json_bytes(value)
    return FollowupTerminalClaim(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_followup_terminal_claim(
    *,
    campaign_id: str,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    compatibility_receipt_sha256: str,
    final_progress_oid: str,
    campaign_selection_sha256: str,
    formal_timing_ledger_sha256: str,
    campaign_transport_sha256: str,
    campaign_transport_member_count: int,
    campaign_transport_expanded_bytes: int,
) -> FollowupTerminalClaim:
    return _claim(
        {
            "authority": False,
            "campaign_id": campaign_id,
            "campaign_selection_sha256": campaign_selection_sha256,
            "campaign_transport_expanded_bytes": campaign_transport_expanded_bytes,
            "campaign_transport_member_count": campaign_transport_member_count,
            "campaign_transport_sha256": campaign_transport_sha256,
            "compatibility_receipt_sha256": compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
            "experiment_source_S1_sha": experiment_source_s1_sha,
            "final_progress_oid": final_progress_oid,
            "formal_timing_ledger_sha256": formal_timing_ledger_sha256,
            "publication_evidence_admitted": False,
            "schema_version": _CLAIM_SCHEMA,
            "state": "terminal-claimed",
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )


def _binding(value: dict[str, object]) -> FollowupTerminalWatchBinding:
    expected = {
        "authority",
        "campaign_id",
        "campaign_transport_sha256",
        "claim_oid",
        "claim_sha256",
        "evidence_freeze_S2_sha",
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
        or set(value) != expected
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or value.get("schema_version") != _BINDING_SCHEMA
        or value.get("state") != "watch-armed"
        or value.get("study_id") != FOLLOWUP_STUDY_ID
        or value.get("provider_run_attempt") != 1
        or type(value.get("provider_run_id")) is not int
        or value["provider_run_id"] <= 0
        or type(value.get("workflow_ref")) is not str
        or not value["workflow_ref"].endswith(_WORKFLOW_SUFFIX)
    ):
        raise FollowupTerminalBindingError("terminal watch binding changed")
    _git_sha(value.get("claim_oid"), field="terminal claim OID")
    for field in (
        "campaign_id",
        "campaign_transport_sha256",
        "claim_sha256",
        "watcher_session_sha256",
    ):
        _sha256(value.get(field), field=field)
    _git_sha(value.get("evidence_freeze_S2_sha"), field="S2")
    content = _canonical_json_bytes(value)
    return FollowupTerminalWatchBinding(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_followup_terminal_watch_binding(
    claim: FollowupTerminalClaim,
    *,
    claim_oid: str,
    provider_run_id: int,
    watcher_session_sha256: str,
    workflow_ref: str,
) -> FollowupTerminalWatchBinding:
    if type(claim) is not FollowupTerminalClaim:
        raise FollowupTerminalBindingError("terminal binding lacks its claim")
    _git_sha(claim_oid, field="terminal claim OID")
    return _binding(
        {
            "authority": False,
            "campaign_id": claim.document["campaign_id"],
            "campaign_transport_sha256": claim.document[
                "campaign_transport_sha256"
            ],
            "claim_oid": claim_oid,
            "claim_sha256": claim.sha256,
            "evidence_freeze_S2_sha": claim.document["evidence_freeze_S2_sha"],
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


def build_followup_terminal_run_admission(
    claim: FollowupTerminalClaim,
    binding: FollowupTerminalWatchBinding,
    *,
    binding_oid: str,
) -> FollowupTerminalRunAdmission:
    if (
        type(claim) is not FollowupTerminalClaim
        or type(binding) is not FollowupTerminalWatchBinding
        or binding.document.get("claim_sha256") != claim.sha256
        or binding.document.get("campaign_id") != claim.document["campaign_id"]
        or binding.document.get("campaign_transport_sha256")
        != claim.document["campaign_transport_sha256"]
    ):
        raise FollowupTerminalBindingError("terminal admission lineage changed")
    _git_sha(binding_oid, field="terminal binding OID")
    document = {
        "authority": False,
        "binding_oid": binding_oid,
        "binding_sha256": binding.sha256,
        "campaign_id": claim.document["campaign_id"],
        "campaign_transport_sha256": claim.document["campaign_transport_sha256"],
        "claim_oid": binding.document["claim_oid"],
        "claim_sha256": claim.sha256,
        "provider_run_attempt": 1,
        "provider_run_id": binding.document["provider_run_id"],
        "publication_evidence_admitted": False,
        "schema_version": _ADMISSION_SCHEMA,
        "study_id": FOLLOWUP_STUDY_ID,
        "watcher_session_sha256": binding.document["watcher_session_sha256"],
    }
    content = _canonical_json_bytes(document)
    return FollowupTerminalRunAdmission(
        document=document,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _parse(content: bytes, *, label: str) -> dict[str, object]:
    if type(content) is not bytes or not content or len(content) > 64 * 1024:
        raise FollowupTerminalBindingError(f"{label} bytes changed")
    try:
        pairs = json.loads(
            content.decode("ascii"),
            object_pairs_hook=lambda rows: rows,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupTerminalBindingError(f"{label} contains {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupTerminalBindingError(f"{label} is not ASCII JSON") from error
    if type(pairs) is not list:
        raise FollowupTerminalBindingError(f"{label} is not one object")
    value: dict[str, object] = {}
    for row in pairs:
        if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str:
            raise FollowupTerminalBindingError(f"{label} is not one object")
        key, item = row
        if key in value:
            raise FollowupTerminalBindingError(f"{label} contains a duplicate key")
        value[key] = item
    return value


def inspect_followup_terminal_claim(content: bytes) -> FollowupTerminalClaim:
    claim = _claim(_parse(content, label="terminal claim"))
    if claim.document_bytes != content:
        raise FollowupTerminalBindingError("terminal claim is not canonical")
    return claim


def inspect_followup_terminal_watch_binding(
    content: bytes,
) -> FollowupTerminalWatchBinding:
    binding = _binding(_parse(content, label="terminal watch binding"))
    if binding.document_bytes != content:
        raise FollowupTerminalBindingError(
            "terminal watch binding is not canonical"
        )
    return binding
