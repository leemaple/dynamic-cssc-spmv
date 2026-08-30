"""Provider claim and mandatory-watch binding for isolated S3 analysis."""

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
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
)

__all__ = (
    "FollowupAnalysisBindingError",
    "FollowupAnalysisClaim",
    "FollowupAnalysisRunAdmission",
    "FollowupAnalysisWatchBinding",
    "build_followup_analysis_claim",
    "build_followup_analysis_run_admission",
    "build_followup_analysis_watch_binding",
    "inspect_followup_analysis_claim",
    "inspect_followup_analysis_watch_binding",
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARTIFACT_NAME = re.compile(
    r"followup-performance-v1-[a-z0-9][a-z0-9-]{0,254}\Z"
)
_WORKFLOW_SUFFIX = (
    "/.github/workflows/followup-performance-analysis.yml@refs/heads/main"
)
_CLAIM_SCHEMA = "dynamic-cssc-followup-performance-analysis-claim-v1"
_BINDING_SCHEMA = (
    "dynamic-cssc-followup-performance-analysis-watch-binding-v1"
)
_ADMISSION_SCHEMA = (
    "dynamic-cssc-followup-performance-analysis-run-admission-v1"
)


class FollowupAnalysisBindingError(FollowupContractError):
    """The S3 analysis run is not bound to one terminal outcome and watcher."""


@dataclass(frozen=True, slots=True)
class FollowupAnalysisClaim:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class FollowupAnalysisWatchBinding:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class FollowupAnalysisRunAdmission:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str


def _git_sha(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise FollowupAnalysisBindingError(f"{field} is not a lowercase Git SHA")
    return value


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupAnalysisBindingError(f"{field} is not a lowercase SHA-256")
    return value


def _artifact(value: object, *, prefix: str, label: str) -> dict[str, object]:
    if (
        type(value) is not dict
        or set(value)
        != {
            "artifact_name",
            "provider_artifact_id",
            "provider_digest",
            "size_in_bytes",
        }
        or type(value.get("artifact_name")) is not str
        or _ARTIFACT_NAME.fullmatch(value["artifact_name"]) is None
        or not value["artifact_name"].startswith(prefix)
        or type(value.get("provider_artifact_id")) is not int
        or value["provider_artifact_id"] <= 0
        or type(value.get("provider_digest")) is not str
        or _PROVIDER_DIGEST.fullmatch(value["provider_digest"]) is None
        or type(value.get("size_in_bytes")) is not int
        or value["size_in_bytes"] <= 0
    ):
        raise FollowupAnalysisBindingError(f"{label} binding changed")
    return value


def _claim(value: dict[str, object]) -> FollowupAnalysisClaim:
    expected = {
        "aggregate_artifact",
        "analysis_compatibility_receipt_sha256",
        "analysis_runner_seconds_limit",
        "analysis_source_S3_sha",
        "authority",
        "campaign_id",
        "campaign_transport_expanded_bytes",
        "campaign_transport_member_count",
        "campaign_transport_sha256",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "publication_evidence_admitted",
        "registration_compatibility_receipt_sha256",
        "schema_version",
        "state",
        "study_id",
        "terminal_artifact",
        "terminal_outcome_oid",
        "terminal_provider_run_id",
        "terminal_run_admission_sha256",
        "terminal_runner_seconds",
        "terminal_watcher_receipt_sha256",
    }
    if (
        type(value) is not dict
        or set(value) != expected
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or value.get("schema_version") != _CLAIM_SCHEMA
        or value.get("state") != "analysis-claimed"
        or value.get("study_id") != FOLLOWUP_STUDY_ID
        or type(value.get("terminal_provider_run_id")) is not int
        or value["terminal_provider_run_id"] <= 0
        or type(value.get("terminal_runner_seconds")) is not int
        or not 0 <= value["terminal_runner_seconds"] < 30 * 60
        or type(value.get("analysis_runner_seconds_limit")) is not int
        or value["analysis_runner_seconds_limit"]
        != 30 * 60 - value["terminal_runner_seconds"]
        or type(value.get("campaign_transport_member_count")) is not int
        or not 1 <= value["campaign_transport_member_count"] <= 512
        or type(value.get("campaign_transport_expanded_bytes")) is not int
        or not 1 <= value["campaign_transport_expanded_bytes"] <= 96 * 1024 * 1024
    ):
        raise FollowupAnalysisBindingError("analysis claim projection changed")
    s1 = _git_sha(value.get("experiment_source_S1_sha"), field="S1")
    s2 = _git_sha(value.get("evidence_freeze_S2_sha"), field="S2")
    s3 = _git_sha(value.get("analysis_source_S3_sha"), field="S3")
    if len({s1, s2, s3}) != 3:
        raise FollowupAnalysisBindingError("analysis source lineage changed")
    _git_sha(value.get("terminal_outcome_oid"), field="terminal outcome OID")
    for field in (
        "analysis_compatibility_receipt_sha256",
        "campaign_id",
        "campaign_transport_sha256",
        "registration_compatibility_receipt_sha256",
        "terminal_run_admission_sha256",
        "terminal_watcher_receipt_sha256",
    ):
        _sha256(value.get(field), field=field)
    terminal = _artifact(
        value.get("terminal_artifact"),
        prefix="followup-performance-v1-formal-terminal-admission-",
        label="terminal artifact",
    )
    aggregate = _artifact(
        value.get("aggregate_artifact"),
        prefix="followup-performance-v1-formal-aggregate-",
        label="aggregate artifact",
    )
    if terminal["provider_artifact_id"] == aggregate["provider_artifact_id"]:
        raise FollowupAnalysisBindingError("analysis input artifacts are duplicated")
    content = _canonical_json_bytes(value)
    return FollowupAnalysisClaim(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_followup_analysis_claim(
    *,
    campaign_id: str,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    analysis_source_s3_sha: str,
    registration_compatibility_receipt_sha256: str,
    analysis_compatibility_receipt_sha256: str,
    terminal_outcome_oid: str,
    terminal_provider_run_id: int,
    terminal_run_admission_sha256: str,
    terminal_watcher_receipt_sha256: str,
    terminal_runner_seconds: int,
    campaign_transport_sha256: str,
    campaign_transport_member_count: int,
    campaign_transport_expanded_bytes: int,
    terminal_artifact: FollowupTerminalArtifactBinding,
    aggregate_artifact: FollowupTerminalArtifactBinding,
) -> FollowupAnalysisClaim:
    if (
        type(terminal_artifact) is not FollowupTerminalArtifactBinding
        or type(aggregate_artifact) is not FollowupTerminalArtifactBinding
    ):
        raise FollowupAnalysisBindingError("analysis input artifact type changed")
    return _claim(
        {
            "aggregate_artifact": aggregate_artifact.document,
            "analysis_compatibility_receipt_sha256": (
                analysis_compatibility_receipt_sha256
            ),
            "analysis_runner_seconds_limit": 30 * 60 - terminal_runner_seconds,
            "analysis_source_S3_sha": analysis_source_s3_sha,
            "authority": False,
            "campaign_id": campaign_id,
            "campaign_transport_expanded_bytes": (
                campaign_transport_expanded_bytes
            ),
            "campaign_transport_member_count": campaign_transport_member_count,
            "campaign_transport_sha256": campaign_transport_sha256,
            "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
            "experiment_source_S1_sha": experiment_source_s1_sha,
            "publication_evidence_admitted": False,
            "registration_compatibility_receipt_sha256": (
                registration_compatibility_receipt_sha256
            ),
            "schema_version": _CLAIM_SCHEMA,
            "state": "analysis-claimed",
            "study_id": FOLLOWUP_STUDY_ID,
            "terminal_artifact": terminal_artifact.document,
            "terminal_outcome_oid": terminal_outcome_oid,
            "terminal_provider_run_id": terminal_provider_run_id,
            "terminal_run_admission_sha256": terminal_run_admission_sha256,
            "terminal_runner_seconds": terminal_runner_seconds,
            "terminal_watcher_receipt_sha256": (
                terminal_watcher_receipt_sha256
            ),
        }
    )


def _binding(value: dict[str, object]) -> FollowupAnalysisWatchBinding:
    expected = {
        "analysis_source_S3_sha",
        "authority",
        "campaign_id",
        "claim_oid",
        "claim_sha256",
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
        raise FollowupAnalysisBindingError("analysis watch binding changed")
    _git_sha(value.get("claim_oid"), field="analysis claim OID")
    _git_sha(value.get("analysis_source_S3_sha"), field="S3")
    for field in ("campaign_id", "claim_sha256", "watcher_session_sha256"):
        _sha256(value.get(field), field=field)
    content = _canonical_json_bytes(value)
    return FollowupAnalysisWatchBinding(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def build_followup_analysis_watch_binding(
    claim: FollowupAnalysisClaim,
    *,
    claim_oid: str,
    provider_run_id: int,
    watcher_session_sha256: str,
    workflow_ref: str,
) -> FollowupAnalysisWatchBinding:
    if type(claim) is not FollowupAnalysisClaim:
        raise FollowupAnalysisBindingError("analysis binding lacks its claim")
    _git_sha(claim_oid, field="analysis claim OID")
    return _binding(
        {
            "analysis_source_S3_sha": claim.document["analysis_source_S3_sha"],
            "authority": False,
            "campaign_id": claim.document["campaign_id"],
            "claim_oid": claim_oid,
            "claim_sha256": claim.sha256,
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


def build_followup_analysis_run_admission(
    claim: FollowupAnalysisClaim,
    binding: FollowupAnalysisWatchBinding,
    *,
    binding_oid: str,
) -> FollowupAnalysisRunAdmission:
    if (
        type(claim) is not FollowupAnalysisClaim
        or type(binding) is not FollowupAnalysisWatchBinding
        or binding.document.get("claim_sha256") != claim.sha256
        or binding.document.get("campaign_id") != claim.document["campaign_id"]
        or binding.document.get("analysis_source_S3_sha")
        != claim.document["analysis_source_S3_sha"]
    ):
        raise FollowupAnalysisBindingError("analysis admission lineage changed")
    _git_sha(binding_oid, field="analysis binding OID")
    document = {
        "analysis_runner_seconds_limit": claim.document[
            "analysis_runner_seconds_limit"
        ],
        "analysis_source_S3_sha": claim.document["analysis_source_S3_sha"],
        "authority": False,
        "binding_oid": binding_oid,
        "binding_sha256": binding.sha256,
        "campaign_id": claim.document["campaign_id"],
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
    return FollowupAnalysisRunAdmission(
        document=document,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _parse(content: bytes, *, label: str) -> dict[str, object]:
    if type(content) is not bytes or not content or len(content) > 64 * 1024:
        raise FollowupAnalysisBindingError(f"{label} bytes changed")
    def reject_duplicates(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in rows:
            if key in value:
                raise FollowupAnalysisBindingError(
                    f"{label} contains a duplicate key"
                )
            value[key] = item
        return value

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupAnalysisBindingError(f"{label} contains {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupAnalysisBindingError(f"{label} is not ASCII JSON") from error
    if type(value) is not dict:
        raise FollowupAnalysisBindingError(f"{label} is not one object")
    return value


def inspect_followup_analysis_claim(content: bytes) -> FollowupAnalysisClaim:
    claim = _claim(_parse(content, label="analysis claim"))
    if claim.document_bytes != content:
        raise FollowupAnalysisBindingError("analysis claim is not canonical")
    return claim


def inspect_followup_analysis_watch_binding(
    content: bytes,
) -> FollowupAnalysisWatchBinding:
    binding = _binding(_parse(content, label="analysis watch binding"))
    if binding.document_bytes != content:
        raise FollowupAnalysisBindingError(
            "analysis watch binding is not canonical"
        )
    return binding
