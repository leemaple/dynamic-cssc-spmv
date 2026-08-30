"""Outer follow-up identity for one formal SNAP ordered-event shard.

The inherited ordered-event ZIP stays byte-exact and authority-false.  This
module adds only the follow-up study, lineage, attempt, partition, semantics,
and phase identity required by terminal admission.  A guarded-final wrapper is
still only a candidate until the complete seventeen-unit set is admitted.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dynamic_cssc.followup_performance_campaign import (
    followup_campaign_artifact_binding_scope,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupEvidenceEnvelope,
    _issue_followup_inner_admission,
    build_followup_unit_identity,
    followup_artifact_name,
    followup_inherited_unit_attempt_ordinal,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)
from dynamic_cssc.followup_performance_formal_artifacts import (
    FollowupFormalArtifactError,
    _checksums,
    _direct_directory,
    _direct_file,
    _manifest,
    _sha256_file,
    _stable_read,
    _write_new,
)
from dynamic_cssc.route_a_ordered_suite import (
    RouteAOrderedSuiteProducerInspection,
    RouteAOrderedSuiteReplayInspection,
    inspect_route_a_ordered_suite_handoff,
    inspect_route_a_ordered_suite_replay,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_snap import (
    RouteASnapTrace,
    route_a_snap_shard_identity,
    validate_route_a_snap_trace,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupFormalOrderedArtifactError",
    "FollowupFormalOrderedInspection",
    "expected_followup_formal_ordered_artifact_name",
    "inspect_followup_formal_ordered_artifact",
    "produce_followup_formal_ordered_artifact",
)

FollowupFormalOrderedPhase = Literal["private-handoff", "guarded-final"]
_INNER_FILE = "inner/payload.zip"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)


class FollowupFormalOrderedArtifactError(FollowupFormalArtifactError):
    """One ordered-event outer wrapper or inherited payload failed closed."""


def _phase_role(phase: FollowupFormalOrderedPhase) -> str:
    if phase == "private-handoff":
        return "formal-ordered-event-private-handoff"
    if phase == "guarded-final":
        return "formal-ordered-event-guarded-shard"
    raise FollowupFormalOrderedArtifactError(
        "formal ordered-event phase is outside its closed domain"
    )


def _shard_identity(
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    *,
    inherited_unit_attempt_ordinal: int,
) -> str:
    trace = validate_route_a_snap_trace(trace)
    if type(lineage) is not RouteASyntheticSuiteLineage:
        raise TypeError("lineage must be an exact RouteASyntheticSuiteLineage")
    return route_a_snap_shard_identity(
        trace,
        experiment_source_sha=lineage.experiment_source_sha,
        workflow_head_sha=lineage.workflow_head_sha,
        compatibility_receipt_sha256=lineage.compatibility_receipt_sha256,
        provider_run_id=lineage.provider_run_id,
        provider_run_attempt=lineage.provider_run_attempt,
        unit_attempt_ordinal=inherited_unit_attempt_ordinal,
    )


def _identity(
    *,
    phase: FollowupFormalOrderedPhase,
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    unit_attempt_ordinal: int,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    acquisition_provider_binding_sha256: str,
) -> tuple[bytes, str, str]:
    inherited_attempt = followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-ordered-event",
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    if re.fullmatch(r"[0-9a-f]{64}", acquisition_provider_binding_sha256) is None:
        raise FollowupFormalOrderedArtifactError(
            "acquisition provider binding is not one lowercase SHA-256"
        )
    trace = validate_route_a_snap_trace(trace)
    shard_identity = _shard_identity(
        trace,
        lineage,
        inherited_unit_attempt_ordinal=inherited_attempt,
    )
    scope = {
        "acquisition_provider_binding_sha256": (
            acquisition_provider_binding_sha256
        ),
        "accepted_trace_sha256": trace.accepted_trace_sha256,
        "artifact_phase": phase,
        "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
        "evidence_freeze_S2_sha": lineage.workflow_head_sha,
        "experiment_source_S1_sha": lineage.experiment_source_sha,
        "inherited_unit_attempt_ordinal": inherited_attempt,
        "mapping_sha256": trace.mapping_sha256,
        "partition": trace.partition,
        "provider_run_attempt": lineage.provider_run_attempt,
        "provider_run_id": lineage.provider_run_id,
        "raw_object_sha256": trace.raw_object_sha256,
        "semantics": trace.semantics,
        "shard_identity_sha256": shard_identity,
        "source_event_trace_sha256": trace.event_trace_sha256,
        "source_kind": "snap-a2q",
    }
    scope.update(
        followup_campaign_artifact_binding_scope(
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
        )
    )
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind="formal-ordered-event",
        unit_attempt_ordinal=unit_attempt_ordinal,
        scope=scope,
    )
    return unit_bytes, unit_sha256, shard_identity


def expected_followup_formal_ordered_artifact_name(
    *,
    phase: FollowupFormalOrderedPhase,
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    acquisition_provider_binding_sha256: str,
    unit_attempt_ordinal: int = 1,
) -> str:
    """Derive the exact provider name without executing the ordered cells."""

    _unit_bytes, unit_sha256, _shard = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
        acquisition_provider_binding_sha256=acquisition_provider_binding_sha256,
    )
    return followup_artifact_name(
        unit_kind="formal-ordered-event",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )


def _inspect_inherited(
    payload_path: Path,
    *,
    phase: FollowupFormalOrderedPhase,
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    inherited_unit_attempt_ordinal: int,
) -> RouteAOrderedSuiteProducerInspection | RouteAOrderedSuiteReplayInspection:
    if phase == "private-handoff":
        return inspect_route_a_ordered_suite_handoff(
            payload_path,
            expected_trace=trace,
            expected_lineage=lineage,
            machine_plan_bytes=machine_plan_bytes,
            unit_attempt_ordinal=inherited_unit_attempt_ordinal,
            scientific_profile=scientific_profile,
        )
    if phase == "guarded-final":
        return inspect_route_a_ordered_suite_replay(
            payload_path,
            expected_trace=trace,
            expected_lineage=lineage,
            machine_plan_bytes=machine_plan_bytes,
            unit_attempt_ordinal=inherited_unit_attempt_ordinal,
            scientific_profile=scientific_profile,
        )
    raise FollowupFormalOrderedArtifactError(
        "formal ordered-event phase is outside its closed domain"
    )


@dataclass(frozen=True, slots=True)
class FollowupFormalOrderedInspection:
    phase: FollowupFormalOrderedPhase
    root: Path
    payload_path: Path
    payload_sha256: str
    payload_byte_count: int
    artifact_name: str
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    inherited: RouteAOrderedSuiteProducerInspection | RouteAOrderedSuiteReplayInspection


def inspect_followup_formal_ordered_artifact(
    root: Path,
    *,
    phase: FollowupFormalOrderedPhase,
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    acquisition_provider_binding_sha256: str,
    unit_attempt_ordinal: int = 1,
) -> FollowupFormalOrderedInspection:
    """Rehash the outer tree before decoding its inherited ordered ZIP."""

    root = _direct_directory(root, label="formal ordered-event artifact root")
    expected_paths = {
        "checksums.sha256",
        "inner",
        _INNER_FILE,
        *_WRAPPER_FILES,
    }
    if (
        {path.relative_to(root).as_posix() for path in root.rglob("*")}
        != expected_paths
        or not (root / "inner").is_dir()
    ):
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event wrapper members changed"
        )
    contents = {name: _stable_read(root / name) for name in _WRAPPER_FILES}
    if _stable_read(root / "checksums.sha256") != _checksums(contents):
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event wrapper checksums changed"
        )
    payload_path = _direct_file(root / _INNER_FILE, label="formal ordered-event payload")
    payload_sha256, payload_bytes = _sha256_file(payload_path)
    unit_bytes, unit_sha256, shard_identity = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
        acquisition_provider_binding_sha256=acquisition_provider_binding_sha256,
    )
    manifest_bytes = _manifest(
        phase=phase,
        payload_sha256=payload_sha256,
        payload_bytes=payload_bytes,
        shard_identity_sha256=shard_identity,
    )
    if (
        contents["unit-identity.json"] != unit_bytes
        or contents["inner-payload.json"] != manifest_bytes
    ):
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event wrapper identity changed"
        )
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        contents["inner-payload.json"],
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != "formal-ordered-event"
        or envelope.document["inner_role"] != _phase_role(phase)
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != unit_attempt_ordinal
    ):
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event envelope changed"
        )
    inherited = _inspect_inherited(
        payload_path,
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        inherited_unit_attempt_ordinal=followup_inherited_unit_attempt_ordinal(
            unit_kind="formal-ordered-event",
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
    )
    if inherited.shard_identity_sha256 != shard_identity:
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event inherited shard changed"
        )
    return FollowupFormalOrderedInspection(
        phase=phase,
        root=root,
        payload_path=payload_path,
        payload_sha256=payload_sha256,
        payload_byte_count=payload_bytes,
        artifact_name=followup_artifact_name(
            unit_kind="formal-ordered-event",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        inherited=inherited,
    )


def produce_followup_formal_ordered_artifact(
    source_payload: Path,
    output_directory: Path,
    *,
    phase: FollowupFormalOrderedPhase,
    trace: RouteASnapTrace,
    lineage: RouteASyntheticSuiteLineage,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
    campaign_id: str,
    campaign_run_admission_sha256: str,
    formal_unit_ordinal: int,
    acquisition_provider_binding_sha256: str,
    unit_attempt_ordinal: int = 1,
) -> FollowupFormalOrderedInspection:
    """Validate and atomically move one ordered ZIP into its outer tree."""

    source_payload = _direct_file(source_payload, label="fresh formal ordered payload")
    output_parent = _direct_directory(
        output_directory.parent,
        label="formal ordered output parent",
    )
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event output target already exists"
        )
    _inspect_inherited(
        source_payload,
        phase=phase,
        trace=trace,
        lineage=lineage,
        scientific_profile=scientific_profile,
        machine_plan_bytes=machine_plan_bytes,
        inherited_unit_attempt_ordinal=followup_inherited_unit_attempt_ordinal(
            unit_kind="formal-ordered-event",
            unit_attempt_ordinal=unit_attempt_ordinal,
        ),
    )
    payload_sha256, payload_bytes = _sha256_file(source_payload)
    unit_bytes, unit_sha256, shard_identity = _identity(
        phase=phase,
        trace=trace,
        lineage=lineage,
        unit_attempt_ordinal=unit_attempt_ordinal,
        campaign_id=campaign_id,
        campaign_run_admission_sha256=campaign_run_admission_sha256,
        formal_unit_ordinal=formal_unit_ordinal,
        acquisition_provider_binding_sha256=acquisition_provider_binding_sha256,
    )
    manifest_bytes = _manifest(
        phase=phase,
        payload_sha256=payload_sha256,
        payload_bytes=payload_bytes,
        shard_identity_sha256=shard_identity,
    )
    admission = _issue_followup_inner_admission(
        inner_role=_phase_role(phase),
        inner_bytes=manifest_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind="formal-ordered-event",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
    )
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_parent)
    )
    moved = False
    try:
        (temporary / "inner").mkdir(mode=0o700)
        os.replace(source_payload, temporary / _INNER_FILE)
        moved = True
        contents = {
            "inner-payload.json": manifest_bytes,
            "outer-envelope.json": envelope.document_bytes,
            "unit-identity.json": unit_bytes,
        }
        for name in _WRAPPER_FILES:
            _write_new(temporary / name, contents[name])
        _write_new(temporary / "checksums.sha256", _checksums(contents))
        os.replace(temporary, output_directory)
        return inspect_followup_formal_ordered_artifact(
            output_directory,
            phase=phase,
            trace=trace,
            lineage=lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            campaign_id=campaign_id,
            campaign_run_admission_sha256=campaign_run_admission_sha256,
            formal_unit_ordinal=formal_unit_ordinal,
            acquisition_provider_binding_sha256=(
                acquisition_provider_binding_sha256
            ),
            unit_attempt_ordinal=unit_attempt_ordinal,
        )
    except BaseException:
        if moved and not source_payload.exists():
            candidate = temporary / _INNER_FILE
            if candidate.is_file() and not candidate.is_symlink():
                os.replace(candidate, source_payload)
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
