"""Independent admission of the complete seventeen-unit formal artifact set."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.followup_performance_acquisition import (
    build_followup_acquisition_provider_binding,
    inspect_followup_acquisition_artifact,
)
from dynamic_cssc.followup_performance_campaign import FollowupCampaignSelection
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
    _issue_followup_inner_admission,
    _parse_ascii_json,
    build_followup_unit_identity,
    followup_artifact_name,
    inspect_followup_outer_envelope,
    seal_followup_inner_payload,
)
from dynamic_cssc.followup_performance_formal_artifacts import (
    _checksums,
    _direct_directory,
    _stable_read,
    _write_new,
    expected_followup_formal_synthetic_artifact_name,
    inspect_followup_formal_synthetic_artifact,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.followup_performance_formal_native_artifacts import (
    expected_followup_formal_native_artifact_name,
    inspect_followup_formal_native_artifact,
)
from dynamic_cssc.followup_performance_formal_ordered_artifacts import (
    expected_followup_formal_ordered_artifact_name,
    inspect_followup_formal_ordered_artifact,
)
from dynamic_cssc.followup_performance_formal_timing import (
    FollowupFormalTimingLedger,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

__all__ = (
    "FollowupFormalArtifactRecord",
    "FollowupFormalArtifactSet",
    "FollowupTerminalAdmissionError",
    "FollowupTerminalAdmissionInspection",
    "inspect_followup_formal_artifact_set",
    "inspect_followup_terminal_admission",
    "produce_followup_terminal_admission",
)

_ADMISSION_SCHEMA = "dynamic-cssc-followup-performance-terminal-admission-v1"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)
_FINAL_COUNTS = {
    "formal-acquisition": 1,
    "formal-native": 6,
    "formal-ordered-event": 4,
    "formal-synthetic": 6,
}


class FollowupTerminalAdmissionError(FollowupContractError):
    """The formal artifact set or terminal admission did not close exactly."""


@dataclass(frozen=True, slots=True)
class FollowupFormalArtifactRecord:
    ordinal: int
    unit_kind: str
    artifact_name: str
    unit_identity_sha256: str
    envelope_sha256: str
    inner_sha256: str
    artifact_id: int
    artifact_provider_digest: str
    campaign_run_admission_sha256: str
    committed_state_sha256: str
    provider_run_id: int
    unit_attempt_ordinal: int
    scope: dict[str, object]

    def document(self) -> dict[str, object]:
        return {
            "artifact_name": self.artifact_name,
            "artifact_id": self.artifact_id,
            "artifact_provider_digest": self.artifact_provider_digest,
            "campaign_run_admission_sha256": self.campaign_run_admission_sha256,
            "committed_state_sha256": self.committed_state_sha256,
            "envelope_sha256": self.envelope_sha256,
            "inner_sha256": self.inner_sha256,
            "ordinal": self.ordinal,
            "scope": self.scope,
            "provider_run_attempt": 1,
            "provider_run_id": self.provider_run_id,
            "unit_attempt_ordinal": self.unit_attempt_ordinal,
            "unit_identity_sha256": self.unit_identity_sha256,
            "unit_kind": self.unit_kind,
        }


@dataclass(frozen=True, slots=True)
class FollowupFormalArtifactSet:
    records: tuple[FollowupFormalArtifactRecord, ...]
    inspections: tuple[object, ...]
    document_bytes: bytes
    sha256: str
    campaign_selection_sha256: str


def _record(
    *,
    ordinal: int,
    unit_kind: str,
    inspection: object,
    selected: dict[str, object],
    scope: dict[str, object],
) -> FollowupFormalArtifactRecord:
    artifact_name = getattr(inspection, "artifact_name", None)
    root = getattr(inspection, "root", None)
    unit_identity = getattr(inspection, "unit_identity_sha256", None)
    envelope = getattr(inspection, "envelope", None)
    selected_attempt = selected.get("unit_attempt_ordinal")
    selected_artifact_id = selected.get("artifact_id")
    selected_artifact_digest = selected.get("artifact_provider_digest")
    selected_admission = selected.get("campaign_run_admission_sha256")
    selected_state = selected.get("committed_state_sha256")
    selected_run_id = selected.get("provider_run_id")
    if (
        type(artifact_name) is not str
        or not isinstance(root, Path)
        or root.name != artifact_name
        or type(unit_identity) is not str
        or not isinstance(envelope, FollowupEvidenceEnvelope)
        or type(selected_attempt) is not int
        or envelope.document.get("unit_attempt_ordinal") != selected_attempt
        or envelope.document.get("unit_kind") != unit_kind
        or envelope.document.get("unit_identity_sha256") != unit_identity
        or envelope.sha256 != selected.get("unit_output_envelope_sha256")
        or artifact_name != selected.get("artifact_name")
        or selected.get("formal_unit_ordinal") != ordinal
        or selected.get("unit_kind") != unit_kind
        or type(selected_artifact_id) is not int
        or type(selected_artifact_digest) is not str
        or type(selected_admission) is not str
        or type(selected_state) is not str
        or type(selected_run_id) is not int
    ):
        raise FollowupTerminalAdmissionError(
            "formal artifact provider name or outer identity changed"
        )
    inner_sha = envelope.document.get("inner_sha256")
    if type(inner_sha) is not str:
        raise FollowupTerminalAdmissionError("formal artifact inner digest is absent")
    return FollowupFormalArtifactRecord(
        ordinal=ordinal,
        unit_kind=unit_kind,
        artifact_name=artifact_name,
        unit_identity_sha256=unit_identity,
        envelope_sha256=envelope.sha256,
        inner_sha256=inner_sha,
        artifact_id=selected_artifact_id,
        artifact_provider_digest=selected_artifact_digest,
        campaign_run_admission_sha256=selected_admission,
        committed_state_sha256=selected_state,
        provider_run_id=selected_run_id,
        unit_attempt_ordinal=selected_attempt,
        scope=scope,
    )


def _classify_children(
    artifact_root: Path,
    *,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
) -> dict[str, dict[str, Path]]:
    artifact_root = _direct_directory(
        artifact_root,
        label="formal terminal input root",
    )
    children = tuple(sorted(artifact_root.iterdir(), key=lambda path: path.name))
    if len(children) != 17 or any(child.is_symlink() or not child.is_dir() for child in children):
        raise FollowupTerminalAdmissionError(
            "terminal admission requires exactly seventeen direct directories"
        )
    classified = {kind: {} for kind in _FINAL_COUNTS}
    for child in children:
        inner = _stable_read(child / "inner-payload.json")
        envelope = inspect_followup_outer_envelope(
            _stable_read(child / "outer-envelope.json"),
            inner,
            expected_experiment_source_s1_sha=experiment_source_s1_sha,
            expected_evidence_freeze_s2_sha=evidence_freeze_s2_sha,
        )
        kind = envelope.document["unit_kind"]
        if kind not in classified or child.name in classified[kind]:
            raise FollowupTerminalAdmissionError(
                "terminal input contains an unexpected or duplicate unit kind"
            )
        classified[kind][child.name] = child
    if {kind: len(paths) for kind, paths in classified.items()} != _FINAL_COUNTS:
        raise FollowupTerminalAdmissionError("formal artifact kind counts changed")
    return classified


def _named(mapping: dict[str, Path], expected_name: str) -> Path:
    try:
        return mapping[expected_name]
    except KeyError as error:
        raise FollowupTerminalAdmissionError(
            "terminal input lacks one exact expected artifact name"
        ) from error


def inspect_followup_formal_artifact_set(
    artifact_root: Path,
    *,
    repository_root: Path,
    campaign_selection: FollowupCampaignSelection,
    scientific_profile: RouteAScientificProfile,
    machine_plan_bytes: bytes,
) -> FollowupFormalArtifactSet:
    """Reinspect and order the exact final-successful-attempt 17-object set."""

    if type(campaign_selection) is not FollowupCampaignSelection:
        raise TypeError("campaign_selection must be exact")
    if type(scientific_profile) is not RouteAScientificProfile:
        raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
    selection = campaign_selection.document
    s1 = selection.get("experiment_source_S1_sha")
    s2 = selection.get("evidence_freeze_S2_sha")
    compatibility = selection.get("compatibility_receipt_sha256")
    campaign_id = selection.get("campaign_id")
    if any(type(value) is not str for value in (s1, s2, compatibility, campaign_id)):
        raise FollowupTerminalAdmissionError("campaign selection lineage changed")
    assert type(s1) is str
    assert type(s2) is str
    assert type(compatibility) is str
    assert type(campaign_id) is str
    units = campaign_selection.units
    specs = followup_formal_unit_specs(scientific_profile)
    if len(units) != 17:
        raise FollowupTerminalAdmissionError("campaign selection is incomplete")
    classified = _classify_children(
        artifact_root,
        experiment_source_s1_sha=s1,
        evidence_freeze_s2_sha=s2,
    )
    records: list[FollowupFormalArtifactRecord] = []
    inspections: list[object] = []

    def selected_lineage(ordinal: int) -> RouteASyntheticSuiteLineage:
        selected = units[ordinal]
        run_id = selected.get("provider_run_id")
        run_attempt = selected.get("provider_run_attempt")
        if type(run_id) is not int or run_attempt != 1:
            raise FollowupTerminalAdmissionError("campaign selection provider lineage changed")
        return RouteASyntheticSuiteLineage(
            experiment_source_sha=s1,
            workflow_head_sha=s2,
            compatibility_receipt_sha256=compatibility,
            provider_run_id=run_id,
            provider_run_attempt=1,
        )

    def binding(ordinal: int) -> dict[str, object]:
        selected = units[ordinal]
        admission = selected.get("campaign_run_admission_sha256")
        attempt = selected.get("unit_attempt_ordinal")
        if type(admission) is not str or type(attempt) is not int:
            raise FollowupTerminalAdmissionError("campaign selection attempt binding changed")
        return {
            "campaign_id": campaign_id,
            "campaign_run_admission_sha256": admission,
            "formal_unit_ordinal": ordinal,
            "unit_attempt_ordinal": attempt,
        }

    acquisition_root = next(iter(classified["formal-acquisition"].values()))
    acquisition_lineage = selected_lineage(0)
    acquisition = inspect_followup_acquisition_artifact(
        acquisition_root,
        phase="guarded-final",
        lineage=acquisition_lineage,
        **binding(0),
    )
    acquisition_artifact_id = units[0].get("artifact_id")
    acquisition_artifact_digest = units[0].get("artifact_provider_digest")
    if (
        type(acquisition_artifact_id) is not int
        or type(acquisition_artifact_digest) is not str
    ):
        raise FollowupTerminalAdmissionError(
            "acquisition provider selection changed"
        )
    acquisition_provider_binding = build_followup_acquisition_provider_binding(
        acquisition,
        artifact_id=acquisition_artifact_id,
        artifact_provider_digest=acquisition_artifact_digest,
    )
    inspections.append(acquisition)
    records.append(
        _record(
            ordinal=0,
            unit_kind="formal-acquisition",
            inspection=acquisition,
            selected=units[0],
            scope={
                "accepted_trace_sha256s": [
                    partition.accepted_trace_sha256
                    for partition in acquisition.transform.partitions
                ],
                "mapping_sha256s": [
                    partition.mapping_sha256 for partition in acquisition.transform.partitions
                ],
                "raw_object_sha256": acquisition.transform.raw_object_sha256,
                "source_kind": "snap-a2q",
            },
        )
    )

    for spec in specs[1:7]:
        assert spec.scale is not None
        assert spec.formal_seed is not None
        assert spec.strategy_candidate_id is not None
        ordinal = spec.ordinal
        lineage = selected_lineage(ordinal)
        expected = expected_followup_formal_native_artifact_name(
            phase="guarded-final",
            repository_root=repository_root,
            lineage=lineage,
            scale=spec.scale,
            formal_seed=spec.formal_seed,
            strategy_candidate_id=spec.strategy_candidate_id,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            **binding(ordinal),
        )
        inspection = inspect_followup_formal_native_artifact(
            _named(classified["formal-native"], expected),
            phase="guarded-final",
            repository_root=repository_root,
            lineage=lineage,
            scale=spec.scale,
            formal_seed=spec.formal_seed,
            strategy_candidate_id=spec.strategy_candidate_id,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            **binding(ordinal),
        )
        inspections.append(inspection)
        records.append(
            _record(
                ordinal=ordinal,
                unit_kind="formal-native",
                inspection=inspection,
                selected=units[ordinal],
                scope={
                    "case_binding_sha256": inspection.case.case_binding_sha256,
                    "formal_seed": spec.formal_seed,
                    "scale": spec.scale,
                    "source_kind": "synthetic-native-snapshot",
                    "strategy_candidate_id": spec.strategy_candidate_id,
                },
            )
        )

    for spec in specs[7:13]:
        assert spec.scale is not None
        assert spec.formal_seed is not None
        ordinal = spec.ordinal
        lineage = selected_lineage(ordinal)
        trace = generate_route_a_formal_trace(
            scale=spec.scale,
            formal_seed=spec.formal_seed,
            scientific_profile=scientific_profile,
        )
        expected = expected_followup_formal_synthetic_artifact_name(
            phase="guarded-final",
            trace=trace,
            lineage=lineage,
            scientific_profile=scientific_profile,
            **binding(ordinal),
        )
        inspection = inspect_followup_formal_synthetic_artifact(
            _named(classified["formal-synthetic"], expected),
            phase="guarded-final",
            trace=trace,
            lineage=lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            **binding(ordinal),
        )
        inspections.append(inspection)
        records.append(
            _record(
                ordinal=ordinal,
                unit_kind="formal-synthetic",
                inspection=inspection,
                selected=units[ordinal],
                scope={
                    "formal_seed": spec.formal_seed,
                    "scale": spec.scale,
                    "shard_identity_sha256": inspection.inherited.shard_identity_sha256,
                    "source_event_trace_sha256": trace.event_trace_sha256,
                    "source_kind": "synthetic",
                },
            )
        )

    traces = {(trace.partition, trace.semantics): trace for trace in acquisition.traces}
    if set(traces) != {(0, "T1"), (0, "T2"), (1, "T1"), (1, "T2")}:
        raise FollowupTerminalAdmissionError("acquisition ordered trace matrix changed")
    for spec in specs[13:17]:
        assert spec.partition is not None
        assert spec.semantics is not None
        ordinal = spec.ordinal
        lineage = selected_lineage(ordinal)
        trace = traces[(spec.partition, spec.semantics)]
        expected = expected_followup_formal_ordered_artifact_name(
            phase="guarded-final",
            trace=trace,
            lineage=lineage,
            acquisition_provider_binding_sha256=(
                acquisition_provider_binding.sha256
            ),
            **binding(ordinal),
        )
        inspection = inspect_followup_formal_ordered_artifact(
            _named(classified["formal-ordered-event"], expected),
            phase="guarded-final",
            trace=trace,
            lineage=lineage,
            scientific_profile=scientific_profile,
            machine_plan_bytes=machine_plan_bytes,
            acquisition_provider_binding_sha256=(
                acquisition_provider_binding.sha256
            ),
            **binding(ordinal),
        )
        inspections.append(inspection)
        records.append(
            _record(
                ordinal=ordinal,
                unit_kind="formal-ordered-event",
                inspection=inspection,
                selected=units[ordinal],
                scope={
                    "accepted_trace_sha256": trace.accepted_trace_sha256,
                    "mapping_sha256": trace.mapping_sha256,
                    "partition": spec.partition,
                    "raw_object_sha256": trace.raw_object_sha256,
                    "semantics": spec.semantics,
                    "shard_identity_sha256": inspection.inherited.shard_identity_sha256,
                    "source_event_trace_sha256": trace.event_trace_sha256,
                    "source_kind": "snap-a2q",
                },
            )
        )
    if len(records) != 17 or tuple(record.ordinal for record in records) != tuple(range(17)):
        raise AssertionError("formal artifact terminal order changed")
    documents = [record.document() for record in records]
    document_bytes = _canonical_json_bytes(documents)
    return FollowupFormalArtifactSet(
        records=tuple(records),
        inspections=tuple(inspections),
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
        campaign_selection_sha256=campaign_selection.sha256,
    )


def _admission_document(
    artifact_set: FollowupFormalArtifactSet,
    *,
    campaign_selection: FollowupCampaignSelection,
    lineage: RouteASyntheticSuiteLineage,
    timing_ledger: FollowupFormalTimingLedger,
) -> bytes:
    replacement_used = campaign_selection.document.get("replacement_attempt_used")
    if (
        type(timing_ledger) is not FollowupFormalTimingLedger
        or type(campaign_selection) is not FollowupCampaignSelection
        or artifact_set.campaign_selection_sha256 != campaign_selection.sha256
        or timing_ledger.document.get("campaign_selection_sha256")
        != campaign_selection.sha256
        or timing_ledger.document.get("campaign_id")
        != campaign_selection.campaign_id
        or timing_ledger.document.get("formal_unit_count") != 17
        or timing_ledger.document.get("provider_retry_used") is not replacement_used
        or hashlib.sha256(timing_ledger.document_bytes).hexdigest() != timing_ledger.sha256
    ):
        raise FollowupTerminalAdmissionError(
            "formal timing ledger differs from the admitted campaign"
        )
    return _canonical_json_bytes(
        {
            "artifacts": [record.document() for record in artifact_set.records],
            "authority": False,
            "campaign_id": campaign_selection.campaign_id,
            "campaign_selection_sha256": campaign_selection.sha256,
            "formal_artifact_count": 17,
            "formal_artifact_set_sha256": artifact_set.sha256,
            "formal_timing_ledger": timing_ledger.document,
            "formal_timing_ledger_sha256": timing_ledger.sha256,
            "publication_evidence_admitted": True,
            "replacement_attempt_used": replacement_used,
            "schema_version": _ADMISSION_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
            "terminal_provider_run_attempt": lineage.provider_run_attempt,
            "terminal_provider_run_id": lineage.provider_run_id,
        }
    )


def _identity(
    artifact_set: FollowupFormalArtifactSet,
    *,
    campaign_selection: FollowupCampaignSelection,
    lineage: RouteASyntheticSuiteLineage,
    timing_ledger: FollowupFormalTimingLedger,
) -> tuple[bytes, str]:
    return build_followup_unit_identity(
        unit_kind="formal-terminal-admission",
        unit_attempt_ordinal=1,
        scope={
            "campaign_id": campaign_selection.campaign_id,
            "campaign_selection_sha256": campaign_selection.sha256,
            "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": lineage.workflow_head_sha,
            "experiment_source_S1_sha": lineage.experiment_source_sha,
            "formal_artifact_count": 17,
            "formal_artifact_set_sha256": artifact_set.sha256,
            "formal_timing_ledger_sha256": timing_ledger.sha256,
            "replacement_attempt_used": campaign_selection.document[
                "replacement_attempt_used"
            ],
            "terminal_provider_run_attempt": lineage.provider_run_attempt,
            "terminal_provider_run_id": lineage.provider_run_id,
        },
    )


@dataclass(frozen=True, slots=True)
class FollowupTerminalAdmissionInspection:
    artifact_name: str
    root: Path
    formal_artifact_set_sha256: str
    formal_timing_ledger_sha256: str
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    document: dict[str, object]


def inspect_followup_terminal_admission(
    artifact_directory: Path,
    *,
    artifact_set: FollowupFormalArtifactSet,
    campaign_selection: FollowupCampaignSelection,
    lineage: RouteASyntheticSuiteLineage,
    timing_ledger: FollowupFormalTimingLedger,
) -> FollowupTerminalAdmissionInspection:
    """Reinspect one terminal record against the independently reconstructed set."""

    artifact_directory = _direct_directory(
        artifact_directory,
        label="follow-up terminal admission artifact",
    )
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    if set(entries) != {*_WRAPPER_FILES, "checksums.sha256"}:
        raise FollowupTerminalAdmissionError("terminal admission members changed")
    contents = {name: _stable_read(entries[name]) for name in _WRAPPER_FILES}
    if _stable_read(entries["checksums.sha256"]) != _checksums(contents):
        raise FollowupTerminalAdmissionError("terminal admission checksums changed")
    admission_bytes = _admission_document(
        artifact_set,
        campaign_selection=campaign_selection,
        lineage=lineage,
        timing_ledger=timing_ledger,
    )
    if contents["inner-payload.json"] != admission_bytes:
        raise FollowupTerminalAdmissionError("terminal admission artifact set changed")
    value = _parse_ascii_json(admission_bytes, label="formal terminal admission")
    if type(value) is not dict:
        raise FollowupTerminalAdmissionError("terminal admission is not an object")
    unit_bytes, unit_sha256 = _identity(
        artifact_set,
        campaign_selection=campaign_selection,
        lineage=lineage,
        timing_ledger=timing_ledger,
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupTerminalAdmissionError("terminal admission unit identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        admission_bytes,
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != "formal-terminal-admission"
        or envelope.document["inner_role"] != "formal-terminal-admission"
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != 1
    ):
        raise FollowupTerminalAdmissionError("terminal admission envelope changed")
    return FollowupTerminalAdmissionInspection(
        artifact_name=followup_artifact_name(
            unit_kind="formal-terminal-admission",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=1,
        ),
        root=artifact_directory,
        formal_artifact_set_sha256=artifact_set.sha256,
        formal_timing_ledger_sha256=timing_ledger.sha256,
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        document=value,
    )


def produce_followup_terminal_admission(
    artifact_set: FollowupFormalArtifactSet,
    output_directory: Path,
    *,
    campaign_selection: FollowupCampaignSelection,
    lineage: RouteASyntheticSuiteLineage,
    timing_ledger: FollowupFormalTimingLedger,
) -> FollowupTerminalAdmissionInspection:
    """Atomically create the first record admitting the exact complete set."""

    _direct_directory(output_directory.parent, label="terminal admission output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupTerminalAdmissionError("terminal admission output already exists")
    if len(artifact_set.records) != 17:
        raise FollowupTerminalAdmissionError("terminal admission set is incomplete")
    admission_bytes = _admission_document(
        artifact_set,
        campaign_selection=campaign_selection,
        lineage=lineage,
        timing_ledger=timing_ledger,
    )
    unit_bytes, unit_sha256 = _identity(
        artifact_set,
        campaign_selection=campaign_selection,
        lineage=lineage,
        timing_ledger=timing_ledger,
    )
    admission = _issue_followup_inner_admission(
        inner_role="formal-terminal-admission",
        inner_bytes=admission_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind="formal-terminal-admission",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    contents = {
        "inner-payload.json": admission_bytes,
        "outer-envelope.json": envelope.document_bytes,
        "unit-identity.json": unit_bytes,
    }
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    try:
        for name in _WRAPPER_FILES:
            _write_new(temporary / name, contents[name])
        _write_new(temporary / "checksums.sha256", _checksums(contents))
        os.replace(temporary, output_directory)
        return inspect_followup_terminal_admission(
            output_directory,
            artifact_set=artifact_set,
            campaign_selection=campaign_selection,
            lineage=lineage,
            timing_ledger=timing_ledger,
        )
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
