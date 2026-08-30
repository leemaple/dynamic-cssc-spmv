"""Deterministic raw-result aggregate after terminal admission."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.followup_performance_acquisition import (
    FollowupAcquisitionInspection,
)
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
    FollowupFormalSyntheticInspection,
    _checksums,
    _direct_directory,
    _stable_read,
    _write_new,
)
from dynamic_cssc.followup_performance_formal_native_artifacts import (
    FollowupFormalNativeInspection,
)
from dynamic_cssc.followup_performance_formal_ordered_artifacts import (
    FollowupFormalOrderedInspection,
)
from dynamic_cssc.followup_performance_terminal import (
    FollowupFormalArtifactSet,
    FollowupTerminalAdmissionInspection,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

__all__ = (
    "FollowupAggregateError",
    "FollowupAggregateInspection",
    "inspect_followup_aggregate",
    "produce_followup_aggregate",
)

_AGGREGATE_SCHEMA = "dynamic-cssc-followup-performance-formal-aggregate-v1"
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)


class FollowupAggregateError(FollowupContractError):
    """An admitted formal aggregate failed closed."""


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    value = _parse_ascii_json(content, label=label)
    if type(value) is not dict or _canonical_json_bytes(value) != content:
        raise FollowupAggregateError(f"{label} is not one canonical object")
    return value


def _receipt_documents(contents: tuple[bytes, ...], *, label: str) -> list[dict[str, object]]:
    return [
        _canonical_object(content, label=f"{label} {ordinal}")
        for ordinal, content in enumerate(contents)
    ]


def _aggregate_document(
    artifact_set: FollowupFormalArtifactSet,
    terminal: FollowupTerminalAdmissionInspection,
    *,
    lineage: RouteASyntheticSuiteLineage,
) -> bytes:
    if (
        len(artifact_set.records) != 17
        or len(artifact_set.inspections) != 17
        or terminal.formal_artifact_set_sha256 != artifact_set.sha256
        or terminal.document.get("publication_evidence_admitted") is not True
        or terminal.document.get("formal_campaign_provider_run_id")
        != lineage.provider_run_id
        or terminal.document.get("formal_campaign_provider_run_attempt")
        != lineage.provider_run_attempt
    ):
        raise FollowupAggregateError("aggregate lacks one exact terminal admission")
    acquisition = artifact_set.inspections[0]
    if type(acquisition) is not FollowupAcquisitionInspection:
        raise FollowupAggregateError("aggregate acquisition inspection changed")
    simulator_rows: list[dict[str, object]] = []
    native_rows: list[dict[str, object]] = []
    for record, inspection in zip(
        artifact_set.records[1:],
        artifact_set.inspections[1:],
        strict=True,
    ):
        if record.unit_kind == "formal-native":
            if (
                type(inspection) is not FollowupFormalNativeInspection
                or inspection.producer_observations_bytes is None
                or inspection.inherited.guard_receipt_bytes is None
            ):
                raise FollowupAggregateError("aggregate native final is incomplete")
            replays = tuple(
                _stable_read(inspection.inner_directory / f"replays/recorded-{ordinal}.json")
                for ordinal in range(3)
            )
            native_rows.append(
                {
                    "case_binding_sha256": inspection.case.case_binding_sha256,
                    "formal_unit_ordinal": record.ordinal,
                    "guard_receipt": _canonical_object(
                        inspection.inherited.guard_receipt_bytes,
                        label="native guard receipt",
                    ),
                    "producer_observations": _canonical_object(
                        inspection.producer_observations_bytes,
                        label="native producer observations",
                    ),
                    "replay_receipts": _receipt_documents(
                        replays,
                        label="native replay receipt",
                    ),
                    "scope": record.scope,
                    "unit_identity_sha256": record.unit_identity_sha256,
                }
            )
            continue
        if type(inspection) is FollowupFormalSyntheticInspection:
            cells = (*inspection.inherited.final_cells, *inspection.inherited.rho10_cells)
            replay_receipts = inspection.inherited.replay_receipts
            guard_receipts = inspection.inherited.guard_receipts
        elif type(inspection) is FollowupFormalOrderedInspection:
            cells = inspection.inherited.final_cells
            replay_receipts = inspection.inherited.replay_receipts
            guard_receipts = inspection.inherited.guard_receipts
        else:
            raise FollowupAggregateError("aggregate formal inspection kind changed")
        simulator_rows.append(
            {
                "cells": [
                    {
                        "document": cell.document,
                        "sha256": cell.sha256,
                    }
                    for cell in cells
                ],
                "formal_unit_ordinal": record.ordinal,
                "guard_receipt_sha256s": [
                    hashlib.sha256(content).hexdigest() for content in guard_receipts
                ],
                "replay_receipt_sha256s": [
                    hashlib.sha256(content).hexdigest() for content in replay_receipts
                ],
                "scope": record.scope,
                "unit_identity_sha256": record.unit_identity_sha256,
                "unit_kind": record.unit_kind,
            }
        )
    if (
        len(native_rows) != 6
        or len(simulator_rows) != 10
        or sum(len(row["cells"]) for row in simulator_rows) != 96
    ):
        raise FollowupAggregateError("aggregate result matrix changed")
    return _canonical_json_bytes(
        {
            "acquisition": {
                "guard_receipt": acquisition.guard_receipt.document,
                "producer_receipt": acquisition.producer_receipt.document,
                "raw_object_sha256": acquisition.transform.raw_object_sha256,
                "raw_source_bytes_included": False,
                "unit_identity_sha256": artifact_set.records[0].unit_identity_sha256,
            },
            "analysis_authority": False,
            "formal_artifact_set_sha256": artifact_set.sha256,
            "formal_artifacts": [
                record.document() for record in artifact_set.records
            ],
            "formal_campaign_provider_run_attempt": lineage.provider_run_attempt,
            "formal_campaign_provider_run_id": lineage.provider_run_id,
            "native_cases": native_rows,
            "publication_evidence_admitted": True,
            "schema_version": _AGGREGATE_SCHEMA,
            "simulator_shards": simulator_rows,
            "study_id": FOLLOWUP_STUDY_ID,
            "terminal_admission_artifact_name": terminal.artifact_name,
            "terminal_admission_envelope_sha256": terminal.envelope.sha256,
            "terminal_admission_unit_identity_sha256": terminal.unit_identity_sha256,
        }
    )


def _identity(
    aggregate_bytes: bytes,
    *,
    artifact_set: FollowupFormalArtifactSet,
    terminal: FollowupTerminalAdmissionInspection,
    lineage: RouteASyntheticSuiteLineage,
) -> tuple[bytes, str]:
    return build_followup_unit_identity(
        unit_kind="formal-aggregate",
        unit_attempt_ordinal=1,
        scope={
            "aggregate_sha256": hashlib.sha256(aggregate_bytes).hexdigest(),
            "compatibility_receipt_sha256": lineage.compatibility_receipt_sha256,
            "evidence_freeze_S2_sha": lineage.workflow_head_sha,
            "experiment_source_S1_sha": lineage.experiment_source_sha,
            "formal_artifact_set_sha256": artifact_set.sha256,
            "formal_campaign_provider_run_attempt": lineage.provider_run_attempt,
            "formal_campaign_provider_run_id": lineage.provider_run_id,
            "terminal_admission_envelope_sha256": terminal.envelope.sha256,
            "terminal_admission_unit_identity_sha256": terminal.unit_identity_sha256,
        },
    )


@dataclass(frozen=True, slots=True)
class FollowupAggregateInspection:
    artifact_name: str
    root: Path
    aggregate_sha256: str
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    document: dict[str, object]


def inspect_followup_aggregate(
    artifact_directory: Path,
    *,
    artifact_set: FollowupFormalArtifactSet,
    terminal: FollowupTerminalAdmissionInspection,
    lineage: RouteASyntheticSuiteLineage,
) -> FollowupAggregateInspection:
    """Recompute an aggregate from admitted inspections and compare exact bytes."""

    artifact_directory = _direct_directory(
        artifact_directory,
        label="follow-up aggregate artifact",
    )
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    if set(entries) != {*_WRAPPER_FILES, "checksums.sha256"}:
        raise FollowupAggregateError("aggregate wrapper members changed")
    contents = {name: _stable_read(entries[name]) for name in _WRAPPER_FILES}
    if _stable_read(entries["checksums.sha256"]) != _checksums(contents):
        raise FollowupAggregateError("aggregate wrapper checksums changed")
    aggregate_bytes = _aggregate_document(
        artifact_set,
        terminal,
        lineage=lineage,
    )
    if contents["inner-payload.json"] != aggregate_bytes:
        raise FollowupAggregateError("aggregate raw result bytes changed")
    unit_bytes, unit_sha256 = _identity(
        aggregate_bytes,
        artifact_set=artifact_set,
        terminal=terminal,
        lineage=lineage,
    )
    if contents["unit-identity.json"] != unit_bytes:
        raise FollowupAggregateError("aggregate unit identity changed")
    envelope = inspect_followup_outer_envelope(
        contents["outer-envelope.json"],
        aggregate_bytes,
        expected_experiment_source_s1_sha=lineage.experiment_source_sha,
        expected_evidence_freeze_s2_sha=lineage.workflow_head_sha,
    )
    if (
        envelope.document["unit_kind"] != "formal-aggregate"
        or envelope.document["inner_role"] != "formal-aggregate"
        or envelope.document["unit_identity_sha256"] != unit_sha256
        or envelope.document["unit_attempt_ordinal"] != 1
    ):
        raise FollowupAggregateError("aggregate outer envelope changed")
    return FollowupAggregateInspection(
        artifact_name=followup_artifact_name(
            unit_kind="formal-aggregate",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=1,
        ),
        root=artifact_directory,
        aggregate_sha256=hashlib.sha256(aggregate_bytes).hexdigest(),
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        document=_canonical_object(aggregate_bytes, label="formal aggregate"),
    )


def produce_followup_aggregate(
    artifact_set: FollowupFormalArtifactSet,
    terminal: FollowupTerminalAdmissionInspection,
    output_directory: Path,
    *,
    lineage: RouteASyntheticSuiteLineage,
) -> FollowupAggregateInspection:
    """Atomically render one raw-data aggregate with no statistical claims."""

    _direct_directory(output_directory.parent, label="aggregate output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupAggregateError("aggregate output already exists")
    aggregate_bytes = _aggregate_document(
        artifact_set,
        terminal,
        lineage=lineage,
    )
    unit_bytes, unit_sha256 = _identity(
        aggregate_bytes,
        artifact_set=artifact_set,
        terminal=terminal,
        lineage=lineage,
    )
    admission = _issue_followup_inner_admission(
        inner_role="formal-aggregate",
        inner_bytes=aggregate_bytes,
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=lineage.experiment_source_sha,
        evidence_freeze_s2_sha=lineage.workflow_head_sha,
        unit_kind="formal-aggregate",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    contents = {
        "inner-payload.json": aggregate_bytes,
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
        return inspect_followup_aggregate(
            output_directory,
            artifact_set=artifact_set,
            terminal=terminal,
            lineage=lineage,
        )
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
