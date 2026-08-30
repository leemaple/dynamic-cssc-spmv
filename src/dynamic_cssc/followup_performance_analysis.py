"""Deterministic descriptive analysis of one terminal-admitted follow-up aggregate."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.followup_performance_aggregate import FollowupAggregateInspection
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
)
from dynamic_cssc.followup_performance_lineage import FollowupCompatibilityReceipt

__all__ = (
    "FollowupAnalysisError",
    "FollowupAnalysisInspection",
    "inspect_followup_analysis",
    "produce_followup_analysis",
)

_ANALYSIS_SCHEMA = "dynamic-cssc-followup-performance-descriptive-analysis-v1"
_MANIFEST_SCHEMA = "dynamic-cssc-followup-performance-analysis-manifest-v1"
_FILES = (
    "SUMMARY.md",
    "analysis-compatibility.json",
    "analysis.json",
    "claim-to-artifact.csv",
    "native-repetitions.csv",
    "native-summary.csv",
    "simulator-cells.csv",
)
_WRAPPER_FILES = (
    "inner-payload.json",
    "outer-envelope.json",
    "unit-identity.json",
)


class FollowupAnalysisError(FollowupContractError):
    """One descriptive analysis or its S1/S2/S3 binding failed closed."""


def _csv_bytes(fields: tuple[str, ...], rows: list[dict[str, object]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=fields,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({field: "" if row[field] is None else row[field] for field in fields})
    try:
        return stream.getvalue().encode("ascii")
    except UnicodeEncodeError as error:
        raise FollowupAnalysisError("analysis CSV is not ASCII") from error


def _object(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise FollowupAnalysisError(f"{label} is not one object")
    return value


def _integer(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise FollowupAnalysisError(f"{label} is not a nonnegative integer")
    return value


def _middle(values: list[int], *, label: str) -> int:
    if len(values) != 3 or any(type(value) is not int or value < 0 for value in values):
        raise FollowupAnalysisError(f"{label} is not three raw repetitions")
    return sorted(values)[1]


def _analysis_rows(
    aggregate: FollowupAggregateInspection,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    document = aggregate.document
    native = document.get("native_cases")
    simulator = document.get("simulator_shards")
    if (
        document.get("publication_evidence_admitted") is not True
        or document.get("analysis_authority") is not False
        or type(native) is not list
        or len(native) != 6
        or type(simulator) is not list
        or len(simulator) != 10
    ):
        raise FollowupAnalysisError("analysis input is not one admitted complete aggregate")

    simulator_rows: list[dict[str, object]] = []
    for shard in simulator:
        shard = _object(shard, label="simulator shard")
        cells = shard.get("cells")
        if type(cells) is not list:
            raise FollowupAnalysisError("simulator shard cells are absent")
        for cell in cells:
            cell = _object(cell, label="simulator cell wrapper")
            value = _object(cell.get("document"), label="simulator cell")
            identity = _object(value.get("identity"), label="cell identity")
            evaluation = _object(value.get("evaluation"), label="cell evaluation")
            counts = _object(value.get("counts"), label="cell counts")
            measurements = _object(value.get("measurements"), label="cell measurements")
            serialized = _object(value.get("serialized_bytes"), label="cell serialized bytes")
            if any(type(item) is not int or item < 0 for item in serialized.values()):
                raise FollowupAnalysisError("cell serialized byte projection changed")
            simulator_rows.append(
                {
                    "cell_sha256": cell.get("sha256"),
                    "count_measurement_label": "exactly-counted",
                    "evaluation_mode": evaluation.get("mode"),
                    "formal_seed_or_null": identity.get("formal_seed_or_null"),
                    "object_sha256_or_null": identity.get("object_sha256_or_null"),
                    "partition_or_null": identity.get("partition_or_null"),
                    "peak_rss_kib_or_null": measurements.get("peak_rss_kib"),
                    "producer_result_assembly_seconds_or_null": measurements.get(
                        "producer_result_assembly_seconds"
                    ),
                    "producer_state_transition_seconds_or_null": measurements.get(
                        "producer_state_transition_seconds"
                    ),
                    "queries": _integer(counts.get("queries"), label="cell queries"),
                    "replay_seconds_or_null": measurements.get("replay_seconds"),
                    "rho": identity.get("rho"),
                    "scale_or_null": identity.get("scale_or_null"),
                    "scratch_allocated_bytes_or_null": measurements.get(
                        "scratch_allocated_bytes"
                    ),
                    "semantics_or_null": identity.get("semantics_or_null"),
                    "serialized_bytes_measurement_label": "upper-bound-projected",
                    "serialized_bytes_total": sum(serialized.values()),
                    "source_kind": identity.get("source_kind"),
                    "strategy_candidate_id": identity.get("strategy_candidate_id"),
                    "timing_measurement_label": (
                        "exactly-rescaled"
                        if evaluation.get("mode") == "exact-query-linear-projection"
                        else "directly-measured"
                    ),
                    "unit_ordinal": shard.get("formal_unit_ordinal"),
                    "updates": _integer(counts.get("updates"), label="cell updates"),
                    "windows": _integer(counts.get("windows"), label="cell windows"),
                }
            )
    if len(simulator_rows) != 96:
        raise FollowupAnalysisError("analysis simulator matrix changed")

    native_rows: list[dict[str, object]] = []
    native_summaries: list[dict[str, object]] = []
    for case in native:
        case = _object(case, label="native case")
        scope = _object(case.get("scope"), label="native scope")
        observations = _object(
            case.get("producer_observations"),
            label="native producer observations",
        )
        ledger = _object(observations.get("producer_stage_ledger"), label="native ledger")
        processes = ledger.get("processes")
        packages = observations.get("recorded_packages")
        replays = case.get("replay_receipts")
        if (
            type(processes) is not list
            or len(processes) != 4
            or type(packages) is not list
            or len(packages) != 3
            or type(replays) is not list
            or len(replays) != 3
        ):
            raise FollowupAnalysisError("native raw repetition set changed")
        recorded = [
            _object(row, label="native producer process")
            for row in processes
            if _object(row, label="native producer process").get("execution_process_role")
            == "openfhe-recorded"
        ]
        if len(recorded) != 3:
            raise FollowupAnalysisError("native producer repetition count changed")
        producer_elapsed: list[int] = []
        replay_elapsed: list[int] = []
        package_bytes: list[int] = []
        for ordinal, (producer, replay, package) in enumerate(
            zip(recorded, replays, packages, strict=True)
        ):
            replay = _object(replay, label="native replay")
            package = _object(package, label="native retained package")
            if (
                producer.get("process_ordinal_or_null") != ordinal
                or package.get("process_ordinal") != ordinal
            ):
                raise FollowupAnalysisError("native repetition ordinal changed")
            producer_ns = _integer(producer.get("elapsed_ns"), label="producer latency")
            replay_ns = _integer(replay.get("elapsed_ns"), label="replay latency")
            retained_bytes = _integer(
                package.get("serialized_package_bytes"),
                label="retained package bytes",
            )
            producer_elapsed.append(producer_ns)
            replay_elapsed.append(replay_ns)
            package_bytes.append(retained_bytes)
            common = {
                "case_binding_sha256": case.get("case_binding_sha256"),
                "formal_seed": scope.get("formal_seed"),
                "formal_unit_ordinal": case.get("formal_unit_ordinal"),
                "measurement_label": "native-measured",
                "process_ordinal": ordinal,
                "scale": scope.get("scale"),
                "strategy_candidate_id": scope.get("strategy_candidate_id"),
            }
            native_rows.extend(
                (
                    {
                        **common,
                        "elapsed_ns": producer_ns,
                        "peak_resident_memory_bytes": _integer(
                            producer.get("peak_resident_memory_bytes"),
                            label="producer RSS",
                        ),
                        "peak_scratch_bytes": _integer(
                            producer.get("peak_scratch_bytes"),
                            label="producer scratch",
                        ),
                        "phase": "producer",
                        "retained_package_bytes": retained_bytes,
                    },
                    {
                        **common,
                        "elapsed_ns": replay_ns,
                        "peak_resident_memory_bytes": _integer(
                            replay.get("peak_resident_memory_bytes"),
                            label="replay RSS",
                        ),
                        "peak_scratch_bytes": _integer(
                            replay.get("peak_scratch_bytes"),
                            label="replay scratch",
                        ),
                        "phase": "independent-replay",
                        "retained_package_bytes": retained_bytes,
                    },
                )
            )
        native_summaries.append(
            {
                "case_binding_sha256": case.get("case_binding_sha256"),
                "formal_seed": scope.get("formal_seed"),
                "formal_unit_ordinal": case.get("formal_unit_ordinal"),
                "producer_elapsed_ns_max": max(producer_elapsed),
                "producer_elapsed_ns_median": _middle(
                    producer_elapsed,
                    label="producer latency",
                ),
                "producer_elapsed_ns_min": min(producer_elapsed),
                "replay_elapsed_ns_max": max(replay_elapsed),
                "replay_elapsed_ns_median": _middle(
                    replay_elapsed,
                    label="replay latency",
                ),
                "replay_elapsed_ns_min": min(replay_elapsed),
                "retained_package_bytes_max": max(package_bytes),
                "retained_package_bytes_median": _middle(
                    package_bytes,
                    label="retained package bytes",
                ),
                "retained_package_bytes_min": min(package_bytes),
                "scale": scope.get("scale"),
                "strategy_candidate_id": scope.get("strategy_candidate_id"),
            }
        )
    if len(native_rows) != 36 or len(native_summaries) != 6:
        raise FollowupAnalysisError("analysis native matrix changed")
    return simulator_rows, native_rows, native_summaries


def _claim_to_artifact_rows(
    aggregate: FollowupAggregateInspection,
    compatibility: FollowupCompatibilityReceipt,
    analysis_bytes: bytes,
) -> list[dict[str, object]]:
    """Render the frozen FU-E1--FU-E4 claim-to-artifact relation."""

    document = aggregate.document
    raw_records = document.get("formal_artifacts")
    terminal_name = document.get("terminal_admission_artifact_name")
    terminal_sha256 = document.get("terminal_admission_envelope_sha256")
    if (
        type(raw_records) is not list
        or len(raw_records) != 17
        or type(terminal_name) is not str
        or not terminal_name
        or type(terminal_sha256) is not str
        or len(terminal_sha256) != 64
    ):
        raise FollowupAnalysisError("claim-to-artifact source ledger changed")
    records = [
        _object(record, label="claim-to-artifact formal record")
        for record in raw_records
    ]
    expected_kinds = (
        "formal-acquisition",
        *("formal-native" for _ in range(6)),
        *("formal-synthetic" for _ in range(6)),
        *("formal-ordered-event" for _ in range(4)),
    )
    for ordinal, (record, expected_kind) in enumerate(
        zip(records, expected_kinds, strict=True)
    ):
        if (
            record.get("ordinal") != ordinal
            or record.get("unit_kind") != expected_kind
            or record.get("unit_attempt_ordinal") not in {1, 2}
            or type(record.get("artifact_name")) is not str
            or type(record.get("envelope_sha256")) is not str
            or len(record["envelope_sha256"]) != 64
        ):
            raise FollowupAnalysisError("claim-to-artifact formal ledger changed")

    rows: list[dict[str, object]] = []
    claim_kinds = (
        ("FU-E1", frozenset({"formal-synthetic"})),
        ("FU-E2", frozenset({"formal-acquisition", "formal-ordered-event"})),
        ("FU-E3", frozenset({"formal-native"})),
        (
            "FU-E4",
            frozenset(
                {
                    "formal-acquisition",
                    "formal-native",
                    "formal-ordered-event",
                    "formal-synthetic",
                }
            ),
        ),
    )
    for claim_id, kinds in claim_kinds:
        for record in records:
            if record["unit_kind"] not in kinds:
                continue
            rows.append(
                {
                    "artifact_name_or_member": record["artifact_name"],
                    "claim_id": claim_id,
                    "evidence_role": "guarded-formal-unit",
                    "sha256": record["envelope_sha256"],
                    "sha256_domain": "outer-envelope",
                    "unit_kind_or_null": record["unit_kind"],
                    "unit_ordinal_or_null": record["ordinal"],
                }
            )
        rows.extend(
            (
                {
                    "artifact_name_or_member": terminal_name,
                    "claim_id": claim_id,
                    "evidence_role": "terminal-admission",
                    "sha256": terminal_sha256,
                    "sha256_domain": "outer-envelope",
                    "unit_kind_or_null": "formal-terminal-admission",
                    "unit_ordinal_or_null": None,
                },
                {
                    "artifact_name_or_member": aggregate.artifact_name,
                    "claim_id": claim_id,
                    "evidence_role": "formal-aggregate",
                    "sha256": aggregate.aggregate_sha256,
                    "sha256_domain": "inner-payload",
                    "unit_kind_or_null": "formal-aggregate",
                    "unit_ordinal_or_null": None,
                },
            )
        )
        if claim_id == "FU-E4":
            rows.extend(
                (
                    {
                        "artifact_name_or_member": "analysis-compatibility.json",
                        "claim_id": claim_id,
                        "evidence_role": "analysis-lineage",
                        "sha256": hashlib.sha256(
                            compatibility.document_bytes
                        ).hexdigest(),
                        "sha256_domain": "analysis-member",
                        "unit_kind_or_null": "analysis",
                        "unit_ordinal_or_null": None,
                    },
                    {
                        "artifact_name_or_member": "analysis.json",
                        "claim_id": claim_id,
                        "evidence_role": "bounded-descriptive-analysis",
                        "sha256": hashlib.sha256(analysis_bytes).hexdigest(),
                        "sha256_domain": "analysis-member",
                        "unit_kind_or_null": "analysis",
                        "unit_ordinal_or_null": None,
                    },
                )
            )
    return rows


def _render(
    aggregate: FollowupAggregateInspection,
    compatibility: FollowupCompatibilityReceipt,
) -> dict[str, bytes]:
    compatibility_document = compatibility.document
    if (
        compatibility_document.get("analysis_compatibility_verified") is not True
        or compatibility_document.get("analyzer_behavior_set_exact") is not True
        or compatibility_document.get("runtime_execution_isolation_verified") is not False
    ):
        raise FollowupAnalysisError("analysis lacks one exact S1/S2/S3 receipt")
    simulator, native, summaries = _analysis_rows(aggregate)
    analysis = {
        "aggregate_sha256": aggregate.aggregate_sha256,
        "analysis_completed": True,
        "analysis_compatibility_receipt_sha256": compatibility.sha256,
        "analysis_source_S3_sha": compatibility_document["analysis_source_S3_sha"],
        "authority": False,
        "bounded_scale_only": True,
        "evidence_freeze_S2_sha": compatibility_document["evidence_freeze_S2_sha"],
        "experiment_source_S1_sha": compatibility_document["experiment_source_S1_sha"],
        "inferential_confidence_intervals": False,
        "native_raw_repetitions": native,
        "native_summaries": summaries,
        "p_values": False,
        "performance_superiority_claim": False,
        "publication_evidence_admitted": True,
        "schema_version": _ANALYSIS_SCHEMA,
        "simulator_cells": simulator,
        "study_id": FOLLOWUP_STUDY_ID,
        "universal_best_strategy_claim": False,
    }
    analysis_bytes = _canonical_json_bytes(analysis)
    claim_rows = _claim_to_artifact_rows(
        aggregate,
        compatibility,
        analysis_bytes,
    )
    simulator_fields = tuple(simulator[0])
    native_fields = tuple(native[0])
    summary_fields = tuple(summaries[0])
    summary = (
        "# Follow-up performance descriptive analysis\n\n"
        "This artifact contains 96 simulator cells, 36 raw native producer/replay "
        "repetitions, and six median/range summaries. It is bounded to the frozen "
        "S/M matrix. No p-value, inferential confidence interval, fitted scaling "
        "law, superiority claim, universal ranking, or cross-machine generalization "
        "is authorized. The claim-to-artifact table binds FU-E1--FU-E4 to the "
        "guarded formal units, terminal admission, aggregate, and isolated "
        "analysis members used for each claim.\n"
    ).encode("ascii")
    return {
        "SUMMARY.md": summary,
        "analysis-compatibility.json": compatibility.document_bytes,
        "analysis.json": analysis_bytes,
        "claim-to-artifact.csv": _csv_bytes(tuple(claim_rows[0]), claim_rows),
        "native-repetitions.csv": _csv_bytes(native_fields, native),
        "native-summary.csv": _csv_bytes(summary_fields, summaries),
        "simulator-cells.csv": _csv_bytes(simulator_fields, simulator),
    }


def _manifest(files: dict[str, bytes]) -> bytes:
    return _canonical_json_bytes(
        {
            "analysis_authority": False,
            "files": [
                {
                    "byte_count": len(files[name]),
                    "path": name,
                    "sha256": hashlib.sha256(files[name]).hexdigest(),
                }
                for name in _FILES
            ],
            "publication_evidence_admitted": True,
            "schema_version": _MANIFEST_SCHEMA,
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )


def _identity(
    manifest: bytes,
    aggregate: FollowupAggregateInspection,
    compatibility: FollowupCompatibilityReceipt,
) -> tuple[bytes, str]:
    document = compatibility.document
    return build_followup_unit_identity(
        unit_kind="analysis",
        unit_attempt_ordinal=1,
        scope={
            "aggregate_sha256": aggregate.aggregate_sha256,
            "analysis_compatibility_receipt_sha256": compatibility.sha256,
            "analysis_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "analysis_source_S3_sha": document["analysis_source_S3_sha"],
            "evidence_freeze_S2_sha": document["evidence_freeze_S2_sha"],
            "experiment_source_S1_sha": document["experiment_source_S1_sha"],
        },
    )


@dataclass(frozen=True, slots=True)
class FollowupAnalysisInspection:
    artifact_name: str
    root: Path
    analysis_sha256: str
    unit_identity_sha256: str
    envelope: FollowupEvidenceEnvelope
    document: dict[str, object]


def inspect_followup_analysis(
    artifact_directory: Path,
    *,
    aggregate: FollowupAggregateInspection,
    compatibility: FollowupCompatibilityReceipt,
) -> FollowupAnalysisInspection:
    artifact_directory = _direct_directory(
        artifact_directory,
        label="follow-up analysis artifact",
    )
    expected_files = {*_FILES, *_WRAPPER_FILES, "checksums.sha256"}
    entries = {entry.name: entry for entry in artifact_directory.iterdir()}
    if set(entries) != expected_files:
        raise FollowupAnalysisError("analysis artifact members changed")
    expected = _render(aggregate, compatibility)
    manifest = _manifest(expected)
    unit_bytes, unit_sha256 = _identity(manifest, aggregate, compatibility)
    expected.update(
        {
            "inner-payload.json": manifest,
            "unit-identity.json": unit_bytes,
        }
    )
    for name, content in expected.items():
        if _stable_read(entries[name]) != content:
            raise FollowupAnalysisError(f"analysis member changed: {name}")
    checksum_names = (*_FILES, "inner-payload.json", "unit-identity.json")
    checksummed = {name: expected[name] for name in checksum_names}
    envelope_bytes = _stable_read(entries["outer-envelope.json"])
    checksummed["outer-envelope.json"] = envelope_bytes
    if _stable_read(entries["checksums.sha256"]) != _checksums(checksummed):
        raise FollowupAnalysisError("analysis checksums changed")
    document = compatibility.document
    envelope = inspect_followup_outer_envelope(
        envelope_bytes,
        manifest,
        expected_experiment_source_s1_sha=document["experiment_source_S1_sha"],
        expected_evidence_freeze_s2_sha=document["evidence_freeze_S2_sha"],
    )
    if (
        envelope.document.get("unit_kind") != "analysis"
        or envelope.document.get("inner_role") != "analysis"
        or envelope.document.get("unit_identity_sha256") != unit_sha256
        or envelope.document.get("unit_attempt_ordinal") != 1
    ):
        raise FollowupAnalysisError("analysis envelope changed")
    value = _parse_ascii_json(expected["analysis.json"], label="follow-up analysis")
    if type(value) is not dict:
        raise FollowupAnalysisError("analysis document is not an object")
    return FollowupAnalysisInspection(
        artifact_name=followup_artifact_name(
            unit_kind="analysis",
            unit_identity_sha256=unit_sha256,
            unit_attempt_ordinal=1,
        ),
        root=artifact_directory,
        analysis_sha256=hashlib.sha256(expected["analysis.json"]).hexdigest(),
        unit_identity_sha256=unit_sha256,
        envelope=envelope,
        document=value,
    )


def produce_followup_analysis(
    aggregate: FollowupAggregateInspection,
    compatibility: FollowupCompatibilityReceipt,
    output_directory: Path,
) -> FollowupAnalysisInspection:
    _direct_directory(output_directory.parent, label="analysis output parent")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupAnalysisError("analysis output already exists")
    files = _render(aggregate, compatibility)
    manifest = _manifest(files)
    unit_bytes, unit_sha256 = _identity(manifest, aggregate, compatibility)
    document = compatibility.document
    admission = _issue_followup_inner_admission(inner_role="analysis", inner_bytes=manifest)
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=document["experiment_source_S1_sha"],
        evidence_freeze_s2_sha=document["evidence_freeze_S2_sha"],
        unit_kind="analysis",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    contents = {
        **files,
        "inner-payload.json": manifest,
        "outer-envelope.json": envelope.document_bytes,
        "unit-identity.json": unit_bytes,
    }
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}-", dir=output_directory.parent)
    )
    try:
        for name in (*_FILES, *_WRAPPER_FILES):
            _write_new(temporary / name, contents[name])
        _write_new(temporary / "checksums.sha256", _checksums(contents))
        os.replace(temporary, output_directory)
        return inspect_followup_analysis(
            output_directory,
            aggregate=aggregate,
            compatibility=compatibility,
        )
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise
