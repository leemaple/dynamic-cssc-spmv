from __future__ import annotations

import bz2
import hashlib
import json
import os
import shutil
import subprocess
import sys
from contextlib import suppress
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from functools import cache
from inspect import signature
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.day1_registry as registry_module
import dynamic_cssc.publication_day1b as day1b_module
import dynamic_cssc.publication_day1b_accounting as day1b_accounting
import dynamic_cssc.publication_day1b_expected_counts as expected_counts_module
import dynamic_cssc.publication_day1b_f1m_aggregation as f1m_aggregation
import dynamic_cssc.publication_day1b_worker_protocol as worker_protocol
import dynamic_cssc.publication_statistics as statistics_module
from dynamic_cssc.day1_registry import Day1CandidateCatalog, RegistrationEvidence
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactInstallError,
    verify_existing_directory,
)
from dynamic_cssc.publication_day1b import (
    DAY1B_RESOURCE_AMENDMENT_SCHEMA,
    DAY1B_UNIT_FRAGMENT_SCHEMA,
    DAY1B_UNIT_SCHEMA,
    PublicationDay1BHold,
    PublicationDay1BResourcePolicy,
    PublicationDay1BUnitBundle,
    _Day1BPreparatorySourceAttestation,
    _Day1BSerializedObjectSizeAuthority,
    _Day1BTraceInput,
    _Day1BWorkerContractSeed,
    _Day1BWorkerLaunch,
    _produce_publication_day1b_unit_for_test,
    _PublicationScheduleAdapter,
    produce_publication_day1b_unit,
)
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    Day1BF1MChargedSizeClass,
    Day1BF1MControllerSummary,
)
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES,
    Day1BCombinedEvaluationKeyFrame,
    day1b_combined_evaluation_key_size_class_sha256,
)
from dynamic_cssc.publication_day1b_metadata_framing import (
    Day1BColumnIndexSynchronizationEntry,
    Day1BQueryVersionPlanMetadata,
    Day1BUpdateVersionPlanMetadata,
    day1b_metadata_size_class_sha256,
)
from dynamic_cssc.publication_day1b_worker_protocol import (
    DAY1B_WORKER_FRAME_SCHEMA,
    Day1BControllerExpectedF1MObject,
    Day1BF1MSizeClass,
    Day1BF1MWindowBatch,
    Day1BF1MWindowCardinality,
    Day1BWorkerPhaseAudit,
    Day1BWorkerPhaseReceipt,
    Day1BWorkerProtocolContract,
    _require_test_invocation_issuer,
    _test_only_issue_day1b_worker_invocation,
    _test_only_prepare_day1b_expected_f1m_registry,
    canonical_day1b_expected_f1m_size_class_set_sha256,
    canonical_day1b_expected_f1m_size_class_subroot_sha256,
    canonical_day1b_f1m_cardinality_derivation_root_sha256,
    canonical_day1b_worker_window_audit_bytes,
    consume_day1b_worker_frames,
)
from dynamic_cssc.publication_schedule import (
    ACCEPTED_EVENT_SCHEDULE_SCHEMA,
    AcceptedGroupPhaseRange,
    ExactPublicationWindow,
    ScheduledNetUpdate,
)
from dynamic_cssc.publication_statistics import (
    ABLATION_CANDIDATE_ID,
    CELL_BINDING_SCHEMA,
    FIXED_CANDIDATE_IDS,
    FRESHNESS_VALUES,
    HELDOUT_RECORD_SCHEMA,
    PRIMITIVE_NAMES,
    QUERY_VECTOR_SCHEMA,
    REFERENCE_CANDIDATE_IDS,
    RHO_VALUES,
    TRACE_UNIT_SCHEMA,
)
from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    ACQUISITION_TRACE_BINDING_SCHEMA,
    PUBLICATION_TRACE_MANIFEST_SCHEMA,
    LicenseTermsObject,
    LocalSourceObject,
    _LocalTraceRequest,
    _prepare_publication_trace,
    _test_only_repository_snapshot,
)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _pending_resource_policy_document() -> dict[str, object]:
    return {
        "amendment_identity": {
            "resource_policy_amendment_git_sha": None,
            "resource_policy_amendment_id": None,
            "resource_policy_amendment_sha256": None,
        },
        "authority": {
            "artifact_publication_authorized": False,
            "claims_authorized": False,
            "common_ordinary_query_preparation_verified": False,
            "controller_scratch_isolation_verified": False,
            "day1_registration_anchor_verified": False,
            "dispatch_authorized": False,
            "formal_authority_granted": False,
            "full_openfhe_runner_verified": False,
            "outcome_blind_structure_pilot_reviewed": False,
            "resource_policy_frozen": False,
            "trace_post_run_anchor_verified": False,
            "workflow_dispatch_authorized": False,
        },
        "limits": {
            "cells_per_shard": None,
            "controller_registered_scratch_bytes_checkpoint_maximum": None,
            "infrastructure_preemption_whole_shard_rerun_limit": None,
            "job_cost_budget_usd_maximum": None,
            "job_wall_clock_seconds_maximum": None,
            "max_concurrency": None,
            "output_bytes_per_unit": None,
            "resident_memory_bytes_per_candidate_cell": None,
            "scratch_bytes_per_candidate_cell": None,
            "serialized_object_bytes_maximum": None,
            "serialized_object_receipt_count_maximum": None,
            "serialized_object_receipt_spool_bytes_maximum": None,
            "serialized_payload_bytes_per_cell_maximum": None,
            "shard_cost_budget_usd_maximum": None,
            "shard_wall_clock_seconds_maximum": None,
            "wall_clock_seconds_per_candidate_cell": None,
            "worker_frame_count_maximum": None,
        },
        "measurement_methods": {
            "controller_scratch_observation_method": None,
            "controlled_scratch_high_water_measurement_method": None,
            "controlled_scratch_root_policy": None,
            "infrastructure_preemption_classification_method": None,
            "output_byte_observation_method": None,
            "resident_memory_observation_method": None,
            "scratch_observation_method": None,
            "wall_clock_observation_method": None,
        },
        "pilot_evidence": {
            "review_receipt_sha256": None,
            "structure_pilot_checksums_sha256": None,
            "structure_pilot_report_sha256": None,
            "structure_pilot_source_git_sha": None,
        },
        "protocol_invariants": {
            "candidate_retry_count": 0,
            "selective_candidate_retry_allowed": False,
        },
        "schema_version": "dynamic-cssc-publication-day1b-resource-policy-pending-v1",
        "state": "PENDING-FREEZE",
        "worker_runtime_identity": {
            "common_ordinary_private_plan_schema_version": None,
            "common_ordinary_query_preparation_schema_version": None,
            "compiler_flags": None,
            "compiler_identity": None,
            "controller_scratch_capability_schema_version": None,
            "cpu_affinity_policy": None,
            "full_openfhe_runner_path": None,
            "full_openfhe_runner_sha256": None,
            "full_openfhe_runtime_receipt_schema_version": None,
            "host_identity": None,
            "openfhe_build_identity_sha256": None,
            "openfhe_version": None,
            "operating_system_identity": None,
            "worker_adapter_schema_version": None,
            "worker_build_receipt_sha256": None,
        },
    }


def _resource_amendment_document() -> dict[str, object]:
    document: dict[str, object] = {
        "amendment_identity": {
            "resource_policy_amendment_id": "day1b-resource-amendment-001",
        },
        "limits": {
            "cells_per_shard": 18,
            "controller_registered_scratch_bytes_checkpoint_maximum": 100_000_000,
            "infrastructure_preemption_whole_shard_rerun_limit": 1,
            "job_cost_budget_usd_maximum": "25",
            "job_wall_clock_seconds_maximum": 86_400,
            "max_concurrency": 1,
            "output_bytes_per_unit": 8_000_000_000,
            "resident_memory_bytes_per_candidate_cell": 2_000_000_000,
            "scratch_bytes_per_candidate_cell": 4_000_000_000,
            "serialized_object_bytes_maximum": 1_000_000,
            "serialized_object_receipt_count_maximum": 100_000,
            "serialized_object_receipt_spool_bytes_maximum": 100_000_000,
            "serialized_payload_bytes_per_cell_maximum": 4_000_000_000,
            "shard_cost_budget_usd_maximum": "5.25",
            "shard_wall_clock_seconds_maximum": 36_000,
            "wall_clock_seconds_per_candidate_cell": 600,
            "worker_frame_count_maximum": 200_000,
        },
        "measurement_methods": {
            "controlled_scratch_high_water_measurement_method": (
                "launcher-controlled-root-high-water-v1"
            ),
            "controlled_scratch_root_policy": "exclusive-inode-bound-root-v1",
            "controller_scratch_observation_method": ("anonymous-registry-spool-st-size-sum-v1"),
            "infrastructure_preemption_classification_method": (
                "repository-whole-shard-preemption-receipt-v1"
            ),
            "output_byte_observation_method": "installed-member-byte-sum-v1",
            "resident_memory_observation_method": "launcher-process-rss-peak-v1",
            "scratch_observation_method": "launcher-controlled-root-high-water-v1",
            "wall_clock_observation_method": "launcher-monotonic-clock-v1",
        },
        "pilot_evidence": {
            "review_receipt_sha256": "1" * 64,
            "structure_pilot_checksums_sha256": "2" * 64,
            "structure_pilot_report_sha256": "3" * 64,
            "structure_pilot_source_git_sha": "4" * 40,
        },
        "protocol_invariants": {
            "candidate_retry_count": 0,
            "selective_candidate_retry_allowed": False,
        },
        "schema_source": {
            "behavior_inventory_sha256": "5" * 64,
            "git_sha": "6" * 40,
        },
        "schema_version": DAY1B_RESOURCE_AMENDMENT_SCHEMA,
        "state": "RESOURCE-VALUES-FROZEN",
    }
    payload_sha256 = _sha(document)
    document["amendment_identity"]["resource_policy_amendment_payload_sha256"] = payload_sha256
    return document


def _trace_v6_history_row(*, timestamp: datetime, user_id: int) -> str:
    fields = [""] * 78
    fields[0] = "simplewiki"
    fields[2] = "revision"
    fields[3] = "create"
    fields[4] = timestamp.strftime("%Y-%m-%d %H:%M:%S.0")
    fields[6] = str(user_id)
    fields[19] = "false"
    fields[20] = "false"
    fields[21] = "true"
    fields[28] = "2"
    fields[31] = "0"
    return "\t".join(fields) + "\n"


def _write_trace_v7_fixture(tmp_path: Path) -> Path:
    source_path = tmp_path / "history.tsv.bz2"
    start = datetime(2020, 1, 1, tzinfo=UTC)
    rows = "".join(
        _trace_v6_history_row(
            timestamp=start + timedelta(seconds=index),
            user_id=1 + index % 10,
        )
        for index in range(100)
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)

    terms_path = tmp_path / "mediawiki-history-readme.html"
    terms_path.write_text("<html>CC0 fixture terms</html>\n", encoding="utf-8")
    terms_bytes = terms_path.read_bytes()
    source_bytes = source_path.read_bytes()
    source_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    source = LocalSourceObject(
        role="history",
        path=source_path,
        source_url=source_url,
        final_url=source_url,
        http_status=200,
        media_type="application/octet-stream",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(source_bytes),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(source_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=(
            LicenseTermsObject(
                source_url=terms_url,
                final_url=terms_url,
                http_status=200,
                media_type="text/html",
                retrieval_utc="2026-08-23T00:00:00Z",
                http_etag=None,
                http_last_modified=None,
                section_anchor=None,
                path=terms_path,
                byte_count=len(terms_bytes),
                sha256=hashlib.sha256(terms_bytes).hexdigest(),
            ),
        ),
        attribution_text="Wikimedia Analytics MediaWiki History (CC0)",
    )
    bundle = _prepare_publication_trace(
        _LocalTraceRequest(
            dataset_id="simplewiki-2026-07",
            semantics="T1",
            source_partition=0,
            sources=(source,),
        ),
        config=replace(
            _PRODUCTION_CONFIG,
            rows=1,
            cols=10,
            target_accepted_events=70,
            minimum_logical_changes=70,
            minimum_complete_window_lower_bound=1,
            maximum_row_nonzeros=10,
        ),
        repository_snapshot=_test_only_repository_snapshot(),
    )
    trace_dir = tmp_path / "trace-v7"
    trace_dir.mkdir()
    artifacts = {
        "publication-trace-manifest.json": bundle.manifest_bytes,
        "publication-trace.jsonl": bundle.trace_jsonl_bytes,
        "publication-query-vector.json": bundle.query_vector_bytes,
    }
    for name, content in artifacts.items():
        (trace_dir / name).write_bytes(content)
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in artifacts.items()
    )
    (trace_dir / "checksums.sha256").write_text(checksums, encoding="ascii")
    return trace_dir


def _catalog() -> Day1CandidateCatalog:
    return Day1CandidateCatalog(
        candidates=registry_module._canonical_registered_candidates(),
        registration=RegistrationEvidence(
            schema_version="dynamic-cssc-day1-registration-evidence-v1",
            source_git_sha="1" * 40,
            run_id=123,
            correctness_artifact_sha256="2" * 64,
            accounting_evidence_sha256="3" * 64,
            policy_contract_sha256=(
                "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
            ),
        ),
    )


def _program(
    rho: Fraction,
    *,
    total: int = 250,
    t2_cardinality: bool = False,
) -> _PublicationScheduleAdapter:
    ranges = (
        AcceptedGroupPhaseRange("warmup", 0, total // 10),
        AcceptedGroupPhaseRange("tuning", total // 10, total * 4 // 10),
        AcceptedGroupPhaseRange("heldout", total * 4 // 10, total),
    )

    def group_set_count(ordinal: int) -> int:
        if not t2_cardinality:
            return 1
        if ordinal < total // 10:
            return 0
        if ordinal < total * 4 // 10:
            return 2
        return 1

    def schedule_bytes() -> object:
        yield _canonical_bytes(
            {
                "schema_version": ACCEPTED_EVENT_SCHEDULE_SCHEMA,
                "record_kind": "accepted-event-schedule-header",
                "accepted_group_count": total,
                "rho": {"numerator": rho.numerator, "denominator": rho.denominator},
            }
        )
        for ordinal in range(total):
            before = ordinal * rho.numerator // rho.denominator
            after = (ordinal + 1) * rho.numerator // rho.denominator
            yield _canonical_bytes(
                {
                    "schema_version": ACCEPTED_EVENT_SCHEDULE_SCHEMA,
                    "record_kind": "accepted-event-group",
                    "accepted_event_ordinal": ordinal,
                    "events": [
                        *({"kind": "set"} for _ in range(group_set_count(ordinal))),
                        {"kind": "tick"},
                        {
                            "kind": "query-run",
                            "first_query_ordinal": before,
                            "count": after - before,
                        },
                    ],
                }
            )

    digest = hashlib.sha256()
    for chunk in schedule_bytes():
        digest.update(chunk)

    def windows(_freshness: Fraction) -> object:
        for index, phase in enumerate(ranges):
            query_count = (phase.end * rho.numerator // rho.denominator) - (
                phase.start * rho.numerator // rho.denominator
            )
            set_start = sum(group_set_count(ordinal) for ordinal in range(phase.start))
            set_count = sum(group_set_count(ordinal) for ordinal in range(phase.start, phase.end))
            yield ExactPublicationWindow(
                index=index,
                phase=phase.name,
                accepted_group_start=phase.start,
                accepted_group_end=phase.end,
                start_time=Fraction(phase.start, 128),
                end_time=Fraction(phase.end - 1, 128),
                set_count=set_count,
                updates=tuple(
                    ScheduledNetUpdate(
                        row=0,
                        col=set_start + ordinal,
                        before=0,
                        after=1,
                    )
                    for ordinal in range(set_count)
                ),
                query_count=query_count,
                reason=f"phase-boundary:{phase.name}",
            )

    return _PublicationScheduleAdapter(
        schema_version=ACCEPTED_EVENT_SCHEDULE_SCHEMA,
        rho=rho,
        phase_ranges=ranges,
        accepted_group_count=total,
        total_set_count=sum(group_set_count(ordinal) for ordinal in range(total)),
        total_query_count=total * rho.numerator // rho.denominator,
        canonical_schedule_sha256=digest.hexdigest(),
        iter_canonical_bytes=schedule_bytes,
        stream_windows=windows,
    )


def _trace() -> _Day1BTraceInput:
    query_vector = {"schema_version": QUERY_VECTOR_SCHEMA, "values": [1, 0, -1]}
    query_vector_bytes = _canonical_bytes(query_vector)
    trace_behavior_sources = (("src/dynamic_cssc/publication_traces.py", "b" * 64),)
    return _Day1BTraceInput(
        dataset_id="simplewiki-2026-07",
        dataset_release="mediawiki-history-2026-07-simplewiki-all-time",
        semantics="T1",
        source_partition=0,
        trace_source_git_sha="4" * 40,
        trace_behavior_source_blob_sha256=trace_behavior_sources,
        trace_behavior_source_inventory_sha256=hashlib.sha256(
            _canonical_bytes(dict(trace_behavior_sources))
        ).hexdigest(),
        repository_provenance_sha256="5" * 64,
        trace_manifest_sha256="6" * 64,
        mapping_sha256="7" * 64,
        accepted_events_sha256="8" * 64,
        replay_receipt_sha256="9" * 64,
        source_bundle_sha256="a" * 64,
        acquisition_transaction_sha256=None,
        source_set_sha256=None,
        acquisition_behavior_set_sha256=None,
        acquisition_behavior_inventory_sha256=None,
        acquisition_authority_state=None,
        acquisition_network_authority_verified=False,
        accepted_group_count=250,
        query_vector=(1, 0, -1),
        query_vector_canonical_bytes=query_vector_bytes,
        query_vector_sha256=hashlib.sha256(query_vector_bytes).hexdigest(),
        compile_schedule=_program,
    )


def _source() -> _Day1BPreparatorySourceAttestation:
    inventory = {
        "behavior_set_schema_version": "dynamic-cssc-day1b-preparatory-behavior-set-v19",
        "behavior_set_sha256": "c" * 64,
        "entries": [],
        "role": "day1b",
        "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
        "source_git_sha": "1" * 40,
    }
    return _Day1BPreparatorySourceAttestation(
        git_sha="1" * 40,
        behavior_inventory=inventory,
        source_attestation="test-only-typed-day1b-source",
    )


def _resource_policy() -> PublicationDay1BResourcePolicy:
    return PublicationDay1BResourcePolicy(
        wall_clock_seconds_per_candidate_cell=600,
        resident_memory_bytes_per_candidate_cell=2_000_000_000,
        scratch_bytes_per_candidate_cell=4_000_000_000,
        serialized_object_bytes_maximum=1_000_000,
        serialized_object_receipt_count_maximum=100_000,
        serialized_object_receipt_spool_bytes_maximum=100_000_000,
        serialized_payload_bytes_per_cell_maximum=4_000_000_000,
        worker_frame_count_maximum=200_000,
        controller_registered_scratch_bytes_checkpoint_maximum=100_000_000,
        output_bytes_per_unit=8_000_000_000,
        cells_per_shard=18,
        max_concurrency=1,
        candidate_retry_count=0,
        infrastructure_preemption_whole_shard_rerun_limit=1,
        authority="test-only-outcome-blind-fixed-policy",
    )


def _size_authority() -> _Day1BSerializedObjectSizeAuthority:
    return _Day1BSerializedObjectSizeAuthority(
        source_git_sha="1" * 40,
        day2_experiment_source_git_sha="2" * 40,
        day2_outer_archive_sha256="3" * 64,
        serialized_object_size_profile_sha256="4" * 64,
        ciphertext_bytes=34567,
        f1m_random_zero_sum_ciphertext_bytes=34568,
        f1m_encrypted_zero_dummy_ciphertext_bytes=34569,
        serialized_rotation_key_inventory_bytes=45678,
        serialized_eval_mult_key_bytes=56789,
    )


def _worker_frame(
    sequence: int,
    kind: str,
    *,
    payload: bytes = b"",
    **fields: object,
) -> bytes:
    header = _canonical_bytes(
        {
            "schema_version": DAY1B_WORKER_FRAME_SCHEMA,
            "frame_kind": kind,
            "sequence": sequence,
            "payload_byte_count": len(payload),
            **fields,
        }
    )
    return len(header).to_bytes(4, "big") + header + payload


def _worker_audits(windows: object) -> tuple[Day1BWorkerPhaseAudit, ...]:
    stats = {
        phase: {
            "hasher": hashlib.sha256(),
            "windows": 0,
            "sets": 0,
            "queries": 0,
            "start": None,
            "end": None,
        }
        for phase in ("warmup", "tuning", "heldout")
    }
    for window in windows:
        values = stats[window.phase]
        values["hasher"].update(
            canonical_day1b_worker_window_audit_bytes(
                index=window.index,
                phase=window.phase,
                accepted_group_start=window.accepted_group_start,
                accepted_group_end=window.accepted_group_end,
                start_time=window.start_time,
                end_time=window.end_time,
                set_count=window.set_count,
                updates=tuple(
                    (update.row, update.col, update.before, update.after)
                    for update in window.updates
                ),
                query_count=window.query_count,
                reason=window.reason,
            )
        )
        values["windows"] += 1
        values["sets"] += window.set_count
        values["queries"] += window.query_count
        values["start"] = (
            window.accepted_group_start if values["start"] is None else values["start"]
        )
        values["end"] = window.accepted_group_end
    return tuple(
        Day1BWorkerPhaseAudit(
            phase=phase,
            accepted_group_start=values["start"],
            accepted_group_end=values["end"],
            realized_window_count=values["windows"],
            realized_set_count=values["sets"],
            realized_query_count=values["queries"],
            consumed_window_audit_stream_sha256=values["hasher"].hexdigest(),
        )
        for phase, values in stats.items()
    )


def _fixed_width_metadata_payload(category: str) -> bytes | None:
    if category == "update-column-index-synchronization":
        return Day1BColumnIndexSynchronizationEntry(
            version_ordinal=1,
            window_index=2,
            component_ordinal=3,
            storage_object_ordinal=4,
            lane_ordinal=5,
            logical_row=6,
            global_column_index=7,
            entry_kind="patch",
        ).to_bytes()
    if category == "update-version-plan-metadata":
        return Day1BUpdateVersionPlanMetadata(
            window_index=2,
            version_ordinal=1,
            accepted_group_start=3,
            accepted_group_end=4,
            logical_state_sha256="a" * 64,
            output_plan_sha256="b" * 64,
            execution_binding_sha256="c" * 64,
        ).to_bytes()
    if category == "query-version-plan-metadata":
        return Day1BQueryVersionPlanMetadata(
            window_index=2,
            global_query_ordinal=3,
            version_ordinal=1,
            query_vector_sha256="d" * 64,
            output_plan_sha256="b" * 64,
            execution_binding_sha256="c" * 64,
        ).to_bytes()
    return None


@cache
def _combined_evaluation_key_payload(
    rotation_key_inventory_bytes: int,
    eval_mult_key_bytes: int,
) -> bytes:
    return Day1BCombinedEvaluationKeyFrame(
        rotation_key_inventory=b"r" * rotation_key_inventory_bytes,
        eval_mult_keys=b"m" * eval_mult_key_bytes,
    ).to_bytes()


def _worker_transcript(
    contract: Day1BWorkerProtocolContract,
    audits: tuple[Day1BWorkerPhaseAudit, ...],
    *,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] = (),
    omit_first_one_time: bool = False,
    failed_phase: str | None = None,
) -> bytes:
    frames: list[bytes] = []
    sequence = 0

    def emit(kind: str, *, payload: bytes = b"", **fields: object) -> None:
        nonlocal sequence
        frames.append(_worker_frame(sequence, kind, payload=payload, **fields))
        sequence += 1

    emit("cell-start", input_binding=contract.input_binding_document())
    candidate = contract.candidate
    emit(
        "candidate-start",
        candidate_id=candidate.candidate_id,
        candidate_role=candidate.candidate_role,
    )
    for audit, phase in zip(
        audits,
        ("warmup", "tuning-prefix", "held-out"),
        strict=True,
    ):
        retained = phase in candidate.retained_phases
        phase_failed = phase == failed_phase
        expected_phase = (
            contract.controller_expected_counts.phase_counts(phase)
            if retained
            else None
        )
        if retained and not phase_failed:
            assert expected_phase is not None
            category_counts: list[int] = []
            for category_index, (category, transaction) in enumerate(
                contract.serialized_categories
            ):
                f1m_routes = tuple(
                    route
                    for route in expected_f1m_objects
                    if route.phase == phase and route.category == category
                )
                if category in contract.f1m_size_class_categories:
                    category_counts.append(len(f1m_routes))
                    for route in f1m_routes:
                        identity = (
                            f"{contract.input_binding_sha256}:{candidate.candidate_id}:"
                            f"{phase}:{category}:{route.object_ordinal}"
                        )
                        emit(
                            "serialized-object",
                            candidate_id=candidate.candidate_id,
                            phase=phase,
                            category=category,
                            object_ordinal=route.object_ordinal,
                            multiplicity=route.multiplicity,
                            f1m_size_class=route.f1m_size_class.to_document(),
                            payload=f"test-only:{identity}".encode("ascii"),
                        )
                    continue
                multiplicity = (
                    expected_phase.worker_streamed_protocol_object_counts[
                        category_index
                    ]
                )
                report = multiplicity > 0 and not (
                    transaction == "one-time" and omit_first_one_time
                )
                category_counts.append(int(report))
                if not report:
                    continue
                identity = (
                    f"{contract.input_binding_sha256}:{candidate.candidate_id}:{phase}:{category}"
                )
                payload = _fixed_width_metadata_payload(category)
                if category == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY:
                    assert contract.serialized_rotation_key_inventory_bytes is not None
                    assert contract.serialized_eval_mult_key_bytes is not None
                    payload = _combined_evaluation_key_payload(
                        contract.serialized_rotation_key_inventory_bytes,
                        contract.serialized_eval_mult_key_bytes,
                    )
                if payload is None:
                    payload = f"test-only:{identity}".encode("ascii")
                emit(
                    "serialized-object",
                    candidate_id=candidate.candidate_id,
                    phase=phase,
                    category=category,
                    object_ordinal=0,
                    multiplicity=multiplicity,
                    f1m_size_class=None,
                    payload=payload,
                )
        emit(
            "phase-result",
            candidate_id=candidate.candidate_id,
            phase=phase,
            outcome=("failed" if phase_failed else "complete"),
            failure_code=("candidate-execution-failed" if phase_failed else None),
            retained_measurement=retained,
            update_primitive_counts=(
                list(expected_phase.update_primitive_counts)
                if expected_phase is not None and not phase_failed
                else None
            ),
            query_primitive_counts=(
                list(expected_phase.query_primitive_counts)
                if expected_phase is not None and not phase_failed
                else None
            ),
            serialized_category_object_counts=(
                category_counts if retained and not phase_failed else None
            ),
            phase_audit=audit.to_document(),
        )
    emit(
        "candidate-result",
        candidate_id=candidate.candidate_id,
        elapsed_ns=1_000_000,
        peak_resident_memory_bytes=250_000_000,
        peak_scratch_bytes=500_000_000,
        candidate_retry_count=0,
        state_reset_count=0,
    )
    emit("cell-end", candidate_count=1)
    return b"".join(frames)


class _StreamingExecutor:
    def __init__(self, controlled_scratch_root: Path) -> None:
        self.controlled_scratch_root = controlled_scratch_root
        self.controlled_scratch_root.mkdir()
        self.calls: list[tuple[Fraction, Fraction, str, int]] = []
        self.f1m_summaries: list[Day1BF1MControllerSummary] = []
        self.terminal_failure_codes: dict[int, str] = {}
        self.worker_failed_phases: dict[int, str] = {}
        self.observation_overrides: dict[int, dict[str, int]] = {}
        self.emit_f1m_routes = False
        self.omit_first_one_time = False
        self.post_mint_failure: BaseException | None = None
        self.last_minted_invocation: object | None = None

    def _registry_inputs(
        self,
        seed: _Day1BWorkerContractSeed,
        audits: tuple[Day1BWorkerPhaseAudit, ...],
    ) -> tuple[
        tuple[Day1BF1MWindowCardinality, ...],
        tuple[Day1BF1MWindowBatch, ...],
        tuple[Day1BControllerExpectedF1MObject, ...],
    ]:
        audit_by_phase = dict(zip(("warmup", "tuning-prefix", "held-out"), audits, strict=True))
        first_query_by_phase: dict[str, int] = {}
        next_query = 0
        for phase in ("warmup", "tuning-prefix", "held-out"):
            first_query_by_phase[phase] = next_query
            next_query += audit_by_phase[phase].realized_query_count

        cardinalities: list[Day1BF1MWindowCardinality] = []
        window_batches: list[Day1BF1MWindowBatch] = []
        expected_f1m_objects: list[Day1BControllerExpectedF1MObject] = []
        for phase in seed.candidate.retained_phases:
            audit = audit_by_phase[phase]
            phase_identity = f"{seed.invocation_id}:{phase}"
            version_id = f"version-{seed.invocation_id[:16]}-{phase}"
            output_plan_digest = hashlib.sha256(
                f"output-plan:{phase_identity}".encode("ascii")
            ).hexdigest()
            private_plan_digest = hashlib.sha256(
                f"test-only-private-plan:{phase_identity}".encode("ascii")
            ).hexdigest()
            execution_binding_digest = hashlib.sha256(
                f"test-only-execution:{phase_identity}".encode("ascii")
            ).hexdigest()
            window_index = {
                "warmup": 0,
                "tuning-prefix": 1,
                "held-out": 2,
            }[phase]
            first_query = first_query_by_phase[phase]
            phase_routes: list[Day1BControllerExpectedF1MObject] = []
            if audit.realized_query_count:
                global_query_ordinal = first_query
                if self.emit_f1m_routes:
                    size_class = Day1BF1MSizeClass(
                        version_id=version_id,
                        output_plan_digest=output_plan_digest,
                        component_id="component-0",
                        output_block_id="block-0",
                        f1m_kind="random-zero-sum",
                        private_plan_digest=private_plan_digest,
                        execution_binding_digest=execution_binding_digest,
                    )
                    route = Day1BControllerExpectedF1MObject(
                        phase=phase,
                        window_index=window_index,
                        first_global_query_ordinal=global_query_ordinal,
                        category="query-f1m-random-mask-ciphertexts",
                        object_ordinal=0,
                        f1m_size_class=size_class,
                        multiplicity=audit.realized_query_count,
                    )
                    phase_routes.append(route)
                    expected_f1m_objects.append(route)
                    query_routes = (route,)
                else:
                    query_routes = ()
                window_batches.append(
                    Day1BF1MWindowBatch(
                        phase=phase,
                        window_index=window_index,
                        first_global_query_ordinal=global_query_ordinal,
                        query_count=audit.realized_query_count,
                        version_id=version_id,
                        output_plan_digest=output_plan_digest,
                        private_plan_digest=private_plan_digest,
                        execution_binding_digest=execution_binding_digest,
                        size_class_subroot_sha256=(
                            canonical_day1b_expected_f1m_size_class_subroot_sha256(query_routes)
                        ),
                    )
                )
            cardinalities.append(
                Day1BF1MWindowCardinality(
                    phase=phase,
                    window_index=window_index,
                    accepted_group_start=audit.accepted_group_start,
                    accepted_group_end=audit.accepted_group_end,
                    first_global_query_ordinal=first_query,
                    query_count=audit.realized_query_count,
                    version_id=version_id,
                    output_plan_digest=output_plan_digest,
                    private_plan_digest=private_plan_digest,
                    execution_binding_digest=execution_binding_digest,
                    f1m_policy=seed.candidate.f1m_policy,
                    returned_share_count=int(self.emit_f1m_routes),
                    overlap_masked_share_count=int(self.emit_f1m_routes),
                    expected_random_route_count=sum(route.multiplicity for route in phase_routes),
                    expected_dummy_route_count=0,
                    expected_size_class_subroot_sha256=(
                        canonical_day1b_expected_f1m_size_class_subroot_sha256(tuple(phase_routes))
                    ),
                )
            )
        return (
            tuple(cardinalities),
            tuple(window_batches),
            tuple(expected_f1m_objects),
        )

    def execute_candidate_cell(
        self,
        *,
        windows: object,
        contract_seed: _Day1BWorkerContractSeed,
    ) -> _Day1BWorkerLaunch:
        assert type(contract_seed) is _Day1BWorkerContractSeed
        audits = _worker_audits(windows)
        cardinalities, window_batches, expected_f1m_objects = self._registry_inputs(
            contract_seed, audits
        )
        expected_binding_sha256 = canonical_day1b_expected_f1m_size_class_set_sha256(
            expected_f1m_objects
        )
        cardinality_root_sha256 = canonical_day1b_f1m_cardinality_derivation_root_sha256(
            window_cardinalities=cardinalities,
            window_batches=window_batches,
            expected_size_classes=expected_f1m_objects,
        )
        f1m_categories = set(
            worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
        )
        expected_serialized_count = sum(
            int(count > 0)
            for phase in contract_seed.controller_expected_counts.phases
            for (category, _transaction), count in zip(
                contract_seed.controller_expected_counts.serialized_categories,
                phase.worker_streamed_protocol_object_counts,
                strict=True,
            )
            if category not in f1m_categories
        )
        contract = contract_seed.bind(
            expected_f1m_size_class_set_sha256=expected_binding_sha256,
            expected_f1m_size_class_count=len(expected_f1m_objects),
            expected_serialized_equivalence_class_count=(
                expected_serialized_count + len(expected_f1m_objects)
            ),
            expected_f1m_cardinality_derivation_root_sha256=(cardinality_root_sha256),
        )
        registry = _test_only_prepare_day1b_expected_f1m_registry(
            contract=contract,
            controller_phase_audits=audits,
            window_cardinalities=iter(cardinalities),
            window_batches=iter(window_batches),
            expected_f1m_objects=iter(expected_f1m_objects),
            controlled_scratch_root=self.controlled_scratch_root,
        )
        call_index = len(self.calls)
        terminal_failure_code = self.terminal_failure_codes.get(call_index)
        observations = {
            "elapsed_ns": 1_000_000,
            "peak_resident_memory_bytes": 250_000_000,
            "peak_scratch_bytes": 500_000_000,
            **self.observation_overrides.get(call_index, {}),
        }
        invocation = _test_only_issue_day1b_worker_invocation(
            contract=contract,
            controller_phase_audits=audits,
            expected_f1m_registry_capability=registry,
            elapsed_ns=observations["elapsed_ns"],
            peak_resident_memory_bytes=observations["peak_resident_memory_bytes"],
            peak_scratch_bytes=observations["peak_scratch_bytes"],
            terminal_failure_code=terminal_failure_code,
        )
        try:
            self.last_minted_invocation = invocation
            launch = _Day1BWorkerLaunch(
                contract=contract,
                frame_chunks=(
                    ()
                    if terminal_failure_code is not None
                    else (
                        _worker_transcript(
                            contract,
                            audits,
                            expected_f1m_objects=expected_f1m_objects,
                            omit_first_one_time=self.omit_first_one_time,
                            failed_phase=self.worker_failed_phases.get(call_index),
                        ),
                    )
                ),
                invocation_capability=invocation,
            )
            if self.post_mint_failure is not None:
                raise self.post_mint_failure
            self.calls.append(
                (
                    Fraction(contract.freshness),
                    Fraction(contract.rho),
                    contract.candidate.candidate_id,
                    sum(audit.realized_window_count for audit in audits),
                )
            )
            self.f1m_summaries.append(contract_seed.f1m_controller_summary)
            return launch
        except BaseException:
            with suppress(BaseException):
                worker_protocol.abandon_day1b_worker_invocation(invocation)
            raise


def test_repository_loader_consumes_one_descriptor_bound_trace_v7_snapshot(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_v7_fixture(tmp_path)

    trace = day1b_module._load_repository_trace_input_for_test(trace_dir)
    manifest = json.loads((trace_dir / "publication-trace-manifest.json").read_bytes())
    acquisition_binding = manifest["acquisition_binding"]
    authority = acquisition_binding["authority"]
    behavior_inventory = acquisition_binding["repository_provenance"]["behavior_inventory"]

    assert manifest["schema_version"] == PUBLICATION_TRACE_MANIFEST_SCHEMA
    assert "acquisition_verification" not in manifest
    assert trace.source_bundle_sha256 == _sha(acquisition_binding)
    assert (
        trace.acquisition_transaction_sha256
        == (acquisition_binding["acquisition_transaction_sha256"])
    )
    assert trace.source_set_sha256 == acquisition_binding["source_set_sha256"]
    assert trace.acquisition_behavior_set_sha256 == (behavior_inventory["behavior_set_sha256"])
    assert trace.acquisition_behavior_inventory_sha256 == _sha(behavior_inventory)
    assert trace.trace_behavior_source_blob_sha256 == tuple(
        sorted(manifest["repository_provenance"]["behavior_source_blob_sha256"].items())
    )
    assert trace.trace_behavior_source_inventory_sha256 == _sha(
        manifest["repository_provenance"]["behavior_source_blob_sha256"]
    )
    program = trace.compile_schedule(Fraction("0.1"))
    assert program.accepted_group_count == 70
    assert program.rho == Fraction("0.1")
    assert tuple(program.stream_windows(Fraction(1)))
    assert authority["state"] == "HOLD-test-only-local-source-fixture"
    assert trace.acquisition_authority_state == authority["state"]
    assert authority["formal_authority_granted"] is False
    assert authority["acquisition_network_authority_verified"] is False
    assert trace.acquisition_network_authority_verified is False
    assert trace.trace_source_authority_verified is False
    day1b_module._validate_trace(trace)

    with pytest.raises(ValueError, match="projection must be complete"):
        day1b_module._validate_trace(replace(trace, acquisition_behavior_set_sha256=None))
    with pytest.raises(ValueError, match="exact frozen HOLD"):
        day1b_module._validate_trace(replace(trace, acquisition_authority_state="authorized"))
    with pytest.raises(ValueError, match="network authority must remain exact false"):
        day1b_module._validate_trace(replace(trace, acquisition_network_authority_verified=True))


def test_public_producer_is_two_path_deep_seam_and_holds_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(signature(produce_publication_day1b_unit).parameters) == (
        "trace_bundle_dir",
        "output_dir",
    )
    assert (
        tuple(signature(day1b_module._repository_day1b_profile_anchor_authority).parameters) == ()
    )
    assert tuple(signature(day1b_module._repository_trace_anchor_authority).parameters) == ()
    assert tuple(signature(day1b_module._repository_day1b_resource_policy).parameters) == ()
    assert tuple(signature(day1b_module._repository_day1b_execution_adapter).parameters) == (
        "size_authority",
    )
    with pytest.raises(PublicationDay1BHold, match="central TRACE post-run anchor"):
        day1b_module._repository_trace_anchor_authority()
    with pytest.raises(PublicationDay1BHold, match="full OpenFHE Day1B runner"):
        day1b_module._repository_day1b_execution_adapter(_size_authority())
    calls: list[str] = []

    monkeypatch.setattr(
        day1b_module,
        "verify_current_role_source",
        lambda role, root: SimpleNamespace(
            git_sha="1" * 40,
            attestation="repository-clean-head",
        ),
    )
    monkeypatch.setattr(
        day1b_module,
        "capture_behavior_inventory",
        lambda role, source_git_sha, repository_root: {
            "behavior_set_schema_version": ("dynamic-cssc-day1b-preparatory-behavior-set-v19"),
            "behavior_set_sha256": "2" * 64,
            "entries": [],
            "role": "day1b",
            "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
            "source_git_sha": source_git_sha,
        },
    )

    def pending_policy() -> PublicationDay1BResourcePolicy:
        calls.append("pending-policy")
        raise PublicationDay1BHold("HOLD: Day1B resource policy is PENDING-FREEZE")

    def forbidden_dependency(*args: object, **kwargs: object) -> object:
        raise AssertionError("production touched a dependency after the pending-policy HOLD")

    monkeypatch.setattr(day1b_module, "_repository_day1b_resource_policy", pending_policy)
    monkeypatch.setattr(
        day1b_module,
        "_repository_day1b_profile_anchor_authority",
        forbidden_dependency,
    )
    monkeypatch.setattr(day1b_module, "repository_day1_candidate_catalog", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_load_repository_trace_input", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_repository_trace_anchor_authority", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_repository_day1b_execution_adapter", forbidden_dependency)
    trace_dir = tmp_path / "trace-that-must-not-be-read"
    output_dir = tmp_path / "unit"

    with pytest.raises(PublicationDay1BHold, match="PENDING-FREEZE"):
        produce_publication_day1b_unit(trace_dir, output_dir)

    assert calls == ["pending-policy"]
    assert not output_dir.exists()


def test_repository_day1b_profile_gate_requires_complete_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        day1b_module,
        "verify_current_role_source",
        lambda role, repository_root: SimpleNamespace(git_sha="1" * 40),
    )
    valid_history = SimpleNamespace(
        analysis_source_git_sha="1" * 40,
        day1a_authority_receipt_sha256="2" * 64,
        day1a_evidence_anchor_git_sha="3" * 40,
        day2_profile_installation_git_sha="4" * 40,
    )
    monkeypatch.setattr(
        day1b_module,
        "verify_repository_anchor_history",
        lambda role, repository_root: valid_history,
    )
    monkeypatch.setattr(
        day1b_module,
        "repository_day2_calibration_authority",
        lambda: SimpleNamespace(
            source_git_sha="2" * 40,
            outer_archive_sha256="3" * 64,
            serialized_object_size_profile_sha256="4" * 64,
            ciphertext_bytes=34567,
            f1m_random_zero_sum_ciphertext_bytes=34568,
            f1m_encrypted_zero_dummy_ciphertext_bytes=34569,
            serialized_rotation_key_inventory_bytes=45678,
            serialized_eval_mult_key_bytes=56789,
        ),
    )

    size_authority = day1b_module._repository_day1b_profile_anchor_authority()
    assert size_authority == _size_authority()

    missing_profile = SimpleNamespace(
        analysis_source_git_sha="1" * 40,
        day1a_authority_receipt_sha256="2" * 64,
        day1a_evidence_anchor_git_sha="3" * 40,
        day2_profile_installation_git_sha=None,
    )
    monkeypatch.setattr(
        day1b_module,
        "verify_repository_anchor_history",
        lambda role, repository_root: missing_profile,
    )
    with pytest.raises(PublicationDay1BHold, match="Day1A anchor and Day2 profile"):
        day1b_module._repository_day1b_profile_anchor_authority()


def test_public_producer_checks_profile_before_catalog_trace_or_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        day1b_module,
        "verify_current_role_source",
        lambda role, repository_root: SimpleNamespace(
            git_sha="1" * 40,
            attestation="repository-clean-head",
        ),
    )
    monkeypatch.setattr(
        day1b_module,
        "capture_behavior_inventory",
        lambda role, source_git_sha, repository_root: {
            "behavior_set_schema_version": "dynamic-cssc-day1b-preparatory-behavior-set-v19",
            "behavior_set_sha256": "2" * 64,
            "entries": [],
            "role": "day1b",
            "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
            "source_git_sha": source_git_sha,
        },
    )
    monkeypatch.setattr(day1b_module, "_repository_day1b_resource_policy", _resource_policy)
    calls: list[str] = []

    def profile_hold() -> str:
        calls.append("profile")
        raise PublicationDay1BHold("HOLD: profile history missing")

    def forbidden_dependency(*args: object, **kwargs: object) -> object:
        raise AssertionError("production touched held-out input before profile admission")

    monkeypatch.setattr(
        day1b_module,
        "_repository_day1b_profile_anchor_authority",
        profile_hold,
    )
    monkeypatch.setattr(day1b_module, "repository_day1_candidate_catalog", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_load_repository_trace_input", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_repository_trace_anchor_authority", forbidden_dependency)
    monkeypatch.setattr(day1b_module, "_repository_day1b_execution_adapter", forbidden_dependency)

    with pytest.raises(PublicationDay1BHold, match="profile history missing"):
        produce_publication_day1b_unit(tmp_path / "unread-trace", tmp_path / "output")

    assert calls == ["profile"]


def test_pending_resource_policy_file_is_one_canonical_closed_non_authority_document() -> None:
    path = Path(__file__).resolve().parents[1] / "config/publication-day1b-resource-policy.json"
    content = path.read_bytes()
    expected = _pending_resource_policy_document()

    assert content == _canonical_bytes(expected)
    pending = day1b_module._decode_pending_day1b_resource_policy(content)
    assert pending.state == "PENDING-FREEZE"
    assert pending.canonical_sha256 == hashlib.sha256(content).hexdigest()
    assert all(value is False for value in expected["authority"].values())
    assert all(value is None for value in expected["limits"].values())
    assert all(value is None for value in expected["measurement_methods"].values())
    assert all(value is None for value in expected["pilot_evidence"].values())
    assert all(value is None for value in expected["amendment_identity"].values())
    assert all(value is None for value in expected["worker_runtime_identity"].values())
    assert expected["protocol_invariants"] == {
        "candidate_retry_count": 0,
        "selective_candidate_retry_allowed": False,
    }


def test_repository_resource_amendment_is_canonical_reviewed_and_non_authorizing() -> None:
    root = Path(__file__).resolve().parents[1]
    amendment_path = root / "config/publication-day1b-resource-amendment.json"
    review_path = root / "docs/reviews/day1b-resource-amendment-review-2026-08-25.md"
    content = amendment_path.read_bytes()

    decoded = day1b_module._decode_day1b_resource_amendment(content)

    assert content == _canonical_bytes(json.loads(content))
    assert decoded.state == "RESOURCE-VALUES-FROZEN"
    assert decoded.amendment_id == "day1b-resource-amendment-2026-08-25-001"
    assert decoded.amendment_payload_sha256 == (
        "ff3409d0a7e30a11b1cc28b1a8dede64652476b00e21baaf94751c823df4736c"
    )
    assert decoded.canonical_sha256 == hashlib.sha256(content).hexdigest()
    assert decoded.schema_source_git_sha == "e4d5d63ddcc7cadf2d2efa870b9faf41ae573489"
    assert decoded.schema_source_behavior_inventory_sha256 == (
        "e23400d6c38245dec97928ff9766130be71c8e86365b06f440964ff97b2b23ec"
    )
    assert decoded.review_receipt_sha256 == hashlib.sha256(review_path.read_bytes()).hexdigest()
    assert decoded.resource_policy.authority.startswith(
        "non-authorizing-resource-amendment-binding:"
    )
    assert decoded.resource_policy.cells_per_shard == 18
    assert decoded.resource_policy.max_concurrency == 1
    assert decoded.resource_policy.candidate_retry_count == 0
    assert decoded.resource_policy.output_bytes_per_unit == 8_000_000_000


def test_repository_resource_policy_uses_reviewed_amendment_without_granting_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(__file__).resolve().parents[1]
    pending = day1b_module._decode_pending_day1b_resource_policy(
        (root / "config/publication-day1b-resource-policy.json").read_bytes()
    )
    amendment = day1b_module._decode_day1b_resource_amendment(
        (root / "config/publication-day1b-resource-amendment.json").read_bytes()
    )
    monkeypatch.setattr(
        day1b_module,
        "_read_repository_day1b_pending_policy",
        lambda _repository_root: pending,
    )
    monkeypatch.setattr(
        day1b_module,
        "_read_repository_day1b_resource_amendment",
        lambda _repository_root: amendment,
    )

    policy = day1b_module._require_repository_day1b_resource_policy(Path("/unused"))

    assert policy == amendment.resource_policy
    assert policy.authority == (
        f"non-authorizing-resource-amendment-binding:{amendment.amendment_payload_sha256}"
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "extra-key",
        "missing-key",
        "active-state",
        "boolean-retry",
        "filled-limit",
        "filled-method",
        "filled-pilot",
        "filled-amendment",
        "filled-runner",
        "authority-true",
    ),
)
def test_pending_resource_policy_rejects_every_attempt_to_fill_or_promote_it(
    mutation: str,
) -> None:
    document = _pending_resource_policy_document()
    if mutation == "extra-key":
        document["caller_override"] = False
    elif mutation == "missing-key":
        del document["pilot_evidence"]
    elif mutation == "active-state":
        document["state"] = "FROZEN"
    elif mutation == "boolean-retry":
        document["protocol_invariants"]["candidate_retry_count"] = False
    elif mutation == "filled-limit":
        document["limits"]["wall_clock_seconds_per_candidate_cell"] = 1
    elif mutation == "filled-method":
        document["measurement_methods"]["wall_clock_observation_method"] = "clock"
    elif mutation == "filled-pilot":
        document["pilot_evidence"]["structure_pilot_report_sha256"] = "3" * 64
    elif mutation == "filled-amendment":
        document["amendment_identity"]["resource_policy_amendment_id"] = "amendment-1"
    elif mutation == "filled-runner":
        document["worker_runtime_identity"]["full_openfhe_runner_path"] = "/runner"
    else:
        document["authority"]["dispatch_authorized"] = True

    with pytest.raises(ValueError, match="pending Day1B resource policy"):
        day1b_module._decode_pending_day1b_resource_policy(_canonical_bytes(document))


def test_resource_amendment_decoder_is_resource_only_and_non_authorizing() -> None:
    document = _resource_amendment_document()
    content = _canonical_bytes(document)

    decoded = day1b_module._decode_day1b_resource_amendment(content)

    assert decoded.state == "RESOURCE-VALUES-FROZEN"
    assert decoded.amendment_id == "day1b-resource-amendment-001"
    assert decoded.canonical_sha256 == hashlib.sha256(content).hexdigest()
    assert (
        decoded.amendment_payload_sha256
        == document["amendment_identity"]["resource_policy_amendment_payload_sha256"]
    )
    assert decoded.schema_source_git_sha == "6" * 40
    assert decoded.schema_source_behavior_inventory_sha256 == "5" * 64
    assert decoded.structure_pilot_source_git_sha == "4" * 40
    assert decoded.shard_cost_budget_usd_maximum == "5.25"
    assert decoded.job_cost_budget_usd_maximum == "25"
    assert decoded.resource_policy.cells_per_shard == 18
    assert decoded.resource_policy.max_concurrency == 1
    assert decoded.resource_policy.candidate_retry_count == 0
    assert decoded.resource_policy.authority == (
        f"non-authorizing-resource-amendment-binding:{decoded.amendment_payload_sha256}"
    )
    assert set(document) == {
        "amendment_identity",
        "limits",
        "measurement_methods",
        "pilot_evidence",
        "protocol_invariants",
        "schema_source",
        "schema_version",
        "state",
    }
    assert "authority" not in document
    assert "worker_runtime_identity" not in document
    assert not hasattr(decoded, "dispatch_authorized")


@pytest.mark.parametrize(
    "mutation",
    (
        "authority-field",
        "worker-runtime-field",
        "wrong-state",
        "boolean-limit",
        "zero-limit",
        "output-over-ceiling",
        "noncanonical-cost",
        "cost-order",
        "wall-clock-order",
        "concurrency",
        "retry",
        "selective-retry",
        "method-token",
        "pilot-digest",
        "schema-source",
        "payload-digest",
    ),
)
def test_resource_amendment_rejects_authority_and_nonclosed_values(
    mutation: str,
) -> None:
    document = _resource_amendment_document()
    limits = document["limits"]
    protocol = document["protocol_invariants"]
    if mutation == "authority-field":
        document["authority"] = {"dispatch_authorized": False}
    elif mutation == "worker-runtime-field":
        document["worker_runtime_identity"] = {}
    elif mutation == "wrong-state":
        document["state"] = "DISPATCH-AUTHORIZED"
    elif mutation == "boolean-limit":
        limits["wall_clock_seconds_per_candidate_cell"] = True
    elif mutation == "zero-limit":
        limits["scratch_bytes_per_candidate_cell"] = 0
    elif mutation == "output-over-ceiling":
        limits["output_bytes_per_unit"] = 8_000_000_001
    elif mutation == "noncanonical-cost":
        limits["job_cost_budget_usd_maximum"] = "25.0"
    elif mutation == "cost-order":
        limits["job_cost_budget_usd_maximum"] = "5"
    elif mutation == "wall-clock-order":
        limits["job_wall_clock_seconds_maximum"] = 35_999
    elif mutation == "concurrency":
        limits["max_concurrency"] = 2
    elif mutation == "retry":
        protocol["candidate_retry_count"] = 1
    elif mutation == "selective-retry":
        protocol["selective_candidate_retry_allowed"] = True
    elif mutation == "method-token":
        document["measurement_methods"]["wall_clock_observation_method"] = "clock method"
    elif mutation == "pilot-digest":
        document["pilot_evidence"]["structure_pilot_report_sha256"] = "A" * 64
    elif mutation == "schema-source":
        document["schema_source"]["git_sha"] = "6" * 64
    else:
        document["amendment_identity"]["resource_policy_amendment_payload_sha256"] = "f" * 64

    with pytest.raises(ValueError):
        day1b_module._decode_day1b_resource_amendment(_canonical_bytes(document))


def test_resource_amendment_rejects_noncanonical_and_duplicate_json() -> None:
    document = _resource_amendment_document()
    noncanonical = json.dumps(document, indent=2, sort_keys=True).encode("ascii") + b"\n"
    duplicate = b'{"schema_version":"x","schema_version":"x"}\n'

    with pytest.raises(ValueError, match="top-level document is not exact"):
        day1b_module._decode_day1b_resource_amendment(noncanonical)
    with pytest.raises(ValueError, match="duplicate key"):
        day1b_module._decode_day1b_resource_amendment(duplicate)


@pytest.mark.parametrize(
    "reported_test",
    (
        "tests/test_publication_day1b.py::forged (call)",
        "tests/not-an-approved-day1b-test.py::forged (call)",
    ),
)
def test_private_protocol_issuer_requires_one_exact_allowed_test_and_stack(
    reported_test: str,
) -> None:
    _require_test_invocation_issuer()
    repository_root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from dynamic_cssc.publication_day1b_worker_protocol import "
                "_require_test_invocation_issuer; _require_test_invocation_issuer()"
            ),
        ],
        cwd=repository_root,
        env={
            **os.environ,
            "PYTHONPATH": str(repository_root / "src"),
            "PYTEST_CURRENT_TEST": reported_test,
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "pytest-only" in result.stderr


def test_cli_exposes_only_the_two_public_paths_and_preserves_the_hold(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    output_dir = tmp_path / "unit"
    environment = {**os.environ, "PYTHONPATH": str(repository_root / "src")}

    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "run_publication_day1b.py"),
            "--trace-bundle-dir",
            str(trace_dir),
            "--output-dir",
            str(output_dir),
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "HOLD" in result.stderr
    assert result.stdout == ""
    assert not output_dir.exists()


@pytest.fixture(scope="module")
def _complete_unit_fixture(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[PublicationDay1BUnitBundle, _StreamingExecutor]:
    root = tmp_path_factory.mktemp("complete-day1b-unit")
    executor = _StreamingExecutor(root / "controlled-scratch")
    bundle = _produce_publication_day1b_unit_for_test(
        trace=_trace(),
        output_dir=root / "unit",
        source_attestation=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    return bundle, executor


def test_day1b_schema_names_are_unambiguous_across_exact_key_contracts() -> None:
    schemas = {
        name: value
        for name, value in vars(day1b_module).items()
        if name.endswith("_SCHEMA") and type(value) is str
    }

    assert DAY1B_UNIT_SCHEMA == "dynamic-cssc-publication-day1b-unit-v4"
    assert DAY1B_UNIT_FRAGMENT_SCHEMA == ("dynamic-cssc-publication-day1b-unit-fragment-v1")
    assert len(set(schemas.values())) == len(schemas)
    retained_document_families = (
        DAY1B_UNIT_SCHEMA,
        day1b_module.DAY1B_SERIALIZATION_LEDGER_SCHEMA,
        f1m_aggregation.DAY1B_F1M_CONTROLLER_SUMMARY_SCHEMA,
        f1m_aggregation.DAY1B_F1M_CONTROLLER_CONTEXT_SCHEMA,
        f1m_aggregation.DAY1B_F1M_ROUTE_COVERAGE_SCHEMA,
        worker_protocol.DAY1B_WORKER_INPUT_BINDING_SCHEMA,
        worker_protocol.DAY1B_WORKER_RECEIPT_SCHEMA,
        day1b_accounting.DAY1B_ACCOUNTING_SCHEMA,
        day1b_accounting.DAY1B_PHASE_ACCOUNTING_SCHEMA,
        expected_counts_module.DAY1B_CONTROLLER_EXPECTED_COUNTS_SCHEMA,
        expected_counts_module.DAY1B_CONTROLLER_EXPECTED_COMBINED_EVALUATION_KEY_SIZE_CLASS_SCHEMA,
        expected_counts_module.DAY1B_CONTROLLER_EXPECTED_METADATA_SIZE_CLASS_SCHEMA,
        expected_counts_module.DAY1B_CONTROLLER_EXPECTED_PHASE_COUNTS_SCHEMA,
    )
    assert len(set(retained_document_families)) == len(retained_document_families)
    assert worker_protocol.DAY1B_WORKER_INPUT_BINDING_SCHEMA.endswith("-v10")
    assert worker_protocol.DAY1B_WORKER_RECEIPT_SCHEMA.endswith("-v10")
    assert day1b_module.DAY1B_SERIALIZATION_LEDGER_SCHEMA.endswith("-v5")
    assert DAY1B_UNIT_SCHEMA.endswith("-v4")


def test_private_typed_core_writes_one_stats_composable_18_cell_486_record_unit(
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, executor = _complete_unit_fixture

    manifest = json.loads(bundle.manifest_path.read_bytes())
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
    schedule_lines = bundle.schedule_path.read_bytes().splitlines()
    ledger_lines = bundle.serialization_ledger_path.read_bytes().splitlines()
    object_receipt_lines = bundle.serialized_object_receipt_path.read_bytes().splitlines()
    trace_unit = fragment["trace_units"][0]
    cells = fragment["cell_bindings"]
    records = fragment["records"]

    assert manifest["schema_version"] == (
        "dynamic-cssc-publication-day1b-unit-private-test-fixture-v4"
    )
    assert manifest["artifact_variant"] == {
        "claims_authorized": False,
        "fixture_seam": "pytest-only-private-day1b-unit-producer",
        "kind": "private-test-fixture",
        "schema_version": "dynamic-cssc-publication-day1b-artifact-variant-v1",
    }
    assert fragment["schema_version"] == (
        "dynamic-cssc-publication-day1b-unit-fragment-private-test-fixture-v1"
    )
    assert manifest["serialized_object_size_authority"] == {
        "schema_version": day1b_module.DAY1B_SERIALIZED_OBJECT_SIZE_AUTHORITY_SCHEMA,
        **executor.f1m_summaries[0].size_authority.to_document(),
    }
    assert manifest["candidate_catalog"]["candidate_policies"] == [
        day1b_module._candidate_policy_document(candidate)
        for candidate in _catalog().candidates
    ]
    assert trace_unit["schema_version"] == TRACE_UNIT_SCHEMA
    assert set(trace_unit) == statistics_module._TRACE_UNIT_KEYS
    assert len(cells) == 18
    assert len(records) == 486
    assert len(ledger_lines) == 486
    assert len(object_receipt_lines) == 3_168
    assert len(executor.calls) == 252
    assert len(executor.f1m_summaries) == 252
    assert all(
        window_count == 3 for _freshness, _rho, _candidate_id, window_count in executor.calls
    )
    assert [candidate_id for _freshness, _rho, candidate_id, _count in executor.calls] == (
        list(FIXED_CANDIDATE_IDS) * 18
    )
    assert [summary.context.candidate_id for summary in executor.f1m_summaries] == (
        list(FIXED_CANDIDATE_IDS) * 18
    )
    assert [summary.context.cell_ordinal for summary in executor.f1m_summaries] == [
        cell_ordinal for cell_ordinal in range(18) for _candidate_id in FIXED_CANDIDATE_IDS
    ]
    assert all(
        summary.context.complete_window_count == 3
        and summary.context.complete_window_count
        == summary.context.query_window_count + summary.context.zero_query_window_count
        for summary in executor.f1m_summaries
    )
    assert any(summary.context.zero_query_window_count > 0 for summary in executor.f1m_summaries)
    assert [cell["freshness_seconds"] for cell in cells] == [
        freshness for freshness in FRESHNESS_VALUES for _rho in RHO_VALUES
    ]
    assert [cell["rho"] for cell in cells] == list(RHO_VALUES) * len(FRESHNESS_VALUES)
    assert all(cell["schema_version"] == CELL_BINDING_SCHEMA for cell in cells)
    assert all(set(cell) == statistics_module._CELL_BINDING_KEYS for cell in cells)
    assert all(
        cell["event_schedule_schema_version"] == ACCEPTED_EVENT_SCHEDULE_SCHEMA for cell in cells
    )
    assert len({cell["query_vector_sha256"] for cell in cells}) == 1
    for cell, receipt in zip(cells, manifest["cell_execution_receipts"], strict=True):
        assert receipt["candidate_cell_receipt_count"] == 14
        assert len(receipt["candidate_cell_receipts"]) == 14
        assert all(
            candidate_receipt["production_execution_admissible"] is False
            and candidate_receipt["runtime_state_continuity_verified"] is False
            and candidate_receipt["candidate"]["worker_declared_state_reset_count"] == 0
            for candidate_receipt in receipt["candidate_cell_receipts"]
        )
        phase_receipts = {row["phase"]: row for row in receipt["phase_receipts"]}
        assert cell["tuning_update_count"] == phase_receipts["tuning"]["accepted_event_group_count"]
        assert cell["tuning_query_count"] == phase_receipts["tuning"]["realized_query_count"]
        assert (
            cell["heldout_update_count"] == phase_receipts["heldout"]["accepted_event_group_count"]
        )
        assert cell["heldout_query_count"] == phase_receipts["heldout"]["realized_query_count"]
    for rho in RHO_VALUES:
        matching = [cell for cell in cells if cell["rho"] == rho]
        assert len(matching) == 2
        assert len({cell["event_schedule_sha256"] for cell in matching}) == 1
    assert all(record["schema_version"] == HELDOUT_RECORD_SCHEMA for record in records)
    decoded_records = tuple(
        statistics_module._decode_record(record, index, PRIMITIVE_NAMES)
        for index, record in enumerate(records)
    )
    assert len(decoded_records) == 486
    assert [record["candidate_id"] for record in records[:27]] == [
        *REFERENCE_CANDIDATE_IDS,
        *FIXED_CANDIDATE_IDS,
    ]
    assert [record["phase"] for record in records[:27]] == [
        *("tuning-prefix" for _ in REFERENCE_CANDIDATE_IDS),
        *("held-out" for _ in FIXED_CANDIDATE_IDS),
    ]
    assert set(records[0]["update_primitive_counts"]) == set(PRIMITIVE_NAMES)
    decoded_ledgers = [json.loads(line) for line in ledger_lines]
    cell_index_by_binding = {cell["cell_binding_sha256"]: index for index, cell in enumerate(cells)}
    summary_by_candidate_cell = {
        (summary.context.cell_ordinal, summary.context.candidate_id): summary
        for summary in executor.f1m_summaries
    }
    assert len(summary_by_candidate_cell) == 252
    for cell_index, receipt in enumerate(manifest["cell_execution_receipts"]):
        for candidate_id, worker_receipt in zip(
            FIXED_CANDIDATE_IDS,
            receipt["candidate_cell_receipts"],
            strict=True,
        ):
            summary = summary_by_candidate_cell[(cell_index, candidate_id)]
            assert len(_canonical_bytes(worker_receipt)) <= (
                day1b_module._DAY1B_WORKER_RECEIPT_CANONICAL_BYTES_MAXIMUM
            )
            assert worker_receipt["f1m_controller_context_sha256"] == (
                summary.context.context_sha256
            )
            assert worker_receipt["f1m_route_coverage_sha256"] == (summary.route_coverage_sha256)
            assert worker_receipt["f1m_charged_size_class_set_sha256"] == (
                summary.charged_size_class_set_sha256
            )
            input_binding_document = worker_receipt["input_binding_document"]
            assert _sha(input_binding_document) == worker_receipt["input_binding_sha256"]
            assert len(_canonical_bytes(input_binding_document)) < (
                worker_protocol.DAY1B_WORKER_MAX_HEADER_BYTES
            )
            assert input_binding_document["f1m_controller_context_document"] == (
                summary.context.to_document()
            )
            assert input_binding_document["f1m_controller_context_document"][
                "trace_source_git_sha"
            ] == manifest["trace_source"]["git_sha"]
            assert input_binding_document["f1m_controller_context_sha256"] == (
                summary.context.context_sha256
            )
            assert input_binding_document["f1m_route_coverage_document"] == (
                summary.route_coverage.to_document()
            )
            assert input_binding_document["f1m_route_coverage_sha256"] == (
                summary.route_coverage_sha256
            )
            assert (
                input_binding_document["f1m_charged_size_class_set_sha256"]
                == summary.charged_size_class_set_sha256
            )
    controller_charges: list[int] = []
    for record, ledger in zip(records, decoded_ledgers, strict=True):
        cell_index = cell_index_by_binding[record["cell_binding_sha256"]]
        summary = summary_by_candidate_cell[(cell_index, record["candidate_id"])]
        candidate_index = FIXED_CANDIDATE_IDS.index(record["candidate_id"])
        worker_receipt = manifest["cell_execution_receipts"][cell_index][
            "candidate_cell_receipts"
        ][candidate_index]
        expected_document = worker_receipt["input_binding_document"][
            "controller_expected_counts_document"
        ]
        expected_phase = next(
            phase
            for phase in expected_document["phases"]
            if phase["phase"] == record["phase"]
        )
        expected_category_index = {
            category[0]: index
            for index, category in enumerate(expected_document["serialized_categories"])
        }
        expected_metadata_classes = {
            item["category"]: item
            for item in expected_document[
                "fixed_width_metadata_size_classes"
            ]
        }
        expected_key_class = expected_document[
            "combined_evaluation_key_size_class"
        ]
        expected_classes = {
            (item.phase, item.category): item.to_document() for item in summary.charged_size_classes
        }
        assert ledger["schema_version"] == day1b_module.DAY1B_SERIALIZATION_LEDGER_SCHEMA
        assert ledger["controller_accounting_sha256"] == expected_document["accounting_sha256"]
        assert ledger["controller_expected_counts_sha256"] == _sha(expected_document)
        assert ledger["f1m_controller_context_sha256"] == (summary.context.context_sha256)
        assert ledger["f1m_route_coverage_sha256"] == summary.route_coverage_sha256
        assert ledger["f1m_charged_size_class_set_sha256"] == (
            summary.charged_size_class_set_sha256
        )
        assert record["update_serialized_bytes"] == ledger["update_serialized_bytes"]
        assert (
            record["query_serialized_bytes"]
            == (ledger["query_serialized_bytes_including_controller_charge"])
        )
        assert ledger["query_serialized_bytes_including_controller_charge"] == (
            ledger["query_serialized_bytes"] + ledger["controller_charged_query_bytes"]
        )
        expected_controller_total = 0
        for row in ledger["categories"]:
            category_index = expected_category_index[row["category"]]
            expected_logical_count = expected_phase[
                "logical_protocol_object_counts"
            ][category_index]
            expected_worker_count = expected_phase[
                "worker_streamed_protocol_object_counts"
            ][category_index]
            assert row[
                "controller_expected_logical_protocol_object_count"
            ] == expected_logical_count
            assert row[
                "controller_expected_worker_streamed_protocol_object_count"
            ] == expected_worker_count
            expected_metadata_class = expected_metadata_classes.get(
                row["category"]
            )
            if row["category"] == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY:
                assert row[
                    "controller_expected_fixed_width_size_class_sha256"
                ] is None
                assert row[
                    "controller_expected_combined_evaluation_key_size_class_sha256"
                ] == expected_key_class[
                    "combined_evaluation_key_size_class_sha256"
                ]
                assert row["controller_expected_serialized_byte_count"] == (
                    expected_key_class["serialized_byte_count"]
                )
                assert row["charged_byte_count"] == (
                    expected_worker_count
                    * expected_key_class["serialized_byte_count"]
                )
                assert row["serialization_equivalence_class_count"] == int(
                    expected_worker_count > 0
                )
            elif expected_metadata_class is None:
                assert row[
                    "controller_expected_fixed_width_size_class_sha256"
                ] is None
                assert row[
                    "controller_expected_combined_evaluation_key_size_class_sha256"
                ] is None
                assert row["controller_expected_serialized_byte_count"] is None
            else:
                expected_metadata_bytes = expected_metadata_class[
                    "serialized_byte_count"
                ]
                assert row[
                    "controller_expected_fixed_width_size_class_sha256"
                ] == day1b_metadata_size_class_sha256(row["category"])
                assert row[
                    "controller_expected_combined_evaluation_key_size_class_sha256"
                ] is None
                assert row[
                    "controller_expected_serialized_byte_count"
                ] == expected_metadata_bytes
                assert row["charged_byte_count"] == (
                    expected_worker_count * expected_metadata_bytes
                )
                assert row["serialization_equivalence_class_count"] == int(
                    expected_worker_count > 0
                )
            if row["category"] in worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES:
                assert row["charge_authority"] == ("controller-anchored-day2-size-class")
                assert row["charged_byte_count"] == 0
                assert row["protocol_object_count"] == 0
                assert expected_worker_count == 0
                assert row["serialization_equivalence_class_count"] == 0
                expected_class = expected_classes.get((record["phase"], row["category"]))
                assert row["controller_charged_size_class"] == expected_class
                assert expected_logical_count == (
                    0 if expected_class is None else expected_class["multiplicity"]
                )
                expected_charge = (
                    0 if expected_class is None else expected_class["charged_byte_count"]
                )
                assert row["controller_charged_byte_count"] == expected_charge
                expected_controller_total += expected_charge
            else:
                assert row["charge_authority"] == "worker-streamed-spool"
                assert row["protocol_object_count"] == expected_logical_count
                assert row["protocol_object_count"] == expected_worker_count
                assert row["controller_charged_byte_count"] == 0
                assert row["controller_charged_size_class"] is None
        assert ledger["controller_charged_query_bytes"] == expected_controller_total
        controller_charges.append(expected_controller_total)
    assert any(charge > 0 for charge in controller_charges)
    assert bundle.manifest_path.stat().st_size <= day1b_module._DAY1B_MANIFEST_BYTES_MAXIMUM

    for cell_index in range(18):
        cell_ledgers = decoded_ledgers[cell_index * 27 : (cell_index + 1) * 27]
        one_time_counts = [
            next(
                category["serialization_equivalence_class_count"]
                for category in ledger["categories"]
                if category["category"] == "one-time-evaluation-key-material"
            )
            for ledger in cell_ledgers
        ]
        assert one_time_counts == [
            *([1] * 13),
            *(int(candidate_id == ABLATION_CANDIDATE_ID) for candidate_id in FIXED_CANDIDATE_IDS),
        ]
    object_receipts = [json.loads(line) for line in object_receipt_lines]
    assert b"test-only:" not in bundle.serialized_object_receipt_path.read_bytes()
    assert (
        sum(row["category"] == "one-time-evaluation-key-material" for row in object_receipts) == 252
    )
    key_size_authority = executor.f1m_summaries[0].size_authority
    rotation_key_bytes = (
        key_size_authority.serialized_rotation_key_inventory_bytes
    )
    eval_mult_key_bytes = key_size_authority.serialized_eval_mult_key_bytes
    expected_key_bytes = 88 + rotation_key_bytes + eval_mult_key_bytes
    key_payload = _combined_evaluation_key_payload(
        rotation_key_bytes,
        eval_mult_key_bytes,
    )
    key_payload_sha256 = hashlib.sha256(key_payload).hexdigest()
    key_receipts = [
        row
        for row in object_receipts
        if row["category"] == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
    ]
    assert all(
        row["transaction"] == "one-time"
        and row["object"]["serialized_byte_count"] == expected_key_bytes
        and row["object"]["multiplicity"] == 1
        and row["object"]["charged_byte_count"] == expected_key_bytes
        and row["object"]["serialized_sha256"] == key_payload_sha256
        for row in key_receipts
    )
    assert manifest["cardinality"] == {
        "cell_binding_count": 18,
        "candidate_cell_receipt_count": 252,
        "physical_record_count": 486,
        "schedule_program_count": 9,
        "serialization_ledger_count": 486,
    }
    assert manifest["experiment_source"]["behavior_inventory"] == (_source().behavior_inventory)
    assert manifest["trace_source"] == {
        "authority_state": "HOLD-no-central-TRACE-post-run-anchor",
        "git_sha": "4" * 40,
        "repository_provenance_sha256": "5" * 64,
        "trace_behavior_source_blob_sha256": {"src/dynamic_cssc/publication_traces.py": "b" * 64},
        "trace_behavior_source_inventory_sha256": _trace().trace_behavior_source_inventory_sha256,
        "trace_central_behavior_inventory_present": False,
        "trace_manifest_schema_version": PUBLICATION_TRACE_MANIFEST_SCHEMA,
        "trace_manifest_sha256": "6" * 64,
        "trace_source_authority_verified": False,
    }
    assert manifest["acquisition_binding"] == {
        "acquisition_authority_state": None,
        "acquisition_behavior_inventory_sha256": None,
        "acquisition_behavior_set_sha256": None,
        "acquisition_network_authority_verified": False,
        "acquisition_transaction_sha256": None,
        "central_behavior_inventory_present": False,
        "schema_version": ACQUISITION_TRACE_BINDING_SCHEMA,
        "source_bundle_sha256": "a" * 64,
        "source_set_sha256": None,
    }
    assert manifest["resource_policy"]["candidate_retry_count"] == 0
    assert {
        receipt["peak_resident_memory_bytes"] for receipt in manifest["cell_execution_receipts"]
    } == {250_000_000}
    assert {receipt["peak_scratch_bytes"] for receipt in manifest["cell_execution_receipts"]} == {
        500_000_000
    }
    assert manifest["authority"] == {
        "state": "HOLD-pre-S1-no-central-TRACE-anchor-no-runtime-admission",
        "local_integrity_verified": False,
        "schedule_v2_verified": False,
        "serialized_protocol_object_bytes_verified": False,
        "derived_aliases_materialized": False,
        "day1b_behavior_source_verified": False,
        "trace_source_authority_verified": False,
        "acquisition_network_authority_verified": False,
        "runtime_execution_isolation_verified": False,
        "publication_claim_allowed": False,
    }
    assert (
        len([line for line in schedule_lines if b'"rho":{"denominator":1,"numerator":100}' in line])
        == 1
    )
    assert not any(b'"kind":"query"' in line for line in schedule_lines)
    assert sum(b'"kind":"query-run"' in line for line in schedule_lines) == 2_250
    assert (
        bundle.heldout_fragment_sha256
        == hashlib.sha256(bundle.heldout_fragment_path.read_bytes()).hexdigest()
    )
    verified = verify_existing_directory(
        bundle.output_dir,
        verifier=lambda view: day1b_module._verify_day1b_unit_view(
            view,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
        ),
    )
    assert verified.cardinality == (18, 252, 486, 486)
    assert verified.manifest_sha256 == bundle.manifest_sha256


@pytest.mark.parametrize(
    "mutation",
    ("duplicate", "order", "missing", "ciphertext", "profile", "day2"),
)
def test_controller_summary_rejects_noncanonical_charged_classes(
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    mutation: str,
) -> None:
    _bundle, executor = _complete_unit_fixture
    summary = next(item for item in executor.f1m_summaries if len(item.charged_size_classes) >= 2)
    classes: list[Day1BF1MChargedSizeClass] = list(summary.charged_size_classes)
    first = classes[0]
    if mutation == "duplicate":
        classes[1] = replace(
            classes[1],
            phase=first.phase,
            category=first.category,
            f1m_kind=first.f1m_kind,
            serialized_size_profile_key=first.serialized_size_profile_key,
        )
    elif mutation == "order":
        classes.reverse()
    elif mutation == "missing":
        classes.pop(0)
    elif mutation == "ciphertext":
        classes[0] = replace(first, ciphertext_bytes=first.ciphertext_bytes + 1)
    elif mutation == "profile":
        classes[0] = replace(first, serialized_object_size_profile_sha256="f" * 64)
    elif mutation == "day2":
        classes[0] = replace(first, day2_outer_archive_sha256="f" * 64)
    with pytest.raises(ValueError, match="do not exactly derive"):
        replace(summary, charged_size_classes=tuple(classes))


def test_prepared_day1b_staging_installs_through_shared_descriptor_seam(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    expected = verify_existing_directory(
        bundle.output_dir,
        verifier=lambda view: day1b_module._verify_day1b_unit_view(
            view,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
        ),
    )
    staging = tmp_path / "staging"
    output = tmp_path / "installed"
    old_lock = tmp_path / ".installed.publication-day1b.lock"
    old_lock.write_bytes(b"foreign-lock-name\n")
    shutil.copytree(bundle.output_dir, staging)
    observed = staging.stat()

    installed = day1b_module._install_verified_day1b_staging(
        staging=staging,
        staging_identity=(observed.st_dev, observed.st_ino),
        output_dir=output,
        artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
        expected_verification=expected,
    )

    assert installed == expected
    assert output.is_dir()
    assert not staging.exists()
    assert old_lock.read_bytes() == b"foreign-lock-name\n"


def _fixture_verification(bundle: PublicationDay1BUnitBundle) -> object:
    return verify_existing_directory(
        bundle.output_dir,
        verifier=lambda view: day1b_module._verify_day1b_unit_view(
            view,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
        ),
    )


def _rewrite_manifest_and_checksums(root: Path, manifest: dict[str, object]) -> None:
    (root / "publication-day1b-unit-manifest.json").write_bytes(_canonical_bytes(manifest))
    checksums = b"".join(
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n".encode()
        for name in (
            "publication-day1b-unit-manifest.json",
            "publication-heldout-fragment.json",
            "accepted-event-schedules.jsonl",
            "serialized-object-ledgers.jsonl",
            "serialized-object-receipts.jsonl",
        )
    )
    (root / "SHA256SUMS").write_bytes(checksums)


def _rehash_open_input_receipt(receipt: dict[str, object]) -> None:
    receipt["input_binding_sha256"] = _sha(receipt["input_binding_document"])
    receipt["worker_candidate_cell_receipt_sha256"] = _sha(
        {
            key: value
            for key, value in receipt.items()
            if key != "worker_candidate_cell_receipt_sha256"
        }
    )


def _rewrite_serialization_ledgers(
    root: Path,
    ledgers: list[dict[str, object]],
) -> None:
    ledger_bytes = b"".join(_canonical_bytes(ledger) for ledger in ledgers)
    ledger_path = root / "serialized-object-ledgers.jsonl"
    ledger_path.write_bytes(ledger_bytes)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    manifest["members"]["serialized-object-ledgers.jsonl"] = {
        "byte_count": len(ledger_bytes),
        "sha256": hashlib.sha256(ledger_bytes).hexdigest(),
    }
    _rewrite_manifest_and_checksums(root, manifest)


def _rewrite_as_production_variant(root: Path) -> None:
    fragment_path = root / "publication-heldout-fragment.json"
    manifest_path = root / "publication-day1b-unit-manifest.json"
    fragment = json.loads(fragment_path.read_bytes())
    manifest = json.loads(manifest_path.read_bytes())
    fragment["schema_version"] = DAY1B_UNIT_FRAGMENT_SCHEMA
    fragment_bytes = _canonical_bytes(fragment)
    fragment_path.write_bytes(fragment_bytes)
    fragment_sha256 = hashlib.sha256(fragment_bytes).hexdigest()
    manifest["schema_version"] = DAY1B_UNIT_SCHEMA
    manifest["artifact_variant"] = {
        "claims_authorized": False,
        "kind": "production",
        "producer_entrypoint": "scripts/run_publication_day1b.py",
        "schema_version": "dynamic-cssc-publication-day1b-artifact-variant-v1",
    }
    manifest["experiment_source"]["source_attestation"] = "repository-clean-head"
    manifest["acquisition_binding"].update(
        {
            "acquisition_authority_state": "HOLD-no-repository-post-run-anchor",
            "acquisition_behavior_inventory_sha256": "d" * 64,
            "acquisition_behavior_set_sha256": "e" * 64,
            "acquisition_transaction_sha256": "f" * 64,
            "central_behavior_inventory_present": True,
            "source_set_sha256": "0" * 64,
        }
    )
    manifest["members"]["publication-heldout-fragment.json"] = {
        "byte_count": len(fragment_bytes),
        "sha256": fragment_sha256,
    }
    manifest["heldout_input_member_sha256"] = fragment_sha256
    _rewrite_manifest_and_checksums(root, manifest)


def test_day1b_verifier_streams_all_jsonl_without_whole_member_reads(
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    real_read = day1b_module.PublicationArtifactDirectory.read_regular

    def reject_jsonl_read(view: object, relative_path: str) -> bytes:
        if relative_path.endswith(".jsonl"):
            raise AssertionError("Day1B verifier must not whole-read a JSONL member")
        return real_read(view, relative_path)

    monkeypatch.setattr(
        day1b_module.PublicationArtifactDirectory,
        "read_regular",
        reject_jsonl_read,
    )

    observed = _fixture_verification(bundle)

    assert observed.cardinality == (18, 252, 486, 486)


def test_day1b_verifier_rejects_oversize_members_before_any_jsonl_read(
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    manifest = json.loads(bundle.manifest_path.read_bytes())
    output_limit = manifest["resource_policy"]["output_bytes_per_unit"]
    real_size = day1b_module.PublicationArtifactDirectory.regular_size
    real_read = day1b_module.PublicationArtifactDirectory.read_regular
    read_members: list[str] = []

    def inflate_object_member(view: object, relative_path: str) -> int:
        if relative_path == "serialized-object-receipts.jsonl":
            return output_limit + 1
        return real_size(view, relative_path)

    def record_small_reads(view: object, relative_path: str) -> bytes:
        read_members.append(relative_path)
        if relative_path.endswith(".jsonl"):
            raise AssertionError("oversize rejection must precede JSONL reads")
        return real_read(view, relative_path)

    monkeypatch.setattr(
        day1b_module.PublicationArtifactDirectory,
        "regular_size",
        inflate_object_member,
    )
    monkeypatch.setattr(
        day1b_module.PublicationArtifactDirectory,
        "read_regular",
        record_small_reads,
    )

    with pytest.raises(ValueError, match="resource-policy output limit"):
        _fixture_verification(bundle)

    assert read_members == [
        "publication-day1b-unit-manifest.json",
        "SHA256SUMS",
    ]


def test_day1b_verifier_rejects_a_rehashed_output_limit_above_the_hard_ceiling(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / "unbounded-policy"
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    resource_policy = manifest["resource_policy"]
    resource_policy["output_bytes_per_unit"] = 8_000_000_001
    resource_policy["resource_policy_sha256"] = _sha(
        {key: value for key, value in resource_policy.items() if key != "resource_policy_sha256"}
    )
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match="repository hard ceiling"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize(
    ("section", "field", "value", "message"),
    (
        (
            "trace_source",
            "trace_manifest_schema_version",
            "dynamic-cssc-publication-trace-manifest-v6",
            "exact v7",
        ),
        (
            "acquisition_binding",
            "schema_version",
            "dynamic-cssc-trace-acquisition-binding-v1",
            "exact v2",
        ),
    ),
)
def test_day1b_manifest_rejects_rehashed_trace_schema_downgrades(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    section: str,
    field: str,
    value: str,
    message: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / "schema-downgrade"
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    manifest[section][field] = value
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match=message):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


def test_day1b_verifier_rejects_rehashed_incomplete_weighted_size_class_receipt(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / "incomplete-weighted-size-classes"
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
    expected_count = receipt["controller_expected_f1m_size_class_count"]
    receipt["controller_expected_f1m_size_class_count"] = expected_count + 1
    receipt["worker_candidate_cell_receipt_sha256"] = _sha(
        {
            key: value
            for key, value in receipt.items()
            if key != "worker_candidate_cell_receipt_sha256"
        }
    )
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match="open exact input binding|input binding retargets"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


def test_day1b_verifier_rejects_rehashed_open_input_binding_splice(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / "open-input-binding-splice"
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
    receipt["input_binding_document"]["candidate_catalog_sha256"] = "f" * 64
    receipt["input_binding_sha256"] = _sha(receipt["input_binding_document"])
    receipt["worker_candidate_cell_receipt_sha256"] = _sha(
        {
            key: value
            for key, value in receipt.items()
            if key != "worker_candidate_cell_receipt_sha256"
        }
    )
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match="open exact input binding|input binding retargets"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize(
    "category",
    (
        "update-column-index-synchronization",
        "update-version-plan-metadata",
        "query-version-plan-metadata",
    ),
)
def test_day1b_verifier_rejects_rehashed_metadata_size_class_byte_splice(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    category: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / category
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
    input_document = receipt["input_binding_document"]
    expected_document = input_document["controller_expected_counts_document"]
    size_class = next(
        item
        for item in expected_document["fixed_width_metadata_size_classes"]
        if item["category"] == category
    )
    size_class["serialized_byte_count"] += 1
    input_document["controller_expected_counts_sha256"] = _sha(expected_document)
    _rehash_open_input_receipt(receipt)
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match="open exact input binding"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize(
    "mutation",
    ("expected-segment-length", "direct-segment-length"),
)
def test_day1b_verifier_rejects_rehashed_combined_key_authority_splice(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    mutation: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / mutation
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
    input_document = receipt["input_binding_document"]
    if mutation == "expected-segment-length":
        expected_document = input_document["controller_expected_counts_document"]
        expected_document["combined_evaluation_key_size_class"][
            "serialized_rotation_key_inventory_bytes"
        ] += 1
        input_document["controller_expected_counts_sha256"] = _sha(
            expected_document
        )
    else:
        input_document["serialized_rotation_key_inventory_bytes"] += 1
    _rehash_open_input_receipt(receipt)
    _rewrite_manifest_and_checksums(root, manifest)

    with pytest.raises(ValueError, match="open exact input binding"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("unit-day2-scalar", "Day 2 authority"),
        ("unit-day2-source", "retargets the experiment source"),
        ("contract-day2-scalar", "Day 2 authority"),
        ("contract-day2-key-scalar", "Day 2 authority"),
        ("policy-digest", "candidate policies do not open"),
        ("policy-strategy", "candidate policies do not open"),
        ("policy-count-13", "candidate policies do not open"),
        ("policy-count-15", "candidate policies do not open"),
        ("policy-order", "candidate policies do not open"),
        ("stale-catalog-hash", "retargets its manifest|controller context retargets"),
        ("trace-source-git", "controller context retargets"),
        ("controller-context", "controller context retargets"),
        ("route-phase-count", "charge-set root|open exact input binding"),
        (
            "controller-expected-primitive-count",
            "controller expected primitive counts differ from the physical record",
        ),
    ),
)
def test_day1b_verifier_rejects_rehashed_authority_policy_and_preimage_splices(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    mutation: str,
    message: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / mutation
    shutil.copytree(bundle.output_dir, root)
    manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
    catalog = manifest["candidate_catalog"]
    policies = catalog["candidate_policies"]
    receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
    input_document = receipt["input_binding_document"]

    if mutation == "unit-day2-scalar":
        manifest["serialized_object_size_authority"]["ciphertext_bytes"] += 1
    elif mutation == "unit-day2-source":
        manifest["serialized_object_size_authority"]["source_git_sha"] = "f" * 40
    elif mutation == "contract-day2-scalar":
        input_document["ciphertext_bytes"] += 1
        _rehash_open_input_receipt(receipt)
    elif mutation == "contract-day2-key-scalar":
        expected_document = input_document["controller_expected_counts_document"]
        key_class = expected_document["combined_evaluation_key_size_class"]
        key_class["serialized_rotation_key_inventory_bytes"] += 1
        key_class["serialized_byte_count"] += 1
        key_class_digest = day1b_combined_evaluation_key_size_class_sha256(
            day2_outer_archive_sha256=key_class["day2_outer_archive_sha256"],
            serialized_object_size_profile_sha256=(
                key_class["serialized_object_size_profile_sha256"]
            ),
            serialized_rotation_key_inventory_bytes=(
                key_class["serialized_rotation_key_inventory_bytes"]
            ),
            serialized_eval_mult_key_bytes=(
                key_class["serialized_eval_mult_key_bytes"]
            ),
        )
        key_class[
            "combined_evaluation_key_size_class_sha256"
        ] = key_class_digest
        input_document["serialized_rotation_key_inventory_bytes"] += 1
        input_document[
            "combined_evaluation_key_size_class_sha256"
        ] = key_class_digest
        input_document["controller_expected_counts_sha256"] = _sha(
            expected_document
        )
        _rehash_open_input_receipt(receipt)
    elif mutation == "policy-digest":
        policies[0]["candidate_policy_digest"] = "f" * 64
    elif mutation == "policy-strategy":
        policies[0]["strategy"] = "Strict-LocalRepack"
        policies[0]["candidate_policy_digest"] = _sha(
            {
                key: value
                for key, value in policies[0].items()
                if key != "candidate_policy_digest"
            }
        )
    elif mutation == "policy-count-13":
        policies.pop()
    elif mutation == "policy-count-15":
        policies.append(dict(policies[-1]))
    elif mutation == "policy-order":
        policies[0], policies[1] = policies[1], policies[0]
    elif mutation == "stale-catalog-hash":
        catalog["registration"]["run_id"] += 1
        catalog["registration_sha256"] = _sha(catalog["registration"])
    elif mutation == "trace-source-git":
        manifest["trace_source"]["git_sha"] = "f" * 40
    elif mutation == "controller-context":
        context_document = input_document["f1m_controller_context_document"]
        context_document["dataset_release"] = "foreign-release"
        context_sha256 = _sha(context_document)
        route_document = input_document["f1m_route_coverage_document"]
        route_document["controller_context_sha256"] = context_sha256
        route_sha256 = _sha(route_document)
        input_document["f1m_controller_context_sha256"] = context_sha256
        input_document["f1m_route_coverage_sha256"] = route_sha256
        receipt["f1m_controller_context_sha256"] = context_sha256
        receipt["f1m_route_coverage_sha256"] = route_sha256
        _rehash_open_input_receipt(receipt)
    elif mutation == "controller-expected-primitive-count":
        expected_document = input_document["controller_expected_counts_document"]
        expected_phase = expected_document["phases"][0]
        expected_phase["update_primitive_counts"][0] += 1
        input_document["controller_expected_counts_sha256"] = _sha(expected_document)
        candidate_phase = next(
            phase
            for phase in receipt["candidate"]["phases"]
            if phase["phase"] == expected_phase["phase"]
        )
        candidate_phase["update_primitive_counts"][0] += 1
        _rehash_open_input_receipt(receipt)
    else:
        route_document = input_document["f1m_route_coverage_document"]
        route_document["phase_random_route_counts"]["tuning-prefix"] += 1
        route_sha256 = _sha(route_document)
        input_document["f1m_route_coverage_sha256"] = route_sha256
        receipt["f1m_route_coverage_sha256"] = route_sha256
        _rehash_open_input_receipt(receipt)

    _rewrite_manifest_and_checksums(root, manifest)
    with pytest.raises(ValueError, match=message):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("controller-class", "controller F1-M charge document changed"),
        ("inclusive-total", "worker, controller, or inclusive totals"),
        ("ledger-v1", "serialization-ledger schema changed"),
        ("metadata-class-root", "metadata ledger row differs"),
        ("metadata-class-size", "metadata ledger row differs"),
        ("combined-key-class-root", "combined evaluation-key ledger row differs"),
        ("combined-key-class-size", "combined evaluation-key ledger row differs"),
        ("receipt-root", "input binding retargets"),
        ("non-f1m-controller-authority", "non-F1-M ledger row claims"),
        (
            "f1m-worker-quantity",
            "does not bind exact object-receipt rows|controller expected multiplicity",
        ),
        ("null-class-charge", "null F1-M controller class carries"),
        ("nonpositive-multiplicity", "controller F1-M charge document changed"),
        ("materialized-controller-object", "controller F1-M charge document changed"),
    ),
)
def test_day1b_verifier_rejects_rehashed_dual_source_ledger_splices(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    mutation: str,
    message: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / mutation
    shutil.copytree(bundle.output_dir, root)
    if mutation == "receipt-root":
        manifest = json.loads((root / "publication-day1b-unit-manifest.json").read_bytes())
        receipt = manifest["cell_execution_receipts"][0]["candidate_cell_receipts"][0]
        receipt["f1m_charged_size_class_set_sha256"] = "0" * 64
        receipt["worker_candidate_cell_receipt_sha256"] = _sha(
            {
                key: value
                for key, value in receipt.items()
                if key != "worker_candidate_cell_receipt_sha256"
            }
        )
        _rewrite_manifest_and_checksums(root, manifest)
    else:
        ledger_path = root / "serialized-object-ledgers.jsonl"
        ledgers = [json.loads(line) for line in ledger_path.read_bytes().splitlines()]
        if mutation == "controller-class":
            target_row = next(
                row
                for ledger in ledgers
                for row in ledger["categories"]
                if row["controller_charged_size_class"] is not None
            )
            target_row["controller_charged_size_class"]["day2_outer_archive_sha256"] = "f" * 64
            target_ledger = next(ledger for ledger in ledgers if target_row in ledger["categories"])
        elif mutation == "non-f1m-controller-authority":
            target_ledger = ledgers[0]
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["category"]
                not in worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
            )
            target_row["charge_authority"] = "controller-anchored-day2-size-class"
        elif mutation in {
            "combined-key-class-root",
            "combined-key-class-size",
        }:
            target_ledger = ledgers[0]
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["category"] == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
            )
            if mutation == "combined-key-class-root":
                target_row[
                    "controller_expected_combined_evaluation_key_size_class_sha256"
                ] = "f" * 64
            else:
                target_row["controller_expected_serialized_byte_count"] += 1
        elif mutation in {"metadata-class-root", "metadata-class-size"}:
            target_ledger = ledgers[0]
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["controller_expected_serialized_byte_count"] is not None
            )
            if mutation == "metadata-class-root":
                target_row[
                    "controller_expected_fixed_width_size_class_sha256"
                ] = "f" * 64
            else:
                target_row["controller_expected_serialized_byte_count"] += 1
        elif mutation == "f1m-worker-quantity":
            target_ledger = ledgers[0]
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["category"]
                in worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
            )
            target_row["protocol_object_count"] = 1
        elif mutation == "null-class-charge":
            target_ledger = next(
                ledger
                for ledger in ledgers
                if any(
                    row["category"]
                    in worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
                    and row["controller_charged_size_class"] is None
                    for row in ledger["categories"]
                )
            )
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["category"]
                in worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
                and row["controller_charged_size_class"] is None
            )
            target_row["controller_charged_byte_count"] = 1
        elif mutation in {
            "nonpositive-multiplicity",
            "materialized-controller-object",
        }:
            target_ledger = next(
                ledger
                for ledger in ledgers
                if any(
                    row["controller_charged_size_class"] is not None for row in ledger["categories"]
                )
            )
            target_row = next(
                row
                for row in target_ledger["categories"]
                if row["controller_charged_size_class"] is not None
            )
            controller_class = target_row["controller_charged_size_class"]
            if mutation == "nonpositive-multiplicity":
                controller_class["multiplicity"] = 0
                controller_class["charged_byte_count"] = 0
                target_row["controller_charged_byte_count"] = 0
            else:
                controller_class["materialized_cryptographic_object_count"] = 1
        else:
            target_ledger = ledgers[0]
            if mutation == "inclusive-total":
                target_ledger["query_serialized_bytes_including_controller_charge"] += 1
            else:
                target_ledger["schema_version"] = (
                    "dynamic-cssc-publication-day1b-serialized-protocol-object-ledger-v1"
                )
        target_ledger["serialization_ledger_sha256"] = _sha(
            {
                key: value
                for key, value in target_ledger.items()
                if key != "serialization_ledger_sha256"
            }
        )
        _rewrite_serialization_ledgers(root, ledgers)

    with pytest.raises(ValueError, match=message):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


def test_manifest_and_fragment_variants_are_mutually_exclusive_on_reparse(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    with pytest.raises(ValueError, match="schemas cross artifact variants"):
        verify_existing_directory(
            bundle.output_dir,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._PRODUCTION_ARTIFACT_VARIANT_TOKEN,
            ),
        )

    projected = tmp_path / "production-projection"
    shutil.copytree(bundle.output_dir, projected)
    _rewrite_as_production_variant(projected)
    verified = verify_existing_directory(
        projected,
        verifier=lambda view: day1b_module._verify_day1b_unit_view(
            view,
            artifact_variant_token=day1b_module._PRODUCTION_ARTIFACT_VARIANT_TOKEN,
        ),
    )
    assert verified.artifact_variant_kind == "production"
    with pytest.raises(ValueError, match="schemas cross artifact variants"):
        verify_existing_directory(
            projected,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


@pytest.mark.parametrize("destination_kind", ("file", "directory", "symlink"))
def test_shared_day1b_install_never_replaces_an_existing_destination(
    tmp_path: Path,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    destination_kind: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    shutil.copytree(bundle.output_dir, staging)
    if destination_kind == "file":
        output.write_bytes(b"foreign-file\n")
    elif destination_kind == "directory":
        output.mkdir()
        (output / "foreign.txt").write_bytes(b"foreign-directory\n")
    else:
        target = tmp_path / "foreign-target"
        target.write_bytes(b"foreign-symlink-target\n")
        output.symlink_to(target)
    before = output.lstat()
    observed = staging.stat()

    with pytest.raises(PublicationArtifactInstallError, match="already exists"):
        day1b_module._install_verified_day1b_staging(
            staging=staging,
            staging_identity=(observed.st_dev, observed.st_ino),
            output_dir=output,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            expected_verification=_fixture_verification(bundle),
        )

    after = output.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )
    assert not staging.exists()
    assert any(".retained-staging-" in path.name for path in tmp_path.iterdir())


@pytest.mark.parametrize(
    "mutation",
    ("extra-member", "member-replacement", "same-size", "rehash-splice"),
)
def test_shared_day1b_install_quarantines_the_whole_mutated_staging_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    mutation: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    shutil.copytree(bundle.output_dir, staging)
    expected = _fixture_verification(bundle)
    observed = staging.stat()
    real_install = day1b_module.install_verified_directory

    def mutate_then_install(*args: object, **kwargs: object) -> object:
        if mutation == "extra-member":
            (staging / "foreign-extra.txt").write_bytes(b"foreign-extra\n")
        elif mutation == "member-replacement":
            member = staging / "publication-heldout-fragment.json"
            member.rename(staging / "owned-original-fragment.json")
            member.write_bytes(b"x" * len(bundle.heldout_fragment_path.read_bytes()))
        elif mutation == "same-size":
            member = staging / "publication-day1b-unit-manifest.json"
            value = bytearray(member.read_bytes())
            value[len(value) // 2] ^= 1
            member.write_bytes(bytes(value))
        else:
            manifest_path = staging / "publication-day1b-unit-manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["trace_source"]["git_sha"] = "f" * 40
            _rewrite_manifest_and_checksums(staging, manifest)
        return real_install(*args, **kwargs)

    monkeypatch.setattr(day1b_module, "install_verified_directory", mutate_then_install)
    with pytest.raises(PublicationArtifactInstallError):
        day1b_module._install_verified_day1b_staging(
            staging=staging,
            staging_identity=(observed.st_dev, observed.st_ino),
            output_dir=output,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            expected_verification=expected,
        )

    assert not output.exists()
    retained = [path for path in tmp_path.iterdir() if ".retained-staging-" in path.name]
    assert len(retained) == 1
    retained_names = {path.name for path in retained[0].iterdir()}
    if mutation == "extra-member":
        assert "foreign-extra.txt" in retained_names
    elif mutation == "member-replacement":
        assert "owned-original-fragment.json" in retained_names


def test_shared_day1b_install_preserves_a_same_name_foreign_staging_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    staging = tmp_path / "staging"
    displaced_owned = tmp_path / "displaced-owned-staging"
    output = tmp_path / "output"
    shutil.copytree(bundle.output_dir, staging)
    expected = _fixture_verification(bundle)
    observed = staging.stat()
    real_install = day1b_module.install_verified_directory

    def replace_root_then_install(*args: object, **kwargs: object) -> object:
        staging.rename(displaced_owned)
        staging.mkdir()
        (staging / "foreign.txt").write_bytes(b"foreign-root\n")
        return real_install(*args, **kwargs)

    monkeypatch.setattr(day1b_module, "install_verified_directory", replace_root_then_install)
    with pytest.raises(PublicationArtifactInstallError):
        day1b_module._install_verified_day1b_staging(
            staging=staging,
            staging_identity=(observed.st_dev, observed.st_ino),
            output_dir=output,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            expected_verification=expected,
        )

    assert (staging / "foreign.txt").read_bytes() == b"foreign-root\n"
    assert displaced_owned.is_dir()
    assert not output.exists()


def test_shared_day1b_install_rejects_a_replaced_staging_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    live_parent = tmp_path / "live-parent"
    live_parent.mkdir()
    staging = live_parent / "staging"
    output = live_parent / "output"
    displaced_parent = tmp_path / "displaced-parent"
    shutil.copytree(bundle.output_dir, staging)
    expected = _fixture_verification(bundle)
    observed = staging.stat()
    real_install = day1b_module.install_verified_directory

    def replace_parent_then_install(*args: object, **kwargs: object) -> object:
        live_parent.rename(displaced_parent)
        live_parent.mkdir()
        (live_parent / "foreign.txt").write_bytes(b"foreign-parent\n")
        return real_install(*args, **kwargs)

    monkeypatch.setattr(day1b_module, "install_verified_directory", replace_parent_then_install)
    with pytest.raises(PublicationArtifactInstallError):
        day1b_module._install_verified_day1b_staging(
            staging=staging,
            staging_identity=(observed.st_dev, observed.st_ino),
            output_dir=output,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            expected_verification=expected,
        )

    assert (live_parent / "foreign.txt").read_bytes() == b"foreign-parent\n"
    assert (displaced_parent / "staging").is_dir()
    assert not output.exists()


def test_renderer_never_writes_into_a_same_name_foreign_staging_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    output = tmp_path / "unit"
    detached = tmp_path / "detached-owned-staging"
    foreign_root: Path | None = None
    real_write = day1b_module._write_new_file_at

    def swap_before_first_write(
        directory_fd: int,
        name: str,
        content: bytes,
    ) -> tuple[str, int]:
        nonlocal foreign_root
        if foreign_root is None:
            staging = next(
                path for path in tmp_path.iterdir() if ".publication-day1b-staging-" in path.name
            )
            staging.rename(detached)
            staging.mkdir()
            foreign_root = staging
        return real_write(directory_fd, name, content)

    monkeypatch.setattr(day1b_module, "_write_new_file_at", swap_before_first_write)
    with pytest.raises(PublicationArtifactInstallError):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert foreign_root is not None
    assert list(foreign_root.iterdir()) == []
    assert detached.is_dir()
    assert {path.name for path in detached.iterdir()} == {
        "SHA256SUMS",
        "accepted-event-schedules.jsonl",
        "publication-day1b-unit-manifest.json",
        "publication-heldout-fragment.json",
        "serialized-object-ledgers.jsonl",
        "serialized-object-receipts.jsonl",
    }
    assert not output.exists()


@pytest.mark.parametrize("failure_point", ("pre-verifier", "post-verifier", "final-tree"))
def test_shared_day1b_install_failure_points_never_publish_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
    failure_point: str,
) -> None:
    bundle, _executor = _complete_unit_fixture
    expected = _fixture_verification(bundle)
    staging = tmp_path / "staging"
    output = tmp_path / "output"
    shutil.copytree(bundle.output_dir, staging)
    observed = staging.stat()

    if failure_point in {"pre-verifier", "post-verifier"}:
        real_verify = day1b_module._verify_day1b_unit_view
        calls = 0

        def fail_selected_verifier(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == (1 if failure_point == "pre-verifier" else 2):
                raise RuntimeError(f"injected {failure_point}")
            return real_verify(*args, **kwargs)

        monkeypatch.setattr(day1b_module, "_verify_day1b_unit_view", fail_selected_verifier)
    else:
        real_revalidate = day1b_module.PublicationArtifactDirectory._revalidate
        calls = 0

        def fail_final_tree(*args: object, **kwargs: object) -> object:
            nonlocal calls
            calls += 1
            if calls == 5:
                raise RuntimeError("injected final tree revalidation")
            return real_revalidate(*args, **kwargs)

        monkeypatch.setattr(
            day1b_module.PublicationArtifactDirectory,
            "_revalidate",
            fail_final_tree,
        )

    with pytest.raises((PublicationArtifactInstallError, RuntimeError)):
        day1b_module._install_verified_day1b_staging(
            staging=staging,
            staging_identity=(observed.st_dev, observed.st_ino),
            output_dir=output,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            expected_verification=expected,
        )

    assert not output.exists()
    retained = [
        path
        for path in tmp_path.iterdir()
        if ".retained-staging-" in path.name or ".rejected-staging-" in path.name
    ]
    assert len(retained) == 1
    assert {path.name for path in retained[0].iterdir()} == {
        "SHA256SUMS",
        "accepted-event-schedules.jsonl",
        "publication-day1b-unit-manifest.json",
        "publication-heldout-fragment.json",
        "serialized-object-ledgers.jsonl",
        "serialized-object-receipts.jsonl",
    }


def test_day1b_descriptor_read_rejects_same_inode_same_size_aba_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _complete_unit_fixture: tuple[PublicationDay1BUnitBundle, _StreamingExecutor],
) -> None:
    bundle, _executor = _complete_unit_fixture
    root = tmp_path / "aba"
    shutil.copytree(bundle.output_dir, root)
    manifest_path = root / "publication-day1b-unit-manifest.json"
    original = manifest_path.read_bytes()
    alternate = bytearray(original)
    alternate[len(alternate) // 2] ^= 1
    real_read = day1b_module.PublicationArtifactDirectory.read_regular
    injected = False

    def read_with_aba(
        view: object,
        relative_path: str,
    ) -> bytes:
        nonlocal injected
        if relative_path == "publication-day1b-unit-manifest.json" and not injected:
            injected = True
            manifest_path.write_bytes(bytes(alternate))
            try:
                return real_read(view, relative_path)
            finally:
                manifest_path.write_bytes(original)
        return real_read(view, relative_path)

    monkeypatch.setattr(
        day1b_module.PublicationArtifactDirectory,
        "read_regular",
        read_with_aba,
    )
    with pytest.raises(PublicationArtifactInstallError, match="snapshotted content"):
        verify_existing_directory(
            root,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )

    assert manifest_path.read_bytes() == original


@pytest.mark.parametrize("invalid_token", (False, "production", object()))
def test_core_rejects_noncapability_artifact_variant_before_worker_or_output(
    tmp_path: Path,
    invalid_token: object,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    output_dir = tmp_path / "unit"

    with pytest.raises(TypeError, match="artifact variant.*capability"):
        day1b_module._produce_publication_day1b_unit(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            size_authority=_size_authority(),
            execution_adapter=executor,
            repository_root=Path(__file__).resolve().parents[1],
            artifact_variant_token=invalid_token,
        )

    assert executor.calls == []
    assert not output_dir.exists()


def test_artifact_variants_reject_crossed_source_and_trace_provenance_before_worker(
    tmp_path: Path,
) -> None:
    cases = (
        (
            _trace(),
            replace(_source(), source_attestation="repository-clean-head"),
            day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            "fixture artifact variant",
        ),
        (
            _trace(),
            replace(_source(), source_attestation="repository-clean-head"),
            day1b_module._PRODUCTION_ARTIFACT_VARIANT_TOKEN,
            "production artifact variant",
        ),
    )
    for index, (trace, source, token, message) in enumerate(cases):
        executor = _StreamingExecutor(tmp_path / f"controlled-scratch-{index}")
        output_dir = tmp_path / f"unit-{index}"
        with pytest.raises(ValueError, match=message):
            day1b_module._produce_publication_day1b_unit(
                trace=trace,
                output_dir=output_dir,
                source_attestation=source,
                candidate_catalog=_catalog(),
                resource_policy=_resource_policy(),
                size_authority=_size_authority(),
                execution_adapter=executor,
                repository_root=Path(__file__).resolve().parents[1],
                artifact_variant_token=token,
            )
        assert executor.calls == []
        assert not output_dir.exists()


def test_t2_realized_set_cardinality_is_separate_from_stats_update_denominator() -> None:
    source = _source()
    trace = replace(
        _trace(),
        semantics="T2",
        accepted_group_count=1_000,
    )
    program = _program(Fraction(1), total=1_000, t2_cardinality=True)
    audit = day1b_module._complete_cell_audit(program, Fraction("0.1"))
    trace_unit = day1b_module._trace_unit_document(trace, source)
    cell = day1b_module._cell_document(
        trace_unit,
        trace,
        source,
        program,
        Fraction("0.1"),
        audit,
    )
    phases = {row["phase"]: row for row in audit.phase_receipts}

    assert cell["tuning_update_count"] == 300
    assert cell["heldout_update_count"] == 600
    assert phases["tuning"]["realized_set_count"] == 600

    assert phases["tuning"]["accepted_event_group_count"] == 300
    assert phases["heldout"]["realized_set_count"] == 600
    assert phases["heldout"]["accepted_event_group_count"] == 600
    catalog = _catalog()
    candidate = catalog.candidates[0]
    resource_policy = _resource_policy()
    summary_trace = _trace()
    summary_freshness = Fraction(FRESHNESS_VALUES[0])
    summary_program = summary_trace.compile_schedule(Fraction(RHO_VALUES[0]))
    summary_audit = day1b_module._complete_cell_audit(
        summary_program,
        summary_freshness,
    )
    summary_cell = day1b_module._cell_document(
        day1b_module._trace_unit_document(summary_trace, source),
        summary_trace,
        source,
        summary_program,
        summary_freshness,
        summary_audit,
    )
    controller_replay = day1b_module._replay_f1m_controller_for_candidate_cell(
        source=source,
        trace=summary_trace,
        program=summary_program,
        freshness=summary_freshness,
        cell=summary_cell,
        cell_ordinal=0,
        candidate=candidate,
        terminal_registration_sha256=day1b_module._digest(asdict(catalog.registration)),
        candidate_catalog_sha256="e" * 64,
        resource_policy_sha256="f" * 64,
        lineage=day1b_module._test_only_f1m_execution_lineage(
            source=source,
            trace=summary_trace,
        ),
        size_authority=_size_authority(),
        resource_policy=resource_policy,
        expected_complete_audit=summary_audit,
    )
    f1m_controller_summary = controller_replay.f1m_summary
    failed_measurement = Day1BWorkerPhaseReceipt(
        phase="tuning-prefix",
        retained_measurement=True,
        outcome="failed",
        failure_code="candidate-execution-failed",
        update_primitive_counts=None,
        query_primitive_counts=None,
        serialized_categories=None,
        worker_declared_phase_audit=None,
    )
    tuning_record, _tuning_ledger = day1b_module._physical_record_and_ledger(
        failed_measurement,
        trace=trace,
        cell=cell,
        phase="tuning-prefix",
        candidate_id=REFERENCE_CANDIDATE_IDS[0],
        candidate_role="reference",
        selection_source="fixed-reference-tuning-prefix",
        worker_object_receipt_spool_sha256="f" * 64,
        f1m_controller_summary=f1m_controller_summary,
        controller_expected_counts=controller_replay.expected_counts,
    )
    heldout_record, _heldout_ledger = day1b_module._physical_record_and_ledger(
        replace(failed_measurement, phase="held-out"),
        trace=trace,
        cell=cell,
        phase="held-out",
        candidate_id=REFERENCE_CANDIDATE_IDS[0],
        candidate_role="reference",
        selection_source="fixed-reference-held-out",
        worker_object_receipt_spool_sha256="f" * 64,
        f1m_controller_summary=f1m_controller_summary,
        controller_expected_counts=controller_replay.expected_counts,
    )
    assert tuning_record["update_count"] == 300
    assert heldout_record["update_count"] == 600


def test_production_f1m_replay_derives_zero_query_coverage_and_closed_context() -> None:
    trace = _trace()
    source = _source()
    freshness = Fraction(FRESHNESS_VALUES[0])
    program = trace.compile_schedule(Fraction(RHO_VALUES[0]))
    audit = day1b_module._complete_cell_audit(program, freshness)
    cell = day1b_module._cell_document(
        day1b_module._trace_unit_document(trace, source),
        trace,
        source,
        program,
        freshness,
        audit,
    )
    catalog = _catalog()
    candidate = catalog.candidates[0]
    resource_policy = _resource_policy()
    size_authority = _size_authority()

    controller_replay = day1b_module._replay_f1m_controller_for_candidate_cell(
        source=source,
        trace=trace,
        program=program,
        freshness=freshness,
        cell=cell,
        cell_ordinal=0,
        candidate=candidate,
        terminal_registration_sha256=day1b_module._digest(asdict(catalog.registration)),
        candidate_catalog_sha256="e" * 64,
        resource_policy_sha256="f" * 64,
        lineage=day1b_module._test_only_f1m_execution_lineage(
            source=source,
            trace=trace,
        ),
        size_authority=size_authority,
        resource_policy=resource_policy,
        expected_complete_audit=audit,
    )
    summary = controller_replay.f1m_summary

    assert summary.context.candidate_id == candidate.candidate_id
    assert summary.context.candidate_policy_sha256 == (
        day1b_module._candidate_policy_digest(candidate)
    )
    assert summary.context.complete_window_count == 3
    assert summary.context.query_window_count == 2
    assert summary.context.zero_query_window_count == 1
    assert summary.context.phase_window_counts == (1, 1, 1)
    assert summary.context.complete_phase_audit_root_sha256 == (
        day1b_module._f1m_complete_schedule_audit(audit).complete_phase_audit_root_sha256
    )
    seed = day1b_module._candidate_worker_contract_seed(
        trace=trace,
        program=program,
        freshness=freshness,
        candidate=candidate,
        cell_binding_sha256=str(cell["cell_binding_sha256"]),
        candidate_catalog_sha256="e" * 64,
        resource_policy=resource_policy,
        resource_policy_sha256="f" * 64,
        size_authority=size_authority,
        f1m_controller_summary=summary,
        controller_expected_counts=controller_replay.expected_counts,
    )
    f1m_categories = set(
        worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
    )
    expected_serialized_count = sum(
        int(count > 0)
        for phase in controller_replay.expected_counts.phases
        for (category, _transaction), count in zip(
            controller_replay.expected_counts.serialized_categories,
            phase.worker_streamed_protocol_object_counts,
            strict=True,
        )
        if category not in f1m_categories
    )
    contract = seed.bind(
        expected_f1m_size_class_set_sha256="1" * 64,
        expected_f1m_size_class_count=0,
        expected_serialized_equivalence_class_count=expected_serialized_count,
        expected_f1m_cardinality_derivation_root_sha256="2" * 64,
    )
    assert contract.f1m_controller_context_sha256 == summary.context.context_sha256
    assert contract.f1m_route_coverage_sha256 == summary.route_coverage_sha256
    assert contract.f1m_charged_size_class_set_sha256 == (summary.charged_size_class_set_sha256)


@pytest.mark.parametrize(
    "tamper",
    (
        "trace-manifest",
        "candidate-catalog",
        "resource-policy",
        "object-cap",
        "payload-cap",
    ),
)
def test_worker_seed_rejects_controller_lineage_or_resource_substitution(
    tamper: str,
) -> None:
    trace = _trace()
    source = _source()
    freshness = Fraction(FRESHNESS_VALUES[0])
    program = trace.compile_schedule(Fraction(RHO_VALUES[0]))
    audit = day1b_module._complete_cell_audit(program, freshness)
    cell = day1b_module._cell_document(
        day1b_module._trace_unit_document(trace, source),
        trace,
        source,
        program,
        freshness,
        audit,
    )
    catalog = _catalog()
    candidate = catalog.candidates[0]
    resource_policy = _resource_policy()
    size_authority = _size_authority()
    controller_replay = day1b_module._replay_f1m_controller_for_candidate_cell(
        source=source,
        trace=trace,
        program=program,
        freshness=freshness,
        cell=cell,
        cell_ordinal=0,
        candidate=candidate,
        terminal_registration_sha256=day1b_module._digest(asdict(catalog.registration)),
        candidate_catalog_sha256="e" * 64,
        resource_policy_sha256="f" * 64,
        lineage=day1b_module._test_only_f1m_execution_lineage(
            source=source,
            trace=trace,
        ),
        size_authority=size_authority,
        resource_policy=resource_policy,
        expected_complete_audit=audit,
    )
    summary = controller_replay.f1m_summary
    context_fields = {
        "trace-manifest": "trace_manifest_sha256",
        "candidate-catalog": "candidate_catalog_sha256",
        "resource-policy": "resource_policy_sha256",
    }
    if tamper in context_fields:
        changed_context = replace(
            summary.context,
            **{context_fields[tamper]: "0" * 64},
        )
        summary = replace(
            summary,
            context=changed_context,
            route_coverage=replace(
                summary.route_coverage,
                controller_context_sha256=changed_context.context_sha256,
            ),
        )
    elif tamper == "object-cap":
        summary = replace(
            summary,
            serialized_object_bytes_maximum=(summary.serialized_object_bytes_maximum + 1),
        )
    else:
        summary = replace(
            summary,
            serialized_payload_bytes_per_cell_maximum=(
                summary.serialized_payload_bytes_per_cell_maximum + 1
            ),
        )

    with pytest.raises(
        worker_protocol.Day1BWorkerProtocolError,
        match="do not bind one candidate cell",
    ):
        day1b_module._candidate_worker_contract_seed(
            trace=trace,
            program=program,
            freshness=freshness,
            candidate=candidate,
            cell_binding_sha256=str(cell["cell_binding_sha256"]),
            candidate_catalog_sha256="e" * 64,
            resource_policy=resource_policy,
            resource_policy_sha256="f" * 64,
            size_authority=size_authority,
            f1m_controller_summary=summary,
            controller_expected_counts=controller_replay.expected_counts,
        )


def test_f1m_complete_audit_rejects_phase_name_position_substitution() -> None:
    audit = day1b_module._complete_cell_audit(
        _program(Fraction(RHO_VALUES[0])),
        Fraction(FRESHNESS_VALUES[0]),
    )
    substituted = day1b_module._CellAudit(
        (
            audit.phase_audits[0],
            replace(audit.phase_audits[1], phase="heldout"),
            replace(audit.phase_audits[2], phase="tuning"),
        )
    )

    with pytest.raises(ValueError, match="exact three phases"):
        day1b_module._f1m_complete_schedule_audit(substituted)


def test_private_core_rejects_a_query_vector_splice_before_output(tmp_path: Path) -> None:
    trace = replace(_trace(), query_vector=(1, 1, -1))
    output_dir = tmp_path / "unit"

    with pytest.raises(ValueError, match="query vector.*artifact"):
        _produce_publication_day1b_unit_for_test(
            trace=trace,
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=_StreamingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_controller_terminal_outcomes_are_null_records_and_later_candidates_continue(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.terminal_failure_codes = {
        0: "wall-clock-limit-exceeded",
        1: "candidate-infeasible",
        2: "candidate-execution-failed",
        3: "candidate-missing-result",
    }
    executor.observation_overrides = {0: {"elapsed_ns": 600_000_000_001}}
    output_dir = tmp_path / "unit"
    bundle = _produce_publication_day1b_unit_for_test(
        trace=_trace(),
        output_dir=output_dir,
        source_attestation=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    manifest = json.loads(bundle.manifest_path.read_bytes())
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
    ledgers = [
        json.loads(line) for line in bundle.serialization_ledger_path.read_bytes().splitlines()
    ]
    first_cell = fragment["cell_bindings"][0]["cell_binding_sha256"]
    first_cell_records = [
        record for record in fragment["records"] if record["cell_binding_sha256"] == first_cell
    ]
    expected_outcomes = {
        FIXED_CANDIDATE_IDS[0]: "timeout",
        FIXED_CANDIDATE_IDS[1]: "infeasible",
        FIXED_CANDIDATE_IDS[2]: "failed",
        FIXED_CANDIDATE_IDS[3]: "missing",
    }
    for candidate_id, outcome in expected_outcomes.items():
        matching = [
            record for record in first_cell_records if record["candidate_id"] == candidate_id
        ]
        assert len(matching) == (1 if candidate_id == ABLATION_CANDIDATE_ID else 2)
        assert {record["outcome"] for record in matching} == {outcome}
        assert all(
            record["update_primitive_counts"] is None
            and record["query_primitive_counts"] is None
            and record["update_serialized_bytes"] is None
            and record["query_serialized_bytes"] is None
            for record in matching
        )
        matching_ledgers = [
            ledger
            for record, ledger in zip(fragment["records"], ledgers, strict=True)
            if record["cell_binding_sha256"] == first_cell
            and record["candidate_id"] == candidate_id
        ]
        receipt = next(
            candidate_receipt
            for candidate_receipt in manifest["cell_execution_receipts"][0][
                "candidate_cell_receipts"
            ]
            if candidate_receipt["candidate"]["candidate_id"] == candidate_id
        )
        assert _sha(receipt["input_binding_document"]) == receipt["input_binding_sha256"]
        assert receipt["input_binding_document"]["f1m_controller_context_document"]
        assert receipt["input_binding_document"]["f1m_route_coverage_document"]
        assert receipt["input_binding_document"]["day2_outer_archive_sha256"] == (
            manifest["serialized_object_size_authority"]["day2_outer_archive_sha256"]
        )
        assert len(matching_ledgers) == len(matching)
        assert all(
            ledger["categories"] is None
            and ledger["byte_derivation"] is None
            and ledger["update_serialized_bytes"] is None
            and ledger["query_serialized_bytes"] is None
            and ledger["controller_charged_query_bytes"] is None
            and ledger["query_serialized_bytes_including_controller_charge"] is None
            and ledger["one_time_serialized_bytes_excluded_from_primary_C"] is None
            and ledger["f1m_controller_context_sha256"] == receipt["f1m_controller_context_sha256"]
            and ledger["f1m_route_coverage_sha256"] == receipt["f1m_route_coverage_sha256"]
            and ledger["f1m_charged_size_class_set_sha256"]
            == receipt["f1m_charged_size_class_set_sha256"]
            for ledger in matching_ledgers
        )
    assert len(executor.calls) == 252
    assert first_cell_records[-1]["outcome"] == "complete"


def test_mixed_retained_phase_outcome_keeps_complete_charge_and_nulls_failure(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.worker_failed_phases = {0: "held-out"}
    bundle = _produce_publication_day1b_unit_for_test(
        trace=_trace(),
        output_dir=tmp_path / "unit",
        source_attestation=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
    ledgers = [
        json.loads(line) for line in bundle.serialization_ledger_path.read_bytes().splitlines()
    ]
    first_cell = fragment["cell_bindings"][0]["cell_binding_sha256"]
    candidate_id = FIXED_CANDIDATE_IDS[0]
    matching = [
        (record, ledger)
        for record, ledger in zip(fragment["records"], ledgers, strict=True)
        if record["cell_binding_sha256"] == first_cell and record["candidate_id"] == candidate_id
    ]

    assert [record["outcome"] for record, _ledger in matching] == [
        "complete",
        "failed",
    ]
    complete_ledger = matching[0][1]
    failed_ledger = matching[1][1]
    assert complete_ledger["categories"] is not None
    assert complete_ledger["controller_charged_query_bytes"] is not None
    assert failed_ledger["categories"] is None
    assert failed_ledger["byte_derivation"] is None
    assert failed_ledger["controller_charged_query_bytes"] is None
    assert failed_ledger["query_serialized_bytes_including_controller_charge"] is None


@pytest.mark.parametrize("outcome_path", ("controller-terminal", "mixed-failure"))
def test_verifier_rejects_self_consistent_incomplete_formal_f1m_worker_count_splice(
    tmp_path: Path,
    outcome_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_derive = day1b_module.derive_day1b_controller_expected_counts
    original_formal_check = day1b_module.require_formal_day1b_f1m_worker_zero

    def derive_materialized_incomplete_phase(
        **kwargs: object,
    ) -> expected_counts_module.Day1BControllerExpectedCounts:
        expected = original_derive(**kwargs)
        category_names = tuple(
            category for category, _transaction in expected.serialized_categories
        )
        f1m_indices = tuple(
            category_names.index(category)
            for category in (
                worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
            )
        )
        phases = []
        for phase in expected.phases:
            if phase.phase != "held-out":
                phases.append(phase)
                continue
            worker_counts = list(phase.worker_streamed_protocol_object_counts)
            for category_index in f1m_indices:
                logical_count = phase.logical_protocol_object_counts[category_index]
                if logical_count > 0:
                    worker_counts[category_index] = logical_count
                    break
            phases.append(
                replace(
                    phase,
                    worker_streamed_protocol_object_counts=tuple(worker_counts),
                )
            )
        return replace(expected, phases=tuple(phases))

    monkeypatch.setattr(
        day1b_module,
        "derive_day1b_controller_expected_counts",
        derive_materialized_incomplete_phase,
    )
    monkeypatch.setattr(
        day1b_module,
        "require_formal_day1b_f1m_worker_zero",
        lambda _expected: None,
    )
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    candidate_cell_count = (
        len(FRESHNESS_VALUES) * len(RHO_VALUES) * len(FIXED_CANDIDATE_IDS)
    )
    if outcome_path == "controller-terminal":
        executor.terminal_failure_codes = {
            index: "candidate-execution-failed"
            for index in range(candidate_cell_count)
        }
    else:
        executor.worker_failed_phases = {
            index: "held-out" for index in range(candidate_cell_count)
        }
    bundle = _produce_publication_day1b_unit_for_test(
        trace=_trace(),
        output_dir=tmp_path / "self-consistent-malicious-unit",
        source_attestation=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    bypassed_verification = verify_existing_directory(
        bundle.output_dir,
        verifier=lambda view: day1b_module._verify_day1b_unit_view(
            view,
            artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
        ),
    )
    assert bypassed_verification.cardinality == (18, 252, 486, 486)

    manifest = json.loads(bundle.manifest_path.read_bytes())
    receipt = None
    expected_phase = None
    f1m_indices = None
    for cell_receipt in manifest["cell_execution_receipts"]:
        for candidate_receipt in cell_receipt["candidate_cell_receipts"]:
            input_document = candidate_receipt["input_binding_document"]
            expected_document = input_document["controller_expected_counts_document"]
            category_names = tuple(
                item[0] for item in expected_document["serialized_categories"]
            )
            candidate_f1m_indices = tuple(
                category_names.index(category)
                for category in (
                    worker_protocol.DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
                )
            )
            candidate_phase = next(
                phase
                for phase in expected_document["phases"]
                if phase["phase"] == "held-out"
            )
            if any(
                candidate_phase["logical_protocol_object_counts"][index] > 0
                for index in candidate_f1m_indices
            ):
                receipt = candidate_receipt
                expected_phase = candidate_phase
                f1m_indices = candidate_f1m_indices
                break
        if receipt is not None:
            break
    assert receipt is not None
    assert expected_phase is not None
    assert f1m_indices is not None
    if outcome_path == "controller-terminal":
        assert receipt["candidate"]["receipt_origin"] == (
            "controller-terminal-null-projection"
        )
    else:
        held_out_receipt = next(
            phase
            for phase in receipt["candidate"]["phases"]
            if phase["phase"] == "held-out"
        )
        assert held_out_receipt["outcome"] == "failed"
    changed = False
    for category_index in f1m_indices:
        logical_count = expected_phase["logical_protocol_object_counts"][category_index]
        if logical_count > 0:
            assert (
                expected_phase["worker_streamed_protocol_object_counts"][
                    category_index
                ]
                == logical_count
            )
            changed = True
            break
    assert changed, "fixture must expose one positive held-out formal F1-M route count"

    monkeypatch.setattr(
        day1b_module,
        "derive_day1b_controller_expected_counts",
        original_derive,
    )
    monkeypatch.setattr(
        day1b_module,
        "require_formal_day1b_f1m_worker_zero",
        original_formal_check,
    )

    with pytest.raises(
        ValueError,
        match="formal F1-M worker multiplicity must remain zero",
    ):
        verify_existing_directory(
            bundle.output_dir,
            verifier=lambda view: day1b_module._verify_day1b_unit_view(
                view,
                artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
            ),
        )


def test_over_limit_controller_observation_without_matching_terminal_holds_unit(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.observation_overrides = {0: {"elapsed_ns": 600_000_000_001}}
    output_dir = tmp_path / "unit"

    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert not output_dir.exists()


def test_private_core_holds_on_malformed_candidate_launch_without_output(
    tmp_path: Path,
) -> None:
    class MissingLaunchExecutor:
        def execute_candidate_cell(self, **kwargs: object) -> object:
            for _window in kwargs["windows"]:  # type: ignore[union-attr]
                pass
            return object()

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=MissingLaunchExecutor(),
        )

    assert not output_dir.exists()


def test_fixture_adapter_abandons_capability_if_launch_fails_before_return(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    failure = RuntimeError("post-mint pre-return fixture failure")
    executor.post_mint_failure = failure
    output_dir = tmp_path / "unit"
    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert executor.last_minted_invocation is not None
    identifier = id(executor.last_minted_invocation)
    try:
        assert raised.value is failure
        assert identifier not in worker_protocol._ISSUED_INVOCATIONS
        assert not output_dir.exists()
    finally:
        if identifier in worker_protocol._ISSUED_INVOCATIONS:
            worker_protocol.abandon_day1b_worker_invocation(executor.last_minted_invocation)


def test_fixture_adapter_abandons_capability_if_mint_tracking_fails(
    tmp_path: Path,
) -> None:
    failure = RuntimeError("fixture mint tracking failure")
    captured: list[object] = []

    class RejectingMintTrackingExecutor(_StreamingExecutor):
        def __init__(self, controlled_scratch_root: Path) -> None:
            self._reject_mint_tracking = False
            super().__init__(controlled_scratch_root)
            self._reject_mint_tracking = True

        def __setattr__(self, name: str, value: object) -> None:
            if name == "last_minted_invocation" and getattr(
                self,
                "_reject_mint_tracking",
                False,
            ):
                captured.append(value)
                raise failure
            super().__setattr__(name, value)

    executor = RejectingMintTrackingExecutor(tmp_path / "controlled-scratch")
    output_dir = tmp_path / "unit"
    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert len(captured) == 1
    identifier = id(captured[0])
    try:
        assert raised.value is failure
        assert identifier not in worker_protocol._ISSUED_INVOCATIONS
        assert not output_dir.exists()
    finally:
        if identifier in worker_protocol._ISSUED_INVOCATIONS:
            worker_protocol.abandon_day1b_worker_invocation(captured[0])


def test_fixture_adapter_abandons_capability_if_final_bookkeeping_fails(
    tmp_path: Path,
) -> None:
    failure = RuntimeError("fixture call bookkeeping failure")

    class RejectingCalls(list[tuple[Fraction, Fraction, str, int]]):
        def append(self, _value: tuple[Fraction, Fraction, str, int]) -> None:
            raise failure

    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.calls = RejectingCalls()
    output_dir = tmp_path / "unit"
    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert executor.last_minted_invocation is not None
    identifier = id(executor.last_minted_invocation)
    try:
        assert raised.value is failure
        assert identifier not in worker_protocol._ISSUED_INVOCATIONS
        assert executor.calls == []
        assert not output_dir.exists()
    finally:
        if identifier in worker_protocol._ISSUED_INVOCATIONS:
            worker_protocol.abandon_day1b_worker_invocation(executor.last_minted_invocation)


def test_core_abandons_returned_launch_on_unexpected_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    output_dir = tmp_path / "unit"
    original_finish = day1b_module._AuditedWindowStream.finish
    finish_count = 0
    failure = RuntimeError("unexpected post-launch validation failure")

    def fail_third_finish(
        stream: day1b_module._AuditedWindowStream,
    ) -> day1b_module._CellAudit:
        nonlocal finish_count
        finish_count += 1
        if finish_count == 3:
            raise failure
        return original_finish(stream)

    monkeypatch.setattr(day1b_module._AuditedWindowStream, "finish", fail_third_finish)

    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert executor.last_minted_invocation is not None
    identifier = id(executor.last_minted_invocation)
    try:
        assert raised.value is failure
        assert identifier not in worker_protocol._ISSUED_INVOCATIONS
        assert not output_dir.exists()
    finally:
        if identifier in worker_protocol._ISSUED_INVOCATIONS:
            worker_protocol.abandon_day1b_worker_invocation(executor.last_minted_invocation)


def test_private_core_holds_on_retargeted_contract_without_output(tmp_path: Path) -> None:
    class RetargetingExecutor(_StreamingExecutor):
        def execute_candidate_cell(self, **kwargs: object) -> _Day1BWorkerLaunch:
            launch = super().execute_candidate_cell(**kwargs)
            return replace(
                launch,
                contract=replace(launch.contract, query_vector_sha256="f" * 64),
            )

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=RetargetingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_private_core_holds_on_protocol_corruption_without_output(tmp_path: Path) -> None:
    class CorruptingExecutor(_StreamingExecutor):
        def execute_candidate_cell(self, **kwargs: object) -> _Day1BWorkerLaunch:
            launch = super().execute_candidate_cell(**kwargs)
            return replace(launch, frame_chunks=(b"not-a-worker-frame",))

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=CorruptingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_private_core_holds_on_window_batch_subroot_splice(
    tmp_path: Path,
) -> None:
    class SplicingExecutor(_StreamingExecutor):
        def _registry_inputs(
            self,
            seed: _Day1BWorkerContractSeed,
            audits: tuple[Day1BWorkerPhaseAudit, ...],
        ) -> tuple[
            tuple[Day1BF1MWindowCardinality, ...],
            tuple[Day1BF1MWindowBatch, ...],
            tuple[Day1BControllerExpectedF1MObject, ...],
        ]:
            cardinalities, window_batches, expected = super()._registry_inputs(seed, audits)
            if len(self.calls) == 1:
                window_batches = (
                    replace(window_batches[0], size_class_subroot_sha256="f" * 64),
                    *window_batches[1:],
                )
            return cardinalities, window_batches, expected

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=SplicingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_private_core_requires_one_time_key_in_first_retained_phase(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.omit_first_one_time = True
    output_dir = tmp_path / "unit"

    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert not output_dir.exists()


def test_private_core_rejects_tampered_combined_evaluation_key_segment(
    tmp_path: Path,
) -> None:
    class TamperingExecutor(_StreamingExecutor):
        def execute_candidate_cell(self, **kwargs: object) -> _Day1BWorkerLaunch:
            launch = super().execute_candidate_cell(**kwargs)
            rotation_bytes = launch.contract.serialized_rotation_key_inventory_bytes
            eval_mult_bytes = launch.contract.serialized_eval_mult_key_bytes
            assert rotation_bytes is not None and eval_mult_bytes is not None
            key_payload = _combined_evaluation_key_payload(
                rotation_bytes,
                eval_mult_bytes,
            )
            transcript = bytearray(next(iter(launch.frame_chunks)))
            payload_start = transcript.find(key_payload)
            assert payload_start >= 0
            transcript[
                payload_start
                + DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES
            ] ^= 1
            return replace(launch, frame_chunks=(bytes(transcript),))

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_attestation=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=TamperingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_formal_seed_rejects_worker_materialized_f1m_against_controller_zero_preimage(
    tmp_path: Path,
) -> None:
    trace = _trace()
    program = _program(Fraction("0.01"))
    freshness = Fraction("0.1")
    source = _source()
    resource_policy = _resource_policy()
    size_authority = _size_authority()
    catalog = _catalog()
    candidate = catalog.candidates[0]
    audit = day1b_module._complete_cell_audit(program, freshness)
    cell = day1b_module._cell_document(
        day1b_module._trace_unit_document(trace, source),
        trace,
        source,
        program,
        freshness,
        audit,
    )
    controller_replay = day1b_module._replay_f1m_controller_for_candidate_cell(
        source=source,
        trace=trace,
        program=program,
        freshness=freshness,
        cell=cell,
        cell_ordinal=0,
        candidate=candidate,
        terminal_registration_sha256=day1b_module._digest(asdict(catalog.registration)),
        candidate_catalog_sha256="e" * 64,
        resource_policy_sha256="f" * 64,
        lineage=day1b_module._test_only_f1m_execution_lineage(
            source=source,
            trace=trace,
        ),
        size_authority=size_authority,
        resource_policy=resource_policy,
        expected_complete_audit=audit,
        accounting_domain=day1b_module._TEST_DAY1B_ACCOUNTING_DOMAIN,
    )
    f1m_controller_summary = controller_replay.f1m_summary
    seed = day1b_module._candidate_worker_contract_seed(
        trace=trace,
        program=program,
        freshness=freshness,
        candidate=candidate,
        cell_binding_sha256=str(cell["cell_binding_sha256"]),
        candidate_catalog_sha256="e" * 64,
        resource_policy=resource_policy,
        resource_policy_sha256="f" * 64,
        size_authority=size_authority,
        f1m_controller_summary=f1m_controller_summary,
        controller_expected_counts=controller_replay.expected_counts,
    )
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.emit_f1m_routes = True
    launch = executor.execute_candidate_cell(
        windows=program.stream_windows(freshness),
        contract_seed=seed,
    )
    with pytest.raises(
        worker_protocol.Day1BWorkerProtocolError,
        match="protocol-object multiplicities",
    ):
        consume_day1b_worker_frames(
            launch.frame_chunks,
            contract=launch.contract,
            invocation_capability=launch.invocation_capability,
        )
