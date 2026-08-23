from __future__ import annotations

import bz2
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from inspect import signature
from pathlib import Path

import pytest

import dynamic_cssc.day1_registry as registry_module
import dynamic_cssc.publication_day1b as day1b_module
import dynamic_cssc.publication_day1b_worker_protocol as worker_protocol
import dynamic_cssc.publication_statistics as statistics_module
from dynamic_cssc.day1_registry import Day1CandidateCatalog, RegistrationEvidence
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactInstallError,
    verify_existing_directory,
)
from dynamic_cssc.publication_day1b import (
    DAY1B_UNIT_FRAGMENT_SCHEMA,
    DAY1B_UNIT_SCHEMA,
    PublicationDay1BHold,
    PublicationDay1BResourcePolicy,
    PublicationDay1BUnitBundle,
    _Day1BSourceAuthority,
    _Day1BTraceInput,
    _Day1BWorkerContractSeed,
    _Day1BWorkerLaunch,
    _produce_publication_day1b_unit_for_test,
    _PublicationScheduleAdapter,
    _UnitObjectReceiptArchive,
    produce_publication_day1b_unit,
)
from dynamic_cssc.publication_day1b_worker_protocol import (
    DAY1B_WORKER_FRAME_SCHEMA,
    Day1BControllerExpectedF1MObject,
    Day1BF1MBatchTransitionReceipt,
    Day1BF1MBindingReceipt,
    Day1BF1MWindowCardinality,
    Day1BWorkerPhaseAudit,
    Day1BWorkerPhaseReceipt,
    Day1BWorkerProtocolContract,
    _require_test_invocation_issuer,
    _test_only_issue_day1b_worker_invocation,
    _test_only_prepare_day1b_expected_f1m_registry,
    canonical_day1b_expected_f1m_binding_set_sha256,
    canonical_day1b_expected_f1m_route_subroot_sha256,
    canonical_day1b_f1m_cardinality_derivation_root_sha256,
    canonical_day1b_f1m_query_id,
    canonical_day1b_worker_window_audit_bytes,
    claim_day1b_worker_evidence,
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
                    ScheduledNetUpdate(row=0, col=ordinal, before=index, after=index + 1)
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


def _source() -> _Day1BSourceAuthority:
    inventory = {
        "behavior_set_schema_version": "dynamic-cssc-day1b-behavior-set-v1",
        "behavior_set_sha256": "c" * 64,
        "entries": [],
        "role": "day1b",
        "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
        "source_git_sha": "1" * 40,
    }
    return _Day1BSourceAuthority(
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
        serialized_payload_bytes_per_cell_maximum=1_000_000_000,
        worker_frame_count_maximum=200_000,
        controller_registered_scratch_bytes_checkpoint_maximum=100_000_000,
        output_bytes_per_unit=8_000_000_000,
        cells_per_shard=18,
        max_concurrency=1,
        candidate_retry_count=0,
        infrastructure_preemption_whole_shard_rerun_limit=1,
        authority="test-only-outcome-blind-fixed-policy",
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


def _worker_transcript(
    contract: Day1BWorkerProtocolContract,
    audits: tuple[Day1BWorkerPhaseAudit, ...],
    *,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] = (),
    omit_first_one_time: bool = False,
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
        if retained:
            category_counts: list[int] = []
            for category, transaction in contract.serialized_categories:
                f1m_routes = tuple(
                    route
                    for route in expected_f1m_objects
                    if route.phase == phase and route.category == category
                )
                if category in contract.f1m_binding_categories:
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
                            multiplicity=1,
                            f1m_binding=route.f1m_binding.to_document(),
                            payload=f"test-only:{identity}".encode("ascii"),
                        )
                    continue
                report = not (
                    transaction == "one-time"
                    and (phase != candidate.retained_phases[0] or omit_first_one_time)
                )
                category_counts.append(int(report))
                if not report:
                    continue
                identity = (
                    f"{contract.input_binding_sha256}:{candidate.candidate_id}:{phase}:{category}"
                )
                payload = f"test-only:{identity}".encode("ascii")
                emit(
                    "serialized-object",
                    candidate_id=candidate.candidate_id,
                    phase=phase,
                    category=category,
                    object_ordinal=0,
                    multiplicity=(1 if transaction == "one-time" else 2),
                    f1m_binding=None,
                    payload=payload,
                )
        candidate_index = FIXED_CANDIDATE_IDS.index(candidate.candidate_id)
        seed = candidate_index + (1 if phase == "tuning-prefix" else 101)
        emit(
            "phase-result",
            candidate_id=candidate.candidate_id,
            phase=phase,
            outcome="complete",
            failure_code=None,
            retained_measurement=retained,
            update_primitive_counts=(
                [seed + index for index in range(len(PRIMITIVE_NAMES))] if retained else None
            ),
            query_primitive_counts=(
                [seed + 100 + index for index in range(len(PRIMITIVE_NAMES))] if retained else None
            ),
            serialized_category_object_counts=(category_counts if retained else None),
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
        self._ledger_identity_sha256 = hashlib.sha256(
            b"private-day1b-core-fixture-ledger-v1"
        ).hexdigest()
        self._ledger_root_sha256 = hashlib.sha256(
            b"private-day1b-core-fixture-empty-root-v1"
        ).hexdigest()
        self.terminal_failure_codes: dict[int, str] = {}
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
        tuple[Day1BF1MBatchTransitionReceipt, ...],
        tuple[Day1BControllerExpectedF1MObject, ...],
        str,
    ]:
        audit_by_phase = dict(zip(("warmup", "tuning-prefix", "held-out"), audits, strict=True))
        first_query_by_phase: dict[str, int] = {}
        next_query = 0
        for phase in ("warmup", "tuning-prefix", "held-out"):
            first_query_by_phase[phase] = next_query
            next_query += audit_by_phase[phase].realized_query_count

        cardinalities: list[Day1BF1MWindowCardinality] = []
        transitions: list[Day1BF1MBatchTransitionReceipt] = []
        expected_f1m_objects: list[Day1BControllerExpectedF1MObject] = []
        prior_root = self._ledger_root_sha256
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
            for offset in range(audit.realized_query_count):
                global_query_ordinal = first_query + offset
                query_id = canonical_day1b_f1m_query_id(
                    invocation_id=seed.invocation_id,
                    global_query_ordinal=global_query_ordinal,
                )
                commitment_token = hashlib.sha256(
                    f"test-only-batch:{query_id}".encode("ascii")
                ).hexdigest()
                if self.emit_f1m_routes:
                    binding = Day1BF1MBindingReceipt(
                        query_id=query_id,
                        version_id=version_id,
                        output_plan_digest=output_plan_digest,
                        component_id="component-0",
                        output_block_id="block-0",
                        f1m_kind="random-zero-sum",
                        ledger_commitment_token=commitment_token,
                        private_plan_digest=private_plan_digest,
                        execution_binding_digest=execution_binding_digest,
                    )
                    route = Day1BControllerExpectedF1MObject(
                        phase=phase,
                        window_index=window_index,
                        global_query_ordinal=global_query_ordinal,
                        category="query-f1m-random-mask-ciphertexts",
                        object_ordinal=offset,
                        f1m_binding=binding,
                    )
                    phase_routes.append(route)
                    expected_f1m_objects.append(route)
                    query_routes = (route,)
                else:
                    query_routes = ()
                route_root = canonical_day1b_expected_f1m_route_subroot_sha256(query_routes)
                reservation_root = hashlib.sha256(
                    _canonical_bytes(
                        {
                            "random_no_reuse_keys": [
                                list(route.f1m_binding.no_reuse_key) for route in query_routes
                            ],
                            "schema_version": "private-core-fixture-reservation-v1",
                        }
                    )
                ).hexdigest()
                after_reservation = hashlib.sha256(
                    _canonical_bytes(
                        {
                            "prior_root_sha256": prior_root,
                            "reservation_set_root_sha256": reservation_root,
                            "schema_version": "private-core-fixture-reserve-v1",
                        }
                    )
                ).hexdigest()
                after_preparation = hashlib.sha256(
                    _canonical_bytes(
                        {
                            "ledger_commitment_token": commitment_token,
                            "prior_root_sha256": after_reservation,
                            "route_set_root_sha256": route_root,
                            "schema_version": "private-core-fixture-prepare-v1",
                        }
                    )
                ).hexdigest()
                transitions.append(
                    Day1BF1MBatchTransitionReceipt(
                        phase=phase,
                        window_index=window_index,
                        global_query_ordinal=global_query_ordinal,
                        query_id=query_id,
                        version_id=version_id,
                        output_plan_digest=output_plan_digest,
                        private_plan_digest=private_plan_digest,
                        execution_binding_digest=execution_binding_digest,
                        ledger_commitment_token=commitment_token,
                        ledger_identity_sha256=self._ledger_identity_sha256,
                        transition_ordinal=len(transitions),
                        ledger_root_before_sha256=prior_root,
                        reservation_set_root_sha256=reservation_root,
                        ledger_root_after_reservation_sha256=after_reservation,
                        ledger_root_after_preparation_sha256=after_preparation,
                        route_set_root_sha256=route_root,
                        random_reservation_transition_verified=False,
                        prepared_commitment_transition_verified=False,
                    )
                )
                prior_root = after_preparation
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
                    expected_random_route_count=len(phase_routes),
                    expected_dummy_route_count=0,
                    expected_route_subroot_sha256=(
                        canonical_day1b_expected_f1m_route_subroot_sha256(tuple(phase_routes))
                    ),
                )
            )
        return (
            tuple(cardinalities),
            tuple(transitions),
            tuple(expected_f1m_objects),
            prior_root,
        )

    def execute_candidate_cell(
        self,
        *,
        windows: object,
        contract_seed: _Day1BWorkerContractSeed,
    ) -> _Day1BWorkerLaunch:
        assert type(contract_seed) is _Day1BWorkerContractSeed
        audits = _worker_audits(windows)
        (
            cardinalities,
            transitions,
            expected_f1m_objects,
            next_ledger_root,
        ) = self._registry_inputs(contract_seed, audits)
        expected_binding_sha256 = canonical_day1b_expected_f1m_binding_set_sha256(
            expected_f1m_objects
        )
        cardinality_root_sha256 = canonical_day1b_f1m_cardinality_derivation_root_sha256(
            window_cardinalities=cardinalities,
            batch_transitions=transitions,
            expected_routes=expected_f1m_objects,
        )
        expected_serialized_count = (
            13 if contract_seed.candidate.candidate_role == "reference" else 7
        )
        if self.omit_first_one_time:
            expected_serialized_count -= 1
        contract = contract_seed.bind(
            expected_f1m_binding_set_sha256=expected_binding_sha256,
            expected_f1m_binding_count=len(expected_f1m_objects),
            expected_serialized_equivalence_class_count=(
                expected_serialized_count + len(expected_f1m_objects)
            ),
            expected_f1m_cardinality_derivation_root_sha256=(cardinality_root_sha256),
        )
        registry = _test_only_prepare_day1b_expected_f1m_registry(
            contract=contract,
            controller_phase_audits=audits,
            window_cardinalities=iter(cardinalities),
            batch_transitions=iter(transitions),
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
            self._ledger_root_sha256 = next_ledger_root
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
) -> None:
    assert tuple(signature(produce_publication_day1b_unit).parameters) == (
        "trace_bundle_dir",
        "output_dir",
    )
    assert tuple(signature(day1b_module._repository_trace_anchor_authority).parameters) == ()
    with pytest.raises(PublicationDay1BHold, match="central TRACE post-run anchor"):
        day1b_module._repository_trace_anchor_authority()
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    output_dir = tmp_path / "unit"

    with pytest.raises(PublicationDay1BHold, match="DAY1B.*Behavior Set|Behavior Set.*DAY1B"):
        produce_publication_day1b_unit(trace_dir, output_dir)

    assert not output_dir.exists()


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
        source_authority=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    return bundle, executor


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
        "dynamic-cssc-publication-day1b-unit-private-test-fixture-v1"
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
    assert trace_unit["schema_version"] == TRACE_UNIT_SCHEMA
    assert set(trace_unit) == statistics_module._TRACE_UNIT_KEYS
    assert len(cells) == 18
    assert len(records) == 486
    assert len(ledger_lines) == 486
    assert len(object_receipt_lines) == 3_168
    assert len(executor.calls) == 252
    assert all(
        window_count == 3 for _freshness, _rho, _candidate_id, window_count in executor.calls
    )
    assert [candidate_id for _freshness, _rho, candidate_id, _count in executor.calls] == (
        list(FIXED_CANDIDATE_IDS) * 18
    )
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
            manifest["unit_identity"]["dataset_release"] = "valid-alternate-release"
            _rewrite_manifest_and_checksums(staging, manifest)
            alternate = verify_existing_directory(
                staging,
                verifier=lambda view: day1b_module._verify_day1b_unit_view(
                    view,
                    artifact_variant_token=day1b_module._TEST_ARTIFACT_VARIANT_TOKEN,
                ),
            )
            assert alternate != expected
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
            source_authority=_source(),
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
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
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
                source_authority=source,
                candidate_catalog=_catalog(),
                resource_policy=_resource_policy(),
                execution_adapter=executor,
                repository_root=Path(__file__).resolve().parents[1],
                artifact_variant_token=token,
            )
        assert executor.calls == []
        assert not output_dir.exists()


def test_t2_realized_set_cardinality_is_separate_from_stats_update_denominator() -> None:
    trace = replace(
        _trace(),
        semantics="T2",
        accepted_group_count=1_000,
    )
    program = _program(Fraction(1), total=1_000, t2_cardinality=True)
    audit = day1b_module._complete_cell_audit(program, Fraction("0.1"))
    trace_unit = day1b_module._trace_unit_document(trace, _source())
    cell = day1b_module._cell_document(
        trace_unit,
        trace,
        _source(),
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
    )
    assert tuning_record["update_count"] == 300
    assert heldout_record["update_count"] == 600


def test_private_core_rejects_a_query_vector_splice_before_output(tmp_path: Path) -> None:
    trace = replace(_trace(), query_vector=(1, 1, -1))
    output_dir = tmp_path / "unit"

    with pytest.raises(ValueError, match="query vector.*artifact"):
        _produce_publication_day1b_unit_for_test(
            trace=trace,
            output_dir=output_dir,
            source_authority=_source(),
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
        source_authority=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
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
    assert len(executor.calls) == 252
    assert first_cell_records[-1]["outcome"] == "complete"


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
            source_authority=_source(),
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
            source_authority=_source(),
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
            source_authority=_source(),
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
            source_authority=_source(),
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
    prior_ledger_root = executor._ledger_root_sha256
    output_dir = tmp_path / "unit"
    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert executor.last_minted_invocation is not None
    identifier = id(executor.last_minted_invocation)
    try:
        assert raised.value is failure
        assert identifier not in worker_protocol._ISSUED_INVOCATIONS
        assert executor._ledger_root_sha256 == prior_ledger_root
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

    def fail_second_finish(
        stream: day1b_module._AuditedWindowStream,
    ) -> day1b_module._CellAudit:
        nonlocal finish_count
        finish_count += 1
        if finish_count == 2:
            raise failure
        return original_finish(stream)

    monkeypatch.setattr(day1b_module._AuditedWindowStream, "finish", fail_second_finish)

    with pytest.raises(RuntimeError) as raised:
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_authority=_source(),
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
            source_authority=_source(),
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
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=CorruptingExecutor(tmp_path / "controlled-scratch"),
        )

    assert not output_dir.exists()


def test_private_core_holds_on_cross_invocation_ledger_root_splice(
    tmp_path: Path,
) -> None:
    class SplicingExecutor(_StreamingExecutor):
        def execute_candidate_cell(self, **kwargs: object) -> _Day1BWorkerLaunch:
            if len(self.calls) == 1:
                self._ledger_root_sha256 = "f" * 64
            return super().execute_candidate_cell(**kwargs)

    output_dir = tmp_path / "unit"
    with pytest.raises(PublicationDay1BHold, match="candidate-cell worker evidence"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_authority=_source(),
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
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=executor,
        )

    assert not output_dir.exists()


def test_unit_archive_rejects_replay_of_protocol_valid_f1m_evidence(
    tmp_path: Path,
) -> None:
    trace = _trace()
    program = _program(Fraction("0.01"))
    resource_policy = _resource_policy()
    candidate = _catalog().candidates[0]
    seed = day1b_module._candidate_worker_contract_seed(
        trace=trace,
        program=program,
        freshness=Fraction("0.1"),
        candidate=candidate,
        cell_binding_sha256="d" * 64,
        candidate_catalog_sha256="e" * 64,
        resource_policy=resource_policy,
        resource_policy_sha256="f" * 64,
    )
    executor = _StreamingExecutor(tmp_path / "controlled-scratch")
    executor.emit_f1m_routes = True
    launch = executor.execute_candidate_cell(
        windows=program.stream_windows(Fraction("0.1")),
        contract_seed=seed,
    )
    evidence_capability = consume_day1b_worker_frames(
        launch.frame_chunks,
        contract=launch.contract,
        invocation_capability=launch.invocation_capability,
    )
    archive = _UnitObjectReceiptArchive()
    try:
        with claim_day1b_worker_evidence(evidence_capability) as evidence:
            copied = io.BytesIO()
            evidence.copy_object_receipts_to(copied)
            lines = copied.getvalue().splitlines(keepends=True)
            f1m_lines = [
                line for line in lines if b'"category":"query-f1m-random-mask-ciphertexts"' in line
            ]
            assert len(f1m_lines) == 2
            assert all(b'"query_id":"day1b-query-' in line for line in f1m_lines)
            for line in lines:
                archive.write(line)
            with pytest.raises(ValueError, match="ADR-0005 binding was reused"):
                for line in lines:
                    archive.write(line)
    finally:
        archive.close()
