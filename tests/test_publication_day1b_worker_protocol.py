from __future__ import annotations

import gc
import hashlib
import inspect
import io
import json
import os
import sqlite3
import tempfile
import threading
import weakref
from collections.abc import Iterable
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from typing import BinaryIO

import pytest

import dynamic_cssc.publication_day1b_worker_protocol as worker_protocol
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    Day1BF1MCompletePhaseAudit,
    Day1BF1MCompleteScheduleAudit,
    Day1BF1MControllerContext,
    Day1BF1MPhaseBoundary,
    Day1BF1MRouteCoverage,
)
from dynamic_cssc.publication_day1b_worker_protocol import (
    DAY1B_WORKER_EXECUTION_BASIS,
    DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA,
    DAY1B_WORKER_FRAME_SCHEMA,
    DAY1B_WORKER_INPUT_BINDING_SCHEMA,
    DAY1B_WORKER_MAX_HEADER_BYTES,
    DAY1B_WORKER_RECEIPT_SCHEMA,
    DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
    Day1BAnonymousScratchCapability,
    Day1BControllerExpectedF1MObject,
    Day1BExpectedF1MRegistryCapability,
    Day1BExpectedF1MRegistryDescriptor,
    Day1BF1MSizeClass,
    Day1BF1MWindowBatch,
    Day1BF1MWindowCardinality,
    Day1BWorkerCandidateSpec,
    Day1BWorkerEvidenceCapability,
    Day1BWorkerInvocationCapability,
    Day1BWorkerPhaseAudit,
    Day1BWorkerPhaseRange,
    Day1BWorkerProtocolContract,
    Day1BWorkerProtocolError,
    Day1BWorkerResourceLimits,
    _test_only_issue_day1b_anonymous_scratch_capability,
    _test_only_issue_day1b_worker_invocation,
    _test_only_prepare_day1b_expected_f1m_registry,
    abandon_day1b_expected_f1m_registry,
    abandon_day1b_worker_evidence,
    abandon_day1b_worker_invocation,
    canonical_day1b_expected_f1m_size_class_set_sha256,
    canonical_day1b_expected_f1m_size_class_subroot_sha256,
    canonical_day1b_f1m_cardinality_derivation_root_sha256,
    canonical_day1b_worker_window_audit_bytes,
    claim_day1b_worker_evidence,
    consume_day1b_worker_frames,
    describe_day1b_expected_f1m_registry,
)

_CURRENT_CONTROLLED_SCRATCH: Path


@pytest.fixture(autouse=True)
def _controlled_scratch(tmp_path: Path) -> None:
    global _CURRENT_CONTROLLED_SCRATCH
    _CURRENT_CONTROLLED_SCRATCH = tmp_path / "controller-owned-scratch"
    _CURRENT_CONTROLLED_SCRATCH.mkdir()


def _assert_no_live_controlled_scratch() -> None:
    assert not tuple(_CURRENT_CONTROLLED_SCRATCH.iterdir())


def _anonymous_test_file() -> BinaryIO:
    # Ownership is transferred to the fixture capability or explicitly closed.
    return tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115


def _scratch_capability(
    *,
    contract: Day1BWorkerProtocolContract | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
    handles: tuple[BinaryIO, ...] | None = None,
) -> tuple[
    Day1BAnonymousScratchCapability,
    Day1BWorkerProtocolContract,
    tuple[Day1BWorkerPhaseAudit, ...],
]:
    selected_contract = contract or _contract()
    selected_audits = controller_phase_audits or _phase_audits()
    capability = _test_only_issue_day1b_anonymous_scratch_capability(
        contract=selected_contract,
        controller_phase_audits=selected_audits,
        controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
        handles=handles,
    )
    return capability, selected_contract, selected_audits


def _claimed_scratch(
    *,
    contract: Day1BWorkerProtocolContract | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
    handles: tuple[BinaryIO, ...] | None = None,
) -> worker_protocol._ControlledScratch:
    capability, selected_contract, selected_audits = _scratch_capability(
        contract=contract,
        controller_phase_audits=controller_phase_audits,
        handles=handles,
    )
    return worker_protocol._ControlledScratch(
        capability,
        contract=selected_contract,
        controller_phase_audits=selected_audits,
    )


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _frame(sequence: int, kind: str, *, payload: bytes = b"", **fields: object) -> bytes:
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


def _contract(
    *,
    wall_clock_ns: int = 1_000,
    candidate: Day1BWorkerCandidateSpec | None = None,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] | None = None,
    expected_serialized_equivalence_class_count: int | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
) -> Day1BWorkerProtocolContract:
    selected_candidate = candidate or Day1BWorkerCandidateSpec(
        candidate_id="reference-a",
        candidate_role="reference",
        strategy="Packed-COO-Cloud-Segmented-Delta",
        f1m_policy="uniform-random-or-zero",
        candidate_policy_digest="9" * 64,
        retained_phases=("tuning-prefix", "held-out"),
    )
    selected_expected = (
        _expected_f1m_objects(selected_candidate.candidate_id)
        if expected_f1m_objects is None
        else expected_f1m_objects
    )
    selected_audits = controller_phase_audits or _phase_audits()
    window_cardinalities, window_batches = _fixture_registry_inputs(
        selected_expected,
        candidate=selected_candidate,
        controller_phase_audits=selected_audits,
    )
    selected_all_serialized_count = (
        len(selected_expected) + len(selected_candidate.retained_phases) + 1
        if expected_serialized_equivalence_class_count is None and expected_f1m_objects is None
        else (
            len(selected_expected)
            if expected_serialized_equivalence_class_count is None
            else expected_serialized_equivalence_class_count
        )
    )
    phase_names = ("warmup", "tuning-prefix", "held-out")
    complete_schedule_audit = Day1BF1MCompleteScheduleAudit(
        tuple(
            Day1BF1MCompletePhaseAudit(
                phase=phase,
                accepted_group_start=audit.accepted_group_start,
                accepted_group_end=audit.accepted_group_end,
                realized_window_count=audit.realized_window_count,
                realized_set_count=audit.realized_set_count,
                realized_query_count=audit.realized_query_count,
                consumed_window_audit_stream_sha256=(
                    audit.consumed_window_audit_stream_sha256
                ),
            )
            for phase, audit in zip(phase_names, selected_audits, strict=True)
        )
    )
    phase_query_window_counts = tuple(
        audit.realized_window_count if audit.realized_query_count else 0
        for audit in selected_audits
    )
    context = Day1BF1MControllerContext(
        publication_source_git_sha="0" * 40,
        trace_source_git_sha="f" * 40,
        publication_behavior_set_schema_version="test-behavior-set-v1",
        publication_behavior_inventory_sha256="0" * 64,
        terminal_registration_sha256="1" * 64,
        day1_registration_anchor_sha256="2" * 64,
        trace_post_run_anchor_sha256="3" * 64,
        acquisition_bundle_sha256="4" * 64,
        trace_manifest_sha256="1" * 64,
        candidate_catalog_sha256="4" * 64,
        resource_policy_sha256="5" * 64,
        worker_build_identity_sha256="6" * 64,
        worker_runtime_identity_sha256="7" * 64,
        dataset_id="test-dataset",
        dataset_release="test-release",
        semantics="insert-only",
        source_partition=0,
        unit_identity_sha256="8" * 64,
        cell_binding_sha256="9" * 64,
        cell_ordinal=0,
        freshness="0.1",
        rho="1",
        candidate_id=selected_candidate.candidate_id,
        candidate_role=selected_candidate.candidate_role,
        candidate_policy_sha256=selected_candidate.candidate_policy_digest,
        retained_phases=selected_candidate.retained_phases,
        phase_boundaries=tuple(
            Day1BF1MPhaseBoundary(
                phase,
                audit.accepted_group_start,
                audit.accepted_group_end,
            )
            for phase, audit in zip(phase_names, selected_audits, strict=True)
        ),
        event_schedule_sha256="2" * 64,
        query_vector_sha256="3" * 64,
        accepted_group_count=selected_audits[-1].accepted_group_end,
        complete_window_count=complete_schedule_audit.complete_window_count,
        query_window_count=sum(phase_query_window_counts),
        zero_query_window_count=(
            complete_schedule_audit.complete_window_count - sum(phase_query_window_counts)
        ),
        total_query_count=sum(complete_schedule_audit.phase_query_counts),
        phase_window_counts=complete_schedule_audit.phase_window_counts,
        phase_query_counts=complete_schedule_audit.phase_query_counts,
        complete_window_stream_sha256="a" * 64,
        complete_phase_audit_root_sha256=(
            complete_schedule_audit.complete_phase_audit_root_sha256
        ),
        accounting_sha256="b" * 64,
        query_window_stream_sha256="c" * 64,
    )
    phase_random_route_counts = tuple(
        sum(
            item.multiplicity
            for item in selected_expected
            if item.phase == phase
            and item.category == "query-f1m-random-mask-ciphertexts"
        )
        for phase in phase_names
    )
    phase_dummy_route_counts = tuple(
        sum(
            item.multiplicity
            for item in selected_expected
            if item.phase == phase
            and item.category == "query-f1m-encrypted-zero-dummy-ciphertexts"
        )
        for phase in phase_names
    )
    route_coverage = Day1BF1MRouteCoverage(
        controller_context_sha256=context.context_sha256,
        day2_outer_archive_sha256="7" * 64,
        element_count=context.query_window_count,
        element_stream_sha256="d" * 64,
        phase_dummy_route_counts=phase_dummy_route_counts,
        phase_query_counts=context.phase_query_counts,
        phase_query_window_counts=phase_query_window_counts,
        phase_random_route_counts=phase_random_route_counts,
        serialized_object_size_profile_sha256="8" * 64,
    )
    return Day1BWorkerProtocolContract(
        invocation_id="6" * 64,
        trace_manifest_sha256="1" * 64,
        event_schedule_sha256="2" * 64,
        query_vector_sha256="3" * 64,
        candidate_catalog_sha256="4" * 64,
        resource_policy_sha256="5" * 64,
        day2_outer_archive_sha256="7" * 64,
        serialized_object_size_profile_sha256="8" * 64,
        ciphertext_bytes=64,
        f1m_random_zero_sum_ciphertext_bytes=65,
        f1m_encrypted_zero_dummy_ciphertext_bytes=66,
        freshness="0.1",
        rho="1",
        execution_basis=DAY1B_WORKER_EXECUTION_BASIS,
        candidate=selected_candidate,
        phase_ranges=(
            Day1BWorkerPhaseRange("warmup", 0, 10),
            Day1BWorkerPhaseRange("tuning", 10, 40),
            Day1BWorkerPhaseRange("heldout", 40, 100),
        ),
        primitive_names=("encrypt", "serialize_ciphertext"),
        serialized_categories=(
            ("update-ciphertexts", "update"),
            ("query-ciphertexts", "query"),
            ("query-f1m-random-mask-ciphertexts", "query"),
            ("query-f1m-encrypted-zero-dummy-ciphertexts", "query"),
            ("evaluation-keys", "one-time"),
        ),
        f1m_size_class_categories=DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
        f1m_controller_context=context,
        f1m_controller_context_sha256=context.context_sha256,
        f1m_route_coverage=route_coverage,
        f1m_route_coverage_sha256=route_coverage.route_coverage_sha256,
        f1m_charged_size_class_set_sha256="c" * 64,
        expected_f1m_size_class_set_sha256=(
            canonical_day1b_expected_f1m_size_class_set_sha256(selected_expected)
        ),
        expected_f1m_size_class_count=len(selected_expected),
        expected_serialized_equivalence_class_count=(selected_all_serialized_count),
        expected_f1m_cardinality_derivation_root_sha256=(
            canonical_day1b_f1m_cardinality_derivation_root_sha256(
                window_cardinalities=window_cardinalities,
                window_batches=window_batches,
                expected_size_classes=selected_expected,
            )
        ),
        resource_limits=Day1BWorkerResourceLimits(
            wall_clock_ns_per_candidate_cell=wall_clock_ns,
            resident_memory_bytes_per_candidate_cell=10_000,
            scratch_bytes_per_candidate_cell=20_000,
            serialized_object_bytes_maximum=10_000,
            serialized_object_receipt_count_maximum=10_000,
            serialized_object_receipt_spool_bytes_maximum=10_000_000,
            serialized_payload_bytes_per_cell_maximum=100_000_000,
            worker_frame_count_maximum=20_000,
            controller_registered_scratch_bytes_checkpoint_maximum=20_000_000,
        ),
    )


def _phase_audits() -> tuple[Day1BWorkerPhaseAudit, ...]:
    return (
        Day1BWorkerPhaseAudit("warmup", 0, 10, 1, 8, 1, "a" * 64),
        Day1BWorkerPhaseAudit("tuning", 10, 40, 1, 24, 1, "b" * 64),
        Day1BWorkerPhaseAudit("heldout", 40, 100, 1, 48, 1, "c" * 64),
    )


def _issue_invocation(
    contract: Day1BWorkerProtocolContract,
    *,
    overrides: dict[str, object] | None = None,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
) -> Day1BWorkerInvocationCapability:
    values = {
        "elapsed_ns": 900,
        "peak_resident_memory_bytes": 7_000,
        "peak_scratch_bytes": 8_000,
    }
    values["terminal_failure_code"] = None
    values.update(overrides or {})
    selected_expected = (
        _expected_f1m_objects(contract.candidate.candidate_id)
        if expected_f1m_objects is None
        else expected_f1m_objects
    )
    selected_audits = controller_phase_audits or _phase_audits()
    window_cardinalities, window_batches = _fixture_registry_inputs(
        selected_expected,
        candidate=contract.candidate,
        controller_phase_audits=selected_audits,
    )
    registry = _test_only_prepare_day1b_expected_f1m_registry(
        contract=contract,
        controller_phase_audits=selected_audits,
        window_cardinalities=iter(window_cardinalities),
        window_batches=iter(window_batches),
        expected_f1m_objects=iter(selected_expected),
        controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
    )
    return _test_only_issue_day1b_worker_invocation(
        contract=contract,
        controller_phase_audits=selected_audits,
        expected_f1m_registry_capability=registry,
        elapsed_ns=values["elapsed_ns"],
        peak_resident_memory_bytes=values["peak_resident_memory_bytes"],
        peak_scratch_bytes=values["peak_scratch_bytes"],
        terminal_failure_code=values["terminal_failure_code"],
    )


def _consume(
    chunks: Iterable[bytes],
    *,
    contract: Day1BWorkerProtocolContract,
    invocation: Day1BWorkerInvocationCapability | None = None,
    observation_overrides: dict[str, object] | None = None,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
) -> object:
    selected_invocation = (
        invocation
        if invocation is not None
        else _issue_invocation(
            contract,
            overrides=observation_overrides,
            expected_f1m_objects=expected_f1m_objects,
            controller_phase_audits=controller_phase_audits,
        )
    )
    return consume_day1b_worker_frames(
        chunks,
        contract=contract,
        invocation_capability=selected_invocation,
    )


def _f1m_size_class(
    *,
    candidate_id: str,
    phase: str,
    category: str,
    ordinal: int,
) -> dict[str, object] | None:
    if category not in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES:
        return None
    window_identity = f"{candidate_id}:{phase}"
    global_query_ordinal = {
        "warmup": 0,
        "tuning-prefix": 1_000_000,
        "held-out": 2_000_000,
    }[phase] + ordinal
    batch_identity = f"{candidate_id}:{global_query_ordinal}"
    f1m_kind = (
        "random-zero-sum"
        if category == "query-f1m-random-mask-ciphertexts"
        else "encrypted-zero-dummy"
    )
    return {
        "schema_version": "dynamic-cssc-publication-day1b-f1m-size-class-v1",
        "version_id": "version-0001",
        "output_plan_digest": hashlib.sha256(f"plan:{window_identity}".encode()).hexdigest(),
        "component_id": f"component-{category}",
        "output_block_id": f"block-{batch_identity}-{category}",
        "f1m_kind": f1m_kind,
        "private_plan_digest": hashlib.sha256(f"private:{window_identity}".encode()).hexdigest(),
        "execution_binding_digest": hashlib.sha256(
            f"execution:{window_identity}".encode()
        ).hexdigest(),
    }


def _expected_f1m_objects(
    candidate_id: str,
    *,
    phases: tuple[str, ...] = ("tuning-prefix", "held-out"),
    object_count: int = 1,
    query_count: int = 1,
    categories: tuple[str, ...] = DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
) -> tuple[Day1BControllerExpectedF1MObject, ...]:
    return tuple(
        _iter_expected_f1m_objects(
            candidate_id,
            phases=phases,
            object_count=object_count,
            query_count=query_count,
            categories=categories,
        )
    )


def _iter_expected_f1m_objects(
    candidate_id: str,
    *,
    phases: tuple[str, ...] = ("tuning-prefix", "held-out"),
    object_count: int = 1,
    query_count: int = 1,
    categories: tuple[str, ...] = DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
) -> Iterable[Day1BControllerExpectedF1MObject]:
    return (
        Day1BControllerExpectedF1MObject(
            category=category,
            f1m_size_class=Day1BF1MSizeClass.from_document(
                _f1m_size_class(
                    candidate_id=candidate_id,
                    phase=phase,
                    category=category,
                    ordinal=ordinal,
                )
            ),
            first_global_query_ordinal={
                "warmup": 0,
                "tuning-prefix": 1_000_000,
                "held-out": 2_000_000,
            }[phase],
            multiplicity=query_count,
            object_ordinal=ordinal,
            phase=phase,
            window_index={"warmup": 0, "tuning-prefix": 1, "held-out": 2}[phase],
        )
        for phase in phases
        for ordinal in range(object_count)
        for category in categories
    )


def _fixture_registry_inputs(
    expected: tuple[Day1BControllerExpectedF1MObject, ...],
    *,
    candidate: Day1BWorkerCandidateSpec,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
) -> tuple[
    tuple[Day1BF1MWindowCardinality, ...],
    tuple[Day1BF1MWindowBatch, ...],
]:
    audit_by_phase = dict(
        zip(("warmup", "tuning-prefix", "held-out"), controller_phase_audits, strict=True)
    )
    window_cardinalities: list[Day1BF1MWindowCardinality] = []
    phase_routes: dict[str, tuple[Day1BControllerExpectedF1MObject, ...]] = {}
    for phase in candidate.retained_phases:
        routes = tuple(item for item in expected if item.phase == phase)
        phase_routes[phase] = routes
        audit = audit_by_phase[phase]
        query_count = audit.realized_query_count
        random_count = sum(
            item.multiplicity
            for item in routes
            if item.category == "query-f1m-random-mask-ciphertexts"
        )
        dummy_count = sum(
            item.multiplicity
            for item in routes
            if item.category == "query-f1m-encrypted-zero-dummy-ciphertexts"
        )
        if query_count:
            assert random_count % query_count == 0
            assert dummy_count % query_count == 0
            masked_share_count = random_count // query_count
            dummy_share_count = dummy_count // query_count
        else:
            assert not routes
            masked_share_count = 0
            dummy_share_count = 0
        if candidate.f1m_policy == "overlap-only":
            assert dummy_share_count == 0
            returned_share_count = masked_share_count
        else:
            returned_share_count = masked_share_count + dummy_share_count
        window_identity = f"{candidate.candidate_id}:{phase}"
        first_query = {
            "warmup": 0,
            "tuning-prefix": 1_000_000,
            "held-out": 2_000_000,
        }[phase]
        window_cardinalities.append(
            Day1BF1MWindowCardinality(
                phase=phase,
                window_index={"warmup": 0, "tuning-prefix": 1, "held-out": 2}[phase],
                accepted_group_start=audit.accepted_group_start,
                accepted_group_end=audit.accepted_group_end,
                first_global_query_ordinal=first_query,
                query_count=query_count,
                version_id="version-0001",
                output_plan_digest=hashlib.sha256(f"plan:{window_identity}".encode()).hexdigest(),
                private_plan_digest=hashlib.sha256(
                    f"private:{window_identity}".encode()
                ).hexdigest(),
                execution_binding_digest=hashlib.sha256(
                    f"execution:{window_identity}".encode()
                ).hexdigest(),
                f1m_policy=candidate.f1m_policy,
                returned_share_count=returned_share_count,
                overlap_masked_share_count=masked_share_count,
                expected_random_route_count=random_count,
                expected_dummy_route_count=dummy_count,
                expected_size_class_subroot_sha256=(
                    canonical_day1b_expected_f1m_size_class_subroot_sha256(routes)
                ),
            )
        )

    window_batches: list[Day1BF1MWindowBatch] = []
    for phase in candidate.retained_phases:
        cardinality = next(row for row in window_cardinalities if row.phase == phase)
        if cardinality.query_count == 0:
            continue
        window_batches.append(
            Day1BF1MWindowBatch(
                phase=phase,
                window_index=cardinality.window_index,
                first_global_query_ordinal=cardinality.first_global_query_ordinal,
                query_count=cardinality.query_count,
                version_id=cardinality.version_id,
                output_plan_digest=cardinality.output_plan_digest,
                private_plan_digest=cardinality.private_plan_digest,
                execution_binding_digest=cardinality.execution_binding_digest,
                size_class_subroot_sha256=(
                    canonical_day1b_expected_f1m_size_class_subroot_sha256(phase_routes[phase])
                ),
            )
        )
    return tuple(window_cardinalities), tuple(window_batches)


def _prepare_registry(
    expected: tuple[Day1BControllerExpectedF1MObject, ...],
    *,
    contract: Day1BWorkerProtocolContract | None = None,
    candidate: Day1BWorkerCandidateSpec | None = None,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
    scratch_cap: int | None = None,
) -> Day1BExpectedF1MRegistryCapability:
    selected_audits = controller_phase_audits or _phase_audits()
    selected_candidate = candidate or (
        contract.candidate if contract is not None else _contract().candidate
    )
    selected_contract = contract or _contract(
        candidate=selected_candidate,
        expected_f1m_objects=expected,
        controller_phase_audits=selected_audits,
    )
    if scratch_cap is not None and scratch_cap != (
        selected_contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
    ):
        selected_contract = replace(
            selected_contract,
            resource_limits=replace(
                selected_contract.resource_limits,
                controller_registered_scratch_bytes_checkpoint_maximum=scratch_cap,
            ),
        )
    window_cardinalities, window_batches = _fixture_registry_inputs(
        expected,
        candidate=selected_candidate,
        controller_phase_audits=selected_audits,
    )
    return _test_only_prepare_day1b_expected_f1m_registry(
        contract=selected_contract,
        controller_phase_audits=selected_audits,
        window_cardinalities=iter(window_cardinalities),
        window_batches=iter(window_batches),
        expected_f1m_objects=iter(expected),
        controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
    )


def _complete_transcript(
    contract: Day1BWorkerProtocolContract,
    *,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...] | None = None,
    expected_f1m_objects: tuple[Day1BControllerExpectedF1MObject, ...] | None = None,
) -> bytes:
    frames: list[bytes] = []
    sequence = 0

    def emit(kind: str, *, payload: bytes = b"", **fields: object) -> None:
        nonlocal sequence
        frames.append(_frame(sequence, kind, payload=payload, **fields))
        sequence += 1

    emit("cell-start", input_binding=contract.input_binding_document())
    candidate = contract.candidate
    emit(
        "candidate-start",
        candidate_id=candidate.candidate_id,
        candidate_role=candidate.candidate_role,
    )
    selected_audits = controller_phase_audits or _phase_audits()
    selected_expected = expected_f1m_objects or _expected_f1m_objects(
        contract.candidate.candidate_id
    )
    for audit in selected_audits:
        phase = {
            "warmup": "warmup",
            "tuning": "tuning-prefix",
            "heldout": "held-out",
        }[audit.phase]
        retained = phase in candidate.retained_phases
        payloads = (
            f"{candidate.candidate_id}:{phase}:update".encode(),
            f"{candidate.candidate_id}:{phase}:mask".encode(),
            f"{candidate.candidate_id}:{phase}:dummy".encode(),
            f"{candidate.candidate_id}:{phase}:key".encode(),
        )
        if retained:
            random_route = next(
                item
                for item in selected_expected
                if item.phase == phase and item.category == "query-f1m-random-mask-ciphertexts"
            )
            dummy_route = next(
                item
                for item in selected_expected
                if item.phase == phase
                and item.category == "query-f1m-encrypted-zero-dummy-ciphertexts"
            )
            emit(
                "serialized-object",
                candidate_id=candidate.candidate_id,
                phase=phase,
                category="update-ciphertexts",
                object_ordinal=0,
                multiplicity=2,
                f1m_size_class=None,
                payload=payloads[0],
            )
            emit(
                "serialized-object",
                candidate_id=candidate.candidate_id,
                phase=phase,
                category="query-f1m-random-mask-ciphertexts",
                object_ordinal=0,
                multiplicity=random_route.multiplicity,
                f1m_size_class=random_route.f1m_size_class.to_document(),
                payload=payloads[1],
            )
            emit(
                "serialized-object",
                candidate_id=candidate.candidate_id,
                phase=phase,
                category="query-f1m-encrypted-zero-dummy-ciphertexts",
                object_ordinal=0,
                multiplicity=dummy_route.multiplicity,
                f1m_size_class=dummy_route.f1m_size_class.to_document(),
                payload=payloads[2],
            )
            if phase == candidate.retained_phases[0]:
                emit(
                    "serialized-object",
                    candidate_id=candidate.candidate_id,
                    phase=phase,
                    category="evaluation-keys",
                    object_ordinal=0,
                    multiplicity=1,
                    f1m_size_class=None,
                    payload=payloads[3],
                )
        emit(
            "phase-result",
            candidate_id=candidate.candidate_id,
            phase=phase,
            outcome="complete",
            failure_code=None,
            retained_measurement=retained,
            update_primitive_counts=[3, 4] if retained else None,
            query_primitive_counts=[5, 6] if retained else None,
            serialized_category_object_counts=(
                [1, 0, 1, 1, int(phase == candidate.retained_phases[0])] if retained else None
            ),
            phase_audit=audit.to_document(),
        )
    emit(
        "candidate-result",
        candidate_id=candidate.candidate_id,
        elapsed_ns=900,
        peak_resident_memory_bytes=7_000,
        peak_scratch_bytes=8_000,
        candidate_retry_count=0,
        state_reset_count=0,
    )
    emit("cell-end", candidate_count=1)
    return b"".join(frames)


def _outcome_transcript(
    contract: Day1BWorkerProtocolContract,
    *,
    outcomes: tuple[tuple[str, str | None], ...],
) -> bytes:
    assert len(outcomes) == 3
    candidate = contract.candidate
    frames = [
        _frame(0, "cell-start", input_binding=contract.input_binding_document()),
        _frame(
            1,
            "candidate-start",
            candidate_id=candidate.candidate_id,
            candidate_role=candidate.candidate_role,
        ),
    ]
    sequence = 2
    for audit, phase, (outcome, failure_code) in zip(
        _phase_audits(),
        ("warmup", "tuning-prefix", "held-out"),
        outcomes,
        strict=True,
    ):
        retained = phase in candidate.retained_phases
        complete = outcome == "complete"
        frames.append(
            _frame(
                sequence,
                "phase-result",
                candidate_id=candidate.candidate_id,
                phase=phase,
                outcome=outcome,
                failure_code=failure_code,
                retained_measurement=retained,
                update_primitive_counts=[0, 0] if retained and complete else None,
                query_primitive_counts=[1, 0] if retained and complete else None,
                serialized_category_object_counts=(
                    [0, 0, 0, 0, 0] if retained and complete else None
                ),
                phase_audit=audit.to_document(),
            )
        )
        sequence += 1
    frames.extend(
        (
            _frame(
                sequence,
                "candidate-result",
                candidate_id=candidate.candidate_id,
                elapsed_ns=900,
                peak_resident_memory_bytes=7_000,
                peak_scratch_bytes=8_000,
                candidate_retry_count=0,
                state_reset_count=0,
            ),
            _frame(sequence + 1, "cell-end", candidate_count=1),
        )
    )
    return b"".join(frames)


def _chunked(value: bytes, widths: Iterable[int]) -> Iterable[bytes]:
    position = 0
    for width in widths:
        if position == len(value):
            break
        yield value[position : position + width]
        position += width
    if position < len(value):
        yield value[position:]


def _rewrite_first_frame(
    transcript: bytes,
    frame_kind: str,
    mutate: object,
    *,
    predicate: object | None = None,
) -> bytes:
    rewritten = bytearray()
    position = 0
    changed = False
    while position < len(transcript):
        header_size = int.from_bytes(transcript[position : position + 4], "big")
        header_start = position + 4
        header_end = header_start + header_size
        header = json.loads(transcript[header_start:header_end])
        payload_end = header_end + header["payload_byte_count"]
        payload = transcript[header_end:payload_end]
        if (
            not changed
            and header["frame_kind"] == frame_kind
            and (predicate is None or predicate(header))
        ):
            replacement = mutate(header, payload)
            header, payload = replacement
            header["payload_byte_count"] = len(payload)
            changed = True
        header_bytes = _canonical_bytes(header)
        rewritten.extend(len(header_bytes).to_bytes(4, "big"))
        rewritten.extend(header_bytes)
        rewritten.extend(payload)
        position = payload_end
    assert changed
    return bytes(rewritten)


def test_streaming_decoder_hashes_payloads_without_retaining_raw_bytes() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)

    evidence_capability = _consume(
        _chunked(transcript, (1, 2, 7, 3, 11, 5, 1, 19, 2, 97)),
        contract=contract,
    )
    evidence = claim_day1b_worker_evidence(evidence_capability)
    receipt = evidence.receipt

    first = receipt.candidate.phases[1]
    assert first.serialized_categories is not None
    update_category = first.serialized_categories[0]
    expected = b"reference-a:tuning-prefix:update"
    assert update_category.serialization_equivalence_class_count == 1
    assert update_category.protocol_object_count == 2
    assert update_category.charged_byte_count == 2 * len(expected)
    assert not hasattr(update_category, "objects")
    destination = io.BytesIO()
    copied_sha256 = evidence.copy_object_receipts_to(destination)
    spooled = destination.getvalue()
    assert copied_sha256 == receipt.object_receipt_spool_sha256
    assert hashlib.sha256(expected).hexdigest().encode() in spooled
    assert b"reference-a:tuning-prefix:update" not in _canonical_bytes(receipt.to_document())
    assert receipt.input_binding_sha256 == contract.input_binding_sha256
    assert receipt.input_binding_document == contract.input_binding_document()
    assert receipt.to_document()["input_binding_document"] == contract.input_binding_document()
    assert receipt.controller_expected_serialized_equivalence_class_count == 7
    assert receipt.object_receipt_line_count == 7
    evidence.close()


def test_decoder_evidence_is_opaque_and_single_use() -> None:
    contract = _contract()

    with pytest.raises(TypeError, match="decoder-minted"):
        Day1BWorkerEvidenceCapability()
    forged = object.__new__(Day1BWorkerEvidenceCapability)
    with pytest.raises(Day1BWorkerProtocolError, match="absent|consumed"):
        claim_day1b_worker_evidence(forged)

    capability = _consume((_complete_transcript(contract),), contract=contract)
    evidence = claim_day1b_worker_evidence(capability)
    with pytest.raises(Day1BWorkerProtocolError, match="absent|consumed"):
        claim_day1b_worker_evidence(capability)
    evidence.close()


@pytest.mark.parametrize("tamper", ("missing", "forged"))
def test_evidence_claim_failure_closes_only_authoritative_spool(tamper: str) -> None:
    contract = _contract()
    capability = _consume((_complete_transcript(contract),), contract=contract)
    authoritative = capability._binding.spool
    forged = _consume((_complete_transcript(contract),), contract=contract)
    forged_spool = forged._binding.spool
    if tamper == "missing":
        del capability._binding
    else:
        capability._binding = forged._binding

    with pytest.raises(Day1BWorkerProtocolError, match="absent or consumed"):
        claim_day1b_worker_evidence(capability)

    assert authoritative._closed is True
    assert forged_spool._closed is False
    abandon_day1b_worker_evidence(forged)
    _assert_no_live_controlled_scratch()


def test_unclaimed_capabilities_do_not_strongly_retain_controlled_scratch() -> None:
    contract = _contract()
    invocation = _issue_invocation(contract)
    invocation_reference = weakref.ref(invocation)
    del invocation
    gc.collect()
    assert invocation_reference() is None
    _assert_no_live_controlled_scratch()


def test_claimed_evidence_drop_and_copy_error_do_not_leak_controlled_scratch() -> None:
    contract = _contract()
    evidence = claim_day1b_worker_evidence(
        _consume((_complete_transcript(contract),), contract=contract)
    )
    evidence_reference = weakref.ref(evidence)
    del evidence
    gc.collect()
    assert evidence_reference() is None
    _assert_no_live_controlled_scratch()

    evidence = claim_day1b_worker_evidence(
        _consume((_complete_transcript(contract),), contract=contract)
    )

    class _RejectingDestination(io.BytesIO):
        def write(self, value: bytes) -> int:
            raise OSError("fixture copy failure")

    with pytest.raises(OSError, match="fixture copy failure"):
        evidence.copy_object_receipts_to(_RejectingDestination())
    evidence_reference = weakref.ref(evidence)
    del evidence
    gc.collect()
    assert evidence_reference() is None
    _assert_no_live_controlled_scratch()

    capability = _consume((_complete_transcript(contract),), contract=contract)
    evidence_reference = weakref.ref(capability)
    del capability
    gc.collect()
    assert evidence_reference() is None
    _assert_no_live_controlled_scratch()


def test_launcher_invocation_capability_is_opaque_bound_and_single_use() -> None:
    contract = _contract()

    with pytest.raises(TypeError, match="launcher-minted"):
        Day1BWorkerInvocationCapability()
    forged = object.__new__(Day1BWorkerInvocationCapability)
    with pytest.raises(Day1BWorkerProtocolError, match="absent|issued|consumed"):
        _consume((_complete_transcript(contract),), contract=contract, invocation=forged)

    invocation = _issue_invocation(contract)
    capability = _consume(
        (_complete_transcript(contract),),
        contract=contract,
        invocation=invocation,
    )
    evidence = claim_day1b_worker_evidence(capability)
    with pytest.raises(Day1BWorkerProtocolError, match="absent|issued|consumed"):
        _consume(
            (_complete_transcript(contract),),
            contract=contract,
            invocation=invocation,
        )
    evidence.close()
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize("tamper", ("missing", "forged"))
def test_invocation_claim_failure_closes_only_authoritative_spool(tamper: str) -> None:
    contract = _contract()
    capability = _issue_invocation(contract)
    authoritative = capability._binding.spool
    forged = _issue_invocation(contract)
    forged_spool = forged._binding.spool
    if tamper == "missing":
        del capability._binding
    else:
        capability._binding = forged._binding

    with pytest.raises(Day1BWorkerProtocolError, match="absent, unissued, or consumed"):
        _consume(
            (_complete_transcript(contract),),
            contract=contract,
            invocation=capability,
        )

    assert authoritative._closed is True
    assert forged_spool._closed is False
    abandon_day1b_worker_invocation(forged)
    _assert_no_live_controlled_scratch()


def test_invocation_capability_cannot_be_spliced_to_another_input_binding() -> None:
    contract = _contract()
    invocation = _issue_invocation(contract)
    other = replace(contract, invocation_id="7" * 64)

    with pytest.raises(Day1BWorkerProtocolError, match="invocation|input binding"):
        _consume((_complete_transcript(other),), contract=other, invocation=invocation)
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize("splice", ("invocation", "candidate", "scratch-cap"))
def test_expected_registry_is_bound_to_exact_predispatch_context(splice: str) -> None:
    base = _contract()
    expected = _expected_f1m_objects(base.candidate.candidate_id)
    if splice == "invocation":
        other = replace(base, invocation_id="7" * 64)
    elif splice == "candidate":
        candidate_splice = _contract(
            candidate=replace(base.candidate, candidate_id="reference-b"),
            expected_f1m_objects=expected,
            expected_serialized_equivalence_class_count=(
                base.expected_serialized_equivalence_class_count
            ),
        )
        other = replace(
            candidate_splice,
            expected_f1m_cardinality_derivation_root_sha256=(
                base.expected_f1m_cardinality_derivation_root_sha256
            ),
        )
    else:
        other = replace(
            base,
            resource_limits=replace(
                base.resource_limits,
                controller_registered_scratch_bytes_checkpoint_maximum=10_000_000,
            ),
        )
    registry = _prepare_registry(expected, contract=base)

    with pytest.raises(Day1BWorkerProtocolError, match="pre-dispatch context"):
        _test_only_issue_day1b_worker_invocation(
            contract=other,
            controller_phase_audits=_phase_audits(),
            expected_f1m_registry_capability=registry,
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            terminal_failure_code=None,
        )
    _assert_no_live_controlled_scratch()


def test_resource_limits_have_no_implicit_defaults() -> None:
    parameters = inspect.signature(Day1BWorkerResourceLimits).parameters.values()
    assert parameters
    assert all(parameter.default is inspect.Parameter.empty for parameter in parameters)


def test_expected_f1m_registry_is_opaque_descriptor_backed_and_single_use() -> None:
    expected = _expected_f1m_objects("reference-a")
    contract = _contract(expected_f1m_objects=expected)
    with pytest.raises(TypeError, match="controller-minted"):
        Day1BExpectedF1MRegistryCapability()
    registry = _prepare_registry(expected, contract=contract)
    descriptor = describe_day1b_expected_f1m_registry(registry)
    assert descriptor.size_class_count == len(expected)
    assert descriptor.size_class_set_sha256 == (
        canonical_day1b_expected_f1m_size_class_set_sha256(expected)
    )
    assert descriptor.controller_registered_scratch_bytes_checkpoint_maximum == (
        contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
    )
    assert len(descriptor.pre_dispatch_context_sha256) == 64
    scratch_members = tuple(_CURRENT_CONTROLLED_SCRATCH.rglob("*"))
    assert all("-journal" not in path.name and "-wal" not in path.name for path in scratch_members)
    assert not hasattr(registry, "expected_f1m_objects")
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()
    with pytest.raises(Day1BWorkerProtocolError, match="absent|consumed"):
        abandon_day1b_expected_f1m_registry(registry)


@pytest.mark.parametrize("tamper", ("missing", "forged"))
def test_registry_claim_failure_closes_only_authoritative_storage(tamper: str) -> None:
    expected = _expected_f1m_objects("reference-a")
    contract = _contract(expected_f1m_objects=expected)
    capability = _prepare_registry(expected, contract=contract)
    authoritative = capability._binding.registry
    forged = _prepare_registry(expected, contract=contract)
    forged_registry = forged._binding.registry
    if tamper == "missing":
        del capability._binding
    else:
        capability._binding = forged._binding

    with pytest.raises(Day1BWorkerProtocolError, match="absent, unissued, or consumed"):
        _test_only_issue_day1b_worker_invocation(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            expected_f1m_registry_capability=capability,
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            terminal_failure_code=None,
        )

    assert authoritative._closed is True
    assert forged_registry._closed is False
    abandon_day1b_expected_f1m_registry(forged)
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize("invalid", ("missing", "range-mismatch"))
def test_invalid_registry_context_is_rejected_before_scratch_creation(invalid: str) -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    windows, window_batches = _fixture_registry_inputs(
        expected,
        candidate=contract.candidate,
        controller_phase_audits=_phase_audits(),
    )
    audits = (
        ()
        if invalid == "missing"
        else (replace(_phase_audits()[0], accepted_group_start=1), *_phase_audits()[1:])
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controller phase audit|range"):
        _test_only_prepare_day1b_expected_f1m_registry(
            contract=contract,
            controller_phase_audits=audits,
            window_cardinalities=iter(windows),
            window_batches=iter(window_batches),
            expected_f1m_objects=iter(expected),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
        )
    assert not tuple(_CURRENT_CONTROLLED_SCRATCH.iterdir())


def test_controlled_scratch_initialization_failures_close_anonymous_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_fstat = worker_protocol.os.fstat
    failed = False

    def fail_first_fstat(descriptor: int) -> os.stat_result:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("fixture root fstat failure")
        return original_fstat(descriptor)

    monkeypatch.setattr(worker_protocol.os, "fstat", fail_first_fstat)
    with pytest.raises(OSError, match="fixture root fstat failure"):
        _claimed_scratch()
    assert failed is True
    assert not tuple(_CURRENT_CONTROLLED_SCRATCH.iterdir())

    monkeypatch.setattr(worker_protocol.os, "fstat", original_fstat)
    scratch = _claimed_scratch()
    monkeypatch.setattr(
        worker_protocol.os,
        "dup",
        lambda _descriptor: (_ for _ in ()).throw(OSError("fixture dup failure")),
    )
    with pytest.raises(Day1BWorkerProtocolError, match="handle could not be duplicated"):
        scratch.create_binary_file("object-receipts.jsonl")
    scratch.close()
    _assert_no_live_controlled_scratch()


def test_expected_f1m_registry_checks_controlled_scratch_cap_incrementally() -> None:
    yielded_size_classes = 0

    def expected_size_classes() -> Iterable[Day1BControllerExpectedF1MObject]:
        nonlocal yielded_size_classes
        for ordinal in range(100_000):
            yielded_size_classes += 1
            yield Day1BControllerExpectedF1MObject(
                phase="held-out",
                window_index=2,
                first_global_query_ordinal=2_000_000,
                category="query-f1m-random-mask-ciphertexts",
                object_ordinal=ordinal,
                multiplicity=100_000,
                f1m_size_class=Day1BF1MSizeClass(
                    version_id="version-0001",
                    output_plan_digest=hashlib.sha256(b"plan:reference-a:held-out").hexdigest(),
                    component_id=f"component-{ordinal}",
                    output_block_id="block-0",
                    f1m_kind="random-zero-sum",
                    private_plan_digest=hashlib.sha256(b"private:reference-a:held-out").hexdigest(),
                    execution_binding_digest=hashlib.sha256(
                        b"execution:reference-a:held-out"
                    ).hexdigest(),
                ),
            )

    window = Day1BF1MWindowCardinality(
        phase="held-out",
        window_index=2,
        accepted_group_start=40,
        accepted_group_end=100,
        first_global_query_ordinal=2_000_000,
        query_count=100_000,
        version_id="version-0001",
        output_plan_digest=hashlib.sha256(b"plan:reference-a:held-out").hexdigest(),
        private_plan_digest=hashlib.sha256(b"private:reference-a:held-out").hexdigest(),
        execution_binding_digest=hashlib.sha256(b"execution:reference-a:held-out").hexdigest(),
        f1m_policy="uniform-random-or-zero",
        returned_share_count=100_000,
        overlap_masked_share_count=100_000,
        expected_random_route_count=10_000_000_000,
        expected_dummy_route_count=0,
        expected_size_class_subroot_sha256="9" * 64,
    )
    window_batch = Day1BF1MWindowBatch(
        phase=window.phase,
        window_index=window.window_index,
        first_global_query_ordinal=window.first_global_query_ordinal,
        query_count=window.query_count,
        version_id=window.version_id,
        output_plan_digest=window.output_plan_digest,
        private_plan_digest=window.private_plan_digest,
        execution_binding_digest=window.execution_binding_digest,
        size_class_subroot_sha256=window.expected_size_class_subroot_sha256,
    )
    scratch_contract = _contract(expected_f1m_objects=())
    scratch_contract = replace(
        scratch_contract,
        resource_limits=replace(
            scratch_contract.resource_limits,
            controller_registered_scratch_bytes_checkpoint_maximum=250_000,
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controlled scratch.*cap"):
        _test_only_prepare_day1b_expected_f1m_registry(
            contract=scratch_contract,
            controller_phase_audits=_phase_audits(),
            window_cardinalities=iter((window,)),
            window_batches=iter((window_batch,)),
            expected_f1m_objects=expected_size_classes(),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
        )
    assert 0 < yielded_size_classes < 100_000
    _assert_no_live_controlled_scratch()


def test_registry_route_cardinality_queries_use_bounded_indexes_without_temp_sorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections: list[sqlite3.Connection] = []
    original_create_tables = worker_protocol._create_expected_f1m_tables

    def capture_connection(connection: sqlite3.Connection) -> None:
        connections.append(connection)
        original_create_tables(connection)

    monkeypatch.setattr(
        worker_protocol,
        "_create_expected_f1m_tables",
        capture_connection,
    )
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    registry = _prepare_registry(expected, contract=contract)
    assert len(connections) == 1
    connection = connections[0]
    plans = (
        connection.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM f1m_window_batches "
            "WHERE phase=? AND window_index=?",
            ("tuning-prefix", 1),
        ).fetchall(),
        connection.execute(
            "EXPLAIN QUERY PLAN SELECT category, COUNT(*) FROM expected_f1m "
            "WHERE phase=? AND window_index=? GROUP BY category",
            ("tuning-prefix", 1),
        ).fetchall(),
        connection.execute(
            "EXPLAIN QUERY PLAN SELECT route_document FROM expected_f1m "
            "WHERE phase=? AND window_index=? "
            "ORDER BY object_ordinal, category_order",
            ("tuning-prefix", 1),
        ).fetchall(),
        connection.execute(
            "EXPLAIN QUERY PLAN SELECT route_document FROM expected_f1m "
            "WHERE phase=? AND window_index=? AND first_global_query_ordinal=? "
            "AND multiplicity=? "
            "ORDER BY phase, window_index, object_ordinal, category_order",
            (
                expected[0].phase,
                expected[0].window_index,
                expected[0].first_global_query_ordinal,
                expected[0].multiplicity,
            ),
        ).fetchall(),
    )
    details = tuple(str(row[3]) for plan in plans for row in plan)
    assert all("SEARCH " in detail for detail in details)
    assert not any("SCAN " in detail or "USE TEMP B-TREE" in detail for detail in details)
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()


def test_active_registry_uses_only_anonymous_controlled_scratch() -> None:
    contract = _contract()
    registry = _prepare_registry(
        _expected_f1m_objects(contract.candidate.candidate_id),
        contract=contract,
    )

    _assert_no_live_controlled_scratch()
    descriptor = describe_day1b_expected_f1m_registry(registry)
    assert descriptor.size_class_count > 0
    assert descriptor.anonymous_scratch_creation_isolation_verified is False
    assert descriptor.pre_dispatch_execution_admissible is False
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()


def test_anonymous_scratch_capability_is_opaque_single_use_and_context_bound() -> None:
    with pytest.raises(TypeError, match="launcher-minted"):
        Day1BAnonymousScratchCapability()

    capability, contract, audits = _scratch_capability()
    with pytest.raises(TypeError, match="not a caller boolean"):
        bool(capability)
    scratch = worker_protocol._ControlledScratch(
        capability,
        contract=contract,
        controller_phase_audits=audits,
    )
    with pytest.raises(Day1BWorkerProtocolError, match="consumed"):
        worker_protocol._ControlledScratch(
            capability,
            contract=contract,
            controller_phase_audits=audits,
        )
    scratch.close()

    capability, contract, audits = _scratch_capability()
    changed_context = replace(
        contract.f1m_controller_context,
        resource_policy_sha256="f" * 64,
    )
    changed_coverage = replace(
        contract.f1m_route_coverage,
        controller_context_sha256=changed_context.context_sha256,
    )
    changed = replace(
        contract,
        resource_policy_sha256="f" * 64,
        f1m_controller_context=changed_context,
        f1m_controller_context_sha256=changed_context.context_sha256,
        f1m_route_coverage=changed_coverage,
        f1m_route_coverage_sha256=changed_coverage.route_coverage_sha256,
    )
    with pytest.raises(Day1BWorkerProtocolError, match="pre-dispatch context"):
        worker_protocol._ControlledScratch(
            capability,
            contract=changed,
            controller_phase_audits=audits,
        )
    _assert_no_live_controlled_scratch()


def test_unclaimed_anonymous_scratch_capability_closes_both_handles_on_collection() -> None:
    capability, _contract_value, _audits = _scratch_capability()
    handles = tuple(item[1] for item in capability._binding.members)
    connection = capability._binding.sqlite_connection
    assert connection is not None
    reference = weakref.ref(capability)

    del capability
    gc.collect()
    assert reference() is None
    assert all(file.closed for file in handles)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    _assert_no_live_controlled_scratch()


def test_anonymous_scratch_capability_rejects_fd_identity_retarget() -> None:
    capability, contract, audits = _scratch_capability()
    first = capability._binding.members[0][1]
    replacement = _anonymous_test_file()
    os.dup2(replacement.fileno(), first.fileno())

    with pytest.raises(Day1BWorkerProtocolError, match="file identity"):
        worker_protocol._ControlledScratch(
            capability,
            contract=contract,
            controller_phase_audits=audits,
        )
    replacement.close()
    _assert_no_live_controlled_scratch()


def test_anonymous_scratch_mint_failure_closes_fixture_owned_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[BinaryIO] = []
    original_temporary_file = worker_protocol.tempfile.TemporaryFile
    original_named_temporary_file = worker_protocol.tempfile.NamedTemporaryFile
    failure = RuntimeError("fixture anonymous scratch mint failure")

    def capture_file(*args: object, **kwargs: object) -> BinaryIO:
        file = original_temporary_file(*args, **kwargs)
        created.append(file)
        return file

    def capture_named_file(*args: object, **kwargs: object) -> BinaryIO:
        file = original_named_temporary_file(*args, **kwargs)
        created.append(file)
        return file

    def fail_mint(_binding: object) -> None:
        raise failure

    monkeypatch.setattr(worker_protocol.tempfile, "TemporaryFile", capture_file)
    monkeypatch.setattr(
        worker_protocol.tempfile,
        "NamedTemporaryFile",
        capture_named_file,
    )
    monkeypatch.setattr(worker_protocol, "_mint_anonymous_scratch_capability", fail_mint)

    with pytest.raises(RuntimeError) as raised:
        _scratch_capability()

    assert raised.value is failure
    assert len(created) == 2
    assert all(file.closed for file in created)
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize("tamper", ("missing", "forged"))
def test_anonymous_scratch_claim_failure_closes_only_authoritative_handles(
    tamper: str,
) -> None:
    capability, contract, audits = _scratch_capability()
    authoritative = tuple(item[1] for item in capability._binding.members)
    forged = tuple(_anonymous_test_file() for _ in range(2))
    if tamper == "missing":
        del capability._binding
    else:
        capability._binding = worker_protocol._AnonymousScratchBinding(
            pre_dispatch_context_sha256="f" * 64,
            controller_registered_scratch_bytes_checkpoint_maximum=1,
            members=tuple(
                (
                    name,
                    file,
                    (os.fstat(file.fileno()).st_dev, os.fstat(file.fileno()).st_ino),
                )
                for name, file in zip(
                    worker_protocol._ANONYMOUS_SCRATCH_MEMBER_NAMES,
                    forged,
                    strict=True,
                )
            ),
            anonymous_scratch_creation_isolation_verified=False,
        )

    with pytest.raises(Day1BWorkerProtocolError, match="absent, unissued, or consumed"):
        worker_protocol._ControlledScratch(
            capability,
            contract=contract,
            controller_phase_audits=audits,
        )

    assert all(file.closed for file in authoritative)
    assert not any(file.closed for file in forged)
    assert id(capability) not in worker_protocol._ISSUED_ANONYMOUS_SCRATCH
    for file in forged:
        file.close()
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize("handle_count", (1, 3))
def test_anonymous_scratch_capability_rejects_missing_or_extra_handles(
    handle_count: int,
) -> None:
    handles = tuple(_anonymous_test_file() for _ in range(handle_count))
    contract = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="exactly two"):
        _test_only_issue_day1b_anonymous_scratch_capability(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
            handles=handles,
        )
    assert all(file.closed for file in handles)


def test_anonymous_scratch_capability_rejects_linked_or_same_inode_handles(
    tmp_path: Path,
) -> None:
    contract = _contract()
    linked_path = tmp_path / "linked-scratch"
    linked_path.write_bytes(b"")
    linked = linked_path.open("r+b")
    anonymous = _anonymous_test_file()
    with pytest.raises(Day1BWorkerProtocolError, match="distinct unlinked"):
        _test_only_issue_day1b_anonymous_scratch_capability(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
            handles=(linked, anonymous),
        )
    assert linked.closed and anonymous.closed
    assert linked_path.exists()

    base = _anonymous_test_file()
    duplicates = (
        os.fdopen(os.dup(base.fileno()), "w+b"),
        os.fdopen(os.dup(base.fileno()), "w+b"),
    )
    with pytest.raises(Day1BWorkerProtocolError, match="distinct unlinked"):
        _test_only_issue_day1b_anonymous_scratch_capability(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
            handles=duplicates,
        )
    assert all(file.closed for file in duplicates)
    base.close()


def test_custom_anonymous_scratch_handles_require_a_preopened_sqlite_connection() -> None:
    handles = tuple(_anonymous_test_file() for _ in range(2))
    contract = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="launcher-opened SQLite connection"):
        _test_only_issue_day1b_anonymous_scratch_capability(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
            handles=handles,
        )
    assert all(file.closed for file in handles)


def test_registry_descriptor_document_is_closed_and_round_trips() -> None:
    contract = _contract()
    registry = _prepare_registry(
        _expected_f1m_objects(contract.candidate.candidate_id),
        contract=contract,
    )
    descriptor = describe_day1b_expected_f1m_registry(registry)
    document = descriptor.to_document()

    assert document["schema_version"] == (DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA)
    assert (
        Day1BExpectedF1MRegistryDescriptor.from_document(json.loads(_canonical_bytes(document)))
        == descriptor
    )
    with pytest.raises(Day1BWorkerProtocolError, match="keys.*exact"):
        Day1BExpectedF1MRegistryDescriptor.from_document({**document, "forged": False})
    with pytest.raises(Day1BWorkerProtocolError, match="schema.*frozen"):
        Day1BExpectedF1MRegistryDescriptor.from_document({**document, "schema_version": "forged"})
    malformed_counts = dict(document["phase_size_class_counts"])
    malformed_counts["forged"] = 0
    with pytest.raises(Day1BWorkerProtocolError, match="phase keys.*exact"):
        Day1BExpectedF1MRegistryDescriptor.from_document(
            {**document, "phase_size_class_counts": malformed_counts}
        )
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()


def test_sqlite_registry_is_bound_to_one_anonymous_descriptor_inode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_connect = worker_protocol.sqlite3.connect
    opened: list[tuple[str, tuple[int, int], sqlite3.Connection]] = []

    def capture_connect(database: str, **kwargs: object) -> sqlite3.Connection:
        assert database.startswith("file:") and database.endswith("?mode=rw")
        assert kwargs == {"check_same_thread": False, "uri": True}
        visible = tuple(_CURRENT_CONTROLLED_SCRATCH.iterdir())
        assert len(visible) == 1
        before = os.stat(visible[0])
        connection = original_connect(database, **kwargs)
        after = os.stat(visible[0])
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        opened.append((database, (before.st_dev, before.st_ino), connection))
        return connection

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", capture_connect)
    contract = _contract()
    registry = _prepare_registry(
        _expected_f1m_objects(contract.candidate.candidate_id),
        contract=contract,
    )

    assert len(opened) == 1
    _database, identity, connection = opened[0]
    held = registry._binding.registry.scratch._files["binding-index.sqlite3"]
    database_stat = os.fstat(held.fileno())
    assert (database_stat.st_dev, database_stat.st_ino) == identity
    assert database_stat.st_nlink == 0
    page_count = connection.execute("PRAGMA page_count").fetchone()[0]
    page_size = connection.execute("PRAGMA page_size").fetchone()[0]
    assert database_stat.st_size == page_count * page_size > 0
    _assert_no_live_controlled_scratch()
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()


def test_sqlite_connection_is_preopened_before_anonymous_capability_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, contract, audits = _scratch_capability()
    preopened = capability._binding.sqlite_connection
    assert type(preopened) is sqlite3.Connection
    scratch = worker_protocol._ControlledScratch(
        capability,
        contract=contract,
        controller_phase_audits=audits,
    )

    def forbid_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise AssertionError("claimed scratch must use its launcher-opened connection")

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", forbid_connect)
    connection = scratch.create_sqlite_connection("binding-index.sqlite3")
    assert connection is preopened
    assert connection.execute("PRAGMA application_id").fetchone() == (
        worker_protocol._ANONYMOUS_SQLITE_APPLICATION_ID,
    )
    held = scratch._files["binding-index.sqlite3"]
    assert int.from_bytes(os.pread(held.fileno(), 4, 68), "big") == (
        worker_protocol._ANONYMOUS_SQLITE_APPLICATION_ID
    )
    connection.close()
    scratch.close()
    _assert_no_live_controlled_scratch()


def test_concurrent_same_member_claim_has_exactly_one_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = _claimed_scratch()
    held = scratch._files["binding-index.sqlite3"]
    original_fstat = worker_protocol.os.fstat
    first_observation = threading.Event()
    release_first = threading.Event()
    observation_lock = threading.Lock()
    observation_count = 0

    def delay_first_observation(descriptor: int) -> os.stat_result:
        nonlocal observation_count
        if (
            descriptor == held.fileno()
            and threading.current_thread() is not threading.main_thread()
        ):
            with observation_lock:
                observation_count += 1
                ordinal = observation_count
            if ordinal == 1:
                first_observation.set()
                release_first.wait(timeout=0.25)
            elif ordinal == 2:
                release_first.set()
        return original_fstat(descriptor)

    monkeypatch.setattr(worker_protocol.os, "fstat", delay_first_observation)
    claimed: list[BinaryIO] = []
    errors: list[BaseException] = []

    def claim() -> None:
        try:
            claimed.append(scratch._claim_file("binding-index.sqlite3"))
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    first = threading.Thread(target=claim)
    second = threading.Thread(target=claim)
    first.start()
    assert first_observation.wait(timeout=1)
    second.start()
    first.join()
    second.join()

    assert len(claimed) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], Day1BWorkerProtocolError)
    assert "already claimed" in str(errors[0])
    scratch.close()
    _assert_no_live_controlled_scratch()


def test_controlled_scratch_member_factory_roles_are_exact() -> None:
    scratch = _claimed_scratch()
    with pytest.raises(Day1BWorkerProtocolError, match="SQLite scratch member role"):
        scratch.create_sqlite_connection("object-receipts.jsonl")
    connection = scratch.create_sqlite_connection("binding-index.sqlite3")
    connection.close()
    scratch.close()

    scratch = _claimed_scratch()
    with pytest.raises(Day1BWorkerProtocolError, match="binary scratch member role"):
        scratch.create_binary_file("binding-index.sqlite3")
    file = scratch.create_binary_file("object-receipts.jsonl")
    file.close()
    scratch.close()
    _assert_no_live_controlled_scratch()


def test_sqlite_registry_accepts_a_platform_normalized_descriptor_filename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_connect = worker_protocol.sqlite3.connect

    class _NormalizedDatabaseList:
        def fetchall(self) -> list[tuple[int, str, str]]:
            return [(0, "main", "/tmp/anonymous-sqlite (deleted)")]

    class _NormalizedFilenameConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self.connection = connection

        def execute(self, statement: str, *args: object, **kwargs: object) -> object:
            cursor = self.connection.execute(statement, *args, **kwargs)
            if statement == "PRAGMA database_list":
                assert cursor.fetchall()[0][:2] == (0, "main")
                return _NormalizedDatabaseList()
            return cursor

        def __getattr__(self, name: str) -> object:
            return getattr(self.connection, name)

    def normalized_connect(database: str, **kwargs: object) -> object:
        return _NormalizedFilenameConnection(original_connect(database, **kwargs))

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", normalized_connect)
    contract = _contract()
    registry = _prepare_registry(
        _expected_f1m_objects(contract.candidate.candidate_id),
        contract=contract,
    )

    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()


def test_sqlite_launcher_rejects_an_observation_root_splice_without_foreign_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_connect = worker_protocol.sqlite3.connect
    detached = _CURRENT_CONTROLLED_SCRATCH.with_name("detached-controlled-scratch")
    observed_identity: tuple[int, int] | None = None

    def splice_root(database: str, **kwargs: object) -> sqlite3.Connection:
        nonlocal observed_identity
        visible = tuple(_CURRENT_CONTROLLED_SCRATCH.iterdir())
        assert len(visible) == 1
        before = os.stat(visible[0])
        observed_identity = before.st_dev, before.st_ino
        _CURRENT_CONTROLLED_SCRATCH.rename(detached)
        _CURRENT_CONTROLLED_SCRATCH.mkdir()
        (_CURRENT_CONTROLLED_SCRATCH / "foreign-marker").write_bytes(b"foreign")
        return original_connect(database, **kwargs)

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", splice_root)
    contract = _contract()
    with pytest.raises(sqlite3.OperationalError, match="unable to open database file"):
        _prepare_registry(
            _expected_f1m_objects(contract.candidate.candidate_id),
            contract=contract,
        )
    assert observed_identity is not None
    assert (_CURRENT_CONTROLLED_SCRATCH / "foreign-marker").read_bytes() == b"foreign"
    assert not tuple(detached.iterdir())


def test_sqlite_connection_retarget_is_rejected_by_held_file_byte_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_connect = worker_protocol.sqlite3.connect
    replacement = tmp_path / "replacement.sqlite3"
    replacement.write_bytes(b"")

    def retarget_during_connect(database: str, **kwargs: object) -> sqlite3.Connection:
        assert database.startswith("file:")
        return original_connect(str(replacement), **kwargs)

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", retarget_during_connect)
    contract = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="held file bytes"):
        _prepare_registry(
            _expected_f1m_objects(contract.candidate.candidate_id),
            contract=contract,
        )
    _assert_no_live_controlled_scratch()


def test_sqlite_scratch_opens_only_one_launcher_visible_path_before_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_connect = worker_protocol.sqlite3.connect
    attempted: list[str] = []

    def reject_descriptor_reopen(database: str, **kwargs: object) -> sqlite3.Connection:
        attempted.append(database)
        assert not database.startswith("/dev/fd/")
        return original_connect(database, **kwargs)

    monkeypatch.setattr(worker_protocol.sqlite3, "connect", reject_descriptor_reopen)
    contract = _contract()
    registry = _prepare_registry(
        _expected_f1m_objects(contract.candidate.candidate_id),
        contract=contract,
    )
    abandon_day1b_expected_f1m_registry(registry)
    _assert_no_live_controlled_scratch()
    assert len(attempted) == 1
    assert attempted[0].startswith("file:") and attempted[0].endswith("?mode=rw")


def test_controller_registry_contract_types_are_explicit_public_api() -> None:
    expected_exports = {
        "DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA",
        "DAY1B_WORKER_F1M_WINDOW_BATCH_SCHEMA",
        "DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA",
        "DAY1B_WORKER_F1M_WINDOW_CARDINALITY_SCHEMA",
        "Day1BF1MWindowBatch",
        "Day1BF1MSizeClass",
        "Day1BF1MWindowCardinality",
        "Day1BAnonymousScratchCapability",
        "Day1BWorkerPhaseReceipt",
        "canonical_day1b_expected_f1m_size_class_subroot_sha256",
        "canonical_day1b_f1m_cardinality_derivation_root_sha256",
        "canonical_day1b_f1m_query_id",
    }

    assert expected_exports <= set(worker_protocol.__all__)
    assert not any(
        "scratch" in name and ("issue" in name or "mint" in name)
        for name in worker_protocol.__all__
    )


def test_repeated_abandon_closes_every_anonymous_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[BinaryIO] = []
    original_temporary_file = worker_protocol.tempfile.TemporaryFile
    original_named_temporary_file = worker_protocol.tempfile.NamedTemporaryFile

    def capture_file(*args: object, **kwargs: object) -> BinaryIO:
        file = original_temporary_file(*args, **kwargs)
        created.append(file)
        return file

    def capture_named_file(*args: object, **kwargs: object) -> BinaryIO:
        file = original_named_temporary_file(*args, **kwargs)
        created.append(file)
        return file

    monkeypatch.setattr(worker_protocol.tempfile, "TemporaryFile", capture_file)
    monkeypatch.setattr(
        worker_protocol.tempfile,
        "NamedTemporaryFile",
        capture_named_file,
    )
    for _ in range(252):
        invocation = _issue_invocation(_contract())
        abandon_day1b_worker_invocation(invocation)
        _assert_no_live_controlled_scratch()
    assert len(created) == 504
    assert all(file.closed for file in created)


def test_registry_mint_failure_closes_fixture_owned_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _expected_f1m_objects("reference-a")
    contract = _contract(expected_f1m_objects=expected)
    captured: list[worker_protocol._ExpectedF1MRegistry] = []
    failure = RuntimeError("fixture expected registry mint failure")

    def fail_mint(registry: worker_protocol._ExpectedF1MRegistry) -> None:
        captured.append(registry)
        raise failure

    monkeypatch.setattr(worker_protocol, "_mint_expected_registry_capability", fail_mint)

    with pytest.raises(RuntimeError) as raised:
        _prepare_registry(expected, contract=contract)

    assert raised.value is failure
    assert len(captured) == 1
    registry = captured[0]
    assert registry._closed is True
    assert all(file.closed for file in registry.scratch._files.values())
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        registry.connection.execute("SELECT 1")
    _assert_no_live_controlled_scratch()


def test_invocation_mint_failure_closes_fixture_owned_spool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[worker_protocol._InvocationBinding] = []
    failure = RuntimeError("fixture invocation mint failure")

    def fail_mint(binding: worker_protocol._InvocationBinding) -> None:
        captured.append(binding)
        raise failure

    monkeypatch.setattr(worker_protocol, "_mint_invocation_capability", fail_mint)

    with pytest.raises(RuntimeError) as raised:
        _issue_invocation(_contract())

    assert raised.value is failure
    assert len(captured) == 1
    spool = captured[0].spool
    assert spool._closed is True
    assert spool._file.closed is True
    assert all(file.closed for file in spool._scratch._files.values())
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        spool._digests.execute("SELECT 1")
    _assert_no_live_controlled_scratch()


def test_receipt_builder_constructor_failure_closes_claimed_invocation_spool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract()
    invocation = _issue_invocation(contract)
    active = worker_protocol._ISSUED_INVOCATIONS[id(invocation)]
    binding = active[1]
    assert type(binding) is worker_protocol._InvocationBinding
    spool = binding.spool
    receipt_file = spool._file
    held_files = tuple(spool._scratch._files.values())
    connection = spool._digests
    failure = RuntimeError("receipt builder constructor failure")

    def fail_builder(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(worker_protocol, "_ReceiptBuilder", fail_builder)

    with pytest.raises(RuntimeError) as raised:
        consume_day1b_worker_frames(
            (_complete_transcript(contract),),
            contract=contract,
            invocation_capability=invocation,
        )

    assert raised.value is failure
    assert spool._closed is True
    assert receipt_file.closed is True
    assert all(file.closed for file in held_files)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    _assert_no_live_controlled_scratch()


def test_claimed_evidence_constructor_failure_closes_authoritative_spool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract()
    capability = _consume((_complete_transcript(contract),), contract=contract)
    active = worker_protocol._ISSUED_EVIDENCE[id(capability)]
    binding = active[1]
    assert type(binding) is worker_protocol._EvidenceBinding
    spool = binding.spool
    receipt_file = spool._file
    held_files = tuple(spool._scratch._files.values())
    connection = spool._digests
    failure = RuntimeError("claimed evidence constructor failure")

    def fail_claimed_evidence(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(
        worker_protocol,
        "Day1BClaimedWorkerEvidence",
        fail_claimed_evidence,
    )

    try:
        with pytest.raises(RuntimeError) as raised:
            claim_day1b_worker_evidence(capability)

        assert raised.value is failure
        assert id(capability) not in worker_protocol._ISSUED_EVIDENCE
        assert spool._closed is True
        assert receipt_file.closed is True
        assert all(file.closed for file in held_files)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
        _assert_no_live_controlled_scratch()
    finally:
        spool.close()


@pytest.mark.parametrize("case", ("start-above-zero", "gap", "phase-reset"))
def test_expected_f1m_ordinals_are_contiguous_from_zero_per_phase_category(
    case: str,
) -> None:
    audits = tuple(
        replace(audit, realized_query_count=3) if audit.phase in {"tuning", "heldout"} else audit
        for audit in _phase_audits()
    )
    original = _expected_f1m_objects("reference-a", object_count=3, query_count=3)
    changed: list[Day1BControllerExpectedF1MObject] = []
    for item in original:
        offset = int(
            case == "start-above-zero"
            or (case == "gap" and item.object_ordinal >= 1)
            or (case == "phase-reset" and item.phase == "held-out")
        )
        changed.append(replace(item, object_ordinal=item.object_ordinal + offset))
    expected = tuple(changed)
    contract = _contract(
        expected_f1m_objects=expected,
        controller_phase_audits=audits,
    )
    windows, window_batches = _fixture_registry_inputs(
        expected,
        candidate=contract.candidate,
        controller_phase_audits=audits,
    )

    with pytest.raises(Day1BWorkerProtocolError, match="contiguous from zero"):
        _test_only_prepare_day1b_expected_f1m_registry(
            contract=contract,
            controller_phase_audits=audits,
            window_cardinalities=iter(windows),
            window_batches=iter(window_batches),
            expected_f1m_objects=iter(expected),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
        )
    _assert_no_live_controlled_scratch()


def test_expected_f1m_registry_rejects_nonretained_routes_and_impossible_caps() -> None:
    warmup_expected = _expected_f1m_objects(
        "reference-a",
        phases=("warmup",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    warmup_contract = _contract(expected_f1m_objects=warmup_expected)
    with pytest.raises(
        Day1BWorkerProtocolError,
        match="non-retained phase|absent from controller window|query range fields",
    ):
        _issue_invocation(warmup_contract, expected_f1m_objects=warmup_expected)
    _assert_no_live_controlled_scratch()

    expected = _expected_f1m_objects("reference-a")
    base = _contract(expected_f1m_objects=expected)
    for field, cap in (
        ("serialized_object_receipt_count_maximum", len(expected) - 1),
        ("worker_frame_count_maximum", len(expected) + 6),
    ):
        contract = replace(
            base,
            resource_limits=replace(base.resource_limits, **{field: cap}),
        )
        with pytest.raises(Day1BWorkerProtocolError, match="receipt count|frame count"):
            _issue_invocation(contract, expected_f1m_objects=expected)
        _assert_no_live_controlled_scratch()


def test_predispatch_caps_cover_all_serialized_equivalence_classes() -> None:
    expected = _expected_f1m_objects("reference-a")
    expected_all = len(expected) + 3
    base = _contract(
        expected_f1m_objects=expected,
        expected_serialized_equivalence_class_count=expected_all,
    )

    for field, cap in (
        ("serialized_object_receipt_count_maximum", expected_all - 1),
        ("worker_frame_count_maximum", expected_all + 6),
    ):
        contract = replace(
            base,
            resource_limits=replace(base.resource_limits, **{field: cap}),
        )
        with pytest.raises(
            Day1BWorkerProtocolError,
            match="all serialized equivalence classes|frame count",
        ):
            _issue_invocation(contract, expected_f1m_objects=expected)
        _assert_no_live_controlled_scratch()


def test_all_serialized_count_is_exact_bound_and_not_a_boolean() -> None:
    base = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="all serialized.*F1-M"):
        replace(
            base,
            expected_serialized_equivalence_class_count=(base.expected_f1m_size_class_count - 1),
        )
    with pytest.raises(Day1BWorkerProtocolError, match="integer"):
        replace(base, expected_serialized_equivalence_class_count=True)

    changed = replace(
        base,
        expected_serialized_equivalence_class_count=(
            base.expected_serialized_equivalence_class_count + 1
        ),
    )
    assert changed.input_binding_sha256 != base.input_binding_sha256


def test_contract_rejects_full_query_replay_as_the_day1b_execution_basis() -> None:
    base = _contract()

    with pytest.raises(Day1BWorkerProtocolError, match="window-weighted"):
        replace(base, execution_basis="full-query-arrival-replay")

    assert base.input_binding_document()["execution_basis"] == (DAY1B_WORKER_EXECUTION_BASIS)


def test_successful_transcript_must_match_all_serialized_count_exactly() -> None:
    base = _contract()
    contract = replace(
        base,
        expected_serialized_equivalence_class_count=(
            base.expected_serialized_equivalence_class_count + 1
        ),
    )

    with pytest.raises(
        Day1BWorkerProtocolError,
        match="all serialized equivalence class count",
    ):
        _consume((_complete_transcript(contract),), contract=contract)
    _assert_no_live_controlled_scratch()


def test_expected_f1m_query_batches_cannot_exceed_controller_realized_queries() -> None:
    expected = _expected_f1m_objects(
        "reference-a",
        phases=("held-out",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    contract = _contract(expected_f1m_objects=expected)
    audits = tuple(
        replace(audit, realized_query_count=0) if audit.phase == "heldout" else audit
        for audit in _phase_audits()
    )

    registry = _prepare_registry(expected)
    with pytest.raises(
        Day1BWorkerProtocolError,
        match="pre-dispatch context|query totals.*controller audit",
    ):
        _test_only_issue_day1b_worker_invocation(
            contract=contract,
            controller_phase_audits=audits,
            expected_f1m_registry_capability=registry,
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            terminal_failure_code=None,
        )
    _assert_no_live_controlled_scratch()


def test_receipt_preserves_weighted_window_batch_and_range_facts() -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    registry = _prepare_registry(
        expected,
        contract=contract,
        candidate=contract.candidate,
        scratch_cap=(
            contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
        ),
    )
    descriptor = describe_day1b_expected_f1m_registry(registry)
    invocation = _test_only_issue_day1b_worker_invocation(
        contract=contract,
        controller_phase_audits=_phase_audits(),
        expected_f1m_registry_capability=registry,
        elapsed_ns=900,
        peak_resident_memory_bytes=7_000,
        peak_scratch_bytes=8_000,
        terminal_failure_code=None,
    )
    evidence = claim_day1b_worker_evidence(
        _consume(
            (_complete_transcript(contract),),
            contract=contract,
            invocation=invocation,
        )
    )
    receipt = evidence.receipt
    assert receipt.controller_f1m_window_batch_stream_sha256 == (
        descriptor.controller_f1m_window_batch_stream_sha256
    )
    assert receipt.controller_expected_f1m_phase_query_counts == (descriptor.phase_query_counts)
    assert receipt.weighted_query_range_coverage_verified is True
    assert receipt.worker_observed_f1m_materialized_binding_count == 0
    assert receipt.pre_dispatch_context_sha256 == descriptor.pre_dispatch_context_sha256
    assert receipt.controller_registered_scratch_bytes_checkpoint_maximum == (
        descriptor.controller_registered_scratch_bytes_checkpoint_maximum
    )
    assert DAY1B_WORKER_RECEIPT_SCHEMA == (
        "dynamic-cssc-publication-day1b-worker-candidate-cell-receipt-v8"
    )
    assert DAY1B_WORKER_RECEIPT_SCHEMA != DAY1B_WORKER_INPUT_BINDING_SCHEMA
    assert (
        0
        < receipt.controller_observed_registered_scratch_peak_bytes
        <= (receipt.controller_registered_scratch_bytes_checkpoint_maximum)
    )
    assert receipt.candidate.peak_scratch_bytes == 8_000
    assert receipt.anonymous_scratch_creation_isolation_verified is False
    assert receipt.controller_f1m_cardinality_derivation_root_sha256 == (
        descriptor.cardinality_derivation_root_sha256
    )
    assert receipt.controller_expected_f1m_phase_random_route_counts == (
        descriptor.phase_random_route_counts
    )
    assert receipt.controller_expected_f1m_phase_dummy_route_counts == (
        descriptor.phase_dummy_route_counts
    )
    assert receipt.production_execution_admissible is False
    document = receipt.to_document()
    assert document["f1m_controller_context_sha256"] == (contract.f1m_controller_context_sha256)
    assert document["f1m_route_coverage_sha256"] == (contract.f1m_route_coverage_sha256)
    assert document["f1m_charged_size_class_set_sha256"] == (
        contract.f1m_charged_size_class_set_sha256
    )
    assert document["controller_observed_registered_scratch_peak_bytes"] == (
        receipt.controller_observed_registered_scratch_peak_bytes
    )
    assert document["anonymous_scratch_creation_isolation_verified"] is False
    assert document["weighted_query_range_coverage_verified"] is True
    assert document["worker_observed_f1m_materialized_binding_count"] == 0
    for forbidden in (
        "pre_dispatch_ledger_identity_sha256",
        "pre_dispatch_ledger_root_before_sha256",
        "pre_dispatch_ledger_root_after_preparation_sha256",
        "persistent_random_reservations_verified",
        "prepared_commitment_batches_verified",
        "prepared_commitment_consumption_verified",
        "common_query_preparation_verified",
    ):
        assert forbidden not in document
    evidence.close()


@pytest.mark.parametrize(
    "field",
    (
        "query_id",
        "ledger_commitment_token",
        "random_reservation_transition_verified",
        "prepared_commitment_transition_verified",
    ),
)
def test_window_batch_schema_cannot_claim_per_query_or_ledger_facts(field: str) -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    windows, window_batches = _fixture_registry_inputs(
        expected,
        candidate=contract.candidate,
        controller_phase_audits=_phase_audits(),
    )

    with pytest.raises(TypeError):
        replace(window_batches[0], **{field: True})
    _assert_no_live_controlled_scratch()


def test_window_cardinality_uses_unique_output_shares_and_allows_zero_routes() -> None:
    common = {
        "phase": "held-out",
        "window_index": 2,
        "accepted_group_start": 40,
        "accepted_group_end": 100,
        "first_global_query_ordinal": 2_000_000,
        "query_count": 2,
        "version_id": "version-0001",
        "output_plan_digest": "1" * 64,
        "private_plan_digest": "2" * 64,
        "execution_binding_digest": "3" * 64,
        "expected_size_class_subroot_sha256": "4" * 64,
    }
    strong = Day1BF1MWindowCardinality(
        **common,
        f1m_policy="uniform-random-or-zero",
        returned_share_count=3,
        overlap_masked_share_count=1,
        expected_random_route_count=2,
        expected_dummy_route_count=4,
    )
    assert strong.expected_random_route_count == 2
    assert strong.expected_dummy_route_count == 4
    with pytest.raises(Day1BWorkerProtocolError, match="unique OutputShares|cardinality"):
        replace(strong, expected_random_route_count=4)

    zero_route = replace(
        strong,
        f1m_policy="overlap-only",
        returned_share_count=1,
        overlap_masked_share_count=0,
        expected_random_route_count=0,
        expected_dummy_route_count=0,
    )
    assert zero_route.query_count == 2
    assert zero_route.expected_random_route_count == 0
    with pytest.raises(Day1BWorkerProtocolError, match="unique OutputShares|cardinality"):
        replace(zero_route, expected_dummy_route_count=1)


def test_registry_rejects_cardinality_subroot_batch_range_and_input_root_splices() -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    windows, window_batches = _fixture_registry_inputs(
        expected,
        candidate=contract.candidate,
        controller_phase_audits=_phase_audits(),
    )

    def prepare(
        *,
        selected_windows: tuple[Day1BF1MWindowCardinality, ...] = windows,
        selected_window_batches: tuple[Day1BF1MWindowBatch, ...] = window_batches,
    ) -> Day1BExpectedF1MRegistryCapability:
        return _test_only_prepare_day1b_expected_f1m_registry(
            contract=contract,
            controller_phase_audits=_phase_audits(),
            window_cardinalities=iter(selected_windows),
            window_batches=iter(selected_window_batches),
            expected_f1m_objects=iter(expected),
            controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
        )

    with pytest.raises(Day1BWorkerProtocolError, match="window batch.*cover"):
        prepare(
            selected_windows=(
                replace(windows[0], expected_size_class_subroot_sha256="f" * 64),
                *windows[1:],
            )
        )
    _assert_no_live_controlled_scratch()

    with pytest.raises(Day1BWorkerProtocolError, match="query range.*exact controller window"):
        prepare(
            selected_window_batches=(
                replace(
                    window_batches[0],
                    first_global_query_ordinal=(window_batches[0].first_global_query_ordinal + 1),
                ),
                *window_batches[1:],
            )
        )
    _assert_no_live_controlled_scratch()

    with pytest.raises(Day1BWorkerProtocolError, match="window batch.*cover"):
        prepare(
            selected_window_batches=(
                replace(window_batches[0], size_class_subroot_sha256="e" * 64),
                *window_batches[1:],
            )
        )
    _assert_no_live_controlled_scratch()

    registry = prepare()
    forged_contract = replace(
        contract,
        expected_f1m_cardinality_derivation_root_sha256="d" * 64,
    )
    with pytest.raises(Day1BWorkerProtocolError, match="cardinality derivation root"):
        _test_only_issue_day1b_worker_invocation(
            contract=forged_contract,
            controller_phase_audits=_phase_audits(),
            expected_f1m_registry_capability=registry,
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            terminal_failure_code=None,
        )
    _assert_no_live_controlled_scratch()

    one_kind = _expected_f1m_objects(
        contract.candidate.candidate_id,
        phases=("held-out",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    one_kind_windows, one_kind_batches = _fixture_registry_inputs(
        one_kind,
        candidate=contract.candidate,
        controller_phase_audits=_phase_audits(),
    )
    policy_windows = tuple(
        replace(row, f1m_policy="overlap-only") if row.phase == "held-out" else row
        for row in one_kind_windows
    )
    policy_contract = replace(
        _contract(expected_f1m_objects=one_kind),
        expected_f1m_cardinality_derivation_root_sha256=(
            canonical_day1b_f1m_cardinality_derivation_root_sha256(
                window_cardinalities=policy_windows,
                window_batches=one_kind_batches,
                expected_size_classes=one_kind,
            )
        ),
    )
    policy_registry = _test_only_prepare_day1b_expected_f1m_registry(
        contract=policy_contract,
        controller_phase_audits=_phase_audits(),
        window_cardinalities=iter(policy_windows),
        window_batches=iter(one_kind_batches),
        expected_f1m_objects=iter(one_kind),
        controlled_scratch_root=_CURRENT_CONTROLLED_SCRATCH,
    )
    with pytest.raises(Day1BWorkerProtocolError, match="range/policy"):
        _test_only_issue_day1b_worker_invocation(
            contract=policy_contract,
            controller_phase_audits=_phase_audits(),
            expected_f1m_registry_capability=policy_registry,
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            terminal_failure_code=None,
        )
    _assert_no_live_controlled_scratch()


def test_candidate_strategy_policy_is_bound_and_ordinary_fixture_remains_hold() -> None:
    with pytest.raises(Day1BWorkerProtocolError, match="policy.*strategy"):
        Day1BWorkerCandidateSpec(
            candidate_id="ordinary-a",
            candidate_role="ablation",
            strategy="Packed-COO-Client-Lane",
            f1m_policy="uniform-random-or-zero",
            candidate_policy_digest="9" * 64,
            retained_phases=("held-out",),
        )
    candidate = Day1BWorkerCandidateSpec(
        candidate_id="ordinary-a",
        candidate_role="ablation",
        strategy="Packed-COO-Client-Lane",
        f1m_policy="overlap-only",
        candidate_policy_digest="8" * 64,
        retained_phases=("held-out",),
    )
    expected = _expected_f1m_objects(
        candidate.candidate_id,
        phases=("held-out",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    contract = _contract(candidate=candidate, expected_f1m_objects=expected)
    registry = _prepare_registry(expected, candidate=candidate)
    descriptor = describe_day1b_expected_f1m_registry(registry)
    assert descriptor.weighted_query_range_coverage_verified is True
    assert descriptor.phase_query_counts == (0, 0, 1)
    assert descriptor.pre_dispatch_execution_admissible is False
    assert contract.candidate.f1m_policy == "overlap-only"
    abandon_day1b_expected_f1m_registry(registry)


def test_byte_caps_are_not_inferred_from_expected_route_count() -> None:
    base = _contract()
    contract = replace(
        base,
        resource_limits=replace(
            base.resource_limits,
            serialized_payload_bytes_per_cell_maximum=1,
            serialized_object_receipt_spool_bytes_maximum=1,
        ),
    )
    invocation = _issue_invocation(contract)
    abandon_day1b_worker_invocation(invocation)
    _assert_no_live_controlled_scratch()


def test_worker_input_binding_commits_to_aggregate_f1m_summary_roots() -> None:
    contract = _contract()
    document = contract.input_binding_document()

    assert document["schema_version"].endswith("-v7")
    assert Day1BWorkerProtocolContract.from_input_binding_document(document) == contract
    assert document["f1m_controller_context_document"] == (
        contract.f1m_controller_context.to_document()
    )
    assert document["f1m_controller_context_sha256"] == (
        contract.f1m_controller_context.context_sha256
    )
    assert document["f1m_route_coverage_document"] == contract.f1m_route_coverage.to_document()
    assert document["f1m_route_coverage_sha256"] == (
        contract.f1m_route_coverage.route_coverage_sha256
    )
    assert document["f1m_charged_size_class_set_sha256"] == "c" * 64
    for field in (
        "f1m_controller_context_sha256",
        "f1m_route_coverage_sha256",
        "f1m_charged_size_class_set_sha256",
    ):
        mutated = dict(document)
        mutated[field] = "f" * 64
        assert hashlib.sha256(_canonical_bytes(mutated)).hexdigest() != (
            contract.input_binding_sha256
        )


def test_worker_input_binding_document_parser_rejects_noncanonical_preimages() -> None:
    document = _contract().input_binding_document()
    document["unexpected"] = True

    with pytest.raises(Day1BWorkerProtocolError, match="keys are not exact"):
        Day1BWorkerProtocolContract.from_input_binding_document(document)


def test_every_retained_receipt_line_uses_the_inclusive_aggregate_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract()
    evidence = claim_day1b_worker_evidence(
        _consume((_complete_transcript(contract),), contract=contract)
    )
    destination = io.BytesIO()
    evidence.copy_object_receipts_to(destination)
    evidence.close()
    lines = destination.getvalue().splitlines(keepends=True)
    documents = tuple(json.loads(line) for line in lines)

    assert lines
    assert all(
        len(line) <= worker_protocol.DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM
        for line in lines
    )
    assert {document["category"] for document in documents} >= {
        "update-ciphertexts",
        "query-f1m-random-mask-ciphertexts",
    }
    first_ordinary_line = next(
        line
        for line, document in zip(lines, documents, strict=True)
        if document["category"] == "update-ciphertexts"
    )
    monkeypatch.setattr(
        worker_protocol,
        "DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM",
        len(first_ordinary_line) - 1,
    )
    with pytest.raises(Day1BWorkerProtocolError, match="receipt exceeds.*bound"):
        _consume((_complete_transcript(contract),), contract=contract)
    _assert_no_live_controlled_scratch()


@pytest.mark.parametrize(
    "failure_code",
    (
        "wall-clock-limit-exceeded",
        "resident-memory-limit-exceeded",
        "scratch-limit-exceeded",
    ),
)
def test_resource_specific_terminal_code_is_rejected_when_observation_is_under_cap(
    failure_code: str,
) -> None:
    contract = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="under.*cap|resource.*code"):
        _consume(
            (),
            contract=contract,
            observation_overrides={"terminal_failure_code": failure_code},
        )
    _assert_no_live_controlled_scratch()


def test_launcher_terminal_missing_result_preserves_taxonomy_and_expected_size_classes() -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    evidence = claim_day1b_worker_evidence(
        _consume(
            (),
            contract=contract,
            observation_overrides={"terminal_failure_code": "candidate-missing-result"},
            expected_f1m_objects=expected,
        )
    )

    receipt = evidence.receipt
    assert receipt.candidate.phases == ()
    assert receipt.candidate.terminal_outcome == "missing"
    assert receipt.candidate.terminal_failure_code == "candidate-missing-result"
    assert receipt.candidate.receipt_origin == "controller-terminal-null-projection"
    assert receipt.controller_expected_f1m_size_class_count == len(expected)
    assert (
        receipt.controller_expected_f1m_size_class_set_sha256
        == canonical_day1b_expected_f1m_size_class_set_sha256(expected)
    )
    assert receipt.worker_observed_f1m_size_class_count == 0
    assert receipt.controller_expected_serialized_equivalence_class_count == 7
    assert receipt.object_receipt_line_count == 0
    assert receipt.worker_observed_f1m_materialized_binding_count == 0
    assert receipt.weighted_query_range_coverage_verified is True
    assert receipt.input_binding_document == contract.input_binding_document()
    assert receipt.input_binding_sha256 == contract.input_binding_sha256
    evidence.close()


@pytest.mark.parametrize("failure_point", ("seal", "flush", "fstat", "mint"))
def test_terminal_receipt_failure_closes_all_claimed_resources(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    contract = _contract()
    invocation = _issue_invocation(
        contract,
        overrides={"terminal_failure_code": "candidate-missing-result"},
    )
    spool = invocation._binding.spool
    receipt_file = spool._file
    held_files = tuple(spool._scratch._files.values())
    connection = spool._digests
    failure = OSError(f"fixture terminal {failure_point} failure")

    if failure_point == "seal":

        def fail_seal(*, required_observed_f1m_phases: tuple[str, ...]) -> None:
            assert required_observed_f1m_phases == ()
            raise failure

        monkeypatch.setattr(spool, "seal", fail_seal)
    elif failure_point == "flush":

        class _FailingFlushFile:
            def flush(self) -> None:
                raise failure

            def close(self) -> None:
                receipt_file.close()

        spool._file = _FailingFlushFile()  # type: ignore[assignment]
    elif failure_point == "fstat":
        original_fstat = worker_protocol.os.fstat
        held_descriptors = {file.fileno() for file in held_files}

        def fail_fstat(descriptor: int) -> os.stat_result:
            if descriptor in held_descriptors:
                raise failure
            return original_fstat(descriptor)

        monkeypatch.setattr(worker_protocol.os, "fstat", fail_fstat)
    else:

        def fail_mint(*_args: object, **_kwargs: object) -> None:
            raise failure

        monkeypatch.setattr(worker_protocol, "_mint_evidence_capability", fail_mint)

    with pytest.raises(OSError) as raised:
        consume_day1b_worker_frames(
            (),
            contract=contract,
            invocation_capability=invocation,
        )

    assert raised.value is failure
    assert spool._closed is True
    assert receipt_file.closed is True
    assert all(file.closed for file in held_files)
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")
    _assert_no_live_controlled_scratch()


def test_window_audit_requires_strictly_increasing_exact_time() -> None:
    with pytest.raises(Day1BWorkerProtocolError, match="start.*end|time.*increasing"):
        canonical_day1b_worker_window_audit_bytes(
            index=0,
            phase="warmup",
            accepted_group_start=0,
            accepted_group_end=1,
            start_time=Fraction(1),
            end_time=Fraction(1),
            set_count=0,
            updates=(),
            query_count=1,
            reason="query",
        )


def test_truncated_payload_is_a_global_protocol_error() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)

    with pytest.raises(Day1BWorkerProtocolError, match="truncated"):
        _consume((transcript[:-1],), contract=contract)


def test_category_order_and_object_ordinals_are_closed() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    bad = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, payload: ({**header, "category": "evaluation-keys"}, payload),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="category order|object ordinal"):
        _consume((bad,), contract=contract)


def test_candidate_failure_is_retained_as_failed_without_partial_quantities() -> None:
    contract = _contract()
    frames = [_frame(0, "cell-start", input_binding=contract.input_binding_document())]
    frames.append(
        _frame(
            1,
            "candidate-start",
            candidate_id="reference-a",
            candidate_role="reference",
        )
    )
    sequence = 2
    for audit, phase in zip(_phase_audits(), ("warmup", "tuning-prefix", "held-out"), strict=True):
        retained = phase != "warmup"
        frames.append(
            _frame(
                sequence,
                "phase-result",
                candidate_id="reference-a",
                phase=phase,
                outcome="failed" if retained else "complete",
                failure_code="candidate-execution-failed" if retained else None,
                retained_measurement=retained,
                update_primitive_counts=None,
                query_primitive_counts=None,
                serialized_category_object_counts=None,
                phase_audit=audit.to_document(),
            )
        )
        sequence += 1
    frames.extend(
        (
            _frame(
                sequence,
                "candidate-result",
                candidate_id="reference-a",
                elapsed_ns=900,
                peak_resident_memory_bytes=7_000,
                peak_scratch_bytes=8_000,
                candidate_retry_count=0,
                state_reset_count=0,
            ),
            _frame(sequence + 1, "cell-end", candidate_count=1),
        )
    )
    transcript = b"".join(frames)

    evidence = claim_day1b_worker_evidence(_consume((transcript,), contract=contract))
    receipt = evidence.receipt

    retained = tuple(phase for phase in receipt.candidate.phases if phase.retained_measurement)
    assert [phase.outcome for phase in retained] == ["failed", "failed"]
    assert all(phase.update_primitive_counts is None for phase in retained)
    assert all(phase.serialized_categories is None for phase in retained)
    evidence.close()


@pytest.mark.parametrize(
    ("outcome", "failure_code"),
    (
        ("timeout", "candidate-timeout"),
        ("infeasible", "candidate-infeasible"),
        ("missing", "candidate-missing-result"),
        ("infeasible", "resident-memory-limit-exceeded"),
    ),
)
def test_worker_cannot_self_report_controller_terminal_taxonomy(
    outcome: str,
    failure_code: str,
) -> None:
    contract = _contract()
    transcript = _outcome_transcript(
        contract,
        outcomes=(
            ("complete", None),
            ("complete", None),
            (outcome, failure_code),
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controller-only|worker.*failed"):
        _consume((transcript,), contract=contract)


def test_heldout_cannot_complete_after_tuning_failure() -> None:
    contract = _contract()
    transcript = _outcome_transcript(
        contract,
        outcomes=(
            ("complete", None),
            ("failed", "candidate-execution-failed"),
            ("complete", None),
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="earlier phase failure"):
        _consume((transcript,), contract=contract)


@pytest.mark.parametrize(
    ("field", "value", "failure_code"),
    (
        ("elapsed_ns", 1_001, "wall-clock-limit-exceeded"),
        ("peak_resident_memory_bytes", 10_001, "resident-memory-limit-exceeded"),
        ("peak_scratch_bytes", 20_001, "scratch-limit-exceeded"),
    ),
)
def test_resource_limit_is_a_per_candidate_failed_outcome(
    field: str,
    value: int,
    failure_code: str,
) -> None:
    contract = _contract()
    evidence = claim_day1b_worker_evidence(
        _consume(
            (),
            contract=contract,
            observation_overrides={field: value, "terminal_failure_code": failure_code},
        )
    )
    receipt = evidence.receipt

    candidate = receipt.candidate
    assert candidate.terminal_failure_code == failure_code
    expected_outcome = "timeout" if field == "elapsed_ns" else "infeasible"
    assert candidate.phases == ()
    assert candidate.terminal_outcome == expected_outcome
    assert receipt.worker_declared_phase_audits_match_controller_schedule_audits is False
    assert receipt.runtime_state_continuity_verified is False
    destination = io.BytesIO()
    evidence.copy_object_receipts_to(destination)
    assert receipt.object_receipt_line_count == 0
    assert b'"candidate_id":"reference-a"' not in destination.getvalue()
    evidence.close()


def test_worker_cannot_change_input_binding_or_candidate_order() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    forged_binding = _rewrite_first_frame(
        transcript,
        "cell-start",
        lambda header, payload: (
            {
                **header,
                "input_binding": {
                    **header["input_binding"],
                    "trace_manifest_sha256": "f" * 64,
                },
            },
            payload,
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="input binding"):
        _consume((forged_binding,), contract=contract)

    wrong_candidate = _rewrite_first_frame(
        transcript,
        "candidate-start",
        lambda header, payload: ({**header, "candidate_id": "reference-b"}, payload),
    )
    with pytest.raises(Day1BWorkerProtocolError, match="candidate"):
        _consume((wrong_candidate,), contract=contract)


def test_worker_report_must_match_controller_owned_observation() -> None:
    contract = _contract()

    with pytest.raises(Day1BWorkerProtocolError, match="controller-owned observations"):
        _consume(
            (_complete_transcript(contract),),
            contract=contract,
            observation_overrides={"elapsed_ns": 899},
        )


def test_json_booleans_cannot_alias_protocol_integers() -> None:
    one_candidate = _contract()
    transcript = _complete_transcript(one_candidate)
    attacks = (
        _rewrite_first_frame(
            transcript,
            "cell-start",
            lambda header, payload: ({**header, "sequence": False}, payload),
        ),
        _rewrite_first_frame(
            transcript,
            "cell-end",
            lambda header, payload: ({**header, "candidate_count": True}, payload),
        ),
        _rewrite_first_frame(
            transcript,
            "phase-result",
            lambda header, payload: (
                {
                    **header,
                    "serialized_category_object_counts": [True, 0, 1, 1, 1],
                },
                payload,
            ),
            predicate=lambda header: header["phase"] == "tuning-prefix",
        ),
        _rewrite_first_frame(
            transcript,
            "cell-start",
            lambda header, payload: (
                {
                    **header,
                    "input_binding": {
                        **header["input_binding"],
                        "phase_ranges": [
                            {
                                **header["input_binding"]["phase_ranges"][0],
                                "accepted_group_start": False,
                            },
                            *header["input_binding"]["phase_ranges"][1:],
                        ],
                    },
                },
                payload,
            ),
        ),
    )

    for attack in attacks:
        with pytest.raises(Day1BWorkerProtocolError, match="integer|count|input binding"):
            _consume((attack,), contract=one_candidate)


def test_controller_enums_reject_unhashable_values_as_protocol_errors() -> None:
    base = _contract()
    for field, value in (("phase", []), ("category", {})):
        binding = _expected_f1m_objects("reference-a")[0]
        with pytest.raises(Day1BWorkerProtocolError, match="phase|category"):
            replace(binding, **{field: value})

    with pytest.raises(Day1BWorkerProtocolError, match="F1-M size-class categories"):
        replace(base, f1m_size_class_categories=([],))


@pytest.mark.parametrize("forged", ([], {}))
def test_unhashable_worker_enum_values_are_protocol_errors(forged: object) -> None:
    contract = _contract()
    transcript = _rewrite_first_frame(
        _complete_transcript(contract),
        "phase-result",
        lambda header, payload: ({**header, "outcome": forged}, payload),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="outcome|enum|worker phase"):
        _consume((transcript,), contract=contract)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        ((0).to_bytes(4, "big"), "header length"),
        ((DAY1B_WORKER_MAX_HEADER_BYTES + 1).to_bytes(4, "big"), "header length"),
    ),
)
def test_header_length_has_a_small_fixed_bound(raw: bytes, message: str) -> None:
    with pytest.raises(Day1BWorkerProtocolError, match=message):
        _consume((raw,), contract=_contract())


@pytest.mark.parametrize(
    ("limit_field", "limit", "message"),
    (
        ("serialized_object_receipt_count_maximum", 1, "receipt count"),
        ("serialized_object_receipt_spool_bytes_maximum", 1, "receipt spool"),
        ("serialized_payload_bytes_per_cell_maximum", 1, "payload bytes"),
        ("worker_frame_count_maximum", 1, "frame count"),
    ),
)
def test_every_streaming_scale_limit_is_policy_bound_and_fail_closed(
    limit_field: str,
    limit: int,
    message: str,
) -> None:
    base = _contract()
    contract = replace(
        base,
        resource_limits=replace(base.resource_limits, **{limit_field: limit}),
    )

    with pytest.raises(Day1BWorkerProtocolError, match=message):
        _consume((_complete_transcript(contract),), contract=contract)


def test_trailing_frame_after_cell_end_is_rejected() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract) + _frame(99, "cell-end", candidate_count=2)

    with pytest.raises(Day1BWorkerProtocolError, match="trailing|sequence"):
        _consume((transcript,), contract=contract)


def test_controller_owned_phase_audit_and_no_reset_are_exact() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    forged_audit = _rewrite_first_frame(
        transcript,
        "phase-result",
        lambda header, payload: (
            {
                **header,
                "phase_audit": {**header["phase_audit"], "realized_window_count": 3},
            },
            payload,
        ),
    )
    reset = _rewrite_first_frame(
        transcript,
        "candidate-result",
        lambda header, payload: ({**header, "state_reset_count": 1}, payload),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controller.*audit|phase audit"):
        _consume((forged_audit,), contract=contract)
    with pytest.raises(Day1BWorkerProtocolError, match="reset"):
        _consume((reset,), contract=contract)

    evidence = claim_day1b_worker_evidence(_consume((transcript,), contract=contract))
    document = evidence.receipt.to_document()
    assert document["worker_declared_phase_audits_match_controller_schedule_audits"] is True
    assert document["runtime_state_continuity_verified"] is False
    assert "worker_schedule_consumption_verified" not in document
    evidence.close()


def test_query_primitive_vector_must_match_controller_realized_query_presence() -> None:
    contract = _contract()
    no_query_primitives = _rewrite_first_frame(
        _complete_transcript(contract),
        "phase-result",
        lambda header, payload: ({**header, "query_primitive_counts": [0, 0]}, payload),
        predicate=lambda header: header["phase"] == "tuning-prefix",
    )

    with pytest.raises(Day1BWorkerProtocolError, match="primitive vector.*realized query"):
        _consume((no_query_primitives,), contract=contract)
    _assert_no_live_controlled_scratch()


def test_f1m_objects_require_bound_multiplicity_and_allow_representative_payload_reuse() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    multiplicity = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, payload: ({**header, "multiplicity": 2}, payload),
        predicate=lambda header: header["category"] == "query-f1m-random-mask-ciphertexts",
    )

    with pytest.raises(Day1BWorkerProtocolError, match="expected weighted size class"):
        _consume((multiplicity,), contract=contract)

    marker = b"reference-a:tuning-prefix:mask"
    duplicate = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, _payload: (header, marker),
        predicate=lambda header: (
            header["candidate_id"] == "reference-a"
            and header["phase"] == "held-out"
            and header["category"] == "query-f1m-random-mask-ciphertexts"
        ),
    )
    evidence = claim_day1b_worker_evidence(_consume((duplicate,), contract=contract))
    assert evidence.receipt.worker_observed_f1m_materialized_binding_count == 0
    evidence.close()


def test_f1m_representative_payload_digest_may_repeat_across_size_classes() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    duplicate_across_categories = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, _payload: (
            header,
            b"reference-a:tuning-prefix:mask",
        ),
        predicate=lambda header: (
            header["candidate_id"] == "reference-a"
            and header["phase"] == "tuning-prefix"
            and header["category"] == "query-f1m-encrypted-zero-dummy-ciphertexts"
        ),
    )

    evidence = claim_day1b_worker_evidence(
        _consume((duplicate_across_categories,), contract=contract)
    )
    assert evidence.receipt.worker_observed_f1m_materialized_binding_count == 0
    evidence.close()


def test_f1m_window_equivalence_class_charges_exact_query_multiplicity() -> None:
    audits = tuple(replace(audit, realized_query_count=3) for audit in _phase_audits())
    expected = tuple(replace(item, multiplicity=3) for item in _expected_f1m_objects("reference-a"))
    contract = _contract(
        expected_f1m_objects=expected,
        expected_serialized_equivalence_class_count=len(expected) + 3,
        controller_phase_audits=audits,
    )
    transcript = _complete_transcript(
        contract,
        controller_phase_audits=audits,
        expected_f1m_objects=expected,
    )

    with claim_day1b_worker_evidence(
        _consume(
            (transcript,),
            contract=contract,
            expected_f1m_objects=expected,
            controller_phase_audits=audits,
        )
    ) as evidence:
        receipt = evidence.receipt
        assert receipt.worker_observed_f1m_size_class_count == len(expected)
        assert receipt.controller_expected_f1m_phase_query_counts == (0, 3, 3)
        assert receipt.controller_expected_f1m_phase_random_route_counts == (0, 3, 3)
        assert receipt.controller_expected_f1m_phase_dummy_route_counts == (0, 3, 3)
        for phase in receipt.candidate.phases:
            if not phase.retained_measurement:
                continue
            assert phase.serialized_categories is not None
            f1m = {
                category.category: category
                for category in phase.serialized_categories
                if category.category in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
            }
            assert {category.protocol_object_count for category in f1m.values()} == {3}
            assert {
                category.serialization_equivalence_class_count for category in f1m.values()
            } == {1}


def test_weighted_f1m_window_batch_has_only_range_and_size_class_facts() -> None:
    contract = _contract()
    expected = _expected_f1m_objects(contract.candidate.candidate_id)
    _windows, window_batches = _fixture_registry_inputs(
        expected,
        candidate=contract.candidate,
        controller_phase_audits=_phase_audits(),
    )

    document = window_batches[0].to_document()
    assert set(document) == {
        "execution_binding_digest",
        "first_global_query_ordinal",
        "output_plan_digest",
        "phase",
        "private_plan_digest",
        "query_count",
        "schema_version",
        "size_class_subroot_sha256",
        "version_id",
        "window_index",
    }
    assert not {
        "query_id",
        "ledger_commitment_token",
        "reservation_set_root_sha256",
        "random_reservation_transition_verified",
        "prepared_commitment_transition_verified",
    } & set(document)


def test_f1m_size_class_cannot_be_spliced_across_window_identities() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    reused_binding = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, payload: (
            {
                **header,
                "f1m_size_class": _f1m_size_class(
                    candidate_id="reference-a",
                    phase="tuning-prefix",
                    category="query-f1m-random-mask-ciphertexts",
                    ordinal=0,
                ),
            },
            payload,
        ),
        predicate=lambda header: (
            header["candidate_id"] == "reference-a"
            and header["phase"] == "held-out"
            and header["category"] == "query-f1m-random-mask-ciphertexts"
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="F1-M.*(expected|reused)"):
        _consume((reused_binding,), contract=contract)


def test_f1m_worker_size_class_must_match_controller_expected_descriptor() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    spliced = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, payload: (
            {
                **header,
                "f1m_size_class": {
                    **header["f1m_size_class"],
                    "output_plan_digest": "f" * 64,
                },
            },
            payload,
        ),
        predicate=lambda header: header["category"] == "query-f1m-random-mask-ciphertexts",
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controller.*expected|size class"):
        _consume((spliced,), contract=contract)


def test_f1m_controller_expected_route_set_rejects_worker_omission_and_extra() -> None:
    base_expected = _expected_f1m_objects("reference-a")
    missing_from_controller = base_expected[1:]
    extra_contract = _contract(expected_f1m_objects=missing_from_controller)
    with pytest.raises(
        Day1BWorkerProtocolError,
        match="unexpected.*F1-M|expected.*weighted size class",
    ):
        _consume(
            (_complete_transcript(extra_contract),),
            contract=extra_contract,
            expected_f1m_objects=missing_from_controller,
        )

    additional = _expected_f1m_objects(
        "reference-a",
        phases=("held-out",),
        object_count=2,
    )[-2:]
    expected_with_unobserved = base_expected + additional
    omitted_contract = _contract(expected_f1m_objects=expected_with_unobserved)
    with pytest.raises(
        Day1BWorkerProtocolError,
        match="missing.*F1-M|expected.*unobserved|query range fields|cardinality",
    ):
        _consume(
            (_complete_transcript(omitted_contract),),
            contract=omitted_contract,
            expected_f1m_objects=expected_with_unobserved,
        )


def test_controller_expected_size_class_requires_shared_query_range() -> None:
    expected = list(_expected_f1m_objects("reference-a"))
    dummy = expected[1]
    document = dummy.to_document()
    document["first_global_query_ordinal"] = 1_000_001
    expected[1] = Day1BControllerExpectedF1MObject.from_document(document)

    closed = tuple(expected)
    contract = _contract(expected_f1m_objects=closed)
    with pytest.raises(Day1BWorkerProtocolError, match="query range|batch.*fields"):
        _issue_invocation(contract, expected_f1m_objects=closed)


def test_f1m_size_classes_pair_by_explicit_query_range_not_query_identity() -> None:
    mask = _expected_f1m_objects(
        "reference-a",
        phases=("tuning-prefix",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )[0]
    dummy = _expected_f1m_objects(
        "reference-a",
        phases=("tuning-prefix",),
        object_count=2,
        categories=("query-f1m-encrypted-zero-dummy-ciphertexts",),
    )[1]
    spliced_dummy = replace(
        dummy,
        object_ordinal=0,
        first_global_query_ordinal=mask.first_global_query_ordinal,
    )
    expected = (mask, spliced_dummy)
    contract = _contract(expected_f1m_objects=expected)

    invocation = _issue_invocation(contract, expected_f1m_objects=expected)
    abandon_day1b_worker_invocation(invocation)


def test_expected_f1m_set_hash_streams_the_exact_canonical_closed_document() -> None:
    expected = _expected_f1m_objects("reference-a")
    closed_document = {
        "schema_version": (
            "dynamic-cssc-publication-day1b-controller-expected-f1m-size-class-set-v3"
        ),
        "objects": [item.to_document() for item in expected],
    }
    assert (
        canonical_day1b_expected_f1m_size_class_set_sha256(expected)
        == hashlib.sha256(_canonical_bytes(closed_document)).hexdigest()
    )


def test_weighted_size_classes_may_share_representative_identity_without_no_reuse_claim() -> None:
    heldout_mask = _expected_f1m_objects(
        "reference-a",
        phases=("held-out",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )[0]
    closed = (
        heldout_mask,
        replace(
            heldout_mask,
            object_ordinal=1,
        ),
    )
    contract = _contract(expected_f1m_objects=closed)
    invocation = _issue_invocation(contract, expected_f1m_objects=closed)
    abandon_day1b_worker_invocation(invocation)
    _assert_no_live_controlled_scratch()


def test_late_phase_failure_cannot_hide_missing_routes_from_earlier_complete_phase() -> None:
    contract = _contract()
    transcript = _outcome_transcript(
        contract,
        outcomes=(
            ("complete", None),
            ("complete", None),
            ("failed", "candidate-execution-failed"),
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="complete phase.*F1-M|F1-M.*unobserved"):
        _consume((transcript,), contract=contract)


def test_one_time_inventory_is_reported_once_per_candidate_cell() -> None:
    contract = _contract()
    transcript = _complete_transcript(contract)
    repeated_one_time = _rewrite_first_frame(
        transcript,
        "serialized-object",
        lambda header, payload: (
            {**header, "category": "evaluation-keys", "f1m_size_class": None},
            payload,
        ),
        predicate=lambda header: (
            header["candidate_id"] == "reference-a"
            and header["phase"] == "held-out"
            and header["category"] == "query-f1m-encrypted-zero-dummy-ciphertexts"
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="one-time.*first retained phase"):
        _consume((repeated_one_time,), contract=contract)


def test_both_f1m_ciphertext_categories_require_size_class_descriptors() -> None:
    base = _contract()
    with pytest.raises(Day1BWorkerProtocolError, match="required.*F1-M.*size-class"):
        replace(base, f1m_size_class_categories=())
    without_random_mask = tuple(
        item
        for item in base.serialized_categories
        if item[0] != "query-f1m-random-mask-ciphertexts"
    )
    with pytest.raises(Day1BWorkerProtocolError, match="required.*F1-M.*category"):
        replace(
            base,
            serialized_categories=without_random_mask,
            f1m_size_class_categories=("query-f1m-encrypted-zero-dummy-ciphertexts",),
        )


def test_positive_query_can_have_zero_f1m_routes_when_output_plan_has_no_shares() -> None:
    contract = _contract(expected_f1m_objects=())
    transcript = _outcome_transcript(
        contract,
        outcomes=(("complete", None), ("complete", None), ("complete", None)),
    )
    nonzero_query = _rewrite_first_frame(
        transcript,
        "phase-result",
        lambda header, payload: (
            {**header, "query_primitive_counts": [1, 0]},
            payload,
        ),
        predicate=lambda header: header["phase"] == "tuning-prefix",
    )

    evidence = claim_day1b_worker_evidence(
        _consume(
            (nonzero_query,),
            contract=contract,
            expected_f1m_objects=(),
        )
    )
    tuning = evidence.receipt.candidate.phases[1]
    assert tuning.outcome == "complete"
    assert tuning.query_primitive_counts == (1, 0)
    assert evidence.receipt.controller_expected_f1m_size_class_count == 0
    evidence.close()


def test_positive_query_accepts_exact_expected_size_classes_of_only_one_f1m_kind() -> None:
    expected = _expected_f1m_objects(
        "reference-a",
        phases=("held-out",),
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    contract = _contract(expected_f1m_objects=expected)
    candidate = contract.candidate
    frames = [
        _frame(0, "cell-start", input_binding=contract.input_binding_document()),
        _frame(
            1,
            "candidate-start",
            candidate_id=candidate.candidate_id,
            candidate_role=candidate.candidate_role,
        ),
    ]
    sequence = 2
    for audit, phase in zip(
        _phase_audits(),
        ("warmup", "tuning-prefix", "held-out"),
        strict=True,
    ):
        retained = phase in candidate.retained_phases
        if phase == "held-out":
            frames.append(
                _frame(
                    sequence,
                    "serialized-object",
                    candidate_id=candidate.candidate_id,
                    phase=phase,
                    category="query-f1m-random-mask-ciphertexts",
                    object_ordinal=0,
                    multiplicity=1,
                    f1m_size_class=_f1m_size_class(
                        candidate_id=candidate.candidate_id,
                        phase=phase,
                        category="query-f1m-random-mask-ciphertexts",
                        ordinal=0,
                    ),
                    payload=b"exact-one-kind-route",
                )
            )
            sequence += 1
        frames.append(
            _frame(
                sequence,
                "phase-result",
                candidate_id=candidate.candidate_id,
                phase=phase,
                outcome="complete",
                failure_code=None,
                retained_measurement=retained,
                update_primitive_counts=[0, 0] if retained else None,
                query_primitive_counts=(
                    [1, 0] if phase == "held-out" else ([1, 0] if retained else None)
                ),
                serialized_category_object_counts=(
                    [0, 0, 1, 0, 0]
                    if phase == "held-out"
                    else ([0, 0, 0, 0, 0] if retained else None)
                ),
                phase_audit=audit.to_document(),
            )
        )
        sequence += 1
    frames.extend(
        (
            _frame(
                sequence,
                "candidate-result",
                candidate_id=candidate.candidate_id,
                elapsed_ns=900,
                peak_resident_memory_bytes=7_000,
                peak_scratch_bytes=8_000,
                candidate_retry_count=0,
                state_reset_count=0,
            ),
            _frame(sequence + 1, "cell-end", candidate_count=1),
        )
    )

    evidence = claim_day1b_worker_evidence(
        _consume(
            (b"".join(frames),),
            contract=contract,
            expected_f1m_objects=expected,
        )
    )
    heldout = evidence.receipt.candidate.phases[2]
    assert heldout.outcome == "complete"
    assert heldout.serialized_categories is not None
    assert heldout.serialized_categories[2].protocol_object_count == 1
    assert heldout.serialized_categories[3].protocol_object_count == 0
    evidence.close()


def test_controlled_scratch_is_cleaned_on_error_abandon_and_evidence_abandon() -> None:
    contract = _contract()
    invocation = _issue_invocation(contract)
    abandon_day1b_worker_invocation(invocation)
    _assert_no_live_controlled_scratch()
    with pytest.raises(Day1BWorkerProtocolError, match="absent|consumed"):
        abandon_day1b_worker_invocation(invocation)

    with pytest.raises(Day1BWorkerProtocolError, match="truncated"):
        _consume((_complete_transcript(contract)[:-1],), contract=contract)
    _assert_no_live_controlled_scratch()

    capability = _consume((_complete_transcript(contract),), contract=contract)
    abandon_day1b_worker_evidence(capability)
    _assert_no_live_controlled_scratch()
    with pytest.raises(Day1BWorkerProtocolError, match="absent|consumed"):
        abandon_day1b_worker_evidence(capability)


def test_claimed_evidence_can_close_from_another_thread_without_leaking_files() -> None:
    contract = _contract()
    evidence = claim_day1b_worker_evidence(
        _consume((_complete_transcript(contract),), contract=contract)
    )
    errors: list[BaseException] = []

    def close() -> None:
        try:
            evidence.close()
        except BaseException as error:  # pragma: no cover - asserted empty below
            errors.append(error)

    thread = threading.Thread(target=close)
    thread.start()
    thread.join()
    assert errors == []
    _assert_no_live_controlled_scratch()


def test_anonymous_scratch_close_never_deletes_a_foreign_visible_member() -> None:
    scratch = _claimed_scratch()
    member = scratch.create_binary_file("object-receipts.jsonl")
    foreign = _CURRENT_CONTROLLED_SCRATCH / "foreign-member"
    foreign.write_bytes(b"foreign-member-must-survive")

    member.close()
    scratch.close()
    assert foreign.read_bytes() == b"foreign-member-must-survive"


def test_anonymous_scratch_close_never_deletes_a_replacement_root() -> None:
    scratch = _claimed_scratch()
    member = scratch.create_binary_file("object-receipts.jsonl")
    detached = _CURRENT_CONTROLLED_SCRATCH.with_name("detached-owned-scratch")
    _CURRENT_CONTROLLED_SCRATCH.rename(detached)
    _CURRENT_CONTROLLED_SCRATCH.mkdir()
    foreign = _CURRENT_CONTROLLED_SCRATCH / "foreign-root-marker"
    foreign.write_bytes(b"foreign-root-must-survive")

    member.close()
    scratch.close()
    assert foreign.read_bytes() == b"foreign-root-must-survive"
    assert not tuple(detached.iterdir())


@pytest.mark.parametrize("kind", ("binary", "sqlite"))
def test_claimed_scratch_lifecycle_performs_no_path_mutation(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    scratch = _claimed_scratch()
    detached = _CURRENT_CONTROLLED_SCRATCH.with_name("detached-controlled-scratch")
    _CURRENT_CONTROLLED_SCRATCH.rename(detached)
    _CURRENT_CONTROLLED_SCRATCH.mkdir()
    foreign = _CURRENT_CONTROLLED_SCRATCH / "foreign-marker"
    foreign.write_bytes(b"foreign-must-survive")

    def forbid_path_mutation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("claimed scratch must not perform pathname mutation")

    monkeypatch.setattr(worker_protocol.os, "open", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "unlink", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "rename", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "replace", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "mkdir", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "rmdir", forbid_path_mutation)
    monkeypatch.setattr(worker_protocol.os, "remove", forbid_path_mutation)
    if kind == "binary":
        file = scratch.create_binary_file("object-receipts.jsonl")
        file.write(b"bound-to-held-root")
        file.close()
    else:
        connection = scratch.create_sqlite_connection("binding-index.sqlite3")
        connection.execute("CREATE TABLE bound(value INTEGER)")
        connection.close()
    scratch.close()
    assert foreign.read_bytes() == b"foreign-must-survive"
    assert not tuple(detached.iterdir())


def test_binary_scratch_duplicate_is_revalidated_against_held_inode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = _claimed_scratch()
    held = scratch._files["object-receipts.jsonl"]
    held_identity = scratch._identities["object-receipts.jsonl"]
    foreign = _anonymous_test_file()
    foreign_identity = os.fstat(foreign.fileno())
    assert (foreign_identity.st_dev, foreign_identity.st_ino) != held_identity
    original_dup = worker_protocol.os.dup
    duplicated: list[int] = []

    def retarget_duplicate(descriptor: int) -> int:
        if descriptor == held.fileno():
            result = original_dup(foreign.fileno())
            duplicated.append(result)
            return result
        return original_dup(descriptor)

    monkeypatch.setattr(worker_protocol.os, "dup", retarget_duplicate)

    with pytest.raises(Day1BWorkerProtocolError, match="identity"):
        scratch.create_binary_file("object-receipts.jsonl")

    assert len(duplicated) == 1
    with pytest.raises(OSError):
        os.fstat(duplicated[0])
    assert not foreign.closed
    foreign.close()
    scratch.close()
    _assert_no_live_controlled_scratch()


def test_controlled_scratch_cap_is_explicit_and_includes_indexes() -> None:
    base = _contract()
    contract = replace(
        base,
        resource_limits=replace(
            base.resource_limits,
            controller_registered_scratch_bytes_checkpoint_maximum=1,
        ),
    )

    with pytest.raises(Day1BWorkerProtocolError, match="controlled scratch.*cap"):
        _issue_invocation(contract)
    _assert_no_live_controlled_scratch()


def test_controlled_scratch_peak_sums_both_members_and_is_monotonic() -> None:
    scratch = _claimed_scratch()
    first = scratch._files["binding-index.sqlite3"]
    second = scratch._files["object-receipts.jsonl"]

    os.ftruncate(first.fileno(), 11)
    os.ftruncate(second.fileno(), 17)
    scratch.require_within_cap()
    assert scratch.peak_bytes == 28

    os.ftruncate(first.fileno(), 5)
    os.ftruncate(second.fileno(), 7)
    scratch.require_within_cap()
    assert scratch.peak_bytes == 28

    scratch.close()
    _assert_no_live_controlled_scratch()


def test_controlled_scratch_over_cap_records_the_observed_peak_before_failing() -> None:
    base = _contract()
    contract = replace(
        base,
        resource_limits=replace(
            base.resource_limits,
            controller_registered_scratch_bytes_checkpoint_maximum=10,
        ),
    )
    scratch = _claimed_scratch(contract=contract)
    first = scratch._files["binding-index.sqlite3"]
    second = scratch._files["object-receipts.jsonl"]

    os.ftruncate(first.fileno(), 7)
    os.ftruncate(second.fileno(), 5)
    with pytest.raises(Day1BWorkerProtocolError, match="controlled scratch.*cap"):
        scratch.require_within_cap()
    assert scratch.peak_bytes == 12

    scratch.close()
    _assert_no_live_controlled_scratch()


def test_object_receipt_copy_requires_empty_destination_and_rehashes_complete_copy() -> None:
    contract = _contract()
    evidence = claim_day1b_worker_evidence(
        _consume((_complete_transcript(contract),), contract=contract)
    )

    with pytest.raises(Day1BWorkerProtocolError, match="destination.*empty"):
        evidence.copy_object_receipts_to(io.BytesIO(b"foreign"))
    destination = io.BytesIO()
    copied = evidence.copy_object_receipts_to(destination)
    assert copied == hashlib.sha256(destination.getvalue()).hexdigest()
    assert len(destination.getvalue()) == evidence.receipt.object_receipt_byte_count
    evidence.close()
    _assert_no_live_controlled_scratch()


def test_large_object_cardinality_spools_metadata_instead_of_growing_receipt() -> None:
    object_count = 5_000
    expected = _expected_f1m_objects(
        "reference-a",
        phases=("held-out",),
        object_count=object_count,
        query_count=object_count,
        categories=("query-f1m-random-mask-ciphertexts",),
    )
    audits = tuple(
        replace(audit, realized_query_count=object_count) if audit.phase == "heldout" else audit
        for audit in _phase_audits()
    )
    contract = _contract(
        expected_f1m_objects=expected,
        controller_phase_audits=audits,
    )
    contract = replace(
        contract,
        resource_limits=replace(
            contract.resource_limits,
            controller_registered_scratch_bytes_checkpoint_maximum=100_000_000,
        ),
    )

    def chunks() -> Iterable[bytes]:
        sequence = 0
        yield _frame(sequence, "cell-start", input_binding=contract.input_binding_document())
        sequence += 1
        yield _frame(
            sequence,
            "candidate-start",
            candidate_id="reference-a",
            candidate_role="reference",
        )
        sequence += 1
        for audit, phase in zip(audits, ("warmup", "tuning-prefix", "held-out"), strict=True):
            retained = phase != "warmup"
            if phase == "held-out":
                for ordinal in range(object_count):
                    yield _frame(
                        sequence,
                        "serialized-object",
                        candidate_id="reference-a",
                        phase=phase,
                        category="query-f1m-random-mask-ciphertexts",
                        object_ordinal=ordinal,
                        multiplicity=object_count,
                        f1m_size_class=_f1m_size_class(
                            candidate_id="reference-a",
                            phase=phase,
                            category="query-f1m-random-mask-ciphertexts",
                            ordinal=ordinal,
                        ),
                        payload=ordinal.to_bytes(8, "big"),
                    )
                    sequence += 1
            yield _frame(
                sequence,
                "phase-result",
                candidate_id="reference-a",
                phase=phase,
                outcome="complete",
                failure_code=None,
                retained_measurement=retained,
                update_primitive_counts=[0, 0] if retained else None,
                query_primitive_counts=(
                    [1, 0] if phase == "held-out" else ([1, 0] if retained else None)
                ),
                serialized_category_object_counts=(
                    [0, 0, object_count, 0, 0]
                    if phase == "held-out"
                    else ([0, 0, 0, 0, 0] if retained else None)
                ),
                phase_audit=audit.to_document(),
            )
            sequence += 1
        yield _frame(
            sequence,
            "candidate-result",
            candidate_id="reference-a",
            elapsed_ns=900,
            peak_resident_memory_bytes=7_000,
            peak_scratch_bytes=8_000,
            candidate_retry_count=0,
            state_reset_count=0,
        )
        yield _frame(sequence + 1, "cell-end", candidate_count=1)

    evidence = claim_day1b_worker_evidence(
        _consume(
            chunks(),
            contract=contract,
            expected_f1m_objects=expected,
            controller_phase_audits=audits,
        )
    )
    heldout = evidence.receipt.candidate.phases[2]
    assert heldout.serialized_categories is not None
    random_masks = heldout.serialized_categories[2]
    assert random_masks.serialization_equivalence_class_count == object_count
    assert random_masks.protocol_object_count == object_count * object_count
    assert evidence.object_receipt_line_count == object_count
    assert len(_canonical_bytes(evidence.receipt.to_document())) < 20_000
    evidence.close()
    _assert_no_live_controlled_scratch()
