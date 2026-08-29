#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import multiprocessing
import os
import queue
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, replace
from pathlib import Path

import dynamic_cssc.output_plan as output_plan_module
from dynamic_cssc.cloud_execution_plan import AddF1MMask, canonical_cloud_program_bytes
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.mask_ledger import (
    ConsumedPreparedF1MCommitmentError,
    DuplicateMaskBindingError,
    PreparedF1MCommitmentError,
    SQLiteMaskBindingLedger,
)
from dynamic_cssc.output_plan import prepare_f1m_masks
from dynamic_cssc.plaintext_oracle import direct_spmv
from dynamic_cssc.strategy_state import (
    advance_strong_publication,
    decode_strong_state,
    initialize_strong_strategy,
)
from dynamic_cssc.strong_execution import (
    PreparedQueryOperand,
    StrongExecutionError,
    compile_strong_execution,
    execute_strong_plaintext,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import (
    STRONG_COMPONENT_ID,
    StrongEntry,
    advance_segmented_delta,
    decode_segmented_delta,
    initialize_segmented_delta,
)
from scripts.property_contract_spec import (
    CASE_SET_ID,
    CASE_SET_VERSION,
    CLAIMS,
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_SCOPE,
    RECORDS_SCHEMA_VERSION,
    build_frozen_manifest,
    case_set_descriptor,
)
from scripts.property_contract_spec import (
    canonical_json_bytes as spec_canonical_json_bytes,
)
from scripts.property_contract_spec import (
    canonical_junit_bytes as spec_canonical_junit_bytes,
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_FILES = {
    "cloud_execution_plan": "src/dynamic_cssc/cloud_execution_plan.py",
    "contract_spec": "scripts/property_contract_spec.py",
    "compiler": "src/dynamic_cssc/query_compiler.py",
    "cssc": "src/dynamic_cssc/cssc.py",
    "events": "src/dynamic_cssc/events.py",
    "generator": "scripts/property_contract.py",
    "mask_ledger": "src/dynamic_cssc/mask_ledger.py",
    "output_plan": "src/dynamic_cssc/output_plan.py",
    "plaintext_oracle": "src/dynamic_cssc/plaintext_oracle.py",
    "strategy_state": "src/dynamic_cssc/strategy_state.py",
    "strong_execution": "src/dynamic_cssc/strong_execution.py",
    "strong_packed_coo": "src/dynamic_cssc/strong_packed_coo.py",
    "validator": "scripts/validate_property_contract.py",
    "test_source": "tests/test_strong_property_contract.py",
}


class PropertyContractError(ValueError):
    """Raised when property-contract evidence cannot be generated or validated."""


class _CrashAfterPersistentConsumeLedger:
    """Test-only adapter that crashes after the real SQLite consume commits."""

    def __init__(self, path: str) -> None:
        self.path = path

    def reserve_all(self, bindings) -> None:  # pragma: no cover - execution never reserves
        raise AssertionError(f"unexpected reservation during crash injection: {tuple(bindings)}")

    def commit_prepared_f1m(self, commitments, **kwargs) -> str:  # pragma: no cover
        raise AssertionError(
            f"unexpected commitment during crash injection: {tuple(commitments)}, {kwargs}"
        )

    def verify_and_consume_prepared_f1m(self, commitments, **kwargs) -> None:
        SQLiteMaskBindingLedger(self.path).verify_and_consume_prepared_f1m(commitments, **kwargs)
        os._exit(23)


def _crash_burn_worker(bundle, prepared, modulus: int, ledger_path: str) -> None:
    execute_strong_plaintext(
        bundle,
        prepared,
        modulus=modulus,
        ledger=_CrashAfterPersistentConsumeLedger(ledger_path),
    )
    os._exit(91)  # pragma: no cover - the injected adapter exits first


def _concurrent_execute_worker(
    bundle,
    prepared,
    modulus: int,
    ledger_path: str,
    barrier,
    results,
) -> None:
    try:
        barrier.wait(timeout=10)
        output = execute_strong_plaintext(
            bundle,
            prepared,
            modulus=modulus,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )
        results.put(("success", tuple(output)))
    except ConsumedPreparedF1MCommitmentError:
        results.put(("consumed", ()))
    except BaseException as error:
        results.put(("error", (type(error).__name__, str(error))))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _run_git(arguments: list[str], *, context: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=_REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PropertyContractError(f"cannot {context}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PropertyContractError(f"cannot {context}: {detail or 'git command failed'}")
    return result.stdout


def _current_git_head() -> str:
    try:
        head = (
            _run_git(
                ["rev-parse", "--verify", "HEAD"],
                context="resolve current Git HEAD",
            )
            .decode("ascii")
            .strip()
        )
    except UnicodeError as error:
        raise PropertyContractError("current Git HEAD is not ASCII") from error
    if _LOWER_GIT_SHA.fullmatch(head) is None:
        raise PropertyContractError("current Git HEAD is not a full lowercase Git SHA")
    return head


def _git_blob_bytes(source_git_sha: str, relative_path: str) -> bytes:
    return _run_git(
        ["show", f"{source_git_sha}:{relative_path}"],
        context=f"read Git blob {source_git_sha}:{relative_path}",
    )


def _require_source_snapshot(source_git_sha: str) -> None:
    current_head = _current_git_head()
    if current_head != source_git_sha:
        raise PropertyContractError(
            f"source_git_sha does not equal current Git HEAD ({source_git_sha} != {current_head})"
        )
    for relative_path in _SOURCE_FILES.values():
        path = _REPOSITORY_ROOT / relative_path
        try:
            current_bytes = path.read_bytes()
        except OSError as error:
            raise PropertyContractError(
                f"cannot read required property-contract source {relative_path}: {error}"
            ) from error
        committed_bytes = _git_blob_bytes(source_git_sha, relative_path)
        if current_bytes != committed_bytes:
            raise PropertyContractError(
                f"required source {relative_path} differs from {source_git_sha}:{relative_path}"
            )


def _source_provenance() -> dict[str, object]:
    provenance = {}
    for name, relative_path in _SOURCE_FILES.items():
        path = _REPOSITORY_ROOT / relative_path
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise PropertyContractError(
                f"cannot hash required property-contract source {relative_path}: {error}"
            ) from error
        provenance[name] = {"path": relative_path, "sha256": digest}
    return provenance


def _build_inputs(case: dict[str, object]):
    dimensions = case["dimensions"]
    versions = case["versions"]
    base_spec = case["base"]
    assert isinstance(dimensions, dict)
    assert isinstance(versions, dict)
    assert isinstance(base_spec, dict)
    base = publish_component(
        {(row, column): value for row, column, value in base_spec["entries"]},
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        effective_slots=dimensions["effective_slots"],
        partition_rows=dimensions["partition_rows"],
        version_id=versions["final"],
        component_prefix=f"property-base-{case['case_id']}",
        physical_capacities=tuple(base_spec["physical_capacities"]),
    )
    delta = initialize_segmented_delta(
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        effective_slots=dimensions["effective_slots"],
        segment_width=dimensions["segment_width"],
        matrix_value_bound=dimensions["matrix_value_bound"],
        version_id=versions["initial_delta"],
    )
    for wave in case["waves"]:
        delta = advance_segmented_delta(
            delta,
            delta_updates=tuple(NetUpdate(*update) for update in wave["updates"]),
            overflow_entries=tuple(StrongEntry(*entry) for entry in wave["overflow"]),
            version_id=wave["version_id"],
        ).state
    if delta.version_id != versions["final"]:
        raise PropertyContractError("case waves do not reach the final version")
    return base, delta


def _independent_spmv(
    matrix: dict[tuple[int, int], int],
    vector: tuple[int, ...],
    *,
    rows: int,
    modulus: int,
) -> tuple[int, ...]:
    output = [0] * rows
    for (row, column), value in matrix.items():
        output[row] += value * vector[column]
    return tuple(value % modulus for value in output)


def _observation(name: str, value: object) -> dict[str, object]:
    return {"name": name, "value": value}


def _logical_sha256(logical: dict[tuple[int, int], int]) -> str:
    entries = [[row, column, value] for (row, column), value in sorted(logical.items())]
    return _sha256_bytes(spec_canonical_json_bytes(entries))


def _strong_query_compile_summary(bundle) -> dict[str, str]:
    return {
        "cloud_program_digest": bundle.cloud_program_digest,
        "output_plan_digest": bundle.output_plan_digest,
        "execution_binding_digest": bundle.execution_binding_digest,
        "private_plan_digest": bundle.private_plan_digest,
    }


def _persistent_strong_record(case: dict[str, object]) -> dict[str, object]:
    dimensions = case["dimensions"]
    policy = case["policy"]
    initial = case["initial"]
    assert isinstance(dimensions, dict)
    assert isinstance(policy, dict)
    assert isinstance(initial, dict)
    state = initialize_strong_strategy(
        {(row, column): value for row, column, value in initial["entries"]},
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        effective_slots=dimensions["effective_slots"],
        partition_rows=dimensions["partition_rows"],
        matrix_value_bound=dimensions["matrix_value_bound"],
        max_row_nnz=policy["max_row_nnz"],
        reserved_slack_beta=policy["reserved_slack_beta"],
        segment_width=dimensions["segment_width"],
    )
    initial_decoded = decode_strong_state(state)
    initial_version = {
        "ordinal": state.version_ordinal,
        "version_id": state.version_id,
    }
    waves = []
    final_compile = None
    for window_spec in case["windows"]:
        window = PublicationWindow(
            index=window_spec["index"],
            start_time=window_spec["start_time"],
            end_time=window_spec["end_time"],
            updates=tuple(NetUpdate(*update) for update in window_spec["updates"]),
            query_count=window_spec["query_count"],
            reason=window_spec["reason"],
        )
        transition = advance_strong_publication(state, window)
        state = transition.state
        decoded = decode_strong_state(state)
        page_count = (
            len(state.delta.segments) + state.delta.segments_per_page - 1
        ) // state.delta.segments_per_page
        transition_bundle = transition.execution_bundle
        if window.query_count:
            if transition_bundle is None:
                raise PropertyContractError(
                    "query-bearing persistent strong wave lost its execution bundle"
                )
            property_probe_bundle = transition_bundle
        else:
            if transition_bundle is not None or transition.output_plan is not None:
                raise PropertyContractError(
                    "zero-query persistent strong wave claimed query execution"
                )
            property_probe_bundle = compile_strong_execution(state.base, state.delta)
        final_compile = _strong_query_compile_summary(property_probe_bundle)
        waves.append(
            {
                "window_index": window.index,
                "version_ordinal": state.version_ordinal,
                "version_id": state.version_id,
                "decode_sha256": _logical_sha256(decoded),
                "segment_count": len(state.delta.segments),
                "page_count": page_count,
                "facts": asdict(transition.facts),
                "output_plan": asdict(property_probe_bundle.output_analysis),
                "cloud_counts": asdict(property_probe_bundle.cloud_counts),
                "query_compile": final_compile,
            }
        )
    if final_compile is None:  # pragma: no cover - the frozen case has windows
        raise PropertyContractError("persistent strong case must have a query window")
    return {
        "case_id": case["case_id"],
        "contract_id": "persistent-strong-transition",
        "observations": [
            _observation(
                "initial_version",
                initial_version,
            ),
            _observation("initial_decode_sha256", _logical_sha256(initial_decoded)),
            _observation("waves", waves),
            _observation("final_query_compile", final_compile),
        ],
    }


def _oracle_record(case: dict[str, object]) -> dict[str, object]:
    dimensions = case["dimensions"]
    base_spec = case["base"]
    query = case["query"]
    assert isinstance(dimensions, dict)
    assert isinstance(base_spec, dict)
    assert isinstance(query, dict)
    base, delta = _build_inputs(case)
    bundle = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    modulus = query["modulus"]
    matrix = {(row, column): value for row, column, value in base_spec["entries"]}
    matrix.update(decode_segmented_delta(delta))
    independent = _independent_spmv(
        matrix,
        vector,
        rows=dimensions["rows"],
        modulus=modulus,
    )
    public_direct = direct_spmv(
        matrix,
        vector,
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        modulus=modulus,
    )
    with tempfile.TemporaryDirectory(prefix="property-contract-oracle-") as temporary:
        ledger = SQLiteMaskBindingLedger(Path(temporary) / "ledger.sqlite3")
        prepared = prepare_strong_query(
            bundle,
            query_id=query["query_id"],
            vector=vector,
            modulus=modulus,
            ledger=ledger,
        )
        executed = execute_strong_plaintext(
            bundle,
            prepared,
            modulus=modulus,
            ledger=ledger,
        )
    if executed != public_direct or executed != independent:
        raise PropertyContractError(f"{case['case_id']}: execution disagrees with direct SpMV")
    return {
        "case_id": case["case_id"],
        "contract_id": "oracle-direct-spmv",
        "observations": [
            _observation("execute_output", list(executed)),
            _observation("direct_spmv_output", list(public_direct)),
            _observation("independent_output", list(independent)),
            _observation("matrix_entry_count", len(matrix)),
            _observation("result_ciphertexts", len(bundle.result_routes)),
        ],
    }


def _f1m_record(case: dict[str, object]) -> dict[str, object]:
    query = case["query"]
    assert isinstance(query, dict)
    base, delta = _build_inputs(case)
    bundle = compile_strong_execution(base, delta)
    multiplicity = Counter(
        logical for share in bundle.output_plan.shares for _, logical in share.slot_to_logical
    )
    overlap = sorted(logical for logical, count in multiplicity.items() if count > 1)
    overlap_set = set(overlap)
    shares = {
        (share.component_id, share.output_block_id): share for share in bundle.output_plan.shares
    }
    expected_kinds = [
        (
            "random-zero-sum"
            if any(
                logical in overlap_set
                for _, logical in shares[route.output_share_id].slot_to_logical
            )
            else "encrypted-zero-dummy"
        )
        for route in bundle.result_routes
    ]
    with tempfile.TemporaryDirectory(prefix="property-contract-f1m-") as temporary:
        ledger = SQLiteMaskBindingLedger(Path(temporary) / "ledger.sqlite3")
        prepared = prepare_strong_query(
            bundle,
            query_id=f"{query['query_id']}-f1m",
            vector=tuple(query["vector"]),
            modulus=query["modulus"],
            ledger=ledger,
        )
    actual_kinds = [operand.kind for operand in prepared.f1m_operands]
    if actual_kinds != expected_kinds:
        raise PropertyContractError(f"{case['case_id']}: F1-M classification is incorrect")
    if any(
        any(operand.values)
        for operand in prepared.f1m_operands
        if operand.kind == "encrypted-zero-dummy"
    ):
        raise PropertyContractError(f"{case['case_id']}: dummy F1-M operand is not exact zero")
    values_by_share = {
        (operand.component_id, operand.output_block_id): operand.values
        for operand in prepared.f1m_operands
    }
    for logical in overlap:
        masked_sum = sum(
            values_by_share[(share.component_id, share.output_block_id)][lane]
            for share in bundle.output_plan.shares
            for lane, mapped in share.slot_to_logical
            if mapped == logical
        )
        if masked_sum % query["modulus"]:
            raise PropertyContractError(f"{case['case_id']}: F1-M masks do not sum to zero")
    delta_mapped_lanes = sorted(
        lane
        for share in bundle.output_plan.shares
        if share.component_id == STRONG_COMPONENT_ID
        for lane, _ in share.slot_to_logical
    )
    delta_segment_starts = sorted(segment.slot_start for segment in delta.segments)
    f1m_additions = sum(isinstance(node, AddF1MMask) for node in bundle.cloud_plan.program.nodes)
    random_count = expected_kinds.count("random-zero-sum")
    dummy_count = expected_kinds.count("encrypted-zero-dummy")
    random_elements = sum(count - 1 for count in multiplicity.values() if count > 1)
    if (
        bundle.f1m_counts.random_zero_sum_ciphertexts != random_count
        or bundle.f1m_counts.encrypted_zero_dummy_ciphertexts != dummy_count
        or bundle.f1m_counts.random_elements != random_elements
        or bundle.f1m_counts.ciphertext_additions != f1m_additions
    ):
        raise PropertyContractError(f"{case['case_id']}: derived F1-M counts disagree")
    return {
        "case_id": case["case_id"],
        "contract_id": "output-plan-f1m",
        "observations": [
            _observation("overlap_coordinates", overlap),
            _observation("f1m_kinds", actual_kinds),
            _observation("random_zero_sum_ciphertexts", random_count),
            _observation("encrypted_zero_dummy_ciphertexts", dummy_count),
            _observation("mask_random_elements", random_elements),
            _observation("f1m_additions_from_dag", f1m_additions),
            _observation("delta_mapped_lanes", delta_mapped_lanes),
            _observation("delta_segment_starts", delta_segment_starts),
        ],
    }


def _global_ci_record(case: dict[str, object]) -> dict[str, object]:
    query = case["query"]
    dimensions = case["dimensions"]
    assert isinstance(query, dict)
    assert isinstance(dimensions, dict)
    base, delta = _build_inputs(case)
    bundle = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    with tempfile.TemporaryDirectory(prefix="property-contract-global-ci-") as temporary:
        ledger = SQLiteMaskBindingLedger(Path(temporary) / "ledger.sqlite3")
        prepared = prepare_strong_query(
            bundle,
            query_id=f"{query['query_id']}-global-ci",
            vector=vector,
            modulus=query["modulus"],
            ledger=ledger,
        )
    operands = {operand.ciphertext_id: operand for operand in prepared.query_operands}
    above_slot_lanes = []
    for spec in bundle.value_operand_specs:
        values = operands[spec.query_ciphertext_id].values
        for lane, global_column in enumerate(spec.global_column_indices):
            expected = vector[global_column] if global_column >= 0 else 0
            if values[lane] != expected:
                raise PropertyContractError(
                    f"{case['case_id']}: global ColumnIndex was not addressed directly"
                )
            if global_column >= dimensions["effective_slots"]:
                above_slot_lanes.append((global_column, values[lane]))
    if not above_slot_lanes:
        raise PropertyContractError(f"{case['case_id']}: no global CI above the slot count")
    max_global_ci = max(global_column for global_column, _ in above_slot_lanes)
    prepared_probe = next(
        value for global_column, value in above_slot_lanes if global_column == max_global_ci
    )
    modulo_alias = vector[max_global_ci % dimensions["effective_slots"]]
    if prepared_probe != vector[max_global_ci] or prepared_probe == modulo_alias:
        raise PropertyContractError(f"{case['case_id']}: global CI anti-alias probe failed")
    return {
        "case_id": case["case_id"],
        "contract_id": "global-ci-no-modulo",
        "observations": [
            _observation("max_global_ci", max_global_ci),
            _observation("above_slot_lane_count", len(above_slot_lanes)),
            _observation("prepared_probe_value", prepared_probe),
            _observation("source_vector_value", vector[max_global_ci]),
            _observation("modulo_alias_value", modulo_alias),
        ],
    }


def _delta_multiwave_record(case: dict[str, object]) -> dict[str, object]:
    dimensions = case["dimensions"]
    versions = case["versions"]
    assert isinstance(dimensions, dict)
    assert isinstance(versions, dict)
    delta = initialize_segmented_delta(
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        effective_slots=dimensions["effective_slots"],
        segment_width=dimensions["segment_width"],
        matrix_value_bound=dimensions["matrix_value_bound"],
        version_id=versions["initial_delta"],
    )
    observed_versions = [delta.version_id]
    segment_counts = [len(delta.segments)]
    deleted_location = None
    for wave_index, wave in enumerate(case["waves"]):
        delta = advance_segmented_delta(
            delta,
            delta_updates=tuple(NetUpdate(*update) for update in wave["updates"]),
            overflow_entries=tuple(StrongEntry(*entry) for entry in wave["overflow"]),
            version_id=wave["version_id"],
        ).state
        observed_versions.append(delta.version_id)
        segment_counts.append(len(delta.segments))
        if wave_index == 1:
            deleted_location = next(
                [segment.segment_ordinal, slot]
                for segment in delta.segments
                for slot, entry in enumerate(segment.entries)
                if entry is not None and entry.coordinate == (0, 11) and entry.value == 0
            )
    reused_location = next(
        [segment.segment_ordinal, slot]
        for segment in delta.segments
        for slot, entry in enumerate(segment.entries)
        if entry is not None and entry.coordinate == (0, 13) and entry.value == 8
    )
    modified_value = decode_segmented_delta(delta)[(0, 10)]
    if deleted_location != reused_location or modified_value != 6:
        raise PropertyContractError("multiwave delta did not reuse the frozen tombstone")
    return {
        "case_id": case["case_id"],
        "contract_id": "delta-multiwave-tombstone",
        "observations": [
            _observation("versions", observed_versions),
            _observation("segment_counts", segment_counts),
            _observation("modified_value", modified_value),
            _observation("deleted_tombstone_location", deleted_location),
            _observation("reused_entry_location", reused_location),
            _observation("reused_entry", [0, 13, 8]),
            _observation("final_active_entries", len(decode_segmented_delta(delta))),
        ],
    }


def _c128_record(case: dict[str, object], contract_id: str) -> dict[str, object]:
    _, delta = _build_inputs(case)
    if delta.segment_width != 128 or not delta.segments:
        raise PropertyContractError(f"{case['case_id']}: c=128 case is malformed")
    active_entries = len(decode_segmented_delta(delta))
    occupied = sum(entry is not None for entry in delta.segments[-1].entries)
    page_count = (len(delta.segments) + delta.segments_per_page - 1) // delta.segments_per_page
    return {
        "case_id": case["case_id"],
        "contract_id": contract_id,
        "observations": [
            _observation("segment_width", delta.segment_width),
            _observation("active_entries", active_entries),
            _observation("segment_count", len(delta.segments)),
            _observation("page_count", page_count),
            _observation("final_segment_occupied", occupied),
            _observation("final_segment_padding", delta.segment_width - occupied),
        ],
    }


def _hidden_owner_permutation_record(case: dict[str, object]) -> dict[str, object]:
    base, delta = _build_inputs(case)
    owner_permutation = (1, 0, 3, 2)
    if base.layout_spec.rows != len(owner_permutation):
        raise PropertyContractError("hidden-owner-permutation requires the frozen four-row case")
    blocks = []
    placements = []
    for block in base.blocks:
        chunks = []
        for chunk in block.chunks:
            owners = tuple(
                None if owner is None else owner_permutation[owner]
                for owner in chunk.slot_owner_rows
            )
            coordinates = tuple(
                None if coordinate is None else (owner_permutation[coordinate[0]], coordinate[1])
                for coordinate in chunk.slot_coordinates
            )
            chunks.append(replace(chunk, slot_owner_rows=owners, slot_coordinates=coordinates))
            placements.extend(
                (coordinate, (base.component_id, chunk.chunk_id, lane))
                for lane, coordinate in enumerate(coordinates)
                if coordinate is not None
            )
        blocks.append(
            replace(
                block,
                row_map=tuple(owner_permutation[row] for row in block.row_map),
                chunks=tuple(chunks),
            )
        )
    permuted_base = replace(
        base,
        blocks=tuple(blocks),
        _coordinate_slots=tuple(sorted(placements)),
        _available_slots=tuple(
            (owner_permutation[row], kind, location)
            for row, kind, location in base._available_slots
        ),
    )
    permuted_delta = replace(
        delta,
        segments=tuple(
            replace(
                segment,
                owner_row=owner_permutation[segment.owner_row],
                entries=tuple(
                    None if entry is None else replace(entry, row=owner_permutation[entry.row])
                    for entry in segment.entries
                ),
            )
            for segment in delta.segments
        ),
    )
    original = compile_strong_execution(base, delta)
    permuted = compile_strong_execution(permuted_base, permuted_delta)
    original_cloud = hashlib.sha256(
        canonical_cloud_program_bytes(original.cloud_plan.program)
    ).hexdigest()
    permuted_cloud = hashlib.sha256(
        canonical_cloud_program_bytes(permuted.cloud_plan.program)
    ).hexdigest()
    if (
        original_cloud != permuted_cloud
        or original.output_plan_digest == permuted.output_plan_digest
        or original.private_plan_digest == permuted.private_plan_digest
    ):
        raise PropertyContractError("hidden owner permutation changed the public Cloud program")
    return {
        "case_id": case["case_id"],
        "contract_id": "hidden-owner-permutation",
        "observations": [
            _observation("owner_permutation", list(owner_permutation)),
            _observation("original_cloud_program_sha256", original_cloud),
            _observation("permuted_cloud_program_sha256", permuted_cloud),
            _observation("original_output_plan_sha256", original.output_plan_digest),
            _observation("permuted_output_plan_sha256", permuted.output_plan_digest),
            _observation("original_private_plan_sha256", original.private_plan_digest),
            _observation("permuted_private_plan_sha256", permuted.private_plan_digest),
        ],
    }


def _publish_retarget_base(
    case: dict[str, object],
    *,
    column_retarget: bool = False,
    wider_capacity: bool = False,
):
    dimensions = case["dimensions"]
    versions = case["versions"]
    base_spec = case["base"]
    assert isinstance(dimensions, dict)
    assert isinstance(versions, dict)
    assert isinstance(base_spec, dict)
    entries = [list(entry) for entry in base_spec["entries"]]
    if column_retarget:
        target = next(entry for entry in entries if entry[:2] == [0, 30])
        target[1] = 31
    capacities = list(base_spec["physical_capacities"])
    if wider_capacity:
        capacities[0] = 4
    return publish_component(
        {(row, column): value for row, column, value in entries},
        rows=dimensions["rows"],
        cols=dimensions["cols"],
        effective_slots=dimensions["effective_slots"],
        partition_rows=dimensions["partition_rows"],
        version_id=versions["final"],
        component_prefix=f"property-base-{case['case_id']}",
        physical_capacities=tuple(capacities),
    )


def _retargeted_queries(bundle, vector: tuple[int, ...]):
    return tuple(
        PreparedQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in bundle.value_operand_specs
    )


def _rejection_record(case: dict[str, object], contract_id: str) -> dict[str, object]:
    query = case["query"]
    assert isinstance(query, dict)
    base, delta = _build_inputs(case)
    original = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    modulus = query["modulus"]
    with tempfile.TemporaryDirectory(prefix="property-contract-rejection-") as temporary:
        ledger = SQLiteMaskBindingLedger(Path(temporary) / "ledger.sqlite3")
        prepared = prepare_strong_query(
            original,
            query_id=f"{query['query_id']}-{contract_id}",
            vector=vector,
            modulus=modulus,
            ledger=ledger,
        )
        if contract_id == "reject-version-retarget":
            target = original
            retargeted = replace(prepared, version_id="pc-retargeted-version")
            expected_error = StrongExecutionError
            expected_message = "execution bundle binding"
            category = "prepared-version-binding"
        elif contract_id == "reject-private-plan-retarget":
            target = compile_strong_execution(
                _publish_retarget_base(case, column_retarget=True), delta
            )
            if (
                original.output_plan != target.output_plan
                or original.cloud_program_digest != target.cloud_program_digest
                or original.private_plan_digest == target.private_plan_digest
            ):
                raise PropertyContractError("private-plan retarget fixture is not orthogonal")
            retargeted = replace(
                prepared,
                private_plan_digest=target.private_plan_digest,
                query_operands=_retargeted_queries(target, vector),
            )
            expected_error = PreparedF1MCommitmentError
            expected_message = "private plan"
            category = "ledger-private-plan-binding"
        elif contract_id == "reject-cloud-dag-retarget":
            target = compile_strong_execution(
                _publish_retarget_base(case, wider_capacity=True), delta
            )
            if (
                original.output_plan != target.output_plan
                or original.private_plan_digest != target.private_plan_digest
                or original.cloud_program_digest == target.cloud_program_digest
            ):
                raise PropertyContractError("Cloud-DAG retarget fixture is not orthogonal")
            retargeted = replace(
                prepared,
                cloud_program_digest=target.cloud_program_digest,
                execution_binding_digest=target.execution_binding_digest,
            )
            expected_error = PreparedF1MCommitmentError
            expected_message = "execution binding"
            category = "ledger-cloud-dag-binding"
        elif contract_id == "reject-f1m-retarget":
            if len(prepared.f1m_operands) < 2:
                raise PropertyContractError("F1-M retarget fixture needs two results")
            target = original
            first = prepared.f1m_operands[0]
            retargeted = replace(
                prepared,
                f1m_operands=(
                    replace(first, result_id=prepared.f1m_operands[1].result_id),
                    *prepared.f1m_operands[1:],
                ),
            )
            expected_error = StrongExecutionError
            expected_message = "result binding"
            category = "prepared-f1m-result-binding"
        else:  # pragma: no cover - frozen descriptor controls the caller
            raise PropertyContractError(f"unsupported rejection contract: {contract_id}")

        try:
            execute_strong_plaintext(target, retargeted, modulus=modulus, ledger=ledger)
        except expected_error as error:
            if expected_message not in str(error):
                raise PropertyContractError(
                    f"{contract_id}: wrong rejection message: {error}"
                ) from error
            rejection_class = type(error).__name__
        else:
            raise PropertyContractError(f"{contract_id}: retargeted execution was accepted")
        original_output = execute_strong_plaintext(
            original,
            prepared,
            modulus=modulus,
            ledger=ledger,
        )
    return {
        "case_id": case["case_id"],
        "contract_id": contract_id,
        "observations": [
            _observation("rejection_class", rejection_class),
            _observation("rejection_category", category),
            _observation("original_execute_output", list(original_output)),
        ],
    }


def _prepare_ledger_case(case: dict[str, object], ledger_path: Path, suffix: str):
    query = case["query"]
    assert isinstance(query, dict)
    base, delta = _build_inputs(case)
    bundle = compile_strong_execution(base, delta)
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_strong_query(
        bundle,
        query_id=f"{query['query_id']}-{suffix}",
        vector=tuple(query["vector"]),
        modulus=query["modulus"],
        ledger=ledger,
    )
    return bundle, prepared, query["modulus"]


def _ledger_single_use_record(case: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="property-contract-ledger-once-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        bundle, prepared, modulus = _prepare_ledger_case(case, ledger_path, "ledger-once")
        first_output = execute_strong_plaintext(
            bundle,
            prepared,
            modulus=modulus,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )
        try:
            execute_strong_plaintext(
                bundle,
                prepared,
                modulus=modulus,
                ledger=SQLiteMaskBindingLedger(ledger_path),
            )
        except ConsumedPreparedF1MCommitmentError as error:
            rejection_class = type(error).__name__
        else:
            raise PropertyContractError("single-use ledger accepted a second execution")
    return {
        "case_id": case["case_id"],
        "contract_id": "ledger-single-use",
        "observations": [
            _observation("first_execute_output", list(first_output)),
            _observation("second_rejection_class", rejection_class),
            _observation("successful_consumptions", 1),
        ],
    }


def _bounded_join(process, *, context: str) -> None:
    process.join(15)
    if process.is_alive():
        process.terminate()
        process.join(5)
        raise PropertyContractError(f"{context}: child process exceeded the bounded join")


def _ledger_reservation_before_sampling_record(
    case: dict[str, object],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="property-contract-ledger-reservation-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        query = case["query"]
        assert isinstance(query, dict)
        base, delta = _build_inputs(case)
        bundle = compile_strong_execution(base, delta)
        query_id = f"{query['query_id']}-ledger-reservation"
        sampling_started = False

        def crash_during_sampling(_: int) -> int:
            nonlocal sampling_started
            sampling_started = True
            raise RuntimeError("test-only crash during first mask sample")

        original_randbelow = output_plan_module.secrets.randbelow
        output_plan_module.secrets.randbelow = crash_during_sampling
        try:
            try:
                prepare_f1m_masks(
                    bundle.output_plan,
                    query_id=query_id,
                    version_id=bundle.base.version_id,
                    modulus=query["modulus"],
                    ledger=SQLiteMaskBindingLedger(ledger_path),
                )
            except RuntimeError as error:
                if str(error) != "test-only crash during first mask sample":
                    raise
            else:
                raise PropertyContractError("sampling crash injection did not run")
        finally:
            output_plan_module.secrets.randbelow = original_randbelow
        if not sampling_started:
            raise PropertyContractError("mask sampling never started after reservation")

        draws_after_reopen = 0

        def forbidden_second_sample(_: int) -> int:
            nonlocal draws_after_reopen
            draws_after_reopen += 1
            raise AssertionError("duplicate retry sampled before rejection")

        output_plan_module.secrets.randbelow = forbidden_second_sample
        try:
            try:
                prepare_f1m_masks(
                    bundle.output_plan,
                    query_id=query_id,
                    version_id=bundle.base.version_id,
                    modulus=query["modulus"],
                    ledger=SQLiteMaskBindingLedger(ledger_path),
                )
            except DuplicateMaskBindingError:
                duplicate_after_reopen = True
            else:
                raise PropertyContractError("reopened ledger accepted a duplicate mask reservation")
        finally:
            output_plan_module.secrets.randbelow = original_randbelow
        if draws_after_reopen != 0:
            raise PropertyContractError("duplicate mask reservation reached sampling after reopen")
    return {
        "case_id": case["case_id"],
        "contract_id": "ledger-reservation-before-sampling",
        "observations": [
            _observation("reservation_committed_before_sampling", True),
            _observation("sampling_started", sampling_started),
            _observation("duplicate_after_reopen", duplicate_after_reopen),
        ],
    }


def _ledger_consume_crash_reopen_record(case: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="property-contract-ledger-crash-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        bundle, prepared, modulus = _prepare_ledger_case(case, ledger_path, "ledger-crash")
        process = multiprocessing.get_context("spawn").Process(
            target=_crash_burn_worker,
            args=(bundle, prepared, modulus, str(ledger_path)),
        )
        process.start()
        _bounded_join(process, context="crash-burn")
        if process.exitcode != 23:
            raise PropertyContractError(
                f"crash-burn child exited with unexpected code {process.exitcode}"
            )
        try:
            execute_strong_plaintext(
                bundle,
                prepared,
                modulus=modulus,
                ledger=SQLiteMaskBindingLedger(ledger_path),
            )
        except ConsumedPreparedF1MCommitmentError as error:
            rejection_class = type(error).__name__
        else:
            raise PropertyContractError("crash-reopen ledger did not burn the consumed batch")
    return {
        "case_id": case["case_id"],
        "contract_id": "ledger-consume-crash-reopen",
        "observations": [
            _observation("injection_scope", "test-only-after-persistent-consume"),
            _observation("crash_exit_code", 23),
            _observation("reopen_rejection_class", rejection_class),
            _observation("successful_consumptions", 1),
        ],
    }


def _ledger_concurrency_record(case: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="property-contract-ledger-concurrency-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        bundle, prepared, modulus = _prepare_ledger_case(case, ledger_path, "ledger-concurrent")
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(2)
        results = context.Queue()
        processes = [
            context.Process(
                target=_concurrent_execute_worker,
                args=(bundle, prepared, modulus, str(ledger_path), barrier, results),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            _bounded_join(process, context="concurrent-single-winner")
        outcomes = []
        try:
            for _ in processes:
                outcomes.append(results.get(timeout=5))
        except queue.Empty as error:
            raise PropertyContractError(
                "concurrent workers did not report bounded outcomes"
            ) from error
        finally:
            results.close()
            results.join_thread()
        errors = [details for kind, details in outcomes if kind == "error"]
        if errors:
            raise PropertyContractError(f"concurrent worker failed: {errors}")
        successes = [details for kind, details in outcomes if kind == "success"]
        consumed = sum(kind == "consumed" for kind, _ in outcomes)
        if len(successes) != 1 or consumed != 1:
            raise PropertyContractError(
                f"concurrent ledger outcomes were not single-winner: {outcomes}"
            )
    return {
        "case_id": case["case_id"],
        "contract_id": "ledger-concurrency",
        "observations": [
            _observation("worker_count", 2),
            _observation("success_count", 1),
            _observation("consumed_count", 1),
            _observation("successful_output", list(successes[0])),
        ],
    }


def _seeded_extension_record(case: dict[str, object], *, seed: int) -> dict[str, object]:
    base_spec = case["base"]
    query = case["query"]
    assert isinstance(base_spec, dict)
    assert isinstance(query, dict)
    _, delta = _build_inputs(case)
    delta_entries = [
        [row, column, value]
        for (row, column), value in sorted(decode_segmented_delta(delta).items())
    ]
    vector = query["vector"]
    return {
        "case_id": case["case_id"],
        "contract_id": "seeded-extension",
        "observations": [
            _observation("seed", seed),
            _observation("base_entries", base_spec["entries"]),
            _observation("delta_entries", delta_entries),
            _observation("vector_probes", [[index, vector[index]] for index in (0, 36, 72)]),
        ],
    }


def recompute_case_records(manifest: dict[str, object]) -> dict[str, object]:
    cases = manifest["cases"]
    assert isinstance(cases, list)
    records = []
    for case in cases:
        contracts = case["contracts"]
        if "oracle-direct-spmv" in contracts:
            records.append(_oracle_record(case))
        if "output-plan-f1m" in contracts:
            records.append(_f1m_record(case))
        if "delta-multiwave-tombstone" in contracts:
            records.append(_delta_multiwave_record(case))
        if "global-ci-no-modulo" in contracts:
            records.append(_global_ci_record(case))
        if "c128-boundary" in contracts:
            records.append(_c128_record(case, "c128-boundary"))
        if "c128-multipage" in contracts:
            records.append(_c128_record(case, "c128-multipage"))
        if "hidden-owner-permutation" in contracts:
            records.append(_hidden_owner_permutation_record(case))
        for contract_id in (
            "reject-version-retarget",
            "reject-private-plan-retarget",
            "reject-cloud-dag-retarget",
            "reject-f1m-retarget",
        ):
            if contract_id in contracts:
                records.append(_rejection_record(case, contract_id))
        if "ledger-single-use" in contracts:
            records.append(_ledger_single_use_record(case))
        if "ledger-reservation-before-sampling" in contracts:
            records.append(_ledger_reservation_before_sampling_record(case))
        if "ledger-consume-crash-reopen" in contracts:
            records.append(_ledger_consume_crash_reopen_record(case))
        if "ledger-concurrency" in contracts:
            records.append(_ledger_concurrency_record(case))
        if "seeded-extension" in contracts:
            records.append(_seeded_extension_record(case, seed=manifest["seed"]))
        if "persistent-strong-transition" in contracts:
            records.append(_persistent_strong_record(case))
    return {
        "schema_version": RECORDS_SCHEMA_VERSION,
        "case_set_id": manifest["case_set_id"],
        "case_set_version": manifest["case_set_version"],
        "seed": manifest["seed"],
        "records": records,
    }


def generate_property_contract_evidence(
    output_dir: Path,
    *,
    source_git_sha: str,
    seed: int,
) -> dict[str, object]:
    """Generate builder-only evidence without enabling any publication claim."""

    if not isinstance(output_dir, Path):
        raise PropertyContractError("output_dir must be a Path")
    if not isinstance(source_git_sha, str) or _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise PropertyContractError("source_git_sha must be a full lowercase Git SHA")
    if type(seed) is not int or seed < 0:
        raise PropertyContractError("seed must be a nonnegative strict integer")
    _require_source_snapshot(source_git_sha)
    if output_dir.exists():
        try:
            if not output_dir.is_dir() or any(output_dir.iterdir()):
                raise PropertyContractError("output_dir must be absent or empty")
        except OSError as error:
            raise PropertyContractError(f"cannot inspect output_dir: {error}") from error
    manifest = build_frozen_manifest(seed)
    manifest_bytes = spec_canonical_json_bytes(manifest)
    descriptor_bytes = spec_canonical_json_bytes(case_set_descriptor(manifest))
    records_document = recompute_case_records(manifest)
    cases = manifest["cases"]
    assert isinstance(cases, list)
    contract_count = sum(len(case["contracts"]) for case in cases)
    record_count = len(records_document["records"])
    if record_count != contract_count:
        raise PropertyContractError(
            "not every frozen contract has exactly one generated case record"
        )
    records_bytes = spec_canonical_json_bytes(records_document)
    junit_bytes = spec_canonical_junit_bytes(records_document)
    evidence = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_scope": EVIDENCE_SCOPE,
        "gate_status": "pass",
        "source_git_sha": source_git_sha,
        "seed": seed,
        "case_set": {
            "id": CASE_SET_ID,
            "version": CASE_SET_VERSION,
            "input_case_count": len(cases),
            "contract_case_count": contract_count,
            "sha256": _sha256_bytes(descriptor_bytes),
            "manifest_sha256": _sha256_bytes(manifest_bytes),
        },
        "provenance": _source_provenance(),
        "artifacts": {
            "manifest": {
                "path": "manifest.json",
                "sha256": _sha256_bytes(manifest_bytes),
            },
            "case_records": {
                "path": "case-records.json",
                "sha256": _sha256_bytes(records_bytes),
            },
            "junit": {
                "path": "junit.xml",
                "sha256": _sha256_bytes(junit_bytes),
            },
        },
        "summary": {
            "record_count": record_count,
            "failed": 0,
        },
        "claims": dict(CLAIMS),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = (
        ("manifest.json", manifest_bytes),
        ("case-records.json", records_bytes),
        ("junit.xml", junit_bytes),
        ("evidence.json", spec_canonical_json_bytes(evidence)),
    )
    try:
        for filename, content in artifacts:
            with (output_dir / filename).open("xb") as stream:
                stream.write(content)
    except OSError as error:
        raise PropertyContractError(f"cannot write property-contract artifact: {error}") from error
    return evidence


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate strong property-contract evidence")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--seed", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        generate_property_contract_evidence(
            args.output_dir,
            source_git_sha=args.source_git_sha,
            seed=args.seed,
        )
    except PropertyContractError as error:
        print(f"property-contract generation failed: {error}", file=sys.stderr)
        return 1
    print("property-contract evidence generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
