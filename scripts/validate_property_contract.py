#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
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
from typing import Any

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
    canonical_json_bytes,
    canonical_junit_bytes,
    case_set_descriptor,
)

_MANIFEST_PATH = "manifest.json"
_RECORDS_PATH = "case-records.json"
_JUNIT_PATH = "junit.xml"
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


class PropertyContractValidationError(ValueError):
    """Raised when property-contract evidence fails independent recomputation."""


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise PropertyContractValidationError(f"duplicate JSON key: {key}")
        decoded[key] = value
    return decoded


def _reject_constant(value: str) -> None:
    raise PropertyContractValidationError(f"non-standard JSON constant: {value}")


def _read_strict_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        decoded = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PropertyContractValidationError(f"cannot read strict JSON {path}: {error}") from error
    if not isinstance(decoded, dict):
        raise PropertyContractValidationError(f"{path} must contain a JSON object")
    if raw != canonical_json_bytes(decoded):
        raise PropertyContractValidationError(f"{path} is not canonical JSON")
    return decoded


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise PropertyContractValidationError(
            f"cannot hash required file {path}: {error}"
        ) from error


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
        raise PropertyContractValidationError(f"cannot {context}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PropertyContractValidationError(f"cannot {context}: {detail or 'git command failed'}")
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
        raise PropertyContractValidationError("current Git HEAD is not ASCII") from error
    if _LOWER_GIT_SHA.fullmatch(head) is None:
        raise PropertyContractValidationError("current Git HEAD is not a full lowercase Git SHA")
    return head


def _git_blob_bytes(source_git_sha: str, relative_path: str) -> bytes:
    return _run_git(
        ["show", f"{source_git_sha}:{relative_path}"],
        context=f"read Git blob {source_git_sha}:{relative_path}",
    )


def _require_source_snapshot(source_git_sha: str) -> None:
    current_head = _current_git_head()
    if current_head != source_git_sha:
        raise PropertyContractValidationError(
            "expected_source_git_sha does not equal current Git HEAD "
            f"({source_git_sha} != {current_head})"
        )
    for relative_path in _SOURCE_FILES.values():
        path = _REPOSITORY_ROOT / relative_path
        try:
            current_bytes = path.read_bytes()
        except OSError as error:
            raise PropertyContractValidationError(
                f"cannot read required property-contract source {relative_path}: {error}"
            ) from error
        committed_bytes = _git_blob_bytes(source_git_sha, relative_path)
        if current_bytes != committed_bytes:
            raise PropertyContractValidationError(
                f"required source {relative_path} differs from {source_git_sha}:{relative_path}"
            )


def _current_provenance() -> dict[str, object]:
    return {
        name: {
            "path": relative_path,
            "sha256": _sha256_file(_REPOSITORY_ROOT / relative_path),
        }
        for name, relative_path in _SOURCE_FILES.items()
    }


def _require_exact_keys(value: object, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise PropertyContractValidationError(
            f"{context} keys must exactly match the closed schema"
        )
    return value


def _validate_evidence_shape(evidence: object) -> dict[str, Any]:
    top = _require_exact_keys(
        evidence,
        {
            "schema_version",
            "evidence_scope",
            "gate_status",
            "source_git_sha",
            "seed",
            "case_set",
            "provenance",
            "artifacts",
            "summary",
            "claims",
        },
        "evidence",
    )
    _require_exact_keys(
        top["case_set"],
        {
            "id",
            "version",
            "input_case_count",
            "contract_case_count",
            "sha256",
            "manifest_sha256",
        },
        "evidence.case_set",
    )
    provenance = _require_exact_keys(top["provenance"], set(_SOURCE_FILES), "evidence.provenance")
    for name, source in provenance.items():
        _require_exact_keys(source, {"path", "sha256"}, f"evidence.provenance.{name}")
    artifacts = _require_exact_keys(
        top["artifacts"], {"manifest", "case_records", "junit"}, "evidence.artifacts"
    )
    for name, artifact in artifacts.items():
        _require_exact_keys(artifact, {"path", "sha256"}, f"evidence.artifacts.{name}")
    _require_exact_keys(top["summary"], {"record_count", "failed"}, "evidence.summary")
    _require_exact_keys(top["claims"], set(CLAIMS), "evidence.claims")
    return top


def _validate_manifest_shape(manifest: object) -> dict[str, Any]:
    top = _require_exact_keys(
        manifest,
        {"schema_version", "case_set_id", "case_set_version", "seed", "cases"},
        "manifest",
    )
    if not isinstance(top["cases"], list):
        raise PropertyContractValidationError("manifest.cases must be an array")
    for case_index, case in enumerate(top["cases"]):
        if isinstance(case, dict) and case.get("kind") == "persistent-strong-strategy":
            case_object = _require_exact_keys(
                case,
                {
                    "case_id",
                    "kind",
                    "dimensions",
                    "policy",
                    "initial",
                    "windows",
                    "contracts",
                },
                f"manifest.cases[{case_index}]",
            )
            _require_exact_keys(
                case_object["dimensions"],
                {
                    "rows",
                    "cols",
                    "effective_slots",
                    "partition_rows",
                    "segment_width",
                    "matrix_value_bound",
                },
                f"manifest.cases[{case_index}].dimensions",
            )
            _require_exact_keys(
                case_object["policy"],
                {"max_row_nnz", "reserved_slack_beta"},
                f"manifest.cases[{case_index}].policy",
            )
            _require_exact_keys(
                case_object["initial"],
                {"entries"},
                f"manifest.cases[{case_index}].initial",
            )
            if not isinstance(case_object["windows"], list):
                raise PropertyContractValidationError(
                    f"manifest.cases[{case_index}].windows must be an array"
                )
            for window_index, window in enumerate(case_object["windows"]):
                _require_exact_keys(
                    window,
                    {
                        "index",
                        "start_time",
                        "end_time",
                        "updates",
                        "query_count",
                        "reason",
                    },
                    f"manifest.cases[{case_index}].windows[{window_index}]",
                )
            if case_object["contracts"] != ["persistent-strong-transition"]:
                raise PropertyContractValidationError(
                    "persistent strong case must name its one frozen contract"
                )
            continue
        case_object = _require_exact_keys(
            case,
            {"case_id", "dimensions", "versions", "base", "waves", "query", "contracts"},
            f"manifest.cases[{case_index}]",
        )
        _require_exact_keys(
            case_object["dimensions"],
            {
                "rows",
                "cols",
                "effective_slots",
                "partition_rows",
                "segment_width",
                "matrix_value_bound",
            },
            f"manifest.cases[{case_index}].dimensions",
        )
        _require_exact_keys(
            case_object["versions"],
            {"initial_delta", "final"},
            f"manifest.cases[{case_index}].versions",
        )
        _require_exact_keys(
            case_object["base"],
            {"entries", "physical_capacities"},
            f"manifest.cases[{case_index}].base",
        )
        if not isinstance(case_object["waves"], list):
            raise PropertyContractValidationError(
                f"manifest.cases[{case_index}].waves must be an array"
            )
        for wave_index, wave in enumerate(case_object["waves"]):
            _require_exact_keys(
                wave,
                {"version_id", "updates", "overflow"},
                f"manifest.cases[{case_index}].waves[{wave_index}]",
            )
        _require_exact_keys(
            case_object["query"],
            {"query_id", "modulus", "vector"},
            f"manifest.cases[{case_index}].query",
        )
        if not isinstance(case_object["contracts"], list):
            raise PropertyContractValidationError(
                f"manifest.cases[{case_index}].contracts must be an array"
            )
    return top


def _validate_records_shape(records_document: object) -> dict[str, Any]:
    top = _require_exact_keys(
        records_document,
        {"schema_version", "case_set_id", "case_set_version", "seed", "records"},
        "case_records",
    )
    if not isinstance(top["records"], list):
        raise PropertyContractValidationError("case_records.records must be an array")
    for record_index, record in enumerate(top["records"]):
        record_object = _require_exact_keys(
            record,
            {"case_id", "contract_id", "observations"},
            f"case_records.records[{record_index}]",
        )
        if not isinstance(record_object["observations"], list):
            raise PropertyContractValidationError(
                f"case_records.records[{record_index}].observations must be an array"
            )
        for observation_index, observation in enumerate(record_object["observations"]):
            _require_exact_keys(
                observation,
                {"name", "value"},
                (f"case_records.records[{record_index}].observations[{observation_index}]"),
            )
    return top


class _CrashAfterPersistentConsumeLedger:
    """Test-only adapter that exits after the real SQLite consume commits."""

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


def _observation(name: str, value: object) -> dict[str, object]:
    return {"name": name, "value": value}


def _frozen_strong_facts(**overrides: object) -> dict[str, object]:
    facts: dict[str, object] = {
        "updates": 0,
        "query_count": 0,
        "value_patch_chunks": 0,
        "ci_patch_entries": 0,
        "ci_full_sync_entries": 0,
        "rebuilt_ciphertexts": 0,
        "delta_ciphertexts": 0,
        "delta_rebuilt_ciphertexts": 0,
        "absorbed_tombstone": 0,
        "absorbed_natural_padding": 0,
        "absorbed_reserved": 0,
        "overflow": 0,
        "overflow_rows": [],
        "patched_chunk_ids": [],
        "rebuilt_output_block_ids": [],
        "active_component_ids": ["base"],
    }
    facts.update(overrides)
    return facts


_EXPECTED_STRONG_FACTS = (
    _frozen_strong_facts(
        updates=1,
        value_patch_chunks=1,
        patched_chunk_ids=[["base", "base-h000000-c000000"]],
    ),
    _frozen_strong_facts(
        updates=1,
        value_patch_chunks=1,
        absorbed_tombstone=1,
        patched_chunk_ids=[["base", "base-h000000-c000000"]],
    ),
    _frozen_strong_facts(
        updates=2,
        value_patch_chunks=1,
        ci_patch_entries=1,
        absorbed_tombstone=1,
        patched_chunk_ids=[["base", "base-h000000-c000000"]],
    ),
    _frozen_strong_facts(
        updates=1,
        ci_full_sync_entries=4,
        delta_ciphertexts=1,
        delta_rebuilt_ciphertexts=1,
        overflow=1,
        overflow_rows=[0],
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        updates=2,
        ci_patch_entries=1,
        delta_ciphertexts=1,
        delta_rebuilt_ciphertexts=1,
        overflow=1,
        overflow_rows=[0],
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        updates=1,
        delta_ciphertexts=1,
        delta_rebuilt_ciphertexts=1,
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        updates=1,
        delta_ciphertexts=1,
        delta_rebuilt_ciphertexts=1,
        overflow=1,
        overflow_rows=[0],
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        updates=2,
        ci_patch_entries=1,
        delta_ciphertexts=1,
        delta_rebuilt_ciphertexts=1,
        overflow=1,
        overflow_rows=[0],
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        updates=3,
        ci_patch_entries=2,
        ci_full_sync_entries=4,
        delta_ciphertexts=2,
        delta_rebuilt_ciphertexts=2,
        overflow=3,
        overflow_rows=[0, 0, 0],
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
    _frozen_strong_facts(
        query_count=3,
        delta_ciphertexts=2,
        active_component_ids=["base", "strong-packed-coo-delta"],
    ),
)

_EXPECTED_STRONG_OUTPUTS = {
    "base": {
        "output_plan_digest": "bef0b30e14375de32d3d32feb35bec3640eae73ae2d8e6847900de12dcbe8db6",
        "reconstruction_mode": "concatenate",
        "result_ciphertexts": 1,
        "masked_result_ciphertexts": 0,
        "implicit_zero_coordinates": 0,
        "overlap_coordinates": 0,
        "mask_random_elements": 0,
        "mask_mapped_elements": 0,
        "client_reorder_elements": 1,
        "client_modular_additions": 0,
    },
    "one-page": {
        "output_plan_digest": "751cad47f52df6fbb02382d9336ec5fdc65f49c0b42957a4d6f607974b72d44c",
        "reconstruction_mode": "coordinate-sum",
        "result_ciphertexts": 2,
        "masked_result_ciphertexts": 2,
        "implicit_zero_coordinates": 0,
        "overlap_coordinates": 1,
        "mask_random_elements": 1,
        "mask_mapped_elements": 2,
        "client_reorder_elements": 2,
        "client_modular_additions": 1,
    },
    "two-page": {
        "output_plan_digest": "afbda9a1d5a350da90ba68ba243113ec60fb1c69d276ed6e5856f2f9b7cf57c0",
        "reconstruction_mode": "coordinate-sum",
        "result_ciphertexts": 3,
        "masked_result_ciphertexts": 3,
        "implicit_zero_coordinates": 0,
        "overlap_coordinates": 1,
        "mask_random_elements": 3,
        "mask_mapped_elements": 4,
        "client_reorder_elements": 4,
        "client_modular_additions": 3,
    },
}

_EXPECTED_STRONG_CLOUD_COUNTS = {
    "base": {
        "ciphertext_inputs": 3,
        "ciphertext_inputs_by_role": [["f1m-mask", 1], ["query", 1], ["value", 1]],
        "plaintext_masks": 1,
        "multiply_ciphertexts": 1,
        "relinearizations": 1,
        "rotations": 1,
        "rotations_by_exact_index": [[1, 1]],
        "multiply_plaintext_masks": 1,
        "add_ciphertexts": 1,
        "add_f1m_masks": 1,
        "returned_ciphertexts": 1,
    },
    "one-page": {
        "ciphertext_inputs": 6,
        "ciphertext_inputs_by_role": [["f1m-mask", 2], ["query", 2], ["value", 2]],
        "plaintext_masks": 2,
        "multiply_ciphertexts": 2,
        "relinearizations": 2,
        "rotations": 2,
        "rotations_by_exact_index": [[1, 2]],
        "multiply_plaintext_masks": 2,
        "add_ciphertexts": 2,
        "add_f1m_masks": 2,
        "returned_ciphertexts": 2,
    },
    "two-page": {
        "ciphertext_inputs": 9,
        "ciphertext_inputs_by_role": [["f1m-mask", 3], ["query", 3], ["value", 3]],
        "plaintext_masks": 3,
        "multiply_ciphertexts": 3,
        "relinearizations": 3,
        "rotations": 3,
        "rotations_by_exact_index": [[1, 3]],
        "multiply_plaintext_masks": 3,
        "add_ciphertexts": 3,
        "add_f1m_masks": 3,
        "returned_ciphertexts": 3,
    },
}

_EXPECTED_STRONG_PHASES = (
    "base",
    "base",
    "base",
    "one-page",
    "one-page",
    "one-page",
    "one-page",
    "one-page",
    "two-page",
    "two-page",
)
_EXPECTED_STRONG_SEGMENT_COUNTS = (0, 0, 0, 1, 1, 1, 1, 1, 3, 3)
_EXPECTED_STRONG_PAGE_COUNTS = (0, 0, 0, 1, 1, 1, 1, 1, 2, 2)
_EXPECTED_FINAL_STRONG_COMPILE = {
    "cloud_program_digest": "2a572b40a7e9b6a0df03cb4eed94c9dce5e5039e9ec4c3cc9d335cca3f43cf19",
    "output_plan_digest": "afbda9a1d5a350da90ba68ba243113ec60fb1c69d276ed6e5856f2f9b7cf57c0",
    "execution_binding_digest": "5409c5a556606804f7aa86640d90c04cb7f319483708082dc5558f7537f2867a",
    "private_plan_digest": "830294ce12d682e97ace7007762fbb12798e63a8fa7afdb66718d77fe3c92a77",
}


def _json_summary(value: object) -> object:
    return json.loads(canonical_json_bytes(value).decode("ascii"))


def _logical_sha256(logical: dict[tuple[int, int], int]) -> str:
    entries = [[row, column, value] for (row, column), value in sorted(logical.items())]
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def _strong_query_compile_summary(bundle) -> dict[str, str]:
    return {
        "cloud_program_digest": bundle.cloud_program_digest,
        "output_plan_digest": bundle.output_plan_digest,
        "execution_binding_digest": bundle.execution_binding_digest,
        "private_plan_digest": bundle.private_plan_digest,
    }


def _persistent_strong_record(case: dict[str, object]) -> dict[str, object]:
    """Interpret public inputs independently, then exercise the public strong seam."""

    dimensions = case["dimensions"]
    policy = case["policy"]
    initial = case["initial"]
    assert isinstance(dimensions, dict)
    assert isinstance(policy, dict)
    assert isinstance(initial, dict)
    expected = {(row, column): value for row, column, value in initial["entries"]}
    if len(expected) != len(initial["entries"]):
        raise PropertyContractValidationError("persistent strong initial entries must be unique")
    state = initialize_strong_strategy(
        dict(expected),
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
    if initial_decoded != expected or (state.version_ordinal, state.version_id) != (
        0,
        "v00000000",
    ):
        raise PropertyContractValidationError("persistent strong initialization is not exact")
    initial_version = {
        "ordinal": state.version_ordinal,
        "version_id": state.version_id,
    }

    waves = []
    version_ordinal = 0
    final_transition = None
    for wave_index, window_spec in enumerate(case["windows"]):
        window = PublicationWindow(
            index=window_spec["index"],
            start_time=window_spec["start_time"],
            end_time=window_spec["end_time"],
            updates=tuple(NetUpdate(*update) for update in window_spec["updates"]),
            query_count=window_spec["query_count"],
            reason=window_spec["reason"],
        )
        prior_state = state
        for update in window.updates:
            coordinate = (update.row, update.col)
            if expected.get(coordinate, 0) != update.before:
                raise PropertyContractValidationError(
                    "persistent strong manifest update.before is inconsistent"
                )
            if update.after == 0:
                expected.pop(coordinate, None)
            else:
                expected[coordinate] = update.after
        if window.updates:
            version_ordinal += 1
        transition = advance_strong_publication(state, window)
        state = transition.state
        decoded = decode_strong_state(state)
        if decoded != expected:
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} decoded state is not exact"
            )
        if (state.version_ordinal, state.version_id) != (
            version_ordinal,
            f"v{version_ordinal:08d}",
        ):
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} version behavior changed"
            )
        if not window.updates and state is not prior_state:
            raise PropertyContractValidationError(
                "persistent strong query-only wave advanced the persistent snapshot"
            )
        facts = _json_summary(asdict(transition.facts))
        if facts != _EXPECTED_STRONG_FACTS[wave_index]:
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} TransitionFacts changed"
            )
        segment_count = len(state.delta.segments)
        page_count = (
            segment_count + state.delta.segments_per_page - 1
        ) // state.delta.segments_per_page
        if (
            segment_count != _EXPECTED_STRONG_SEGMENT_COUNTS[wave_index]
            or page_count != _EXPECTED_STRONG_PAGE_COUNTS[wave_index]
            or transition.facts.delta_ciphertexts != page_count
        ):
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} segment/page count changed"
            )
        transition_bundle = transition.execution_bundle
        if window.query_count:
            if (
                transition_bundle is None
                or transition.output_plan != transition_bundle.output_plan
            ):
                raise PropertyContractValidationError(
                    f"persistent strong wave {wave_index} returned mismatched plans"
                )
            bundle = transition_bundle
        else:
            if transition_bundle is not None or transition.output_plan is not None:
                raise PropertyContractValidationError(
                    f"persistent strong wave {wave_index} claimed query execution"
                )
            bundle = compile_strong_execution(state.base, state.delta)
        output_summary = _json_summary(asdict(bundle.output_analysis))
        cloud_summary = _json_summary(asdict(bundle.cloud_counts))
        phase = _EXPECTED_STRONG_PHASES[wave_index]
        if output_summary != _EXPECTED_STRONG_OUTPUTS[phase]:
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} OutputPlan summary changed"
            )
        if cloud_summary != _EXPECTED_STRONG_CLOUD_COUNTS[phase]:
            raise PropertyContractValidationError(
                f"persistent strong wave {wave_index} cloud count summary changed"
            )
        query_compile = _strong_query_compile_summary(bundle)
        waves.append(
            {
                "window_index": window.index,
                "version_ordinal": state.version_ordinal,
                "version_id": state.version_id,
                "decode_sha256": _logical_sha256(expected),
                "segment_count": segment_count,
                "page_count": page_count,
                "facts": facts,
                "output_plan": output_summary,
                "cloud_counts": cloud_summary,
                "query_compile": query_compile,
            }
        )
        final_transition = transition

    if final_transition is None:  # pragma: no cover - frozen manifest has windows
        raise PropertyContractValidationError("persistent strong case has no final query compile")
    independently_compiled = compile_strong_execution(state.base, state.delta)
    if independently_compiled != final_transition.execution_bundle:
        raise PropertyContractValidationError(
            "persistent strong final query compilation is not deterministic"
        )
    final_compile = _strong_query_compile_summary(independently_compiled)
    if final_compile != _EXPECTED_FINAL_STRONG_COMPILE:
        raise PropertyContractValidationError("persistent strong final query compile changed")
    return {
        "case_id": case["case_id"],
        "contract_id": "persistent-strong-transition",
        "observations": [
            _observation("initial_version", initial_version),
            _observation("initial_decode_sha256", _logical_sha256(initial_decoded)),
            _observation("waves", waves),
            _observation("final_query_compile", final_compile),
        ],
    }


def _build_actual_inputs(case: dict[str, object]):
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
        raise PropertyContractValidationError("case waves do not reach the final version")
    return base, delta


def _interpret_logical_delta(case: dict[str, object]) -> dict[tuple[int, int], int]:
    """Interpret update waves without calling the production delta decoder."""

    logical: dict[tuple[int, int], int] = {}
    for wave in case["waves"]:
        for row, column, before, after in wave["updates"]:
            coordinate = (row, column)
            if logical.get(coordinate, 0) != before:
                raise PropertyContractValidationError(
                    f"{case['case_id']}: manifest update.before is inconsistent"
                )
            if after == 0:
                logical.pop(coordinate, None)
            else:
                logical[coordinate] = after
        for row, column, value in wave["overflow"]:
            coordinate = (row, column)
            if coordinate in logical or value == 0:
                raise PropertyContractValidationError(
                    f"{case['case_id']}: manifest overflow is inconsistent"
                )
            logical[coordinate] = value
    return logical


def _interpret_case_matrix(case: dict[str, object]) -> dict[tuple[int, int], int]:
    base_spec = case["base"]
    assert isinstance(base_spec, dict)
    matrix = {(row, column): value for row, column, value in base_spec["entries"]}
    delta = _interpret_logical_delta(case)
    if set(matrix) & set(delta):
        raise PropertyContractValidationError(
            f"{case['case_id']}: manifest base and delta coordinates overlap"
        )
    matrix.update(delta)
    return matrix


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


def _oracle_record(case: dict[str, object]) -> dict[str, object]:
    dimensions = case["dimensions"]
    query = case["query"]
    assert isinstance(dimensions, dict)
    assert isinstance(query, dict)
    base, delta = _build_actual_inputs(case)
    bundle = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    expected = _independent_spmv(
        _interpret_case_matrix(case),
        vector,
        rows=dimensions["rows"],
        modulus=query["modulus"],
    )
    with tempfile.TemporaryDirectory(prefix="property-validator-oracle-") as temporary:
        ledger = SQLiteMaskBindingLedger(Path(temporary) / "ledger.sqlite3")
        prepared = prepare_strong_query(
            bundle,
            query_id=query["query_id"],
            vector=vector,
            modulus=query["modulus"],
            ledger=ledger,
        )
        executed = execute_strong_plaintext(
            bundle,
            prepared,
            modulus=query["modulus"],
            ledger=ledger,
        )
    if executed != expected:
        raise PropertyContractValidationError(
            f"{case['case_id']}: execution disagrees with manifest-interpreted SpMV"
        )
    return {
        "case_id": case["case_id"],
        "contract_id": "oracle-direct-spmv",
        "observations": [
            _observation("execute_output", list(executed)),
            _observation("direct_spmv_output", list(expected)),
            _observation("independent_output", list(expected)),
            _observation("matrix_entry_count", len(_interpret_case_matrix(case))),
            _observation("result_ciphertexts", len(bundle.result_routes)),
        ],
    }


def _f1m_record(case: dict[str, object]) -> dict[str, object]:
    query = case["query"]
    assert isinstance(query, dict)
    base, delta = _build_actual_inputs(case)
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
    with tempfile.TemporaryDirectory(prefix="property-validator-f1m-") as temporary:
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
        raise PropertyContractValidationError(
            f"{case['case_id']}: F1-M classification is incorrect"
        )
    if any(
        any(operand.values)
        for operand in prepared.f1m_operands
        if operand.kind == "encrypted-zero-dummy"
    ):
        raise PropertyContractValidationError(
            f"{case['case_id']}: dummy F1-M operand is not exact zero"
        )
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
            raise PropertyContractValidationError(
                f"{case['case_id']}: F1-M masks do not sum to zero"
            )
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
        raise PropertyContractValidationError(f"{case['case_id']}: derived F1-M counts disagree")
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
    interpreted = _interpret_logical_delta(case)
    modified_value = interpreted[(0, 10)]
    if deleted_location != reused_location or modified_value != 6:
        raise PropertyContractValidationError("multiwave delta did not reuse the frozen tombstone")
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
            _observation("final_active_entries", len(interpreted)),
        ],
    }


def _global_ci_record(case: dict[str, object]) -> dict[str, object]:
    query = case["query"]
    dimensions = case["dimensions"]
    assert isinstance(query, dict)
    assert isinstance(dimensions, dict)
    base, delta = _build_actual_inputs(case)
    bundle = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    with tempfile.TemporaryDirectory(prefix="property-validator-global-ci-") as temporary:
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
                raise PropertyContractValidationError(
                    f"{case['case_id']}: global ColumnIndex was not addressed directly"
                )
            if global_column >= dimensions["effective_slots"]:
                above_slot_lanes.append((global_column, values[lane]))
    if not above_slot_lanes:
        raise PropertyContractValidationError(
            f"{case['case_id']}: no global CI above the slot count"
        )
    max_global_ci = max(global_column for global_column, _ in above_slot_lanes)
    prepared_probe = next(
        value for global_column, value in above_slot_lanes if global_column == max_global_ci
    )
    modulo_alias = vector[max_global_ci % dimensions["effective_slots"]]
    if prepared_probe != vector[max_global_ci] or prepared_probe == modulo_alias:
        raise PropertyContractValidationError(
            f"{case['case_id']}: global CI anti-alias probe failed"
        )
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


def _c128_record(case: dict[str, object], contract_id: str) -> dict[str, object]:
    _, delta = _build_actual_inputs(case)
    if delta.segment_width != 128 or not delta.segments:
        raise PropertyContractValidationError(f"{case['case_id']}: c=128 case is malformed")
    active_entries = len(_interpret_logical_delta(case))
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
    base, delta = _build_actual_inputs(case)
    owner_permutation = (1, 0, 3, 2)
    if base.layout_spec.rows != len(owner_permutation):
        raise PropertyContractValidationError(
            "hidden-owner-permutation requires the frozen four-row case"
        )
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
        raise PropertyContractValidationError(
            "hidden owner permutation changed the public Cloud program"
        )
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
    base, delta = _build_actual_inputs(case)
    original = compile_strong_execution(base, delta)
    vector = tuple(query["vector"])
    modulus = query["modulus"]
    with tempfile.TemporaryDirectory(prefix="property-validator-rejection-") as temporary:
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
                raise PropertyContractValidationError(
                    "private-plan retarget fixture is not orthogonal"
                )
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
                raise PropertyContractValidationError(
                    "Cloud-DAG retarget fixture is not orthogonal"
                )
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
                raise PropertyContractValidationError("F1-M retarget fixture needs two results")
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
            raise PropertyContractValidationError(f"unsupported rejection contract: {contract_id}")
        try:
            execute_strong_plaintext(target, retargeted, modulus=modulus, ledger=ledger)
        except expected_error as error:
            if expected_message not in str(error):
                raise PropertyContractValidationError(
                    f"{contract_id}: wrong rejection message: {error}"
                ) from error
            rejection_class = type(error).__name__
        else:
            raise PropertyContractValidationError(
                f"{contract_id}: retargeted execution was accepted"
            )
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
    base, delta = _build_actual_inputs(case)
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
    with tempfile.TemporaryDirectory(prefix="property-validator-ledger-once-") as temporary:
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
            raise PropertyContractValidationError("single-use ledger accepted a second execution")
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
        raise PropertyContractValidationError(f"{context}: child process exceeded the bounded join")


def _ledger_reservation_before_sampling_record(
    case: dict[str, object],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="property-validator-ledger-reservation-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        query = case["query"]
        assert isinstance(query, dict)
        base, delta = _build_actual_inputs(case)
        bundle = compile_strong_execution(base, delta)
        query_id = f"{query['query_id']}-ledger-reservation"
        sampling_started = False

        def crash_during_sampling(_: int) -> int:
            nonlocal sampling_started
            sampling_started = True
            raise RuntimeError("validator test-only crash during first mask sample")

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
                if str(error) != "validator test-only crash during first mask sample":
                    raise
            else:
                raise PropertyContractValidationError("sampling crash injection did not run")
        finally:
            output_plan_module.secrets.randbelow = original_randbelow
        if not sampling_started:
            raise PropertyContractValidationError("mask sampling never started after reservation")

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
                raise PropertyContractValidationError(
                    "reopened ledger accepted a duplicate mask reservation"
                )
        finally:
            output_plan_module.secrets.randbelow = original_randbelow
        if draws_after_reopen != 0:
            raise PropertyContractValidationError(
                "duplicate mask reservation reached sampling after reopen"
            )
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
    with tempfile.TemporaryDirectory(prefix="property-validator-ledger-crash-") as temporary:
        ledger_path = Path(temporary) / "ledger.sqlite3"
        bundle, prepared, modulus = _prepare_ledger_case(case, ledger_path, "ledger-crash")
        process = multiprocessing.get_context("spawn").Process(
            target=_crash_burn_worker,
            args=(bundle, prepared, modulus, str(ledger_path)),
        )
        process.start()
        _bounded_join(process, context="crash-burn")
        if process.exitcode != 23:
            raise PropertyContractValidationError(
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
            raise PropertyContractValidationError(
                "crash-reopen ledger did not burn the consumed batch"
            )
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
    with tempfile.TemporaryDirectory(prefix="property-validator-ledger-concurrency-") as temporary:
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
            raise PropertyContractValidationError(
                "concurrent workers did not report bounded outcomes"
            ) from error
        finally:
            results.close()
            results.join_thread()
        errors = [details for kind, details in outcomes if kind == "error"]
        if errors:
            raise PropertyContractValidationError(f"concurrent worker failed: {errors}")
        successes = [details for kind, details in outcomes if kind == "success"]
        consumed = sum(kind == "consumed" for kind, _ in outcomes)
        if len(successes) != 1 or consumed != 1:
            raise PropertyContractValidationError(
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
    delta_entries = [
        [row, column, value]
        for (row, column), value in sorted(_interpret_logical_delta(case).items())
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


def _independently_recompute_case_records(manifest: dict[str, object]) -> dict[str, object]:
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


def validate_property_contract_evidence(
    evidence_dir: Path,
    *,
    expected_source_git_sha: str,
) -> dict[str, object]:
    """Rebuild all case inputs, rerun every contract, and validate exact artifacts."""

    if not isinstance(evidence_dir, Path):
        raise PropertyContractValidationError("evidence_dir must be a Path")
    if (
        not isinstance(expected_source_git_sha, str)
        or _LOWER_GIT_SHA.fullmatch(expected_source_git_sha) is None
    ):
        raise PropertyContractValidationError(
            "expected_source_git_sha must be a full lowercase Git SHA"
        )
    _require_source_snapshot(expected_source_git_sha)
    evidence = _validate_evidence_shape(_read_strict_json(evidence_dir / "evidence.json"))
    if type(evidence["seed"]) is not int or evidence["seed"] < 0:
        raise PropertyContractValidationError("evidence.seed must be a nonnegative strict integer")
    if evidence["source_git_sha"] != expected_source_git_sha:
        raise PropertyContractValidationError("evidence source Git SHA does not match expected")

    manifest_path = evidence_dir / _MANIFEST_PATH
    records_path = evidence_dir / _RECORDS_PATH
    junit_path = evidence_dir / _JUNIT_PATH
    manifest = _validate_manifest_shape(_read_strict_json(manifest_path))
    expected_manifest = build_frozen_manifest(evidence["seed"])
    if manifest != expected_manifest:
        raise PropertyContractValidationError("manifest does not match the frozen case specs")
    expected_records = _independently_recompute_case_records(manifest)
    actual_records = _validate_records_shape(_read_strict_json(records_path))
    if actual_records != expected_records:
        raise PropertyContractValidationError(
            "case records do not match independently recomputed observations"
        )
    try:
        junit_bytes = junit_path.read_bytes()
    except OSError as error:
        raise PropertyContractValidationError(
            f"cannot read required JUnit {junit_path}: {error}"
        ) from error
    expected_junit = canonical_junit_bytes(expected_records)
    if junit_bytes != expected_junit:
        raise PropertyContractValidationError(
            "JUnit bytes do not match independently recomputed case records"
        )

    manifest_bytes = canonical_json_bytes(expected_manifest)
    records_bytes = canonical_json_bytes(expected_records)
    descriptor_bytes = canonical_json_bytes(case_set_descriptor(expected_manifest))
    cases = expected_manifest["cases"]
    record_count = len(expected_records["records"])
    contract_count = sum(len(case["contracts"]) for case in cases)
    if record_count != contract_count:
        raise PropertyContractValidationError(
            "not every frozen contract has exactly one recomputed case record"
        )
    expected_evidence = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_scope": EVIDENCE_SCOPE,
        "gate_status": "pass",
        "source_git_sha": expected_source_git_sha,
        "seed": evidence["seed"],
        "case_set": {
            "id": CASE_SET_ID,
            "version": CASE_SET_VERSION,
            "input_case_count": len(cases),
            "contract_case_count": contract_count,
            "sha256": hashlib.sha256(descriptor_bytes).hexdigest(),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "provenance": _current_provenance(),
        "artifacts": {
            "manifest": {
                "path": _MANIFEST_PATH,
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            },
            "case_records": {
                "path": _RECORDS_PATH,
                "sha256": hashlib.sha256(records_bytes).hexdigest(),
            },
            "junit": {
                "path": _JUNIT_PATH,
                "sha256": hashlib.sha256(expected_junit).hexdigest(),
            },
        },
        "summary": {"record_count": record_count, "failed": 0},
        "claims": dict(CLAIMS),
    }
    if evidence != expected_evidence:
        raise PropertyContractValidationError(
            "evidence metadata does not match independently recomputed artifacts and sources"
        )
    return evidence


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate strong property-contract evidence")
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("--expected-source-git-sha", required=True)
    args = parser.parse_args(argv)
    try:
        validate_property_contract_evidence(
            args.evidence_dir,
            expected_source_git_sha=args.expected_source_git_sha,
        )
    except PropertyContractValidationError as error:
        print(f"property-contract validation failed: {error}", file=sys.stderr)
        return 1
    print("property-contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
