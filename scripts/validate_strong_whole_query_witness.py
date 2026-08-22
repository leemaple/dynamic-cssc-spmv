#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from make_strong_whole_query_witness_binding import make_witness_binding_payload

from dynamic_cssc.cloud_execution_plan import canonical_cloud_program_payload
from dynamic_cssc.manifest import validate_manifest
from dynamic_cssc.strong_whole_query_witness import (
    OPENFHE_COMMIT,
    build_strong_whole_query_fixture,
    canonical_whole_query_contract,
)


class WitnessValidationError(ValueError):
    """Raised when whole-query correctness evidence is incomplete or inconsistent."""


_PROPERTY_SOURCE_PATHS = (
    "scripts/property_contract_spec.py",
    "scripts/property_contract.py",
    "scripts/validate_property_contract.py",
    "tests/test_strong_property_contract.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/strong_packed_coo.py",
)
_PROPERTY_ARTIFACT_NAMES = (
    "case-records.json",
    "evidence.json",
    "junit.xml",
    "manifest.json",
)


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise WitnessValidationError(f"duplicate JSON key: {key}")
        decoded[key] = value
    return decoded


def _reject_constant(value: str) -> None:
    raise WitnessValidationError(f"non-standard JSON constant: {value}")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WitnessValidationError(f"cannot read strict JSON {path}: {error}") from error
    if not isinstance(decoded, dict):
        raise WitnessValidationError(f"{path} must contain a JSON object")
    return decoded


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise WitnessValidationError(f"cannot hash required file {path}: {error}") from error


def _require_exact(actual: Any, expected: Any, path: str) -> None:
    if type(actual) is not type(expected):
        raise WitnessValidationError(
            f"{path} has type {type(actual).__name__}; expected {type(expected).__name__}"
        )
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            raise WitnessValidationError(f"{path} keys do not match the closed schema")
        for key in expected:
            _require_exact(actual[key], expected[key], f"{path}.{key}")
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            raise WitnessValidationError(f"{path} has the wrong array length")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected, strict=True)):
            _require_exact(actual_item, expected_item, f"{path}[{index}]")
        return
    if actual != expected:
        raise WitnessValidationError(f"{path} must equal {expected!r}; got {actual!r}")


def _require_bounded_integer(value: Any, *, bound: int, path: str, bound_path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WitnessValidationError(f"{path} must be a strict integer")
    if abs(value) > bound:
        raise WitnessValidationError(f"{path} violates {bound_path}={bound}")


def _require_realized_manifest_bounds(
    witness: dict[str, Any], manifest: dict[str, Any]
) -> None:
    query_bound = manifest["integer_correctness"]["query_entry_abs_bound"]
    matrix_bound = manifest["integer_correctness"]["matrix_entry_abs_bound"]
    realized = witness.get("realized_contract")
    if not isinstance(realized, dict):
        raise WitnessValidationError("witness.realized_contract must be an object")
    prepared_query = realized.get("prepared_query")
    if not isinstance(prepared_query, dict):
        raise WitnessValidationError("witness.realized_contract.prepared_query must be an object")

    vector_entries = prepared_query.get("vector_nonzero_entries")
    if not isinstance(vector_entries, list):
        raise WitnessValidationError(
            "witness.realized_contract.prepared_query.vector_nonzero_entries must be an array"
        )
    for ordinal, entry in enumerate(vector_entries):
        path = (
            "witness.realized_contract.prepared_query.vector_nonzero_entries"
            f"[{ordinal}]"
        )
        if not isinstance(entry, list) or len(entry) != 2:
            raise WitnessValidationError(f"{path} must be a [column, value] pair")
        _require_bounded_integer(
            entry[1],
            bound=query_bound,
            path=f"{path}[1]",
            bound_path="manifest.integer_correctness.query_entry_abs_bound",
        )

    query_operands = prepared_query.get("query_operands")
    if not isinstance(query_operands, list):
        raise WitnessValidationError(
            "witness.realized_contract.prepared_query.query_operands must be an array"
        )
    for operand_ordinal, operand in enumerate(query_operands):
        operand_path = (
            "witness.realized_contract.prepared_query.query_operands"
            f"[{operand_ordinal}]"
        )
        if not isinstance(operand, dict) or not isinstance(operand.get("values"), list):
            raise WitnessValidationError(f"{operand_path}.values must be an array")
        for value_ordinal, value in enumerate(operand["values"]):
            _require_bounded_integer(
                value,
                bound=query_bound,
                path=f"{operand_path}.values[{value_ordinal}]",
                bound_path="manifest.integer_correctness.query_entry_abs_bound",
            )

    private_plan = realized.get("private_plan")
    if not isinstance(private_plan, dict) or not isinstance(private_plan.get("operands"), list):
        raise WitnessValidationError(
            "witness.realized_contract.private_plan.operands must be an array"
        )
    for operand_ordinal, operand in enumerate(private_plan["operands"]):
        operand_path = f"witness.realized_contract.private_plan.operands[{operand_ordinal}]"
        if not isinstance(operand, dict) or not isinstance(operand.get("values"), list):
            raise WitnessValidationError(f"{operand_path}.values must be an array")
        for value_ordinal, value in enumerate(operand["values"]):
            _require_bounded_integer(
                value,
                bound=matrix_bound,
                path=f"{operand_path}.values[{value_ordinal}]",
                bound_path="manifest.integer_correctness.matrix_entry_abs_bound",
            )


def _expected_witness(
    manifest: dict[str, Any],
    binding_payload: dict[str, object],
) -> dict[str, object]:
    fixture = build_strong_whole_query_fixture()
    bindings = binding_payload["bindings"]
    return {
        "adapter": {
            "physical_batch_size": 8192,
            "second_batching_row_zero": True,
            "typed_slot_count": 4096,
        },
        "bindings": bindings,
        "claims": {
            "candidate_registered": False,
            "complete_cost_claim_allowed": False,
            "complete_reference_set": False,
            "end_to_end_correctness_claim_allowed": False,
            "formal_correctness_claim": False,
            "formal_parameter_claim_allowed": False,
            "formal_performance_claim": False,
            "formal_security_claim": False,
            "gate_eligible": False,
            "mixed_workload_parameter_claim": False,
            "security_claim_allowed": False,
        },
        "correctness": {
            "active_offset_126_exercised": True,
            "decrypted_centered_output_sparse": [[0, 128], [4095, 5]],
            "decryptions_valid": True,
            "direct_spmv_centered_output_sparse": [[0, 128], [4095, 5]],
            "global_column_index_anti_alias": True,
            "matches_python_direct_spmv": True,
            "matches_python_typed_plaintext_oracle": True,
            "padding_offset_127_zero": True,
            "product_element_counts": [2, 2, 2],
            "products_relinearized": True,
            "query_entry_bound_respected": True,
            "unrelinearized_product_element_counts": [3, 3, 3],
        },
        "evidence_scope": ("actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe"),
        "execution_trace": canonical_cloud_program_payload(fixture.bundle.cloud_plan.program)[
            "nodes"
        ],
        "f1m": {
            "ciphertext_additions": 3,
            "dummy_exact_zero": True,
            "encrypted_zero_dummy_ciphertext_count": 1,
            "mask_values_redacted": True,
            "mode": "encrypted-correctness-test-operands",
            "persistent_ledger_exercised": False,
            "production_csprng_security_claim_allowed": False,
            "random_parts_nonzero": True,
            "random_zero_sum_ciphertext_count": 2,
            "return_ciphertext_count": 3,
            "zero_sum_mask": True,
        },
        "fixture": {
            "active_delta_payload": 127,
            "base_active_coordinate_count": 4,
            "cols": 8193,
            "global_column_index": 8192,
            "kind": "actual-cssc-base-plus-strong-delta",
            "padding_offset": 127,
            "return_count": 3,
            "rows": 4096,
            "segment_width": 128,
        },
        "openfhe": {
            "batch_size": 8192,
            "commit": manifest["openfhe"]["commit"],
            "effective_first_row_slots": 4096,
            "eval_add_count": 0,
            "key_switch_count": 0,
            "multiplicative_depth": 2,
            "plaintext_modulus": 65537,
            "repository": manifest["openfhe"]["repository"],
            "ring_dimension": 8192,
            "scheme": "BFVRNS",
            "version": manifest["openfhe"]["version"],
        },
        "realized_contract": canonical_whole_query_contract(fixture),
        "schema_version": "strong-whole-query-witness-v2",
        "status": "pass",
    }


def _expected_provenance(
    *,
    witness_path: Path,
    manifest_path: Path,
    bindings_path: Path,
    source_git_sha: str,
    source_git_ref: str,
    github_run_id: str,
    witness_source: Path,
    witness_binary: Path,
    binding_generator: Path,
    validator_source: Path,
    property_contract_dir: Path,
) -> dict[str, object]:
    if len(source_git_sha) != 40 or set(source_git_sha) - set("0123456789abcdef"):
        raise WitnessValidationError("source_git_sha must be a full lowercase Git SHA")
    if not source_git_ref:
        raise WitnessValidationError("source_git_ref must be non-empty")
    if (
        not github_run_id.isdecimal()
        or github_run_id == "0"
        or str(int(github_run_id)) != github_run_id
    ):
        raise WitnessValidationError("github_run_id must be canonical decimal digits")
    try:
        property_entries = {path.name for path in property_contract_dir.iterdir()}
    except OSError as error:
        raise WitnessValidationError(
            f"cannot inspect property contract directory {property_contract_dir}: {error}"
        ) from error
    if property_entries != set(_PROPERTY_ARTIFACT_NAMES) or not all(
        (property_contract_dir / name).is_file() for name in _PROPERTY_ARTIFACT_NAMES
    ):
        raise WitnessValidationError(
            "property contract directory must contain exactly the four validated artifacts"
        )
    repository_root = validator_source.resolve().parents[1]
    return {
        "binding_generator_sha256": _sha256_file(binding_generator),
        "bindings_sha256": _sha256_file(bindings_path),
        "github_run_id": github_run_id,
        "manifest_sha256": _sha256_file(manifest_path),
        "openfhe_commit": OPENFHE_COMMIT,
        "schema_version": "strong-whole-query-witness-provenance-v2",
        "source_git_ref": source_git_ref,
        "source_git_sha": source_git_sha,
        "validator_sha256": _sha256_file(validator_source),
        "witness_binary_sha256": _sha256_file(witness_binary),
        "witness_sha256": _sha256_file(witness_path),
        "witness_source_sha256": _sha256_file(witness_source),
        "property_contract": {
            "artifacts": {
                name: _sha256_file(property_contract_dir / name)
                for name in _PROPERTY_ARTIFACT_NAMES
            },
            "sources": {
                relative: _sha256_file(repository_root / relative)
                for relative in _PROPERTY_SOURCE_PATHS
            },
        },
    }


def validate_witness(
    witness_path: Path,
    manifest_path: Path,
    bindings_path: Path,
    provenance_path: Path,
    *,
    source_git_sha: str,
    source_git_ref: str,
    github_run_id: str,
    witness_source: Path,
    witness_binary: Path,
    binding_generator: Path,
    validator_source: Path,
    property_contract_dir: Path,
) -> None:
    witness = _read_json(witness_path)
    manifest = _read_json(manifest_path)
    bindings = _read_json(bindings_path)
    provenance = _read_json(provenance_path)
    validate_manifest(manifest)
    _require_realized_manifest_bounds(witness, manifest)
    recomputed_bindings = make_witness_binding_payload(manifest)
    _require_exact(bindings, recomputed_bindings, "bindings")
    _require_exact(witness, _expected_witness(manifest, recomputed_bindings), "witness")
    _require_exact(
        provenance,
        _expected_provenance(
            witness_path=witness_path,
            manifest_path=manifest_path,
            bindings_path=bindings_path,
            source_git_sha=source_git_sha,
            source_git_ref=source_git_ref,
            github_run_id=github_run_id,
            witness_source=witness_source,
            witness_binary=witness_binary,
            binding_generator=binding_generator,
            validator_source=validator_source,
            property_contract_dir=property_contract_dir,
        ),
        "provenance",
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the pinned OpenFHE Phase 2 whole-query witness."
    )
    parser.add_argument("witness", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("bindings", type=Path)
    parser.add_argument("provenance", type=Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--source-git-ref", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--witness-source", type=Path, required=True)
    parser.add_argument("--witness-binary", type=Path, required=True)
    parser.add_argument("--binding-generator", type=Path, required=True)
    parser.add_argument("--validator-source", type=Path, required=True)
    parser.add_argument("--property-contract-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        validate_witness(
            arguments.witness,
            arguments.manifest,
            arguments.bindings,
            arguments.provenance,
            source_git_sha=arguments.source_git_sha,
            source_git_ref=arguments.source_git_ref,
            github_run_id=arguments.github_run_id,
            witness_source=arguments.witness_source,
            witness_binary=arguments.witness_binary,
            binding_generator=arguments.binding_generator,
            validator_source=arguments.validator_source,
            property_contract_dir=arguments.property_contract_dir,
        )
    except (WitnessValidationError, ValueError, TypeError) as error:
        print(f"strong whole-query witness validation failed: {error}", file=sys.stderr)
        return 1
    print(f"validated strong whole-query witness: {arguments.witness}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
