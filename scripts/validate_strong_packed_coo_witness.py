#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from make_strong_packed_coo_witness_binding import (
    build_witness_cloud_program,
    build_witness_realized_contract,
    make_witness_bindings,
)

from dynamic_cssc.cloud_execution_plan import (
    ExecutionBinding,
    canonical_cloud_program_payload,
    execution_binding_digest,
)
from dynamic_cssc.manifest import validate_manifest

TOP_LEVEL_KEYS = {
    "adapter",
    "bindings",
    "circuit",
    "claims",
    "correctness",
    "evidence_scope",
    "execution_trace",
    "f1m",
    "openfhe",
    "realized_contract",
    "schema_version",
    "status",
}


class WitnessValidationError(ValueError):
    """Raised when correctness evidence is incomplete or inconsistent."""


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


def _expected_witness(
    manifest: dict[str, Any],
    bindings: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": "strong-packed-coo-witness-v1",
        "status": "pass",
        "evidence_scope": "fixed-stride-primitive-correctness-only-pinned-openfhe",
        "bindings": bindings,
        "adapter": {
            "typed_slot_count": 4096,
            "physical_batch_size": 8192,
            "second_batching_row_zero": True,
        },
        "openfhe": {
            "repository": manifest["openfhe"]["repository"],
            "version": manifest["openfhe"]["version"],
            "commit": manifest["openfhe"]["commit"],
            "scheme": manifest["openfhe"]["scheme"],
            "ring_dimension": 8192,
            "plaintext_modulus": 65537,
            "batch_size": 8192,
            "effective_first_row_slots": 4096,
            "multiplicative_depth": 2,
            "eval_add_count": 0,
            "key_switch_count": 0,
        },
        "circuit": {
            "component_count": 2,
            "logical_payload_width": 127,
            "physical_segment_width": 128,
            "padding_lanes_per_segment": 1,
            "reduction_rotation_indices": [1, 2, 4, 8, 16, 32, 64],
            "reduction_eval_add_count_per_component": 7,
            "start_mask_applications_per_component": 1,
        },
        "realized_contract": build_witness_realized_contract(),
        "execution_trace": canonical_cloud_program_payload(build_witness_cloud_program())["nodes"],
        "correctness": {
            "expected_centered_result": [4, 6, 20, -8],
            "decrypted_centered_result": [4, 6, 20, -8],
            "matches_expected": True,
            "decryptions_valid": True,
            "products_relinearized": True,
            "unrelinearized_product_element_counts": [3, 3],
            "product_element_counts": [2, 2],
            "global_column_index": 8192,
            "global_column_index_anti_alias": True,
            "tail_segment_start": 3968,
            "tail_segment_exercised": True,
            "non_power_of_two_payload_boundary_exercised": True,
            "padding_lane_zero": True,
        },
        "f1m": {
            "mode": "encrypted-one-time-zero-sum",
            "mask_scope": "logical-coordinate-overlap-only",
            "encrypted_mask_ciphertext_count": 2,
            "overlap_coordinate_count": 2,
            "disjoint_mask_zero": True,
            "zero_sum_mask": True,
            "mask_values_redacted": True,
        },
        "claims": {
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "formal_parameter_claim_allowed": False,
            "end_to_end_correctness_claim_allowed": False,
            "security_claim_allowed": False,
            "formal_correctness_claim": False,
            "formal_security_claim": False,
            "formal_performance_claim": False,
            "mixed_workload_parameter_claim": False,
        },
    }


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


def _canonical_payload_digest(payload: dict[str, Any], *, ensure_ascii: bool) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
        allow_nan=False,
    ).encode("ascii" if ensure_ascii else "utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _reconstruct_cloud_program_payload(
    realized_cloud_program: dict[str, Any],
    execution_trace: list[dict[str, Any]],
) -> dict[str, Any]:
    plaintext_masks = []
    for mask_index, realized_mask in enumerate(realized_cloud_program["plaintext_masks"]):
        length = realized_mask["length"]
        if type(length) is not int or length <= 0:
            raise WitnessValidationError(
                f"realized_contract.cloud_program.plaintext_masks[{mask_index}].length "
                "must be a positive integer"
            )
        values = [0] * length
        seen: set[int] = set()
        previous_position = -1
        for leader_index, position in enumerate(realized_mask["leader_positions"]):
            if (
                type(position) is not int
                or not 0 <= position < length
                or position in seen
                or position <= previous_position
            ):
                raise WitnessValidationError(
                    "realized_contract.cloud_program.plaintext_masks"
                    f"[{mask_index}].leader_positions[{leader_index}] is invalid"
                )
            seen.add(position)
            previous_position = position
            values[position] = 1
        plaintext_masks.append(
            {
                "length": length,
                "mask_id": realized_mask["mask_id"],
                "role": realized_mask["role"],
                "values": values,
            }
        )
    return {
        "ciphertext_inputs": realized_cloud_program["ciphertext_inputs"],
        "format": realized_cloud_program["format"],
        "nodes": execution_trace,
        "plaintext_masks": plaintext_masks,
        "result_ids": realized_cloud_program["result_ids"],
        "rotation_catalog": realized_cloud_program["rotation_catalog"],
        "slot_count": realized_cloud_program["slot_count"],
    }


def _verify_realized_binding(
    witness: dict[str, Any],
    bindings: dict[str, str],
) -> None:
    realized = witness["realized_contract"]
    program_payload = _reconstruct_cloud_program_payload(
        realized["cloud_program"],
        witness["execution_trace"],
    )
    _require_exact(
        program_payload,
        canonical_cloud_program_payload(build_witness_cloud_program()),
        "witness.realized_contract.cloud_program+execution_trace",
    )
    _require_exact(
        bindings["cloud_program_digest"],
        _canonical_payload_digest(program_payload, ensure_ascii=True),
        "witness.bindings.cloud_program_digest",
    )

    output_plan_payload = realized["output_plan"]
    _require_exact(
        realized["cloud_program"]["result_ids"],
        [
            f"{share['component_id']}-{share['output_block_id']}"
            for share in output_plan_payload["shares"]
        ],
        "witness.realized_contract.result/output-share cross-link",
    )
    _require_exact(
        bindings["output_plan_digest"],
        _canonical_payload_digest(output_plan_payload, ensure_ascii=False),
        "witness.bindings.output_plan_digest",
    )
    atomic_binding = ExecutionBinding(
        format=realized["execution_binding"]["format"],
        version_id=realized["execution_binding"]["version_id"],
        output_plan_digest=bindings["output_plan_digest"],
        cloud_program_digest=bindings["cloud_program_digest"],
    )
    _require_exact(
        bindings["execution_binding_digest"],
        execution_binding_digest(atomic_binding),
        "witness.bindings.execution_binding_digest",
    )


def _expected_provenance(
    *,
    manifest: dict[str, Any],
    bindings: dict[str, str],
    source_git_sha: str,
    source_git_ref: str,
    github_run_id: str,
    witness_source: Path,
    witness_binary: Path,
    binding_generator: Path,
    validator_source: Path,
) -> dict[str, Any]:
    if len(source_git_sha) != 40 or set(source_git_sha) - set("0123456789abcdef"):
        raise WitnessValidationError("source_git_sha must be a full lowercase Git SHA")
    if not source_git_ref:
        raise WitnessValidationError("source_git_ref must be non-empty")
    if not github_run_id.isdecimal():
        raise WitnessValidationError("github_run_id must be canonical decimal digits")
    return {
        "schema_version": "strong-packed-coo-witness-provenance-v1",
        "source_git_sha": source_git_sha,
        "source_git_ref": source_git_ref,
        "github_run_id": github_run_id,
        "openfhe_commit": manifest["openfhe"]["commit"],
        "witness_source_sha256": _sha256_file(witness_source),
        "witness_binary_sha256": _sha256_file(witness_binary),
        "binding_generator_sha256": _sha256_file(binding_generator),
        "validator_sha256": _sha256_file(validator_source),
        **bindings,
    }


def validate_witness(
    witness_path: Path,
    manifest_path: Path,
    provenance_path: Path,
    *,
    source_git_sha: str,
    source_git_ref: str,
    github_run_id: str,
    witness_source: Path,
    witness_binary: Path,
    binding_generator: Path,
    validator_source: Path,
) -> None:
    witness = _read_json(witness_path)
    manifest = _read_json(manifest_path)
    provenance = _read_json(provenance_path)
    validate_manifest(manifest)
    if set(witness) != TOP_LEVEL_KEYS:
        raise WitnessValidationError("witness top-level keys must exactly match the closed schema")
    bindings = make_witness_bindings(manifest)
    _require_exact(witness, _expected_witness(manifest, bindings), "witness")
    _verify_realized_binding(witness, bindings)
    _require_exact(
        provenance,
        _expected_provenance(
            manifest=manifest,
            bindings=bindings,
            source_git_sha=source_git_sha,
            source_git_ref=source_git_ref,
            github_run_id=github_run_id,
            witness_source=witness_source,
            witness_binary=witness_binary,
            binding_generator=binding_generator,
            validator_source=validator_source,
        ),
        "provenance",
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a pinned OpenFHE strong packed-COO correctness witness."
    )
    parser.add_argument("witness", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("provenance", type=Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--source-git-ref", required=True)
    parser.add_argument("--github-run-id", required=True)
    parser.add_argument("--witness-source", type=Path, required=True)
    parser.add_argument("--witness-binary", type=Path, required=True)
    parser.add_argument("--binding-generator", type=Path, required=True)
    parser.add_argument("--validator-source", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        validate_witness(
            arguments.witness,
            arguments.manifest,
            arguments.provenance,
            source_git_sha=arguments.source_git_sha,
            source_git_ref=arguments.source_git_ref,
            github_run_id=arguments.github_run_id,
            witness_source=arguments.witness_source,
            witness_binary=arguments.witness_binary,
            binding_generator=arguments.binding_generator,
            validator_source=arguments.validator_source,
        )
    except (WitnessValidationError, ValueError, TypeError) as error:
        print(f"strong packed-COO witness validation failed: {error}", file=sys.stderr)
        return 1
    print(f"validated strong packed-COO witness: {arguments.witness}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
