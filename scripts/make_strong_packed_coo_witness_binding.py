#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from dynamic_cssc.cloud_execution_plan import (
    CLOUD_PROGRAM_FORMAT,
    EXECUTION_BINDING_FORMAT,
    AddCiphertexts,
    AddF1MMask,
    CiphertextInput,
    CloudProgram,
    ExecutionBinding,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    PlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    RotationCatalog,
    canonical_cloud_program_payload,
    cloud_program_digest,
    execution_binding_digest,
    validate_cloud_program,
)
from dynamic_cssc.manifest import validate_manifest
from dynamic_cssc.output_plan import (
    OUTPUT_PLAN_FORMAT,
    OutputPlan,
    OutputShare,
    analyze_output_plan,
)

RING_DIMENSION = 8192
PLAINTEXT_MODULUS = 65537
PHYSICAL_BATCH_SIZE = 8192
EFFECTIVE_FIRST_ROW_SLOTS = 4096
LOGICAL_PAYLOAD_WIDTH = 127
PHYSICAL_SEGMENT_WIDTH = 128
TAIL_SEGMENT_START = 3968
REDUCTION_ROTATIONS = (1, 2, 4, 8, 16, 32, 64)
OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
EXECUTION_BINDING_VERSION = "strong-witness-v1"


class BindingGenerationError(ValueError):
    """Raised when the manifest cannot authorize the fixed witness program."""


def _require_manifest_contract(manifest: dict[str, Any]) -> None:
    expected = {
        "functional_mode": "F1-M-hidden-rowmap",
        "matrix.rows": 4096,
        "matrix.cols": 8193,
        "packing.total_slots": PHYSICAL_BATCH_SIZE,
        "packing.row_slots": EFFECTIVE_FIRST_ROW_SLOTS,
        "packing.effective_slots": EFFECTIVE_FIRST_ROW_SLOTS,
        "openfhe.version": "1.5.1",
        "openfhe.commit": OPENFHE_COMMIT,
        "openfhe.scheme": "BFVRNS",
        "openfhe.ring_dimension": RING_DIMENSION,
        "openfhe.plaintext_modulus": PLAINTEXT_MODULUS,
        "openfhe.batch_size": PHYSICAL_BATCH_SIZE,
        "openfhe.day2_mult_only.multiplicative_depth": 2,
        "openfhe.day2_mult_only.eval_add_count": 0,
        "openfhe.day2_mult_only.key_switch_count": 0,
    }
    actual = {
        "functional_mode": manifest.get("functional_mode"),
        "matrix.rows": manifest.get("matrix", {}).get("rows"),
        "matrix.cols": manifest.get("matrix", {}).get("cols"),
        "packing.total_slots": manifest.get("packing", {}).get("total_slots"),
        "packing.row_slots": manifest.get("packing", {}).get("row_slots"),
        "packing.effective_slots": manifest.get("packing", {}).get("effective_slots"),
        "openfhe.version": manifest.get("openfhe", {}).get("version"),
        "openfhe.commit": manifest.get("openfhe", {}).get("commit"),
        "openfhe.scheme": manifest.get("openfhe", {}).get("scheme"),
        "openfhe.ring_dimension": manifest.get("openfhe", {}).get("ring_dimension"),
        "openfhe.plaintext_modulus": manifest.get("openfhe", {}).get("plaintext_modulus"),
        "openfhe.batch_size": manifest.get("openfhe", {}).get("batch_size"),
        "openfhe.day2_mult_only.multiplicative_depth": manifest.get("openfhe", {})
        .get("noise_budget_profiles", {})
        .get("day2_mult_only", {})
        .get("multiplicative_depth"),
        "openfhe.day2_mult_only.eval_add_count": manifest.get("openfhe", {})
        .get("noise_budget_profiles", {})
        .get("day2_mult_only", {})
        .get("eval_add_count"),
        "openfhe.day2_mult_only.key_switch_count": manifest.get("openfhe", {})
        .get("noise_budget_profiles", {})
        .get("day2_mult_only", {})
        .get("key_switch_count"),
    }
    mismatches = [
        f"{field}: expected {expected[field]!r}, got {actual[field]!r}"
        for field in expected
        if actual[field] != expected[field]
    ]
    if mismatches:
        raise BindingGenerationError(
            "manifest does not match fixed witness: " + "; ".join(mismatches)
        )


def build_witness_output_plan() -> OutputPlan:
    return OutputPlan(
        logical_output_size=4,
        slot_count=EFFECTIVE_FIRST_ROW_SLOTS,
        shares=(
            OutputShare(
                "witness-component-0",
                "page-000000",
                ((0, 0), (128, 1), (256, 2), (TAIL_SEGMENT_START, 3)),
            ),
            OutputShare(
                "witness-component-1",
                "page-000000",
                ((0, 0), (128, 2)),
            ),
        ),
    )


def _component_nodes(component: str) -> tuple[object, ...]:
    nodes: list[object] = [
        MultiplyCiphertexts(
            f"{component}-product",
            f"{component}-values",
            f"{component}-query",
        ),
        Relinearize(f"{component}-relinearized", f"{component}-product"),
    ]
    reduced_id = f"{component}-relinearized"
    span = 1
    for rotation in REDUCTION_ROTATIONS:
        rotated_id = f"{component}-rotate-{rotation}"
        summed_id = f"{component}-sum-{span + rotation}"
        nodes.append(Rotate(rotated_id, reduced_id, rotation, rotation))
        nodes.append(AddCiphertexts(summed_id, reduced_id, rotated_id))
        reduced_id = summed_id
        span += rotation
    nodes.extend(
        (
            MultiplyPlaintextMask(
                f"{component}-selected",
                reduced_id,
                "segment-starts",
            ),
            AddF1MMask(
                f"{component}-masked",
                f"{component}-selected",
                f"{component}-f1m-mask",
                "opaque-zero-sum",
            ),
            ReturnResult(
                f"{component}-page-000000",
                f"{component}-masked",
            ),
        )
    )
    return tuple(nodes)


def build_witness_cloud_program() -> CloudProgram:
    start_mask = tuple(
        1 if slot < EFFECTIVE_FIRST_ROW_SLOTS and slot % PHYSICAL_SEGMENT_WIDTH == 0 else 0
        for slot in range(EFFECTIVE_FIRST_ROW_SLOTS)
    )
    components = ("witness-component-0", "witness-component-1")
    program = CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=EFFECTIVE_FIRST_ROW_SLOTS,
        ciphertext_inputs=tuple(
            operand
            for component in components
            for operand in (
                CiphertextInput(f"{component}-values", "value", EFFECTIVE_FIRST_ROW_SLOTS),
                CiphertextInput(f"{component}-query", "query", EFFECTIVE_FIRST_ROW_SLOTS),
                CiphertextInput(f"{component}-f1m-mask", "f1m-mask", EFFECTIVE_FIRST_ROW_SLOTS),
            )
        ),
        plaintext_masks=(
            PlaintextMask(
                "segment-starts",
                "selection",
                EFFECTIVE_FIRST_ROW_SLOTS,
                start_mask,
            ),
        ),
        nodes=tuple(node for component in components for node in _component_nodes(component)),
        result_ids=tuple(f"{component}-page-000000" for component in components),
        rotation_catalog=RotationCatalog(
            tuple((rotation, rotation) for rotation in REDUCTION_ROTATIONS)
        ),
    )
    validate_cloud_program(program)
    return program


def _canonical_output_plan_contract(plan: OutputPlan) -> dict[str, Any]:
    analysis = analyze_output_plan(plan)
    payload: dict[str, Any] = {
        "format": OUTPUT_PLAN_FORMAT,
        "logical_output_size": plan.logical_output_size,
        "slot_count": plan.slot_count,
        "shares": [
            {
                "component_id": share.component_id,
                "output_block_id": share.output_block_id,
                "slot_to_logical": [
                    [physical_slot, logical_coordinate]
                    for physical_slot, logical_coordinate in sorted(share.slot_to_logical)
                ],
            }
            for share in sorted(
                plan.shares,
                key=lambda item: (item.component_id, item.output_block_id),
            )
        ],
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != analysis.output_plan_digest:
        raise BindingGenerationError("realized OutputPlan payload is not canonical")
    return payload


def build_witness_realized_contract() -> dict[str, Any]:
    """Build the non-node contract that the C++ witness must realize and report."""

    program_payload = canonical_cloud_program_payload(build_witness_cloud_program())
    realized_masks = []
    for mask in program_payload["plaintext_masks"]:
        values = mask["values"]
        leader_positions = [index for index, value in enumerate(values) if value == 1]
        reconstructed = [0] * mask["length"]
        for position in leader_positions:
            reconstructed[position] = 1
        if reconstructed != values:
            raise BindingGenerationError(
                "selection mask leaders do not reconstruct canonical values"
            )
        realized_masks.append(
            {
                "length": mask["length"],
                "mask_id": mask["mask_id"],
                "role": mask["role"],
                "leader_positions": leader_positions,
            }
        )

    return {
        "execution_binding": {
            "format": EXECUTION_BINDING_FORMAT,
            "version_id": EXECUTION_BINDING_VERSION,
        },
        "cloud_program": {
            "format": program_payload["format"],
            "slot_count": program_payload["slot_count"],
            "ciphertext_inputs": program_payload["ciphertext_inputs"],
            "plaintext_masks": realized_masks,
            "rotation_catalog": program_payload["rotation_catalog"],
            "result_ids": program_payload["result_ids"],
        },
        "output_plan": _canonical_output_plan_contract(build_witness_output_plan()),
    }


def make_witness_bindings(manifest: dict[str, Any]) -> dict[str, str]:
    validate_manifest(manifest)
    _require_manifest_contract(manifest)
    output_plan_digest = analyze_output_plan(build_witness_output_plan()).output_plan_digest
    program = build_witness_cloud_program()
    program_digest = cloud_program_digest(program)
    binding = ExecutionBinding(
        format=EXECUTION_BINDING_FORMAT,
        version_id=EXECUTION_BINDING_VERSION,
        output_plan_digest=output_plan_digest,
        cloud_program_digest=program_digest,
    )
    return {
        "cloud_program_digest": program_digest,
        "output_plan_digest": output_plan_digest,
        "execution_binding_digest": execution_binding_digest(binding),
    }


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BindingGenerationError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(decoded, dict):
        raise BindingGenerationError("manifest must contain a JSON object")
    return decoded


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate canonical digests for the fixed strong packed-COO witness."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        bindings = make_witness_bindings(_read_manifest(arguments.manifest))
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(bindings, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (BindingGenerationError, ValueError, TypeError, OSError) as error:
        print(f"strong packed-COO binding generation failed: {error}", file=sys.stderr)
        return 1
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
