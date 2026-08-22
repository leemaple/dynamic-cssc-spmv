#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dynamic_cssc.manifest import validate_manifest
from dynamic_cssc.strong_whole_query_witness import (
    ACTIVE_DELTA_PAYLOAD,
    COLS,
    EFFECTIVE_SLOTS,
    OPENFHE_COMMIT,
    OPENFHE_VERSION,
    PHYSICAL_BATCH_SIZE,
    RING_DIMENSION,
    ROWS,
    SEGMENT_WIDTH,
    VERSION_ID,
    build_strong_whole_query_fixture,
    strong_whole_query_bindings,
)


class BindingGenerationError(ValueError):
    """Raised when the manifest cannot authorize the fixed whole-query witness."""


def _require_manifest_contract(manifest: dict[str, Any]) -> None:
    expected = {
        "functional_mode": "F1-M-hidden-rowmap",
        "matrix.rows": ROWS,
        "matrix.cols": COLS,
        "packing.total_slots": PHYSICAL_BATCH_SIZE,
        "packing.row_slots": EFFECTIVE_SLOTS,
        "packing.effective_slots": EFFECTIVE_SLOTS,
        "openfhe.version": OPENFHE_VERSION,
        "openfhe.commit": OPENFHE_COMMIT,
        "openfhe.scheme": "BFVRNS",
        "openfhe.ring_dimension": RING_DIMENSION,
        "openfhe.plaintext_modulus": 65537,
        "openfhe.batch_size": PHYSICAL_BATCH_SIZE,
        "openfhe.day2_mult_only.multiplicative_depth": 2,
        "openfhe.day2_mult_only.eval_add_count": 0,
        "openfhe.day2_mult_only.key_switch_count": 0,
    }
    openfhe = manifest.get("openfhe", {})
    profile = openfhe.get("noise_budget_profiles", {}).get("day2_mult_only", {})
    actual = {
        "functional_mode": manifest.get("functional_mode"),
        "matrix.rows": manifest.get("matrix", {}).get("rows"),
        "matrix.cols": manifest.get("matrix", {}).get("cols"),
        "packing.total_slots": manifest.get("packing", {}).get("total_slots"),
        "packing.row_slots": manifest.get("packing", {}).get("row_slots"),
        "packing.effective_slots": manifest.get("packing", {}).get("effective_slots"),
        "openfhe.version": openfhe.get("version"),
        "openfhe.commit": openfhe.get("commit"),
        "openfhe.scheme": openfhe.get("scheme"),
        "openfhe.ring_dimension": openfhe.get("ring_dimension"),
        "openfhe.plaintext_modulus": openfhe.get("plaintext_modulus"),
        "openfhe.batch_size": openfhe.get("batch_size"),
        "openfhe.day2_mult_only.multiplicative_depth": profile.get("multiplicative_depth"),
        "openfhe.day2_mult_only.eval_add_count": profile.get("eval_add_count"),
        "openfhe.day2_mult_only.key_switch_count": profile.get("key_switch_count"),
    }
    mismatches = [
        f"{field}: expected {expected[field]!r}, got {actual[field]!r}"
        for field in expected
        if actual[field] != expected[field]
    ]
    if mismatches:
        raise BindingGenerationError(
            "manifest does not match fixed whole-query witness: " + "; ".join(mismatches)
        )


def make_witness_binding_payload(manifest: dict[str, Any]) -> dict[str, object]:
    validate_manifest(manifest)
    _require_manifest_contract(manifest)
    fixture = build_strong_whole_query_fixture()
    return {
        "bindings": strong_whole_query_bindings(fixture),
        "fixture": {
            "active_delta_payload": ACTIVE_DELTA_PAYLOAD,
            "base_active_coordinate_count": 4,
            "cols": COLS,
            "effective_slots": EFFECTIVE_SLOTS,
            "kind": "actual-cssc-base-plus-strong-delta",
            "physical_batch_size": PHYSICAL_BATCH_SIZE,
            "rows": ROWS,
            "segment_width": SEGMENT_WIDTH,
            "version_id": VERSION_ID,
        },
        "schema_version": "strong-whole-query-witness-bindings-v2",
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
        description="Generate canonical bindings for the Phase 2 whole-query witness."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        payload = make_witness_binding_payload(_read_manifest(arguments.manifest))
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
    except (BindingGenerationError, ValueError, TypeError, OSError) as error:
        print(f"strong whole-query binding generation failed: {error}", file=sys.stderr)
        return 1
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
