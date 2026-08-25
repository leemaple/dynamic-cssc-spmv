#!/usr/bin/env python3
"""Run one private, non-authorizing typed query through the real OpenFHE binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
from pathlib import Path

from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    pre_admission_day2_openfhe_key_generation_plan,
)
from dynamic_cssc.openfhe_query_runtime import (
    execute_authorized_openfhe_query,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.query_compiler import compile_query

ROOT = Path(__file__).resolve().parents[1]


def _day2_plan_smoke_bytes() -> bytes:
    """Mirror one exact Day 2 member without importing its producer internals."""

    document = {
        "composite_decompositions": [],
        "day1a_authority_receipt_sha256": hashlib.sha256(
            b"non-authorizing-day1a-authority-smoke"
        ).hexdigest(),
        "day1a_inventory_sha256": hashlib.sha256(
            b"non-authorizing-day1a-inventory-smoke"
        ).hexdigest(),
        "effective_slots": 4096,
        "eval_rotate_case_ids": ["index=-1", "index=1", "index=2"],
        "inventory_source_schema_version": (
            "dynamic-cssc-day1a-rotation-inventory-v1"
        ),
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": [-1, 1, 2],
        "required_exact_indices": [-1, 1, 2],
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
    }
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--scratch-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--resident-memory-limit-bytes", type=int, default=4 * 1024**3)
    parser.add_argument("--scratch-limit-bytes", type=int, default=2 * 1024**3)
    arguments = parser.parse_args()
    if arguments.runner.is_absolute() or ".." in arguments.runner.parts:
        raise SystemExit("OpenFHE query runner must be repository-relative")
    if not arguments.scratch_dir.is_absolute():
        raise SystemExit("scratch-dir must be absolute")
    arguments.scratch_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    scratch_identity = arguments.scratch_dir.lstat()
    runtime_scratch = arguments.scratch_dir / "runtime"
    ledger = SQLiteMaskBindingLedger(arguments.scratch_dir / "mask-ledger.sqlite3")
    try:
        rotating_component = publish_component(
            {(0, 0): 2, (0, 1): 3, (0, 2): 4},
            rows=1,
            cols=4,
            effective_slots=4,
            version_id="openfhe-query-smoke-version-1",
            component_prefix="openfhe-query-smoke",
        )
        overlapping_component = publish_component(
            {(0, 3): 6},
            rows=1,
            cols=4,
            effective_slots=4,
            version_id="openfhe-query-smoke-version-1",
            component_prefix="openfhe-query-overlap-smoke",
        )
        bundle = bind_ordinary_execution(
            compile_query(
                (rotating_component, overlapping_component),
                f1m_policy="overlap-only",
            )
        )
        prepared = prepare_ordinary_query(
            bundle,
            query_id="openfhe-query-smoke-1",
            vector=(5, 7, 11, 13),
            modulus=65537,
            ledger=ledger,
        )
        execution = execute_authorized_openfhe_query(
            bundle,
            prepared,
            ledger=ledger,
            expected_output=(153,),
            repository_root=ROOT,
            runner_relative_path=arguments.runner.as_posix(),
            scratch_root=runtime_scratch,
            timeout_seconds=arguments.timeout_seconds,
            resident_memory_limit_bytes=arguments.resident_memory_limit_bytes,
            scratch_limit_bytes=arguments.scratch_limit_bytes,
            key_generation_plan=pre_admission_day2_openfhe_key_generation_plan(
                _day2_plan_smoke_bytes()
            ),
        )
        verified = execution.verified_result
        print(
            json.dumps(
                {
                    "formal_parameter_claim_allowed": False,
                    "key_material_receipt": verified.key_material_receipt.to_document(),
                    "operation_counts": dict(verified.operation_counts),
                    "publication_authority": verified.publication_authority,
                    "reconstructed_output": verified.reconstructed_output,
                    "request_sha256": verified.request_sha256,
                    "runtime_receipt": execution.runtime_receipt.to_document(),
                    "runtime_receipt_sha256": execution.runtime_receipt.receipt_sha256,
                    "second_batch_row_zero": verified.second_batch_row_zero,
                    "serialized_object_count": len(verified.serialized_objects),
                    "status": "verified-openfhe-runtime-smoke-only",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    finally:
        current = arguments.scratch_dir.lstat()
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino)
            != (scratch_identity.st_dev, scratch_identity.st_ino)
        ):
            raise RuntimeError("smoke controller scratch identity changed before cleanup")
        shutil.rmtree(arguments.scratch_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
