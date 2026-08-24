#!/usr/bin/env python3
"""Run one private, non-authorizing typed query through the real OpenFHE binary."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    build_ordinary_openfhe_query_request,
    verify_ordinary_openfhe_query_result,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.query_compiler import compile_query


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--scratch-dir", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.runner.is_file():
        raise SystemExit("OpenFHE query runner is absent")
    arguments.scratch_dir.mkdir(parents=False, exist_ok=False)
    object_root = arguments.scratch_dir / "objects"
    object_root.mkdir()

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
        ledger=SQLiteMaskBindingLedger(arguments.scratch_dir / "mask-ledger.sqlite3"),
    )
    request = build_ordinary_openfhe_query_request(bundle, prepared)
    request_path = arguments.scratch_dir / "request.json"
    result_path = arguments.scratch_dir / "result.json"
    request_path.write_bytes(request)
    subprocess.run(
        (
            str(arguments.runner),
            "--request",
            str(request_path),
            "--result",
            str(result_path),
            "--object-dir",
            str(object_root),
        ),
        check=True,
        timeout=300,
    )
    verified = verify_ordinary_openfhe_query_result(
        bundle,
        prepared,
        request_bytes=request,
        result_path=result_path,
        object_root=object_root,
        expected_output=(153,),
    )
    print(
        json.dumps(
            {
                "formal_parameter_claim_allowed": False,
                "operation_counts": dict(verified.operation_counts),
                "publication_authority": verified.publication_authority,
                "reconstructed_output": verified.reconstructed_output,
                "request_sha256": verified.request_sha256,
                "second_batch_row_zero": verified.second_batch_row_zero,
                "serialized_object_count": len(verified.serialized_objects),
                "status": "verified-openfhe-smoke-only",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
