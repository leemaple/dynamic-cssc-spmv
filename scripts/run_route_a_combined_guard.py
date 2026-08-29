#!/usr/bin/env python3
"""Run the closed q5 Route A combined qualification guard."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from dynamic_cssc.route_a_native_case import RouteANativeCaseError
from dynamic_cssc.route_a_native_suite import RouteANativeQualificationError
from dynamic_cssc.route_a_qualification_guard import (
    RouteACombinedGuardError,
    produce_route_a_combined_guard,
)
from dynamic_cssc.route_a_qualification_runtime import RouteAQualificationRuntimeError
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteError,
    RouteASyntheticSuiteLineage,
)


def _verify_exact_checkout(repository_root: Path, expected_s1: str) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    head = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise RouteACombinedGuardError(
            "q5 requires one clean detached exact-S1 behavior checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--provider-artifacts-json", required=True, type=Path)
    parser.add_argument("--q2-wrapper", required=True, type=Path)
    parser.add_argument("--q4-wrapper", required=True, type=Path)
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        paths = (
            arguments.repository_root,
            arguments.provider_artifacts_json,
            arguments.q2_wrapper,
            arguments.q4_wrapper,
            arguments.scratch_parent,
            arguments.output_directory,
        )
        if any(not path.is_absolute() for path in paths):
            raise RouteACombinedGuardError("all q5 paths must be absolute")
        _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
        lineage = RouteASyntheticSuiteLineage(
            experiment_source_sha=arguments.experiment_source_sha,
            workflow_head_sha=arguments.workflow_head_sha,
            compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
            provider_run_id=arguments.provider_run_id,
            provider_run_attempt=arguments.provider_run_attempt,
        )
        inspection = produce_route_a_combined_guard(
            repository_root=arguments.repository_root,
            lineage=lineage,
            provider_artifacts_json_path=arguments.provider_artifacts_json,
            q2_wrapper_path=arguments.q2_wrapper,
            q4_wrapper_path=arguments.q4_wrapper,
            scratch_parent=arguments.scratch_parent,
            output_directory=arguments.output_directory,
        )
        print(
            json.dumps(
                {
                    "authority_granted": False,
                    "formal_execution_authorized": False,
                    "manifest_sha256": inspection.manifest_sha256,
                    "publication_evidence": False,
                    "q2_provider_digest": inspection.q2_provider.digest,
                    "q4_provider_digest": inspection.q4_provider.digest,
                    "stage": "q5",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        OSError,
        RouteACombinedGuardError,
        RouteANativeCaseError,
        RouteANativeQualificationError,
        RouteAQualificationRuntimeError,
        RouteASyntheticSuiteError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"Route A combined qualification guard failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
