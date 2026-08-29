#!/usr/bin/env python3
"""Run the closed q3 or q4 native Route A qualification stage."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from dynamic_cssc.route_a_native_build import RouteANativeBuildError
from dynamic_cssc.route_a_native_case import RouteANativeCaseError
from dynamic_cssc.route_a_native_guard import RouteANativeGuardError
from dynamic_cssc.route_a_native_invocation import RouteANativeInvocationError
from dynamic_cssc.route_a_native_runtime import RouteANativeRuntimeError
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationError,
    produce_route_a_native_qualification_handoff,
    replay_and_guard_route_a_native_qualification,
)
from dynamic_cssc.route_a_openfhe_package import RouteAOpenFHEPackageError
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage


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
        raise RouteANativeQualificationError(
            "native qualification requires one clean detached exact-S1 checkout"
        )


def _lineage(arguments: argparse.Namespace) -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=("q3", "q4"))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--q3-artifact-directory", type=Path)
    parser.add_argument("--expected-q3-manifest-sha256")
    parser.add_argument("--timeout-seconds-per-process", type=int, default=900)
    parser.add_argument("--resident-memory-limit-bytes", type=int, default=7 * 1024**3)
    parser.add_argument("--scratch-limit-bytes", type=int, default=8 * 1024**3)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        for field in ("repository_root", "scratch_parent", "output_directory"):
            value = getattr(arguments, field)
            if not value.is_absolute():
                raise RouteANativeQualificationError(f"{field} must be an absolute path")
        if (
            arguments.q3_artifact_directory is not None
            and not arguments.q3_artifact_directory.is_absolute()
        ):
            raise RouteANativeQualificationError(
                "q3_artifact_directory must be an absolute path"
            )
        _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
        common = {
            "repository_root": arguments.repository_root,
            "lineage": _lineage(arguments),
            "scratch_parent": arguments.scratch_parent,
            "output_directory": arguments.output_directory,
            "timeout_seconds_per_process": arguments.timeout_seconds_per_process,
            "resident_memory_limit_bytes": arguments.resident_memory_limit_bytes,
            "scratch_limit_bytes": arguments.scratch_limit_bytes,
        }
        if arguments.stage == "q3":
            if (
                arguments.q3_artifact_directory is not None
                or arguments.expected_q3_manifest_sha256 is not None
            ):
                raise RouteANativeQualificationError(
                    "q3 cannot consume a q3 artifact or expected q3 address"
                )
            inspection = produce_route_a_native_qualification_handoff(**common)
        else:
            if (
                arguments.q3_artifact_directory is None
                or arguments.expected_q3_manifest_sha256 is None
            ):
                raise RouteANativeQualificationError(
                    "q4 requires the exact q3 artifact and expected q3 address"
                )
            inspection = replay_and_guard_route_a_native_qualification(
                **common,
                q3_artifact_directory=arguments.q3_artifact_directory,
                expected_q3_manifest_sha256=arguments.expected_q3_manifest_sha256,
            )
        print(
            json.dumps(
                {
                    "authority_granted": False,
                    "build_manifest_sha256": inspection.build_manifest_sha256,
                    "case_binding_sha256": inspection.case_binding_sha256,
                    "input_q3_manifest_sha256_or_null": (
                        inspection.input_q3_manifest_sha256
                    ),
                    "manifest_sha256": inspection.manifest_sha256,
                    "publication_evidence": False,
                    "stage": inspection.stage,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        OSError,
        RouteANativeBuildError,
        RouteANativeCaseError,
        RouteANativeGuardError,
        RouteANativeInvocationError,
        RouteANativeQualificationError,
        RouteANativeRuntimeError,
        RouteAOpenFHEPackageError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"Route A native qualification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
