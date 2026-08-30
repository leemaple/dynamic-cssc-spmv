#!/usr/bin/env python3
"""Download, transform, independently redownload, and guard SNAP a2q."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import ssl
import stat
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from dynamic_cssc.followup_performance_acquisition import (
    FOLLOWUP_SNAP_SOURCE_URL,
    FollowupAcquisitionArtifactError,
    build_route_a_snap_acquisition_receipt,
    guard_and_produce_followup_acquisition_artifact,
    produce_followup_acquisition_handoff,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    followup_inherited_unit_attempt_ordinal,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.route_a_snap import RouteASnapError, transform_route_a_snap_gzip
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

_MAX_COMPRESSED_BYTES = 4 * 1024 * 1024 * 1024


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise FollowupAcquisitionArtifactError("SNAP acquisition redirect is forbidden")


def _verify_exact_checkout(repository_root: Path, expected_s1: str) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    head = subprocess.run(
        ("git", "--no-replace-objects", "rev-parse", "HEAD"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ("git", "--no-replace-objects", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise FollowupAcquisitionArtifactError(
            "acquisition requires a clean detached exact-S1 checkout"
        )


def _download(destination: Path) -> tuple[str, str, dict[str, str | None]]:
    if destination.exists() or destination.is_symlink():
        raise FollowupAcquisitionArtifactError("SNAP download target already exists")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _RejectRedirect(),
    )
    request = urllib.request.Request(
        FOLLOWUP_SNAP_SOURCE_URL,
        headers={"Accept-Encoding": "identity", "User-Agent": "dynamic-cssc-followup/1"},
        method="GET",
    )
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o400,
    )
    try:
        with opener.open(request, timeout=120) as response:
            if response.status != 200 or response.geturl() != FOLLOWUP_SNAP_SOURCE_URL:
                raise FollowupAcquisitionArtifactError(
                    "SNAP response status or final URL changed"
                )
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > _MAX_COMPRESSED_BYTES:
                    raise FollowupAcquisitionArtifactError(
                        "SNAP response exceeds its compressed byte bound"
                    )
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:  # pragma: no cover - os.write advances or raises
                        raise FollowupAcquisitionArtifactError("SNAP response write stalled")
                    view = view[written:]
            os.fsync(descriptor)
            retrieved = dt.datetime.now(dt.UTC).replace(microsecond=0).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            headers = {
                name: response.headers.get(name)
                for name in ("content-length", "content-type", "etag", "last-modified")
            }
            return response.geturl(), retrieved, headers
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("private-handoff", "guarded-final"))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--campaign-run-admission-sha256", required=True)
    parser.add_argument("--formal-unit-ordinal", required=True, type=int, choices=range(17))
    parser.add_argument("--unit-attempt-ordinal", type=int, default=1, choices=(1, 2))
    parser.add_argument("--scratch-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--producer-artifact-directory", type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.scratch_root,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths) or (
        arguments.producer_artifact_directory is not None
        and not arguments.producer_artifact_directory.is_absolute()
    ):
        raise FollowupAcquisitionArtifactError("acquisition paths must be absolute")
    observed = arguments.scratch_root.lstat()
    if (
        arguments.scratch_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or any(arguments.scratch_root.iterdir())
    ):
        raise FollowupAcquisitionArtifactError("acquisition scratch must be empty and direct")
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    compatibility = verify_followup_s1_s2_compatibility(
        arguments.repository_root,
        s1=arguments.experiment_source_sha,
        s2=arguments.workflow_head_sha,
    )
    if compatibility.sha256 != arguments.compatibility_receipt_sha256:
        raise FollowupAcquisitionArtifactError("acquisition compatibility receipt changed")
    materialize_followup_scientific_plan(arguments.repository_root)
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    if (arguments.phase == "private-handoff") == (
        arguments.producer_artifact_directory is not None
    ):
        raise FollowupAcquisitionArtifactError(
            "acquisition phase and producer artifact presence disagree"
        )
    raw_path = arguments.scratch_root / "sx-stackoverflow-a2q.txt.gz"
    transform_scratch = arguments.scratch_root / "transform"
    transform_scratch.mkdir(mode=0o700)
    try:
        final_url, retrieved_utc, headers = _download(raw_path)
        receipt = build_route_a_snap_acquisition_receipt(
            raw_path,
            unit_attempt_ordinal=followup_inherited_unit_attempt_ordinal(
                unit_kind="formal-acquisition",
                unit_attempt_ordinal=arguments.unit_attempt_ordinal,
            ),
            final_url=final_url,
            retrieved_utc=retrieved_utc,
            response_headers=headers,
        )
        transform = transform_route_a_snap_gzip(
            raw_path,
            transform_scratch,
            raw_object_sha256=receipt.compressed_sha256,
            raw_object_byte_count=receipt.compressed_byte_count,
        )
        if arguments.phase == "private-handoff":
            inspection = produce_followup_acquisition_handoff(
                transform,
                receipt,
                arguments.output_directory,
                lineage=lineage,
                campaign_id=arguments.campaign_id,
                campaign_run_admission_sha256=(
                    arguments.campaign_run_admission_sha256
                ),
                formal_unit_ordinal=arguments.formal_unit_ordinal,
                unit_attempt_ordinal=arguments.unit_attempt_ordinal,
            )
        else:
            assert arguments.producer_artifact_directory is not None
            inspection = guard_and_produce_followup_acquisition_artifact(
                arguments.producer_artifact_directory,
                transform,
                receipt,
                arguments.output_directory,
                lineage=lineage,
                campaign_id=arguments.campaign_id,
                campaign_run_admission_sha256=(
                    arguments.campaign_run_admission_sha256
                ),
                formal_unit_ordinal=arguments.formal_unit_ordinal,
                unit_attempt_ordinal=arguments.unit_attempt_ordinal,
            )
    finally:
        raw_path.unlink(missing_ok=True)
        if transform_scratch.exists() and not transform_scratch.is_symlink():
            shutil.rmtree(transform_scratch, ignore_errors=True)
    print(
        json.dumps(
            {
                "artifact_name": inspection.artifact_name,
                "raw_object_sha256": inspection.transform.raw_object_sha256,
                "unit_identity_sha256": inspection.unit_identity_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (
        FollowupAcquisitionArtifactError,
        FollowupContractError,
        OSError,
        RouteASnapError,
        subprocess.SubprocessError,
        TypeError,
        urllib.error.URLError,
        ValueError,
    ) as error:
        print(f"follow-up acquisition failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
