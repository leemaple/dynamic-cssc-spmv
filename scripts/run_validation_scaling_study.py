#!/usr/bin/env python3
"""Thin process/provider adapter for the validation-scaling study."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import stat
import sys
import time
import urllib.error
import urllib.request
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.validation_scaling_study import (
    produce_validation_scaling_seed_shard,
    replay_validation_scaling_seed_shard,
)
from scripts import validate_validation_scaling_study as evidence_validator

_RECEIPT_SCHEMA = "dynamic-cssc-validation-scaling-execution-receipt-v1"
_SOURCE_TAG = "validation-scaling-source-v2"
_RECEIPT_FIELDS = (
    "schema_version",
    "artifact_role",
    "seed_ordinal",
    "runner_os",
    "runner_arch",
    "python_version",
    "github_run_id",
    "github_run_attempt",
    "github_job",
    "source_git_sha",
    "operation_started_utc",
    "package_finished_utc",
    "seed_package_wall_nanoseconds",
    "seed_package_process_nanoseconds",
    "process_peak_rss_bytes_or_null",
    "payload_filename",
    "payload_byte_count",
    "payload_sha256",
)
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class _RunnerError(ValueError):
    """The process/provider boundary differs from the frozen execution identity."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--role",
        required=True,
        choices=("producer", "independent-replay", "aggregate"),
    )
    parser.add_argument("--seed-ordinal", type=int, choices=(1, 2, 3))
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--scratch-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--producer-artifact-directory", type=Path)
    parser.add_argument("--input-root", type=Path)
    return parser


def _strict_environment_integer(name: str) -> int:
    text = os.environ.get(name)
    if type(text) is not str or not text.isascii() or not text.isdigit():
        raise _RunnerError(f"{name} must be one positive provider integer")
    value = int(text)
    if value <= 0:
        raise _RunnerError(f"{name} must be one positive provider integer")
    return value


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_direct_file(path: Path, *, label: str) -> bytes:
    try:
        observed = path.lstat()
    except OSError as error:
        raise _RunnerError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(observed.st_mode):
        raise _RunnerError(f"{label} must be direct regular bytes")
    try:
        return path.read_bytes()
    except OSError as error:
        raise _RunnerError(f"{label} cannot be read") from error


def _require_output_directory(path: Path) -> None:
    if not path.is_absolute():
        raise _RunnerError("output_directory must be absolute")
    try:
        observed = path.lstat()
        entries = tuple(path.iterdir())
    except OSError as error:
        raise _RunnerError("output_directory is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o700
        or entries
    ):
        raise _RunnerError("output_directory must be a direct empty mode-0700 directory")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RunnerError("execution receipt contains a duplicate key")
        result[key] = value
    return result


def _canonical_receipt(content: bytes) -> dict[str, object]:
    try:
        decoded = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _RunnerError("execution receipt is not canonical ASCII JSON") from error
    if (
        type(decoded) is not dict
        or set(decoded) != set(_RECEIPT_FIELDS)
        or canonical_route_a_document(decoded) != content
    ):
        raise _RunnerError("execution receipt fields or serialization changed")
    return decoded


def _read_producer_artifact(
    directory: Path,
    *,
    seed_ordinal: int,
    github_run_id: int,
    source_git_sha: str,
) -> bytes:
    if not directory.is_absolute():
        raise _RunnerError("producer_artifact_directory must be absolute")
    try:
        observed = directory.lstat()
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise _RunnerError("producer artifact directory is unavailable") from error
    if directory.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise _RunnerError("producer artifact directory must be direct")
    names = tuple(sorted((entry.name for entry in entries), key=lambda name: name.encode()))
    if names != ("execution-receipt.json", "payload.zip"):
        raise _RunnerError("producer artifact must contain exactly the two frozen files")
    if any("/" in name or "\\" in name for name in names):
        raise _RunnerError("producer artifact member path is unsafe")
    payload = _require_direct_file(directory / "payload.zip", label="producer payload")
    receipt_bytes = _require_direct_file(
        directory / "execution-receipt.json",
        label="producer execution receipt",
    )
    receipt = _canonical_receipt(receipt_bytes)
    if (
        receipt["schema_version"] != _RECEIPT_SCHEMA
        or receipt["artifact_role"] != "producer"
        or receipt["seed_ordinal"] != seed_ordinal
        or receipt["github_run_id"] != github_run_id
        or receipt["github_run_attempt"] != 1
        or receipt["github_job"] != f"producer-seed-{seed_ordinal}"
        or receipt["source_git_sha"] != source_git_sha
        or receipt["payload_filename"] != "payload.zip"
        or receipt["payload_byte_count"] != len(payload)
        or receipt["payload_sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        raise _RunnerError("producer execution receipt does not bind the exact payload")
    return payload


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    if path.exists() or temporary.exists():
        raise _RunnerError(f"refusing to replace an existing output: {path.name}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _peak_rss_bytes() -> int | None:
    observed = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if type(observed) not in {int, float} or observed < 0:
        return None
    multiplier = 1 if sys.platform == "darwin" else 1024
    value = int(observed) * multiplier
    return value if value >= 0 else None


def _provider_json(path: str, *, token: str) -> dict[str, object]:
    api_url = os.environ.get("GITHUB_API_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if (
        type(api_url) is not str
        or api_url != "https://api.github.com"
        or type(repository) is not str
        or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
    ):
        raise _RunnerError("GitHub API or repository identity changed")
    request = urllib.request.Request(
        f"{api_url}/repos/{repository}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "dynamic-cssc-validation-scaling-v1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200:
                raise _RunnerError("GitHub provider API returned a non-success status")
            content = response.read(10 * 1024 * 1024 + 1)
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise _RunnerError("GitHub provider API read failed") from error
    if len(content) > 10 * 1024 * 1024:
        raise _RunnerError("GitHub provider API response exceeds its byte bound")
    try:
        decoded = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _RunnerError("GitHub provider API response is not closed JSON") from error
    if type(decoded) is not dict:
        raise _RunnerError("GitHub provider API response is not one object")
    return decoded


def _artifact_metadata_from_provider(
    *,
    run_id: int,
    source_git_sha: str,
    token: str,
) -> dict[str, evidence_validator.ProviderArtifactMetadata]:
    response = _provider_json(f"/actions/runs/{run_id}/artifacts?per_page=100", token=token)
    artifacts = response.get("artifacts")
    if (
        type(response.get("total_count")) is not int
        or response["total_count"] != 6
        or type(artifacts) is not list
        or len(artifacts) != 6
    ):
        raise _RunnerError("provider artifact inventory is not exactly six inputs")
    expected_names = tuple(
        f"validation-scaling-{role}-seed-{ordinal}-v1"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    by_name: dict[str, dict[str, object]] = {}
    for artifact in artifacts:
        if type(artifact) is not dict or type(artifact.get("name")) is not str:
            raise _RunnerError("provider artifact inventory contains a malformed row")
        name = artifact["name"]
        if name in by_name:
            raise _RunnerError("provider artifact inventory contains a duplicate name")
        by_name[name] = artifact
    if set(by_name) != set(expected_names):
        raise _RunnerError("provider artifact inventory names differ from the matrix")
    result: dict[str, evidence_validator.ProviderArtifactMetadata] = {}
    ids: set[int] = set()
    for name in expected_names:
        artifact = by_name[name]
        artifact_id = artifact.get("id")
        size = artifact.get("size_in_bytes")
        digest = artifact.get("digest")
        workflow_run = artifact.get("workflow_run")
        if (
            type(artifact_id) is not int
            or artifact_id <= 0
            or artifact_id in ids
            or type(size) is not int
            or size <= 0
            or type(digest) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or artifact.get("expired") is not False
            or type(workflow_run) is not dict
            or workflow_run.get("id") != run_id
            or workflow_run.get("head_branch") != _SOURCE_TAG
            or workflow_run.get("head_sha") != source_git_sha
        ):
            raise _RunnerError("provider artifact metadata binding changed")
        ids.add(artifact_id)
        result[name] = evidence_validator.ProviderArtifactMetadata(
            artifact_id=artifact_id,
            name=name,
            size_in_bytes=size,
            digest=digest,
        )
    return result


def _assert_single_run_inventory(
    *,
    run_id: int,
    source_git_sha: str,
    token: str,
) -> None:
    response = _provider_json(
        (
            "/actions/workflows/validation-scaling-study.yml/runs"
            f"?event=workflow_dispatch&branch={_SOURCE_TAG}&per_page=100"
        ),
        token=token,
    )
    runs = response.get("workflow_runs")
    if (
        type(response.get("total_count")) is not int
        or response["total_count"] != 1
        or type(runs) is not list
        or len(runs) != 1
    ):
        raise _RunnerError("formal run inventory is not exactly one workflow dispatch")
    observed = runs[0]
    if (
        type(observed) is not dict
        or type(observed.get("id")) is not int
        or observed["id"] != run_id
        or type(observed.get("run_attempt")) is not int
        or observed["run_attempt"] != 1
        or observed.get("event") != "workflow_dispatch"
        or observed.get("head_branch") != _SOURCE_TAG
        or observed.get("head_sha") != source_git_sha
    ):
        raise _RunnerError("formal run inventory differs from the exact current run")


def _job_observations_from_provider(
    *,
    run_id: int,
    token: str,
) -> tuple[dict[str, object], ...]:
    response = _provider_json(f"/actions/runs/{run_id}/jobs?per_page=100", token=token)
    jobs = response.get("jobs")
    if (
        type(response.get("total_count")) is not int
        or response["total_count"] != 7
        or type(jobs) is not list
        or len(jobs) != 7
    ):
        raise _RunnerError("provider job inventory is not exactly seven jobs")
    expected_dependency_names = tuple(
        f"{role}-seed-{ordinal}"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    by_name: dict[str, dict[str, object]] = {}
    for job in jobs:
        if type(job) is not dict or type(job.get("name")) is not str:
            raise _RunnerError("provider job inventory contains a malformed row")
        name = job["name"]
        if name in by_name:
            raise _RunnerError("provider job inventory contains a duplicate name")
        by_name[name] = job
    if set(by_name) != {*expected_dependency_names, "aggregate"}:
        raise _RunnerError("provider job inventory names differ from the topology")
    aggregate = by_name["aggregate"]
    if (
        type(aggregate.get("id")) is not int
        or aggregate["id"] <= 0
        or aggregate.get("status") != "in_progress"
        or aggregate.get("conclusion") is not None
        or type(aggregate.get("started_at")) is not str
        or aggregate.get("completed_at") is not None
    ):
        raise _RunnerError("aggregate job attempted to claim its own terminal state")
    observations: list[dict[str, object]] = []
    job_ids: set[int] = set()
    for name in expected_dependency_names:
        job = by_name[name]
        if (
            type(job.get("id")) is not int
            or job["id"] <= 0
            or job["id"] in job_ids
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or type(job.get("started_at")) is not str
            or type(job.get("completed_at")) is not str
        ):
            raise _RunnerError("dependency job is not one successful terminal observation")
        job_ids.add(job["id"])
        observations.append(
            {
                "github_job_database_id": job["id"],
                "github_job_name": name,
                "github_job_started_at": job["started_at"],
                "github_job_completed_at": job["completed_at"],
                "github_job_conclusion": "success",
            }
        )
    return tuple(observations)


def _run_aggregate(
    arguments: argparse.Namespace,
    *,
    run_id: int,
    source_git_sha: str,
) -> int:
    if (
        arguments.seed_ordinal is not None
        or arguments.producer_artifact_directory is not None
        or arguments.input_root is None
        or not arguments.input_root.is_absolute()
        or os.environ.get("GITHUB_JOB") != "aggregate"
    ):
        raise _RunnerError("aggregate arguments differ from the exact topology")
    token = os.environ.get("GITHUB_TOKEN")
    if type(token) is not str or not token:
        raise _RunnerError("aggregate lacks its read-only GitHub token")
    metadata = _artifact_metadata_from_provider(
        run_id=run_id,
        source_git_sha=source_git_sha,
        token=token,
    )
    observations = _job_observations_from_provider(run_id=run_id, token=token)
    producers, replays = evidence_validator._inspect_six_inputs(
        input_root=arguments.input_root,
        metadata_by_name=metadata,
        run_id=run_id,
        source_git_sha=source_git_sha,
    )
    aggregate = evidence_validator.build_aggregate(
        producers=producers,
        replays=replays,
        provider_observations=observations,
        source_git_sha=source_git_sha,
    )
    _atomic_write(arguments.output_directory / "aggregate.zip", aggregate)
    print(
        canonical_route_a_document(
            {
                "aggregate_sha256": hashlib.sha256(aggregate).hexdigest(),
                "authority": False,
                "formal_authority_granted": False,
                "matrix_complete": True,
            }
        ).decode("ascii"),
        end="",
    )
    return 0


def _run(arguments: argparse.Namespace) -> int:
    if not arguments.plan.is_absolute() or not arguments.scratch_root.is_absolute():
        raise _RunnerError("plan and scratch_root must be absolute")
    _require_output_directory(arguments.output_directory)
    plan_bytes = _require_direct_file(arguments.plan, label="Stage-0 v2 plan")
    run_id = _strict_environment_integer("GITHUB_RUN_ID")
    run_attempt = _strict_environment_integer("GITHUB_RUN_ATTEMPT")
    if run_attempt != 1:
        raise _RunnerError("the validation-scaling study permits only attempt one")
    source_git_sha = os.environ.get("GITHUB_SHA")
    if type(source_git_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise _RunnerError("GITHUB_SHA is not one lowercase Git object identity")
    if os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64":
        raise _RunnerError("runner OS or architecture differs from the frozen identity")
    if platform.python_version() != "3.12.13":
        raise _RunnerError("Python version differs from 3.12.13")
    token = os.environ.get("GITHUB_TOKEN")
    if type(token) is not str or not token:
        raise _RunnerError("study job lacks its read-only GitHub token")
    _assert_single_run_inventory(
        run_id=run_id,
        source_git_sha=source_git_sha,
        token=token,
    )
    if arguments.role == "aggregate":
        return _run_aggregate(
            arguments,
            run_id=run_id,
            source_git_sha=source_git_sha,
        )
    expected_job_id = "producer" if arguments.role == "producer" else "replay"
    if os.environ.get("GITHUB_JOB") != expected_job_id:
        raise _RunnerError("GITHUB_JOB differs from the exact scientific role")
    if arguments.seed_ordinal is None or arguments.input_root is not None:
        raise _RunnerError("seed role arguments differ from the exact topology")
    if arguments.role == "producer":
        if arguments.producer_artifact_directory is not None:
            raise _RunnerError("producer role cannot accept a producer artifact")
        producer_payload = None
    else:
        if arguments.producer_artifact_directory is None:
            raise _RunnerError("independent replay requires one producer artifact")
        producer_payload = _read_producer_artifact(
            arguments.producer_artifact_directory,
            seed_ordinal=arguments.seed_ordinal,
            github_run_id=run_id,
            source_git_sha=source_git_sha,
        )

    operation_started_utc = _utc_now()
    wall_started = time.perf_counter_ns()
    process_started = time.process_time_ns()
    if arguments.role == "producer":
        payload = produce_validation_scaling_seed_shard(
            plan_bytes=plan_bytes,
            seed_ordinal=arguments.seed_ordinal,
            scratch_root=arguments.scratch_root,
        )
    else:
        assert producer_payload is not None
        payload = replay_validation_scaling_seed_shard(
            plan_bytes=plan_bytes,
            producer_package_bytes=producer_payload,
            seed_ordinal=arguments.seed_ordinal,
            scratch_root=arguments.scratch_root,
        )
    wall_finished = time.perf_counter_ns()
    process_finished = time.process_time_ns()
    package_finished_utc = _utc_now()
    if wall_finished < wall_started or process_finished < process_started:
        raise _RunnerError("process-owned seed-package clock moved backwards")

    payload_sha256 = hashlib.sha256(payload).hexdigest()
    receipt = canonical_route_a_document(
        {
            "schema_version": _RECEIPT_SCHEMA,
            "artifact_role": arguments.role,
            "seed_ordinal": arguments.seed_ordinal,
            "runner_os": "Linux",
            "runner_arch": "X64",
            "python_version": "3.12.13",
            "github_run_id": run_id,
            "github_run_attempt": run_attempt,
            "github_job": f"{expected_job_id}-seed-{arguments.seed_ordinal}",
            "source_git_sha": source_git_sha,
            "operation_started_utc": operation_started_utc,
            "package_finished_utc": package_finished_utc,
            "seed_package_wall_nanoseconds": wall_finished - wall_started,
            "seed_package_process_nanoseconds": process_finished - process_started,
            "process_peak_rss_bytes_or_null": _peak_rss_bytes(),
            "payload_filename": "payload.zip",
            "payload_byte_count": len(payload),
            "payload_sha256": payload_sha256,
        }
    )
    _atomic_write(arguments.output_directory / "payload.zip", payload)
    _atomic_write(arguments.output_directory / "execution-receipt.json", receipt)
    print(
        canonical_route_a_document(
            {
                "artifact_role": arguments.role,
                "authority": False,
                "formal_authority_granted": False,
                "payload_sha256": payload_sha256,
                "seed_ordinal": arguments.seed_ordinal,
            }
        ).decode("ascii"),
        end="",
    )
    return 0


def main() -> int:
    try:
        return _run(_parser().parse_args())
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"validation-scaling seed job failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
