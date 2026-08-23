#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path

from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactDirectory,
    PublicationArtifactInstallError,
    install_verified_directory,
    quarantine_owned_directory,
)
from dynamic_cssc.publication_traces import (
    PublicationTraceBundle,
    PublicationTraceRequest,
    _RepositorySnapshot,
    _require_path_outside_repository,
    _test_only_prepare_publication_trace_from_bundle,
    _TraceConfig,
    prepare_publication_trace,
)

_CANONICAL_PARTITION = re.compile(r"[0-4]")
_MANIFEST_NAME = "publication-trace-manifest.json"
_TRACE_NAME = "publication-trace.jsonl"
_QUERY_VECTOR_NAME = "publication-query-vector.json"
_CHECKSUMS_NAME = "checksums.sha256"


def _write_regular_file_new(path: Path, content: bytes) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("trace artifact writing requires OS O_NOFOLLOW support")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o644)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:  # pragma: no cover - defensive OS contract guard
                raise OSError("trace artifact write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _trace_bundle_fingerprint(
    artifact_directory: PublicationArtifactDirectory,
    *,
    expected_members: tuple[tuple[str, bytes], ...],
) -> tuple[tuple[str, str], ...]:
    expected_names = tuple(name for name, _ in expected_members)
    if artifact_directory.entries() != tuple(sorted(expected_names)):
        raise RuntimeError("trace artifact directory does not have the exact member set")
    observed: list[tuple[str, str]] = []
    for name, expected_bytes in expected_members:
        content = artifact_directory.read_regular(name)
        if content != expected_bytes:
            raise RuntimeError("trace artifact member bytes changed")
        observed.append((name, artifact_directory.sha256_regular(name)))
    return tuple(observed)


def _quarantine_trace_staging(staging: Path, identity: tuple[int, int]) -> None:
    try:
        quarantine_owned_directory(staging, staging_identity=identity)
    except (OSError, PublicationArtifactInstallError):
        # Preserve any changed directory as diagnostic evidence; never delete it by path.
        return


def _parse_partition(value: str) -> int:
    if not _CANONICAL_PARTITION.fullmatch(value):
        raise argparse.ArgumentTypeError("source partition must be one canonical digit 0..4")
    return int(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare a canonical derived publication trace from a closed acquisition "
            "transaction bundle. This command never downloads or republishes raw data."
        )
    )
    parser.add_argument("--acquisition-bundle-dir", required=True, type=Path)
    parser.add_argument(
        "--dataset-id",
        required=True,
        choices=("stack-overflow", "simplewiki-2026-07", "nyc-tlc-yellow-2022"),
    )
    parser.add_argument("--semantics", required=True, choices=("T1", "T2"))
    parser.add_argument("--source-partition", required=True, type=_parse_partition)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def _write_bundle(
    output_dir: Path,
    *,
    manifest_bytes: bytes,
    trace_bytes: bytes,
    query_vector_bytes: bytes,
) -> None:
    if output_dir.exists():
        raise ValueError("output directory must not already exist")
    parent = output_dir.parent
    if not parent.is_dir():
        raise ValueError("output directory parent must already exist")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=parent))
    temporary_stat = temporary.lstat()
    staging_identity = temporary_stat.st_dev, temporary_stat.st_ino
    try:
        checksums_bytes = (
            f"{hashlib.sha256(manifest_bytes).hexdigest()}  {_MANIFEST_NAME}\n"
            f"{hashlib.sha256(trace_bytes).hexdigest()}  {_TRACE_NAME}\n"
            f"{hashlib.sha256(query_vector_bytes).hexdigest()}  {_QUERY_VECTOR_NAME}\n"
        ).encode("ascii")
        expected_members = (
            (_MANIFEST_NAME, manifest_bytes),
            (_TRACE_NAME, trace_bytes),
            (_QUERY_VECTOR_NAME, query_vector_bytes),
            (_CHECKSUMS_NAME, checksums_bytes),
        )
        for name, content in expected_members:
            _write_regular_file_new(temporary / name, content)
        directory_fd = os.open(
            temporary,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        install_verified_directory(
            temporary,
            output_dir,
            staging_identity=staging_identity,
            verifier=lambda root: _trace_bundle_fingerprint(
                root,
                expected_members=expected_members,
            ),
            fingerprint=lambda value: value,
        )
    except PublicationArtifactInstallError:
        # The installer preserves rejected or identity-changed evidence.  Do not
        # recurse through a directory whose member ownership is no longer known.
        raise
    except BaseException:
        _quarantine_trace_staging(temporary, staging_identity)
        raise


def _run(
    arguments: argparse.Namespace,
    *,
    trace_preparer: Callable[[PublicationTraceRequest], PublicationTraceBundle],
) -> int:
    request = PublicationTraceRequest(
        dataset_id=arguments.dataset_id,
        semantics=arguments.semantics,
        source_partition=arguments.source_partition,
        acquisition_bundle_dir=arguments.acquisition_bundle_dir,
    )
    bundle = trace_preparer(request)
    _write_bundle(
        arguments.output_dir,
        manifest_bytes=bundle.manifest_bytes,
        trace_bytes=bundle.trace_jsonl_bytes,
        query_vector_bytes=bundle.query_vector_bytes,
    )
    return 0


def _run_cli(
    argv: list[str],
    *,
    config: _TraceConfig,
    repository_snapshot: _RepositorySnapshot,
) -> int:
    """Private test seam with explicit frozen test configuration and provenance."""

    arguments = _parser().parse_args(argv)
    return _run(
        arguments,
        trace_preparer=lambda request: _test_only_prepare_publication_trace_from_bundle(
            request,
            config=config,
            repository_snapshot=repository_snapshot,
            repository_root=Path(__file__).resolve().parents[1],
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        repository_root = Path(__file__).resolve().parents[1]
        _require_path_outside_repository(
            arguments.acquisition_bundle_dir,
            repository_root,
            field="acquisition bundle directory",
        )
        _require_path_outside_repository(
            arguments.output_dir,
            repository_root,
            field="trace output directory",
        )
        return _run(arguments, trace_preparer=prepare_publication_trace)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
