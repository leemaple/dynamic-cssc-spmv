#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

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
    try:
        manifest_name = "publication-trace-manifest.json"
        trace_name = "publication-trace.jsonl"
        query_vector_name = "publication-query-vector.json"
        (temporary / manifest_name).write_bytes(manifest_bytes)
        (temporary / trace_name).write_bytes(trace_bytes)
        (temporary / query_vector_name).write_bytes(query_vector_bytes)
        checksums = (
            f"{hashlib.sha256(manifest_bytes).hexdigest()}  {manifest_name}\n"
            f"{hashlib.sha256(trace_bytes).hexdigest()}  {trace_name}\n"
            f"{hashlib.sha256(query_vector_bytes).hexdigest()}  {query_vector_name}\n"
        )
        (temporary / "checksums.sha256").write_text(checksums, encoding="utf-8")
        temporary.replace(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
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
