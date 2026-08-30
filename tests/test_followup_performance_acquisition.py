from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

import dynamic_cssc.route_a_snap as snap_module
from dynamic_cssc.followup_performance_acquisition import (
    FOLLOWUP_SNAP_SOURCE_URL,
    FollowupAcquisitionArtifactError,
    build_route_a_snap_acquisition_receipt,
    guard_and_produce_followup_acquisition_artifact,
    inspect_followup_acquisition_artifact,
    produce_followup_acquisition_handoff,
)
from dynamic_cssc.route_a_snap import (
    RouteASnapAcceptedRecord,
    RouteASnapPartitionTransform,
    RouteASnapTransform,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=121,
        provider_run_attempt=1,
    )


def _partition(partition: int, raw_sha: str) -> RouteASnapPartitionTransform:
    row_start = 1 + partition * 10_000
    column_start = 100_000 + partition * 20_000
    rows = tuple(
        f"stack-overflow:user:{value:020d}"
        for value in range(row_start, row_start + 1024)
    )
    columns = tuple(
        f"stack-overflow:user:{value:020d}"
        for value in range(column_start, column_start + 8193)
    )
    mapping = snap_module._canonical(
        {
            "mapping_prefix_eligible_record_count": 1_000_000,
            "mapping_prefix_identity_sha256": str(4 + partition) * 64,
            "ordered_1024_row_identities": list(rows),
            "ordered_8193_column_identities": list(columns),
            "ordered_reserved_column_identities": [],
            "partition": partition,
            "raw_object_sha256": raw_sha,
            "reserved_column_count": 0,
            "schema_version": "dynamic-cssc-route-a-snap-mapping-v1",
        }
    )
    mapping_sha = hashlib.sha256(mapping).hexdigest()
    records = tuple(
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=1_000_000 + partition * 10_000 + ordinal,
            source_id=row_start + ordinal % 1024,
            target_id=column_start + ordinal % 8193,
            historical_timestamp=ordinal,
            row_ordinal=ordinal % 1024,
            column_ordinal=ordinal % 8193,
        )
        for ordinal in range(4096)
    )
    accepted = snap_module._accepted_trace_bytes(
        partition=partition,
        raw_object_sha256=raw_sha,
        mapping_sha256=mapping_sha,
        records=records,
    )
    return RouteASnapPartitionTransform(
        partition=partition,
        raw_object_sha256=raw_sha,
        mapping_prefix_identity_sha256=str(4 + partition) * 64,
        ordered_row_identities=rows,
        ordered_column_identities=columns,
        ordered_reserved_column_identities=(),
        mapping_bytes=mapping,
        mapping_sha256=mapping_sha,
        accepted_records=records,
        accepted_trace_bytes=accepted,
        accepted_trace_sha256=hashlib.sha256(accepted).hexdigest(),
    )


def _raw_and_transform(tmp_path: Path) -> tuple[Path, RouteASnapTransform]:
    raw = gzip.compress(b"acquisition-raw-sentinel-never-redistribute\n", mtime=0)
    raw_path = (tmp_path / "source.gz").resolve()
    raw_path.write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    transform = RouteASnapTransform(
        raw_object_sha256=sha,
        raw_object_byte_count=len(raw),
        source_url=FOLLOWUP_SNAP_SOURCE_URL,
        parsing_counts={
            "blank": 1,
            "comment": 2,
            "eligible": 2_000_000,
            "malformed": 3,
            "physical_records": 2_000_010,
            "self_loop": 4,
        },
        partitions=(_partition(0, sha), _partition(1, sha)),
    )
    return raw_path, transform


def _receipt(path: Path, *, second: int = 1):  # type: ignore[no-untyped-def]
    return build_route_a_snap_acquisition_receipt(
        path,
        unit_attempt_ordinal=0,
        final_url=FOLLOWUP_SNAP_SOURCE_URL,
        retrieved_utc=f"2026-08-30T00:00:0{second}Z",
        response_headers={
            "content-length": str(path.stat().st_size),
            "content-type": "application/x-gzip",
            "etag": None,
            "last-modified": None,
        },
    )


def test_two_download_acquisition_emits_candidate_without_raw_source_bytes(
    tmp_path: Path,
) -> None:
    raw_path, transform = _raw_and_transform(tmp_path)
    producer_receipt = _receipt(raw_path, second=1)
    producer_root = (tmp_path / "producer").resolve()
    final_root = (tmp_path / "final").resolve()

    producer = produce_followup_acquisition_handoff(
        transform,
        producer_receipt,
        producer_root,
        lineage=_lineage(),
    )
    guard_receipt = _receipt(raw_path, second=2)
    final = guard_and_produce_followup_acquisition_artifact(
        producer_root,
        transform,
        guard_receipt,
        final_root,
        lineage=_lineage(),
    )
    reinspected = inspect_followup_acquisition_artifact(
        final_root,
        phase="guarded-final",
        lineage=_lineage(),
    )

    assert producer.phase == "private-handoff"
    assert final.artifact_name == reinspected.artifact_name
    assert len(reinspected.traces) == 4
    assert reinspected.guard_receipt is not None
    assert reinspected.envelope.document["authority"] is False
    assert b'"formal_evidence_candidate":true' in reinspected.envelope.inner_bytes
    assert b'"raw_source_bytes_included":false' in reinspected.envelope.inner_bytes
    raw_bytes = raw_path.read_bytes()
    assert all(
        path.read_bytes() != raw_bytes
        for path in final_root.rglob("*")
        if path.is_file()
    )


def test_acquisition_guard_rejects_second_object_drift(tmp_path: Path) -> None:
    raw_path, transform = _raw_and_transform(tmp_path)
    producer_root = (tmp_path / "producer").resolve()
    produce_followup_acquisition_handoff(
        transform,
        _receipt(raw_path),
        producer_root,
        lineage=_lineage(),
    )
    different = (tmp_path / "different.gz").resolve()
    different.write_bytes(gzip.compress(b"different raw object\n", mtime=0))

    with pytest.raises(FollowupAcquisitionArtifactError, match="differs"):
        guard_and_produce_followup_acquisition_artifact(
            producer_root,
            transform,
            _receipt(different, second=2),
            (tmp_path / "final").resolve(),
            lineage=_lineage(),
        )


def test_acquisition_receipt_rejects_same_domain_url_drift(tmp_path: Path) -> None:
    raw_path, _transform = _raw_and_transform(tmp_path)

    with pytest.raises(FollowupAcquisitionArtifactError, match="schema changed"):
        build_route_a_snap_acquisition_receipt(
            raw_path,
            unit_attempt_ordinal=0,
            final_url="https://snap.stanford.edu/data/a-different-object.txt.gz",
            retrieved_utc="2026-08-30T00:00:01Z",
            response_headers={
                "content-length": str(raw_path.stat().st_size),
                "content-type": "application/x-gzip",
                "etag": None,
                "last-modified": None,
            },
        )
