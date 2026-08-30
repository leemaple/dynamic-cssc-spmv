from __future__ import annotations

import gzip
import hashlib
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.route_a_snap as snap_module
from dynamic_cssc.route_a_artifacts import produce_route_a_synthetic_cell_archive
from dynamic_cssc.route_a_evaluation import (
    evaluate_route_a_ordered_event_cell,
    replay_route_a_ordered_event_cell_read_only,
)
from dynamic_cssc.route_a_guard import guard_route_a_ordered_event_replay
from dynamic_cssc.route_a_replay import (
    RouteAOrderedEventCellTarget,
    produce_route_a_synthetic_replay_archive,
    replay_route_a_ordered_event_cell,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_snap import (
    RouteASnapAcceptedRecord,
    RouteASnapError,
    RouteASnapPartitionTransform,
    build_route_a_snap_trace,
    decode_route_a_snap_partition,
    validate_route_a_snap_trace,
)


def _sources() -> tuple[tuple[int, int], tuple[int, int]]:
    by_partition: dict[int, list[int]] = {0: [], 1: []}
    candidate = 1
    while any(len(values) < 2 for values in by_partition.values()):
        partition = snap_module._partition(candidate)
        if len(by_partition[partition]) < 2:
            by_partition[partition].append(candidate)
        candidate += 1
    return tuple(by_partition[0]), tuple(by_partition[1])  # type: ignore[return-value]


def _small_object(tmp_path: Path) -> tuple[Path, str, int]:
    sources = _sources()
    eligible: list[tuple[int, int, int]] = []
    timestamp = 100
    for repeat in range(4):
        for partition in (0, 1):
            for source_index in (0, 1):
                source = sources[partition][source_index]
                target = 100 + partition * 10 + (repeat % 4)
                eligible.append((source, target, timestamp))
                timestamp += 1
    for partition in (0, 1):
        for ordinal in range(4):
            eligible.append(
                (
                    sources[partition][ordinal % 2],
                    100 + partition * 10 + ordinal,
                    200 + partition * 10 + ordinal,
                )
            )
    lines = [
        b"# official sentinel header",
        b"",
        b"malformed record",
        b"999 999 3",
        *[
            f"{source}\t{target} {timestamp}".encode("ascii")
            for source, target, timestamp in reversed(eligible)
        ],
    ]
    raw = gzip.compress(b"\n".join(lines) + b"\n", mtime=0)
    path = (tmp_path / "a2q.txt.gz").resolve()
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest(), len(raw)


def test_external_sort_transform_closes_mapping_suffix_and_omits_raw_bytes(
    tmp_path: Path,
) -> None:
    source, sha256, byte_count = _small_object(tmp_path)
    scratch = (tmp_path / "scratch").resolve()
    scratch.mkdir()

    transformed = snap_module._transform(
        source,
        scratch,
        raw_object_sha256=sha256,
        raw_object_byte_count=byte_count,
        prefix_count=16,
        row_count=2,
        column_count=4,
        minimum_observed_columns=3,
        suffix_count=4,
        chunk_records=3,
    )

    assert transformed.raw_object_sha256 == sha256
    assert transformed.parsing_counts == {
        "blank": 1,
        "comment": 1,
        "eligible": 24,
        "malformed": 1,
        "physical_records": 28,
        "self_loop": 1,
    }
    assert not any(scratch.iterdir())
    assert [partition.partition for partition in transformed.partitions] == [0, 1]
    for partition in transformed.partitions:
        assert len(partition.ordered_row_identities) == 2
        assert len(partition.ordered_column_identities) == 4
        assert len(partition.accepted_records) == 4
        assert [record.accepted_ordinal for record in partition.accepted_records] == list(
            range(4)
        )
        assert sha256.encode("ascii") in partition.mapping_bytes
        assert source.name.encode("ascii") not in partition.mapping_bytes


def _partition_with_records(
    records: tuple[RouteASnapAcceptedRecord, ...],
) -> RouteASnapPartitionTransform:
    raw_sha = "1" * 64
    mapping = b'{"sentinel_mapping":true}\n'
    mapping_sha = hashlib.sha256(mapping).hexdigest()
    accepted = snap_module._accepted_trace_bytes(
        partition=0,
        raw_object_sha256=raw_sha,
        mapping_sha256=mapping_sha,
        records=records,
    )
    return RouteASnapPartitionTransform(
        partition=0,
        raw_object_sha256=raw_sha,
        mapping_prefix_identity_sha256="2" * 64,
        ordered_row_identities=(),
        ordered_column_identities=(),
        ordered_reserved_column_identities=(),
        mapping_bytes=mapping,
        mapping_sha256=mapping_sha,
        accepted_records=records,
        accepted_trace_bytes=accepted,
        accepted_trace_sha256=hashlib.sha256(accepted).hexdigest(),
    )


def test_t1_caps_and_t2_expiry_precedes_admission_atomically() -> None:
    t1_records = tuple(
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=ordinal,
            source_id=1,
            target_id=2,
            historical_timestamp=ordinal,
            row_ordinal=0,
            column_ordinal=0,
        )
        for ordinal in range(9)
    )
    t1 = build_route_a_snap_trace(_partition_with_records(t1_records), semantics="T1")
    assert t1.accepted_groups[6].transitions[0].after == 7
    assert t1.accepted_groups[7].transitions == ()
    assert validate_route_a_snap_trace(t1) is t1

    t2_records = [
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=ordinal,
            source_id=1,
            target_id=2,
            historical_timestamp=ordinal,
            row_ordinal=(0 if ordinal == 0 else 1),
            column_ordinal=(0 if ordinal == 0 else 1),
        )
        for ordinal in range(1024)
    ]
    t2_records.append(
        RouteASnapAcceptedRecord(
            accepted_ordinal=1024,
            within_file_ordinal=1024,
            source_id=3,
            target_id=4,
            historical_timestamp=1024,
            row_ordinal=2,
            column_ordinal=2,
        )
    )
    t2 = build_route_a_snap_trace(
        _partition_with_records(tuple(t2_records)),
        semantics="T2",
    )
    expiry_group = t2.accepted_groups[1024]
    assert [(item.cause, item.row, item.column) for item in expiry_group.transitions] == [
        ("delete", 0, 0),
        ("insert", 2, 2),
    ]


def test_transform_rejects_wrong_raw_address_and_trace_rejects_tampering(
    tmp_path: Path,
) -> None:
    source, _sha256, byte_count = _small_object(tmp_path)
    scratch = (tmp_path / "scratch").resolve()
    scratch.mkdir()
    with pytest.raises(RouteASnapError, match="address"):
        snap_module._transform(
            source,
            scratch,
            raw_object_sha256="0" * 64,
            raw_object_byte_count=byte_count,
            prefix_count=16,
            row_count=2,
            column_count=4,
            minimum_observed_columns=3,
            suffix_count=4,
            chunk_records=3,
        )

    record = RouteASnapAcceptedRecord(0, 0, 1, 2, 3, 0, 0)
    trace = build_route_a_snap_trace(_partition_with_records((record,)), semantics="T1")
    tampered = trace.__class__(
        **{
            field: getattr(trace, field)
            for field in trace.__dataclass_fields__
            if field != "accepted_trace_bytes"
        },
        accepted_trace_bytes=trace.accepted_trace_bytes + b" ",
    )
    with pytest.raises(RouteASnapError, match="canonical derived bytes|digest changed"):
        validate_route_a_snap_trace(tampered)


def test_ordered_event_cell_uses_snap_identity_and_exact_read_only_replay(
    tmp_path: Path,
) -> None:
    plan = (
        Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    ).read_bytes()
    profile = RouteAScientificProfile(
        profile_id="ordered-event-evaluation-sentinel",
        qualification_seed=66_001,
        formal_seeds=(66_002, 66_003, 66_004),
        query_vector_seed=6_600_102,
        machine_plan_sha256=hashlib.sha256(plan).hexdigest(),
    )
    records = tuple(
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=ordinal,
            source_id=1,
            target_id=2 + ordinal,
            historical_timestamp=ordinal,
            row_ordinal=0,
            column_ordinal=ordinal,
        )
        for ordinal in range(2)
    )
    trace = build_route_a_snap_trace(_partition_with_records(records), semantics="T1")
    shard = snap_module.route_a_snap_shard_identity(
        trace,
        experiment_source_sha="3" * 40,
        workflow_head_sha="4" * 40,
        compatibility_receipt_sha256="5" * 64,
        provider_run_id=17,
        provider_run_attempt=1,
        unit_attempt_ordinal=0,
    )
    producer_scratch = (tmp_path / "producer-scratch").resolve()
    replay_scratch = (tmp_path / "replay-scratch").resolve()
    producer_scratch.mkdir()
    replay_scratch.mkdir()
    producer = evaluate_route_a_ordered_event_cell(
        trace,
        strategy_candidate_id="periodic-repack/windows=1",
        rho=Fraction(1),
        shard_identity_sha256=shard,
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan,
        scratch_directory=producer_scratch,
        scientific_profile=profile,
    )
    replay = replay_route_a_ordered_event_cell_read_only(
        trace,
        strategy_candidate_id="periodic-repack/windows=1",
        rho=Fraction(1),
        shard_identity_sha256=shard,
        unit_attempt_ordinal=0,
        machine_plan_bytes=plan,
        scratch_directory=replay_scratch,
        private_preparation_documents=producer.private_preparation_documents,
        ledger_snapshot_bytes=producer.ledger_snapshot_bytes,
        scientific_profile=profile,
    )

    identity = producer.cell.document["identity"]
    assert identity["source_kind"] == "snap-a2q"
    assert identity["object_sha256_or_null"] == trace.raw_object_sha256
    assert identity["partition_or_null"] == 0
    assert identity["semantics_or_null"] == "T1"
    assert replay.query_identity_documents == producer.query_identity_documents
    assert replay.output_digest_documents == producer.output_digest_documents

    archive_replay_scratch = (tmp_path / "archive-replay-scratch").resolve()
    archive_replay_scratch.mkdir()
    target = RouteAOrderedEventCellTarget.for_snap_trace(
        trace,
        strategy_candidate_id="periodic-repack/windows=1",
        rho=Fraction(1),
        shard_identity_sha256=shard,
        unit_attempt_ordinal=0,
    )
    producer_archive = produce_route_a_synthetic_cell_archive(producer)
    archive_replay = replay_route_a_ordered_event_cell(
        trace,
        archive_bytes=producer_archive,
        expected_target=target,
        machine_plan_bytes=plan,
        scratch_directory=archive_replay_scratch,
        scientific_profile=profile,
    )
    replay_archive = produce_route_a_synthetic_replay_archive(archive_replay)
    guard = guard_route_a_ordered_event_replay(
        producer_archive_bytes=producer_archive,
        replay_archive_bytes=replay_archive,
        expected_target=target,
        scientific_profile=profile,
    )
    assert guard.final_cell.document["identity"] == identity
    assert guard.receipt["accepted"] is True


def test_formal_partition_decoder_closes_dimensions_ids_and_global_order() -> None:
    raw_sha = "6" * 64
    rows = tuple(f"stack-overflow:user:{value:020d}" for value in range(1, 1025))
    columns = tuple(
        f"stack-overflow:user:{value:020d}" for value in range(20_000, 28_193)
    )
    mapping = snap_module._canonical(
        {
            "mapping_prefix_eligible_record_count": 1_000_000,
            "mapping_prefix_identity_sha256": "7" * 64,
            "ordered_1024_row_identities": list(rows),
            "ordered_8193_column_identities": list(columns),
            "ordered_reserved_column_identities": [],
            "partition": 1,
            "raw_object_sha256": raw_sha,
            "reserved_column_count": 0,
            "schema_version": "dynamic-cssc-route-a-snap-mapping-v1",
        }
    )
    mapping_sha = hashlib.sha256(mapping).hexdigest()
    records = tuple(
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=1_000_000 + ordinal,
            source_id=(ordinal % 1024) + 1,
            target_id=20_000 + (ordinal % 8193),
            historical_timestamp=ordinal,
            row_ordinal=ordinal % 1024,
            column_ordinal=ordinal % 8193,
        )
        for ordinal in range(4096)
    )
    accepted = snap_module._accepted_trace_bytes(
        partition=1,
        raw_object_sha256=raw_sha,
        mapping_sha256=mapping_sha,
        records=records,
    )

    decoded = decode_route_a_snap_partition(mapping, accepted)

    assert decoded.partition == 1
    assert decoded.accepted_records == records
    assert decoded.mapping_sha256 == mapping_sha
