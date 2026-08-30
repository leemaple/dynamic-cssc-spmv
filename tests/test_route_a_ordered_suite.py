from __future__ import annotations

import hashlib
from pathlib import Path

import dynamic_cssc.route_a_snap as snap_module
from dynamic_cssc.route_a_ordered_suite import (
    inspect_route_a_ordered_suite_handoff,
    inspect_route_a_ordered_suite_replay,
    produce_route_a_ordered_suite_handoff,
    replay_and_guard_route_a_ordered_suite,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_snap import (
    RouteASnapAcceptedRecord,
    RouteASnapPartitionTransform,
    build_route_a_snap_trace,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

ROOT = Path(__file__).resolve().parents[1]
PLAN = (ROOT / "config/route-a-publication-plan.json").read_bytes()
PROFILE = RouteAScientificProfile(
    profile_id="ordered-suite-sentinel",
    qualification_seed=55_001,
    formal_seeds=(55_002, 55_003, 55_004),
    query_vector_seed=5_500_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _trace():  # type: ignore[no-untyped-def]
    raw_sha = "1" * 64
    mapping = b'{"ordered_suite_mapping_sentinel":true}\n'
    mapping_sha = hashlib.sha256(mapping).hexdigest()
    records = tuple(
        RouteASnapAcceptedRecord(
            accepted_ordinal=ordinal,
            within_file_ordinal=ordinal,
            source_id=1,
            target_id=10 + ordinal,
            historical_timestamp=ordinal,
            row_ordinal=0,
            column_ordinal=ordinal,
        )
        for ordinal in range(2)
    )
    accepted = snap_module._accepted_trace_bytes(
        partition=0,
        raw_object_sha256=raw_sha,
        mapping_sha256=mapping_sha,
        records=records,
    )
    partition = RouteASnapPartitionTransform(
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
    return build_route_a_snap_trace(partition, semantics="T1")


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="3" * 40,
        workflow_head_sha="4" * 40,
        compatibility_receipt_sha256="5" * 64,
        provider_run_id=27,
        provider_run_attempt=1,
    )


def test_ordered_suite_producer_replay_guard_and_redacted_reinspection(
    tmp_path: Path,
) -> None:
    trace = _trace()
    lineage = _lineage()
    producer_scratch = (tmp_path / "producer-scratch").resolve()
    replay_scratch = (tmp_path / "replay-scratch").resolve()
    producer_scratch.mkdir(mode=0o700)
    replay_scratch.mkdir(mode=0o700)
    producer_path = (tmp_path / "producer.zip").resolve()
    replay_path = (tmp_path / "replay.zip").resolve()

    produce_route_a_ordered_suite_handoff(
        trace,
        lineage=lineage,
        machine_plan_bytes=PLAN,
        scratch_root=producer_scratch,
        output_path=producer_path,
        scientific_profile=PROFILE,
    )
    producer = inspect_route_a_ordered_suite_handoff(
        producer_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=PLAN,
        scientific_profile=PROFILE,
    )
    replay_and_guard_route_a_ordered_suite(
        trace,
        lineage=lineage,
        machine_plan_bytes=PLAN,
        producer_archive_path=producer_path,
        scratch_root=replay_scratch,
        output_path=replay_path,
        scientific_profile=PROFILE,
    )
    replay = inspect_route_a_ordered_suite_replay(
        replay_path,
        expected_trace=trace,
        expected_lineage=lineage,
        machine_plan_bytes=PLAN,
        scientific_profile=PROFILE,
    )

    assert len(producer.cell_archives) == 6
    assert len(replay.final_cells) == 6
    assert len(replay.replay_receipts) == 6
    assert len(replay.guard_receipts) == 6
    assert all(
        cell.document["identity"]["source_kind"] == "snap-a2q"
        for cell in replay.final_cells
    )
    assert b"private-preparation" not in replay_path.read_bytes()
