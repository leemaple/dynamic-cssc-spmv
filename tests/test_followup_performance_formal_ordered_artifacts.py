from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_formal_ordered_artifacts as ordered_artifacts
import dynamic_cssc.route_a_snap as snap_module
from dynamic_cssc.followup_performance_formal_ordered_artifacts import (
    FollowupFormalOrderedArtifactError,
    inspect_followup_formal_ordered_artifact,
    produce_followup_formal_ordered_artifact,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_snap import (
    RouteASnapAcceptedRecord,
    RouteASnapPartitionTransform,
    build_route_a_snap_trace,
    route_a_snap_shard_identity,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

SENTINEL_PLAN = b'{"formal_ordered_artifact_sentinel":true}\n'
SENTINEL_PROFILE = RouteAScientificProfile(
    profile_id="formal-ordered-artifact-sentinel",
    qualification_seed=88_001,
    formal_seeds=(88_002, 88_003, 88_004),
    query_vector_seed=8_800_102,
    machine_plan_sha256=hashlib.sha256(SENTINEL_PLAN).hexdigest(),
)


def _trace():  # type: ignore[no-untyped-def]
    raw_sha = "1" * 64
    mapping = b'{"formal_ordered_mapping_sentinel":true}\n'
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
        provider_run_id=91,
        provider_run_attempt=1,
    )


def _shard(trace, lineage: RouteASyntheticSuiteLineage) -> str:  # type: ignore[no-untyped-def]
    return route_a_snap_shard_identity(
        trace,
        experiment_source_sha=lineage.experiment_source_sha,
        workflow_head_sha=lineage.workflow_head_sha,
        compatibility_receipt_sha256=lineage.compatibility_receipt_sha256,
        provider_run_id=lineage.provider_run_id,
        provider_run_attempt=lineage.provider_run_attempt,
        unit_attempt_ordinal=0,
    )


def test_formal_ordered_wrapper_moves_and_reinspects_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _trace()
    lineage = _lineage()
    monkeypatch.setattr(
        ordered_artifacts,
        "_inspect_inherited",
        lambda *_args, **_kwargs: SimpleNamespace(
            shard_identity_sha256=_shard(trace, lineage)
        ),
    )
    payload = (tmp_path / "payload.zip").resolve()
    payload.write_bytes(b"inherited-route-a-ordered-payload")
    output = (tmp_path / "artifact").resolve()

    produced = produce_followup_formal_ordered_artifact(
        payload,
        output,
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
    )
    inspected = inspect_followup_formal_ordered_artifact(
        output,
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
    )

    assert not payload.exists()
    assert produced.artifact_name == inspected.artifact_name
    assert inspected.payload_path.read_bytes() == b"inherited-route-a-ordered-payload"
    assert inspected.envelope.document["authority"] is False
    assert inspected.envelope.document["inner_role"] == (
        "formal-ordered-event-private-handoff"
    )


def test_formal_ordered_phase_and_semantics_have_distinct_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _trace()
    lineage = _lineage()
    monkeypatch.setattr(
        ordered_artifacts,
        "_inspect_inherited",
        lambda *_args, **_kwargs: SimpleNamespace(
            shard_identity_sha256=_shard(trace, lineage)
        ),
    )
    producer_payload = (tmp_path / "producer.zip").resolve()
    producer_payload.write_bytes(b"producer")
    final_payload = (tmp_path / "final.zip").resolve()
    final_payload.write_bytes(b"guarded-final")

    producer = produce_followup_formal_ordered_artifact(
        producer_payload,
        (tmp_path / "producer-artifact").resolve(),
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
    )
    final = produce_followup_formal_ordered_artifact(
        final_payload,
        (tmp_path / "final-artifact").resolve(),
        phase="guarded-final",
        trace=trace,
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
    )

    assert producer.artifact_name != final.artifact_name
    assert final.envelope.document["authority"] is False
    assert b'"formal_evidence_candidate":true' in final.envelope.inner_bytes
    assert b'"publication_evidence_admitted":false' in final.envelope.inner_bytes


def test_formal_ordered_replacement_attempt_fails_closed() -> None:
    with pytest.raises(FollowupFormalOrderedArtifactError, match="replacement"):
        ordered_artifacts.expected_followup_formal_ordered_artifact_name(
            phase="private-handoff",
            trace=_trace(),
            lineage=_lineage(),
            unit_attempt_ordinal=2,
        )
