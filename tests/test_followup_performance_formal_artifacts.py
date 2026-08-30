from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_formal_artifacts as formal_artifacts
from dynamic_cssc.followup_performance_formal_artifacts import (
    FollowupFormalArtifactError,
    inspect_followup_formal_synthetic_artifact,
    produce_followup_formal_synthetic_artifact,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    route_a_synthetic_shard_identity,
)
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

SENTINEL_PLAN = b'{"formal_artifact_sentinel":true}\n'
SENTINEL_PROFILE = RouteAScientificProfile(
    profile_id="formal-artifact-sentinel",
    qualification_seed=77_001,
    formal_seeds=(77_002, 77_003, 77_004),
    query_vector_seed=7_700_102,
    machine_plan_sha256=hashlib.sha256(SENTINEL_PLAN).hexdigest(),
)


def _scope() -> tuple[object, object, RouteASyntheticSuiteLineage, object]:
    scientific = SimpleNamespace(
        machine_plan_bytes=SENTINEL_PLAN,
        scientific_profile=SENTINEL_PROFILE,
    )
    profile = SENTINEL_PROFILE
    trace = generate_route_a_formal_trace(
        scale="S",
        formal_seed=profile.formal_seeds[0],
        scientific_profile=profile,
    )
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha="a" * 40,
        workflow_head_sha="b" * 40,
        compatibility_receipt_sha256="c" * 64,
        provider_run_id=88,
        provider_run_attempt=1,
    )
    return scientific, profile, lineage, trace


def test_formal_synthetic_wrapper_moves_and_reinspects_exact_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scientific, profile, lineage, trace = _scope()
    shard = route_a_synthetic_shard_identity(
        trace,
        lineage,
        scientific_profile=profile,
    )
    monkeypatch.setattr(
        formal_artifacts,
        "_inspect_inherited",
        lambda *_args, **_kwargs: SimpleNamespace(shard_identity_sha256=shard),
    )
    payload = (tmp_path / "payload.zip").resolve()
    payload.write_bytes(b"inherited-route-a-payload")
    output = (tmp_path / "artifact").resolve()

    produced = produce_followup_formal_synthetic_artifact(
        payload,
        output,
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    inspected = inspect_followup_formal_synthetic_artifact(
        output,
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )

    assert not payload.exists()
    assert produced.artifact_name == inspected.artifact_name
    assert inspected.payload_path.read_bytes() == b"inherited-route-a-payload"
    assert inspected.envelope.document["authority"] is False
    assert inspected.envelope.document["inner_role"] == (
        "formal-synthetic-private-handoff"
    )


def test_guarded_final_has_distinct_identity_but_no_terminal_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scientific, profile, lineage, trace = _scope()
    shard = route_a_synthetic_shard_identity(
        trace,
        lineage,
        scientific_profile=profile,
    )
    monkeypatch.setattr(
        formal_artifacts,
        "_inspect_inherited",
        lambda *_args, **_kwargs: SimpleNamespace(shard_identity_sha256=shard),
    )
    producer_payload = (tmp_path / "producer.zip").resolve()
    producer_payload.write_bytes(b"producer")
    final_payload = (tmp_path / "final.zip").resolve()
    final_payload.write_bytes(b"guarded-final")

    producer = produce_followup_formal_synthetic_artifact(
        producer_payload,
        (tmp_path / "producer-artifact").resolve(),
        phase="private-handoff",
        trace=trace,
        lineage=lineage,
        scientific_profile=profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    final = produce_followup_formal_synthetic_artifact(
        final_payload,
        (tmp_path / "final-artifact").resolve(),
        phase="guarded-final",
        trace=trace,
        lineage=lineage,
        scientific_profile=profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )

    assert producer.artifact_name != final.artifact_name
    manifest = final.envelope.inner_bytes.decode("ascii")
    assert '"formal_evidence_candidate":true' in manifest
    assert '"publication_evidence_admitted":false' in manifest
    assert final.envelope.document["authority"] is False


def test_formal_synthetic_replacement_attempt_fails_closed() -> None:
    scientific, profile, lineage, trace = _scope()

    with pytest.raises(FollowupFormalArtifactError, match="replacement"):
        formal_artifacts.expected_followup_formal_synthetic_artifact_name(
            phase="private-handoff",
            trace=trace,
            lineage=lineage,
            scientific_profile=profile,
            unit_attempt_ordinal=2,
        )
