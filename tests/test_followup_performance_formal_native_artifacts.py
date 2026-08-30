from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_formal_native_artifacts as native_artifacts
from dynamic_cssc.followup_performance_formal_native_artifacts import (
    inspect_followup_formal_native_artifact,
    produce_followup_formal_native_artifact,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

ROOT = Path(__file__).resolve().parents[1]
PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
PROFILE = RouteAScientificProfile(
    profile_id="formal-native-artifact-sentinel",
    qualification_seed=88_001,
    formal_seeds=(88_002, 88_003, 88_004),
    query_vector_seed=8_800_102,
    machine_plan_sha256=hashlib.sha256(PLAN_BYTES).hexdigest(),
)
BINDING = {
    "campaign_id": "6" * 64,
    "campaign_run_admission_sha256": "7" * 64,
    "formal_unit_ordinal": 1,
}


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=91,
        provider_run_attempt=1,
    )


def _scope(tmp_path: Path) -> dict[str, object]:
    repository = (tmp_path / "repo").resolve()
    repository.mkdir()
    return {
        "repository_root": repository,
        "lineage": _lineage(),
        "scale": "S",
        "formal_seed": PROFILE.formal_seeds[0],
        "strategy_candidate_id": "periodic-repack/windows=1",
        "scientific_profile": PROFILE,
        "machine_plan_bytes": PLAN_BYTES,
    }


def test_native_wrapper_moves_tree_and_binds_outer_to_inner_attempt_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _scope(tmp_path)
    source = (tmp_path / "source").resolve()
    source.mkdir()
    (source / "sentinel.bin").write_bytes(b"native-sentinel")
    output = (tmp_path / "output").resolve()
    monkeypatch.setattr(
        native_artifacts,
        "_inspect_inherited",
        lambda *_args, **_kwargs: SimpleNamespace(manifest_sha256="4" * 64),
    )

    produced = produce_followup_formal_native_artifact(
        source,
        output,
        phase="private-handoff",
        **BINDING,
        **scope,
    )
    inspected = inspect_followup_formal_native_artifact(
        output,
        phase="private-handoff",
        **BINDING,
        **scope,
    )

    assert not source.exists()
    assert produced.artifact_name == inspected.artifact_name
    assert (output / "inner/sentinel.bin").read_bytes() == b"native-sentinel"
    assert inspected.case.unit_attempt_ordinal == 0
    assert inspected.envelope.document["unit_attempt_ordinal"] == 1
    assert b'"inherited_unit_attempt_ordinal":0' in (
        output / "unit-identity.json"
    ).read_bytes()
    assert inspected.envelope.document["authority"] is False


def test_native_guarded_case_is_candidate_only_and_replacement_is_distinct(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope = _scope(tmp_path)
    producer_source = (tmp_path / "producer-source").resolve()
    producer_source.mkdir()
    (producer_source / "stage-ledger.json").write_bytes(b'{"sentinel":"ledger"}\n')
    (producer_source / "warmup-receipt.json").write_bytes(b'{"sentinel":"warmup"}\n')
    producer_output = (tmp_path / "producer-output").resolve()
    source = (tmp_path / "source").resolve()
    source.mkdir()
    (source / "sentinel.bin").write_bytes(b"guarded-native-sentinel")

    def inherited(*_args: object, **kwargs: object) -> SimpleNamespace:
        case = kwargs["case"]
        phase = kwargs["phase"]
        packages = tuple(
            SimpleNamespace(
                manifest_bytes=f'{{"package":{ordinal}}}\n'.encode(),
                manifest_sha256=f"{ordinal + 20:064x}",
                members=(
                    SimpleNamespace(role="ciphertext", byte_count=100 + ordinal),
                    SimpleNamespace(role="metadata", byte_count=10 + ordinal),
                ),
            )
            for ordinal in range(3)
        )
        return SimpleNamespace(
            stage="q3" if phase == "private-handoff" else "q4",
            case_binding_sha256=case.case_binding_sha256,
            manifest_sha256="5" * 64 if phase == "private-handoff" else "6" * 64,
            input_q3_manifest_sha256=(
                None if phase == "private-handoff" else "5" * 64
            ),
            packages=packages if phase == "private-handoff" else (),
        )

    monkeypatch.setattr(native_artifacts, "_inspect_inherited", inherited)
    produce_followup_formal_native_artifact(
        producer_source,
        producer_output,
        phase="private-handoff",
        **BINDING,
        **scope,
    )

    inspection = produce_followup_formal_native_artifact(
        source,
        (tmp_path / "output").resolve(),
        phase="guarded-final",
        producer_artifact_directory=producer_output,
        **BINDING,
        **scope,
    )

    manifest = inspection.envelope.inner_bytes.decode("ascii")
    assert '"formal_evidence_candidate":true' in manifest
    assert '"publication_evidence_admitted":false' in manifest
    assert inspection.producer_observations_bytes is not None
    assert b'"producer_stage_ledger":{"sentinel":"ledger"}' in (
        inspection.producer_observations_bytes
    )
    assert b'"serialized_package_bytes":' in inspection.producer_observations_bytes
    nominal = native_artifacts.expected_followup_formal_native_artifact_name(
        phase="private-handoff",
        unit_attempt_ordinal=1,
        **BINDING,
        **scope,
    )
    replacement = native_artifacts.expected_followup_formal_native_artifact_name(
        phase="private-handoff",
        unit_attempt_ordinal=2,
        **BINDING,
        **scope,
    )
    assert replacement != nominal
    assert native_artifacts._case(
        unit_attempt_ordinal=2,
        **scope,
    ).unit_attempt_ordinal == 1
