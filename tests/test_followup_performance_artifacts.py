from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from dynamic_cssc import followup_performance_artifacts as artifact_module
from dynamic_cssc import route_a_qualification_runtime as runtime_module
from dynamic_cssc.followup_performance_artifacts import (
    FollowupArtifactError,
    inspect_followup_qualification_artifact,
    produce_followup_qualification_artifact,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

SENTINEL_PLAN = b'{"sentinel_followup_plan":true}\n'
SENTINEL_PROFILE = RouteAScientificProfile(
    profile_id="sentinel-followup-artifact-test",
    qualification_seed=19_970_101,
    formal_seeds=(19_970_102, 19_970_103, 19_970_104),
    query_vector_seed=1_997_010_202,
    machine_plan_sha256=hashlib.sha256(SENTINEL_PLAN).hexdigest(),
)


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=71,
        provider_run_attempt=1,
    )


def _stage_tree(root: Path, *, stage: str, lineage: RouteASyntheticSuiteLineage) -> None:
    root.mkdir()
    payload_name = runtime_module._STAGE_PAYLOAD[stage]
    payload = b"sentinel inherited payload\n"
    (root / payload_name).write_bytes(payload)
    expected_stages = runtime_module._expected_stages(stage)
    ledger = canonical_route_a_document(
        {
            "entries": [
                {
                    "observed_monotonic_ns": 100 + ordinal,
                    "scratch_allocated_bytes": ordinal,
                    "sequence": ordinal,
                    "stage": name,
                }
                for ordinal, name in enumerate(expected_stages)
            ],
            "formal_authority_granted": False,
            "peak_scratch_allocated_bytes": len(expected_stages),
            "publication_evidence": False,
            "schema_version": runtime_module._STAGE_LEDGER_SCHEMA,
            "stage": stage,
        }
    )
    process = canonical_route_a_document(
        {
            "command_sha256": "4" * 64,
            "elapsed_nanoseconds": 1,
            "executable_sha256": "5" * 64,
            "formal_authority_granted": False,
            "operating_system": "Linux-sentinel",
            "payload_byte_count": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "peak_rss_kib": 1,
            "peak_scratch_allocated_bytes": len(expected_stages),
            "process_id": 1,
            "process_start_time_ticks": 1,
            "publication_evidence": False,
            "return_code": 0,
            "schema_version": runtime_module._PROCESS_RECEIPT_SCHEMA,
            "scratch_cleanup_verified": True,
            "stage": stage,
            "stderr_byte_count": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_byte_count": 0,
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "wait_api": "linux-wait4-ru_maxrss-kib-v1",
        }
    )
    (root / "owned-child-receipt.json").write_bytes(process)
    (root / "stage-ledger.json").write_bytes(ledger)
    manifest = runtime_module._manifest(
        stage=stage,
        lineage=lineage,
        members=(
            (payload_name, (hashlib.sha256(payload).hexdigest(), len(payload))),
            ("owned-child-receipt.json", process),
            ("stage-ledger.json", ledger),
        ),
    )
    (root / "manifest.json").write_bytes(manifest)
    (root / "checksums.sha256").write_bytes(
        b"".join(
            f"{hashlib.sha256(content).hexdigest()}  {name}\n".encode("ascii")
            for name, content in (
                (payload_name, payload),
                ("owned-child-receipt.json", process),
                ("stage-ledger.json", ledger),
                ("manifest.json", manifest),
            )
        )
    )


@pytest.fixture
def bypass_inner_science(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        artifact_module,
        "generate_route_a_qualification_trace",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        artifact_module,
        "inspect_route_a_synthetic_suite_handoff",
        lambda *_args, **_kwargs: calls.append("q1"),
    )
    monkeypatch.setattr(
        artifact_module,
        "inspect_route_a_synthetic_suite_replay",
        lambda *_args, **_kwargs: calls.append("q2"),
    )
    return calls


@pytest.mark.parametrize("stage", ["q1", "q2"])
def test_outer_wrapper_round_trip_keeps_inherited_tree_unmodified(
    tmp_path: Path,
    stage: str,
    bypass_inner_science: list[str],
) -> None:
    lineage = _lineage()
    source = (tmp_path / "source").resolve()
    output = (tmp_path / "outer").resolve()
    _stage_tree(source, stage=stage, lineage=lineage)
    before = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.iterdir()
    }

    produced = produce_followup_qualification_artifact(
        source,
        output,
        stage=stage,  # type: ignore[arg-type]
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
        repository_root=tmp_path,
    )
    inspected = inspect_followup_qualification_artifact(
        output,
        stage=stage,  # type: ignore[arg-type]
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
        repository_root=tmp_path,
    )

    assert produced == inspected
    assert not source.exists()
    assert produced.artifact_name.startswith(f"followup-performance-v1-qualification-{stage}-")
    assert produced.envelope.document["authority"] is False
    assert produced.envelope.document["inner_role"].startswith(
        "simulator-" if stage == "q1" else "simulator-guarded"
    )
    assert {
        path.relative_to(produced.inner_directory).as_posix(): path.read_bytes()
        for path in produced.inner_directory.iterdir()
    } == before
    assert bypass_inner_science == [stage, stage, stage]


def test_inner_scientific_rejection_happens_before_outer_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lineage = _lineage()
    source = (tmp_path / "source").resolve()
    output = (tmp_path / "outer").resolve()
    _stage_tree(source, stage="q1", lineage=lineage)
    monkeypatch.setattr(
        artifact_module,
        "generate_route_a_qualification_trace",
        lambda **_kwargs: object(),
    )

    def reject(*_args, **_kwargs):
        raise ValueError("sentinel scientific rejection")

    monkeypatch.setattr(
        artifact_module,
        "inspect_route_a_synthetic_suite_handoff",
        reject,
    )
    with pytest.raises(ValueError, match="scientific rejection"):
        produce_followup_qualification_artifact(
            source,
            output,
            stage="q1",
            lineage=lineage,
            scientific_profile=SENTINEL_PROFILE,
            machine_plan_bytes=SENTINEL_PLAN,
            repository_root=tmp_path,
        )
    assert source.is_dir()
    assert not output.exists()


def test_outer_wrapper_rejects_extra_member_before_inner_exposure(
    tmp_path: Path,
    bypass_inner_science: list[str],
) -> None:
    lineage = _lineage()
    source = (tmp_path / "source").resolve()
    output = (tmp_path / "outer").resolve()
    _stage_tree(source, stage="q1", lineage=lineage)
    produce_followup_qualification_artifact(
        source,
        output,
        stage="q1",
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
        repository_root=tmp_path,
    )
    (output / "predecessor-capability.json").write_text("{}\n", encoding="ascii")

    with pytest.raises(FollowupArtifactError, match="missing, extra, or open"):
        inspect_followup_qualification_artifact(
            output,
            stage="q1",
            lineage=lineage,
            scientific_profile=SENTINEL_PROFILE,
            machine_plan_bytes=SENTINEL_PLAN,
            repository_root=tmp_path,
        )


@pytest.mark.parametrize(
    ("stage", "inner_role"),
    (
        ("q3", "native-private-handoff"),
        ("q4", "native-guarded-receipt"),
        ("q5", "combined-guard"),
        ("q6", "postrun-admission"),
    ),
)
def test_later_stage_outer_identity_is_closed_without_rewriting_inner_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    inner_role: str,
) -> None:
    lineage = _lineage()
    source = (tmp_path / "source").resolve()
    output = (tmp_path / "outer").resolve()
    source.mkdir()
    (source / "sentinel.bin").write_bytes(b"later-stage-inner\n")
    calls: list[str] = []

    def inspect_inner(_root: Path, **kwargs: object) -> SimpleNamespace:
        calls.append(str(kwargs["stage"]))
        return SimpleNamespace(manifest_sha256="7" * 64, record_sha256="8" * 64)

    monkeypatch.setattr(artifact_module, "_inspect_inherited", inspect_inner)
    produced = produce_followup_qualification_artifact(
        source,
        output,
        stage=stage,  # type: ignore[arg-type]
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
        repository_root=tmp_path,
    )
    inspected = inspect_followup_qualification_artifact(
        output,
        stage=stage,  # type: ignore[arg-type]
        lineage=lineage,
        scientific_profile=SENTINEL_PROFILE,
        machine_plan_bytes=SENTINEL_PLAN,
        repository_root=tmp_path,
    )

    assert produced == inspected
    assert produced.envelope.document["inner_role"] == inner_role
    assert (produced.inner_directory / "sentinel.bin").read_bytes() == (
        b"later-stage-inner\n"
    )
    assert calls == [stage, stage, stage]
