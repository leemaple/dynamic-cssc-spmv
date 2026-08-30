from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_combined_guard as q5_cli
import scripts.run_followup_performance_postrun_admission as q6_cli
from dynamic_cssc.followup_performance_artifacts import (
    expected_followup_qualification_artifact_name,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

PLAN = b'{"followup_late_qualification_sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="followup-late-qualification-sentinel",
    qualification_seed=92_001,
    formal_seeds=(92_002, 92_003, 92_004),
    query_vector_seed=9_200_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _common(tmp_path: Path) -> dict[str, object]:
    repository = (tmp_path / "repo").resolve()
    repository.mkdir()
    return {
        "repository_root": repository,
        "experiment_source_sha": "1" * 40,
        "workflow_head_sha": "2" * 40,
        "compatibility_receipt_sha256": "3" * 64,
        "provider_run_id": 71,
        "provider_run_attempt": 1,
        "output_directory": (tmp_path / "output").resolve(),
    }


def _lineage(arguments: argparse.Namespace) -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )


@pytest.fixture
def scientific(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    result = SimpleNamespace(machine_plan_bytes=PLAN, scientific_profile=PROFILE)
    monkeypatch.setattr(q5_cli, "materialize_followup_scientific_plan", lambda _root: result)
    monkeypatch.setattr(q6_cli, "materialize_followup_scientific_plan", lambda _root: result)
    monkeypatch.setattr(q5_cli, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(q6_cli, "_verify_exact_checkout", lambda *_args: None)
    return result


def test_q5_derives_provider_names_and_requires_outer_wrapper_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scientific: SimpleNamespace,
) -> None:
    common = _common(tmp_path)
    scratch = (tmp_path / "scratch").resolve()
    scratch.mkdir()
    arguments = argparse.Namespace(
        **common,
        provider_artifacts_json=(tmp_path / "provider.json").resolve(),
        q2_wrapper=(tmp_path / "q2.zip").resolve(),
        q4_wrapper=(tmp_path / "q4.zip").resolve(),
        scratch_parent=scratch,
    )
    observed: dict[str, object] = {}

    def produce_inner(**kwargs: object) -> None:
        observed.update(kwargs)
        output = kwargs["output_directory"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "sentinel.bin").write_bytes(b"q5")

    monkeypatch.setattr(q5_cli, "produce_route_a_combined_guard", produce_inner)
    monkeypatch.setattr(
        q5_cli,
        "produce_followup_qualification_artifact",
        lambda source, _output, **_kwargs: SimpleNamespace(
            artifact_name="followup-q5-sentinel",
            envelope=SimpleNamespace(document={"inner_sha256": "4" * 64}),
            inherited=SimpleNamespace(manifest_sha256="5" * 64),
            inner_directory=source,
            unit_identity_sha256="6" * 64,
        ),
    )

    assert q5_cli._main(arguments) == 0  # noqa: SLF001
    lineage = _lineage(arguments)
    assert observed["followup_outer_wrappers"] is True
    assert observed["q2_provider_name"] == expected_followup_qualification_artifact_name(
        stage="q2",
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
    )
    assert observed["q4_provider_name"] == expected_followup_qualification_artifact_name(
        stage="q4",
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
    )


def test_q6_requires_the_complete_five_artifact_followup_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scientific: SimpleNamespace,
) -> None:
    common = _common(tmp_path)
    arguments = argparse.Namespace(
        **common,
        expected_head_branch="main",
        run_json=(tmp_path / "run.json").resolve(),
        jobs_json=(tmp_path / "jobs.json").resolve(),
        artifacts_json=(tmp_path / "artifacts.json").resolve(),
    )
    observed: dict[str, object] = {}

    def produce_inner(**kwargs: object) -> None:
        observed.update(kwargs)
        output = kwargs["output_directory"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "sentinel.bin").write_bytes(b"q6")

    monkeypatch.setattr(q6_cli, "produce_route_a_postrun_admission", produce_inner)
    monkeypatch.setattr(
        q6_cli,
        "produce_followup_qualification_artifact",
        lambda source, _output, **_kwargs: SimpleNamespace(
            artifact_name="followup-q6-sentinel",
            envelope=SimpleNamespace(document={"inner_sha256": "4" * 64}),
            inherited=SimpleNamespace(record_sha256="5" * 64),
            inner_directory=source,
            unit_identity_sha256="6" * 64,
        ),
    )

    assert q6_cli._main(arguments) == 0  # noqa: SLF001
    lineage = _lineage(arguments)
    assert observed["expected_prefix_artifact_names"] == tuple(
        expected_followup_qualification_artifact_name(
            stage=stage,
            lineage=lineage,
            scientific_profile=scientific.scientific_profile,
        )
        for stage in ("q1", "q2", "q3", "q4", "q5")
    )
