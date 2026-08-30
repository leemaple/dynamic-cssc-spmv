from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_formal_unit as cli_module
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile


def _arguments(tmp_path: Path, *, ordinal: int, token: str) -> argparse.Namespace:
    repository = (tmp_path / "repository").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output_parent = (tmp_path / "output").resolve()
    for directory in (repository, scratch, output_parent):
        directory.mkdir()
    return argparse.Namespace(
        phase="private-handoff",
        formal_unit_ordinal=ordinal,
        expected_job_token=token,
        repository_root=repository,
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=909,
        provider_run_attempt=1,
        scratch_root=scratch,
        output_directory=output_parent / "artifact",
        producer_artifact_directory=None,
        acquisition_artifact_directory=None,
    )


def _scientific() -> SimpleNamespace:
    plan = b'{"formal_unit_sentinel":true}\n'
    return SimpleNamespace(
        scientific_profile=RouteAScientificProfile(
            profile_id="formal-unit-sentinel",
            qualification_seed=93_001,
            formal_seeds=(93_002, 93_003, 93_004),
            query_vector_seed=9_300_102,
            machine_plan_sha256=hashlib.sha256(plan).hexdigest(),
        )
    )


def test_formal_unit_dispatches_only_the_exact_ordinal_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(
        tmp_path,
        ordinal=7,
        token="formal-07-synthetic-S-seed-0",
    )
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: _scientific(),
    )
    monkeypatch.setattr(
        cli_module.synthetic_cli,
        "_main",
        lambda namespace: observed.update(vars(namespace)) or 0,
    )

    assert cli_module._main(arguments) == 0
    assert observed["scale"] == "S"
    assert observed["formal_seed"] == 93_002
    assert observed["unit_attempt_ordinal"] == 1
    assert observed["provider_run_id"] == 909


def test_formal_unit_rejects_job_token_or_phase_input_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: _scientific(),
    )
    arguments = _arguments(tmp_path, ordinal=1, token="wrong-token")
    with pytest.raises(ValueError, match="job token"):
        cli_module._main(arguments)

    arguments.expected_job_token = "formal-01-native-strategy-0-S"
    arguments.producer_artifact_directory = (tmp_path / "producer").resolve()
    with pytest.raises(ValueError, match="phase and producer"):
        cli_module._main(arguments)
