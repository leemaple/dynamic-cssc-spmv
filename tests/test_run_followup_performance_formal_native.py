from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_formal_native as cli_module


def _arguments(tmp_path: Path, *, phase: str) -> argparse.Namespace:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output_parent = (tmp_path / "out").resolve()
    producer = (tmp_path / "producer").resolve()
    for directory in (repository, scratch, output_parent):
        directory.mkdir()
    if phase == "guarded-final":
        producer.mkdir()
    return argparse.Namespace(
        phase=phase,
        repository_root=repository,
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=101,
        provider_run_attempt=1,
        campaign_id="4" * 64,
        campaign_run_admission_sha256="5" * 64,
        formal_unit_ordinal=1,
        scale="S",
        formal_seed=99_002,
        strategy_candidate_id="periodic-repack/windows=1",
        unit_attempt_ordinal=1,
        scratch_parent=scratch,
        output_directory=output_parent / "artifact",
        producer_artifact_directory=(
            producer if phase == "guarded-final" else None
        ),
        timeout_seconds_per_process=900,
        resident_memory_limit_bytes=7 * 1024**3,
        scratch_limit_bytes=8 * 1024**3,
    )


@pytest.fixture
def common_mocks(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    profile = SimpleNamespace(profile_id="formal-native-cli-sentinel")
    scientific = SimpleNamespace(
        scientific_profile=profile,
        machine_plan_bytes=b"sentinel-plan\n",
    )
    case = SimpleNamespace(case_binding_sha256="4" * 64)
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        cli_module,
        "verify_followup_s1_s2_compatibility",
        lambda *_args, **_kwargs: SimpleNamespace(sha256="3" * 64),
    )
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: scientific,
    )
    monkeypatch.setattr(
        cli_module,
        "compile_route_a_native_formal_case",
        lambda *_args, **_kwargs: case,
    )
    return SimpleNamespace(profile=profile, scientific=scientific, case=case)


def _wrapped(arguments: argparse.Namespace, inner: Path) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_name="followup-formal-native-sentinel",
        case=SimpleNamespace(case_binding_sha256="4" * 64),
        inherited=SimpleNamespace(manifest_sha256="5" * 64),
        inner_directory=inner,
        unit_identity_sha256="6" * 64,
    )


def test_formal_native_producer_forwards_compiled_case_and_wraps_fresh_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = _arguments(tmp_path, phase="private-handoff")
    observed: dict[str, object] = {}

    def produce_inner(**kwargs: object) -> None:
        observed["native"] = kwargs
        inner = kwargs["output_directory"]
        assert isinstance(inner, Path)
        inner.mkdir()
        (inner / "sentinel").write_bytes(b"producer")

    def wrap(source: Path, output: Path, **kwargs: object) -> SimpleNamespace:
        observed["wrapper"] = kwargs
        return _wrapped(arguments, source)

    monkeypatch.setattr(
        cli_module,
        "produce_route_a_native_qualification_handoff",
        produce_inner,
    )
    monkeypatch.setattr(cli_module, "produce_followup_formal_native_artifact", wrap)

    assert cli_module._main(arguments) == 0
    assert observed["native"]["case_plan"] is common_mocks.case  # type: ignore[index]
    assert observed["wrapper"]["phase"] == "private-handoff"  # type: ignore[index]
    assert '"artifact_name":"followup-formal-native-sentinel"' in capsys.readouterr().out


def test_formal_native_replay_consumes_exact_producer_inner_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: SimpleNamespace,
) -> None:
    arguments = _arguments(tmp_path, phase="guarded-final")
    producer_inner = (tmp_path / "producer-inner").resolve()
    producer_inner.mkdir()
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        cli_module,
        "inspect_followup_formal_native_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(
            inner_directory=producer_inner,
            inherited=SimpleNamespace(manifest_sha256="7" * 64),
        ),
    )

    def replay_inner(**kwargs: object) -> None:
        observed["native"] = kwargs
        inner = kwargs["output_directory"]
        assert isinstance(inner, Path)
        inner.mkdir()
        (inner / "sentinel").write_bytes(b"replay")

    monkeypatch.setattr(
        cli_module,
        "replay_and_guard_route_a_native_qualification",
        replay_inner,
    )
    monkeypatch.setattr(
        cli_module,
        "produce_followup_formal_native_artifact",
        lambda source, _output, **_kwargs: _wrapped(arguments, source),
    )

    assert cli_module._main(arguments) == 0
    assert observed["native"]["q3_artifact_directory"] == producer_inner  # type: ignore[index]
    assert observed["native"]["expected_q3_manifest_sha256"] == "7" * 64  # type: ignore[index]
    assert observed["native"]["case_plan"] is common_mocks.case  # type: ignore[index]
