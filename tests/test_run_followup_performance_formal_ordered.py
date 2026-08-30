from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_formal_ordered as cli_module


def _arguments(tmp_path: Path, *, phase: str) -> argparse.Namespace:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output_parent = (tmp_path / "out").resolve()
    acquisition = (tmp_path / "acquisition").resolve()
    producer = (tmp_path / "producer").resolve()
    for directory in (repository, scratch, output_parent, acquisition):
        directory.mkdir()
    if phase == "guarded-final":
        producer.mkdir()
    return argparse.Namespace(
        phase=phase,
        repository_root=repository,
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=202,
        provider_run_attempt=1,
        campaign_id="4" * 64,
        campaign_run_admission_sha256="5" * 64,
        formal_unit_ordinal=13,
        acquisition_provider_run_id=201,
        acquisition_provider_artifact_id=301,
        acquisition_provider_artifact_digest=f"sha256:{'7' * 64}",
        acquisition_campaign_run_admission_sha256="6" * 64,
        partition=1,
        semantics="T2",
        unit_attempt_ordinal=1,
        acquisition_unit_attempt_ordinal=1,
        scratch_root=scratch,
        output_directory=output_parent / "artifact",
        acquisition_artifact_directory=acquisition,
        producer_artifact_directory=(
            producer if phase == "guarded-final" else None
        ),
    )


@pytest.fixture
def common_mocks(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    trace = SimpleNamespace(partition=1, semantics="T2")
    scientific = SimpleNamespace(
        scientific_profile=SimpleNamespace(profile_id="ordered-cli-sentinel"),
        machine_plan_bytes=b"sentinel-plan\n",
    )
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
        "inspect_followup_acquisition_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(traces=(trace,)),
    )
    monkeypatch.setattr(
        cli_module,
        "build_followup_acquisition_provider_binding",
        lambda *_args, **_kwargs: SimpleNamespace(sha256="8" * 64),
    )
    return SimpleNamespace(trace=trace, scientific=scientific)


def _wrapped(source: Path) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_name="followup-formal-ordered-sentinel",
        payload_sha256="4" * 64,
        unit_identity_sha256="5" * 64,
        root=source,
    )


def test_formal_ordered_producer_uses_exact_acquisition_trace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: SimpleNamespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = _arguments(tmp_path, phase="private-handoff")
    observed: dict[str, object] = {}

    def produce_inner(trace: object, **kwargs: object) -> None:
        observed["trace"] = trace
        output = kwargs["output_path"]
        assert isinstance(output, Path)
        output.write_bytes(b"ordered-producer")

    def wrap(source: Path, _output: Path, **kwargs: object) -> SimpleNamespace:
        observed["wrapper"] = kwargs
        return _wrapped(source)

    monkeypatch.setattr(cli_module, "produce_route_a_ordered_suite_handoff", produce_inner)
    monkeypatch.setattr(cli_module, "produce_followup_formal_ordered_artifact", wrap)

    assert cli_module._main(arguments) == 0
    assert observed["trace"] is common_mocks.trace
    assert observed["wrapper"]["phase"] == "private-handoff"  # type: ignore[index]
    assert '"partition":1' in capsys.readouterr().out


def test_formal_ordered_replay_consumes_exact_producer_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: SimpleNamespace,
) -> None:
    arguments = _arguments(tmp_path, phase="guarded-final")
    producer_payload = (tmp_path / "producer-inner.zip").resolve()
    producer_payload.write_bytes(b"private-producer")
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        cli_module,
        "inspect_followup_formal_ordered_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(payload_path=producer_payload),
    )

    def replay_inner(trace: object, **kwargs: object) -> None:
        observed["trace"] = trace
        observed["producer"] = kwargs["producer_archive_path"]
        output = kwargs["output_path"]
        assert isinstance(output, Path)
        output.write_bytes(b"ordered-replay")

    monkeypatch.setattr(
        cli_module,
        "replay_and_guard_route_a_ordered_suite",
        replay_inner,
    )
    monkeypatch.setattr(
        cli_module,
        "produce_followup_formal_ordered_artifact",
        lambda source, _output, **_kwargs: _wrapped(source),
    )

    assert cli_module._main(arguments) == 0
    assert observed["trace"] is common_mocks.trace
    assert observed["producer"] == producer_payload
