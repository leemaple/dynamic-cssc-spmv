from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_acquisition as cli_module


def _arguments(tmp_path: Path, *, phase: str) -> argparse.Namespace:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output_parent = (tmp_path / "output").resolve()
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
        provider_run_id=131,
        provider_run_attempt=1,
        unit_attempt_ordinal=1,
        scratch_root=scratch,
        output_directory=output_parent / "artifact",
        producer_artifact_directory=(
            producer if phase == "guarded-final" else None
        ),
    )


@pytest.fixture
def common_mocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        cli_module,
        "verify_followup_s1_s2_compatibility",
        lambda *_args, **_kwargs: SimpleNamespace(sha256="3" * 64),
    )
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: SimpleNamespace(),
    )

    def download(path: Path) -> tuple[str, str, dict[str, str | None]]:
        path.write_bytes(b"sentinel gzip response")
        return (
            cli_module.FOLLOWUP_SNAP_SOURCE_URL,
            "2026-08-30T00:00:01Z",
            {
                "content-length": str(path.stat().st_size),
                "content-type": "application/x-gzip",
                "etag": None,
                "last-modified": None,
            },
        )

    monkeypatch.setattr(cli_module, "_download", download)


def _inspection(transform: object) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_name="followup-acquisition-sentinel",
        transform=transform,
        unit_identity_sha256="4" * 64,
    )


def test_acquisition_producer_downloads_transforms_wraps_and_erases_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = _arguments(tmp_path, phase="private-handoff")
    transform = SimpleNamespace(raw_object_sha256="5" * 64)
    observed: dict[str, object] = {}

    def transform_source(*args: object, **kwargs: object) -> object:
        observed["transform"] = (args, kwargs)
        return transform

    def wrap(*args: object, **kwargs: object) -> SimpleNamespace:
        observed["wrapper"] = (args, kwargs)
        return _inspection(transform)

    monkeypatch.setattr(cli_module, "transform_route_a_snap_gzip", transform_source)
    monkeypatch.setattr(cli_module, "produce_followup_acquisition_handoff", wrap)

    assert cli_module._main(arguments) == 0
    assert not any(arguments.scratch_root.iterdir())
    assert observed["wrapper"][0][0] is transform  # type: ignore[index]
    assert '"artifact_name":"followup-acquisition-sentinel"' in capsys.readouterr().out


def test_acquisition_guard_uses_second_transform_and_exact_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: None,
) -> None:
    arguments = _arguments(tmp_path, phase="guarded-final")
    transform = SimpleNamespace(raw_object_sha256="6" * 64)
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        cli_module,
        "transform_route_a_snap_gzip",
        lambda *_args, **_kwargs: transform,
    )

    def guard(*args: object, **kwargs: object) -> SimpleNamespace:
        observed["guard"] = (args, kwargs)
        return _inspection(transform)

    monkeypatch.setattr(
        cli_module,
        "guard_and_produce_followup_acquisition_artifact",
        guard,
    )

    assert cli_module._main(arguments) == 0
    positional = observed["guard"][0]  # type: ignore[index]
    assert positional[0] == arguments.producer_artifact_directory
    assert positional[1] is transform
    assert not any(arguments.scratch_root.iterdir())
