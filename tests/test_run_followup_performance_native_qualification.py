from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_native_qualification as cli_module
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"followup_native_cli_sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="followup-native-cli-sentinel",
    qualification_seed=91_001,
    formal_seeds=(91_002, 91_003, 91_004),
    query_vector_seed=9_100_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _arguments(tmp_path: Path, *, stage: str) -> argparse.Namespace:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "output").resolve()
    repository.mkdir()
    scratch.mkdir()
    return argparse.Namespace(
        stage=stage,
        repository_root=repository,
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=71,
        provider_run_attempt=1,
        scratch_parent=scratch,
        output_directory=output,
        q3_artifact_directory=None,
        timeout_seconds_per_process=900,
        resident_memory_limit_bytes=7 * 1024**3,
        scratch_limit_bytes=8 * 1024**3,
    )


def _outer_inspection(*, stage: str, inner: Path) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_name=f"followup-{stage}-sentinel",
        envelope=SimpleNamespace(document={"inner_sha256": "4" * 64}),
        inherited=SimpleNamespace(manifest_sha256="5" * 64),
        inner_directory=inner,
        unit_identity_sha256="6" * 64,
    )


@pytest.fixture
def common_mocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: SimpleNamespace(
            machine_plan_bytes=PLAN,
            scientific_profile=PROFILE,
        ),
    )


def test_q3_forwards_profile_and_wraps_only_the_fresh_inner_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = _arguments(tmp_path, stage="q3")
    observed: dict[str, object] = {}

    def produce_inner(**kwargs: object) -> None:
        observed["native"] = kwargs
        output = kwargs["output_directory"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "sentinel.bin").write_bytes(b"native")

    def wrap(source: Path, output: Path, **kwargs: object) -> SimpleNamespace:
        observed["wrapper"] = (source, output, kwargs)
        return _outer_inspection(stage="q3", inner=source)

    monkeypatch.setattr(
        cli_module,
        "produce_route_a_native_qualification_handoff",
        produce_inner,
    )
    monkeypatch.setattr(cli_module, "produce_followup_qualification_artifact", wrap)

    assert cli_module._main(arguments) == 0  # noqa: SLF001
    native = observed["native"]
    assert isinstance(native, dict)
    assert native["scientific_profile"] is PROFILE
    assert native["machine_plan_bytes"] == PLAN
    wrapper = observed["wrapper"]
    assert isinstance(wrapper, tuple)
    assert wrapper[2]["stage"] == "q3"
    assert json.loads(capsys.readouterr().out)["artifact_name"] == "followup-q3-sentinel"


def test_q4_derives_the_inherited_manifest_address_from_the_verified_outer_q3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    common_mocks: None,
) -> None:
    arguments = _arguments(tmp_path, stage="q4")
    q3_outer = (tmp_path / "q3-outer").resolve()
    q3_inner = (tmp_path / "q3-inner").resolve()
    q3_outer.mkdir()
    q3_inner.mkdir()
    arguments.q3_artifact_directory = q3_outer
    observed: dict[str, object] = {}

    def inspect(*_args: object, **kwargs: object) -> SimpleNamespace:
        observed["inspect"] = kwargs
        return _outer_inspection(stage="q3", inner=q3_inner)

    def replay(**kwargs: object) -> None:
        observed["native"] = kwargs
        output = kwargs["output_directory"]
        assert isinstance(output, Path)
        output.mkdir()
        (output / "sentinel.bin").write_bytes(b"replay")

    monkeypatch.setattr(cli_module, "inspect_followup_qualification_artifact", inspect)
    monkeypatch.setattr(
        cli_module,
        "replay_and_guard_route_a_native_qualification",
        replay,
    )
    monkeypatch.setattr(
        cli_module,
        "produce_followup_qualification_artifact",
        lambda source, _output, **_kwargs: _outer_inspection(stage="q4", inner=source),
    )

    assert cli_module._main(arguments) == 0  # noqa: SLF001
    native = observed["native"]
    assert isinstance(native, dict)
    assert native["q3_artifact_directory"] == q3_inner
    assert native["expected_q3_manifest_sha256"] == "5" * 64
    assert native["scientific_profile"] is PROFILE
    assert observed["inspect"]["stage"] == "q3"  # type: ignore[index]


def test_q3_rejects_a_predecessor_or_followup_q3_input(
    tmp_path: Path,
    common_mocks: None,
) -> None:
    arguments = _arguments(tmp_path, stage="q3")
    arguments.q3_artifact_directory = (tmp_path / "unexpected-q3").resolve()

    with pytest.raises(cli_module.RouteANativeQualificationError, match="cannot consume"):
        cli_module._main(arguments)  # noqa: SLF001
