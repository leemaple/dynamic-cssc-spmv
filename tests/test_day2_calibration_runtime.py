from __future__ import annotations

import inspect
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_runtime as runtime
from dynamic_cssc.day2_calibration_authority import DAY2_RUNTIME_ISOLATION_CHECKS
from dynamic_cssc.day2_calibration_runtime import (
    Day2CalibrationRuntimeError,
    run_day2_calibration_isolated,
)


class _ProfileAuthority:
    experiment_source_git_sha = "a" * 40

    def __init__(self) -> None:
        self.calls = 0

    def validate_pre_dispatch_contract(
        self,
        operation_profile_set: object,
        rotation_key_plan: object,
        contract_bindings: object,
    ) -> None:
        assert operation_profile_set == {"profiles": "bound"}
        assert rotation_key_plan == {"rotations": "bound"}
        assert contract_bindings == {"contracts": "bound"}
        self.calls += 1


def _capability() -> object:
    return runtime._runtime_capability_from_verified_facts(  # noqa: SLF001
        runtime._VerifiedRuntimeFacts(  # noqa: SLF001
            source_git_sha="a" * 40,
            fresh_detached_checkout=True,
            clean_environment=True,
            isolated_build_root=True,
            caller_python_and_git_environment_removed=True,
            launcher_source_sha256="b" * 64,
            producer_source_sha256="c" * 64,
        )
    )


def test_live_runtime_capability_is_nonboolean_and_consumed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime, "Day2CalibrationProfileAuthority", _ProfileAuthority)
    authority = _ProfileAuthority()
    capability = _capability()

    with pytest.raises(TypeError, match="consume"):
        bool(capability)

    receipt = capability.consume(
        authority,
        {"profiles": "bound"},
        {"rotations": "bound"},
        {"contracts": "bound"},
    )

    assert authority.calls == 1
    assert receipt == {
        "schema_version": "dynamic-cssc-publication-day2-runtime-isolation-receipt-v1",
        "authority_state": "descriptive-live-capability-consumed-v1",
        "formal_authority_granted": False,
        "source_git_sha": "a" * 40,
        "fresh_detached_checkout": True,
        "clean_environment": True,
        "isolated_build_root": True,
        "caller_python_and_git_environment_removed": True,
        "profile_authority_consumed_once": True,
        "launcher_source_sha256": "b" * 64,
        "producer_source_sha256": "c" * 64,
        "isolation_checks": list(DAY2_RUNTIME_ISOLATION_CHECKS),
    }
    with pytest.raises(Day2CalibrationRuntimeError, match="already been consumed"):
        capability.consume(
            authority,
            {"profiles": "bound"},
            {"rotations": "bound"},
            {"contracts": "bound"},
        )
    assert authority.calls == 1


def test_runtime_capability_cannot_be_constructed_or_minted_from_claim_flags() -> None:
    with pytest.raises(TypeError, match="verified isolated worker"):
        runtime.Day2RuntimeIsolationCapability()
    with pytest.raises(TypeError):
        runtime._runtime_capability_from_verified_facts(  # noqa: SLF001
            {
                "fresh_detached_checkout": True,
                "clean_environment": True,
                "isolated_build_root": True,
            }
        )
    with pytest.raises(TypeError):
        runtime._VerifiedRuntimeFacts(  # noqa: SLF001
            source_git_sha="a" * 40,
            fresh_detached_checkout=True,
            clean_environment=True,
            isolated_build_root=True,
            caller_python_and_git_environment_removed=True,
            launcher_source_sha256="b" * 64,
            producer_source_sha256="c" * 64,
            runtime_isolation_verified=True,  # type: ignore[call-arg]
        )


def test_clean_worker_environment_discards_caller_injection_and_arbitrary_secrets() -> None:
    environment = runtime._clean_worker_environment(  # noqa: SLF001
        Path("/opt/toolcache/Python/3.12/bin/python"),
        {
            "PATH": "/attacker/bin",
            "PYTHONPATH": "/attacker/python",
            "PYTHONHOME": "/attacker/home",
            "GIT_DIR": "/attacker/git",
            "GIT_CONFIG_GLOBAL": "/attacker/config",
            "LD_PRELOAD": "/attacker/lib.so",
            "SECRET_TOKEN": "must-not-cross",
            "GITHUB_REPOSITORY": "leemaple/dynamic-cssc-spmv",
            "GITHUB_REPOSITORY_ID": "1341939625",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "RUNNER_OS": "Linux",
        },
    )

    assert environment["PATH"] == "/opt/toolcache/Python/3.12/bin:/usr/local/bin:/usr/bin:/bin"
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["OMP_NUM_THREADS"] == "2"
    assert environment["GITHUB_REPOSITORY"] == "leemaple/dynamic-cssc-spmv"
    assert environment["RUNNER_OS"] == "Linux"
    assert not {
        "PYTHONPATH",
        "PYTHONHOME",
        "GIT_DIR",
        "GIT_CONFIG_GLOBAL",
        "LD_PRELOAD",
        "SECRET_TOKEN",
    } & set(environment)


def test_worker_command_forces_isolated_python_and_has_only_path_inputs() -> None:
    command = runtime._worker_command(  # noqa: SLF001
        python_executable=Path("/opt/python"),
        worker_script=Path("/fresh/scripts/run_day2_calibration_isolated.py"),
        day1a_directory=Path("/runtime/input/day1a"),
        metadata_path=Path("/runtime/input/metadata.json"),
        execution_root=Path("/runtime/execution"),
        staging_archive=Path("/runtime/execution/day2.zip"),
        capability_fd=9,
    )

    assert command[:3] == ("/opt/python", "-I", "-B")
    assert "--isolated-worker" in command
    assert "--source-git-sha" not in command
    assert "--rotation-indices" not in command
    assert "--authority-verified" not in command


def test_public_isolated_launcher_accepts_only_selected_artifact_and_output_paths() -> None:
    assert tuple(inspect.signature(run_day2_calibration_isolated).parameters) == (
        "day1a_directory",
        "github_artifact_metadata_path",
        "output_archive",
    )
