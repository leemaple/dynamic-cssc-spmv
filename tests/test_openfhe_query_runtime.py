from __future__ import annotations

from pathlib import Path

import pytest

import dynamic_cssc.openfhe_query_runtime as runtime
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryQueryLifecycleError,
    authorize_ordinary_execution,
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.query_compiler import compile_query

ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, content: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o700 if executable else 0o600)


def _runner_repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path.resolve() / "runner-repository"
    compiler = root / "toolchain" / "test-cxx"
    _write(compiler, b"#!/bin/sh\nprintf 'test-cxx 1.0\\n'\n", executable=True)
    for index, source in enumerate(runtime._SOURCE_PATHS):
        _write(root / source, f"source-{index}\n".encode())
    runner_relative_path = "build/cpp/openfhe_query_runner"
    runner = root / runner_relative_path
    _write(runner, b"#!/bin/sh\nexit 0\n", executable=True)
    _write(
        runner.parent / "CMakeCache.txt",
        (
            "CMAKE_BUILD_TYPE:STRING=Release\n"
            f"CMAKE_CXX_COMPILER:FILEPATH={compiler}\n"
            "CMAKE_CXX_FLAGS:STRING=-fno-omit-frame-pointer\n"
            "CMAKE_CXX_FLAGS_RELEASE:STRING=-O3 -DNDEBUG\n"
        ).encode(),
    )
    return root, runner_relative_path


def _process_scratch(tmp_path: Path, name: str) -> tuple[Path, Path, Path, Path]:
    scratch = tmp_path.resolve() / name
    scratch.mkdir(mode=0o700)
    (scratch / "home").mkdir(mode=0o700)
    (scratch / "tmp").mkdir(mode=0o700)
    object_root = scratch / "objects"
    object_root.mkdir(mode=0o700)
    request_path = scratch / "request.json"
    request_path.write_bytes(b"{}")
    return scratch, request_path, scratch / "result.json", object_root


def _shell_runner(tmp_path: Path, name: str) -> Path:
    runner = tmp_path.resolve() / name
    _write(
        runner,
        b"""#!/bin/sh
result=''
while [ "$#" -gt 0 ]; do
    if [ "$1" = '--result' ]; then
        shift
        result="$1"
    fi
    shift
done
printf '%s\\n' "$result"
""",
        executable=True,
    )
    return runner


def test_runner_build_identity_binds_binary_sources_compiler_and_flags(tmp_path: Path) -> None:
    repository, runner_relative_path = _runner_repository(tmp_path)

    identity = runtime.capture_openfhe_runner_build_identity(
        repository,
        runner_relative_path,
    )

    assert identity.runner_relative_path == runner_relative_path
    assert identity.runner_byte_count > 0
    assert identity.compiler_path.startswith(str(repository))
    assert identity.compiler_flags == (
        "-fno-omit-frame-pointer",
        "-O3",
        "-DNDEBUG",
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
    )
    assert set(dict(identity.source_sha256)) == set(runtime._SOURCE_PATHS)
    assert identity.to_document()["schema_version"] == (
        runtime.OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA
    )

    (repository / "cpp/openfhe_query_runner.cpp").write_bytes(b"changed source\n")
    changed = runtime.capture_openfhe_runner_build_identity(
        repository,
        runner_relative_path,
    )
    assert changed.build_identity_sha256 != identity.build_identity_sha256


def test_process_controller_enforces_stdout_and_fast_exit_scratch_limit(
    tmp_path: Path,
) -> None:
    runner = _shell_runner(tmp_path, "test-runner")
    repository = tmp_path.resolve()
    scratch, request_path, result_path, object_root = _process_scratch(
        tmp_path,
        "successful-scratch",
    )

    observation = runtime._run_process(
        runner,
        repository_root=repository,
        scratch_root=scratch,
        request_path=request_path,
        result_path=result_path,
        object_root=object_root,
        timeout_seconds=10,
        scratch_limit_bytes=1024 * 1024,
    )

    assert observation.stdout == f"{result_path}\n".encode()
    assert observation.stderr == b""
    assert observation.elapsed_ns > 0
    assert observation.peak_scratch_bytes >= len(observation.stdout)

    limited, limited_request, limited_result, limited_objects = _process_scratch(
        tmp_path,
        "limited-scratch",
    )
    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="scratch-limit-exceeded"):
        runtime._run_process(
            runner,
            repository_root=repository,
            scratch_root=limited,
            request_path=limited_request,
            result_path=limited_result,
            object_root=limited_objects,
            timeout_seconds=10,
            scratch_limit_bytes=1,
        )


def test_failed_launch_consumes_authorization_and_cleans_private_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="runtime-cleanup-version-1",
        component_prefix="runtime-cleanup-a",
    )
    second = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="runtime-cleanup-version-1",
        component_prefix="runtime-cleanup-b",
    )
    bundle = bind_ordinary_execution(
        compile_query((first, second), f1m_policy="overlap-only")
    )
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="runtime-cleanup-query-1",
        vector=(5, 7, 11, 13),
        modulus=65537,
        ledger=ledger,
    )
    identity = runtime.OpenFHERunnerBuildIdentity(
        runner_relative_path="build/cpp/openfhe_query_runner",
        runner_sha256="1" * 64,
        runner_byte_count=1,
        source_sha256=(("source", "2" * 64),),
        compiler_path="/compiler",
        compiler_identity_sha256="3" * 64,
        compiler_flags=("-O3",),
        build_identity_sha256="4" * 64,
    )

    monkeypatch.setattr(
        runtime,
        "capture_openfhe_runner_build_identity",
        lambda _root, _relative: identity,
    )

    def fail_after_authorization(*_args: object, **_kwargs: object) -> object:
        raise runtime.OpenFHEQueryRuntimeError("synthetic launch failure")

    monkeypatch.setattr(runtime, "_run_process", fail_after_authorization)
    scratch = tmp_path.resolve() / "owned-runtime-scratch"

    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="synthetic launch failure"):
        runtime.execute_authorized_openfhe_query(
            bundle,
            prepared,
            ledger=ledger,
            expected_output=(10,),
            repository_root=ROOT,
            runner_relative_path="build/cpp/openfhe_query_runner",
            scratch_root=scratch,
            timeout_seconds=10,
            resident_memory_limit_bytes=1024 * 1024,
            scratch_limit_bytes=1024 * 1024,
        )

    assert not scratch.exists()
    with pytest.raises(OrdinaryQueryLifecycleError, match="consumption failed"):
        authorize_ordinary_execution(bundle, prepared, ledger=ledger)
