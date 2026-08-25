from __future__ import annotations

import hashlib
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
from dynamic_cssc.strong_execution import (
    StrongExecutionError,
    authorize_strong_execution,
    compile_strong_execution,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import (
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
)

ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, content: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o700 if executable else 0o600)


def _runner_repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path.resolve() / "runner-repository"
    compiler = root / "toolchain" / "test-cxx"
    _write(
        compiler,
        b"""#!/bin/sh
if [ "$1" = '-dumpmachine' ]; then
    printf 'test-target\\n'
else
    printf 'test-cxx 1.0\\n'
fi
""",
        executable=True,
    )
    cmake = root / "toolchain" / "test-cmake"
    _write(cmake, b"#!/bin/sh\nprintf 'cmake version 1.0\\n'\n", executable=True)
    for index, source in enumerate(runtime._SOURCE_PATHS):
        _write(root / source, f"source-{index}\n".encode())
    runner_relative_path = "build/cpp/openfhe_query_runner"
    runner = root / runner_relative_path
    _write(runner, b"#!/bin/sh\nexit 0\n", executable=True)
    _write(
        runner.parent / "CMakeCache.txt",
        (
            "CMAKE_BUILD_TYPE:STRING=Release\n"
            f"CMAKE_COMMAND:INTERNAL={cmake}\n"
            f"CMAKE_CXX_COMPILER:FILEPATH={compiler}\n"
            "CMAKE_CXX_FLAGS:STRING=-fno-omit-frame-pointer\n"
            "CMAKE_CXX_FLAGS_RELEASE:STRING=-O3 -DNDEBUG\n"
            "CMAKE_GENERATOR:INTERNAL=Ninja\n"
            f"CMAKE_HOME_DIRECTORY:INTERNAL={root / 'cpp'}\n"
            f"OpenFHE_DIR:PATH={root / 'openfhe' / 'lib' / 'OpenFHE'}\n"
        ).encode(),
    )
    return root, runner_relative_path


def _build_provenance(root: Path) -> runtime.OpenFHEBuildProvenance:
    return runtime.OpenFHEBuildProvenance(
        cmake_path=str(root / "toolchain" / "test-cmake"),
        cmake_sha256="9" * 64,
        cmake_byte_count=1,
        cmake_version="cmake version 1.0",
        cmake_identity_sha256="a" * 64,
        cmake_cache_sha256="b" * 64,
        compile_commands_sha256="c" * 64,
        build_ninja_sha256="d" * 64,
        rules_ninja_sha256="e" * 64,
        openfhe_directory=str(root / "openfhe" / "lib" / "OpenFHE"),
        openfhe_config_sha256="f" * 64,
        openfhe_repository="https://example.invalid/openfhe.git",
        openfhe_version="1.5.1",
        openfhe_package_version="1.5.1",
        openfhe_source_cmake_sha256="0" * 64,
        openfhe_source_commit="1" * 40,
        openfhe_source_tree="2" * 40,
        openfhe_source_clean=True,
        openfhe_cmake_cache_sha256="3" * 64,
        openfhe_compile_commands_sha256="4" * 64,
        openfhe_install_manifest_sha256="5" * 64,
    )


def _runtime_identity(tmp_path: Path) -> runtime.OpenFHERunnerBuildIdentity:
    return runtime.OpenFHERunnerBuildIdentity(
        runner_relative_path="build/cpp/openfhe_query_runner",
        runner_sha256="1" * 64,
        runner_byte_count=1,
        runner_device=1,
        runner_inode=2,
        runner_mode=0o755,
        runner_binary_format="elf-v1",
        runner_binary_id="0" * 40,
        runner_needed_load_names=("libOPENFHEpke.so",),
        source_sha256=(("source", "2" * 64),),
        compiler_path="/compiler",
        compiler_sha256="6" * 64,
        compiler_byte_count=1,
        compiler_identity_sha256="3" * 64,
        compiler_version="test-cxx 1.0",
        compiler_target="test-target",
        compiler_flags=("-O3",),
        build_provenance=_build_provenance(tmp_path.resolve()),
        linkage_inspection_format="test-linked-library-inspector-v1",
        linked_libraries=(
            runtime.OpenFHELinkedLibraryIdentity(
                load_name="libOPENFHEpke.so",
                resolved_path="/lib/libOPENFHEpke.so",
                byte_count=1,
                sha256="5" * 64,
                device=1,
                inode=3,
                mode=0o755,
                binary_format="elf-v1",
                binary_id="7" * 40,
                soname="libOPENFHEpke.so",
                needed_load_names=("libOPENFHEcore.so",),
            ),
        ),
        linked_system_library_load_names=(),
        build_identity_sha256="4" * 64,
    )


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


def _handshake_runner(tmp_path: Path, name: str, *, ready: bytes = b"D1BRDY01") -> Path:
    runner = tmp_path.resolve() / name
    _write(
        runner,
        (
            "#!/usr/bin/python3\n"
            "import os, sys\n"
            "arguments = dict(zip(sys.argv[1::2], sys.argv[2::2]))\n"
            "write_fd = int(arguments['--control-write-fd'])\n"
            "read_fd = int(arguments['--control-read-fd'])\n"
            f"os.write(write_fd, {ready!r})\n"
            "if os.read(read_fd, 8) != b'D1BGO001': raise SystemExit(21)\n"
            "os.write(write_fd, b'D1BDON01')\n"
            "if os.read(read_fd, 8) != b'D1BGO002': raise SystemExit(22)\n"
            "print(arguments['--result'])\n"
        ).encode(),
        executable=True,
    )
    return runner


def test_runner_build_identity_binds_binary_sources_compiler_flags_and_libraries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, runner_relative_path = _runner_repository(tmp_path)
    library = repository / "lib" / "libOPENFHEpke.so"
    _write(library, b"test-openfhe-shared-library-v1")
    monkeypatch.setattr(
        runtime,
        "_inspect_linked_library_paths",
        lambda _runner: (
            "test-linked-library-inspector-v1",
            (("libOPENFHEpke.so", library),),
            ("test-system-library",),
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_binary_metadata",
        lambda path, **_kwargs: (
            "test-binary-v1",
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.name if path.suffix == ".so" else None,
            ("test-needed",),
        ),
    )
    monkeypatch.setattr(
        runtime,
        "_capture_build_provenance",
        lambda root, *_args: _build_provenance(root),
    )

    identity = runtime.capture_openfhe_runner_build_identity(
        repository,
        runner_relative_path,
    )

    assert identity.runner_relative_path == runner_relative_path
    assert identity.runner_byte_count > 0
    assert identity.compiler_path.startswith(str(repository))
    assert identity.compiler_target == "test-target"
    assert identity.compiler_version == "test-cxx 1.0"
    assert identity.runner_binary_format == "test-binary-v1"
    assert identity.runner_needed_load_names == ("test-needed",)
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
    assert identity.linkage_inspection_format == "test-linked-library-inspector-v1"
    assert identity.linked_system_library_load_names == ("test-system-library",)
    assert tuple(item.load_name for item in identity.linked_libraries) == (
        "libOPENFHEpke.so",
    )
    assert identity.linked_libraries[0].resolved_path == str(library)
    assert identity.linked_libraries[0].needed_load_names == ("test-needed",)
    assert identity.to_document()["schema_version"] == (
        runtime.OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA
    )

    (repository / "cpp/openfhe_query_runner.cpp").write_bytes(b"changed source\n")
    changed = runtime.capture_openfhe_runner_build_identity(
        repository,
        runner_relative_path,
    )
    assert changed.build_identity_sha256 != identity.build_identity_sha256

    library.write_bytes(b"test-openfhe-shared-library-v2")
    changed_library = runtime.capture_openfhe_runner_build_identity(
        repository,
        runner_relative_path,
    )
    assert changed_library.build_identity_sha256 != changed.build_identity_sha256


def test_linkage_parsers_resolve_physical_openfhe_and_retain_dyld_cache_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path.resolve()
    runner = root / "bin" / "openfhe_query_runner"
    linux_library = root / "linux" / "libOPENFHEpke.so.1"
    darwin_library = root / "darwin" / "libOPENFHEpke.1.dylib"
    _write(runner, b"test-runner", executable=True)
    _write(linux_library, b"linux-openfhe")
    _write(darwin_library, b"darwin-openfhe")
    monkeypatch.setattr(runtime.shutil, "which", lambda *_args, **_kwargs: "/tool")

    monkeypatch.setattr(
        runtime,
        "_linkage_tool_output",
        lambda _arguments, **_kwargs: (
            "linux-vdso.so.1 (0x0001)\n"
            f"libOPENFHEpke.so.1 => {linux_library} (0x0002)\n"
        ),
    )
    linux_format, linux_entries, linux_system = runtime._linux_linked_library_paths(runner)
    assert linux_format == "linux-ldd-direct-and-transitive-v1"
    assert linux_entries == (("libOPENFHEpke.so.1", linux_library),)
    assert linux_system == ()

    def darwin_output(arguments: tuple[str, ...], **_kwargs: object) -> str:
        if "-L" in arguments:
            return (
                f"{runner}:\n"
                "\t@rpath/libOPENFHEpke.1.dylib (compatibility version 1.0.0)\n"
                "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            )
        return f"cmd LC_RPATH\npath {darwin_library.parent} (offset 12)\n"

    monkeypatch.setattr(runtime, "_linkage_tool_output", darwin_output)
    darwin_format, darwin_entries, darwin_system = runtime._darwin_linked_library_paths(
        runner
    )
    assert darwin_format == "darwin-otool-direct-v1"
    assert darwin_entries == (("@rpath/libOPENFHEpke.1.dylib", darwin_library),)
    assert darwin_system == ("/usr/lib/libSystem.B.dylib",)


def test_binary_metadata_parses_elf_and_macho_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path.resolve() / "test-binary"
    _write(binary, b"test-binary", executable=True)
    monkeypatch.setattr(
        runtime.shutil,
        "which",
        lambda name, **_kwargs: f"/tool/{name}",
    )

    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")

    def linux_output(arguments: tuple[str, ...], **_kwargs: object) -> str:
        if "-n" in arguments:
            return "Build ID: A1B2C3D4\n"
        return (
            "0x1 (NEEDED) Shared library: [libOPENFHEcore.so.1]\n"
            "0x2 (NEEDED) Shared library: [libc.so.6]\n"
            "0x3 (SONAME) Library soname: [libOPENFHEpke.so.1]\n"
        )

    monkeypatch.setattr(runtime, "_linkage_tool_output", linux_output)
    assert runtime._binary_metadata(binary, expected_status=binary.lstat()) == (
        "elf-v1",
        "a1b2c3d4",
        "libOPENFHEpke.so.1",
        ("libOPENFHEcore.so.1", "libc.so.6"),
    )

    monkeypatch.setattr(runtime.platform, "system", lambda: "Darwin")

    def darwin_output(arguments: tuple[str, ...], **_kwargs: object) -> str:
        if "--uuid" in arguments:
            return "UUID: 00112233-4455-6677-8899-AABBCCDDEEFF (arm64) test\n"
        if "-L" in arguments:
            return (
                f"{binary}:\n"
                "\t@rpath/libOPENFHEpke.1.dylib (compatibility version 1.0.0)\n"
                "\t@rpath/libOPENFHEcore.1.dylib (compatibility version 1.0.0)\n"
                "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            )
        return f"{binary}:\n@rpath/libOPENFHEpke.1.dylib\n"

    monkeypatch.setattr(runtime, "_linkage_tool_output", darwin_output)
    assert runtime._binary_metadata(binary, expected_status=binary.lstat()) == (
        "mach-o-v1",
        "00112233445566778899aabbccddeeff",
        "@rpath/libOPENFHEpke.1.dylib",
        ("/usr/lib/libSystem.B.dylib", "@rpath/libOPENFHEcore.1.dylib"),
    )


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


def test_process_controller_requires_exact_ready_done_handshake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _handshake_runner(tmp_path, "handshake-runner")
    scratch, request_path, result_path, object_root = _process_scratch(
        tmp_path,
        "handshake-scratch",
    )
    identity = object.__new__(runtime.OpenFHERunnerBuildIdentity)
    monkeypatch.setattr(runtime.platform, "system", lambda: "Darwin")

    observation = runtime._run_process(
        runner,
        repository_root=tmp_path.resolve(),
        scratch_root=scratch,
        request_path=request_path,
        result_path=result_path,
        object_root=object_root,
        timeout_seconds=10,
        scratch_limit_bytes=1024 * 1024,
        runner_identity=identity,
    )

    assert observation.runtime_mapping_admission is None
    assert observation.stdout == f"{result_path}\n".encode()

    bad_runner = _handshake_runner(
        tmp_path,
        "bad-handshake-runner",
        ready=b"D1RBAD01",
    )
    bad_scratch, bad_request, bad_result, bad_objects = _process_scratch(
        tmp_path,
        "bad-handshake-scratch",
    )
    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="control record changed"):
        runtime._run_process(
            bad_runner,
            repository_root=tmp_path.resolve(),
            scratch_root=bad_scratch,
            request_path=bad_request,
            result_path=bad_result,
            object_root=bad_objects,
            timeout_seconds=10,
            scratch_limit_bytes=1024 * 1024,
            runner_identity=identity,
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
    identity = _runtime_identity(tmp_path)

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


def test_failed_strong_launch_uses_same_cleanup_and_consumption_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=4,
        effective_slots=4,
        version_id="runtime-strong-version-1",
        component_prefix="runtime-strong-base",
    )
    empty = initialize_segmented_delta(
        rows=1,
        cols=4,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=7,
        version_id="runtime-strong-version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 1, 3),),
        version_id="runtime-strong-version-1",
    ).state
    bundle = compile_strong_execution(base, delta)
    ledger = SQLiteMaskBindingLedger(tmp_path / "strong-mask-ledger.sqlite3")
    prepared = prepare_strong_query(
        bundle,
        query_id="runtime-strong-query-1",
        vector=(5, 7, 11, 13),
        modulus=65537,
        ledger=ledger,
    )
    identity = _runtime_identity(tmp_path)
    monkeypatch.setattr(
        runtime,
        "capture_openfhe_runner_build_identity",
        lambda _root, _relative: identity,
    )

    def fail_after_authorization(*_args: object, **_kwargs: object) -> object:
        raise runtime.OpenFHEQueryRuntimeError("synthetic strong launch failure")

    monkeypatch.setattr(runtime, "_run_process", fail_after_authorization)
    scratch = tmp_path.resolve() / "owned-strong-runtime-scratch"

    with pytest.raises(
        runtime.OpenFHEQueryRuntimeError,
        match="synthetic strong launch failure",
    ):
        runtime.execute_authorized_strong_openfhe_query(
            bundle,
            prepared,
            ledger=ledger,
            expected_output=(31,),
            repository_root=ROOT,
            runner_relative_path="build/cpp/openfhe_query_runner",
            scratch_root=scratch,
            timeout_seconds=10,
            resident_memory_limit_bytes=1024 * 1024,
            scratch_limit_bytes=1024 * 1024,
        )

    assert not scratch.exists()
    with pytest.raises(StrongExecutionError, match="consumption failed"):
        authorize_strong_execution(bundle, prepared, ledger=ledger)
