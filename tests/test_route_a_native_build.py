from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import dynamic_cssc.route_a_native_build as build_module
from dynamic_cssc.openfhe_query_runtime import (
    OpenFHEBuildProvenance,
    OpenFHELinkedLibraryIdentity,
    OpenFHERunnerBuildIdentity,
)
from dynamic_cssc.route_a_native_build import (
    RouteANativeBuildError,
    inspect_route_a_native_build,
    install_route_a_native_build,
    produce_route_a_native_build,
)
from dynamic_cssc.route_a_results import canonical_route_a_document


def _write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def _git(command: tuple[str, ...], cwd: Path) -> str:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fixture_repository(root: Path) -> tuple[str, str]:
    source = root / "_openfhe/source"
    source.mkdir(parents=True)
    _git(("git", "init", "--quiet"), source)
    _write(source / "CMakeLists.txt", b"project(test)\n")
    _git(("git", "add", "CMakeLists.txt"), source)
    _git(
        (
            "git",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "user.name=Test",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ),
        source,
    )
    commit = _git(("git", "rev-parse", "HEAD"), source)
    tree = _git(("git", "rev-parse", "HEAD^{tree}"), source)
    _write(root / "build/cpp/openfhe_query_runner", b"runner", 0o755)
    for path in build_module._FIXED_METADATA_PATHS:  # noqa: SLF001
        _write(root / path, path.encode("ascii"))
    _write(
        root / "_openfhe/install/lib/OpenFHE/OpenFHEConfig.cmake",
        b"set(BASE_OPENFHE_VERSION 1.5.1)\n",
    )
    _write(root / "_openfhe/install/lib/libOPENFHEpke.so.1.5.1", b"library", 0o755)
    _write(
        root / "config/params_manifest.json",
        json.dumps(
            {
                "openfhe": {
                    "commit": commit,
                    "repository": "https://example.invalid/openfhe.git",
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii"),
    )
    return commit, tree


def _identity(root: Path, commit: str, tree: str, *, relocated: bool) -> OpenFHERunnerBuildIdentity:
    library_path = root / "_openfhe/install/lib/libOPENFHEpke.so.1.5.1"
    library_bytes = library_path.read_bytes()
    runner_path = root / "build/cpp/openfhe_query_runner"
    runner_bytes = runner_path.read_bytes()
    library = OpenFHELinkedLibraryIdentity(
        load_name="libOPENFHEpke.so.1",
        resolved_path=str(library_path),
        byte_count=7,
        sha256=hashlib.sha256(library_bytes).hexdigest(),
        device=31 if relocated else 11,
        inode=41 if relocated else 21,
        mode=library_path.stat().st_mode & 0o7777,
        binary_format="elf-v1",
        binary_id="5" * 40,
        soname="libOPENFHEpke.so.1",
        needed_load_names=("libc.so.6",),
    )
    provenance = OpenFHEBuildProvenance(
        cmake_path="/usr/bin/cmake",
        cmake_sha256="6" * 64,
        cmake_byte_count=1,
        cmake_version="cmake version test",
        cmake_identity_sha256="7" * 64,
        cmake_cache_sha256="8" * 64,
        compile_commands_sha256="9" * 64,
        build_ninja_sha256="a" * 64,
        rules_ninja_sha256="b" * 64,
        openfhe_directory=str(root / "_openfhe/install/lib/OpenFHE"),
        openfhe_config_sha256="c" * 64,
        openfhe_repository="https://example.invalid/openfhe.git",
        openfhe_version="1.5.1",
        openfhe_package_version="1.5.1",
        openfhe_source_cmake_sha256="d" * 64,
        openfhe_source_commit=commit,
        openfhe_source_tree=tree,
        openfhe_source_clean=True,
        openfhe_cmake_cache_sha256="e" * 64,
        openfhe_compile_commands_sha256="f" * 64,
        openfhe_install_manifest_sha256="0" * 64,
    )
    return OpenFHERunnerBuildIdentity(
        runner_relative_path="build/cpp/openfhe_query_runner",
        runner_sha256=hashlib.sha256(runner_bytes).hexdigest(),
        runner_byte_count=6,
        runner_device=30 if relocated else 10,
        runner_inode=40 if relocated else 20,
        runner_mode=runner_path.stat().st_mode & 0o7777,
        runner_binary_format="elf-v1",
        runner_binary_id="2" * 40,
        runner_needed_load_names=("libOPENFHEpke.so.1",),
        source_sha256=(("cpp/openfhe_query_runner.cpp", "3" * 64),),
        compiler_path="/usr/bin/c++",
        compiler_sha256="6" * 64,
        compiler_byte_count=1,
        compiler_identity_sha256="7" * 64,
        compiler_version="test compiler",
        compiler_target="x86_64-linux-gnu",
        compiler_flags=("-O3",),
        build_provenance=provenance,
        linkage_inspection_format="linux-ldd-direct-and-transitive-v1",
        linked_libraries=(library,),
        linked_system_library_load_names=(),
        build_identity_sha256=("9" if relocated else "8") * 64,
    )


def _replace_manifest(
    source_path: Path,
    target_path: Path,
    mutate: object,
) -> None:
    with zipfile.ZipFile(source_path, "r") as source, zipfile.ZipFile(
        target_path,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == "manifest.json":
                document = json.loads(content)
                mutate(document)  # type: ignore[operator]
                content = canonical_route_a_document(document)
            target.writestr(info, content)


def test_retained_build_round_trip_ignores_only_filesystem_instance_numbers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    producer = _identity(root, commit, tree, relocated=False)
    current = _identity(root, commit, tree, relocated=True)
    observed = iter((producer, current))
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: next(observed),
    )
    archive = (tmp_path / "retained-build.zip").resolve()

    produced = produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    assert produced.producer_build_identity_sha256 == producer.build_identity_sha256
    shutil.rmtree(root / "build")
    shutil.rmtree(root / "_openfhe")

    installed, installed_identity = install_route_a_native_build(
        archive,
        repository_root=root,
    )

    assert installed.manifest_sha256 == produced.manifest_sha256
    assert installed_identity is current
    assert (root / "build/cpp/openfhe_query_runner").stat().st_mode & 0o111
    alias = root / "_openfhe/install/lib/libOPENFHEpke.so.1"
    assert alias.is_symlink()
    assert alias.resolve().read_bytes() == b"library"
    assert _git(("git", "rev-parse", "HEAD"), root / "_openfhe/source") == commit


def test_retained_build_rejects_self_consistent_archive_member_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    changed = (tmp_path / "changed.zip").resolve()
    with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(
        changed,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as target:
        for info in source.infolist():
            content = source.read(info)
            if info.filename == "build/cpp/openfhe_query_runner":
                content = b"changed"
            target.writestr(info, content)

    with pytest.raises(RouteANativeBuildError, match="inventory bytes"):
        inspect_route_a_native_build(changed)


def test_retained_build_rejects_workspace_retargeting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    other = (tmp_path / "other").resolve()
    other.mkdir()

    with pytest.raises(RouteANativeBuildError, match="workspace path"):
        install_route_a_native_build(archive, repository_root=other)


def test_retained_build_rejects_identity_bytes_that_disagree_with_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    changed = (tmp_path / "identity-drift.zip").resolve()

    def mutate(document: dict[str, object]) -> None:
        identity = document["runner_build_identity"]
        assert type(identity) is dict
        identity["runner_sha256"] = "f" * 64

    _replace_manifest(archive, changed, mutate)

    with pytest.raises(RouteANativeBuildError, match="runner identity"):
        inspect_route_a_native_build(changed)


def test_retained_build_restores_exact_mode_despite_process_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    (root / "build/cpp/openfhe_query_runner").chmod(0o770)
    producer = _identity(root, commit, tree, relocated=False)
    current = _identity(root, commit, tree, relocated=True)
    observed = iter((producer, current))
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: next(observed),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    shutil.rmtree(root / "build")
    shutil.rmtree(root / "_openfhe")
    previous_umask = os.umask(0o077)
    try:
        install_route_a_native_build(archive, repository_root=root)
    finally:
        os.umask(previous_umask)

    assert (root / "build/cpp/openfhe_query_runner").stat().st_mode & 0o7777 == 0o770


def test_retained_build_rejects_manifest_git_option_before_invoking_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    changed = (tmp_path / "git-option.zip").resolve()

    def mutate(document: dict[str, object]) -> None:
        identity = document["runner_build_identity"]
        assert type(identity) is dict
        provenance = identity["build_provenance"]
        assert type(provenance) is dict
        provenance["openfhe_source_commit"] = "--detach"

    _replace_manifest(archive, changed, mutate)
    shutil.rmtree(root / "build")
    shutil.rmtree(root / "_openfhe")
    monkeypatch.setattr(
        build_module,
        "_git",
        lambda *_args, **_kwargs: pytest.fail("git must not run for an invalid retained pin"),
    )

    with pytest.raises(RouteANativeBuildError, match="source identity"):
        install_route_a_native_build(changed, repository_root=root)


@pytest.mark.parametrize(
    "unsafe_name",
    ("../escape", "/absolute", "foreign/member"),
)
def test_retained_build_rejects_unsafe_archive_member_paths(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    archive = (tmp_path / "unsafe.zip").resolve()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as target:
        info = zipfile.ZipInfo(unsafe_name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = 0o100400 << 16
        target.writestr(info, b"unsafe")

    with pytest.raises(RouteANativeBuildError, match="path|member"):
        inspect_route_a_native_build(archive)


def test_retained_build_rejects_dirty_install_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )

    with pytest.raises(RouteANativeBuildError, match="target is not empty"):
        install_route_a_native_build(archive, repository_root=root)


@pytest.mark.parametrize(
    ("compression", "date_time", "mode"),
    (
        (zipfile.ZIP_DEFLATED, (1980, 1, 1, 0, 0, 0), 0o100400),
        (zipfile.ZIP_STORED, (1980, 1, 2, 0, 0, 0), 0o100400),
        (zipfile.ZIP_STORED, (1980, 1, 1, 0, 0, 0), 0o120777),
        (zipfile.ZIP_STORED, (1980, 1, 1, 0, 0, 0), 0o104755),
    ),
)
def test_retained_build_rejects_noncanonical_zip_member_metadata(
    tmp_path: Path,
    compression: int,
    date_time: tuple[int, int, int, int, int, int],
    mode: int,
) -> None:
    archive = (tmp_path / "unsafe-metadata.zip").resolve()
    with zipfile.ZipFile(archive, "w", compression=compression) as target:
        info = zipfile.ZipInfo("build/member", date_time=date_time)
        info.compress_type = compression
        info.create_system = 3
        info.external_attr = mode << 16
        target.writestr(info, b"unsafe")

    with pytest.raises(RouteANativeBuildError, match="member is unsafe"):
        inspect_route_a_native_build(archive)


def test_retained_build_rejects_duplicate_archive_member_names(tmp_path: Path) -> None:
    archive = (tmp_path / "duplicate.zip").resolve()
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as target,
    ):
        for content in (b"first", b"second"):
            info = zipfile.ZipInfo(
                "build/member",
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100400 << 16
            target.writestr(info, content)

    with pytest.raises(RouteANativeBuildError, match="identity is not unique"):
        inspect_route_a_native_build(archive)


def test_retained_build_rejects_excess_member_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = (tmp_path / "too-many-members.zip").resolve()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as target:
        for name in ("build/one", "build/two"):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100400 << 16
            target.writestr(info, b"x")
    monkeypatch.setattr(build_module, "_MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(RouteANativeBuildError, match="identity is not unique"):
        inspect_route_a_native_build(archive)


def test_retained_build_rejects_excess_cumulative_declared_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = (tmp_path / "too-large-declared-total.zip").resolve()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as target:
        info = zipfile.ZipInfo("build/member", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = 0o100400 << 16
        target.writestr(info, b"xx")
    monkeypatch.setattr(build_module, "_MAX_DECLARED_UNCOMPRESSED_BYTES", 1)

    with pytest.raises(RouteANativeBuildError, match="identity is not unique"):
        inspect_route_a_native_build(archive)


def test_retained_build_rejects_cross_directory_library_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    commit, tree = _fixture_repository(root)
    monkeypatch.setattr(
        build_module,
        "capture_openfhe_runner_build_identity",
        lambda *_args: _identity(root, commit, tree, relocated=False),
    )
    archive = (tmp_path / "retained-build.zip").resolve()
    produce_route_a_native_build(
        root,
        runner_relative_path="build/cpp/openfhe_query_runner",
        output_path=archive,
    )
    changed = (tmp_path / "cross-directory-alias.zip").resolve()

    def mutate(document: dict[str, object]) -> None:
        aliases = document["library_aliases"]
        assert type(aliases) is list and aliases
        alias = aliases[0]
        assert type(alias) is dict
        alias["alias_path"] = "_openfhe/install/other/libOPENFHEpke.so.1"

    _replace_manifest(archive, changed, mutate)

    with pytest.raises(RouteANativeBuildError, match="crosses a directory"):
        inspect_route_a_native_build(changed)
