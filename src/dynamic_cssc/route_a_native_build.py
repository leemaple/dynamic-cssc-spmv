"""Content-addressed q3-to-q4 transfer for one pinned OpenFHE runner build.

The producer job captures the full repository build identity, but the replay
job does not need the multi-gigabyte compiler tree.  This module retains the
runner, every repository-owned linked library, the small provenance files
needed by ``capture_openfhe_runner_build_identity``, and a Git bundle for the
exact pinned OpenFHE source.  q4 restores those bytes at the same provider
workspace path, reconstructs a clean source checkout without network access,
and then independently captures and compares the full identity while ignoring
only filesystem instance numbers (device/inode).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dynamic_cssc.openfhe_query_runtime import (
    OpenFHERunnerBuildIdentity,
    capture_openfhe_runner_build_identity,
)
from dynamic_cssc.route_a_results import canonical_route_a_document

__all__ = (
    "RouteANativeBuildError",
    "RouteANativeBuildInspection",
    "inspect_route_a_native_build",
    "install_route_a_native_build",
    "produce_route_a_native_build",
)

_SCHEMA = "dynamic-cssc-route-a-retained-openfhe-build-v1"
_ARCHIVE_MEMBER_PREFIXES = frozenset({"_openfhe", "build", "retained-build"})
_SOURCE_BUNDLE = "retained-build/openfhe-source.bundle"
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FIXED_METADATA_PATHS = (
    "build/cpp/CMakeCache.txt",
    "build/cpp/compile_commands.json",
    "build/cpp/build.ninja",
    "build/cpp/CMakeFiles/rules.ninja",
    "_openfhe/build/CMakeCache.txt",
    "_openfhe/build/compile_commands.json",
    "_openfhe/build/install_manifest.txt",
)


class RouteANativeBuildError(RuntimeError):
    """A retained build is incomplete, unsafe, or differs after transfer."""


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise RouteANativeBuildError(f"{field} must be lowercase SHA-256")
    return value


def _canonical_object(content: bytes, *, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RouteANativeBuildError(f"{field} contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(content.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteANativeBuildError(f"{field} is not ASCII JSON") from error
    if type(document) is not dict or canonical_route_a_document(document) != content:
        raise RouteANativeBuildError(f"{field} is not canonical JSON")
    return document


def _stable_read(path: Path, *, maximum: int = _MAX_MEMBER_BYTES) -> tuple[bytes, int]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteANativeBuildError(f"retained build member is unavailable: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise RouteANativeBuildError("retained build member is outside its byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        identity = lambda value: (  # noqa: E731 - compact immutable stat projection
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or identity(before) != identity(after)
        ):
            raise RouteANativeBuildError("retained build member changed while reading")
        return bytes(content), stat.S_IMODE(before.st_mode)
    finally:
        os.close(descriptor)


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteANativeBuildError("retained build write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _zip_info(path: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.flag_bits = 0
    return info


def _normalized_relative(value: str) -> str:
    if type(value) is not str or not value:
        raise RouteANativeBuildError("retained build path is not closed")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or path.parts[0] not in _ARCHIVE_MEMBER_PREFIXES
    ):
        raise RouteANativeBuildError("retained build path is not closed")
    return value


def _git(
    command: tuple[str, ...],
    *,
    cwd: Path,
    timeout: int = 120,
) -> bytes:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env={
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RouteANativeBuildError("retained OpenFHE Git operation failed") from error
    if completed.returncode != 0 or completed.stderr:
        raise RouteANativeBuildError("retained OpenFHE Git operation was not clean")
    return completed.stdout


def _source_bundle(repository_root: Path) -> bytes:
    source = repository_root / "_openfhe/source"
    with tempfile.TemporaryDirectory(prefix="route-a-openfhe-bundle-") as directory:
        target = Path(directory) / "openfhe-source.bundle"
        _git(("git", "bundle", "create", str(target), "HEAD"), cwd=source)
        content, _mode = _stable_read(target)
        return content


def _repository_relative(repository_root: Path, value: str) -> str | None:
    try:
        path = Path(value).resolve(strict=True)
        relative = path.relative_to(repository_root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return _normalized_relative(PurePosixPath(relative).as_posix())


def _portable_identity(document: dict[str, object]) -> dict[str, object]:
    """Drop only host filesystem instance numbers from one exact identity."""

    result = json.loads(json.dumps(document))
    if type(result) is not dict:
        raise RouteANativeBuildError("runner identity is not an object")
    result.pop("build_identity_sha256", None)
    result.pop("runner_device", None)
    result.pop("runner_inode", None)
    libraries = result.get("linked_libraries")
    if type(libraries) is not list:
        raise RouteANativeBuildError("runner linked-library identity is not closed")
    for item in libraries:
        if type(item) is not dict:
            raise RouteANativeBuildError("runner linked-library row is not closed")
        item.pop("device", None)
        item.pop("inode", None)
    return result


@dataclass(frozen=True, slots=True)
class RouteANativeBuildInspection:
    archive_path: Path
    manifest_bytes: bytes
    manifest_sha256: str
    producer_identity_document: dict[str, object]
    producer_build_identity_sha256: str
    runner_relative_path: str


def _manifest(
    *,
    repository_root: Path,
    identity: OpenFHERunnerBuildIdentity,
    members: tuple[tuple[str, bytes, int], ...],
    aliases: tuple[tuple[str, str], ...],
) -> bytes:
    return canonical_route_a_document(
        {
            "authority_granted": False,
            "library_aliases": [
                {"alias_path": alias, "target_path": target} for alias, target in aliases
            ],
            "members": [
                {
                    "byte_count": len(content),
                    "mode": mode,
                    "path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content, mode in members
            ],
            "producer_repository_root": str(repository_root),
            "publication_evidence": False,
            "runner_build_identity": identity.to_document(),
            "runner_relative_path": identity.runner_relative_path,
            "schema_version": _SCHEMA,
        }
    )


def produce_route_a_native_build(
    repository_root: Path,
    *,
    runner_relative_path: str,
    output_path: Path,
) -> RouteANativeBuildInspection:
    """Create one deterministic compact build archive after a pinned q3 build."""

    if not repository_root.is_absolute() or not output_path.is_absolute():
        raise TypeError("retained build paths must be absolute")
    if output_path.exists() or output_path.is_symlink():
        raise RouteANativeBuildError("refusing to replace a retained build archive")
    identity = capture_openfhe_runner_build_identity(repository_root, runner_relative_path)
    openfhe_config = _repository_relative(
        repository_root,
        str(Path(identity.build_provenance.openfhe_directory) / "OpenFHEConfig.cmake"),
    )
    if openfhe_config is None:
        raise RouteANativeBuildError("OpenFHE package configuration is outside the repository")
    paths = [runner_relative_path, *_FIXED_METADATA_PATHS, openfhe_config]
    aliases: set[tuple[str, str]] = set()
    for library in identity.linked_libraries:
        relative = _repository_relative(repository_root, library.resolved_path)
        if relative is None:
            continue
        paths.append(relative)
        alias = PurePosixPath(relative).parent / library.load_name
        alias_text = _normalized_relative(alias.as_posix())
        if alias_text != relative:
            aliases.add((alias_text, relative))
    members: list[tuple[str, bytes, int]] = []
    for path in sorted(set(paths)):
        content, mode = _stable_read(repository_root.joinpath(*PurePosixPath(path).parts))
        members.append((path, content, mode))
    members.append((_SOURCE_BUNDLE, _source_bundle(repository_root), 0o400))
    members.sort(key=lambda item: item[0])
    alias_rows = tuple(sorted(aliases))
    manifest_bytes = _manifest(
        repository_root=repository_root,
        identity=identity,
        members=tuple(members),
        aliases=alias_rows,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("xb") as stream:
            with zipfile.ZipFile(
                stream,
                "w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as archive:
                for path, content, mode in members:
                    archive.writestr(_zip_info(path, mode), content)
                archive.writestr(_zip_info("manifest.json", 0o400), manifest_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise
    if output_path.stat().st_size > _MAX_ARCHIVE_BYTES:
        output_path.unlink(missing_ok=True)
        raise RouteANativeBuildError("retained build archive exceeds its byte bound")
    return inspect_route_a_native_build(output_path)


def _read_archive(archive_path: Path) -> tuple[dict[str, bytes], dict[str, int]]:
    if not archive_path.is_absolute():
        raise TypeError("archive_path must be absolute")
    status = archive_path.lstat()
    if (
        archive_path.is_symlink()
        or not stat.S_ISREG(status.st_mode)
        or status.st_size > _MAX_ARCHIVE_BYTES
    ):
        raise RouteANativeBuildError("retained build archive is not a bounded regular file")
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            if archive.comment or len({item.filename for item in infos}) != len(infos):
                raise RouteANativeBuildError("retained build archive identity is not unique")
            contents: dict[str, bytes] = {}
            modes: dict[str, int] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or info.compress_type != zipfile.ZIP_STORED
                    or not stat.S_ISREG(mode)
                    or info.file_size <= 0
                    or info.file_size > _MAX_MEMBER_BYTES
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or (
                        info.filename != "manifest.json"
                        and _normalized_relative(info.filename) != info.filename
                    )
                ):
                    raise RouteANativeBuildError("retained build archive member is unsafe")
                contents[info.filename] = archive.read(info)
                modes[info.filename] = stat.S_IMODE(mode)
            return contents, modes
    except RouteANativeBuildError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise RouteANativeBuildError("retained build archive is unreadable") from error


def _validate_manifest(
    archive_path: Path,
    contents: dict[str, bytes],
    modes: dict[str, int],
) -> RouteANativeBuildInspection:
    manifest_bytes = contents.get("manifest.json")
    if manifest_bytes is None:
        raise RouteANativeBuildError("retained build manifest is absent")
    manifest = _canonical_object(manifest_bytes, field="retained build manifest")
    if set(manifest) != {
        "authority_granted",
        "library_aliases",
        "members",
        "producer_repository_root",
        "publication_evidence",
        "runner_build_identity",
        "runner_relative_path",
        "schema_version",
    }:
        raise RouteANativeBuildError("retained build manifest shape changed")
    inventory = manifest.get("members")
    aliases = manifest.get("library_aliases")
    identity = manifest.get("runner_build_identity")
    if (
        manifest.get("schema_version") != _SCHEMA
        or manifest.get("authority_granted") is not False
        or manifest.get("publication_evidence") is not False
        or type(manifest.get("producer_repository_root")) is not str
        or type(manifest.get("runner_relative_path")) is not str
        or type(inventory) is not list
        or not inventory
        or type(aliases) is not list
        or type(identity) is not dict
    ):
        raise RouteANativeBuildError("retained build manifest identity changed")
    producer_root_value = manifest.get("producer_repository_root")
    if type(producer_root_value) is not str:
        raise RouteANativeBuildError("retained build producer root changed")
    producer_root = Path(producer_root_value)
    if not producer_root.is_absolute() or str(producer_root) != producer_root_value:
        raise RouteANativeBuildError("retained build producer root is not canonical")
    expected_names = {"manifest.json"}
    inventory_by_path: dict[str, dict[str, object]] = {}
    previous = ""
    for row in inventory:
        if type(row) is not dict or set(row) != {"byte_count", "mode", "path", "sha256"}:
            raise RouteANativeBuildError("retained build inventory row changed")
        path = _normalized_relative(row.get("path"))  # type: ignore[arg-type]
        if (
            path <= previous
            or type(row.get("byte_count")) is not int
            or type(row.get("mode")) is not int
        ):
            raise RouteANativeBuildError("retained build inventory order/type changed")
        previous = path
        digest = _sha256(row.get("sha256"), field="retained member")
        content = contents.get(path)
        if (
            content is None
            or len(content) != row["byte_count"]
            or hashlib.sha256(content).hexdigest() != digest
            or modes.get(path) != row["mode"]
        ):
            raise RouteANativeBuildError("retained build inventory bytes changed")
        expected_names.add(path)
        inventory_by_path[path] = row
    if set(contents) != expected_names or _SOURCE_BUNDLE not in contents:
        raise RouteANativeBuildError("retained build archive has missing or extra members")
    alias_paths: set[str] = set()
    for row in aliases:
        if type(row) is not dict or set(row) != {"alias_path", "target_path"}:
            raise RouteANativeBuildError("retained build alias row changed")
        alias = _normalized_relative(row.get("alias_path"))  # type: ignore[arg-type]
        target = _normalized_relative(row.get("target_path"))  # type: ignore[arg-type]
        if alias in expected_names or alias in alias_paths or target not in expected_names:
            raise RouteANativeBuildError("retained build alias identity is invalid")
        if PurePosixPath(alias).parent != PurePosixPath(target).parent:
            raise RouteANativeBuildError("retained build alias crosses a directory")
        alias_paths.add(alias)
    identity_build_sha = _sha256(
        identity.get("build_identity_sha256"),
        field="producer build identity",
    )
    runner_relative_path = manifest.get("runner_relative_path")
    runner_row = inventory_by_path.get(str(runner_relative_path))
    if (
        type(runner_relative_path) is not str
        or _normalized_relative(runner_relative_path) != runner_relative_path
        or identity.get("runner_relative_path") != runner_relative_path
        or type(runner_row) is not dict
        or runner_row.get("sha256") != identity.get("runner_sha256")
        or runner_row.get("byte_count") != identity.get("runner_byte_count")
        or runner_row.get("mode") != identity.get("runner_mode")
    ):
        raise RouteANativeBuildError("retained runner identity path changed")
    linked_libraries = identity.get("linked_libraries")
    if type(linked_libraries) is not list or not linked_libraries:
        raise RouteANativeBuildError("retained linked-library identity is absent")
    for library in linked_libraries:
        if type(library) is not dict:
            raise RouteANativeBuildError("retained linked-library identity changed")
        resolved_path = library.get("resolved_path")
        if type(resolved_path) is not str:
            raise RouteANativeBuildError("retained linked-library path changed")
        try:
            relative = Path(resolved_path).relative_to(producer_root).as_posix()
        except ValueError:
            continue
        relative = _normalized_relative(relative)
        row = inventory_by_path.get(relative)
        if (
            type(row) is not dict
            or row.get("sha256") != library.get("sha256")
            or row.get("byte_count") != library.get("byte_count")
            or row.get("mode") != library.get("mode")
        ):
            raise RouteANativeBuildError(
                "retained linked-library bytes differ from the runner identity"
            )
    return RouteANativeBuildInspection(
        archive_path=archive_path,
        manifest_bytes=manifest_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        producer_identity_document=identity,
        producer_build_identity_sha256=identity_build_sha,
        runner_relative_path=manifest["runner_relative_path"],  # type: ignore[arg-type]
    )


def inspect_route_a_native_build(archive_path: Path) -> RouteANativeBuildInspection:
    contents, modes = _read_archive(archive_path)
    return _validate_manifest(archive_path, contents, modes)


def _restore_openfhe_source(
    repository_root: Path,
    bundle_path: Path,
    identity: dict[str, object],
) -> None:
    provenance = identity.get("build_provenance")
    if type(provenance) is not dict:
        raise RouteANativeBuildError("retained build provenance is absent")
    commit = provenance.get("openfhe_source_commit")
    repository = provenance.get("openfhe_repository")
    try:
        parameter_document = json.loads(
            _stable_read(
                repository_root / "config/params_manifest.json",
                maximum=16 * 1024 * 1024,
            )[0]
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise RouteANativeBuildError("repository OpenFHE pin is unreadable") from error
    parameter_openfhe = (
        parameter_document.get("openfhe") if type(parameter_document) is dict else None
    )
    if (
        type(commit) is not str
        or _LOWER_GIT_SHA.fullmatch(commit) is None
        or type(repository) is not str
        or not repository
        or type(parameter_openfhe) is not dict
        or parameter_openfhe.get("commit") != commit
        or parameter_openfhe.get("repository") != repository
    ):
        raise RouteANativeBuildError("retained OpenFHE source identity changed")
    source = repository_root / "_openfhe/source"
    if source.exists() or source.is_symlink():
        raise RouteANativeBuildError("retained OpenFHE source target is not empty")
    _git(
        ("git", "clone", "--quiet", "--no-checkout", str(bundle_path), str(source)),
        cwd=repository_root,
    )
    _git(("git", "-C", str(source), "remote", "set-url", "origin", repository), cwd=repository_root)
    _git(
        ("git", "-C", str(source), "checkout", "--quiet", "--detach", commit),
        cwd=repository_root,
    )


def install_route_a_native_build(
    archive_path: Path,
    *,
    repository_root: Path,
) -> tuple[RouteANativeBuildInspection, OpenFHERunnerBuildIdentity]:
    """Install and independently re-capture one q3 build without rebuilding."""

    if not repository_root.is_absolute():
        raise TypeError("repository_root must be absolute")
    contents, modes = _read_archive(archive_path)
    inspection = _validate_manifest(archive_path, contents, modes)
    manifest = _canonical_object(inspection.manifest_bytes, field="retained build manifest")
    if manifest["producer_repository_root"] != str(repository_root):
        raise RouteANativeBuildError("provider workspace path changed between q3 and q4")
    for top_level in ("build", "_openfhe", "retained-build"):
        candidate = repository_root / top_level
        if candidate.exists() or candidate.is_symlink():
            raise RouteANativeBuildError("retained build installation target is not empty")
    inventory = manifest["members"]
    assert type(inventory) is list
    for row in inventory:
        assert type(row) is dict
        path = row["path"]
        assert type(path) is str
        target = repository_root.joinpath(*PurePosixPath(path).parts)
        _write_new(target, contents[path], modes[path])
    aliases = manifest["library_aliases"]
    assert type(aliases) is list
    for row in aliases:
        assert type(row) is dict
        alias = row["alias_path"]
        target = row["target_path"]
        assert type(alias) is str and type(target) is str
        alias_path = repository_root.joinpath(*PurePosixPath(alias).parts)
        target_path = repository_root.joinpath(*PurePosixPath(target).parts)
        alias_path.symlink_to(target_path.name)
    _restore_openfhe_source(
        repository_root,
        repository_root.joinpath(*PurePosixPath(_SOURCE_BUNDLE).parts),
        inspection.producer_identity_document,
    )
    current = capture_openfhe_runner_build_identity(
        repository_root,
        inspection.runner_relative_path,
    )
    if _portable_identity(current.to_document()) != _portable_identity(
        inspection.producer_identity_document
    ):
        raise RouteANativeBuildError("retained runner differs after q4 installation")
    return inspection, current
