"""Fail-closed isolated launcher for the frozen publication analyzer.

The public seam accepts only the held-out input artifact and an all-new output
directory.  Every authority-bearing identity is derived from the current clean
repository and then re-established in a fresh detached checkout.  This module
does not upgrade the central evidence receipt: until that integration consumes
this receipt, ``formal_authority_granted`` remains false.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import NoReturn

from dynamic_cssc.evidence_compatibility import EvidenceRole, repository_behavior_paths

RUNTIME_RECEIPT_SCHEMA = "dynamic-cssc-runtime-execution-isolation-receipt-v1"
RUNTIME_POLICY_SCHEMA = "dynamic-cssc-publication-runtime-policy-v1"
RUNTIME_SOURCE_ATTESTATION_SCHEMA = "dynamic-cssc-runtime-source-attestation-v1"
RUNTIME_WORKER_SCHEMA = "dynamic-cssc-publication-runtime-worker-v1"
RUNTIME_AUTHORITY_HOLD = "HOLD-until-central-evidence-compatibility-consumes-runtime-receipt-v1"
RUNTIME_RECEIPT_FILENAME = "runtime-execution-isolation-receipt.json"
RUNTIME_RECEIPT_SHA_FILENAME = "runtime-execution-isolation-receipt.sha256"

_POLICY_PATH = "config/publication-runtime-policy.json"
_ANALYSIS_ENTRYPOINT = "scripts/analyze_publication_results.py"
_ANALYSIS_OUTPUT_FILES = (
    "SHA256SUMS",
    "publication-effects.csv",
    "publication-summary.csv",
    "publication-verdict.json",
)
_DEPENDENCY_LOCK_PATHS = ("requirements-ci.txt", "requirements-publication.txt")
_INTERPRETER_OPTIONS = ("-I", "-S", "-X", "pycache_prefix={isolated_pycache}")
_REQUIRED_BEHAVIOR_PATHS = repository_behavior_paths(EvidenceRole.ANALYZER)
_POLICY_KEYS = frozenset(
    {
        "analysis_entrypoint",
        "analysis_output_files",
        "approved_third_party_distributions",
        "behavior_paths",
        "dependency_lock_paths",
        "interpreter_options",
        "python_implementation",
        "python_version",
        "schema_version",
        "worker_protocol",
    }
)
_LOWER_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOCK_REQUIREMENT = re.compile(r"[A-Za-z0-9_.-]+==[^\s\\]+(?:\s*;[^\\]+)?\s*\\?\Z")
_LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?\Z")
_GIT_EXECUTABLE = Path("/usr/bin/git")
_EXPECTED_PYTHON_IMPLEMENTATION = "CPython"
_EXPECTED_PYTHON_VERSION = "3.12.13"
_RECEIPT_KEYS = frozenset(
    {
        "analysis_cli_receipt",
        "analysis_output_files",
        "authority_state",
        "caller_environment_names_removed",
        "dependency_locks",
        "exact_invocation",
        "formal_authority_granted",
        "fresh_checkout",
        "git_executable",
        "import_manifest",
        "input_artifact",
        "interpreter",
        "output_install",
        "policy",
        "runtime_execution_isolation_verified",
        "schema_version",
        "source_attestation_after_analysis",
        "source_attestation_after_render_and_atomic_install_expected",
        "source_attestation_before_decode",
        "third_party_wheel_set",
    }
)


class PublicationRuntimeError(ValueError):
    """A runtime-isolation invariant failed closed."""


class PublicationRuntimeHold(PublicationRuntimeError):
    """The current environment cannot satisfy the frozen runtime contract."""


@dataclass(frozen=True, slots=True)
class _ReceiptBinding:
    document: bytes
    installed_output_directory: Path
    repository_root: Path
    interpreter: Path


class PublicationRuntimeReceipt:
    """Read-only descriptive receipt minted only after post-install verification."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> PublicationRuntimeReceipt:
        raise TypeError("PublicationRuntimeReceipt can only be minted by the isolated launcher")

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("PublicationRuntimeReceipt is read-only")

    def __bool__(self) -> NoReturn:
        raise TypeError("runtime receipts are not caller-supplied booleans")

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(self._binding.document).hexdigest()

    @property
    def output_directory(self) -> Path:
        return self._binding.installed_output_directory

    @property
    def formal_authority_granted(self) -> bool:
        return False

    def to_document(self) -> dict[str, object]:
        document = json.loads(self._binding.document)
        if type(document) is not dict:  # pragma: no cover - construction invariant
            raise AssertionError("minted runtime receipt is not an object")
        return document


_LIVE_RECEIPT_LOCK = threading.Lock()
_LIVE_RUNNER_RECEIPTS: weakref.WeakKeyDictionary[PublicationRuntimeReceipt, _ReceiptBinding] = (
    weakref.WeakKeyDictionary()
)


@dataclass(frozen=True, slots=True)
class _VerifiedRuntimeRun:
    repository_root: Path
    output_directory: Path
    source_git_sha: str
    source_attestation: MappingProxyType[str, object]
    analysis_output_files: tuple[MappingProxyType[str, object], ...]
    receipt_sha256: str
    installed_artifact_set_sha256: str


@dataclass(frozen=True, slots=True)
class _RuntimeContext:
    repository_root: Path
    interpreter: Path
    after_checkout_hook: object | None = None
    after_worker_hook: object | None = None
    before_install_hook: object | None = None


@dataclass(frozen=True, slots=True)
class _Policy:
    document: MappingProxyType[str, object]
    canonical_bytes: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def _absolute_path(value: object, label: str) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or ".." in value.parts
        or Path(os.path.normpath(value)) != value
    ):
        raise PublicationRuntimeError(f"{label} must be an absolute pathlib.Path")
    return value


def _reject_symlink_components(path: Path, *, missing_leaf_allowed: bool) -> None:
    current = Path(path.anchor)
    for index, component in enumerate(path.parts[1:], start=1):
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if missing_leaf_allowed and index == len(path.parts) - 1:
                return
            raise PublicationRuntimeError(f"path component does not exist: {current}") from None
        except OSError as error:
            raise PublicationRuntimeError(f"cannot inspect path component: {current}") from error
        if stat.S_ISLNK(mode):
            raise PublicationRuntimeError(f"symlink path components are forbidden: {current}")


def _secure_read(path: Path, label: str) -> bytes:
    _reject_symlink_components(path, missing_leaf_allowed=False)
    if not hasattr(os, "O_NOFOLLOW"):
        raise PublicationRuntimeHold("O_NOFOLLOW is required for publication artifacts")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise PublicationRuntimeError(f"cannot securely open {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PublicationRuntimeError(f"{label} must be a no-follow regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise PublicationRuntimeError(f"{label} changed while it was being read")
    if len(content) != after.st_size:
        raise PublicationRuntimeError(f"{label} size changed while it was being read")
    return content


def _secure_write_new(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise PublicationRuntimeError(f"cannot create all-new file: {path.name}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_document(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    content = _secure_read(path, label)
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationRuntimeError(f"{label} must be canonical JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise PublicationRuntimeError(f"{label} must be one canonical JSON object")
    return document, content


def _exact_string_list(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise PublicationRuntimeError(f"{label} must be a JSON string array")
    items = tuple(value)
    if items != tuple(sorted(items)) or len(set(items)) != len(items):
        raise PublicationRuntimeError(f"{label} must be unique and canonically ordered")
    return items


def _load_policy(repository_root: Path) -> _Policy:
    document, content = _canonical_document(
        repository_root / _POLICY_PATH,
        "publication runtime policy",
    )
    if set(document) != _POLICY_KEYS:
        raise PublicationRuntimeError("publication runtime policy fields are not exact")
    expected_scalars = {
        "analysis_entrypoint": _ANALYSIS_ENTRYPOINT,
        "python_implementation": _EXPECTED_PYTHON_IMPLEMENTATION,
        "python_version": _EXPECTED_PYTHON_VERSION,
        "schema_version": RUNTIME_POLICY_SCHEMA,
        "worker_protocol": RUNTIME_WORKER_SCHEMA,
    }
    for field, expected in expected_scalars.items():
        if document[field] != expected or type(document[field]) is not str:
            raise PublicationRuntimeError(f"publication runtime policy {field} is not frozen")
    exact_arrays = {
        "analysis_output_files": _ANALYSIS_OUTPUT_FILES,
        "approved_third_party_distributions": (),
        "behavior_paths": _REQUIRED_BEHAVIOR_PATHS,
        "dependency_lock_paths": _DEPENDENCY_LOCK_PATHS,
    }
    for field, expected in exact_arrays.items():
        if _exact_string_list(document[field], field) != expected:
            raise PublicationRuntimeError(f"publication runtime policy {field} is not exact")
    options = document["interpreter_options"]
    if type(options) is not list or tuple(options) != _INTERPRETER_OPTIONS:
        raise PublicationRuntimeError("publication runtime interpreter invocation is not exact")
    for relative_path in _REQUIRED_BEHAVIOR_PATHS:
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != relative_path:
            raise PublicationRuntimeError("runtime Behavior Set contains an unsafe path")
    return _Policy(MappingProxyType(document.copy()), content)


def _clean_environment(private_root: Path) -> dict[str, str]:
    home = private_root / "home"
    temporary = private_root / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(temporary),
        "TZ": "UTC",
        "XDG_CONFIG_HOME": str(home / ".config"),
        # macOS injects this key when it is absent; pinning it keeps the child
        # environment closed and makes the value part of the invocation receipt.
        "__CF_USER_TEXT_ENCODING": "0x0:0x0:0x0",
    }


def _run(
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    cwd: Path | None = None,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise PublicationRuntimeHold(f"cannot execute isolated command: {arguments[0]}") from error
    if completed.returncode not in allowed_returncodes:
        detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
        raise PublicationRuntimeError(
            f"isolated command failed ({completed.returncode}): {detail or arguments[0]}"
        )
    return completed


def _git(
    repository_root: Path,
    environment: dict[str, str],
    *arguments: str,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    if not _GIT_EXECUTABLE.is_file():
        raise PublicationRuntimeHold("the frozen /usr/bin/git executable is unavailable")
    return _run(
        (
            str(_GIT_EXECUTABLE),
            "--no-replace-objects",
            "-C",
            str(repository_root),
            *arguments,
        ),
        environment=environment,
        allowed_returncodes=allowed_returncodes,
    )


def _git_stdout(repository_root: Path, environment: dict[str, str], *arguments: str) -> bytes:
    return _git(repository_root, environment, *arguments).stdout


def _git_blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(content)}\0".encode("ascii"))
    digest.update(content)
    return digest.hexdigest()


def _repository_head(
    repository_root: Path,
    environment: dict[str, str],
    *,
    require_detached: bool,
) -> str:
    _reject_symlink_components(repository_root, missing_leaf_allowed=False)
    if not repository_root.is_dir():
        raise PublicationRuntimeError("repository root must be a directory")
    top = Path(
        _git_stdout(repository_root, environment, "rev-parse", "--show-toplevel")
        .decode("utf-8")
        .strip()
    )
    if top != repository_root:
        raise PublicationRuntimeError("runtime repository must be the exact Git top level")
    if (
        _git_stdout(repository_root, environment, "rev-parse", "--show-object-format")
        .decode("ascii")
        .strip()
        != "sha1"
    ):
        raise PublicationRuntimeError("runtime source requires exact SHA-1 Git objects")
    if (
        _git_stdout(repository_root, environment, "rev-parse", "--is-shallow-repository")
        .decode("ascii")
        .strip()
        != "false"
    ):
        raise PublicationRuntimeError("runtime source may not be a shallow repository")
    if _git_stdout(
        repository_root,
        environment,
        "for-each-ref",
        "--format=%(refname)",
        "refs/replace/",
    ):
        raise PublicationRuntimeError("Git replacement refs are forbidden")
    head = (
        _git_stdout(repository_root, environment, "rev-parse", "--verify", "HEAD^{commit}")
        .decode("ascii")
        .strip()
    )
    if _LOWER_SHA1.fullmatch(head) is None:
        raise PublicationRuntimeError("runtime source HEAD is not one exact commit")
    if _git_stdout(
        repository_root,
        environment,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ):
        raise PublicationRuntimeError("runtime source must be fully clean")
    for entry in _git_stdout(repository_root, environment, "ls-files", "-v", "-z").split(b"\0"):
        if entry and not entry.startswith(b"H "):
            raise PublicationRuntimeError(
                "runtime source forbids skip-worktree and assume-unchanged files"
            )
    symbolic = _git(
        repository_root,
        environment,
        "symbolic-ref",
        "-q",
        "HEAD",
        allowed_returncodes=(0, 1),
    )
    if require_detached and symbolic.returncode == 0:
        raise PublicationRuntimeError("publication execution checkout must be detached")
    return head


def _tree_entry(
    repository_root: Path,
    environment: dict[str, str],
    head: str,
    relative_path: str,
) -> tuple[str, str]:
    raw = _git_stdout(
        repository_root,
        environment,
        "ls-tree",
        "-z",
        "--full-tree",
        head,
        "--",
        relative_path,
    )
    entries = [entry for entry in raw.split(b"\0") if entry]
    if len(entries) != 1:
        raise PublicationRuntimeError(f"runtime Behavior Set path is absent: {relative_path}")
    try:
        metadata, encoded_path = entries[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        observed_path = encoded_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise PublicationRuntimeError("runtime Behavior Set Git entry is malformed") from error
    if observed_path != relative_path or object_type != "blob" or mode not in {"100644", "100755"}:
        raise PublicationRuntimeError(
            f"runtime Behavior Set path is not a regular blob: {relative_path}"
        )
    if _LOWER_SHA1.fullmatch(object_id) is None:
        raise PublicationRuntimeError("runtime Behavior Set object ID is malformed")
    return mode, object_id


def _attest_repository(
    repository_root: Path,
    environment: dict[str, str],
    policy: _Policy,
    *,
    require_detached: bool,
) -> dict[str, object]:
    head = _repository_head(repository_root, environment, require_detached=require_detached)
    entries: list[dict[str, str]] = []
    for relative_path in _REQUIRED_BEHAVIOR_PATHS:
        git_mode, object_id = _tree_entry(
            repository_root,
            environment,
            head,
            relative_path,
        )
        content = _secure_read(repository_root / relative_path, relative_path)
        if _git_blob_oid(content) != object_id:
            raise PublicationRuntimeError(
                f"runtime Behavior Set bytes differ from Git: {relative_path}"
            )
        observed_mode = (repository_root / relative_path).lstat().st_mode
        executable = bool(observed_mode & 0o111)
        if executable != (git_mode == "100755"):
            raise PublicationRuntimeError(
                f"runtime Behavior Set mode differs from Git: {relative_path}"
            )
        entries.append(
            {
                "git_mode": git_mode,
                "object_id": object_id,
                "path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    if entries != sorted(entries, key=lambda entry: entry["path"]):
        raise PublicationRuntimeError("runtime Behavior Set is not canonically ordered")
    behavior_document = {
        "entries": entries,
        "policy_sha256": policy.sha256,
        "schema_version": "dynamic-cssc-publication-runtime-behavior-set-v1",
    }
    second_head = _repository_head(
        repository_root,
        environment,
        require_detached=require_detached,
    )
    if second_head != head:
        raise PublicationRuntimeError("runtime source changed during attestation")
    return {
        "behavior_set_sha256": hashlib.sha256(_canonical_json_bytes(behavior_document)).hexdigest(),
        "entries": entries,
        "git_sha": head,
        "repository_state": "clean-detached-head" if require_detached else "clean-head",
        "schema_version": RUNTIME_SOURCE_ATTESTATION_SCHEMA,
    }


def _prepare_fresh_checkout(
    source_root: Path,
    source_sha: str,
    checkout: Path,
    environment: dict[str, str],
) -> None:
    checkout.mkdir(mode=0o700)
    _run(
        (str(_GIT_EXECUTABLE), "init", "--quiet", "--object-format=sha1", str(checkout)),
        environment=environment,
    )
    _git(checkout, environment, "config", "--local", "core.hooksPath", "/dev/null")
    _git(checkout, environment, "config", "--local", "core.autocrlf", "false")
    _git(checkout, environment, "config", "--local", "core.safecrlf", "true")
    _git(checkout, environment, "remote", "add", "origin", str(source_root))
    _git(checkout, environment, "fetch", "--quiet", "--no-tags", "origin", source_sha)
    _git(
        checkout,
        environment,
        "checkout",
        "--quiet",
        "--detach",
        "--no-recurse-submodules",
        source_sha,
    )
    _git(checkout, environment, "remote", "remove", "origin")


def _validate_lock(content: bytes, relative_path: str) -> None:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PublicationRuntimeError(f"dependency lock is not UTF-8: {relative_path}") from error
    blocks: list[list[str]] = []
    active: list[str] = []
    only_binary_seen = False
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "--only-binary=:all:" and not active and not only_binary_seen:
            only_binary_seen = True
            continue
        if raw_line[:1].isspace():
            if not active:
                raise PublicationRuntimeError(
                    f"dependency lock continuation is orphaned: {relative_path}"
                )
            active.append(stripped)
            continue
        if active:
            blocks.append(active)
        active = [stripped]
    if active:
        blocks.append(active)
    if not blocks:
        raise PublicationRuntimeError(f"dependency lock is empty: {relative_path}")
    for block in blocks:
        if _LOCK_REQUIREMENT.fullmatch(block[0]) is None:
            raise PublicationRuntimeError(
                f"dependency lock requirement is not exact: {relative_path}"
            )
        hashes = [match.group(1) for line in block[1:] if (match := _LOCK_HASH.fullmatch(line))]
        if not hashes or len(set(hashes)) != len(hashes):
            raise PublicationRuntimeError(
                f"dependency lock hashes are absent or duplicated: {relative_path}"
            )
        if len(hashes) != len(block) - 1:
            raise PublicationRuntimeError(
                f"dependency lock has an unapproved option: {relative_path}"
            )


def _dependency_lock_receipts(checkout: Path) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    for relative_path in _DEPENDENCY_LOCK_PATHS:
        content = _secure_read(checkout / relative_path, relative_path)
        _validate_lock(content, relative_path)
        receipts.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "usage": "identity-only-empty-runtime-wheel-set",
            }
        )
    return receipts


_PROBE = """\
import json, os, platform, sys, sysconfig
print(json.dumps({
    "base_prefix": sys.base_prefix,
    "environment_names": sorted(os.environ),
    "executable": sys.executable,
    "flags": {
        "ignore_environment": sys.flags.ignore_environment,
        "isolated": sys.flags.isolated,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
        "safe_path": sys.flags.safe_path,
    },
    "implementation": platform.python_implementation(),
    "prefix": sys.prefix,
    "stdlib": sysconfig.get_path("stdlib"),
    "sys_path": sys.path,
    "version": platform.python_version(),
}, sort_keys=True, separators=(",", ":")))
"""


def _binary_identity(path: Path, label: str) -> dict[str, object]:
    resolved = Path(os.path.realpath(path))
    content = _secure_read(resolved, label)
    if not os.access(resolved, os.X_OK):
        raise PublicationRuntimeHold(f"{label} is not executable")
    return {
        "path": str(path),
        "realpath": str(resolved),
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def _probe_interpreter(
    interpreter: Path,
    pycache: Path,
    environment: dict[str, str],
) -> tuple[dict[str, object], tuple[Path, ...]]:
    identity = _binary_identity(interpreter, "CPython interpreter")
    completed = _run(
        (
            str(interpreter),
            "-I",
            "-S",
            "-X",
            f"pycache_prefix={pycache}",
            "-c",
            _PROBE,
        ),
        environment=environment,
    )
    if completed.stderr:
        raise PublicationRuntimeError("isolated interpreter probe emitted stderr")
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationRuntimeError("isolated interpreter probe was not exact JSON") from error
    expected_keys = {
        "base_prefix",
        "environment_names",
        "executable",
        "flags",
        "implementation",
        "prefix",
        "stdlib",
        "sys_path",
        "version",
    }
    if type(report) is not dict or set(report) != expected_keys:
        raise PublicationRuntimeError("isolated interpreter probe fields are not exact")
    if report["implementation"] != _EXPECTED_PYTHON_IMPLEMENTATION:
        raise PublicationRuntimeHold("publication analysis requires exact CPython")
    if report["version"] != _EXPECTED_PYTHON_VERSION:
        raise PublicationRuntimeHold("publication analysis requires exact CPython 3.12.13")
    expected_flags = {
        "ignore_environment": 1,
        "isolated": 1,
        "no_site": 1,
        "no_user_site": 1,
        "safe_path": True,
    }
    if report["flags"] != expected_flags:
        raise PublicationRuntimeHold("CPython isolation flags are not exact")
    if Path(os.path.realpath(str(report["executable"]))) != Path(str(identity["realpath"])):
        raise PublicationRuntimeHold("interpreter wrapper does not identify the executed CPython")
    if type(report["sys_path"]) is not list or any(
        type(path) is not str for path in report["sys_path"]
    ):
        raise PublicationRuntimeError("isolated interpreter sys.path is malformed")
    if any("site-packages" in PurePosixPath(path).parts for path in report["sys_path"]):
        raise PublicationRuntimeHold("isolated interpreter admitted site-packages")
    stdlib = Path(str(report["stdlib"]))
    roots: list[Path] = []
    for raw_path in report["sys_path"]:
        path = Path(raw_path)
        if path.is_dir() and (path == stdlib or stdlib in path.parents):
            roots.append(path)
    if stdlib not in roots:
        roots.append(stdlib)
    unique_roots = tuple(dict.fromkeys(roots))
    report["binary"] = identity
    return report, unique_roots


def _reject_injection_files(checkout: Path, stdlib_roots: tuple[Path, ...]) -> None:
    forbidden_names = {"sitecustomize.py", "usercustomize.py"}
    roots = (checkout / "src", *stdlib_roots)
    visited: set[Path] = set()
    for root in roots:
        if root in visited or not root.is_dir():
            continue
        visited.add(root)
        for directory, directory_names, file_names in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            directory_names[:] = [name for name in directory_names if name != "site-packages"]
            if any(name.endswith(".pth") or name in forbidden_names for name in file_names):
                raise PublicationRuntimeHold(
                    f"runtime import root contains a forbidden injection file: {directory_path}"
                )


_WORKER = r"""
import hashlib, json, os, runpy, stat, sys

source_root, script, input_path, input_sha256, output_dir, report_path, expected_env = sys.argv[1:]
initial_sys_path = list(sys.path)
sys.path.insert(0, source_root)
sys.argv = [
    script,
    "--input",
    input_path,
    "--input-sha256",
    input_sha256,
    "--output-dir",
    output_dir,
]
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit as error:
    code = error.code
    if code is None:
        code = 0
    if type(code) is not int or code != 0:
        raise
else:
    code = 0

modules = []
for name, module in sorted(tuple(sys.modules.items())):
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    if origin in {"built-in", "frozen"}:
        modules.append({"name": name, "origin": origin, "origin_kind": origin, "sha256": None})
        continue
    file_name = getattr(module, "__file__", None)
    if origin is None and file_name is None:
        search_locations = getattr(spec, "submodule_search_locations", None)
        if search_locations is None:
            kind = "no-origin"
            reported_origin = None
        else:
            kind = "namespace"
            reported_origin = sorted(os.path.abspath(path) for path in search_locations)
        modules.append(
            {
                "name": name,
                "origin": reported_origin,
                "origin_kind": kind,
                "sha256": None,
            }
        )
        continue
    path = os.path.abspath(file_name or origin)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("import origin is not regular")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise RuntimeError("import origin changed while hashing")
    modules.append(
        {
            "name": name,
            "origin": path,
            "origin_kind": "file",
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    )

report = {
    "environment_names": sorted(os.environ),
    "expected_environment_names": json.loads(expected_env),
    "flags": {
        "ignore_environment": sys.flags.ignore_environment,
        "isolated": sys.flags.isolated,
        "no_site": sys.flags.no_site,
        "no_user_site": sys.flags.no_user_site,
        "safe_path": sys.flags.safe_path,
    },
    "initial_sys_path": initial_sys_path,
    "modules": modules,
    "pycache_prefix": sys.pycache_prefix,
    "schema_version": "dynamic-cssc-publication-runtime-worker-v1",
    "sys_path": sys.path,
}
payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
descriptor = os.open(
    report_path,
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(descriptor)
finally:
    os.close(descriptor)
"""


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _relative_import_origin(
    origin: Path,
    checkout: Path,
    stdlib_roots: tuple[Path, ...],
) -> tuple[str, str]:
    if _is_within(origin, checkout):
        relative = origin.relative_to(checkout).as_posix()
        if relative not in _REQUIRED_BEHAVIOR_PATHS:
            raise PublicationRuntimeError(
                f"imported repository file is outside the Behavior Set: {relative}"
            )
        return "checkout", relative
    matching_roots = [root for root in stdlib_roots if _is_within(origin, root)]
    if not matching_roots:
        raise PublicationRuntimeError(
            f"import origin is outside checkout and approved stdlib: {origin}"
        )
    root = max(matching_roots, key=lambda value: len(value.parts))
    if "site-packages" in origin.parts:
        raise PublicationRuntimeError("third-party site-packages imports are forbidden")
    return "stdlib", origin.relative_to(root).as_posix()


def _validate_worker_report(
    report_path: Path,
    *,
    checkout: Path,
    source_root: Path,
    stdlib_roots: tuple[Path, ...],
    expected_environment: dict[str, str],
    expected_initial_sys_path: list[str],
    pycache: Path,
) -> list[dict[str, object]]:
    report, _ = _canonical_document(report_path, "runtime worker report")
    expected_keys = {
        "environment_names",
        "expected_environment_names",
        "flags",
        "initial_sys_path",
        "modules",
        "pycache_prefix",
        "schema_version",
        "sys_path",
    }
    if set(report) != expected_keys or report["schema_version"] != RUNTIME_WORKER_SCHEMA:
        raise PublicationRuntimeError("runtime worker report fields are not exact")
    expected_names = sorted(expected_environment)
    if report["expected_environment_names"] != expected_names:
        raise PublicationRuntimeError("runtime worker expected-environment binding changed")
    observed_names = report["environment_names"]
    if type(observed_names) is not list or any(type(name) is not str for name in observed_names):
        raise PublicationRuntimeError("runtime worker environment names are malformed")
    unexpected = set(observed_names) - set(expected_names)
    if unexpected:
        raise PublicationRuntimeError(
            f"runtime worker inherited unexpected environment: {sorted(unexpected)}"
        )
    if any(name.startswith("PYTHON") for name in observed_names):
        raise PublicationRuntimeError("runtime worker inherited a PYTHON* variable")
    if report["flags"] != {
        "ignore_environment": 1,
        "isolated": 1,
        "no_site": 1,
        "no_user_site": 1,
        "safe_path": True,
    }:
        raise PublicationRuntimeError("runtime worker isolation flags changed")
    if report["pycache_prefix"] != str(pycache):
        raise PublicationRuntimeError("runtime worker bytecode cache is not isolated")
    if report["initial_sys_path"] != expected_initial_sys_path:
        raise PublicationRuntimeError("runtime worker initial sys.path changed after probing")
    expected_initial = [str(path) for path in report["initial_sys_path"]]
    if report["sys_path"] != [str(source_root), *expected_initial]:
        raise PublicationRuntimeError(
            "runtime worker sys.path changed outside the closed bootstrap"
        )
    raw_modules = report["modules"]
    if type(raw_modules) is not list:
        raise PublicationRuntimeError("runtime import manifest is malformed")
    names: list[str] = []
    normalized: list[dict[str, object]] = []
    for raw_module in raw_modules:
        if type(raw_module) is not dict or set(raw_module) != {
            "name",
            "origin",
            "origin_kind",
            "sha256",
        }:
            raise PublicationRuntimeError("runtime import entry is malformed")
        name = raw_module["name"]
        kind = raw_module["origin_kind"]
        if type(name) is not str or type(kind) is not str:
            raise PublicationRuntimeError("runtime import identity is malformed")
        names.append(name)
        if name in {"site", "sitecustomize", "usercustomize"}:
            raise PublicationRuntimeError(f"forbidden runtime customization module loaded: {name}")
        if kind in {"built-in", "frozen"}:
            if raw_module["origin"] != kind or raw_module["sha256"] is not None:
                raise PublicationRuntimeError("built-in/frozen import identity is malformed")
            normalized.append({"name": name, "origin": kind, "origin_kind": kind, "sha256": None})
            continue
        if kind == "no-origin":
            if raw_module["origin"] is not None or raw_module["sha256"] is not None:
                raise PublicationRuntimeError("no-origin import identity is malformed")
            normalized.append({"name": name, "origin": None, "origin_kind": kind, "sha256": None})
            continue
        if kind == "namespace":
            raw_origins = raw_module["origin"]
            if (
                type(raw_origins) is not list
                or not raw_origins
                or any(type(origin) is not str for origin in raw_origins)
                or raw_origins != sorted(set(raw_origins))
                or raw_module["sha256"] is not None
            ):
                raise PublicationRuntimeError("namespace import identity is malformed")
            normalized_origins = []
            for raw_origin in raw_origins:
                origin = Path(raw_origin)
                if not origin.is_absolute() or not origin.is_dir():
                    raise PublicationRuntimeError("namespace import origin is malformed")
                root_kind, relative = _relative_import_origin(origin, checkout, stdlib_roots)
                normalized_origins.append({"path": relative, "root": root_kind})
            normalized.append(
                {
                    "name": name,
                    "origin": normalized_origins,
                    "origin_kind": kind,
                    "sha256": None,
                }
            )
            continue
        if kind != "file" or type(raw_module["origin"]) is not str:
            raise PublicationRuntimeError("file import identity is malformed")
        origin = Path(raw_module["origin"])
        if not origin.is_absolute():
            raise PublicationRuntimeError("runtime import origin must be absolute")
        content = _secure_read(origin, f"import origin {name}")
        digest = hashlib.sha256(content).hexdigest()
        if raw_module["sha256"] != digest:
            raise PublicationRuntimeError(f"runtime import bytes changed: {name}")
        root_kind, relative = _relative_import_origin(origin, checkout, stdlib_roots)
        normalized.append(
            {
                "name": name,
                "origin": {"path": relative, "root": root_kind},
                "origin_kind": "file",
                "sha256": digest,
            }
        )
    if names != sorted(names) or len(names) != len(set(names)):
        raise PublicationRuntimeError("runtime import manifest is not exact and ordered")
    return normalized


def _parse_analysis_cli_receipt(
    stdout: bytes,
    *,
    input_path: Path,
    input_sha256: str,
    output_directory: Path,
) -> dict[str, object]:
    try:
        document = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationRuntimeError("analysis entrypoint stdout is not canonical JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != stdout:
        raise PublicationRuntimeError("analysis entrypoint stdout is not one canonical receipt")
    if set(document) != {
        "artifact_sha256",
        "input_path",
        "input_sha256",
        "output_dir",
        "schema_version",
    }:
        raise PublicationRuntimeError("analysis CLI receipt fields are not exact")
    if document["schema_version"] != "dynamic-cssc-publication-analysis-cli-receipt-v1":
        raise PublicationRuntimeError("analysis CLI receipt schema changed")
    if document["input_path"] != str(input_path):
        raise PublicationRuntimeError("analysis CLI receipt input path changed")
    if document["input_sha256"] != input_sha256:
        raise PublicationRuntimeError("analysis CLI receipt input digest changed")
    if document["output_dir"] != str(output_directory):
        raise PublicationRuntimeError("analysis CLI receipt output path changed")
    artifact_digests = document["artifact_sha256"]
    if (
        type(artifact_digests) is not dict
        or set(artifact_digests) != set(_ANALYSIS_OUTPUT_FILES)
        or any(
            type(digest) is not str or _LOWER_SHA256.fullmatch(digest) is None
            for digest in artifact_digests.values()
        )
    ):
        raise PublicationRuntimeError("analysis CLI artifact digest map is malformed")
    observed_digests = {
        entry["path"]: entry["sha256"]
        for entry in _directory_file_receipts(output_directory, _ANALYSIS_OUTPUT_FILES)
    }
    if artifact_digests != observed_digests:
        raise PublicationRuntimeError("analysis CLI artifact digests differ from output bytes")
    return document


def _directory_file_receipts(
    directory: Path,
    expected_names: tuple[str, ...],
) -> list[dict[str, object]]:
    _reject_symlink_components(directory, missing_leaf_allowed=False)
    if not directory.is_dir():
        raise PublicationRuntimeError("analysis output is not a no-follow directory")
    observed = tuple(sorted(entry.name for entry in directory.iterdir()))
    if observed != tuple(sorted(expected_names)):
        raise PublicationRuntimeError("analysis output file set is not exact")
    receipts: list[dict[str, object]] = []
    for name in sorted(expected_names):
        content = _secure_read(directory / name, f"analysis output {name}")
        receipts.append(
            {"path": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return receipts


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_no_replace_method() -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        return "renamex_np-RENAME_EXCL"
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        return "renameat2-RENAME_NOREPLACE"
    raise PublicationRuntimeHold("atomic no-replace directory installation is unavailable")


def _atomic_install_directory(source: Path, destination: Path) -> str:
    if destination.exists() or destination.is_symlink():
        raise PublicationRuntimeError("output directory must be all-new")
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    libc = ctypes.CDLL(None, use_errno=True)
    method = _atomic_no_replace_method()
    if method == "renamex_np-RENAME_EXCL":
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(source_bytes, destination_bytes, 0x00000004)
    else:
        rename = libc.renameat2
        rename.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename.restype = ctypes.c_int
        result = rename(-100, source_bytes, -100, destination_bytes, 0x00000001)
    if result != 0:
        observed_errno = ctypes.get_errno()
        if observed_errno in {errno.EEXIST, errno.ENOTEMPTY}:
            raise PublicationRuntimeError("output installation lost an all-new race")
        raise PublicationRuntimeError(
            f"atomic output installation failed: {os.strerror(observed_errno)}"
        )
    _fsync_directory(destination.parent)
    return method


def _claim_runner_receipt(runtime_receipt: object) -> _ReceiptBinding:
    if type(runtime_receipt) is not PublicationRuntimeReceipt:
        raise PublicationRuntimeError(
            "runtime admission requires the exact isolated runner receipt"
        )
    with _LIVE_RECEIPT_LOCK:
        binding = _LIVE_RUNNER_RECEIPTS.pop(runtime_receipt, None)
    if binding is None or getattr(runtime_receipt, "_binding", None) is not binding:
        raise PublicationRuntimeError(
            "runtime receipt was not minted by the isolated runner or was already consumed"
        )
    return binding


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PublicationRuntimeError(f"{label} fields are not exact")
    return value


def _exact_lower_sha256(value: object, label: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise PublicationRuntimeError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _existing_stdlib_file(
    relative_path: str,
    stdlib_roots: tuple[Path, ...],
    expected_sha256: str,
) -> None:
    matches: list[Path] = []
    for root in stdlib_roots:
        candidate = root / relative_path
        if not candidate.exists() or not candidate.is_file():
            continue
        try:
            content = _secure_read(candidate, f"installed stdlib import {relative_path}")
        except PublicationRuntimeError:
            continue
        if hashlib.sha256(content).hexdigest() == expected_sha256:
            matches.append(candidate)
    if not matches:
        raise PublicationRuntimeError(f"installed stdlib import identity changed: {relative_path}")


def _verify_installed_import_manifest(
    raw_manifest: object,
    *,
    repository_root: Path,
    source_attestation: dict[str, object],
    stdlib_roots: tuple[Path, ...],
) -> None:
    manifest = _exact_object(
        raw_manifest,
        {"entries", "sha256"},
        "installed runtime import manifest",
    )
    entries = manifest["entries"]
    if type(entries) is not list:
        raise PublicationRuntimeError("installed runtime import entries are not exact")
    if manifest["sha256"] != hashlib.sha256(_canonical_json_bytes(entries)).hexdigest():
        raise PublicationRuntimeError("installed runtime import manifest digest changed")
    source_entries = source_attestation["entries"]
    if type(source_entries) is not list:  # pragma: no cover - attestation invariant
        raise AssertionError("runtime source attestation entries are malformed")
    source_by_path = {entry["path"]: entry for entry in source_entries}
    names: list[str] = []
    for raw_entry in entries:
        entry = _exact_object(
            raw_entry,
            {"name", "origin", "origin_kind", "sha256"},
            "installed runtime import entry",
        )
        name = entry["name"]
        kind = entry["origin_kind"]
        if type(name) is not str or type(kind) is not str:
            raise PublicationRuntimeError("installed runtime import identity is malformed")
        names.append(name)
        if name in {"site", "sitecustomize", "usercustomize"}:
            raise PublicationRuntimeError("installed runtime imported a customization module")
        if kind in {"built-in", "frozen"}:
            if entry["origin"] != kind or entry["sha256"] is not None:
                raise PublicationRuntimeError("installed built-in import identity changed")
            continue
        if kind == "no-origin":
            if entry["origin"] is not None or entry["sha256"] is not None:
                raise PublicationRuntimeError("installed no-origin import identity changed")
            continue
        if kind == "namespace":
            origins = entry["origin"]
            if (
                type(origins) is not list
                or not origins
                or entry["sha256"] is not None
                or origins != sorted(origins, key=lambda item: (item["root"], item["path"]))
            ):
                raise PublicationRuntimeError("installed namespace import identity changed")
            for raw_origin in origins:
                origin = _exact_object(
                    raw_origin,
                    {"path", "root"},
                    "installed namespace import origin",
                )
                relative = origin["path"]
                root_kind = origin["root"]
                if type(relative) is not str or root_kind not in {"checkout", "stdlib"}:
                    raise PublicationRuntimeError("installed namespace import origin is malformed")
                if root_kind == "checkout":
                    candidate = repository_root / relative
                    if not candidate.is_dir() or not any(
                        path == relative or path.startswith(f"{relative}/")
                        for path in source_by_path
                    ):
                        raise PublicationRuntimeError(
                            "installed checkout namespace is outside the Behavior Set"
                        )
                elif not any((root / relative).is_dir() for root in stdlib_roots):
                    raise PublicationRuntimeError("installed stdlib namespace identity changed")
            continue
        if kind != "file":
            raise PublicationRuntimeError("installed runtime import kind is not frozen")
        origin = _exact_object(
            entry["origin"],
            {"path", "root"},
            "installed file import origin",
        )
        relative = origin["path"]
        root_kind = origin["root"]
        digest = _exact_lower_sha256(entry["sha256"], "installed import SHA-256")
        if type(relative) is not str or root_kind not in {"checkout", "stdlib"}:
            raise PublicationRuntimeError("installed file import origin is malformed")
        if root_kind == "checkout":
            source_entry = source_by_path.get(relative)
            if source_entry is None or source_entry["sha256"] != digest:
                raise PublicationRuntimeError(
                    "installed checkout import differs from the Analyzer Behavior Set"
                )
        else:
            _existing_stdlib_file(relative, stdlib_roots, digest)
    if names != sorted(names) or len(names) != len(set(names)):
        raise PublicationRuntimeError("installed runtime import manifest is not ordered")


def _verify_recorded_invocation(
    raw_invocation: object,
    *,
    interpreter: Path,
    input_artifact: dict[str, object],
    analysis_cli_receipt: dict[str, object],
) -> None:
    invocation = _exact_object(
        raw_invocation,
        {"argv", "environment", "worker_sha256"},
        "installed runtime invocation",
    )
    environment = invocation["environment"]
    expected_environment_keys = {
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LC_ALL",
        "PATH",
        "TMPDIR",
        "TZ",
        "XDG_CONFIG_HOME",
        "__CF_USER_TEXT_ENCODING",
    }
    if (
        type(environment) is not dict
        or set(environment) != expected_environment_keys
        or any(type(value) is not str for value in environment.values())
        or any(name.startswith("PYTHON") for name in environment)
    ):
        raise PublicationRuntimeError("installed runtime environment is not closed")
    home = Path(environment["HOME"])
    stage_root = home.parent
    expected_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(stage_root / "home"),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(stage_root / "tmp"),
        "TZ": "UTC",
        "XDG_CONFIG_HOME": str(stage_root / "home" / ".config"),
        "__CF_USER_TEXT_ENCODING": "0x0:0x0:0x0",
    }
    if environment != expected_environment or not stage_root.is_absolute():
        raise PublicationRuntimeError("installed runtime environment paths are not exact")
    argv = invocation["argv"]
    expected_argv = [
        str(interpreter),
        "-I",
        "-S",
        "-X",
        f"pycache_prefix={stage_root / 'pycache'}",
        "-c",
        _WORKER,
        str(stage_root / "checkout" / "src"),
        str(stage_root / "checkout" / _ANALYSIS_ENTRYPOINT),
        str(stage_root / "input-artifact.json"),
        input_artifact["sha256"],
        str(stage_root / "analysis-output"),
        str(stage_root / "worker-report.json"),
        json.dumps(sorted(environment), separators=(",", ":")),
    ]
    if argv != expected_argv:
        raise PublicationRuntimeError("installed runtime invocation is not exact")
    if invocation["worker_sha256"] != hashlib.sha256(_WORKER.encode("utf-8")).hexdigest():
        raise PublicationRuntimeError("installed runtime worker identity changed")
    if input_artifact["snapshot_path"] != expected_argv[9]:
        raise PublicationRuntimeError("installed runtime input snapshot path changed")
    if analysis_cli_receipt["input_path"] != expected_argv[9]:
        raise PublicationRuntimeError("installed analysis receipt input path changed")
    if analysis_cli_receipt["output_dir"] != expected_argv[11]:
        raise PublicationRuntimeError("installed analysis receipt output path changed")


def _verify_and_consume_runtime_receipt(runtime_receipt: object) -> _VerifiedRuntimeRun:
    """Consume a live runner result and independently reverify installed evidence."""

    binding = _claim_runner_receipt(runtime_receipt)
    repository_root = _absolute_path(binding.repository_root, "runtime repository_root")
    output_directory = _absolute_path(
        binding.installed_output_directory,
        "runtime output_directory",
    )
    interpreter = _absolute_path(binding.interpreter, "runtime interpreter")
    all_output_names = (
        *_ANALYSIS_OUTPUT_FILES,
        RUNTIME_RECEIPT_FILENAME,
        RUNTIME_RECEIPT_SHA_FILENAME,
    )
    installed_files = _directory_file_receipts(output_directory, all_output_names)
    installed_by_path = {entry["path"]: entry for entry in installed_files}
    receipt_path = output_directory / RUNTIME_RECEIPT_FILENAME
    document, receipt_bytes = _canonical_document(receipt_path, "installed runtime receipt")
    if receipt_bytes != binding.document:
        raise PublicationRuntimeError("installed runtime receipt differs from runner result")
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    checksum = _secure_read(
        output_directory / RUNTIME_RECEIPT_SHA_FILENAME,
        "installed runtime receipt checksum",
    )
    if checksum != f"{receipt_sha256}  {RUNTIME_RECEIPT_FILENAME}\n".encode("ascii"):
        raise PublicationRuntimeError("installed runtime receipt checksum changed")
    if set(document) != _RECEIPT_KEYS:
        raise PublicationRuntimeError("installed runtime receipt fields are not exact")
    if document["schema_version"] != RUNTIME_RECEIPT_SCHEMA:
        raise PublicationRuntimeError("installed runtime receipt schema changed")
    if (
        document["authority_state"] != RUNTIME_AUTHORITY_HOLD
        or document["formal_authority_granted"] is not False
        or document["runtime_execution_isolation_verified"] is not False
    ):
        raise PublicationRuntimeError(
            "the inner runtime receipt must remain descriptive and non-authoritative"
        )

    with tempfile.TemporaryDirectory(prefix="dynamic-cssc-runtime-admission-") as temporary:
        verification_root = Path(temporary)
        environment = _clean_environment(verification_root)
        policy = _load_policy(repository_root)
        current_source = _attest_repository(
            repository_root,
            environment,
            policy,
            require_detached=False,
        )
        detached_source = {**current_source, "repository_state": "clean-detached-head"}
        for field in (
            "source_attestation_before_decode",
            "source_attestation_after_analysis",
            "source_attestation_after_render_and_atomic_install_expected",
        ):
            if document[field] != detached_source:
                raise PublicationRuntimeError(
                    "installed runtime receipt source attestation differs from current S3"
                )
        source_sha = str(current_source["git_sha"])
        if document["fresh_checkout"] != {
            "detached": True,
            "fresh_private_checkout": True,
            "git_sha": source_sha,
        }:
            raise PublicationRuntimeError("installed runtime fresh-checkout identity changed")
        if document["policy"] != {
            "path": _POLICY_PATH,
            "schema_version": RUNTIME_POLICY_SCHEMA,
            "sha256": policy.sha256,
        }:
            raise PublicationRuntimeError("installed runtime policy identity changed")
        if document["dependency_locks"] != _dependency_lock_receipts(repository_root):
            raise PublicationRuntimeError("installed runtime dependency lock identity changed")
        interpreter_report, stdlib_roots = _probe_interpreter(
            interpreter,
            verification_root / "pycache",
            environment,
        )
        if document["interpreter"] != interpreter_report:
            raise PublicationRuntimeError("installed runtime interpreter identity changed")
        if document["git_executable"] != _binary_identity(_GIT_EXECUTABLE, "Git executable"):
            raise PublicationRuntimeError("installed runtime Git executable identity changed")
        if document["third_party_wheel_set"] != []:
            raise PublicationRuntimeError("installed runtime wheel set is not frozen empty")

        analysis_files = [installed_by_path[name] for name in sorted(_ANALYSIS_OUTPUT_FILES)]
        if document["analysis_output_files"] != analysis_files:
            raise PublicationRuntimeError("installed analysis artifact identities changed")
        input_artifact = _exact_object(
            document["input_artifact"],
            {"path", "sha256", "snapshot_path"},
            "installed runtime input artifact",
        )
        _exact_lower_sha256(input_artifact["sha256"], "installed input artifact SHA-256")
        if any(type(input_artifact[field]) is not str for field in ("path", "snapshot_path")):
            raise PublicationRuntimeError("installed input artifact paths are malformed")
        _absolute_path(Path(input_artifact["path"]), "installed input artifact path")
        _absolute_path(Path(input_artifact["snapshot_path"]), "installed input snapshot path")
        cli_receipt = _exact_object(
            document["analysis_cli_receipt"],
            {"artifact_sha256", "input_path", "input_sha256", "output_dir", "schema_version"},
            "installed analysis CLI receipt",
        )
        if cli_receipt["schema_version"] != "dynamic-cssc-publication-analysis-cli-receipt-v1":
            raise PublicationRuntimeError("installed analysis CLI receipt schema changed")
        if cli_receipt["input_sha256"] != input_artifact["sha256"]:
            raise PublicationRuntimeError("installed analysis CLI input digest changed")
        cli_artifact_digests = cli_receipt["artifact_sha256"]
        installed_artifact_digests = {entry["path"]: entry["sha256"] for entry in analysis_files}
        if cli_artifact_digests != installed_artifact_digests:
            raise PublicationRuntimeError(
                "installed analysis CLI artifact digests differ from installed bytes"
            )
        _verify_recorded_invocation(
            document["exact_invocation"],
            interpreter=interpreter,
            input_artifact=input_artifact,
            analysis_cli_receipt=cli_receipt,
        )
        _verify_installed_import_manifest(
            document["import_manifest"],
            repository_root=repository_root,
            source_attestation=current_source,
            stdlib_roots=stdlib_roots,
        )
        if document["output_install"] != {
            "destination": str(output_directory),
            "method": _atomic_no_replace_method(),
        }:
            raise PublicationRuntimeError("installed runtime output identity changed")
        removed = document["caller_environment_names_removed"]
        if (
            type(removed) is not list
            or any(type(name) is not str for name in removed)
            or removed != sorted(set(removed))
            or any(not (name.startswith("GIT_") or name.startswith("PYTHON")) for name in removed)
        ):
            raise PublicationRuntimeError("removed caller environment inventory is malformed")

        second_source = _attest_repository(
            repository_root,
            environment,
            policy,
            require_detached=False,
        )
        second_files = _directory_file_receipts(output_directory, all_output_names)
        if second_source != current_source or second_files != installed_files:
            raise PublicationRuntimeError(
                "runtime source or installed artifacts changed during admission"
            )

    installed_artifact_set_sha256 = hashlib.sha256(
        _canonical_json_bytes(installed_files)
    ).hexdigest()
    return _VerifiedRuntimeRun(
        repository_root=repository_root,
        output_directory=output_directory,
        source_git_sha=source_sha,
        source_attestation=MappingProxyType(current_source.copy()),
        analysis_output_files=tuple(MappingProxyType(entry.copy()) for entry in analysis_files),
        receipt_sha256=receipt_sha256,
        installed_artifact_set_sha256=installed_artifact_set_sha256,
    )


def _invoke_hook(hook: object | None, *arguments: object) -> None:
    if hook is None:
        return
    if not callable(hook):
        raise PublicationRuntimeError("private runtime test hook is not callable")
    hook(*arguments)


def _run_isolated(
    input_artifact: Path,
    output_directory: Path,
    context: _RuntimeContext,
) -> PublicationRuntimeReceipt:
    input_artifact = _absolute_path(input_artifact, "input_artifact")
    output_directory = _absolute_path(output_directory, "output_directory")
    repository_root = _absolute_path(context.repository_root, "repository_root")
    interpreter = _absolute_path(context.interpreter, "interpreter")
    _reject_symlink_components(input_artifact, missing_leaf_allowed=False)
    _reject_symlink_components(output_directory.parent, missing_leaf_allowed=False)
    if not output_directory.parent.is_dir():
        raise PublicationRuntimeError("output parent must be an existing directory")
    if output_directory.exists() or output_directory.is_symlink():
        raise PublicationRuntimeError("output directory must be all-new")
    if _is_within(output_directory, repository_root):
        raise PublicationRuntimeError("publication output must be outside the source checkout")

    input_bytes = _secure_read(input_artifact, "publication input artifact")
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    stage_root = Path(
        tempfile.mkdtemp(prefix=f".{output_directory.name}.runtime-", dir=output_directory.parent)
    )
    installed = False
    try:
        environment = _clean_environment(stage_root)
        policy = _load_policy(repository_root)
        source_attestation = _attest_repository(
            repository_root,
            environment,
            policy,
            require_detached=False,
        )
        source_sha = str(source_attestation["git_sha"])
        checkout = stage_root / "checkout"
        _prepare_fresh_checkout(
            repository_root,
            source_sha,
            checkout,
            environment,
        )
        _invoke_hook(context.after_checkout_hook, checkout)
        checkout_policy = _load_policy(checkout)
        if checkout_policy.canonical_bytes != policy.canonical_bytes:
            raise PublicationRuntimeError("fresh checkout runtime policy differs from S3")
        before_decode = _attest_repository(
            checkout,
            environment,
            checkout_policy,
            require_detached=True,
        )
        if before_decode != {
            **source_attestation,
            "repository_state": "clean-detached-head",
        }:
            raise PublicationRuntimeError("fresh detached checkout is not exact S3")

        lock_receipts = _dependency_lock_receipts(checkout)
        pycache = stage_root / "pycache"
        pycache.mkdir(mode=0o700)
        interpreter_report, stdlib_roots = _probe_interpreter(
            interpreter,
            pycache,
            environment,
        )
        _reject_injection_files(checkout, stdlib_roots)
        git_identity = _binary_identity(_GIT_EXECUTABLE, "Git executable")

        snapshot = stage_root / "input-artifact.json"
        _secure_write_new(snapshot, input_bytes)
        analysis_output = stage_root / "analysis-output"
        worker_report_path = stage_root / "worker-report.json"
        source_import_root = checkout / "src"
        entrypoint = checkout / _ANALYSIS_ENTRYPOINT
        expected_environment_names = sorted(environment)
        invocation = (
            str(interpreter),
            "-I",
            "-S",
            "-X",
            f"pycache_prefix={pycache}",
            "-c",
            _WORKER,
            str(source_import_root),
            str(entrypoint),
            str(snapshot),
            input_sha256,
            str(analysis_output),
            str(worker_report_path),
            json.dumps(expected_environment_names, separators=(",", ":")),
        )
        completed = _run(invocation, environment=environment, cwd=checkout)
        if completed.stderr:
            raise PublicationRuntimeError("isolated analysis emitted stderr")
        analysis_cli_receipt = _parse_analysis_cli_receipt(
            completed.stdout,
            input_path=snapshot,
            input_sha256=input_sha256,
            output_directory=analysis_output,
        )
        import_manifest = _validate_worker_report(
            worker_report_path,
            checkout=checkout,
            source_root=source_import_root,
            stdlib_roots=stdlib_roots,
            expected_environment=environment,
            expected_initial_sys_path=interpreter_report["sys_path"],
            pycache=pycache,
        )
        _invoke_hook(context.after_worker_hook, checkout, import_manifest)
        after_analysis = _attest_repository(
            checkout,
            environment,
            checkout_policy,
            require_detached=True,
        )
        if after_analysis != before_decode:
            raise PublicationRuntimeError("source attestation changed after analysis")
        analysis_files = _directory_file_receipts(analysis_output, _ANALYSIS_OUTPUT_FILES)
        analysis_output.chmod(0o700)
        expected_install_method = _atomic_no_replace_method()

        removed_names = sorted(
            name for name in os.environ if name.startswith("GIT_") or name.startswith("PYTHON")
        )
        receipt_document: dict[str, object] = {
            "analysis_cli_receipt": analysis_cli_receipt,
            "analysis_output_files": analysis_files,
            "authority_state": RUNTIME_AUTHORITY_HOLD,
            "caller_environment_names_removed": removed_names,
            "dependency_locks": lock_receipts,
            "exact_invocation": {
                "argv": list(invocation),
                "environment": environment,
                "worker_sha256": hashlib.sha256(_WORKER.encode("utf-8")).hexdigest(),
            },
            "formal_authority_granted": False,
            "fresh_checkout": {
                "detached": True,
                "fresh_private_checkout": True,
                "git_sha": source_sha,
            },
            "git_executable": git_identity,
            "import_manifest": {
                "entries": import_manifest,
                "sha256": hashlib.sha256(_canonical_json_bytes(import_manifest)).hexdigest(),
            },
            "input_artifact": {
                "path": str(input_artifact),
                "sha256": input_sha256,
                "snapshot_path": str(snapshot),
            },
            "interpreter": interpreter_report,
            "output_install": {
                "destination": str(output_directory),
                "method": expected_install_method,
            },
            "policy": {
                "path": _POLICY_PATH,
                "schema_version": RUNTIME_POLICY_SCHEMA,
                "sha256": checkout_policy.sha256,
            },
            # The standalone launcher verifies the evidence before returning its
            # non-boolean capability.  The repository-wide authority bit stays
            # false until evidence_compatibility independently consumes it.
            "runtime_execution_isolation_verified": False,
            "schema_version": RUNTIME_RECEIPT_SCHEMA,
            "source_attestation_after_analysis": after_analysis,
            "source_attestation_after_render_and_atomic_install_expected": before_decode,
            "source_attestation_before_decode": before_decode,
            "third_party_wheel_set": [],
        }
        if set(receipt_document) != _RECEIPT_KEYS:
            raise AssertionError("runtime receipt construction is not exact")
        receipt_bytes = _canonical_json_bytes(receipt_document)
        receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
        _secure_write_new(analysis_output / RUNTIME_RECEIPT_FILENAME, receipt_bytes)
        _secure_write_new(
            analysis_output / RUNTIME_RECEIPT_SHA_FILENAME,
            f"{receipt_digest}  {RUNTIME_RECEIPT_FILENAME}\n".encode("ascii"),
        )
        all_output_names = (
            *_ANALYSIS_OUTPUT_FILES,
            RUNTIME_RECEIPT_FILENAME,
            RUNTIME_RECEIPT_SHA_FILENAME,
        )
        staged_files = _directory_file_receipts(analysis_output, all_output_names)
        _fsync_directory(analysis_output)
        _invoke_hook(context.before_install_hook, output_directory, checkout)
        install_method = _atomic_install_directory(analysis_output, output_directory)
        installed = True
        installed_files = _directory_file_receipts(output_directory, all_output_names)
        if installed_files != staged_files:
            raise PublicationRuntimeError("installed publication output differs from staging")
        installed_receipt = _secure_read(
            output_directory / RUNTIME_RECEIPT_FILENAME,
            "installed runtime receipt",
        )
        installed_checksum = _secure_read(
            output_directory / RUNTIME_RECEIPT_SHA_FILENAME,
            "installed runtime receipt checksum",
        )
        if installed_receipt != receipt_bytes or installed_checksum != (
            f"{receipt_digest}  {RUNTIME_RECEIPT_FILENAME}\n".encode("ascii")
        ):
            raise PublicationRuntimeError("installed runtime receipt identity changed")
        second_import_manifest = _validate_worker_report(
            worker_report_path,
            checkout=checkout,
            source_root=source_import_root,
            stdlib_roots=stdlib_roots,
            expected_environment=environment,
            expected_initial_sys_path=interpreter_report["sys_path"],
            pycache=pycache,
        )
        if second_import_manifest != import_manifest:
            raise PublicationRuntimeError("runtime imports changed after rendering and install")
        if _binary_identity(interpreter, "CPython interpreter") != interpreter_report["binary"]:
            raise PublicationRuntimeError("CPython interpreter bytes changed during analysis")
        if _binary_identity(_GIT_EXECUTABLE, "Git executable") != git_identity:
            raise PublicationRuntimeError("Git executable bytes changed during analysis")
        after_install = _attest_repository(
            checkout,
            environment,
            checkout_policy,
            require_detached=True,
        )
        if after_install != before_decode:
            raise PublicationRuntimeError(
                "source attestation changed after rendering and atomic install"
            )
        if install_method != expected_install_method:
            raise AssertionError("output no-replace installation method changed")
        receipt = object.__new__(PublicationRuntimeReceipt)
        binding = _ReceiptBinding(
            receipt_bytes,
            output_directory,
            repository_root,
            interpreter,
        )
        object.__setattr__(receipt, "_binding", binding)
        with _LIVE_RECEIPT_LOCK:
            _LIVE_RUNNER_RECEIPTS[receipt] = binding
        return receipt
    finally:
        if stage_root.exists():
            shutil.rmtree(stage_root)
        if not installed and output_directory.exists():
            # A failed no-replace call never creates the destination.  If a racing
            # caller created it, it is deliberately left untouched.
            pass


def run_publication_analysis_isolated(
    input_artifact: Path,
    output_directory: Path,
) -> PublicationRuntimeReceipt:
    """Run the frozen analyzer through the repository-owned isolated seam.

    The function intentionally has no source-SHA, interpreter, environment,
    policy, anchor, or boolean override.  The current module location determines
    the sole candidate S3 repository and ``sys.executable`` determines the sole
    candidate interpreter; both must pass the frozen checks.
    """

    module_path = Path(__file__).absolute()
    repository_root = module_path.parents[2]
    context = _RuntimeContext(
        repository_root=repository_root,
        interpreter=Path(sys.executable).absolute(),
    )
    return _run_isolated(input_artifact, output_directory, context)


__all__ = (
    "PublicationRuntimeError",
    "PublicationRuntimeHold",
    "PublicationRuntimeReceipt",
    "RUNTIME_AUTHORITY_HOLD",
    "RUNTIME_POLICY_SCHEMA",
    "RUNTIME_RECEIPT_FILENAME",
    "RUNTIME_RECEIPT_SCHEMA",
    "RUNTIME_RECEIPT_SHA_FILENAME",
    "run_publication_analysis_isolated",
)
