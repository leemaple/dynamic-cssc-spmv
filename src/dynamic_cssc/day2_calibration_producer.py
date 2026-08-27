"""Formal Day 2 calibration producer used only by the isolated worker."""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

from dynamic_cssc.day2_calibration_authority import (
    CALIBRATION_MEASUREMENT_BLOCK_COUNT,
    CALIBRATION_MEASUREMENT_STOP_RULE,
    CALIBRATION_OPERATION_ORDER_METHOD,
    CALIBRATION_OPERATION_ORDER_SEED,
    CALIBRATION_WARMUP_BLOCK_COUNT,
    EVIDENCE_SCOPE,
    PRIMITIVE_NAMES,
    _calibration_projection,
    inspect_day2_calibration_archive,
    repository_day2_calibration_profile_authority,
)
from dynamic_cssc.day2_calibration_profile import (
    propose_repository_day2_calibration_profile,
)
from dynamic_cssc.day2_calibration_runtime import Day2RuntimeIsolationCapability
from dynamic_cssc.evidence_compatibility import (
    EvidenceRole,
    capture_behavior_inventory,
)

__all__ = ("Day2CalibrationProducerError",)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_WORKFLOW_PATH = ".github/workflows/day2-publication-calibration.yml"
_REPOSITORY = "leemaple/dynamic-cssc-spmv"
_REPOSITORY_ID = 1_341_939_625
_OPENFHE_REPOSITORY = "https://github.com/openfheorg/openfhe-development.git"
_OPENFHE_VERSION = "1.5.1"
_OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
_ARCHIVE_TIMESTAMP = (2026, 8, 23, 0, 0, 0)
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_KEY_BYTES = 16 * 1024 * 1024
_PAYLOAD_FILENAMES = (
    "RUN_STATUS.json",
    "source-provenance.json",
    "workflow-provenance.json",
    "host-profile.json",
    "openfhe-build.json",
    "contract-bindings.json",
    "rotation-key-plan.json",
    "generated-key-inventory.json",
    "serialized-object-size-profile.json",
    "operation-profile-set.json",
    "raw-measurement-blocks.json",
    "runtime-isolation-receipt.json",
    "producer-validation.json",
)
_ARCHIVE_ORDER = (*_PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json", "SHA256SUMS")
_PROFILE_PROPOSAL_MEMBERS = frozenset(
    {
        "contract-bindings.json",
        "day2-calibration-profile-anchor-proposal.json",
        "operation-profile-set.json",
        "rotation-key-plan.json",
        "PROFILE-MANIFEST.json",
        "SHA256SUMS",
    }
)
_PROBE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "noise_budget_profile",
        "evidence_scope",
        "mixed_workload_formal_parameter_claim_allowed",
        "publication_raw_block_contract_satisfied",
        "all_profiles_correct",
        "eval_mult_includes_relinearization",
        "measured_rotation_index",
        "required_exact_rotation_indices",
        "process_affinity_cpu_list",
        "ciphertext_bytes",
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
        "rotation_key_bytes",
        "eval_mult_key_bytes",
        "operations",
        "raw_measurement_blocks",
    }
)


class Day2CalibrationProducerError(RuntimeError):
    """Formal Day 2 production failed before a valid archive was installed."""


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day2CalibrationProducerError("producer value is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_regular(path: Path, *, field: str, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise Day2CalibrationProducerError(f"{field} must be a regular non-symlink file")
    content = path.read_bytes()
    if not content or len(content) > maximum_bytes:
        raise Day2CalibrationProducerError(f"{field} exceeds its closed byte bound")
    return content


def _load_canonical_json(path: Path, *, field: str) -> dict[str, object]:
    content = _read_regular(path, field=field, maximum_bytes=_MAX_JSON_BYTES)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise Day2CalibrationProducerError(f"{field} contains a duplicate JSON key")
            value[key] = item
        return value

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationProducerError(f"{field} is not readable JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise Day2CalibrationProducerError(f"{field} is not canonical JSON")
    return document


def _strict_positive_environment_integer(
    environment: dict[str, str] | os._Environ[str],
    name: str,
) -> int:
    value = environment.get(name)
    if type(value) is not str or _INTEGER.fullmatch(value) is None or value == "0":
        raise Day2CalibrationProducerError(f"{name} must be a positive canonical integer")
    return int(value)


def _workflow_provenance_from_environment(
    *,
    repository_root: Path,
    source_git_sha: str,
    environment: dict[str, str] | os._Environ[str],
) -> dict[str, object]:
    if _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise Day2CalibrationProducerError("workflow source Git SHA is invalid")
    workflow_ref = environment.get("GITHUB_WORKFLOW_REF")
    expected_workflow_ref = f"{_REPOSITORY}/{_WORKFLOW_PATH}@refs/heads/main"
    if (
        environment.get("GITHUB_REPOSITORY") != _REPOSITORY
        or environment.get("GITHUB_REPOSITORY_ID") != str(_REPOSITORY_ID)
        or type(workflow_ref) is not str
        or workflow_ref != expected_workflow_ref
        or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environment.get("GITHUB_REF") != "refs/heads/main"
        or environment.get("GITHUB_SHA") != source_git_sha
    ):
        raise Day2CalibrationProducerError(
            "GitHub environment does not match the dedicated formal Day 2 workflow"
        )
    workflow_file = repository_root / _WORKFLOW_PATH
    workflow_bytes = _read_regular(
        workflow_file,
        field="formal Day 2 workflow",
        maximum_bytes=1024 * 1024,
    )
    run_id = _strict_positive_environment_integer(environment, "GITHUB_RUN_ID")
    run_attempt = _strict_positive_environment_integer(environment, "GITHUB_RUN_ATTEMPT")
    artifact_name = f"r3-day2-calibration-{source_git_sha}-{run_id}-{run_attempt}"
    return {
        "schema_version": "dynamic-cssc-publication-day2-workflow-provenance-v1",
        "repository": _REPOSITORY,
        "repository_id": _REPOSITORY_ID,
        "workflow_path": _WORKFLOW_PATH,
        "workflow_file_sha256": _sha256(workflow_bytes),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "head_sha": source_git_sha,
        "artifact_name": artifact_name,
    }


def _generated_key_inventory(
    *,
    rotation_key_plan: dict[str, object],
    rotation_key_plan_sha256: str,
    serialized_rotation_keys: bytes,
    serialized_eval_mult_keys: bytes,
) -> dict[str, object]:
    if _LOWER_SHA256.fullmatch(rotation_key_plan_sha256) is None:
        raise Day2CalibrationProducerError("rotation plan digest is invalid")
    indices = rotation_key_plan.get("required_exact_indices")
    if (
        type(indices) is not list
        or not indices
        or any(type(index) is not int for index in indices)
        or indices != sorted(set(indices))
        or any(index == 0 or not -4095 <= index <= 4095 for index in indices)
        or len({index % 4096 for index in indices}) != len(indices)
    ):
        raise Day2CalibrationProducerError("rotation plan indices are not canonical")
    if not serialized_rotation_keys or not serialized_eval_mult_keys:
        raise Day2CalibrationProducerError("serialized evaluation key inputs must be nonempty")
    if (
        len(serialized_rotation_keys) > _MAX_KEY_BYTES
        or len(serialized_eval_mult_keys) > _MAX_KEY_BYTES
    ):
        raise Day2CalibrationProducerError("serialized evaluation key input is oversized")
    return {
        "schema_version": "dynamic-cssc-publication-generated-key-inventory-v1",
        "rotation_key_plan_sha256": rotation_key_plan_sha256,
        "generated_exact_indices": list(indices),
        "serialized_rotation_key_inventory_sha256": _sha256(serialized_rotation_keys),
        "serialized_rotation_key_bytes": len(serialized_rotation_keys),
        "eval_mult_key_generated": True,
        "serialized_eval_mult_key_sha256": _sha256(serialized_eval_mult_keys),
        "serialized_eval_mult_key_bytes": len(serialized_eval_mult_keys),
    }


def _serialized_object_size_profile(
    *,
    ciphertext_bytes: object,
    f1m_random_zero_sum_ciphertext_bytes: object,
    f1m_encrypted_zero_dummy_ciphertext_bytes: object,
    generated_key_inventory: dict[str, object],
) -> dict[str, object]:
    """Bind category-specific formal-probe ciphertext lengths to measured keys."""

    for field, value in (
        ("ciphertext_bytes", ciphertext_bytes),
        (
            "f1m_random_zero_sum_ciphertext_bytes",
            f1m_random_zero_sum_ciphertext_bytes,
        ),
        (
            "f1m_encrypted_zero_dummy_ciphertext_bytes",
            f1m_encrypted_zero_dummy_ciphertext_bytes,
        ),
    ):
        if type(value) is not int or value <= 0:
            raise Day2CalibrationProducerError(
                f"serialized object size profile requires positive {field}"
            )
    if type(generated_key_inventory) is not dict:
        raise Day2CalibrationProducerError(
            "serialized object size profile requires a generated-key inventory"
        )
    rotation_key_bytes = generated_key_inventory.get(
        "serialized_rotation_key_bytes"
    )
    eval_mult_key_bytes = generated_key_inventory.get("serialized_eval_mult_key_bytes")
    if (
        type(rotation_key_bytes) is not int
        or rotation_key_bytes <= 0
        or type(eval_mult_key_bytes) is not int
        or eval_mult_key_bytes <= 0
    ):
        raise Day2CalibrationProducerError(
            "serialized object size profile requires positive evaluation-key sizes"
        )
    return {
        "schema_version": "dynamic-cssc-publication-day2-serialized-object-size-profile-v2",
        "ciphertext_serialization_format": "openfhe-sertype-binary-v1",
        "ciphertext_measurement_method": "formal-probe-exact-serialized-byte-length-v1",
        "ciphertext_bytes": ciphertext_bytes,
        "f1m_ciphertext_construction_profile": (
            "fresh-bfvrns-encryption-fixed-context-v1"
        ),
        "f1m_random_zero_sum_ciphertext_bytes": (
            f1m_random_zero_sum_ciphertext_bytes
        ),
        "f1m_encrypted_zero_dummy_ciphertext_bytes": (
            f1m_encrypted_zero_dummy_ciphertext_bytes
        ),
        "generated_key_inventory_sha256": _sha256(
            _canonical_json_bytes(generated_key_inventory)
        ),
        "serialized_rotation_key_inventory_bytes": rotation_key_bytes,
        "serialized_eval_mult_key_bytes": eval_mult_key_bytes,
    }


def _canonical_zip_bytes(
    members: dict[str, bytes],
    *,
    member_order: tuple[str, ...],
) -> bytes:
    if set(members) != set(member_order) or len(member_order) != len(set(member_order)):
        raise Day2CalibrationProducerError("canonical ZIP member order is not exact")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in member_order:
            if type(name) is not str or not name or "/" in name or "\\" in name:
                raise Day2CalibrationProducerError("canonical ZIP member name is unsafe")
            content = members[name]
            if type(content) is not bytes:
                raise Day2CalibrationProducerError("canonical ZIP members must be bytes")
            info = zipfile.ZipInfo(name, date_time=_ARCHIVE_TIMESTAMP)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    return buffer.getvalue()


def _write_new_file(path: Path, content: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise Day2CalibrationProducerError(f"producer write failed: {path.name}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    field: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        stderr = (
            error.stderr.decode("utf-8", errors="replace")[-4000:]
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        raise Day2CalibrationProducerError(f"{field} failed: {stderr}") from error


def _git_output(
    repository: Path,
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
) -> bytes:
    git = shutil.which("git", path=environment["PATH"])
    if git is None:
        raise Day2CalibrationProducerError("git executable is unavailable")
    return _run(
        (git, "-C", str(repository), *arguments),
        cwd=repository,
        environment=environment,
        field="Git provenance command",
    ).stdout


def _source_identity(
    repository_root: Path,
    *,
    environment: dict[str, str],
) -> tuple[str, str, bytes]:
    head = _git_output(
        repository_root,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        environment=environment,
    ).decode("ascii").strip()
    tree = _git_output(
        repository_root,
        ("rev-parse", "--verify", "HEAD^{tree}"),
        environment=environment,
    ).decode("ascii").strip()
    status = _git_output(
        repository_root,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        environment=environment,
    )
    if (
        _LOWER_GIT_SHA.fullmatch(head) is None
        or _LOWER_GIT_SHA.fullmatch(tree) is None
        or status
    ):
        raise Day2CalibrationProducerError("formal producer source checkout is not clean")
    return head, tree, status


def _profile_documents(
    *,
    day1a_directory: Path,
    github_artifact_metadata_path: Path,
    execution_root: Path,
    runtime_capability: Day2RuntimeIsolationCapability,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    proposal_root = execution_root / "profile-proposal"
    propose_repository_day2_calibration_profile(
        day1a_directory,
        github_artifact_metadata_path,
        proposal_root,
    )
    if frozenset(path.name for path in proposal_root.iterdir()) != _PROFILE_PROPOSAL_MEMBERS:
        raise Day2CalibrationProducerError("profile proposal member set changed")
    profiles = _load_canonical_json(
        proposal_root / "operation-profile-set.json",
        field="operation profile set",
    )
    rotation_plan = _load_canonical_json(
        proposal_root / "rotation-key-plan.json",
        field="rotation key plan",
    )
    contract = _load_canonical_json(
        proposal_root / "contract-bindings.json",
        field="contract bindings",
    )
    anchor_set = _load_canonical_json(
        proposal_root / "day2-calibration-profile-anchor-proposal.json",
        field="profile anchor proposal",
    )
    anchors = anchor_set.get("anchors")
    if type(anchors) is not list or len(anchors) != 1 or type(anchors[0]) is not dict:
        raise Day2CalibrationProducerError("profile anchor proposal is not singular")
    authority = repository_day2_calibration_profile_authority()
    receipt = runtime_capability.consume(authority, profiles, rotation_plan, contract)
    return profiles, rotation_plan, contract, receipt


def _sha256_file(path: Path, *, field: str, maximum_bytes: int = _MAX_JSON_BYTES) -> str:
    return _sha256(_read_regular(path, field=field, maximum_bytes=maximum_bytes))


def _tool_output(
    executable: str,
    arguments: tuple[str, ...],
    *,
    repository_root: Path,
    environment: dict[str, str],
    field: str,
) -> str:
    path = shutil.which(executable, path=environment["PATH"])
    if path is None:
        raise Day2CalibrationProducerError(f"{field} executable is unavailable")
    output = _run(
        (path, *arguments),
        cwd=repository_root,
        environment=environment,
        field=field,
    ).stdout.decode("utf-8", errors="strict").strip()
    if not output:
        raise Day2CalibrationProducerError(f"{field} produced no identity output")
    return output


def _shared_library_inventory(install_root: Path) -> dict[str, object]:
    libraries = sorted(
        path
        for path in install_root.rglob("libOPENFHE*")
        if path.is_file() and not path.is_symlink()
    )
    if not libraries:
        raise Day2CalibrationProducerError("OpenFHE shared-library inventory is empty")
    entries = [
        {
            "path": path.relative_to(install_root).as_posix(),
            "sha256": _sha256_file(
                path,
                field="OpenFHE shared library",
                maximum_bytes=256 * 1024 * 1024,
            ),
            "bytes": path.stat(follow_symlinks=False).st_size,
        }
        for path in libraries
    ]
    return {
        "schema_version": "dynamic-cssc-openfhe-shared-library-inventory-v1",
        "entries": entries,
    }


def _build_openfhe_and_probe(
    *,
    repository_root: Path,
    execution_root: Path,
    environment: dict[str, str],
) -> tuple[dict[str, object], Path, dict[str, str]]:
    openfhe_root = execution_root / "openfhe"
    openfhe_source = openfhe_root / "source"
    openfhe_build = openfhe_root / "build"
    openfhe_install = openfhe_root / "install"
    probe_build = execution_root / "probe-build"
    for path in (openfhe_root, probe_build):
        if path.exists() or path.is_symlink():
            raise Day2CalibrationProducerError("private build target must be absent")
    build_environment = dict(environment)
    build_environment.update(
        {
            "OPENFHE_SOURCE_DIR": str(openfhe_source),
            "OPENFHE_BUILD_DIR": str(openfhe_build),
            "OPENFHE_INSTALL_DIR": str(openfhe_install),
            "DYNAMIC_CSSC_CPP_BUILD_DIR": str(probe_build),
            "BUILD_JOBS": "2",
        }
    )
    bootstrap = repository_root / "scripts/bootstrap_openfhe.sh"
    build_probe = repository_root / "scripts/build_cpp.sh"
    _run(
        (str(bootstrap), str(repository_root / "config/params_manifest.json")),
        cwd=repository_root,
        environment=build_environment,
        field="pinned OpenFHE build",
    )
    _run(
        (str(build_probe),),
        cwd=repository_root,
        environment=build_environment,
        field="formal probe build",
    )
    commit = _git_output(
        openfhe_source,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        environment=build_environment,
    ).decode("ascii").strip()
    tree = _git_output(
        openfhe_source,
        ("rev-parse", "--verify", "HEAD^{tree}"),
        environment=build_environment,
    ).decode("ascii").strip()
    status = _git_output(
        openfhe_source,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        environment=build_environment,
    )
    if commit != _OPENFHE_COMMIT or _LOWER_GIT_SHA.fullmatch(tree) is None or status:
        raise Day2CalibrationProducerError("OpenFHE source identity is not the frozen clean tree")
    tree_listing = _git_output(
        openfhe_source,
        ("ls-files", "-s", "-z"),
        environment=build_environment,
    )
    if not tree_listing:
        raise Day2CalibrationProducerError("OpenFHE source tree inventory is empty")
    openfhe_compile_commands = openfhe_build / "compile_commands.json"
    probe_compile_commands = probe_build / "compile_commands.json"
    for path, label in (
        (openfhe_compile_commands, "OpenFHE compile commands"),
        (probe_compile_commands, "probe compile commands"),
    ):
        _read_regular(path, field=label, maximum_bytes=64 * 1024 * 1024)
    probe_compile_text = probe_compile_commands.read_text(encoding="utf-8")
    if "-O3" not in probe_compile_text or "-fopenmp" not in probe_compile_text:
        raise Day2CalibrationProducerError(
            "probe compile commands do not contain the frozen -O3/-fopenmp profile"
        )
    if "-march=native" in probe_compile_text or "-mtune=native" in probe_compile_text:
        raise Day2CalibrationProducerError("native optimization flags are forbidden")
    compiler = shutil.which("g++", path=environment["PATH"])
    if compiler is None:
        raise Day2CalibrationProducerError("g++ is unavailable")
    compiler_path = str(Path(compiler).resolve())
    compiler_version = _tool_output(
        compiler_path,
        ("--version",),
        repository_root=repository_root,
        environment=build_environment,
        field="compiler version",
    ).splitlines()[0]
    compiler_target = _tool_output(
        compiler_path,
        ("-dumpmachine",),
        repository_root=repository_root,
        environment=build_environment,
        field="compiler target",
    )
    cmake_version = _tool_output(
        "cmake",
        ("--version",),
        repository_root=repository_root,
        environment=build_environment,
        field="CMake version",
    ).splitlines()[0]
    ninja_version = _tool_output(
        "ninja",
        ("--version",),
        repository_root=repository_root,
        environment=build_environment,
        field="Ninja version",
    ).splitlines()[0]
    probe_binary = probe_build / "openfhe_microbench"
    if probe_binary.is_symlink() or not probe_binary.is_file():
        raise Day2CalibrationProducerError("formal OpenFHE probe binary is unavailable")
    linked_tool = "ldd" if platform.system() == "Linux" else "otool"
    linked_args = (str(probe_binary),) if linked_tool == "ldd" else ("-L", str(probe_binary))
    linked_inventory = _tool_output(
        linked_tool,
        linked_args,
        repository_root=repository_root,
        environment=build_environment,
        field="linked library inventory",
    ).encode("utf-8")
    library_inventory = _shared_library_inventory(openfhe_install)
    producer_path = Path(__file__).resolve()
    validator_path = repository_root / "src/dynamic_cssc/day2_calibration_authority.py"
    build_document = {
        "schema_version": "dynamic-cssc-publication-day2-openfhe-build-v1",
        "repository": _OPENFHE_REPOSITORY,
        "version": _OPENFHE_VERSION,
        "commit": commit,
        "source_git_tree": tree,
        "source_tree_clean": True,
        "source_tree_sha256": _sha256(tree_listing),
        "cmake_version": cmake_version,
        "ninja_version": ninja_version,
        "cmake_flags": {
            "BUILD_BENCHMARKS": "OFF",
            "BUILD_EXAMPLES": "OFF",
            "BUILD_UNITTESTS": "OFF",
            "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_CXX_EXTENSIONS": "OFF",
            "CMAKE_CXX_STANDARD": "17",
            "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
            "WITH_NATIVEOPT": "OFF",
            "WITH_OPENMP": "ON",
        },
        "cmake_cache_sha256": _sha256_file(
            openfhe_build / "CMakeCache.txt",
            field="OpenFHE CMake cache",
        ),
        "compile_commands_sha256": _sha256_file(
            openfhe_compile_commands,
            field="OpenFHE compile commands",
        ),
        "installed_manifest_sha256": _sha256_file(
            openfhe_build / "install_manifest.txt",
            field="OpenFHE install manifest",
        ),
        "openfhe_shared_library_sha256": _sha256(_canonical_json_bytes(library_inventory)),
        "probe_source_sha256": _sha256_file(
            repository_root / "cpp/microbench.cpp",
            field="formal probe source",
        ),
        "probe_binary_sha256": _sha256_file(
            probe_binary,
            field="formal probe binary",
            maximum_bytes=256 * 1024 * 1024,
        ),
        "manifest_generator_sha256": _sha256_file(
            producer_path,
            field="formal manifest generator",
        ),
        "bundle_validator_sha256": _sha256_file(
            validator_path,
            field="formal bundle validator",
        ),
        "compiler_path": compiler_path,
        "compiler_vendor": "gcc",
        "compiler_version": compiler_version,
        "compiler_target": compiler_target,
        "effective_compile_flags": ["-O3", "-fopenmp"],
        "linked_library_inventory_sha256": _sha256(linked_inventory),
    }
    return build_document, probe_binary, build_environment


def _read_text_or(path: Path, fallback: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return fallback
    return value or fallback


def _cpu_info() -> tuple[dict[str, str], list[dict[str, str]]]:
    try:
        content = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise Day2CalibrationProducerError("Linux /proc/cpuinfo is unavailable") from error
    blocks: list[dict[str, str]] = []
    for raw_block in content.strip().split("\n\n"):
        block: dict[str, str] = {}
        for line in raw_block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                block[key.strip()] = value.strip()
        if block:
            blocks.append(block)
    if not blocks:
        raise Day2CalibrationProducerError("Linux CPU inventory is empty")
    return blocks[0], blocks


def _os_release() -> dict[str, str]:
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise Day2CalibrationProducerError("Linux OS release identity is unavailable") from error
    values: dict[str, str] = {}
    for line in lines:
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def _thermal_throttle_count(cpus: list[int]) -> int | None:
    counters: list[int] = []
    for cpu in cpus:
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}/thermal_throttle")
        for name in ("core_throttle_count", "package_throttle_count"):
            path = base / name
            if not path.is_file():
                continue
            value = _read_text_or(path, "")
            if not value.isdigit():
                raise Day2CalibrationProducerError("thermal throttle counter is invalid")
            counters.append(int(value))
    return sum(counters) if counters else None


def _turbo_state() -> str:
    no_turbo = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")
    if no_turbo.is_file():
        value = _read_text_or(no_turbo, "")
        if value in {"0", "1"}:
            return "enabled" if value == "0" else "disabled"
    boost = Path("/sys/devices/system/cpu/cpufreq/boost")
    if boost.is_file():
        value = _read_text_or(boost, "")
        if value in {"0", "1"}:
            return "enabled" if value == "1" else "disabled"
    return "unobservable"


def _power_source() -> str:
    supplies = Path("/sys/class/power_supply")
    if not supplies.is_dir():
        return "unobservable"
    battery_present = False
    observed_online: list[bool] = []
    for entry in sorted(supplies.iterdir()):
        kind = _read_text_or(entry / "type", "unknown").casefold()
        if kind == "battery":
            battery_present = True
        online = entry / "online"
        if kind in {"mains", "usb", "usb_c", "wireless"} and online.is_file():
            value = _read_text_or(online, "")
            if value not in {"0", "1"}:
                raise Day2CalibrationProducerError("power-supply online state is invalid")
            observed_online.append(value == "1")
    if observed_online:
        return (
            "ac-observed-online"
            if any(observed_online)
            else "battery-or-disconnected-observed"
        )
    if not battery_present:
        # A server/VM with an observable empty power-supply class has no battery
        # transition path; record the continuously powered host classification.
        return "server-or-vm-no-battery-interface"
    return "unobservable"


def _host_profile(
    *,
    openfhe_build: dict[str, object],
    effective_cpus: list[int],
    thermal_before: int | None,
    thermal_after: int | None,
    environment: dict[str, str],
) -> dict[str, object]:
    first_cpu, cpu_blocks = _cpu_info()
    logical_cpu_count = os.cpu_count()
    if type(logical_cpu_count) is not int or logical_cpu_count <= 0:
        raise Day2CalibrationProducerError("logical CPU count is unavailable")
    physical_pairs = {
        (block.get("physical id", "0"), block.get("core id", block.get("processor", "0")))
        for block in cpu_blocks
    }
    socket_ids = {block.get("physical id", "0") for block in cpu_blocks}
    memory_line = _read_text_or(Path("/proc/meminfo"), "").splitlines()
    memory_kib = None
    for line in memory_line:
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                memory_kib = int(parts[1])
                break
    if memory_kib is None or memory_kib <= 0:
        raise Day2CalibrationProducerError("host memory size is unavailable")
    numa_entries = []
    for path in sorted(Path("/sys/devices/system/node").glob("node[0-9]*/cpulist")):
        numa_entries.append(
            {"path": path.as_posix(), "cpulist": _read_text_or(path, "unavailable")}
        )
    if not numa_entries:
        numa_entries = [{"path": "process-affinity", "cpulist": list(effective_cpus)}]
    release = _os_release()
    kernel_cmdline = Path("/proc/cmdline").read_bytes()
    image_identity = {
        "ImageOS": environment.get("ImageOS", "unavailable"),
        "ImageVersion": environment.get("ImageVersion", "unavailable"),
        "RUNNER_ENVIRONMENT": environment.get("RUNNER_ENVIRONMENT", "unavailable"),
        "RUNNER_NAME": environment.get("RUNNER_NAME", "unavailable"),
    }
    governors = []
    fallback_mhz = first_cpu.get("cpu MHz", "1")
    try:
        fallback_khz = max(1, int(float(fallback_mhz) * 1000))
    except ValueError:
        fallback_khz = 1
    scaling_drivers: list[str] = []
    for cpu in effective_cpus:
        base = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        driver = _read_text_or(base / "scaling_driver", "unavailable")
        scaling_drivers.append(driver)
        minimum_text = _read_text_or(base / "scaling_min_freq", str(fallback_khz))
        maximum_text = _read_text_or(base / "scaling_max_freq", str(fallback_khz))
        if not minimum_text.isdigit() or not maximum_text.isdigit():
            raise Day2CalibrationProducerError("CPU frequency bounds are invalid")
        governors.append(
            {
                "cpu": cpu,
                "governor": _read_text_or(base / "scaling_governor", "unavailable"),
                "min_khz": max(1, int(minimum_text)),
                "max_khz": max(1, int(maximum_text)),
                "energy_performance_preference": _read_text_or(
                    base / "energy_performance_preference",
                    "unavailable",
                ),
            }
        )
    scaling_driver = (
        scaling_drivers[0]
        if len(set(scaling_drivers)) == 1
        else "mixed:" + ",".join(scaling_drivers)
    )
    return {
        "schema_version": "dynamic-cssc-publication-day2-host-profile-v2",
        "hardware": {
            "architecture": platform.machine(),
            "cpu_vendor": first_cpu.get("vendor_id", "unavailable"),
            "cpu_model_name": first_cpu.get("model name", "unavailable"),
            "cpu_family": first_cpu.get("cpu family", "unavailable"),
            "cpu_model": first_cpu.get("model", "unavailable"),
            "cpu_stepping": first_cpu.get("stepping", "unavailable"),
            "microcode": first_cpu.get("microcode", "unavailable"),
            "socket_count": max(1, len(socket_ids)),
            "physical_core_count": max(1, len(physical_pairs)),
            "logical_cpu_count": logical_cpu_count,
            "memory_bytes": memory_kib * 1024,
            "numa_topology_sha256": _sha256(_canonical_json_bytes(numa_entries)),
        },
        "os": {
            "distribution_id": release.get("ID", "unavailable"),
            "distribution_version": release.get("VERSION_ID", "unavailable"),
            "kernel_release": platform.release(),
            "kernel_cmdline_sha256": _sha256(kernel_cmdline),
            "glibc_version": " ".join(platform.libc_ver()).strip() or "unavailable",
            "runner_image_identity_sha256": _sha256(
                _canonical_json_bytes(image_identity)
            ),
        },
        "compiler": {
            "path": openfhe_build["compiler_path"],
            "vendor": openfhe_build["compiler_vendor"],
            "version": openfhe_build["compiler_version"],
            "target": openfhe_build["compiler_target"],
        },
        "affinity": {
            "requested_cpu_list": list(effective_cpus),
            "verified_probe_cpu_list": list(effective_cpus),
            "probe_affinity_observation_stage": "pre-and-post-measurement-identical",
            "omp_num_threads": len(effective_cpus),
            "omp_proc_bind": "close",
            "omp_places": "cores",
            "per_block_allowed_cpu_sets": [
                list(effective_cpus) for _ in range(CALIBRATION_MEASUREMENT_BLOCK_COUNT)
            ],
        },
        "power": {
            "scaling_driver": scaling_driver,
            "governor_by_cpu": governors,
            "turbo_state": _turbo_state(),
            "power_source": _power_source(),
            "thermal_throttle_counters_observable": thermal_before is not None,
            "thermal_throttle_count_before": thermal_before,
            "thermal_throttle_count_after": thermal_after,
            "thermal_throttling_observed": (
                None
                if thermal_before is None
                else thermal_after is not None and thermal_after > thermal_before
            ),
        },
    }


def _extract_formal_probe(
    *,
    document: object,
    rotation_key_plan: dict[str, object],
    rotation_key_bytes: int,
    eval_mult_key_bytes: int,
) -> tuple[dict[str, object], int, int, int]:
    if type(document) is not dict or set(document) != _PROBE_KEYS:
        raise Day2CalibrationProducerError("formal probe keys are not exact")
    expected_indices = rotation_key_plan["required_exact_indices"]
    if (
        document["schema_version"] != "dynamic-cssc-day2-raw-block-probe-v1"
        or document["status"] != "measured-openfhe"
        or document["noise_budget_profile"] != "day2_mult_only"
        or document["evidence_scope"] != "isolated-unit-probe-only"
        or document["mixed_workload_formal_parameter_claim_allowed"] is not False
        or document["publication_raw_block_contract_satisfied"] is not True
        or document["all_profiles_correct"] is not True
        or document["eval_mult_includes_relinearization"] is not True
        or document["required_exact_rotation_indices"] != expected_indices
        or document["measured_rotation_index"] != expected_indices[0]
        or document["rotation_key_bytes"] != rotation_key_bytes
        or document["eval_mult_key_bytes"] != eval_mult_key_bytes
    ):
        raise Day2CalibrationProducerError("formal probe identity does not match its profile")
    for field in (
        "ciphertext_bytes",
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
    ):
        if type(document[field]) is not int or document[field] <= 0:
            raise Day2CalibrationProducerError(
                f"formal probe {field} size is invalid"
            )
    raw = document["raw_measurement_blocks"]
    if type(raw) is not dict:
        raise Day2CalibrationProducerError("formal probe raw blocks are absent")
    if (
        raw.get("primitive_names") != list(PRIMITIVE_NAMES)
        or raw.get("warmup_block_count") != CALIBRATION_WARMUP_BLOCK_COUNT
        or raw.get("measurement_block_count") != CALIBRATION_MEASUREMENT_BLOCK_COUNT
        or raw.get("measurement_stop_rule") != CALIBRATION_MEASUREMENT_STOP_RULE
        or raw.get("operation_order_seed") != CALIBRATION_OPERATION_ORDER_SEED
        or raw.get("operation_order_method") != CALIBRATION_OPERATION_ORDER_METHOD
        or type(raw.get("warmup_blocks")) is not list
        or len(raw["warmup_blocks"]) != CALIBRATION_WARMUP_BLOCK_COUNT
        or type(raw.get("blocks")) is not list
        or len(raw["blocks"]) != CALIBRATION_MEASUREMENT_BLOCK_COUNT
    ):
        raise Day2CalibrationProducerError("formal probe block contract is incomplete")
    return (
        raw,
        document["ciphertext_bytes"],
        document["f1m_random_zero_sum_ciphertext_bytes"],
        document["f1m_encrypted_zero_dummy_ciphertext_bytes"],
    )


def _decode_probe(path: Path) -> dict[str, object]:
    content = _read_regular(path, field="formal probe output", maximum_bytes=_MAX_JSON_BYTES)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise Day2CalibrationProducerError(
                    "formal probe output contains a duplicate JSON key"
                )
            value[key] = item
        return value

    try:
        document = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationProducerError("formal probe output is not JSON") from error
    if type(document) is not dict:
        raise Day2CalibrationProducerError("formal probe output must be an object")
    return document


def _run_formal_probe(
    *,
    repository_root: Path,
    execution_root: Path,
    probe_binary: Path,
    rotation_key_plan: dict[str, object],
    openfhe_build: dict[str, object],
    environment: dict[str, str],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    if not hasattr(os, "sched_getaffinity"):
        raise Day2CalibrationProducerError("formal calibration requires Linux CPU affinity")
    available = sorted(os.sched_getaffinity(0))
    if len(available) < 2:
        raise Day2CalibrationProducerError("formal calibration requires at least two CPUs")
    effective_cpus = available[:2]
    thermal_before = _thermal_throttle_count(effective_cpus)
    probe_output = execution_root / "formal-probe-output.json"
    rotation_keys_path = execution_root / "serialized-rotation-evaluation-keys.bin"
    eval_mult_keys_path = execution_root / "serialized-multiplication-evaluation-keys.bin"
    params = json.loads(
        (repository_root / "config/params_manifest.json").read_text(encoding="utf-8")
    )
    if type(params) is not dict or type(params.get("openfhe")) is not dict:
        raise Day2CalibrationProducerError("publication OpenFHE parameters are unavailable")
    openfhe = params["openfhe"]
    depth_profiles = openfhe.get("noise_budget_profiles")
    if type(depth_profiles) is not dict or type(depth_profiles.get("day2_mult_only")) is not dict:
        raise Day2CalibrationProducerError("Day 2 multiplication profile is unavailable")
    depth = depth_profiles["day2_mult_only"].get("multiplicative_depth")
    expected_parameters = (
        openfhe.get("ring_dimension"),
        openfhe.get("plaintext_modulus"),
        openfhe.get("batch_size"),
        depth,
    )
    if expected_parameters != (8192, 65537, 8192, 2):
        raise Day2CalibrationProducerError("formal OpenFHE parameter tuple is not frozen")
    indices = rotation_key_plan["required_exact_indices"]
    indices_text = ",".join(str(index) for index in indices)
    taskset = shutil.which("taskset", path=environment["PATH"])
    if taskset is None:
        raise Day2CalibrationProducerError("taskset is unavailable")
    probe_environment = dict(environment)
    library_paths = [
        execution_root / "openfhe/install/lib",
        execution_root / "openfhe/install/lib64",
    ]
    existing_library_paths = [str(path) for path in library_paths if path.is_dir()]
    if not existing_library_paths:
        raise Day2CalibrationProducerError("OpenFHE installed library directory is unavailable")
    probe_environment.update(
        {
            "LD_LIBRARY_PATH": ":".join(existing_library_paths),
            "OMP_NUM_THREADS": "2",
            "OMP_PLACES": "cores",
            "OMP_PROC_BIND": "close",
        }
    )
    _run(
        (
            taskset,
            "-c",
            ",".join(str(cpu) for cpu in effective_cpus),
            str(probe_binary),
            "--output",
            str(probe_output),
            "--rotation-keys-output",
            str(rotation_keys_path),
            "--eval-mult-key-output",
            str(eval_mult_keys_path),
            "--ring-dim",
            "8192",
            "--plaintext-modulus",
            "65537",
            "--batch-size",
            "8192",
            "--multiplicative-depth",
            "2",
            "--noise-budget-profile",
            "day2_mult_only",
            "--warmups",
            str(CALIBRATION_WARMUP_BLOCK_COUNT),
            "--repetitions",
            str(CALIBRATION_MEASUREMENT_BLOCK_COUNT),
            "--indices",
            indices_text,
        ),
        cwd=execution_root,
        environment=probe_environment,
        field="formal OpenFHE calibration probe",
    )
    thermal_after = _thermal_throttle_count(effective_cpus)
    rotation_keys = _read_regular(
        rotation_keys_path,
        field="serialized rotation evaluation keys",
        maximum_bytes=_MAX_KEY_BYTES,
    )
    eval_mult_keys = _read_regular(
        eval_mult_keys_path,
        field="serialized multiplication evaluation keys",
        maximum_bytes=_MAX_KEY_BYTES,
    )
    probe_document = _decode_probe(probe_output)
    if probe_document.get("process_affinity_cpu_list") != effective_cpus:
        raise Day2CalibrationProducerError("formal probe affinity differs from taskset")
    (
        raw,
        ciphertext_bytes,
        f1m_random_zero_sum_ciphertext_bytes,
        f1m_encrypted_zero_dummy_ciphertext_bytes,
    ) = _extract_formal_probe(
        document=probe_document,
        rotation_key_plan=rotation_key_plan,
        rotation_key_bytes=len(rotation_keys),
        eval_mult_key_bytes=len(eval_mult_keys),
    )
    generated = _generated_key_inventory(
        rotation_key_plan=rotation_key_plan,
        rotation_key_plan_sha256=_sha256(_canonical_json_bytes(rotation_key_plan)),
        serialized_rotation_keys=rotation_keys,
        serialized_eval_mult_keys=eval_mult_keys,
    )
    serialized_size_profile = _serialized_object_size_profile(
        ciphertext_bytes=ciphertext_bytes,
        f1m_random_zero_sum_ciphertext_bytes=(
            f1m_random_zero_sum_ciphertext_bytes
        ),
        f1m_encrypted_zero_dummy_ciphertext_bytes=(
            f1m_encrypted_zero_dummy_ciphertext_bytes
        ),
        generated_key_inventory=generated,
    )
    host = _host_profile(
        openfhe_build=openfhe_build,
        effective_cpus=effective_cpus,
        thermal_before=thermal_before,
        thermal_after=thermal_after,
        environment=environment,
    )
    return raw, generated, serialized_size_profile, host


def _render_archive(
    *,
    output_archive: Path,
    payloads: dict[str, dict[str, object]],
) -> tuple[bytes, dict[str, bytes]]:
    if set(payloads) != set(_PAYLOAD_FILENAMES):
        raise Day2CalibrationProducerError("formal archive payload set is not closed")
    encoded = {name: _canonical_json_bytes(payloads[name]) for name in _PAYLOAD_FILENAMES}
    manifest = {
        "schema_version": "dynamic-cssc-publication-day2-calibration-evidence-v2",
        "evidence_scope": EVIDENCE_SCOPE,
        "files": [
            {"path": name, "sha256": _sha256(encoded[name]), "bytes": len(encoded[name])}
            for name in _PAYLOAD_FILENAMES
        ],
    }
    encoded["CALIBRATION-MANIFEST.json"] = _canonical_json_bytes(manifest)
    checksummed = sorted((*_PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json"))
    encoded["SHA256SUMS"] = "".join(
        f"{_sha256(encoded[name])}  {name}\n" for name in checksummed
    ).encode("ascii")
    archive_bytes = _canonical_zip_bytes(encoded, member_order=_ARCHIVE_ORDER)
    _write_new_file(output_archive, archive_bytes)
    return archive_bytes, encoded


def _source_provenance(
    *,
    source_git_sha: str,
    source_git_tree: str,
    behavior_inventory: dict[str, object],
) -> dict[str, object]:
    empty_sha = _sha256(b"")
    return {
        "schema_version": "dynamic-cssc-publication-day2-source-provenance-v2",
        "repository": _REPOSITORY,
        "repository_id": _REPOSITORY_ID,
        "git_sha": source_git_sha,
        "git_tree": source_git_tree,
        "git_status_before_sha256": empty_sha,
        "git_status_after_sha256": empty_sha,
        "tracked_tree_clean_before": True,
        "tracked_tree_clean_after": True,
        "untracked_nonignored_clean_before": True,
        "untracked_nonignored_clean_after": True,
        "behavior_inventory": behavior_inventory,
    }


def produce_day2_calibration_archive_from_isolated_worker(
    day1a_directory: Path,
    github_artifact_metadata_path: Path,
    execution_root: Path,
    output_archive: Path,
    runtime_capability: Day2RuntimeIsolationCapability,
) -> None:
    """Produce one exact R3 archive from the already verified live worker."""

    if type(runtime_capability) is not Day2RuntimeIsolationCapability:
        raise Day2CalibrationProducerError("formal producer requires live runtime capability")
    if (
        not isinstance(execution_root, Path)
        or execution_root.is_symlink()
        or not execution_root.is_dir()
    ):
        raise Day2CalibrationProducerError("execution_root must be a regular directory")
    output_archive = output_archive.absolute()
    if output_archive.parent != execution_root.absolute():
        raise Day2CalibrationProducerError("formal archive staging must stay in execution_root")
    if output_archive.exists() or output_archive.is_symlink():
        raise Day2CalibrationProducerError("formal archive staging output must be absent")
    repository_root = Path(__file__).resolve().parents[2]
    if repository_root == execution_root or repository_root in execution_root.parents:
        raise Day2CalibrationProducerError("execution_root must be outside the source checkout")
    environment = dict(os.environ)
    before_sha, before_tree, before_status = _source_identity(
        repository_root,
        environment=environment,
    )
    if before_status:
        raise Day2CalibrationProducerError("source status changed before formal production")
    workflow = _workflow_provenance_from_environment(
        repository_root=repository_root,
        source_git_sha=before_sha,
        environment=environment,
    )
    profiles, rotation_plan, contract, isolation_receipt = _profile_documents(
        day1a_directory=day1a_directory,
        github_artifact_metadata_path=github_artifact_metadata_path,
        execution_root=execution_root,
        runtime_capability=runtime_capability,
    )
    openfhe_build, probe_binary, build_environment = _build_openfhe_and_probe(
        repository_root=repository_root,
        execution_root=execution_root,
        environment=environment,
    )
    raw, generated, serialized_size_profile, host = _run_formal_probe(
        repository_root=repository_root,
        execution_root=execution_root,
        probe_binary=probe_binary,
        rotation_key_plan=rotation_plan,
        openfhe_build=openfhe_build,
        environment=build_environment,
    )
    after_sha, after_tree, after_status = _source_identity(
        repository_root,
        environment=environment,
    )
    if (after_sha, after_tree, after_status) != (before_sha, before_tree, before_status):
        raise Day2CalibrationProducerError("source identity changed during formal production")
    behavior_inventory = capture_behavior_inventory(
        EvidenceRole.DAY2,
        source_git_sha=before_sha,
        repository_root=repository_root,
    )
    source = _source_provenance(
        source_git_sha=before_sha,
        source_git_tree=before_tree,
        behavior_inventory=behavior_inventory,
    )
    raw_bytes = _canonical_json_bytes(raw)
    profiles_bytes = _canonical_json_bytes(profiles)
    rotation_bytes = _canonical_json_bytes(rotation_plan)
    generated_bytes = _canonical_json_bytes(generated)
    serialized_size_profile_bytes = _canonical_json_bytes(serialized_size_profile)
    isolation_bytes = _canonical_json_bytes(isolation_receipt)
    projection_sha256 = _sha256(_canonical_json_bytes(_calibration_projection(raw)))
    producer_validation = {
        "schema_version": "dynamic-cssc-publication-day2-producer-validation-v2",
        "status": "pass",
        "formal_authority_granted": False,
        "validator_source_sha256": openfhe_build["bundle_validator_sha256"],
        "manifest_generator_sha256": openfhe_build["manifest_generator_sha256"],
        "probe_source_sha256": openfhe_build["probe_source_sha256"],
        "probe_binary_sha256": openfhe_build["probe_binary_sha256"],
        "raw_measurement_blocks_sha256": _sha256(raw_bytes),
        "operation_profile_set_sha256": _sha256(profiles_bytes),
        "rotation_key_plan_sha256": _sha256(rotation_bytes),
        "generated_key_inventory_sha256": _sha256(generated_bytes),
        "serialized_object_size_profile_sha256": _sha256(
            serialized_size_profile_bytes
        ),
        "runtime_isolation_receipt_sha256": _sha256(isolation_bytes),
        "calibration_projection_sha256": projection_sha256,
        "candidate_catalog_sha256": contract["candidate_catalog_sha256"],
        "accounting_contract_sha256": contract["primitive_accounting_mapping_sha256"],
        "all_profiles_correct": True,
    }
    payloads = {
        "RUN_STATUS.json": {
            "schema_version": "dynamic-cssc-publication-day2-run-status-v1",
            "status": "pass",
            "evidence_scope": EVIDENCE_SCOPE,
            "producer_validation_passed": True,
            "formal_authority_granted": False,
            "complete_cost_claim_allowed": False,
            "mixed_circuit_parameter_claim_allowed": False,
            "r4_claim_allowed": False,
            "security_claim_allowed": False,
        },
        "source-provenance.json": source,
        "workflow-provenance.json": workflow,
        "host-profile.json": host,
        "openfhe-build.json": openfhe_build,
        "contract-bindings.json": contract,
        "rotation-key-plan.json": rotation_plan,
        "generated-key-inventory.json": generated,
        "serialized-object-size-profile.json": serialized_size_profile,
        "operation-profile-set.json": profiles,
        "raw-measurement-blocks.json": raw,
        "runtime-isolation-receipt.json": isolation_receipt,
        "producer-validation.json": producer_validation,
    }
    archive_bytes, _members = _render_archive(
        output_archive=output_archive,
        payloads=payloads,
    )
    outer_sha256 = _sha256(archive_bytes)
    github_metadata = {
        **workflow,
        "schema_version": "dynamic-cssc-publication-day2-github-artifact-metadata-v2",
        "artifact_id": 1,
        # The hosted artifact service wraps this evidence ZIP.  Its provider
        # digest therefore has a distinct identity from the inner archive.
        "artifact_digest": f"sha256:{_sha256(b'internal-provider-wrapper')}",
        "inner_archive_sha256": outer_sha256,
    }
    inspection = inspect_day2_calibration_archive(
        output_archive,
        expected_outer_sha256=outer_sha256,
        github_metadata=github_metadata,
    )
    if (
        inspection.source_git_sha != before_sha
        or inspection.outer_archive_sha256 != outer_sha256
        or inspection.operation_profile_set_sha256 != _sha256(profiles_bytes)
        or inspection.rotation_key_plan_sha256 != _sha256(rotation_bytes)
        or inspection.generated_key_inventory_sha256 != _sha256(generated_bytes)
        or inspection.serialized_object_size_profile_sha256
        != _sha256(serialized_size_profile_bytes)
        or inspection.ciphertext_bytes != serialized_size_profile["ciphertext_bytes"]
        or inspection.f1m_random_zero_sum_ciphertext_bytes
        != serialized_size_profile["f1m_random_zero_sum_ciphertext_bytes"]
        or inspection.f1m_encrypted_zero_dummy_ciphertext_bytes
        != serialized_size_profile["f1m_encrypted_zero_dummy_ciphertext_bytes"]
        or inspection.runtime_isolation_receipt_sha256 != _sha256(isolation_bytes)
    ):
        raise Day2CalibrationProducerError("formal archive inspection identity changed")
