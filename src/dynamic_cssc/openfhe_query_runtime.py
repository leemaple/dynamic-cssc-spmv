"""Controller-owned launcher for one authorized generic OpenFHE query.

This module closes the seam between the canonical ordinary/strong lifecycles
and the generic C++ OpenFHE runner.  It owns an exclusive scratch tree, consumes
the prepared F1-M batch immediately before launch, observes the child process,
verifies every result/object byte, and removes all private runtime material.

The receipt is deliberately pre-admission evidence.  Resource-policy and
publication authority remain outside this module and are always false here.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import resource
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeAlias

from dynamic_cssc.day2_openfhe_key_plan import (
    ClaimedDay2OpenFHEKeyPlan,
    Day2OpenFHEKeyPlanCapability,
    Day2OpenFHEKeyPlanReceipt,
    claim_day2_openfhe_key_plan,
)
from dynamic_cssc.mask_ledger import PreparedF1MCommitmentLedger
from dynamic_cssc.openfhe_query_runner import (
    OpenFHEKeyGenerationPlan,
    OpenFHESerializedObjectReceipt,
    VerifiedOpenFHEQueryResult,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
    verify_ordinary_openfhe_query_result,
    verify_strong_openfhe_query_result,
)
from dynamic_cssc.openfhe_runtime_admission import (
    AdmittedExecutableFile,
    OpenFHERuntimeAdmissionError,
    OpenFHERuntimeMappingAdmission,
    admit_linux_runtime_mapping_continuity,
    capture_linux_process_mapping_snapshot,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionAuthorizationReceipt,
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    authorize_ordinary_execution,
    claim_ordinary_execution,
)
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
)
from dynamic_cssc.strong_execution import (
    PreparedStrongQuery,
    StrongExecutionAuthorizationReceipt,
    StrongExecutionBundle,
    authorize_strong_execution,
    claim_strong_execution,
)

OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA = "dynamic-cssc-full-openfhe-runtime-receipt-v7"
OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA = "dynamic-cssc-openfhe-runner-build-identity-v3"
OPENFHE_WORKER_BUILD_RECEIPT_SCHEMA = "dynamic-cssc-openfhe-worker-build-receipt-v1"
OPENFHE_WORKER_RUNTIME_IDENTITY_SCHEMA = (
    "dynamic-cssc-openfhe-worker-runtime-identity-v1"
)
OPENFHE_SERIALIZED_PAYLOAD_SCHEMA = "dynamic-cssc-openfhe-serialized-payload-v2"
OPENFHE_RUNTIME_CONTROL_PROTOCOL_SCHEMA = "dynamic-cssc-openfhe-runtime-control-v1"
OPENFHE_WORKER_RUNTIME_MAPPING_POLICY = "linux-ready-done-executable-closure-v1"
OPENFHE_DYNAMIC_LOADER_ENVIRONMENT_POLICY = "clear-v1"
OPENFHE_CPU_AFFINITY_POLICY = "linux-controller-affinity-exact-match-v1"

_LINUX_DISTRIBUTION_LIBRARY_ROOTS = tuple(
    Path(value)
    for value in (
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/usr/lib",
        "/usr/lib32",
        "/usr/lib64",
        "/usr/libx32",
    )
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_PATHS = (
    "config/params_manifest.json",
    "cpp/CMakeLists.txt",
    "cpp/openfhe_query_runner.cpp",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
)
_CMAKE_CACHE_KEYS = (
    "CMAKE_BUILD_TYPE",
    "CMAKE_COMMAND",
    "CMAKE_CXX_COMPILER",
    "CMAKE_CXX_FLAGS",
    "CMAKE_CXX_FLAGS_RELEASE",
    "CMAKE_GENERATOR",
    "CMAKE_HOME_DIRECTORY",
    "OpenFHE_DIR",
)
_FIXED_TARGET_FLAGS = ("-std=c++17", "-Wall", "-Wextra", "-Wpedantic")
_LOG_BYTES_MAXIMUM = 1024 * 1024
_LINKED_LIBRARY_BYTES_MAXIMUM = 512 * 1024 * 1024
_OBSERVATION_INTERVAL_SECONDS = 0.01
_CONTROL_RECORDS = {
    "READY": (b"D1BRDY01", b"D1BGO001"),
    "DONE": (b"D1BDON01", b"D1BGO002"),
}


class OpenFHEQueryRuntimeError(RuntimeError):
    """The runner identity, process observation, or private cleanup failed closed."""


OpenFHEExecutionAuthorizationReceipt: TypeAlias = (
    OrdinaryExecutionAuthorizationReceipt | StrongExecutionAuthorizationReceipt
)


@dataclass(frozen=True, slots=True)
class OpenFHELinkedLibraryIdentity:
    load_name: str
    resolved_path: str
    byte_count: int
    sha256: str
    device: int
    inode: int
    mode: int
    binary_format: str
    binary_id: str
    soname: str | None
    needed_load_names: tuple[str, ...]

    def to_document(self) -> dict[str, object]:
        return {
            "binary_format": self.binary_format,
            "binary_id": self.binary_id,
            "byte_count": self.byte_count,
            "device": self.device,
            "inode": self.inode,
            "load_name": self.load_name,
            "mode": self.mode,
            "needed_load_names": list(self.needed_load_names),
            "resolved_path": self.resolved_path,
            "sha256": self.sha256,
            "soname": self.soname,
        }


@dataclass(frozen=True, slots=True)
class OpenFHEBuildProvenance:
    cmake_path: str
    cmake_sha256: str
    cmake_byte_count: int
    cmake_version: str
    cmake_identity_sha256: str
    cmake_cache_sha256: str
    compile_commands_sha256: str
    build_ninja_sha256: str
    rules_ninja_sha256: str
    openfhe_directory: str
    openfhe_config_sha256: str
    openfhe_repository: str
    openfhe_version: str
    openfhe_package_version: str
    openfhe_source_cmake_sha256: str
    openfhe_source_commit: str
    openfhe_source_tree: str
    openfhe_source_clean: bool
    openfhe_cmake_cache_sha256: str
    openfhe_compile_commands_sha256: str
    openfhe_install_manifest_sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "build_ninja_sha256": self.build_ninja_sha256,
            "cmake_byte_count": self.cmake_byte_count,
            "cmake_cache_sha256": self.cmake_cache_sha256,
            "cmake_identity_sha256": self.cmake_identity_sha256,
            "cmake_path": self.cmake_path,
            "cmake_sha256": self.cmake_sha256,
            "cmake_version": self.cmake_version,
            "compile_commands_sha256": self.compile_commands_sha256,
            "openfhe_cmake_cache_sha256": self.openfhe_cmake_cache_sha256,
            "openfhe_compile_commands_sha256": self.openfhe_compile_commands_sha256,
            "openfhe_config_sha256": self.openfhe_config_sha256,
            "openfhe_directory": self.openfhe_directory,
            "openfhe_install_manifest_sha256": self.openfhe_install_manifest_sha256,
            "openfhe_repository": self.openfhe_repository,
            "openfhe_package_version": self.openfhe_package_version,
            "openfhe_source_clean": self.openfhe_source_clean,
            "openfhe_source_cmake_sha256": self.openfhe_source_cmake_sha256,
            "openfhe_source_commit": self.openfhe_source_commit,
            "openfhe_source_tree": self.openfhe_source_tree,
            "openfhe_version": self.openfhe_version,
            "rules_ninja_sha256": self.rules_ninja_sha256,
        }


@dataclass(frozen=True, slots=True)
class OpenFHERunnerBuildIdentity:
    runner_relative_path: str
    runner_sha256: str
    runner_byte_count: int
    runner_device: int
    runner_inode: int
    runner_mode: int
    runner_binary_format: str
    runner_binary_id: str
    runner_needed_load_names: tuple[str, ...]
    source_sha256: tuple[tuple[str, str], ...]
    compiler_path: str
    compiler_sha256: str
    compiler_byte_count: int
    compiler_identity_sha256: str
    compiler_version: str
    compiler_target: str
    compiler_flags: tuple[str, ...]
    build_provenance: OpenFHEBuildProvenance
    linkage_inspection_format: str
    linked_libraries: tuple[OpenFHELinkedLibraryIdentity, ...]
    linked_system_library_load_names: tuple[str, ...]
    build_identity_sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "build_identity_sha256": self.build_identity_sha256,
            "build_provenance": self.build_provenance.to_document(),
            "compiler_byte_count": self.compiler_byte_count,
            "compiler_flags": list(self.compiler_flags),
            "compiler_identity_sha256": self.compiler_identity_sha256,
            "compiler_path": self.compiler_path,
            "compiler_sha256": self.compiler_sha256,
            "compiler_target": self.compiler_target,
            "compiler_version": self.compiler_version,
            "linkage_inspection_format": self.linkage_inspection_format,
            "linked_libraries": [item.to_document() for item in self.linked_libraries],
            "linked_system_library_load_names": list(
                self.linked_system_library_load_names
            ),
            "runner_byte_count": self.runner_byte_count,
            "runner_binary_format": self.runner_binary_format,
            "runner_binary_id": self.runner_binary_id,
            "runner_device": self.runner_device,
            "runner_inode": self.runner_inode,
            "runner_mode": self.runner_mode,
            "runner_needed_load_names": list(self.runner_needed_load_names),
            "runner_relative_path": self.runner_relative_path,
            "runner_sha256": self.runner_sha256,
            "schema_version": OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA,
            "source_sha256": dict(self.source_sha256),
        }


def _openfhe_worker_build_receipt_body(
    identity: OpenFHERunnerBuildIdentity,
) -> dict[str, object]:
    """Project one captured build onto repository-stable content identities."""

    if type(identity) is not OpenFHERunnerBuildIdentity:
        raise TypeError("worker build receipt requires one exact runner build identity")
    provenance = identity.build_provenance
    if type(provenance) is not OpenFHEBuildProvenance:
        raise TypeError("worker build receipt requires exact OpenFHE build provenance")
    if any(
        type(library) is not OpenFHELinkedLibraryIdentity
        for library in identity.linked_libraries
    ):
        raise TypeError("worker build receipt requires exact linked-library identities")
    if (
        identity.runner_binary_format != "elf-v1"
        or identity.linkage_inspection_format
        != "linux-ldd-direct-and-transitive-v2"
        or any(library.binary_format != "elf-v1" for library in identity.linked_libraries)
    ):
        raise OpenFHEQueryRuntimeError(
            "worker build receipt requires one Linux ELF linkage identity"
        )
    source_names = tuple(name for name, _digest in identity.source_sha256)
    library_load_names = tuple(
        library.load_name for library in identity.linked_libraries
    )
    system_load_names = identity.linked_system_library_load_names
    if (
        len(set(source_names)) != len(source_names)
        or len(set(library_load_names)) != len(library_load_names)
        or len(set(system_load_names)) != len(system_load_names)
        or not set(system_load_names).issubset(library_load_names)
    ):
        raise OpenFHEQueryRuntimeError(
            "worker build receipt source/library names are not one closed partition"
        )
    linked_libraries = sorted(
        (
            library
            for library in identity.linked_libraries
            if library.load_name not in system_load_names
        ),
        key=lambda library: (
            library.load_name,
            library.sha256,
            library.binary_id,
        ),
    )
    if not linked_libraries or not any(
        library.load_name.lower().startswith("libopenfhe")
        for library in linked_libraries
    ):
        raise OpenFHEQueryRuntimeError(
            "worker build receipt lacks one content-bound OpenFHE library"
        )
    return {
        "build_provenance": {
            "cmake_byte_count": provenance.cmake_byte_count,
            "cmake_identity_sha256": provenance.cmake_identity_sha256,
            "cmake_sha256": provenance.cmake_sha256,
            "cmake_version": provenance.cmake_version,
            "openfhe_package_version": provenance.openfhe_package_version,
            "openfhe_repository": provenance.openfhe_repository,
            "openfhe_source_clean": provenance.openfhe_source_clean,
            "openfhe_source_cmake_sha256": provenance.openfhe_source_cmake_sha256,
            "openfhe_source_commit": provenance.openfhe_source_commit,
            "openfhe_source_tree": provenance.openfhe_source_tree,
            "openfhe_version": provenance.openfhe_version,
        },
        "compiler": {
            "byte_count": identity.compiler_byte_count,
            "flags": list(identity.compiler_flags),
            "identity_sha256": identity.compiler_identity_sha256,
            "sha256": identity.compiler_sha256,
            "target": identity.compiler_target,
            "version": identity.compiler_version,
        },
        "linkage_inspection_format": identity.linkage_inspection_format,
        "linked_libraries": [
            {
                "binary_format": library.binary_format,
                "binary_id": library.binary_id,
                "byte_count": library.byte_count,
                "load_name": library.load_name,
                "needed_load_names": sorted(library.needed_load_names),
                "sha256": library.sha256,
                "soname": library.soname,
            }
            for library in linked_libraries
        ],
        "linked_system_library_load_names": sorted(
            identity.linked_system_library_load_names
        ),
        "runner": {
            "binary_format": identity.runner_binary_format,
            "binary_id": identity.runner_binary_id,
            "byte_count": identity.runner_byte_count,
            "needed_load_names": sorted(identity.runner_needed_load_names),
            "relative_path": identity.runner_relative_path,
            "sha256": identity.runner_sha256,
        },
        "runner_identity_schema_version": OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA,
        "schema_version": OPENFHE_WORKER_BUILD_RECEIPT_SCHEMA,
        "source_sha256": dict(sorted(identity.source_sha256)),
    }


def openfhe_worker_build_receipt_sha256(
    identity: OpenFHERunnerBuildIdentity,
) -> str:
    """Return the domain-separated stable worker-build root for one capture."""

    return hashlib.sha256(
        _canonical_bytes(_openfhe_worker_build_receipt_body(identity))
    ).hexdigest()


def project_openfhe_worker_build_receipt(
    identity: OpenFHERunnerBuildIdentity,
) -> dict[str, object]:
    """Return a descriptive stable receipt; it grants no execution authority."""

    body = _openfhe_worker_build_receipt_body(identity)
    return {
        **body,
        "worker_build_receipt_sha256": hashlib.sha256(
            _canonical_bytes(body)
        ).hexdigest(),
    }


@dataclass(frozen=True, slots=True)
class OpenFHEWorkerRuntimeIdentityPolicy:
    """Stable controller policy for one admissible OpenFHE worker runtime."""

    worker_adapter_schema_version: str
    worker_build_identity_sha256: str
    operating_system_identity: str
    cpu_affinity_policy_token: str
    required_cpu_affinity: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            type(self.worker_adapter_schema_version) is not str
            or not self.worker_adapter_schema_version
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in self.worker_adapter_schema_version
            )
            or _LOWER_SHA256.fullmatch(self.worker_build_identity_sha256) is None
            or type(self.operating_system_identity) is not str
            or not self.operating_system_identity.startswith("Linux-")
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in self.operating_system_identity
            )
            or self.cpu_affinity_policy_token != OPENFHE_CPU_AFFINITY_POLICY
            or type(self.required_cpu_affinity) is not tuple
            or not self.required_cpu_affinity
            or any(
                type(cpu) is not int or cpu < 0
                for cpu in self.required_cpu_affinity
            )
            or tuple(sorted(set(self.required_cpu_affinity)))
            != self.required_cpu_affinity
        ):
            raise OpenFHEQueryRuntimeError(
                "OpenFHE worker runtime-identity policy is malformed"
            )


def project_expected_openfhe_worker_runtime_identity(
    policy: OpenFHEWorkerRuntimeIdentityPolicy,
) -> dict[str, object]:
    """Project the controller's stable policy without using runtime evidence."""

    if type(policy) is not OpenFHEWorkerRuntimeIdentityPolicy:
        raise TypeError("expected worker runtime identity requires one exact policy")
    return {
        "cpu_affinity_policy": policy.cpu_affinity_policy_token,
        "dynamic_loader_environment_policy": (
            OPENFHE_DYNAMIC_LOADER_ENVIRONMENT_POLICY
        ),
        "openfhe_runtime_receipt_schema_version": (
            OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA
        ),
        "operating_system_identity": policy.operating_system_identity,
        "runtime_control_protocol_schema": OPENFHE_RUNTIME_CONTROL_PROTOCOL_SCHEMA,
        "runtime_mapping_policy": OPENFHE_WORKER_RUNTIME_MAPPING_POLICY,
        "schema_version": OPENFHE_WORKER_RUNTIME_IDENTITY_SCHEMA,
        "worker_adapter_schema_version": policy.worker_adapter_schema_version,
        "worker_build_identity_sha256": policy.worker_build_identity_sha256,
    }


def project_observed_openfhe_worker_runtime_identity(
    policy: OpenFHEWorkerRuntimeIdentityPolicy,
    receipt: OpenFHEQueryRuntimeReceipt,
) -> dict[str, object]:
    """Reconstruct a stable identity from observed receipt facts, fail closed."""

    if type(policy) is not OpenFHEWorkerRuntimeIdentityPolicy:
        raise TypeError("observed worker runtime identity requires one exact policy")
    if type(receipt) is not OpenFHEQueryRuntimeReceipt:
        raise TypeError("observed worker runtime identity requires one exact receipt")
    if type(receipt.runtime_mapping_admission) is not OpenFHERuntimeMappingAdmission:
        raise OpenFHEQueryRuntimeError(
            "OpenFHE worker runtime mapping continuity is absent"
        )
    observed_worker_build_identity_sha256 = openfhe_worker_build_receipt_sha256(
        receipt.runner
    )
    if observed_worker_build_identity_sha256 != policy.worker_build_identity_sha256:
        raise OpenFHEQueryRuntimeError(
            "observed OpenFHE worker build differs from the runtime policy"
        )
    if receipt.operating_system_identity != policy.operating_system_identity:
        raise OpenFHEQueryRuntimeError(
            "observed OpenFHE operating system differs from the runtime policy"
        )
    if receipt.cpu_affinity != policy.required_cpu_affinity:
        raise OpenFHEQueryRuntimeError(
            "observed OpenFHE CPU affinity differs from the runtime policy"
        )
    document = receipt.to_document()
    if (
        document.get("schema_version") != OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA
        or document.get("runtime_control_protocol_schema")
        != OPENFHE_RUNTIME_CONTROL_PROTOCOL_SCHEMA
        or document.get("dynamic_loader_environment_clear") is not True
        or document.get("runtime_state_continuity_verified") is not True
    ):
        raise OpenFHEQueryRuntimeError(
            "observed OpenFHE runtime receipt violates its fixed protocol policy"
        )
    return {
        "cpu_affinity_policy": policy.cpu_affinity_policy_token,
        "dynamic_loader_environment_policy": (
            OPENFHE_DYNAMIC_LOADER_ENVIRONMENT_POLICY
        ),
        "openfhe_runtime_receipt_schema_version": document["schema_version"],
        "operating_system_identity": receipt.operating_system_identity,
        "runtime_control_protocol_schema": document[
            "runtime_control_protocol_schema"
        ],
        "runtime_mapping_policy": OPENFHE_WORKER_RUNTIME_MAPPING_POLICY,
        "schema_version": OPENFHE_WORKER_RUNTIME_IDENTITY_SCHEMA,
        "worker_adapter_schema_version": policy.worker_adapter_schema_version,
        "worker_build_identity_sha256": (
            observed_worker_build_identity_sha256
        ),
    }


@dataclass(frozen=True, slots=True)
class OpenFHESerializedPayload:
    category: str
    subject_id: str
    binary_framing_schema: str | None
    sha256: str
    payload: bytes

    def __post_init__(self) -> None:
        if (
            type(self.category) is not str
            or not self.category
            or type(self.subject_id) is not str
            or not self.subject_id
            or (
                self.binary_framing_schema
                != (
                    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA
                    if self.category == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
                    else None
                )
            )
            or _LOWER_SHA256.fullmatch(self.sha256) is None
            or type(self.payload) is not bytes
            or not self.payload
            or hashlib.sha256(self.payload).hexdigest() != self.sha256
        ):
            raise OpenFHEQueryRuntimeError("serialized OpenFHE payload binding is invalid")

    def receipt_document(self) -> dict[str, object]:
        return {
            "binary_framing_schema": self.binary_framing_schema,
            "byte_count": len(self.payload),
            "category": self.category,
            "schema_version": OPENFHE_SERIALIZED_PAYLOAD_SCHEMA,
            "sha256": self.sha256,
            "subject_id": self.subject_id,
        }


@dataclass(frozen=True, slots=True)
class OpenFHEQueryRuntimeReceipt:
    runner: OpenFHERunnerBuildIdentity
    execution_kind: str
    authorization: OpenFHEExecutionAuthorizationReceipt
    day2_key_plan_authorization: Day2OpenFHEKeyPlanReceipt | None
    request_sha256: str
    request_byte_count: int
    result_sha256: str
    result_byte_count: int
    elapsed_ns: int
    timeout_seconds: int
    peak_resident_memory_bytes: int
    resident_memory_limit_bytes: int
    peak_scratch_bytes: int
    scratch_limit_bytes: int
    stdout_sha256: str
    stdout_byte_count: int
    stderr_sha256: str
    stderr_byte_count: int
    serialized_object_count: int
    serialized_object_bytes: int
    host_identity_sha256: str
    operating_system_identity: str
    cpu_affinity: tuple[int, ...] | None
    runtime_mapping_admission: OpenFHERuntimeMappingAdmission | None

    def to_document(self) -> dict[str, object]:
        expected_authorization_type = {
            "ordinary": OrdinaryExecutionAuthorizationReceipt,
            "strong": StrongExecutionAuthorizationReceipt,
        }.get(self.execution_kind)
        if type(self.authorization) is not expected_authorization_type:
            raise OpenFHEQueryRuntimeError(
                "runtime execution kind differs from its lifecycle authorization"
            )
        if self.day2_key_plan_authorization is not None and (
            type(self.day2_key_plan_authorization)
            is not Day2OpenFHEKeyPlanReceipt
        ):
            raise OpenFHEQueryRuntimeError(
                "runtime Day 2 key-plan authorization is not exact"
            )
        return {
            "anchored_day2_key_plan_verified": (
                self.day2_key_plan_authorization is not None
            ),
            "authorization": self.authorization.to_document(),
            "cpu_affinity": None if self.cpu_affinity is None else list(self.cpu_affinity),
            "elapsed_ns": self.elapsed_ns,
            "formal_authority_granted": False,
            "host_identity_sha256": self.host_identity_sha256,
            "operating_system_identity": self.operating_system_identity,
            "peak_resident_memory_bytes": self.peak_resident_memory_bytes,
            "peak_scratch_bytes": self.peak_scratch_bytes,
            "publication_authority": False,
            "request_byte_count": self.request_byte_count,
            "request_sha256": self.request_sha256,
            "resident_memory_limit_bytes": self.resident_memory_limit_bytes,
            "result_byte_count": self.result_byte_count,
            "result_sha256": self.result_sha256,
            "runner": self.runner.to_document(),
            "runtime_control_protocol_schema": OPENFHE_RUNTIME_CONTROL_PROTOCOL_SCHEMA,
            "runtime_mapping_admission": (
                None
                if self.runtime_mapping_admission is None
                else self.runtime_mapping_admission.to_document()
            ),
            "runtime_state_continuity_verified": (
                self.runtime_mapping_admission is not None
            ),
            "day2_key_plan_authorization": (
                None
                if self.day2_key_plan_authorization is None
                else self.day2_key_plan_authorization.to_document()
            ),
            "dynamic_loader_environment_clear": True,
            "execution_kind": self.execution_kind,
            "schema_version": OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA,
            "scratch_limit_bytes": self.scratch_limit_bytes,
            "serialized_object_bytes": self.serialized_object_bytes,
            "serialized_object_count": self.serialized_object_count,
            "status": "verified-pre-admission-only",
            "stderr_byte_count": self.stderr_byte_count,
            "stderr_sha256": self.stderr_sha256,
            "stdout_byte_count": self.stdout_byte_count,
            "stdout_sha256": self.stdout_sha256,
            "timeout_seconds": self.timeout_seconds,
        }

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.to_document())).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutedOpenFHEQuery:
    verified_result: VerifiedOpenFHEQueryResult
    runtime_receipt: OpenFHEQueryRuntimeReceipt
    serialized_payloads: tuple[OpenFHESerializedPayload, ...]


@dataclass(frozen=True, slots=True)
class _ProcessObservation:
    elapsed_ns: int
    peak_resident_memory_bytes: int
    peak_scratch_bytes: int
    stdout: bytes
    stderr: bytes
    runtime_mapping_admission: OpenFHERuntimeMappingAdmission | None


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise OpenFHEQueryRuntimeError("runtime receipt is not canonical JSON") from error


def _absolute_path(value: object, *, field: str) -> Path:
    if (
        not isinstance(value, Path)
        or not value.is_absolute()
        or ".." in value.parts
        or Path(os.path.normpath(value)) != value
    ):
        raise OpenFHEQueryRuntimeError(f"{field} must be one normalized absolute Path")
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
            raise OpenFHEQueryRuntimeError(f"runtime path component is absent: {current}") from None
        except OSError as error:
            raise OpenFHEQueryRuntimeError(
                f"runtime path component cannot be inspected: {current}"
            ) from error
        if stat.S_ISLNK(mode):
            raise OpenFHEQueryRuntimeError(f"runtime symlink component is forbidden: {current}")


def _read_direct_file(
    path: Path,
    *,
    field: str,
    maximum: int = 256 * 1024 * 1024,
    allow_empty: bool = False,
) -> bytes:
    _reject_symlink_components(path, missing_leaf_allowed=False)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} cannot be opened directly") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > maximum
        ):
            raise OpenFHEQueryRuntimeError(f"{field} is outside its regular-file bounds")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not chunk:
                raise OpenFHEQueryRuntimeError(f"{field} ended before its observed size")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise OpenFHEQueryRuntimeError(f"{field} grew while reading")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise OpenFHEQueryRuntimeError(f"{field} changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _parse_cmake_cache(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError("CMake cache is not UTF-8") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line or ":" not in line:
            continue
        name_and_type, value = line.split("=", 1)
        name, _cache_type = name_and_type.split(":", 1)
        if name in _CMAKE_CACHE_KEYS:
            values[name] = value
    if set(values) != set(_CMAKE_CACHE_KEYS) or values["CMAKE_BUILD_TYPE"] != "Release":
        raise OpenFHEQueryRuntimeError("runner CMake cache lacks the exact Release identity")
    return values


def _stable_status_tuple(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_file_content(
    path: Path,
    *,
    field: str,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} identity cannot be inspected") from error
    content = _read_direct_file(path, field=field, maximum=maximum)
    try:
        after = path.lstat()
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} identity cannot be re-inspected") from error
    if _stable_status_tuple(before) != _stable_status_tuple(after):
        raise OpenFHEQueryRuntimeError(f"{field} identity changed while hashing")
    return content, after


def _compiler_identity(
    compiler: Path,
) -> tuple[str, bytes, bytes, str, str]:
    compiler = _absolute_path(compiler, field="CMake C++ compiler")
    try:
        compiler = compiler.resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError("C++ compiler path cannot be resolved") from error
    _reject_symlink_components(compiler, missing_leaf_allowed=False)
    content, status = _stable_file_content(
        compiler,
        field="C++ compiler",
        maximum=256 * 1024 * 1024,
    )

    def probe(argument: str, field: str) -> bytes:
        try:
            completed = subprocess.run(
                (str(compiler), argument),
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise OpenFHEQueryRuntimeError(f"C++ compiler {field} probe failed") from error
        identity = completed.stdout + completed.stderr
        if completed.returncode != 0 or not identity or len(identity) > _LOG_BYTES_MAXIMUM:
            raise OpenFHEQueryRuntimeError(f"C++ compiler {field} probe is not exact")
        return identity

    identity = probe("--version", "version")
    target_bytes = probe("-dumpmachine", "target")
    try:
        after = compiler.lstat()
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "C++ compiler changed after identity probes"
        ) from error
    if _stable_status_tuple(after) != _stable_status_tuple(status):
        raise OpenFHEQueryRuntimeError("C++ compiler changed during identity probes")
    try:
        version = identity.decode("utf-8").splitlines()[0]
        target = target_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError("C++ compiler identity is not UTF-8") from error
    if not version or not target or "\n" in target or "\r" in target:
        raise OpenFHEQueryRuntimeError("C++ compiler version/target identity is malformed")
    return str(compiler), identity, content, version, target


def _linkage_tool_output(arguments: tuple[str, ...], *, field: str) -> str:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpenFHEQueryRuntimeError(f"{field} probe failed") from error
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or not output or len(output) > _LOG_BYTES_MAXIMUM:
        raise OpenFHEQueryRuntimeError(f"{field} probe is not exact")
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError(f"{field} probe is not UTF-8") from error


def _binary_metadata(
    path: Path,
    *,
    expected_status: os.stat_result,
) -> tuple[str, str, str | None, tuple[str, ...]]:
    system = platform.system()
    if system == "Linux":
        readelf = shutil.which("readelf", path="/usr/bin:/bin")
        if readelf is None:
            raise OpenFHEQueryRuntimeError("readelf is unavailable")
        notes = _linkage_tool_output(
            (readelf, "-n", str(path)),
            field=f"binary notes {path.name}",
        )
        dynamic = _linkage_tool_output(
            (readelf, "-d", str(path)),
            field=f"binary dynamic section {path.name}",
        )
        build_ids = tuple(
            item.lower() for item in re.findall(r"Build ID:\s*([0-9A-Fa-f]+)", notes)
        )
        if len(build_ids) != 1:
            raise OpenFHEQueryRuntimeError("ELF binary does not have one exact build ID")
        sonames = tuple(re.findall(r"\(SONAME\).*\[([^]]+)\]", dynamic))
        if len(sonames) > 1:
            raise OpenFHEQueryRuntimeError("ELF binary has multiple SONAME values")
        needed = tuple(sorted(set(re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic))))
        binary_format = "elf-v1"
        binary_id = build_ids[0]
        soname = sonames[0] if sonames else None
    elif system == "Darwin":
        dwarfdump = shutil.which("dwarfdump", path="/usr/bin:/bin")
        otool = shutil.which("otool", path="/usr/bin:/bin")
        if dwarfdump is None or otool is None:
            raise OpenFHEQueryRuntimeError("Darwin binary identity tools are unavailable")
        uuid_output = _linkage_tool_output(
            (dwarfdump, "--uuid", str(path)),
            field=f"Mach-O UUID {path.name}",
        )
        uuids = tuple(
            item.replace("-", "").lower()
            for item in re.findall(r"UUID:\s*([0-9A-Fa-f-]{36})", uuid_output)
        )
        if len(uuids) != 1 or len(uuids[0]) != 32:
            raise OpenFHEQueryRuntimeError("Mach-O binary does not have one exact UUID")
        linked_output = _linkage_tool_output(
            (otool, "-L", str(path)),
            field=f"Mach-O dependencies {path.name}",
        )
        linked_lines = tuple(
            line.strip() for line in linked_output.splitlines() if line.strip()
        )
        if not linked_lines or not linked_lines[0].endswith(":"):
            raise OpenFHEQueryRuntimeError("Mach-O dependency identity is malformed")
        needed = tuple(
            sorted(
                {
                    line.split(" (compatibility version ", 1)[0].strip()
                    for line in linked_lines[1:]
                }
            )
        )
        id_output = _linkage_tool_output(
            (otool, "-D", str(path)),
            field=f"Mach-O install name {path.name}",
        )
        id_lines = tuple(line.strip() for line in id_output.splitlines() if line.strip())
        if not id_lines or not id_lines[0].endswith(":") or len(id_lines) > 2:
            raise OpenFHEQueryRuntimeError("Mach-O install-name identity is malformed")
        binary_format = "mach-o-v1"
        binary_id = uuids[0]
        soname = id_lines[1] if len(id_lines) == 2 else None
        if soname is not None:
            needed = tuple(item for item in needed if item != soname)
    else:
        raise OpenFHEQueryRuntimeError("binary identity OS is unsupported")
    try:
        after = path.lstat()
    except OSError as error:
        raise OpenFHEQueryRuntimeError("binary changed after identity inspection") from error
    if _stable_status_tuple(after) != _stable_status_tuple(expected_status):
        raise OpenFHEQueryRuntimeError("binary changed during identity inspection")
    return binary_format, binary_id, soname, needed


def _resolved_linked_path(value: str, *, field: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise OpenFHEQueryRuntimeError(f"{field} is not an absolute resolved path")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(f"{field} cannot be resolved") from error
    _reject_symlink_components(resolved, missing_leaf_allowed=False)
    if not resolved.is_file():
        raise OpenFHEQueryRuntimeError(f"{field} is not a regular file")
    return resolved


def _is_linux_distribution_library_path(path: Path) -> bool:
    """Return whether one resolved path is under a closed distribution lib root."""

    return any(path.is_relative_to(root) for root in _LINUX_DISTRIBUTION_LIBRARY_ROOTS)


def _linux_linked_library_paths(
    runner: Path,
    *,
    pinned_install_root: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    try:
        install_root = pinned_install_root.resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "pinned OpenFHE install root cannot be resolved"
        ) from error
    if (
        not install_root.is_dir()
        or _is_linux_distribution_library_path(install_root)
        or any(
            root.is_relative_to(install_root)
            for root in _LINUX_DISTRIBUTION_LIBRARY_ROOTS
        )
    ):
        raise OpenFHEQueryRuntimeError(
            "pinned OpenFHE install root overlaps the Linux distribution roots"
        )
    executable = shutil.which("ldd", path="/usr/bin:/bin")
    if executable is None:
        raise OpenFHEQueryRuntimeError("ldd is unavailable")
    output = _linkage_tool_output((executable, str(runner)), field="runner ldd identity")
    entries_by_load_name: dict[str, Path] = {}
    system_load_names: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "not found" in line:
            raise OpenFHEQueryRuntimeError("runner has an unresolved linked library")
        without_address = re.sub(r"\s+\([^)]*\)\s*$", "", line)
        if "=>" in without_address:
            load_name, target = (item.strip() for item in without_address.split("=>", 1))
            if not load_name or not target:
                raise OpenFHEQueryRuntimeError("runner ldd identity is malformed")
        elif without_address.startswith("/"):
            target = without_address
            load_name = Path(target).name
        elif without_address.startswith("linux-vdso"):
            continue
        else:
            raise OpenFHEQueryRuntimeError("runner ldd identity contains an unknown row")
        resolved = _resolved_linked_path(
            target,
            field=f"linked library {load_name}",
        )
        if load_name in entries_by_load_name:
            raise OpenFHEQueryRuntimeError(
                "runner ldd identity repeats one linked-library load name"
            )
        under_install_root = resolved.is_relative_to(install_root)
        under_distribution_root = _is_linux_distribution_library_path(resolved)
        is_openfhe = load_name.lower().startswith("libopenfhe")
        if under_install_root:
            pass
        elif under_distribution_root:
            if is_openfhe:
                raise OpenFHEQueryRuntimeError(
                    "OpenFHE library resolved through a Linux distribution root"
                )
            system_load_names.add(load_name)
        else:
            raise OpenFHEQueryRuntimeError(
                "linked library is outside the pinned OpenFHE and distribution roots"
            )
        entries_by_load_name[load_name] = resolved
    result = tuple(sorted(entries_by_load_name.items()))
    if not result:
        raise OpenFHEQueryRuntimeError(
            "runner non-system linked-library inventory is empty"
        )
    return (
        "linux-ldd-direct-and-transitive-v2",
        result,
        tuple(sorted(system_load_names)),
    )


def _darwin_rpaths(otool: str, runner: Path) -> tuple[Path, ...]:
    output = _linkage_tool_output(
        (otool, "-l", str(runner)),
        field="runner LC_RPATH identity",
    )
    raw_paths: list[str] = []
    awaiting_path = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "cmd LC_RPATH":
            awaiting_path = True
            continue
        if awaiting_path and line.startswith("path "):
            raw_paths.append(line[5:].split(" (offset ", 1)[0])
            awaiting_path = False
    resolved: list[Path] = []
    for value in raw_paths:
        expanded = value.replace("@loader_path", str(runner.parent)).replace(
            "@executable_path", str(runner.parent)
        )
        candidate = Path(expanded)
        if not candidate.is_absolute():
            raise OpenFHEQueryRuntimeError("runner LC_RPATH is not absolute after expansion")
        try:
            directory = candidate.resolve(strict=True)
        except OSError as error:
            raise OpenFHEQueryRuntimeError("runner LC_RPATH cannot be resolved") from error
        if not directory.is_dir():
            raise OpenFHEQueryRuntimeError("runner LC_RPATH is not a directory")
        resolved.append(directory)
    return tuple(sorted(set(resolved), key=str))


def _darwin_linked_library_paths(
    runner: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    executable = shutil.which("otool", path="/usr/bin:/bin")
    if executable is None:
        raise OpenFHEQueryRuntimeError("otool is unavailable")
    output = _linkage_tool_output(
        (executable, "-L", str(runner)),
        field="runner otool identity",
    )
    rpaths = _darwin_rpaths(executable, runner)
    entries: list[tuple[str, Path]] = []
    system_load_names: list[str] = []
    lines = tuple(line.strip() for line in output.splitlines() if line.strip())
    if not lines or not lines[0].endswith(":"):
        raise OpenFHEQueryRuntimeError("runner otool identity is malformed")
    for line in lines[1:]:
        load_name = line.split(" (compatibility version ", 1)[0].strip()
        candidates: tuple[Path, ...]
        if load_name.startswith("@rpath/"):
            suffix = load_name.removeprefix("@rpath/")
            candidates = tuple(directory / suffix for directory in rpaths)
        elif load_name.startswith("@loader_path/"):
            candidates = (runner.parent / load_name.removeprefix("@loader_path/"),)
        elif load_name.startswith("@executable_path/"):
            candidates = (runner.parent / load_name.removeprefix("@executable_path/"),)
        else:
            candidates = (Path(load_name),)
        existing = tuple(candidate for candidate in candidates if candidate.exists())
        if not existing:
            if load_name.startswith(("/usr/lib/", "/System/Library/")):
                system_load_names.append(load_name)
                continue
            raise OpenFHEQueryRuntimeError(
                f"linked library {load_name} cannot be resolved through LC_RPATH"
            )
        if len(existing) != 1:
            raise OpenFHEQueryRuntimeError(
                f"linked library {load_name} resolves to multiple physical files"
            )
        entries.append(
            (
                load_name,
                _resolved_linked_path(str(existing[0]), field=f"linked library {load_name}"),
            )
        )
    result = tuple(sorted(set(entries), key=lambda item: (item[0], str(item[1]))))
    if not result:
        raise OpenFHEQueryRuntimeError("runner file-backed linked-library inventory is empty")
    return (
        "darwin-otool-direct-v1",
        result,
        tuple(sorted(set(system_load_names))),
    )


def _inspect_linked_library_paths(
    runner: Path,
    *,
    pinned_install_root: Path,
) -> tuple[str, tuple[tuple[str, Path], ...], tuple[str, ...]]:
    system = platform.system()
    if system == "Linux":
        return _linux_linked_library_paths(
            runner,
            pinned_install_root=pinned_install_root,
        )
    if system == "Darwin":
        return _darwin_linked_library_paths(runner)
    raise OpenFHEQueryRuntimeError("runner linked-library inspection OS is unsupported")


def _linked_library_identity(
    runner: Path,
    *,
    pinned_install_root: Path,
) -> tuple[str, tuple[OpenFHELinkedLibraryIdentity, ...], tuple[str, ...]]:
    inspection_format, paths, system_load_names = _inspect_linked_library_paths(
        runner,
        pinned_install_root=pinned_install_root,
    )
    identities: list[OpenFHELinkedLibraryIdentity] = []
    for load_name, path in paths:
        content, status = _stable_file_content(
            path,
            field=f"linked library {load_name}",
            maximum=_LINKED_LIBRARY_BYTES_MAXIMUM,
        )
        binary_format, binary_id, soname, needed = _binary_metadata(
            path,
            expected_status=status,
        )
        identities.append(
            OpenFHELinkedLibraryIdentity(
                load_name=load_name,
                resolved_path=str(path),
                byte_count=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                device=status.st_dev,
                inode=status.st_ino,
                mode=stat.S_IMODE(status.st_mode),
                binary_format=binary_format,
                binary_id=binary_id,
                soname=soname,
                needed_load_names=needed,
            )
        )
    linked_libraries = tuple(identities)
    if not any(
        "openfhe" in f"{item.load_name} {item.resolved_path}".lower()
        for item in linked_libraries
    ):
        raise OpenFHEQueryRuntimeError("runner is not linked to a file-backed OpenFHE library")
    return inspection_format, linked_libraries, system_load_names


def _git_source_output(
    source_root: Path,
    arguments: tuple[str, ...],
    *,
    field: str,
    allow_empty: bool = False,
) -> str:
    git = shutil.which("git", path="/usr/bin:/bin")
    if git is None:
        raise OpenFHEQueryRuntimeError("git is unavailable for OpenFHE identity")
    try:
        completed = subprocess.run(
            (git, "-C", str(source_root), *arguments),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OpenFHEQueryRuntimeError(f"OpenFHE {field} probe failed") from error
    output = completed.stdout + completed.stderr
    if (
        completed.returncode != 0
        or len(output) > _LOG_BYTES_MAXIMUM
        or (not output and not allow_empty)
    ):
        raise OpenFHEQueryRuntimeError(f"OpenFHE {field} probe is not exact")
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError(f"OpenFHE {field} probe is not UTF-8") from error


def _build_file_sha256(
    path: Path,
    *,
    field: str,
    maximum: int = 256 * 1024 * 1024,
) -> str:
    content, _status = _stable_file_content(path, field=field, maximum=maximum)
    return hashlib.sha256(content).hexdigest()


def _cmake_set_value(content: bytes, name: str, *, field: str) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenFHEQueryRuntimeError(f"{field} is not UTF-8") from error
    pattern = re.compile(
        rf'^\s*set\(\s*{re.escape(name)}\s+(?:"([^"]+)"|([^\s)]+))\s*\)\s*$',
        re.MULTILINE,
    )
    values = tuple(match.group(1) or match.group(2) for match in pattern.finditer(text))
    if len(values) != 1 or not values[0]:
        raise OpenFHEQueryRuntimeError(f"{field} lacks one exact {name} value")
    return values[0]


def _capture_build_provenance(
    root: Path,
    build_root: Path,
    cache: dict[str, str],
    cache_content: bytes,
) -> OpenFHEBuildProvenance:
    if cache["CMAKE_GENERATOR"] != "Ninja":
        raise OpenFHEQueryRuntimeError("runner build generator is not exact Ninja")
    try:
        cmake_home = Path(cache["CMAKE_HOME_DIRECTORY"]).resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "runner CMake source directory cannot be resolved"
        ) from error
    if cmake_home != (root / "cpp").resolve(strict=True):
        raise OpenFHEQueryRuntimeError("runner CMake source directory changed")
    cmake = _resolved_linked_path(cache["CMAKE_COMMAND"], field="CMake executable")
    cmake_content, cmake_status = _stable_file_content(
        cmake,
        field="CMake executable",
        maximum=256 * 1024 * 1024,
    )
    cmake_version_output = _linkage_tool_output(
        (str(cmake), "--version"),
        field="CMake version identity",
    )
    try:
        cmake_after = cmake.lstat()
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "CMake executable changed after identity probe"
        ) from error
    if _stable_status_tuple(cmake_after) != _stable_status_tuple(cmake_status):
        raise OpenFHEQueryRuntimeError("CMake executable changed during identity probe")
    cmake_version = cmake_version_output.splitlines()[0]

    try:
        openfhe_directory = Path(cache["OpenFHE_DIR"]).resolve(strict=True)
    except OSError as error:
        raise OpenFHEQueryRuntimeError("OpenFHE package directory cannot be resolved") from error
    _reject_symlink_components(openfhe_directory, missing_leaf_allowed=False)
    if not openfhe_directory.is_dir():
        raise OpenFHEQueryRuntimeError("OpenFHE package directory is not a directory")
    install_root = openfhe_directory.parent.parent
    openfhe_root = install_root.parent
    source_root = openfhe_root / "source"
    openfhe_build = openfhe_root / "build"
    try:
        manifest_document = json.loads(
            _read_direct_file(
                root / "config/params_manifest.json",
                field="OpenFHE parameter manifest",
            )
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise OpenFHEQueryRuntimeError("OpenFHE parameter manifest is invalid") from error
    if type(manifest_document) is not dict:
        raise OpenFHEQueryRuntimeError("OpenFHE parameter manifest identity changed")
    openfhe_manifest = manifest_document.get("openfhe")
    if type(openfhe_manifest) is not dict:
        raise OpenFHEQueryRuntimeError("OpenFHE parameter manifest identity changed")
    expected_commit = openfhe_manifest.get("commit")
    repository = openfhe_manifest.get("repository")
    version = openfhe_manifest.get("version")
    if not all(type(value) is str and value for value in (expected_commit, repository, version)):
        raise OpenFHEQueryRuntimeError("OpenFHE parameter manifest identity changed")
    source_remote = _git_source_output(
        source_root,
        ("config", "--get", "remote.origin.url"),
        field="source repository",
    )
    commit = _git_source_output(source_root, ("rev-parse", "HEAD"), field="source commit")
    tree = _git_source_output(
        source_root,
        ("rev-parse", "HEAD^{tree}"),
        field="source tree",
    )
    dirty = _git_source_output(
        source_root,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        field="source status",
        allow_empty=True,
    )
    source_cmake_content, _source_cmake_status = _stable_file_content(
        source_root / "CMakeLists.txt",
        field="OpenFHE source CMakeLists",
        maximum=16 * 1024 * 1024,
    )
    source_version = ".".join(
        _cmake_set_value(
            source_cmake_content,
            f"OPENFHE_VERSION_{part}",
            field="OpenFHE source CMakeLists",
        )
        for part in ("MAJOR", "MINOR", "PATCH")
    )
    package_config_content, _package_config_status = _stable_file_content(
        openfhe_directory / "OpenFHEConfig.cmake",
        field="OpenFHE package config",
        maximum=16 * 1024 * 1024,
    )
    package_version = _cmake_set_value(
        package_config_content,
        "BASE_OPENFHE_VERSION",
        field="OpenFHE package config",
    )
    if (
        source_remote != repository
        or commit != expected_commit
        or source_version != version
        or package_version != version
        or dirty
    ):
        raise OpenFHEQueryRuntimeError(
            "OpenFHE repository/version/commit/cleanliness changed"
        )
    return OpenFHEBuildProvenance(
        cmake_path=str(cmake),
        cmake_sha256=hashlib.sha256(cmake_content).hexdigest(),
        cmake_byte_count=len(cmake_content),
        cmake_version=cmake_version,
        cmake_identity_sha256=hashlib.sha256(
            cmake_content + cmake_version_output.encode("utf-8")
        ).hexdigest(),
        cmake_cache_sha256=hashlib.sha256(cache_content).hexdigest(),
        compile_commands_sha256=_build_file_sha256(
            build_root / "compile_commands.json",
            field="runner compile commands",
        ),
        build_ninja_sha256=_build_file_sha256(
            build_root / "build.ninja",
            field="runner Ninja build graph",
        ),
        rules_ninja_sha256=_build_file_sha256(
            build_root / "CMakeFiles/rules.ninja",
            field="runner Ninja rules",
        ),
        openfhe_directory=str(openfhe_directory),
        openfhe_config_sha256=hashlib.sha256(package_config_content).hexdigest(),
        openfhe_repository=source_remote,
        openfhe_version=source_version,
        openfhe_package_version=package_version,
        openfhe_source_cmake_sha256=hashlib.sha256(source_cmake_content).hexdigest(),
        openfhe_source_commit=commit,
        openfhe_source_tree=tree,
        openfhe_source_clean=True,
        openfhe_cmake_cache_sha256=_build_file_sha256(
            openfhe_build / "CMakeCache.txt",
            field="OpenFHE CMake cache",
        ),
        openfhe_compile_commands_sha256=_build_file_sha256(
            openfhe_build / "compile_commands.json",
            field="OpenFHE compile commands",
        ),
        openfhe_install_manifest_sha256=_build_file_sha256(
            openfhe_build / "install_manifest.txt",
            field="OpenFHE install manifest",
        ),
    )


def capture_openfhe_runner_build_identity(
    repository_root: Path,
    runner_relative_path: str,
) -> OpenFHERunnerBuildIdentity:
    """Bind the direct runner bytes to its exact repository/build inputs."""

    root = _absolute_path(repository_root, field="repository_root")
    _reject_symlink_components(root, missing_leaf_allowed=False)
    relative = PurePosixPath(runner_relative_path)
    if (
        type(runner_relative_path) is not str
        or not runner_relative_path
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != runner_relative_path
    ):
        raise OpenFHEQueryRuntimeError("runner_relative_path must be one normalized relative path")
    runner = root.joinpath(*relative.parts)
    runner_content, runner_status = _stable_file_content(
        runner,
        field="OpenFHE runner",
        maximum=256 * 1024 * 1024,
    )
    if runner_status.st_mode & 0o111 == 0:
        raise OpenFHEQueryRuntimeError("OpenFHE runner is not executable")
    runner_format, runner_binary_id, runner_soname, runner_needed = _binary_metadata(
        runner,
        expected_status=runner_status,
    )
    if runner_soname is not None:
        raise OpenFHEQueryRuntimeError("OpenFHE executable unexpectedly has a SONAME")
    source_entries = tuple(
        (
            source,
            hashlib.sha256(
                _read_direct_file(root / source, field=f"runner source {source}")
            ).hexdigest(),
        )
        for source in _SOURCE_PATHS
    )
    cache_content = _read_direct_file(
        runner.parent / "CMakeCache.txt",
        field="runner CMake cache",
    )
    cache = _parse_cmake_cache(cache_content)
    (
        compiler_path,
        compiler_identity,
        compiler_content,
        compiler_version,
        compiler_target,
    ) = _compiler_identity(Path(cache["CMAKE_CXX_COMPILER"]))
    compiler_flags = tuple(
        [
            *shlex.split(cache["CMAKE_CXX_FLAGS"]),
            *shlex.split(cache["CMAKE_CXX_FLAGS_RELEASE"]),
            *_FIXED_TARGET_FLAGS,
        ]
    )
    build_provenance = _capture_build_provenance(
        root,
        runner.parent,
        cache,
        cache_content,
    )
    linkage_format, linked_libraries, linked_system_libraries = _linked_library_identity(
        runner,
        pinned_install_root=Path(build_provenance.openfhe_directory).parent.parent,
    )
    build_binding = {
        "build_provenance": build_provenance.to_document(),
        "compiler_byte_count": len(compiler_content),
        "compiler_flags": list(compiler_flags),
        "compiler_identity_sha256": hashlib.sha256(compiler_identity).hexdigest(),
        "compiler_path": compiler_path,
        "compiler_sha256": hashlib.sha256(compiler_content).hexdigest(),
        "compiler_target": compiler_target,
        "compiler_version": compiler_version,
        "linkage_inspection_format": linkage_format,
        "linked_libraries": [item.to_document() for item in linked_libraries],
        "linked_system_library_load_names": list(linked_system_libraries),
        "runner_binary_format": runner_format,
        "runner_binary_id": runner_binary_id,
        "runner_byte_count": len(runner_content),
        "runner_device": runner_status.st_dev,
        "runner_inode": runner_status.st_ino,
        "runner_mode": stat.S_IMODE(runner_status.st_mode),
        "runner_needed_load_names": list(runner_needed),
        "runner_relative_path": runner_relative_path,
        "runner_sha256": hashlib.sha256(runner_content).hexdigest(),
        "schema_version": OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA,
        "source_sha256": dict(source_entries),
    }
    return OpenFHERunnerBuildIdentity(
        runner_relative_path=runner_relative_path,
        runner_sha256=str(build_binding["runner_sha256"]),
        runner_byte_count=len(runner_content),
        runner_device=runner_status.st_dev,
        runner_inode=runner_status.st_ino,
        runner_mode=stat.S_IMODE(runner_status.st_mode),
        runner_binary_format=runner_format,
        runner_binary_id=runner_binary_id,
        runner_needed_load_names=runner_needed,
        source_sha256=source_entries,
        compiler_path=compiler_path,
        compiler_sha256=str(build_binding["compiler_sha256"]),
        compiler_byte_count=len(compiler_content),
        compiler_identity_sha256=str(build_binding["compiler_identity_sha256"]),
        compiler_version=compiler_version,
        compiler_target=compiler_target,
        compiler_flags=compiler_flags,
        build_provenance=build_provenance,
        linkage_inspection_format=linkage_format,
        linked_libraries=linked_libraries,
        linked_system_library_load_names=linked_system_libraries,
        build_identity_sha256=hashlib.sha256(_canonical_bytes(build_binding)).hexdigest(),
    )


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - operating-system contract
                raise OpenFHEQueryRuntimeError("private request write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scratch_bytes(root: Path) -> int:
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError as error:
            raise OpenFHEQueryRuntimeError("controlled scratch cannot be enumerated") from error
        for entry in entries:
            status = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(status.st_mode):
                pending.append(Path(entry.path))
            elif stat.S_ISREG(status.st_mode):
                total += status.st_size
            else:
                raise OpenFHEQueryRuntimeError(
                    "controlled scratch contains a non-directory/non-regular member"
                )
    return total


def _rss_bytes(rusage: resource.struct_rusage) -> int:
    observed = int(rusage.ru_maxrss)
    return observed if sys.platform == "darwin" else observed * 1024


def _read_log(path: Path) -> bytes:
    return _read_direct_file(
        path,
        field=f"runner log {path.name}",
        maximum=_LOG_BYTES_MAXIMUM,
        allow_empty=True,
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        raise OpenFHEQueryRuntimeError("OpenFHE process group could not be terminated") from error


def _terminate_and_reap_process(process: subprocess.Popen[bytes]) -> None:
    try:
        waited_pid, status, _usage = os.wait4(process.pid, os.WNOHANG)
    except ChildProcessError:
        return
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "OpenFHE child state could not be inspected before termination"
        ) from error
    if waited_pid == process.pid:
        process.returncode = os.waitstatus_to_exitcode(status)
        return
    try:
        _terminate_process_group(process)
    except OpenFHEQueryRuntimeError:
        try:
            waited_pid, status, _usage = os.wait4(process.pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            raise
        if waited_pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return
        raise
    try:
        _waited_pid, status, _usage = os.wait4(process.pid, 0)
    except ChildProcessError:
        return
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "terminated OpenFHE child could not be reaped"
        ) from error
    process.returncode = os.waitstatus_to_exitcode(status)


def _admitted_executable_files(
    runner: Path,
    identity: OpenFHERunnerBuildIdentity,
) -> tuple[AdmittedExecutableFile, ...]:
    if (
        type(identity) is not OpenFHERunnerBuildIdentity
        or identity.runner_binary_format != "elf-v1"
        or any(item.binary_format != "elf-v1" for item in identity.linked_libraries)
    ):
        raise OpenFHEQueryRuntimeError(
            "Linux mapping admission requires one exact ELF build identity"
        )
    try:
        runner_path = str(runner.resolve(strict=True))
    except OSError as error:
        raise OpenFHEQueryRuntimeError(
            "OpenFHE runner cannot be resolved for mapping admission"
        ) from error
    values = [
        AdmittedExecutableFile(
            path=runner_path,
            device=identity.runner_device,
            inode=identity.runner_inode,
            mode=identity.runner_mode,
            byte_count=identity.runner_byte_count,
            sha256=identity.runner_sha256,
            binary_format=identity.runner_binary_format,
            binary_id=identity.runner_binary_id,
        ),
        *(
            AdmittedExecutableFile(
                path=item.resolved_path,
                device=item.device,
                inode=item.inode,
                mode=item.mode,
                byte_count=item.byte_count,
                sha256=item.sha256,
                binary_format=item.binary_format,
                binary_id=item.binary_id,
            )
            for item in identity.linked_libraries
        ),
    ]
    result = tuple(sorted(values, key=lambda item: item.path))
    if len({item.path for item in result}) != len(result):
        raise OpenFHEQueryRuntimeError(
            "admitted executable closure contains duplicate physical paths"
        )
    return result


def _await_control_record(
    descriptor: int,
    expected: bytes,
    *,
    scratch_root: Path,
    scratch_limit_bytes: int,
    deadline: float,
    peak_scratch_bytes: int,
) -> int:
    received = bytearray()
    while len(received) < len(expected):
        peak_scratch_bytes = max(peak_scratch_bytes, _scratch_bytes(scratch_root))
        if peak_scratch_bytes > scratch_limit_bytes:
            raise OpenFHEQueryRuntimeError("scratch-limit-exceeded")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OpenFHEQueryRuntimeError("wall-clock-limit-exceeded")
        try:
            readable, _writable, _exceptional = select.select(
                (descriptor,),
                (),
                (),
                min(_OBSERVATION_INTERVAL_SECONDS, remaining),
            )
        except (OSError, ValueError) as error:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE runtime control descriptor could not be observed"
            ) from error
        if not readable:
            continue
        try:
            chunk = os.read(descriptor, len(expected) - len(received))
        except OSError as error:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE runtime control record could not be read"
            ) from error
        if not chunk:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE runner ended before its runtime control record"
            )
        received.extend(chunk)
    if bytes(received) != expected:
        raise OpenFHEQueryRuntimeError("OpenFHE runtime control record changed")
    return peak_scratch_bytes


def _write_control_acknowledgement(descriptor: int, acknowledgement: bytes) -> None:
    view = memoryview(acknowledgement)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as error:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE runtime acknowledgement could not be written"
            ) from error
        if written <= 0:  # pragma: no cover - operating-system contract
            raise OpenFHEQueryRuntimeError(
                "OpenFHE runtime acknowledgement made no progress"
            )
        view = view[written:]


def _wait4_process(
    process: subprocess.Popen[bytes],
    *,
    scratch_root: Path,
    timeout_seconds: int,
    scratch_limit_bytes: int,
    deadline: float | None = None,
    initial_peak_scratch_bytes: int = 0,
) -> tuple[int, resource.struct_rusage, int]:
    if deadline is None:
        deadline = time.monotonic() + timeout_seconds
    peak_scratch = max(initial_peak_scratch_bytes, _scratch_bytes(scratch_root))
    failure: str | None = None
    status = 0
    usage: resource.struct_rusage | None = None
    while usage is None:
        try:
            waited_pid, status, observed = os.wait4(process.pid, os.WNOHANG)
        except (ChildProcessError, OSError) as error:
            raise OpenFHEQueryRuntimeError(
                "controller could not observe the OpenFHE child"
            ) from error
        peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
        if waited_pid == process.pid:
            usage = observed
            if peak_scratch > scratch_limit_bytes:
                failure = "scratch-limit-exceeded"
            break
        if peak_scratch > scratch_limit_bytes:
            failure = "scratch-limit-exceeded"
        elif time.monotonic() >= deadline:
            failure = "wall-clock-limit-exceeded"
        if failure is not None:
            _terminate_process_group(process)
            try:
                _waited_pid, status, usage = os.wait4(process.pid, 0)
            except (ChildProcessError, OSError) as error:
                raise OpenFHEQueryRuntimeError(
                    "controller could not reap the terminated OpenFHE child"
                ) from error
            break
        time.sleep(_OBSERVATION_INTERVAL_SECONDS)
    process.returncode = os.waitstatus_to_exitcode(status)
    peak_scratch = max(peak_scratch, _scratch_bytes(scratch_root))
    if failure is not None:
        raise OpenFHEQueryRuntimeError(failure)
    return process.returncode, usage, peak_scratch


def _wait4_handshaken_process(
    process: subprocess.Popen[bytes],
    *,
    runner: Path,
    runner_identity: OpenFHERunnerBuildIdentity,
    control_read_descriptor: int,
    control_write_descriptor: int,
    scratch_root: Path,
    timeout_seconds: int,
    scratch_limit_bytes: int,
) -> tuple[
    int,
    resource.struct_rusage,
    int,
    OpenFHERuntimeMappingAdmission | None,
]:
    deadline = time.monotonic() + timeout_seconds
    peak_scratch = _scratch_bytes(scratch_root)
    ready_record, ready_acknowledgement = _CONTROL_RECORDS["READY"]
    peak_scratch = _await_control_record(
        control_read_descriptor,
        ready_record,
        scratch_root=scratch_root,
        scratch_limit_bytes=scratch_limit_bytes,
        deadline=deadline,
        peak_scratch_bytes=peak_scratch,
    )
    admitted_files: tuple[AdmittedExecutableFile, ...] | None = None
    ready_snapshot = None
    if platform.system() == "Linux":
        admitted_files = _admitted_executable_files(runner, runner_identity)
        try:
            ready_snapshot = capture_linux_process_mapping_snapshot(
                pid=process.pid,
                stage="READY",
                admitted_executable_files=admitted_files,
            )
        except OpenFHERuntimeAdmissionError as error:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE READY executable mappings failed admission"
            ) from error
    _write_control_acknowledgement(
        control_write_descriptor,
        ready_acknowledgement,
    )

    done_record, done_acknowledgement = _CONTROL_RECORDS["DONE"]
    peak_scratch = _await_control_record(
        control_read_descriptor,
        done_record,
        scratch_root=scratch_root,
        scratch_limit_bytes=scratch_limit_bytes,
        deadline=deadline,
        peak_scratch_bytes=peak_scratch,
    )
    mapping_admission = None
    if admitted_files is not None:
        assert ready_snapshot is not None
        try:
            done_snapshot = capture_linux_process_mapping_snapshot(
                pid=process.pid,
                stage="DONE",
                admitted_executable_files=admitted_files,
            )
            mapping_admission = admit_linux_runtime_mapping_continuity(
                ready_snapshot,
                done_snapshot,
            )
        except OpenFHERuntimeAdmissionError as error:
            raise OpenFHEQueryRuntimeError(
                "OpenFHE DONE executable mappings failed continuity admission"
            ) from error
    _write_control_acknowledgement(
        control_write_descriptor,
        done_acknowledgement,
    )
    return_code, usage, peak_scratch = _wait4_process(
        process,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        scratch_limit_bytes=scratch_limit_bytes,
        deadline=deadline,
        initial_peak_scratch_bytes=peak_scratch,
    )
    return return_code, usage, peak_scratch, mapping_admission


def _run_process(
    runner: Path,
    *,
    repository_root: Path,
    scratch_root: Path,
    request_path: Path,
    result_path: Path,
    object_root: Path,
    timeout_seconds: int,
    scratch_limit_bytes: int,
    runner_identity: OpenFHERunnerBuildIdentity | None = None,
) -> _ProcessObservation:
    stdout_path = scratch_root / "stdout.bin"
    stderr_path = scratch_root / "stderr.bin"
    stdout_fd: int | None = None
    stderr_fd: int | None = None
    child_to_parent_read: int | None = None
    child_to_parent_write: int | None = None
    parent_to_child_read: int | None = None
    parent_to_child_write: int | None = None
    process: subprocess.Popen[bytes] | None = None
    mapping_admission: OpenFHERuntimeMappingAdmission | None = None
    started_ns = time.monotonic_ns()
    try:
        stdout_fd = os.open(
            stdout_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        stderr_fd = os.open(
            stderr_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        command = [
            str(runner),
            "--request",
            str(request_path),
            "--result",
            str(result_path),
            "--object-dir",
            str(object_root),
        ]
        passed_descriptors: tuple[int, ...] = ()
        if runner_identity is not None:
            if type(runner_identity) is not OpenFHERunnerBuildIdentity:
                raise TypeError("runner_identity must be one exact build identity")
            child_to_parent_read, child_to_parent_write = os.pipe()
            parent_to_child_read, parent_to_child_write = os.pipe()
            command.extend(
                (
                    "--control-write-fd",
                    str(child_to_parent_write),
                    "--control-read-fd",
                    str(parent_to_child_read),
                )
            )
            passed_descriptors = (child_to_parent_write, parent_to_child_read)
        process = subprocess.Popen(
            tuple(command),
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            cwd=repository_root,
            env={
                "HOME": str(scratch_root / "home"),
                "LANG": "C",
                "LC_ALL": "C",
                "OMP_NUM_THREADS": "1",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TMPDIR": str(scratch_root / "tmp"),
                "TZ": "UTC",
            },
            close_fds=True,
            pass_fds=passed_descriptors,
            start_new_session=True,
        )
        if child_to_parent_write is not None:
            os.close(child_to_parent_write)
            child_to_parent_write = None
        if parent_to_child_read is not None:
            os.close(parent_to_child_read)
            parent_to_child_read = None
        try:
            if runner_identity is None:
                return_code, usage, peak_scratch = _wait4_process(
                    process,
                    scratch_root=scratch_root,
                    timeout_seconds=timeout_seconds,
                    scratch_limit_bytes=scratch_limit_bytes,
                )
            else:
                assert child_to_parent_read is not None
                assert parent_to_child_write is not None
                (
                    return_code,
                    usage,
                    peak_scratch,
                    mapping_admission,
                ) = _wait4_handshaken_process(
                    process,
                    runner=runner,
                    runner_identity=runner_identity,
                    control_read_descriptor=child_to_parent_read,
                    control_write_descriptor=parent_to_child_write,
                    scratch_root=scratch_root,
                    timeout_seconds=timeout_seconds,
                    scratch_limit_bytes=scratch_limit_bytes,
                )
        except BaseException:
            if process.returncode is None:
                with suppress(BaseException):
                    _terminate_and_reap_process(process)
            raise
    finally:
        for descriptor in (
            stdout_fd,
            stderr_fd,
            child_to_parent_read,
            child_to_parent_write,
            parent_to_child_read,
            parent_to_child_write,
        ):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
    elapsed_ns = time.monotonic_ns() - started_ns
    stdout = _read_log(stdout_path)
    stderr = _read_log(stderr_path)
    if return_code != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        raise OpenFHEQueryRuntimeError(f"OpenFHE runner exited {return_code}: {message}")
    expected_stdout = f"{result_path}\n".encode()
    if stdout != expected_stdout or stderr:
        raise OpenFHEQueryRuntimeError("OpenFHE runner stdout/stderr contract changed")
    return _ProcessObservation(
        elapsed_ns=elapsed_ns,
        peak_resident_memory_bytes=_rss_bytes(usage),
        peak_scratch_bytes=peak_scratch,
        stdout=stdout,
        stderr=stderr,
        runtime_mapping_admission=mapping_admission,
    )


def _payloads(
    object_root: Path,
    receipts: tuple[OpenFHESerializedObjectReceipt, ...],
) -> tuple[OpenFHESerializedPayload, ...]:
    payloads: list[OpenFHESerializedPayload] = []
    for receipt in receipts:
        content = _read_direct_file(
            object_root / receipt.relative_path,
            field=f"serialized OpenFHE object {receipt.relative_path}",
        )
        if (
            len(content) != receipt.byte_count
            or hashlib.sha256(content).hexdigest() != receipt.sha256
        ):
            raise OpenFHEQueryRuntimeError("serialized OpenFHE object changed after verification")
        payloads.append(
            OpenFHESerializedPayload(
                category=receipt.category,
                subject_id=receipt.subject_id,
                binary_framing_schema=(
                    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA
                    if receipt.category == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
                    else None
                ),
                sha256=receipt.sha256,
                payload=content,
            )
        )
    return tuple(payloads)


def _cpu_affinity() -> tuple[int, ...] | None:
    getter = getattr(os, "sched_getaffinity", None)
    if getter is None:
        return None
    try:
        return tuple(sorted(getter(0)))
    except OSError as error:
        raise OpenFHEQueryRuntimeError("CPU affinity could not be observed") from error


def _execute_authorized_openfhe_query(
    *,
    execution_kind: str,
    request_builder: Callable[
        [Path, OpenFHEKeyGenerationPlan | None],
        bytes,
    ],
    day2_key_plan_claim: Callable[[], ClaimedDay2OpenFHEKeyPlan] | None,
    authorize_and_claim: Callable[[], OpenFHEExecutionAuthorizationReceipt],
    result_verifier: Callable[
        [bytes, Path, Path],
        VerifiedOpenFHEQueryResult,
    ],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> ExecutedOpenFHEQuery:
    """Deep launcher shared by the two typed lifecycle adapters."""

    root = _absolute_path(repository_root, field="repository_root")
    scratch = _absolute_path(scratch_root, field="scratch_root")
    if execution_kind not in {"ordinary", "strong"}:
        raise OpenFHEQueryRuntimeError("runtime execution kind is not closed")
    if day2_key_plan_claim is not None and not callable(day2_key_plan_claim):
        raise OpenFHEQueryRuntimeError(
            "runtime Day 2 key-plan claim must be callable or absent"
        )
    if (
        type(timeout_seconds) is not int
        or timeout_seconds <= 0
        or type(resident_memory_limit_bytes) is not int
        or resident_memory_limit_bytes <= 0
        or type(scratch_limit_bytes) is not int
        or scratch_limit_bytes <= 0
    ):
        raise OpenFHEQueryRuntimeError("runtime limits must be exact positive integers")
    _reject_symlink_components(scratch, missing_leaf_allowed=True)
    if scratch.exists() or scratch.is_symlink():
        raise OpenFHEQueryRuntimeError("scratch_root must be one absent path")
    runner_identity = capture_openfhe_runner_build_identity(root, runner_relative_path)
    runner = root.joinpath(*PurePosixPath(runner_relative_path).parts)
    scratch.mkdir(mode=0o700)
    scratch_identity = scratch.lstat()
    request_path = scratch / "request.json"
    result_path = scratch / "result.json"
    object_root = scratch / "objects"
    try:
        object_root.mkdir(mode=0o700)
        (scratch / "home").mkdir(mode=0o700)
        (scratch / "tmp").mkdir(mode=0o700)
        if day2_key_plan_claim is None:
            anchored_key_plan = None
            key_plan_authorization = None
        else:
            claimed_key_plan = day2_key_plan_claim()
            if type(claimed_key_plan) is not ClaimedDay2OpenFHEKeyPlan:
                raise OpenFHEQueryRuntimeError(
                    "runtime did not receive one exact claimed Day 2 key plan"
                )
            anchored_key_plan = claimed_key_plan.key_generation_plan
            key_plan_authorization = claimed_key_plan.receipt
        request_bytes = request_builder(root, anchored_key_plan)
        _write_new_file(request_path, request_bytes)
        if _scratch_bytes(scratch) > scratch_limit_bytes:
            raise OpenFHEQueryRuntimeError("scratch-limit-exceeded-before-authorization")
        authorization = authorize_and_claim()
        observation = _run_process(
            runner,
            repository_root=root,
            scratch_root=scratch,
            request_path=request_path,
            result_path=result_path,
            object_root=object_root,
            timeout_seconds=timeout_seconds,
            scratch_limit_bytes=scratch_limit_bytes,
            runner_identity=runner_identity,
        )
        if observation.peak_resident_memory_bytes > resident_memory_limit_bytes:
            raise OpenFHEQueryRuntimeError("resident-memory-limit-exceeded")
        result_before_verification = _read_direct_file(
            result_path,
            field="OpenFHE result before verification",
            maximum=128 * 1024 * 1024,
        )
        verified = result_verifier(request_bytes, result_path, object_root)
        if key_plan_authorization is not None and (
            verified.key_material_receipt.rotation_key_plan_sha256
            != key_plan_authorization.rotation_key_plan_sha256
            or verified.key_material_receipt.required_exact_indices
            != key_plan_authorization.required_exact_indices
        ):
            raise OpenFHEQueryRuntimeError(
                "runtime key material differs from anchored Day 2 plan authority"
            )
        result_after_verification = _read_direct_file(
            result_path,
            field="OpenFHE result after verification",
            maximum=128 * 1024 * 1024,
        )
        if result_after_verification != result_before_verification:
            raise OpenFHEQueryRuntimeError("OpenFHE result changed during verification")
        payloads = _payloads(object_root, verified.serialized_objects)
        if capture_openfhe_runner_build_identity(root, runner_relative_path) != runner_identity:
            raise OpenFHEQueryRuntimeError("OpenFHE runner/build identity changed during execution")
        final_scratch = _scratch_bytes(scratch)
        peak_scratch = max(observation.peak_scratch_bytes, final_scratch)
        if peak_scratch > scratch_limit_bytes:
            raise OpenFHEQueryRuntimeError("scratch-limit-exceeded")
        host_identity = hashlib.sha256(platform.node().encode("utf-8")).hexdigest()
        os_identity = f"{platform.system()}-{platform.release()}-{platform.machine()}"
        receipt = OpenFHEQueryRuntimeReceipt(
            runner=runner_identity,
            execution_kind=execution_kind,
            authorization=authorization,
            day2_key_plan_authorization=key_plan_authorization,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            request_byte_count=len(request_bytes),
            result_sha256=hashlib.sha256(result_after_verification).hexdigest(),
            result_byte_count=len(result_after_verification),
            elapsed_ns=observation.elapsed_ns,
            timeout_seconds=timeout_seconds,
            peak_resident_memory_bytes=observation.peak_resident_memory_bytes,
            resident_memory_limit_bytes=resident_memory_limit_bytes,
            peak_scratch_bytes=peak_scratch,
            scratch_limit_bytes=scratch_limit_bytes,
            stdout_sha256=hashlib.sha256(observation.stdout).hexdigest(),
            stdout_byte_count=len(observation.stdout),
            stderr_sha256=hashlib.sha256(observation.stderr).hexdigest(),
            stderr_byte_count=len(observation.stderr),
            serialized_object_count=len(payloads),
            serialized_object_bytes=sum(len(item.payload) for item in payloads),
            host_identity_sha256=host_identity,
            operating_system_identity=os_identity,
            cpu_affinity=_cpu_affinity(),
            runtime_mapping_admission=observation.runtime_mapping_admission,
        )
        return ExecutedOpenFHEQuery(
            verified_result=verified,
            runtime_receipt=receipt,
            serialized_payloads=payloads,
        )
    finally:
        try:
            current = scratch.lstat()
            if (current.st_dev, current.st_ino) != (
                scratch_identity.st_dev,
                scratch_identity.st_ino,
            ):
                raise OpenFHEQueryRuntimeError("controlled scratch identity changed before cleanup")
            shutil.rmtree(scratch)
        except FileNotFoundError as error:
            raise OpenFHEQueryRuntimeError(
                "controlled scratch disappeared before cleanup"
            ) from error
        except OSError as error:
            raise OpenFHEQueryRuntimeError("controlled scratch cleanup failed") from error


def _execute_ordinary_openfhe_query_adapter(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
    key_generation_plan: OpenFHEKeyGenerationPlan | None,
    day2_key_plan_capability: Day2OpenFHEKeyPlanCapability | None,
) -> ExecutedOpenFHEQuery:
    if key_generation_plan is not None and day2_key_plan_capability is not None:
        raise OpenFHEQueryRuntimeError(
            "ordinary runtime cannot combine caller and anchored key plans"
        )
    if day2_key_plan_capability is not None and (
        type(day2_key_plan_capability) is not Day2OpenFHEKeyPlanCapability
    ):
        raise TypeError(
            "anchored ordinary runtime requires one exact Day 2 plan capability"
        )
    active_key_generation_plan = key_generation_plan

    def request_builder(
        root: Path,
        anchored_plan: OpenFHEKeyGenerationPlan | None,
    ) -> bytes:
        nonlocal active_key_generation_plan
        if day2_key_plan_capability is None:
            if anchored_plan is not None:
                raise OpenFHEQueryRuntimeError(
                    "pre-admission ordinary runtime received anchored plan state"
                )
        else:
            if type(anchored_plan) is not OpenFHEKeyGenerationPlan:
                raise OpenFHEQueryRuntimeError(
                    "anchored ordinary runtime did not claim its exact Day 2 plan"
                )
            active_key_generation_plan = anchored_plan
        return build_ordinary_openfhe_query_request(
            bundle,
            prepared,
            repository_root=root,
            key_generation_plan=active_key_generation_plan,
        )

    def claim_key_plan() -> ClaimedDay2OpenFHEKeyPlan:
        assert day2_key_plan_capability is not None
        return claim_day2_openfhe_key_plan(day2_key_plan_capability)

    def authorize_and_claim() -> OrdinaryExecutionAuthorizationReceipt:
        capability = authorize_ordinary_execution(bundle, prepared, ledger=ledger)
        return claim_ordinary_execution(capability, bundle, prepared)

    def result_verifier(
        request_bytes: bytes,
        result_path: Path,
        object_root: Path,
    ) -> VerifiedOpenFHEQueryResult:
        return verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=expected_output,
            repository_root=repository_root,
            key_generation_plan=active_key_generation_plan,
        )

    return _execute_authorized_openfhe_query(
        execution_kind="ordinary",
        request_builder=request_builder,
        day2_key_plan_claim=(
            None if day2_key_plan_capability is None else claim_key_plan
        ),
        authorize_and_claim=authorize_and_claim,
        result_verifier=result_verifier,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
    )


def execute_authorized_openfhe_query(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> ExecutedOpenFHEQuery:
    """Execute one ordinary query through the non-anchored smoke seam."""

    return _execute_ordinary_openfhe_query_adapter(
        bundle,
        prepared,
        ledger=ledger,
        expected_output=expected_output,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
        key_generation_plan=key_generation_plan,
        day2_key_plan_capability=None,
    )


def execute_day2_anchored_openfhe_query(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    day2_key_plan_capability: Day2OpenFHEKeyPlanCapability,
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> ExecutedOpenFHEQuery:
    """Consume an anchored Day 2 plan inside one ordinary launch."""

    return _execute_ordinary_openfhe_query_adapter(
        bundle,
        prepared,
        ledger=ledger,
        expected_output=expected_output,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
        key_generation_plan=None,
        day2_key_plan_capability=day2_key_plan_capability,
    )


def _execute_strong_openfhe_query_adapter(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
    key_generation_plan: OpenFHEKeyGenerationPlan | None,
    day2_key_plan_capability: Day2OpenFHEKeyPlanCapability | None,
) -> ExecutedOpenFHEQuery:
    if key_generation_plan is not None and day2_key_plan_capability is not None:
        raise OpenFHEQueryRuntimeError(
            "strong runtime cannot combine caller and anchored key plans"
        )
    if day2_key_plan_capability is not None and (
        type(day2_key_plan_capability) is not Day2OpenFHEKeyPlanCapability
    ):
        raise TypeError(
            "anchored strong runtime requires one exact Day 2 plan capability"
        )
    active_key_generation_plan = key_generation_plan

    def request_builder(
        root: Path,
        anchored_plan: OpenFHEKeyGenerationPlan | None,
    ) -> bytes:
        nonlocal active_key_generation_plan
        if day2_key_plan_capability is None:
            if anchored_plan is not None:
                raise OpenFHEQueryRuntimeError(
                    "pre-admission strong runtime received anchored plan state"
                )
        else:
            if type(anchored_plan) is not OpenFHEKeyGenerationPlan:
                raise OpenFHEQueryRuntimeError(
                    "anchored strong runtime did not claim its exact Day 2 plan"
                )
            active_key_generation_plan = anchored_plan
        return build_strong_openfhe_query_request(
            bundle,
            prepared,
            repository_root=root,
            key_generation_plan=active_key_generation_plan,
        )

    def claim_key_plan() -> ClaimedDay2OpenFHEKeyPlan:
        assert day2_key_plan_capability is not None
        return claim_day2_openfhe_key_plan(day2_key_plan_capability)

    def authorize_and_claim() -> StrongExecutionAuthorizationReceipt:
        capability = authorize_strong_execution(bundle, prepared, ledger=ledger)
        return claim_strong_execution(capability, bundle, prepared)

    def result_verifier(
        request_bytes: bytes,
        result_path: Path,
        object_root: Path,
    ) -> VerifiedOpenFHEQueryResult:
        return verify_strong_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=expected_output,
            repository_root=repository_root,
            key_generation_plan=active_key_generation_plan,
        )

    return _execute_authorized_openfhe_query(
        execution_kind="strong",
        request_builder=request_builder,
        day2_key_plan_claim=(
            None if day2_key_plan_capability is None else claim_key_plan
        ),
        authorize_and_claim=authorize_and_claim,
        result_verifier=result_verifier,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
    )


def execute_authorized_strong_openfhe_query(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> ExecutedOpenFHEQuery:
    """Execute one strong query through the non-anchored smoke seam."""

    return _execute_strong_openfhe_query_adapter(
        bundle,
        prepared,
        ledger=ledger,
        expected_output=expected_output,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
        key_generation_plan=key_generation_plan,
        day2_key_plan_capability=None,
    )


def execute_day2_anchored_strong_openfhe_query(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
    expected_output: tuple[int, ...],
    day2_key_plan_capability: Day2OpenFHEKeyPlanCapability,
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> ExecutedOpenFHEQuery:
    """Consume an anchored Day 2 plan inside one strong launch."""

    return _execute_strong_openfhe_query_adapter(
        bundle,
        prepared,
        ledger=ledger,
        expected_output=expected_output,
        repository_root=repository_root,
        runner_relative_path=runner_relative_path,
        scratch_root=scratch_root,
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
        key_generation_plan=None,
        day2_key_plan_capability=day2_key_plan_capability,
    )


__all__ = (
    "OPENFHE_CPU_AFFINITY_POLICY",
    "OPENFHE_DYNAMIC_LOADER_ENVIRONMENT_POLICY",
    "OPENFHE_QUERY_RUNTIME_RECEIPT_SCHEMA",
    "OPENFHE_RUNNER_BUILD_IDENTITY_SCHEMA",
    "OPENFHE_RUNTIME_CONTROL_PROTOCOL_SCHEMA",
    "OPENFHE_WORKER_BUILD_RECEIPT_SCHEMA",
    "OPENFHE_WORKER_RUNTIME_IDENTITY_SCHEMA",
    "OPENFHE_WORKER_RUNTIME_MAPPING_POLICY",
    "ExecutedOpenFHEQuery",
    "OpenFHEBuildProvenance",
    "OpenFHEQueryRuntimeError",
    "OpenFHEQueryRuntimeReceipt",
    "OpenFHELinkedLibraryIdentity",
    "OpenFHERunnerBuildIdentity",
    "OpenFHESerializedPayload",
    "OpenFHEWorkerRuntimeIdentityPolicy",
    "capture_openfhe_runner_build_identity",
    "execute_authorized_openfhe_query",
    "execute_authorized_strong_openfhe_query",
    "execute_day2_anchored_openfhe_query",
    "execute_day2_anchored_strong_openfhe_query",
    "openfhe_worker_build_receipt_sha256",
    "project_expected_openfhe_worker_runtime_identity",
    "project_observed_openfhe_worker_runtime_identity",
    "project_openfhe_worker_build_receipt",
)
