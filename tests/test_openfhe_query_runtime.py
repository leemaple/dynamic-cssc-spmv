from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_authority as day2_authority
import dynamic_cssc.day2_openfhe_key_plan as day2_key_plan
import dynamic_cssc.openfhe_query_runtime as runtime
import dynamic_cssc.openfhe_runtime_admission as runtime_admission
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.day2_openfhe_key_plan import Day2OpenFHEKeyPlanError
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionAuthorizationReceipt,
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


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _anchored_day2_key_plan() -> day2_key_plan.Day2OpenFHEKeyPlanCapability:
    indices = (-2, -1, 1, 2)
    content = _canonical_line(
        {
            "composite_decompositions": [],
            "day1a_authority_receipt_sha256": "6" * 64,
            "day1a_inventory_sha256": "7" * 64,
            "effective_slots": 4096,
            "eval_rotate_case_ids": [f"index={index}" for index in indices],
            "inventory_source_schema_version": (
                "dynamic-cssc-day1a-rotation-inventory-v1"
            ),
            "key_plan_kind": "direct-exact-index-v1",
            "planned_exact_indices": list(indices),
            "required_exact_indices": list(indices),
            "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        }
    )
    authority = day2_authority._mint_repository_calibration_authority(
        source_git_sha="1" * 40,
        outer_archive_sha256="2" * 64,
        raw_measurement_blocks_sha256="3" * 64,
        calibration_projection_sha256="4" * 64,
        rotation_key_plan_sha256=hashlib.sha256(content).hexdigest(),
        serialized_object_size_profile_sha256="5" * 64,
        ciphertext_bytes=100,
        f1m_random_zero_sum_ciphertext_bytes=101,
        f1m_encrypted_zero_dummy_ciphertext_bytes=102,
        serialized_rotation_key_inventory_bytes=103,
        serialized_eval_mult_key_bytes=104,
    )
    return day2_key_plan._issue_from_day2_authority(authority, content)


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
        linkage_inspection_format="linux-ldd-direct-and-transitive-v2",
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


def test_worker_build_receipt_projection_excludes_ephemeral_filesystem_identity(
    tmp_path: Path,
) -> None:
    identity = _runtime_identity(tmp_path)
    library = identity.linked_libraries[0]
    provenance = identity.build_provenance
    relocated = replace(
        identity,
        runner_device=101,
        runner_inode=202,
        runner_mode=0o711,
        compiler_path="/relocated/toolchain/cxx",
        build_provenance=replace(
            provenance,
            cmake_path="/relocated/toolchain/cmake",
            openfhe_directory="/relocated/openfhe/lib/OpenFHE",
        ),
        linked_libraries=(
            replace(
                library,
                resolved_path="/relocated/lib/libOPENFHEpke.so",
                device=303,
                inode=404,
                mode=0o711,
            ),
        ),
        build_identity_sha256="f" * 64,
    )

    receipt = runtime.project_openfhe_worker_build_receipt(identity)
    relocated_receipt = runtime.project_openfhe_worker_build_receipt(relocated)

    assert receipt == relocated_receipt
    assert set(receipt) == {
        "build_provenance",
        "compiler",
        "linkage_inspection_format",
        "linked_libraries",
        "linked_system_library_load_names",
        "runner",
        "runner_identity_schema_version",
        "schema_version",
        "source_sha256",
        "worker_build_receipt_sha256",
    }
    assert set(receipt["build_provenance"]) == {
        "cmake_byte_count",
        "cmake_identity_sha256",
        "cmake_sha256",
        "cmake_version",
        "openfhe_package_version",
        "openfhe_repository",
        "openfhe_source_clean",
        "openfhe_source_cmake_sha256",
        "openfhe_source_commit",
        "openfhe_source_tree",
        "openfhe_version",
    }
    assert set(receipt["compiler"]) == {
        "byte_count",
        "flags",
        "identity_sha256",
        "sha256",
        "target",
        "version",
    }
    assert set(receipt["runner"]) == {
        "binary_format",
        "binary_id",
        "byte_count",
        "needed_load_names",
        "relative_path",
        "sha256",
    }
    assert set(receipt["linked_libraries"][0]) == {
        "binary_format",
        "binary_id",
        "byte_count",
        "load_name",
        "needed_load_names",
        "sha256",
        "soname",
    }
    assert receipt["schema_version"] == runtime.OPENFHE_WORKER_BUILD_RECEIPT_SCHEMA
    assert receipt["worker_build_receipt_sha256"] == (
        runtime.openfhe_worker_build_receipt_sha256(identity)
    )
    assert runtime.openfhe_worker_build_receipt_sha256(identity) == (
        runtime.openfhe_worker_build_receipt_sha256(relocated)
    )
    rendered = _canonical_line(receipt)
    for forbidden in (
        b"/compiler",
        b"/relocated",
        b"openfhe_directory",
        b"resolved_path",
        b"runner_device",
        b"runner_inode",
        b"runner_mode",
        b"build_identity_sha256",
        b"cmake_cache_sha256",
        b"compile_commands_sha256",
        b"build_ninja_sha256",
        b"rules_ninja_sha256",
        b"openfhe_config_sha256",
        b"openfhe_cmake_cache_sha256",
        b"openfhe_compile_commands_sha256",
        b"openfhe_install_manifest_sha256",
    ):
        assert forbidden not in rendered


def test_worker_build_receipt_projection_is_stable_across_real_path_bearing_preimages(
    tmp_path: Path,
) -> None:
    first_root = tmp_path.resolve() / "checkout-a"
    second_root = tmp_path.resolve() / "checkout-b"
    first = _runtime_identity(first_root)
    first_provenance = first.build_provenance

    def path_bearing_digest(root: Path, filename: str) -> str:
        content = f"command={root}/toolchain/cxx;output={root}/{filename}\n".encode()
        return hashlib.sha256(content).hexdigest()

    first_path_digests = {
        field: path_bearing_digest(first_root, field)
        for field in (
            "cmake_cache_sha256",
            "compile_commands_sha256",
            "build_ninja_sha256",
            "rules_ninja_sha256",
            "openfhe_config_sha256",
            "openfhe_cmake_cache_sha256",
            "openfhe_compile_commands_sha256",
            "openfhe_install_manifest_sha256",
        )
    }
    second_path_digests = {
        field: path_bearing_digest(second_root, field)
        for field in first_path_digests
    }
    assert first_path_digests != second_path_digests
    first = replace(
        first,
        build_provenance=replace(first_provenance, **first_path_digests),
    )
    relocated = replace(
        first,
        compiler_path=str(second_root / "toolchain/cxx"),
        build_provenance=replace(
            first.build_provenance,
            cmake_path=str(second_root / "toolchain/cmake"),
            openfhe_directory=str(second_root / "openfhe/lib/OpenFHE"),
            **second_path_digests,
        ),
        linked_libraries=(
            replace(
                first.linked_libraries[0],
                resolved_path=str(second_root / "openfhe/lib/libOPENFHEpke.so"),
            ),
        ),
    )

    assert first.build_provenance != relocated.build_provenance
    assert runtime.project_openfhe_worker_build_receipt(first) == (
        runtime.project_openfhe_worker_build_receipt(relocated)
    )


@pytest.mark.parametrize(
    "changed",
    (
        "runner_sha256",
        "compiler_flags",
        "openfhe_source_commit",
        "linked_library_sha256",
    ),
)
def test_worker_build_receipt_projection_binds_each_stable_build_domain(
    tmp_path: Path,
    changed: str,
) -> None:
    identity = _runtime_identity(tmp_path)
    if changed == "runner_sha256":
        modified = replace(identity, runner_sha256="a" * 64)
    elif changed == "compiler_flags":
        modified = replace(identity, compiler_flags=("-O2",))
    elif changed == "openfhe_source_commit":
        modified = replace(
            identity,
            build_provenance=replace(
                identity.build_provenance,
                openfhe_source_commit="9" * 40,
            ),
        )
    else:
        modified = replace(
            identity,
            linked_libraries=(
                replace(identity.linked_libraries[0], sha256="b" * 64),
            ),
        )

    assert runtime.openfhe_worker_build_receipt_sha256(modified) != (
        runtime.openfhe_worker_build_receipt_sha256(identity)
    )


def test_worker_build_receipt_projection_canonicalizes_dependency_order(
    tmp_path: Path,
) -> None:
    identity = _runtime_identity(tmp_path)
    first = identity.linked_libraries[0]
    second = replace(
        first,
        load_name="libOPENFHEcore.so",
        sha256="c" * 64,
        binary_id="8" * 40,
        soname="libOPENFHEcore.so",
        needed_load_names=("libm.so.6", "libc.so.6"),
    )
    system_m = replace(
        first,
        load_name="libm.so.6",
        resolved_path="/usr/lib/x86_64-linux-gnu/libm.so.6",
        sha256="8" * 64,
        binary_id="9" * 40,
        soname="libm.so.6",
        needed_load_names=("libc.so.6",),
    )
    system_c = replace(
        first,
        load_name="libc.so.6",
        resolved_path="/usr/lib/x86_64-linux-gnu/libc.so.6",
        sha256="a" * 64,
        binary_id="b" * 40,
        soname="libc.so.6",
        needed_load_names=(),
    )
    forward = replace(
        identity,
        source_sha256=(("z-source", "d" * 64), ("a-source", "e" * 64)),
        linked_libraries=(first, second, system_m, system_c),
        linked_system_library_load_names=("libm.so.6", "libc.so.6"),
    )
    reversed_order = replace(
        forward,
        source_sha256=tuple(reversed(forward.source_sha256)),
        linked_libraries=tuple(reversed(forward.linked_libraries)),
        linked_system_library_load_names=tuple(
            reversed(forward.linked_system_library_load_names)
        ),
    )

    assert runtime.project_openfhe_worker_build_receipt(forward) == (
        runtime.project_openfhe_worker_build_receipt(reversed_order)
    )


@pytest.mark.parametrize("duplicate", ("source", "library", "unknown-system"))
def test_worker_build_receipt_projection_rejects_duplicate_or_overlapping_names(
    tmp_path: Path,
    duplicate: str,
) -> None:
    identity = _runtime_identity(tmp_path)
    if duplicate == "source":
        changed = replace(
            identity,
            source_sha256=(identity.source_sha256[0], identity.source_sha256[0]),
        )
    elif duplicate == "library":
        changed = replace(
            identity,
            linked_libraries=(identity.linked_libraries[0],) * 2,
        )
    else:
        changed = replace(
            identity,
            linked_system_library_load_names=("libabsent.so.1",),
        )

    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="closed partition"):
        runtime.project_openfhe_worker_build_receipt(changed)


def test_worker_build_receipt_system_bytes_are_dynamic_but_load_names_are_stable(
    tmp_path: Path,
) -> None:
    identity = _runtime_identity(tmp_path)
    openfhe = identity.linked_libraries[0]
    system = replace(
        openfhe,
        load_name="libgomp.so.1",
        resolved_path="/usr/lib/x86_64-linux-gnu/libgomp.so.1",
        sha256="8" * 64,
        binary_id="9" * 40,
        soname="libgomp.so.1",
        needed_load_names=("libc.so.6",),
    )
    with_system = replace(
        identity,
        linked_libraries=(openfhe, system),
        linked_system_library_load_names=(system.load_name,),
    )
    changed_instance = replace(
        with_system,
        linked_libraries=(
            openfhe,
            replace(
                system,
                resolved_path="/lib64/libgomp.so.1",
                sha256="a" * 64,
                device=303,
                inode=404,
                binary_id="b" * 40,
            ),
        ),
    )

    assert with_system != changed_instance
    assert runtime.project_openfhe_worker_build_receipt(with_system) == (
        runtime.project_openfhe_worker_build_receipt(changed_instance)
    )
    added_system_name = replace(
        with_system,
        linked_libraries=(
            *with_system.linked_libraries,
            replace(
                system,
                load_name="libquadmath.so.0",
                soname="libquadmath.so.0",
                sha256="c" * 64,
                binary_id="d" * 40,
            ),
        ),
        linked_system_library_load_names=("libgomp.so.1", "libquadmath.so.0"),
    )
    assert runtime.openfhe_worker_build_receipt_sha256(added_system_name) != (
        runtime.openfhe_worker_build_receipt_sha256(with_system)
    )


def _runtime_mapping_admission(
    *,
    pid: int = 101,
    process_start_time_ticks: int = 202,
    path: str = "/opt/worker/openfhe_query_runner",
    device: int = 1,
    inode: int = 2,
) -> runtime_admission.OpenFHERuntimeMappingAdmission:
    admitted = runtime_admission.AdmittedExecutableFile(
        path=path,
        device=device,
        inode=inode,
        mode=0o755,
        byte_count=1,
        sha256="1" * 64,
        binary_format="elf-v1",
        binary_id="2" * 40,
    )
    ready = runtime_admission.OpenFHEProcessMappingSnapshot(
        stage="READY",
        pid=pid,
        process_start_time_ticks=process_start_time_ticks,
        raw_maps_byte_count=10,
        raw_maps_sha256="3" * 64,
        proc_map_entry_count=1,
        executable_map_entry_count=1,
        admitted_executable_files=(admitted,),
        kernel_executable_mappings=(),
        admitted_executable_file_set_sha256="4" * 64,
        executable_mapping_set_sha256="5" * 64,
    )
    done = replace(
        ready,
        stage="DONE",
        raw_maps_sha256="6" * 64,
    )
    return runtime_admission.OpenFHERuntimeMappingAdmission(
        ready=ready,
        done=done,
        admitted_executable_file_set_sha256=ready.admitted_executable_file_set_sha256,
        executable_mapping_set_sha256=ready.executable_mapping_set_sha256,
    )


def _runtime_receipt(
    tmp_path: Path,
    *,
    mapping: runtime_admission.OpenFHERuntimeMappingAdmission | None = None,
) -> runtime.OpenFHEQueryRuntimeReceipt:
    return runtime.OpenFHEQueryRuntimeReceipt(
        runner=_runtime_identity(tmp_path),
        execution_kind="ordinary",
        authorization=OrdinaryExecutionAuthorizationReceipt(
            query_id="query-1",
            version_id="v00000001",
            ledger_commitment_token="commitment-1",
            query_preparation_sha256="7" * 64,
            execution_binding_digest="8" * 64,
            authorization_transition_sha256="9" * 64,
        ),
        day2_key_plan_authorization=None,
        request_sha256="a" * 64,
        request_byte_count=1,
        result_sha256="b" * 64,
        result_byte_count=1,
        elapsed_ns=10,
        timeout_seconds=60,
        peak_resident_memory_bytes=20,
        resident_memory_limit_bytes=100,
        peak_scratch_bytes=30,
        scratch_limit_bytes=100,
        stdout_sha256="c" * 64,
        stdout_byte_count=1,
        stderr_sha256="d" * 64,
        stderr_byte_count=0,
        serialized_object_count=1,
        serialized_object_bytes=40,
        host_identity_sha256="e" * 64,
        operating_system_identity="Linux-6.8.0-x86_64",
        cpu_affinity=(0, 1),
        runtime_mapping_admission=(
            _runtime_mapping_admission() if mapping is None else mapping
        ),
    )


def _runtime_identity_policy(
    tmp_path: Path,
) -> runtime.OpenFHEWorkerRuntimeIdentityPolicy:
    expected_build_identity = (
        "453131210d0ec4721ab7ece3e13c601d4c37ec8dbab481aae72663519d9c80bb"
    )
    assert runtime.openfhe_worker_build_receipt_sha256(
        _runtime_identity(tmp_path)
    ) == expected_build_identity
    return runtime.OpenFHEWorkerRuntimeIdentityPolicy(
        worker_adapter_schema_version=(
            "dynamic-cssc-publication-day1b-worker-adapter-v1"
        ),
        worker_build_identity_sha256=expected_build_identity,
        operating_system_identity="Linux-6.8.0-x86_64",
        cpu_affinity_policy_token=runtime.OPENFHE_CPU_AFFINITY_POLICY,
        required_cpu_affinity=(0, 1),
    )


def test_expected_and_observed_worker_runtime_identity_are_independently_equal(
    tmp_path: Path,
) -> None:
    receipt = _runtime_receipt(tmp_path)
    policy = _runtime_identity_policy(tmp_path)

    expected = runtime.project_expected_openfhe_worker_runtime_identity(policy)
    observed = runtime.project_observed_openfhe_worker_runtime_identity(
        policy,
        receipt,
    )

    assert observed == expected
    assert runtime.openfhe_worker_runtime_identity_sha256(observed) == (
        runtime.openfhe_worker_runtime_identity_sha256(expected)
    )
    assert expected["schema_version"] == (
        runtime.OPENFHE_WORKER_RUNTIME_IDENTITY_SCHEMA
    )
    assert expected["runtime_mapping_policy"] == (
        "linux-ready-done-executable-closure-v1"
    )
    assert expected["dynamic_loader_environment_policy"] == "clear-v1"
    assert expected["cpu_affinity_policy"] == runtime.OPENFHE_CPU_AFFINITY_POLICY
    assert "required_cpu_affinity" not in expected
    assert [0, 1] not in expected.values()


@pytest.mark.parametrize("mutation", ("extra-key", "schema"))
def test_worker_runtime_identity_digest_rejects_noncanonical_projection(
    tmp_path: Path,
    mutation: str,
) -> None:
    document = runtime.project_expected_openfhe_worker_runtime_identity(
        _runtime_identity_policy(tmp_path)
    )
    if mutation == "extra-key":
        document["caller_fact"] = True
        message = "keys are not exact"
    else:
        document["schema_version"] = "retargeted-runtime-identity-v1"
        message = "projection is malformed"

    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match=message):
        runtime.openfhe_worker_runtime_identity_sha256(document)


def test_worker_runtime_identity_policy_rejects_non_linux_identity() -> None:
    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="policy is malformed"):
        runtime.OpenFHEWorkerRuntimeIdentityPolicy(
            worker_adapter_schema_version=(
                "dynamic-cssc-publication-day1b-worker-adapter-v1"
            ),
            worker_build_identity_sha256="0" * 64,
            operating_system_identity="Darwin-25.0.0-arm64",
            cpu_affinity_policy_token=runtime.OPENFHE_CPU_AFFINITY_POLICY,
            required_cpu_affinity=(0, 1),
        )


def test_worker_runtime_identity_policy_rejects_an_unfrozen_affinity_token() -> None:
    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match="policy is malformed"):
        runtime.OpenFHEWorkerRuntimeIdentityPolicy(
            worker_adapter_schema_version=(
                "dynamic-cssc-publication-day1b-worker-adapter-v1"
            ),
            worker_build_identity_sha256="0" * 64,
            operating_system_identity="Linux-6.8.0-x86_64",
            cpu_affinity_policy_token="caller-selected-policy-v1",
            required_cpu_affinity=(0, 1),
        )


def test_worker_runtime_identity_excludes_dynamic_process_and_measurement_facts(
    tmp_path: Path,
) -> None:
    receipt = _runtime_receipt(tmp_path)
    policy = _runtime_identity_policy(tmp_path)
    changed_mapping = _runtime_mapping_admission(
        pid=303,
        process_start_time_ticks=404,
        path="/relocated/openfhe_query_runner",
        device=505,
        inode=606,
    )
    changed = replace(
        receipt,
        runner=replace(
            receipt.runner,
            runner_device=707,
            runner_inode=808,
            compiler_path="/relocated/cxx",
            build_identity_sha256="f" * 64,
        ),
        request_sha256="0" * 64,
        result_sha256="1" * 64,
        elapsed_ns=999,
        peak_resident_memory_bytes=888,
        peak_scratch_bytes=777,
        host_identity_sha256="2" * 64,
        runtime_mapping_admission=changed_mapping,
    )

    assert runtime.project_observed_openfhe_worker_runtime_identity(
        policy,
        changed,
    ) == runtime.project_observed_openfhe_worker_runtime_identity(policy, receipt)
    rendered = _canonical_line(
        runtime.project_observed_openfhe_worker_runtime_identity(policy, changed)
    )
    for forbidden in (
        b"host_identity",
        b"elapsed",
        b"resident",
        b"scratch",
        b"request",
        b"result",
        b"pid",
        b"process_start",
        b"raw_maps",
        b"/relocated",
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("mapping", "mapping continuity"),
        ("operating-system", "operating system"),
        ("cpu-affinity", "CPU affinity"),
        ("worker-build", "worker build"),
    ),
)
def test_observed_worker_runtime_identity_rejects_policy_mismatch(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    receipt = _runtime_receipt(tmp_path)
    policy = _runtime_identity_policy(tmp_path)
    if mutation == "mapping":
        changed = replace(receipt, runtime_mapping_admission=None)
    elif mutation == "operating-system":
        changed = replace(receipt, operating_system_identity="Linux-6.9.0-x86_64")
    elif mutation == "cpu-affinity":
        changed = replace(receipt, cpu_affinity=(0,))
    else:
        changed = replace(
            receipt,
            runner=replace(receipt.runner, runner_sha256="0" * 64),
        )

    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match=message):
        runtime.project_observed_openfhe_worker_runtime_identity(policy, changed)


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
    system_library = repository / "lib" / "libc.so.6"
    _write(library, b"test-openfhe-shared-library-v1")
    _write(system_library, b"test-system-shared-library-v1")
    monkeypatch.setattr(
        runtime,
        "_inspect_linked_library_paths",
        lambda _runner, **_kwargs: (
            "test-linked-library-inspector-v1",
            (
                ("libOPENFHEpke.so", library),
                ("libc.so.6", system_library),
            ),
            ("libc.so.6",),
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
    assert identity.linked_system_library_load_names == ("libc.so.6",)
    assert tuple(item.load_name for item in identity.linked_libraries) == (
        "libOPENFHEpke.so",
        "libc.so.6",
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
    linux_install_root = root / "openfhe-install"
    linux_library = linux_install_root / "lib" / "libOPENFHEpke.so.1"
    linux_system_library = root / "system" / "libc.so.6"
    darwin_library = root / "darwin" / "libOPENFHEpke.1.dylib"
    _write(runner, b"test-runner", executable=True)
    _write(linux_library, b"linux-openfhe")
    _write(linux_system_library, b"linux-system")
    _write(darwin_library, b"darwin-openfhe")
    monkeypatch.setattr(runtime.shutil, "which", lambda *_args, **_kwargs: "/tool")
    monkeypatch.setattr(
        runtime,
        "_is_linux_distribution_library_path",
        lambda path: path == linux_system_library,
    )

    monkeypatch.setattr(
        runtime,
        "_linkage_tool_output",
        lambda _arguments, **_kwargs: (
            "linux-vdso.so.1 (0x0001)\n"
            f"libOPENFHEpke.so.1 => {linux_library} (0x0002)\n"
            f"libc.so.6 => {linux_system_library} (0x0003)\n"
        ),
    )
    linux_format, linux_entries, linux_system = runtime._linux_linked_library_paths(
        runner,
        pinned_install_root=linux_install_root,
    )
    assert linux_format == "linux-ldd-direct-and-transitive-v2"
    assert linux_entries == (
        ("libOPENFHEpke.so.1", linux_library),
        ("libc.so.6", linux_system_library),
    )
    assert linux_system == ("libc.so.6",)

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


def test_linux_distribution_library_classification_is_path_bounded() -> None:
    assert runtime._is_linux_distribution_library_path(
        Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
    )
    assert runtime._is_linux_distribution_library_path(
        Path("/lib64/ld-linux-x86-64.so.2"),
    )
    assert not runtime._is_linux_distribution_library_path(
        Path("/opt/attacker/libc.so.6"),
    )
    assert not runtime._is_linux_distribution_library_path(
        Path("/usr/local/lib/libunexpected.so.1"),
    )


def test_linux_linkage_rejects_install_root_ancestor_of_distribution_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_root = tmp_path.resolve()
    distribution_root = install_root / "usr/lib"
    distribution_root.mkdir(parents=True)
    runner = install_root / "bin/openfhe_query_runner"
    _write(runner, b"runner", executable=True)
    monkeypatch.setattr(
        runtime,
        "_LINUX_DISTRIBUTION_LIBRARY_ROOTS",
        (distribution_root,),
    )

    with pytest.raises(
        runtime.OpenFHEQueryRuntimeError,
        match="install root overlaps the Linux distribution roots",
    ):
        runtime._linux_linked_library_paths(
            runner,
            pinned_install_root=install_root,
        )


@pytest.mark.parametrize(
    ("load_name", "location", "message"),
    (
        (
            "libOPENFHEpke.so.1",
            "system",
            "OpenFHE library resolved through a Linux distribution root",
        ),
        (
            "libunexpected.so.1",
            "outside",
            "outside the pinned OpenFHE and distribution roots",
        ),
    ),
)
def test_linux_linkage_classification_rejects_untrusted_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    load_name: str,
    location: str,
    message: str,
) -> None:
    root = tmp_path.resolve()
    runner = root / "bin/openfhe_query_runner"
    install_root = root / "openfhe-install"
    install_root.mkdir()
    target = root / location / load_name
    _write(runner, b"runner", executable=True)
    _write(target, b"library")
    monkeypatch.setattr(runtime.shutil, "which", lambda *_args, **_kwargs: "/tool")
    monkeypatch.setattr(
        runtime,
        "_linkage_tool_output",
        lambda _arguments, **_kwargs: f"{load_name} => {target} (0x0001)\n",
    )
    monkeypatch.setattr(
        runtime,
        "_is_linux_distribution_library_path",
        lambda path: path.is_relative_to(root / "system"),
    )

    with pytest.raises(runtime.OpenFHEQueryRuntimeError, match=message):
        runtime._linux_linked_library_paths(
            runner,
            pinned_install_root=install_root,
        )


def test_dynamic_mapping_admission_retains_system_and_non_system_files(
    tmp_path: Path,
) -> None:
    runner = tmp_path.resolve() / "openfhe_query_runner"
    _write(runner, b"runner", executable=True)
    identity = _runtime_identity(tmp_path)
    openfhe = replace(
        identity.linked_libraries[0],
        resolved_path=str(tmp_path.resolve() / "libOPENFHEpke.so"),
    )
    system = replace(
        openfhe,
        load_name="libc.so.6",
        resolved_path=str(tmp_path.resolve() / "libc.so.6"),
        sha256="8" * 64,
        binary_id="9" * 40,
        soname="libc.so.6",
        needed_load_names=(),
    )
    with_system = replace(
        identity,
        runner_device=runner.stat().st_dev,
        runner_inode=runner.stat().st_ino,
        runner_mode=0o755,
        linked_libraries=(openfhe, system),
        linked_system_library_load_names=(system.load_name,),
    )

    admitted = runtime._admitted_executable_files(runner, with_system)

    assert {entry.path for entry in admitted} == {
        str(runner),
        openfhe.resolved_path,
        system.resolved_path,
    }


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


def test_failed_anchored_launch_consumes_both_authorities_and_cleans_scratch(
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
    key_plan_capability = _anchored_day2_key_plan()
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
        runtime.execute_day2_anchored_openfhe_query(
            bundle,
            prepared,
            ledger=ledger,
            expected_output=(10,),
            day2_key_plan_capability=key_plan_capability,
            repository_root=ROOT,
            runner_relative_path="build/cpp/openfhe_query_runner",
            scratch_root=scratch,
            timeout_seconds=10,
            resident_memory_limit_bytes=1024 * 1024,
            scratch_limit_bytes=1024 * 1024,
        )

    assert not scratch.exists()
    assert key_plan_capability._binding is None
    with pytest.raises(Day2OpenFHEKeyPlanError, match="absent or consumed"):
        day2_key_plan.claim_day2_openfhe_key_plan(key_plan_capability)
    with pytest.raises(OrdinaryQueryLifecycleError, match="consumption failed"):
        authorize_ordinary_execution(bundle, prepared, ledger=ledger)


def test_failed_anchored_strong_launch_uses_same_consumption_seam(
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
    key_plan_capability = _anchored_day2_key_plan()
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
        runtime.execute_day2_anchored_strong_openfhe_query(
            bundle,
            prepared,
            ledger=ledger,
            expected_output=(31,),
            day2_key_plan_capability=key_plan_capability,
            repository_root=ROOT,
            runner_relative_path="build/cpp/openfhe_query_runner",
            scratch_root=scratch,
            timeout_seconds=10,
            resident_memory_limit_bytes=1024 * 1024,
            scratch_limit_bytes=1024 * 1024,
        )

    assert not scratch.exists()
    assert key_plan_capability._binding is None
    with pytest.raises(Day2OpenFHEKeyPlanError, match="absent or consumed"):
        day2_key_plan.claim_day2_openfhe_key_plan(key_plan_capability)
    with pytest.raises(StrongExecutionError, match="consumption failed"):
        authorize_strong_execution(bundle, prepared, ledger=ledger)
