from __future__ import annotations

import hashlib
import inspect
import io
import json
import stat
import subprocess
import zipfile
from copy import deepcopy
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.day2_calibration_authority as authority_module
from dynamic_cssc.day2_calibration_authority import (
    Day2CalibrationAuthority,
    Day2CalibrationAuthorityError,
    Day2CalibrationInspection,
    Day2CalibrationProfileAuthority,
    inspect_day2_calibration_archive,
    repository_day2_calibration_authority,
    repository_day2_calibration_profile_authority,
)
from dynamic_cssc.evidence_compatibility import (
    EvidenceRole,
    RoleSourceAttestation,
    repository_behavior_paths,
)
from dynamic_cssc.publication_statistics import calibration_operation_order

PRIMITIVE_NAMES = (
    "client_merge",
    "client_reorder_element",
    "decrypt",
    "deserialize_ciphertext",
    "encode",
    "encrypt",
    "eval_add_ciphertext",
    "eval_mult_plaintext_mask",
    "eval_mult_with_relinearization",
    "eval_rotate",
    "mask_map_element",
    "mask_random_element",
    "query_vector_pack",
    "serialize_ciphertext",
)
FIXED_CANDIDATE_IDS = (
    "padding-reuse",
    "mini-cssc-delta",
    "packed-coo-client-lane-delta/capacity=128",
    "strict-local-repack",
    "reserved-slack/beta=0",
    "reserved-slack/beta=0.05",
    "reserved-slack/beta=0.1",
    "reserved-slack/beta=0.2",
    "reserved-slack/beta=0.4",
    "periodic-repack/windows=1",
    "periodic-repack/windows=4",
    "periodic-repack/windows=16",
    "periodic-repack/windows=64",
    "packed-coo-cloud-segmented-delta/segment-width=128",
)
REFERENCE_CANDIDATE_IDS = tuple(
    candidate_id
    for candidate_id in FIXED_CANDIDATE_IDS
    if candidate_id != "packed-coo-client-lane-delta/capacity=128"
)


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
    )


def _day2_anchor_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "day2-anchor-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "day2-anchor@example.invalid")
    _git(repository, "config", "user.name", "Day2 Anchor Test")
    source_root = Path(__file__).resolve().parents[1]
    for relative_path in (
        "config/day2-calibration-profile-anchors.json",
        "config/day2-calibration-anchors.json",
        "config/evidence-compatibility-anchors.json",
    ):
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / relative_path).read_bytes())
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "install Day2 data anchors")
    return repository


PAYLOAD_FILENAMES = (
    "RUN_STATUS.json",
    "source-provenance.json",
    "workflow-provenance.json",
    "host-profile.json",
    "openfhe-build.json",
    "contract-bindings.json",
    "rotation-key-plan.json",
    "generated-key-inventory.json",
    "operation-profile-set.json",
    "raw-measurement-blocks.json",
    "runtime-isolation-receipt.json",
    "producer-validation.json",
)
MEASUREMENT_STOP_RULE = "exactly-14-whole-blocks-outcome-independent-no-optional-stopping"
OPERATION_ORDER_METHOD = "domain-separated-shake256-counter-rejection-fisher-yates-v1"


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _fraction_text(value: Fraction) -> str:
    denominator = value.denominator
    reduced = denominator
    twos = 0
    while reduced % 2 == 0:
        reduced //= 2
        twos += 1
    fives = 0
    while reduced % 5 == 0:
        reduced //= 5
        fives += 1
    if reduced != 1:
        return f"{value.numerator}/{value.denominator}"
    places = max(twos, fives)
    scaled = value.numerator * 2 ** (places - twos) * 5 ** (places - fives)
    whole, fractional = divmod(scaled, 10**places)
    if fractional == 0:
        return str(whole)
    return f"{whole}.{fractional:0{places}d}".rstrip("0")


def _calibration_projection(payloads: dict[str, object]) -> dict[str, object]:
    raw = payloads["raw-measurement-blocks.json"]
    names = raw["primitive_names"]
    projected_blocks = []
    for block in raw["blocks"]:
        samples = {sample["primitive_name"]: sample for sample in block["samples"]}
        seconds_by_primitive = {}
        for name in names:
            cases = samples[name]["cases"]
            seconds_by_primitive[name] = _fraction_text(
                max(
                    Fraction(case["elapsed_ns"], case["operation_count"] * 1_000_000_000)
                    for case in cases
                )
            )
        projected_blocks.append(
            {
                "schema_version": "dynamic-cssc-publication-calibration-block-v1",
                "block_ordinal": block["ordinal"],
                "operation_order": block["operation_order"],
                "seconds_by_primitive": seconds_by_primitive,
            }
        )
    return {
        "schema_version": "dynamic-cssc-publication-calibration-v3",
        "primitive_names": names,
        "operation_order_seed": raw["operation_order_seed"],
        "measurement_block_count": raw["measurement_block_count"],
        "measurement_stop_rule": raw["measurement_stop_rule"],
        "raw_repetition_blocks": projected_blocks,
    }


def _profile(primitive_name: str) -> dict[str, object]:
    rotation_cases = ["index=-1", "index=1", "index=2"]
    if primitive_name == "eval_rotate":
        case_ids = rotation_cases
    elif primitive_name == "encrypt":
        case_ids = ["admitted-case-a", "admitted-case-b"]
    else:
        case_ids = ["admitted-case"]
    return {
        "primitive_name": primitive_name,
        "profile_id": f"publication/{primitive_name}/v1",
        "setup_scope": "outside-timed-region",
        "timed_operation": f"one admitted {primitive_name} operation",
        "case_aggregation_rule": (
            "per-block-max-over-all-exact-indices"
            if primitive_name == "eval_rotate"
            else "per-block-max-over-all-admitted-cases"
        ),
        "warmup_policy": "complete-profile-blocks-before-measurement",
        "measurement_policy": "elapsed-ns-divided-by-operation-count",
        "includes_relinearization": primitive_name == "eval_mult_with_relinearization",
        "randomness_policy": (
            "operating-system-csprng-unbiased-rejection-sampling"
            if primitive_name == "mask_random_element"
            else "not-applicable"
        ),
        "correctness_check_sha256": "4" * 64,
        "cases": [
            {
                "case_id": case_id,
                "unit_definition": f"one {primitive_name} unit",
                "input_fixture_contract_sha256": "5" * 64,
                "operation_count": (
                    1
                    if primitive_name.startswith("eval_")
                    else 4096
                    if case_id == "admitted-case-b"
                    else 1024
                ),
            }
            for case_id in case_ids
        ],
    }


def _artifact_behavior_inventory(source_sha: str) -> dict[str, object]:
    entries = [
        {
            "mode": "100644",
            "object_id": "2" * 40,
            "object_type": "blob",
            "path": path,
        }
        for path in repository_behavior_paths(EvidenceRole.DAY2)
    ]
    behavior_set = {
        "behavior_set_schema_version": "dynamic-cssc-day2-behavior-set-v3",
        "entries": entries,
        "role": "day2",
    }
    return {
        "behavior_set_schema_version": "dynamic-cssc-day2-behavior-set-v3",
        "behavior_set_sha256": _sha256(_canonical(behavior_set)),
        "entries": entries,
        "role": "day2",
        "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
        "source_git_sha": source_sha,
    }


def _valid_payloads() -> dict[str, object]:
    source_sha = "a" * 40
    behavior_inventory = _artifact_behavior_inventory(source_sha)
    workflow = {
        "schema_version": "dynamic-cssc-publication-day2-workflow-provenance-v1",
        "repository": "example/dynamic-cssc-spmv",
        "repository_id": 123,
        "workflow_path": ".github/workflows/day2-publication-calibration.yml",
        "workflow_file_sha256": "1" * 64,
        "run_id": 456,
        "run_attempt": 2,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "head_sha": source_sha,
        "artifact_name": "r3-day2-calibration-test",
    }
    profiles = [_profile(name) for name in PRIMITIVE_NAMES]
    profiles_by_name = {profile["primitive_name"]: profile for profile in profiles}
    raw_blocks = []
    for block in range(14):
        operation_order = calibration_operation_order(block)
        raw_blocks.append(
            {
                "ordinal": block,
                "operation_order": list(operation_order),
                "samples": [
                    {
                        "primitive_name": primitive_name,
                        "cases": [
                            {
                                "case_id": case["case_id"],
                                "elapsed_ns": 1000 + block + case_index * 500,
                                "operation_count": case["operation_count"],
                            }
                            for case_index, case in enumerate(
                                profiles_by_name[primitive_name]["cases"]
                            )
                        ],
                    }
                    for primitive_name in operation_order
                ],
            }
        )
    rotation_plan = {
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        "inventory_source_schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "day1a_authority_receipt_sha256": "6" * 64,
        "day1a_inventory_sha256": "7" * 64,
        "effective_slots": 4096,
        "required_exact_indices": [-1, 1, 2],
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": [-1, 1, 2],
        "composite_decompositions": [],
        "eval_rotate_case_ids": ["index=-1", "index=1", "index=2"],
    }
    generated_key_inventory = {
        "schema_version": "dynamic-cssc-publication-generated-key-inventory-v1",
        "rotation_key_plan_sha256": _sha256(_canonical(rotation_plan)),
        "generated_exact_indices": [-1, 1, 2],
        "serialized_rotation_key_inventory_sha256": "8" * 64,
        "serialized_rotation_key_bytes": 12345,
        "eval_mult_key_generated": True,
        "serialized_eval_mult_key_sha256": "9" * 64,
        "serialized_eval_mult_key_bytes": 23456,
    }
    contract_bindings = {
        "schema_version": "dynamic-cssc-publication-day2-contract-bindings-v1",
        "experiment_contract_sha256": "b" * 64,
        "day1_candidate_registration_receipt_sha256": "c" * 64,
        "candidate_catalog_schema_version": "dynamic-cssc-day1-candidate-catalog-v1",
        "candidate_catalog_sha256": "d" * 64,
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": ["packed-coo-client-lane-delta/capacity=128"],
        "day1a_count_bundle_schema_version": "dynamic-cssc-day1a-count-bundle-v1",
        "day1a_count_bundle_sha256": "e" * 64,
        "heldout_record_schema_version": "dynamic-cssc-publication-heldout-record-v4",
        "primitive_accounting_schema_version": ("dynamic-cssc-publication-primitive-accounting-v1"),
        "primitive_accounting_mapping_sha256": "f" * 64,
        "serialized_object_accounting_schema_version": (
            "dynamic-cssc-publication-serialized-object-accounting-v1"
        ),
        "serialized_object_accounting_contract_sha256": "0" * 64,
        "day1a_rotation_inventory_sha256": rotation_plan["day1a_inventory_sha256"],
        "rotation_key_plan_sha256": _sha256(_canonical(rotation_plan)),
    }
    return {
        "RUN_STATUS.json": {
            "schema_version": "dynamic-cssc-publication-day2-run-status-v1",
            "status": "pass",
            "evidence_scope": "isolated-14-primitive-fixed-host-calibration-only",
            "producer_validation_passed": True,
            "formal_authority_granted": False,
            "complete_cost_claim_allowed": False,
            "mixed_circuit_parameter_claim_allowed": False,
            "r4_claim_allowed": False,
            "security_claim_allowed": False,
        },
        "source-provenance.json": {
            "schema_version": "dynamic-cssc-publication-day2-source-provenance-v2",
            "repository": workflow["repository"],
            "repository_id": workflow["repository_id"],
            "git_sha": source_sha,
            "git_tree": "b" * 40,
            "git_status_before_sha256": hashlib.sha256(b"").hexdigest(),
            "git_status_after_sha256": hashlib.sha256(b"").hexdigest(),
            "tracked_tree_clean_before": True,
            "tracked_tree_clean_after": True,
            "untracked_nonignored_clean_before": True,
            "untracked_nonignored_clean_after": True,
            "behavior_inventory": behavior_inventory,
        },
        "workflow-provenance.json": workflow,
        "host-profile.json": {
            "schema_version": "dynamic-cssc-publication-day2-host-profile-v2",
            "hardware": {
                "architecture": "x86_64",
                "cpu_vendor": "GenuineIntel",
                "cpu_model_name": "Publication Test CPU",
                "cpu_family": "6",
                "cpu_model": "143",
                "cpu_stepping": "8",
                "microcode": "0x1",
                "socket_count": 1,
                "physical_core_count": 2,
                "logical_cpu_count": 2,
                "memory_bytes": 8_589_934_592,
                "numa_topology_sha256": "5" * 64,
            },
            "os": {
                "distribution_id": "ubuntu",
                "distribution_version": "24.04",
                "kernel_release": "6.8.0",
                "kernel_cmdline_sha256": "6" * 64,
                "glibc_version": "2.39",
                "runner_image_identity_sha256": "7" * 64,
            },
            "compiler": {
                "path": "/usr/bin/g++",
                "vendor": "gcc",
                "version": "13.3.0",
                "target": "x86_64-linux-gnu",
            },
            "affinity": {
                "requested_cpu_list": [0, 1],
                "verified_probe_cpu_list": [0, 1],
                "probe_affinity_observation_stage": "pre-and-post-measurement-identical",
                "omp_num_threads": 2,
                "omp_proc_bind": "close",
                "omp_places": "cores",
                "per_block_allowed_cpu_sets": [[0, 1] for _ in range(14)],
            },
            "power": {
                "scaling_driver": "intel_pstate",
                "governor_by_cpu": [
                    {
                        "cpu": cpu,
                        "governor": "performance",
                        "min_khz": 1_000_000,
                        "max_khz": 3_000_000,
                        "energy_performance_preference": "performance",
                    }
                    for cpu in range(2)
                ],
                "turbo_state": "disabled",
                "power_source": "ac-observed-online",
                "thermal_throttle_counters_observable": True,
                "thermal_throttle_count_before": 3,
                "thermal_throttle_count_after": 3,
                "thermal_throttling_observed": False,
            },
        },
        "openfhe-build.json": {
            "schema_version": "dynamic-cssc-publication-day2-openfhe-build-v1",
            "repository": "https://github.com/openfheorg/openfhe-development.git",
            "version": "1.5.1",
            "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
            "source_git_tree": "c" * 40,
            "source_tree_clean": True,
            "source_tree_sha256": "8" * 64,
            "cmake_version": "3.30.0",
            "ninja_version": "1.12.1",
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
            "cmake_cache_sha256": "9" * 64,
            "compile_commands_sha256": "a" * 64,
            "installed_manifest_sha256": "b" * 64,
            "openfhe_shared_library_sha256": "c" * 64,
            "probe_source_sha256": "d" * 64,
            "probe_binary_sha256": "e" * 64,
            "manifest_generator_sha256": "f" * 64,
            "bundle_validator_sha256": "0" * 64,
            "compiler_path": "/usr/bin/g++",
            "compiler_vendor": "gcc",
            "compiler_version": "13.3.0",
            "compiler_target": "x86_64-linux-gnu",
            "effective_compile_flags": ["-O3", "-fopenmp"],
            "linked_library_inventory_sha256": "1" * 64,
        },
        "contract-bindings.json": contract_bindings,
        "rotation-key-plan.json": rotation_plan,
        "generated-key-inventory.json": generated_key_inventory,
        "operation-profile-set.json": {
            "schema_version": "dynamic-cssc-publication-operation-profile-set-v2",
            "primitive_names": list(PRIMITIVE_NAMES),
            "warmup_block_count": 3,
            "measurement_block_count": 14,
            "measurement_stop_rule": MEASUREMENT_STOP_RULE,
            "operation_order_seed": 2_026_082_302,
            "operation_order_method": OPERATION_ORDER_METHOD,
            "profiles": profiles,
        },
        "raw-measurement-blocks.json": {
            "schema_version": "dynamic-cssc-publication-raw-measurement-blocks-v1",
            "clock": "std::chrono::steady_clock",
            "clock_unit": "nanosecond",
            "primitive_names": list(PRIMITIVE_NAMES),
            "warmup_block_count": 3,
            "measurement_block_count": 14,
            "measurement_stop_rule": MEASUREMENT_STOP_RULE,
            "operation_order_seed": 2_026_082_302,
            "operation_order_method": OPERATION_ORDER_METHOD,
            "warmup_blocks": deepcopy(raw_blocks[:3]),
            "blocks": raw_blocks,
        },
        "runtime-isolation-receipt.json": {
            "schema_version": "dynamic-cssc-publication-day2-runtime-isolation-receipt-v1",
            "authority_state": "descriptive-live-capability-consumed-v1",
            "formal_authority_granted": False,
            "source_git_sha": source_sha,
            "fresh_detached_checkout": True,
            "clean_environment": True,
            "isolated_build_root": True,
            "caller_python_and_git_environment_removed": True,
            "profile_authority_consumed_once": True,
            "launcher_source_sha256": "1" * 64,
            "producer_source_sha256": "2" * 64,
            "isolation_checks": list(authority_module.DAY2_RUNTIME_ISOLATION_CHECKS),
        },
        "producer-validation.json": {
            "schema_version": "dynamic-cssc-publication-day2-producer-validation-v1",
            "status": "pass",
            "formal_authority_granted": False,
            "validator_source_sha256": "0" * 64,
            "manifest_generator_sha256": "f" * 64,
            "probe_source_sha256": "d" * 64,
            "probe_binary_sha256": "e" * 64,
            "raw_measurement_blocks_sha256": "PENDING",
            "operation_profile_set_sha256": "PENDING",
            "rotation_key_plan_sha256": "PENDING",
            "generated_key_inventory_sha256": "PENDING",
            "runtime_isolation_receipt_sha256": "PENDING",
            "calibration_projection_sha256": "PENDING",
            "candidate_catalog_sha256": contract_bindings["candidate_catalog_sha256"],
            "accounting_contract_sha256": contract_bindings["primitive_accounting_mapping_sha256"],
            "all_profiles_correct": True,
        },
    }


def _archive_bytes(
    *,
    mutate_payloads: object | None = None,
    extra_members: list[tuple[zipfile.ZipInfo | str, bytes]] | None = None,
    mutate_bound_payloads: object | None = None,
) -> tuple[bytes, dict[str, object]]:
    payloads = _valid_payloads()
    if mutate_payloads is not None:
        mutate_payloads(payloads)
    encoded = {name: _canonical(payload) for name, payload in payloads.items()}
    payloads["generated-key-inventory.json"]["rotation_key_plan_sha256"] = _sha256(
        encoded["rotation-key-plan.json"]
    )
    encoded["generated-key-inventory.json"] = _canonical(
        payloads["generated-key-inventory.json"]
    )
    encoded["contract-bindings.json"] = _canonical(payloads["contract-bindings.json"])
    payloads["contract-bindings.json"]["day1a_rotation_inventory_sha256"] = payloads[
        "rotation-key-plan.json"
    ]["day1a_inventory_sha256"]
    payloads["contract-bindings.json"]["rotation_key_plan_sha256"] = _sha256(
        encoded["rotation-key-plan.json"]
    )
    encoded["contract-bindings.json"] = _canonical(payloads["contract-bindings.json"])
    validation = payloads["producer-validation.json"]
    validation["raw_measurement_blocks_sha256"] = _sha256(encoded["raw-measurement-blocks.json"])
    validation["operation_profile_set_sha256"] = _sha256(encoded["operation-profile-set.json"])
    validation["rotation_key_plan_sha256"] = _sha256(encoded["rotation-key-plan.json"])
    validation["generated_key_inventory_sha256"] = _sha256(
        encoded["generated-key-inventory.json"]
    )
    validation["runtime_isolation_receipt_sha256"] = _sha256(
        encoded["runtime-isolation-receipt.json"]
    )
    validation["calibration_projection_sha256"] = _sha256(
        _canonical(_calibration_projection(payloads))
    )
    encoded["producer-validation.json"] = _canonical(validation)
    if mutate_bound_payloads is not None:
        mutate_bound_payloads(payloads)
        encoded = {name: _canonical(payload) for name, payload in payloads.items()}
    manifest = {
        "schema_version": "dynamic-cssc-publication-day2-calibration-evidence-v1",
        "evidence_scope": "isolated-14-primitive-fixed-host-calibration-only",
        "files": [
            {"path": name, "sha256": _sha256(encoded[name]), "bytes": len(encoded[name])}
            for name in PAYLOAD_FILENAMES
        ],
    }
    encoded["CALIBRATION-MANIFEST.json"] = _canonical(manifest)
    checksummed_names = sorted((*PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json"))
    encoded["SHA256SUMS"] = "".join(
        f"{_sha256(encoded[name])}  {name}\n" for name in checksummed_names
    ).encode("ascii")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in (*PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json", "SHA256SUMS"):
            info = zipfile.ZipInfo(name, date_time=(2026, 8, 23, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, encoded[name])
        for name_or_info, content in extra_members or []:
            archive.writestr(name_or_info, content)
    return buffer.getvalue(), payloads


def _github_metadata(archive_bytes: bytes) -> dict[str, object]:
    workflow = _valid_payloads()["workflow-provenance.json"]
    return {
        **workflow,
        "schema_version": "dynamic-cssc-publication-day2-github-artifact-metadata-v2",
        "artifact_id": 789,
        "artifact_digest": "sha256:" + "f" * 64,
        "inner_archive_sha256": _sha256(archive_bytes),
    }


def _valid_profile_anchor() -> tuple[dict[str, object], dict[str, object]]:
    payloads = _valid_payloads()
    profiles = payloads["operation-profile-set.json"]
    rotation_plan = payloads["rotation-key-plan.json"]
    contract = payloads["contract-bindings.json"]
    contract["day1a_rotation_inventory_sha256"] = rotation_plan["day1a_inventory_sha256"]
    contract["rotation_key_plan_sha256"] = _sha256(_canonical(rotation_plan))
    anchor = {
        "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-v3",
        "operation_profile_set_sha256": _sha256(_canonical(profiles)),
        "warmup_block_count": 3,
        "rotation_key_plan_sha256": _sha256(_canonical(rotation_plan)),
        "rotation_inventory_source_schema_version": ("dynamic-cssc-day1a-rotation-inventory-v1"),
        "day1a_authority_receipt_sha256": rotation_plan["day1a_authority_receipt_sha256"],
        "day1a_inventory_sha256": rotation_plan["day1a_inventory_sha256"],
        "contract_bindings_sha256": _sha256(_canonical(contract)),
        "experiment_contract_sha256": contract["experiment_contract_sha256"],
        "day1_candidate_registration_receipt_sha256": contract[
            "day1_candidate_registration_receipt_sha256"
        ],
        "candidate_catalog_schema_version": contract["candidate_catalog_schema_version"],
        "candidate_catalog_sha256": contract["candidate_catalog_sha256"],
        "day1a_count_bundle_schema_version": contract["day1a_count_bundle_schema_version"],
        "day1a_count_bundle_sha256": contract["day1a_count_bundle_sha256"],
        "heldout_record_schema_version": contract["heldout_record_schema_version"],
        "primitive_accounting_schema_version": contract["primitive_accounting_schema_version"],
        "primitive_accounting_mapping_sha256": contract["primitive_accounting_mapping_sha256"],
        "serialized_object_accounting_schema_version": contract[
            "serialized_object_accounting_schema_version"
        ],
        "serialized_object_accounting_contract_sha256": contract[
            "serialized_object_accounting_contract_sha256"
        ],
        "day1a_workflow_run_id": 123456,
        "day1a_artifact_id": 654321,
        "day1a_artifact_name": "r2-day1a-publication-" + "a" * 40 + "-20260821",
        "day1a_artifact_digest": "sha256:" + "3" * 64,
    }
    return anchor, payloads


def _valid_post_run_anchor(
    archive_bytes: bytes,
    payloads: dict[str, object],
) -> dict[str, object]:
    behavior_inventory = payloads["source-provenance.json"]["behavior_inventory"]
    return {
        "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-v4",
        "experiment_source_git_sha": "a" * 40,
        "experiment_behavior_set_schema_version": behavior_inventory["behavior_set_schema_version"],
        "experiment_behavior_set_sha256": behavior_inventory["behavior_set_sha256"],
        "artifact_behavior_inventory": deepcopy(behavior_inventory),
        "artifact_behavior_inventory_sha256": _sha256(_canonical(behavior_inventory)),
        "outer_archive_sha256": _sha256(archive_bytes),
        "raw_measurement_blocks_sha256": _sha256(
            _canonical(payloads["raw-measurement-blocks.json"])
        ),
        "operation_profile_set_sha256": _sha256(_canonical(payloads["operation-profile-set.json"])),
        "rotation_key_plan_sha256": _sha256(_canonical(payloads["rotation-key-plan.json"])),
        "generated_key_inventory_sha256": _sha256(
            _canonical(payloads["generated-key-inventory.json"])
        ),
        "runtime_isolation_receipt_sha256": _sha256(
            _canonical(payloads["runtime-isolation-receipt.json"])
        ),
        "contract_bindings_sha256": _sha256(_canonical(payloads["contract-bindings.json"])),
        "calibration_projection_sha256": _sha256(_canonical(_calibration_projection(payloads))),
    }


def _remove_last_primitive(payloads: dict[str, object]) -> None:
    profiles = payloads["operation-profile-set.json"]
    raw = payloads["raw-measurement-blocks.json"]
    removed = profiles["primitive_names"].pop()
    profiles["profiles"].pop()
    raw["primitive_names"].pop()
    for block in raw["blocks"]:
        block["operation_order"].remove(removed)
        block["samples"] = [
            sample for sample in block["samples"] if sample["primitive_name"] != removed
        ]


def _reduce_to_thirteen_blocks(payloads: dict[str, object]) -> None:
    profiles = payloads["operation-profile-set.json"]
    raw = payloads["raw-measurement-blocks.json"]
    host = payloads["host-profile.json"]
    profiles["measurement_block_count"] = 13
    raw["measurement_block_count"] = 13
    raw["blocks"].pop()
    host["affinity"]["per_block_allowed_cpu_sets"].pop()


def _set_zero_elapsed_time(payloads: dict[str, object]) -> None:
    raw = payloads["raw-measurement-blocks.json"]
    raw["blocks"][0]["samples"][0]["cases"][0]["elapsed_ns"] = 0


def _drop_one_complete_warmup_block(payloads: dict[str, object]) -> None:
    payloads["raw-measurement-blocks.json"]["warmup_blocks"].pop()


def _set_zero_warmup_elapsed_time(payloads: dict[str, object]) -> None:
    raw = payloads["raw-measurement-blocks.json"]
    raw["warmup_blocks"][0]["samples"][0]["cases"][0]["elapsed_ns"] = 0


def _swap_one_warmup_operation_order(payloads: dict[str, object]) -> None:
    block = payloads["raw-measurement-blocks.json"]["warmup_blocks"][0]
    block["operation_order"][0], block["operation_order"][1] = (
        block["operation_order"][1],
        block["operation_order"][0],
    )
    block["samples"][0], block["samples"][1] = block["samples"][1], block["samples"][0]


def _change_raw_operation_count(payloads: dict[str, object]) -> None:
    raw = payloads["raw-measurement-blocks.json"]
    raw["blocks"][0]["samples"][0]["cases"][0]["operation_count"] = 2048


def _use_nonterminating_exact_rational_timing(payloads: dict[str, object]) -> None:
    profile = next(
        item
        for item in payloads["operation-profile-set.json"]["profiles"]
        if item["primitive_name"] == "decrypt"
    )
    assert len(profile["cases"]) == 1
    profile["cases"][0]["operation_count"] = 3
    raw = payloads["raw-measurement-blocks.json"]
    for block in (*raw["warmup_blocks"], *raw["blocks"]):
        sample = next(item for item in block["samples"] if item["primitive_name"] == "decrypt")
        sample["cases"][0]["operation_count"] = 3
        sample["cases"][0]["elapsed_ns"] = 1


def _change_measurement_stop_rule(payloads: dict[str, object]) -> None:
    for name in ("operation-profile-set.json", "raw-measurement-blocks.json"):
        payloads[name]["measurement_stop_rule"] = "caller-stops-when-stable"


def _change_operation_order_seed(payloads: dict[str, object]) -> None:
    for name in ("operation-profile-set.json", "raw-measurement-blocks.json"):
        payloads[name]["operation_order_seed"] = 2_026_082_303


def _swap_one_block_operation_order(payloads: dict[str, object]) -> None:
    block = payloads["raw-measurement-blocks.json"]["blocks"][0]
    block["operation_order"][0], block["operation_order"][1] = (
        block["operation_order"][1],
        block["operation_order"][0],
    )
    block["samples"][0], block["samples"][1] = block["samples"][1], block["samples"][0]


def _change_projection_digest(payloads: dict[str, object]) -> None:
    payloads["producer-validation.json"]["calibration_projection_sha256"] = "2" * 64


def _disable_relinearization(payloads: dict[str, object]) -> None:
    profiles = payloads["operation-profile-set.json"]
    profile = next(
        item
        for item in profiles["profiles"]
        if item["primitive_name"] == "eval_mult_with_relinearization"
    )
    profile["includes_relinearization"] = False


def _drop_one_rotation_raw_case(payloads: dict[str, object]) -> None:
    raw = payloads["raw-measurement-blocks.json"]
    rotation_sample = next(
        item for item in raw["blocks"][0]["samples"] if item["primitive_name"] == "eval_rotate"
    )
    rotation_sample["cases"].pop()


def _change_generated_rotation_inventory(payloads: dict[str, object]) -> None:
    payloads["generated-key-inventory.json"]["generated_exact_indices"] = [-1, 1]


def _enable_composite_rotation_plan(payloads: dict[str, object]) -> None:
    plan = payloads["rotation-key-plan.json"]
    plan["composite_decompositions"] = [{"logical_index": 2, "primitive_indices": [1, 1]}]


def _add_modulo_alias_rotation(payloads: dict[str, object]) -> None:
    plan = payloads["rotation-key-plan.json"]
    plan["required_exact_indices"].append(4095)
    plan["planned_exact_indices"].append(4095)
    payloads["generated-key-inventory.json"]["generated_exact_indices"].append(4095)
    plan["eval_rotate_case_ids"].append("index=4095")
    profiles = payloads["operation-profile-set.json"]
    profile = next(item for item in profiles["profiles"] if item["primitive_name"] == "eval_rotate")
    profile["cases"].append(
        {
            "case_id": "index=4095",
            "unit_definition": "one eval_rotate unit",
            "input_fixture_contract_sha256": "5" * 64,
            "operation_count": 1,
        }
    )
    raw = payloads["raw-measurement-blocks.json"]
    for block in raw["blocks"]:
        sample = next(item for item in block["samples"] if item["primitive_name"] == "eval_rotate")
        sample["cases"].append(
            {
                "case_id": "index=4095",
                "elapsed_ns": 1000 + block["ordinal"],
                "operation_count": 1,
            }
        )


def _change_openfhe_commit(payloads: dict[str, object]) -> None:
    payloads["openfhe-build.json"]["commit"] = "f" * 40


def _enable_native_optimization(payloads: dict[str, object]) -> None:
    payloads["openfhe-build.json"]["cmake_flags"]["WITH_NATIVEOPT"] = "ON"


def _splice_probe_binary_identity(payloads: dict[str, object]) -> None:
    payloads["openfhe-build.json"]["probe_binary_sha256"] = "2" * 64


def _change_host_compiler(payloads: dict[str, object]) -> None:
    payloads["host-profile.json"]["compiler"]["version"] = "12.0.0"


def _change_effective_affinity(payloads: dict[str, object]) -> None:
    payloads["host-profile.json"]["affinity"]["verified_probe_cpu_list"] = [0]


def _make_power_state_unobservable(payloads: dict[str, object]) -> None:
    payloads["host-profile.json"]["power"]["scaling_driver"] = ""


def _make_thermal_counters_unobservable(payloads: dict[str, object]) -> None:
    power = payloads["host-profile.json"]["power"]
    power["thermal_throttle_counters_observable"] = False
    power["thermal_throttle_count_before"] = None
    power["thermal_throttle_count_after"] = None
    power["thermal_throttling_observed"] = None


def _hide_observed_thermal_throttling(payloads: dict[str, object]) -> None:
    power = payloads["host-profile.json"]["power"]
    power["thermal_throttle_count_after"] = 4
    power["thermal_throttling_observed"] = False


def _replace_fixed_candidate(payloads: dict[str, object]) -> None:
    payloads["contract-bindings.json"]["fixed_candidate_ids"][0] = "caller-candidate"


def _change_accounting_schema(payloads: dict[str, object]) -> None:
    payloads["contract-bindings.json"]["primitive_accounting_schema_version"] = (
        "caller-accounting-v1"
    )


def _claim_producer_authority(payloads: dict[str, object]) -> None:
    payloads["producer-validation.json"]["formal_authority_granted"] = True


def _change_generator_identity(payloads: dict[str, object]) -> None:
    payloads["producer-validation.json"]["manifest_generator_sha256"] = "2" * 64


def _change_rotation_binding(payloads: dict[str, object]) -> None:
    payloads["contract-bindings.json"]["day1a_rotation_inventory_sha256"] = "2" * 64


def _change_raw_blocks_binding(payloads: dict[str, object]) -> None:
    payloads["producer-validation.json"]["raw_measurement_blocks_sha256"] = "2" * 64


def _change_behavior_source_set_binding(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["behavior_set_sha256"] = "2" * 64


def _rehash_artifact_behavior_inventory(payloads: dict[str, object]) -> None:
    inventory = payloads["source-provenance.json"]["behavior_inventory"]
    inventory["behavior_set_sha256"] = _sha256(
        _canonical(
            {
                "behavior_set_schema_version": inventory["behavior_set_schema_version"],
                "entries": inventory["entries"],
                "role": inventory["role"],
            }
        )
    )


def _omit_artifact_behavior_entry(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["entries"].pop()
    _rehash_artifact_behavior_inventory(payloads)


def _add_artifact_behavior_entry(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["entries"].append(
        {
            "mode": "100644",
            "object_id": "3" * 40,
            "object_type": "blob",
            "path": "caller/extra.py",
        }
    )
    _rehash_artifact_behavior_inventory(payloads)


def _change_artifact_behavior_mode(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["entries"][0]["mode"] = "120000"
    _rehash_artifact_behavior_inventory(payloads)


def _change_artifact_behavior_type(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["entries"][0]["object_type"] = "tree"
    _rehash_artifact_behavior_inventory(payloads)


def _change_artifact_behavior_oid_shape(payloads: dict[str, object]) -> None:
    payloads["source-provenance.json"]["behavior_inventory"]["entries"][0]["object_id"] = (
        "not-a-git-object-id"
    )
    _rehash_artifact_behavior_inventory(payloads)


def _extend_host_schema(payloads: dict[str, object]) -> None:
    payloads["host-profile.json"]["caller_note"] = "trust me"


def _extend_openfhe_schema(payloads: dict[str, object]) -> None:
    payloads["openfhe-build.json"]["caller_attested"] = True


def _extend_contract_schema(payloads: dict[str, object]) -> None:
    payloads["contract-bindings.json"]["caller_candidate"] = "admit-me"


def _extend_producer_schema(payloads: dict[str, object]) -> None:
    payloads["producer-validation.json"]["caller_authority"] = True


def _with_member_mode(archive_bytes: bytes, target: str, mode: int) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(archive_bytes))
    buffer = io.BytesIO()
    with source, zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as destination:
        for source_info in source.infolist():
            info = zipfile.ZipInfo(source_info.filename, date_time=(2026, 8, 23, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (
                mode if source_info.filename == target else stat.S_IFREG | 0o600
            ) << 16
            destination.writestr(info, source.read(source_info.filename))
    return buffer.getvalue()


def _replace_member_content(archive_bytes: bytes, target: str, content: bytes) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(archive_bytes))
    buffer = io.BytesIO()
    with source, zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as destination:
        for source_info in source.infolist():
            info = zipfile.ZipInfo(source_info.filename, date_time=(2026, 8, 23, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            destination.writestr(
                info,
                content if source_info.filename == target else source.read(source_info.filename),
            )
    return buffer.getvalue()


def _replace_payload_and_rebuild_integrity(
    archive_bytes: bytes,
    target: str,
    content: bytes,
) -> bytes:
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as source:
        members = {info.filename: source.read(info) for info in source.infolist()}
    members[target] = content
    manifest = json.loads(members["CALIBRATION-MANIFEST.json"])
    entry = next(item for item in manifest["files"] if item["path"] == target)
    entry["bytes"] = len(content)
    entry["sha256"] = _sha256(content)
    members["CALIBRATION-MANIFEST.json"] = _canonical(manifest)
    checksummed_names = sorted((*PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json"))
    members["SHA256SUMS"] = "".join(
        f"{_sha256(members[name])}  {name}\n" for name in checksummed_names
    ).encode("ascii")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as destination:
        for name in (*PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json", "SHA256SUMS"):
            info = zipfile.ZipInfo(name, date_time=(2026, 8, 23, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            destination.writestr(info, members[name])
    return buffer.getvalue()


def test_valid_archive_inspection_is_descriptive_and_binds_the_closed_evidence(
    tmp_path: Path,
) -> None:
    archive_bytes, payloads = _archive_bytes()
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    inspection = inspect_day2_calibration_archive(
        archive_path,
        expected_outer_sha256=_sha256(archive_bytes),
        github_metadata=_github_metadata(archive_bytes),
    )

    assert isinstance(inspection, Day2CalibrationInspection)
    assert inspection.authority_granted is False
    assert inspection.evidence_scope == "isolated-14-primitive-fixed-host-calibration-only"
    assert inspection.source_git_sha == "a" * 40
    assert inspection.workflow_run_id == 456
    assert inspection.workflow_run_attempt == 2
    assert inspection.primitive_names == PRIMITIVE_NAMES
    assert inspection.measurement_block_count == 14
    assert inspection.outer_archive_sha256 == _sha256(archive_bytes)
    assert inspection.raw_measurement_blocks_sha256 == _sha256(
        _canonical(payloads["raw-measurement-blocks.json"])
    )
    assert inspection.contract_bindings_sha256 == _sha256(
        _canonical(payloads["contract-bindings.json"])
    )
    assert inspection.calibration_projection_sha256 == _sha256(
        _canonical(_calibration_projection(payloads))
    )
    behavior_inventory = payloads["source-provenance.json"]["behavior_inventory"]
    assert inspection.artifact_behavior_inventory_sha256 == _sha256(_canonical(behavior_inventory))
    assert inspection.behavior_set_schema_version == "dynamic-cssc-day2-behavior-set-v3"
    assert inspection.behavior_set_sha256 == behavior_inventory["behavior_set_sha256"]


def test_inspector_accepts_a_canonical_nonterminating_exact_rational_projection(
    tmp_path: Path,
) -> None:
    archive_bytes, payloads = _archive_bytes(
        mutate_payloads=_use_nonterminating_exact_rational_timing
    )
    archive_path = tmp_path / "day2-rational.zip"
    archive_path.write_bytes(archive_bytes)

    inspection = inspect_day2_calibration_archive(
        archive_path,
        expected_outer_sha256=_sha256(archive_bytes),
        github_metadata=_github_metadata(archive_bytes),
    )

    assert inspection.calibration_projection_sha256 == _sha256(
        _canonical(_calibration_projection(payloads))
    )
    projection = _calibration_projection(payloads)
    assert projection["raw_repetition_blocks"][0]["seconds_by_primitive"]["decrypt"] == (
        "1/3000000000"
    )


def test_inspector_rejects_extra_github_metadata_even_when_the_digest_matches(
    tmp_path: Path,
) -> None:
    archive_bytes, _ = _archive_bytes()
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)
    metadata = _github_metadata(archive_bytes)
    metadata["caller_claims_authority"] = True

    with pytest.raises(Day2CalibrationAuthorityError, match="GitHub metadata keys must be exact"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=metadata,
        )


def test_inspector_rejects_a_symlink_member_with_valid_content_and_checksums(
    tmp_path: Path,
) -> None:
    archive_bytes, _ = _archive_bytes()
    archive_bytes = _with_member_mode(
        archive_bytes,
        "RUN_STATUS.json",
        stat.S_IFLNK | 0o777,
    )
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="regular files"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


@pytest.mark.parametrize("member_name", ["../escape", "/absolute", "logs\\escape"])
def test_inspector_rejects_noncanonical_or_extra_archive_members(
    tmp_path: Path,
    member_name: str,
) -> None:
    archive_bytes, _ = _archive_bytes(extra_members=[(member_name, b"attack")])
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="exact closed evidence file set"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_rejects_duplicate_archive_members(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive_bytes, _ = _archive_bytes(
            extra_members=[("RUN_STATUS.json", _canonical({"forged": True}))]
        )
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="exact closed evidence file set"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_rejects_oversized_members_before_parsing(tmp_path: Path) -> None:
    archive_bytes, _ = _archive_bytes()
    archive_bytes = _replace_member_content(
        archive_bytes,
        "RUN_STATUS.json",
        b"x" * (16 * 1024 * 1024 + 1),
    )
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="member exceeds the size limit"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_rejects_tampered_manifest_member_and_checksums(tmp_path: Path) -> None:
    archive_bytes, _ = _archive_bytes()
    archive_bytes = _replace_member_content(
        archive_bytes,
        "raw-measurement-blocks.json",
        b"{}\n",
    )
    archive_path = tmp_path / "member-tampered.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="manifest byte length mismatch"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_rejects_duplicate_json_keys_after_integrity_is_rebuilt(
    tmp_path: Path,
) -> None:
    archive_bytes, _ = _archive_bytes()
    run_status = _canonical(_valid_payloads()["RUN_STATUS.json"])
    duplicate_status = run_status.replace(
        b'"status":"pass"',
        b'"status":"pass","status":"pass"',
    )
    archive_bytes = _replace_payload_and_rebuild_integrity(
        archive_bytes,
        "RUN_STATUS.json",
        duplicate_status,
    )
    archive_path = tmp_path / "duplicate-json-key.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="canonical JSON"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda payloads: payloads["source-provenance.json"].__setitem__(
                "tracked_tree_clean_after", False
            ),
            "source tree must be clean",
        ),
        (
            lambda payloads: payloads["source-provenance.json"].__setitem__(
                "caller_attestation", True
            ),
            "source provenance keys must be exact",
        ),
        (_change_behavior_source_set_binding, "Behavior Set digest"),
        (_omit_artifact_behavior_entry, "exact repository Day 2 set"),
        (_add_artifact_behavior_entry, "exact repository Day 2 set"),
        (_change_artifact_behavior_mode, "regular Git blob mode"),
        (_change_artifact_behavior_type, "entry type must be blob"),
        (_change_artifact_behavior_oid_shape, "lowercase Git SHA"),
        (
            lambda payloads: payloads["source-provenance.json"].__setitem__("git_sha", "b" * 40),
            "inventory source SHA does not match source provenance",
        ),
        (
            lambda payloads: payloads["workflow-provenance.json"].__setitem__("run_attempt", 3),
            "workflow provenance does not match GitHub metadata",
        ),
        (
            lambda payloads: payloads["workflow-provenance.json"].__setitem__("event_name", "push"),
            "workflow event_name is not frozen",
        ),
        (
            lambda payloads: payloads["RUN_STATUS.json"].__setitem__(
                "formal_authority_granted", True
            ),
            "run status cannot grant authority",
        ),
    ],
)
def test_inspector_rejects_self_consistent_provenance_and_status_attacks(
    tmp_path: Path,
    mutator: object,
    message: str,
) -> None:
    archive_bytes, _ = _archive_bytes(mutate_payloads=mutator)
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (_remove_last_primitive, "primitive_names must equal the frozen 14-item vocabulary"),
        (_reduce_to_thirteen_blocks, "exactly 14 complete measurement blocks"),
        (_drop_one_complete_warmup_block, "every complete warmup block"),
        (_set_zero_warmup_elapsed_time, "elapsed_ns must be a positive strict integer"),
        (_swap_one_warmup_operation_order, "operation_order is not the frozen permutation"),
        (_set_zero_elapsed_time, "elapsed_ns must be a positive strict integer"),
        (_change_raw_operation_count, "operation_count does not match its profile"),
        (_change_measurement_stop_rule, "measurement stop rule is not frozen"),
        (_change_operation_order_seed, "operation-order seed is not frozen"),
        (_swap_one_block_operation_order, "operation_order is not the frozen permutation"),
        (_disable_relinearization, "relinearization pricing contract"),
        (_drop_one_rotation_raw_case, "raw cases do not match their profile"),
        (_change_generated_rotation_inventory, "generated rotation indices"),
        (_enable_composite_rotation_plan, "composite rotation decompositions are forbidden"),
        (_add_modulo_alias_rotation, "modulo-congruent aliases"),
    ],
)
def test_inspector_rejects_self_consistent_raw_profile_and_key_plan_attacks(
    tmp_path: Path,
    mutator: object,
    message: str,
) -> None:
    archive_bytes, _ = _archive_bytes(mutate_payloads=mutator)
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_rejects_a_self_consistent_but_wrong_calibration_projection_digest(
    tmp_path: Path,
) -> None:
    archive_bytes, _ = _archive_bytes(mutate_bound_payloads=_change_projection_digest)
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="calibration projection SHA-256"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (_change_openfhe_commit, "OpenFHE commit is not frozen"),
        (_enable_native_optimization, "OpenFHE CMake flags are not frozen"),
        (_splice_probe_binary_identity, "producer identities do not match the OpenFHE build"),
        (_change_host_compiler, "host compiler does not match the OpenFHE build"),
        (_change_effective_affinity, "requested and verified probe CPU affinity"),
        (_make_power_state_unobservable, "power scaling_driver"),
        (_hide_observed_thermal_throttling, "thermal throttle counters are inconsistent"),
        (_replace_fixed_candidate, "fixed candidate IDs are not frozen"),
        (_change_accounting_schema, "primitive accounting schema is not frozen"),
        (_claim_producer_authority, "producer validation cannot grant authority"),
        (_change_generator_identity, "producer identities do not match the OpenFHE build"),
        (_extend_host_schema, "host profile keys must be exact"),
        (_extend_openfhe_schema, "OpenFHE build keys must be exact"),
        (_extend_contract_schema, "contract bindings keys must be exact"),
        (_extend_producer_schema, "producer validation keys must be exact"),
    ],
)
def test_inspector_rejects_self_consistent_environment_contract_and_producer_attacks(
    tmp_path: Path,
    mutator: object,
    message: str,
) -> None:
    archive_bytes, _ = _archive_bytes(mutate_payloads=mutator)
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_inspector_records_unobservable_thermal_counters_without_fabricating_values(
    tmp_path: Path,
) -> None:
    archive_bytes, _ = _archive_bytes(
        mutate_payloads=_make_thermal_counters_unobservable
    )
    archive_path = tmp_path / "day2-unobservable-thermal.zip"
    archive_path.write_bytes(archive_bytes)

    inspection = inspect_day2_calibration_archive(
        archive_path,
        expected_outer_sha256=_sha256(archive_bytes),
        github_metadata=_github_metadata(archive_bytes),
    )

    assert inspection.outer_archive_sha256 == _sha256(archive_bytes)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (_change_rotation_binding, "rotation inventory binding"),
        (_change_raw_blocks_binding, "raw measurement blocks SHA-256"),
    ],
)
def test_inspector_rejects_cross_file_digest_splicing_after_all_inner_hashes_are_rebuilt(
    tmp_path: Path,
    mutator: object,
    message: str,
) -> None:
    archive_bytes, _ = _archive_bytes(mutate_bound_payloads=mutator)
    archive_path = tmp_path / "day2.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )

    archive_bytes, _ = _archive_bytes()
    archive_bytes = _replace_member_content(archive_bytes, "SHA256SUMS", b"0" * 64 + b"\n")
    archive_path = tmp_path / "checksums-tampered.zip"
    archive_path.write_bytes(archive_bytes)

    with pytest.raises(Day2CalibrationAuthorityError, match="exact canonical checksum set"):
        inspect_day2_calibration_archive(
            archive_path,
            expected_outer_sha256=_sha256(archive_bytes),
            github_metadata=_github_metadata(archive_bytes),
        )


def test_repository_calibration_authority_fails_closed_without_an_approved_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_post_run = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda _relative_path: empty_post_run,
    )
    assert tuple(inspect.signature(repository_day2_calibration_authority).parameters) == ()

    with pytest.raises(TypeError, match="only be minted by the repository anchor"):
        Day2CalibrationAuthority()

    with pytest.raises(
        Day2CalibrationAuthorityError,
        match="no repository-approved Day 2 calibration anchor is installed",
    ):
        repository_day2_calibration_authority()

    with pytest.raises(TypeError):
        repository_day2_calibration_authority(object())  # type: ignore[call-arg]


def test_repository_pre_dispatch_profile_authority_fails_closed_without_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty_profile = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda _relative_path: empty_profile,
    )
    assert tuple(inspect.signature(repository_day2_calibration_profile_authority).parameters) == ()
    with pytest.raises(TypeError, match="only be minted by the repository anchor"):
        Day2CalibrationProfileAuthority()
    with pytest.raises(
        Day2CalibrationAuthorityError,
        match="no repository-approved pre-dispatch calibration profile anchor",
    ):
        repository_day2_calibration_profile_authority()
    with pytest.raises(TypeError):
        repository_day2_calibration_profile_authority(object())  # type: ignore[call-arg]


def test_day2_capabilities_do_not_accept_caller_source_or_anchor_inputs() -> None:
    assert (
        "source_git_sha"
        not in inspect.signature(
            Day2CalibrationProfileAuthority.validate_pre_dispatch_contract
        ).parameters
    )
    assert (
        "source_git_sha"
        not in inspect.signature(
            Day2CalibrationAuthority.validate_calibration_projection
        ).parameters
    )
    assert tuple(inspect.signature(repository_day2_calibration_profile_authority).parameters) == ()
    assert tuple(inspect.signature(repository_day2_calibration_authority).parameters) == ()

    with pytest.raises(TypeError):
        repository_day2_calibration_profile_authority(source_git_sha="a" * 40)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        repository_day2_calibration_profile_authority(anchor={})  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        repository_day2_calibration_authority(repository_root=Path.cwd())  # type: ignore[call-arg]


def test_repository_anchor_data_is_canonical_closed_and_not_embedded_in_validator_source() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    profile_bindings = authority_module._decode_profile_anchor_set(  # noqa: SLF001
        (repository_root / "config/day2-calibration-profile-anchors.json").read_bytes()
    )
    post_run_bindings = authority_module._decode_post_run_anchor_set(  # noqa: SLF001
        (repository_root / "config/day2-calibration-anchors.json").read_bytes()
    )
    assert len(profile_bindings) <= 1
    assert len(post_run_bindings) <= 1
    assert not hasattr(authority_module, "_REPOSITORY_CALIBRATION_PROFILE_ANCHORS")
    assert not hasattr(authority_module, "_REPOSITORY_CALIBRATION_ANCHORS")


@pytest.mark.parametrize(
    "relative_path",
    (
        authority_module._PROFILE_ANCHOR_PATH,  # noqa: SLF001
        authority_module._POST_RUN_ANCHOR_PATH,  # noqa: SLF001
    ),
)
def test_repository_day2_anchor_reader_rejects_git_100755_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: Path,
) -> None:
    repository = _day2_anchor_repository(tmp_path)
    (repository / relative_path).chmod(0o755)
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "make Day2 anchor executable")
    monkeypatch.setattr(
        authority_module,
        "__file__",
        str(repository / "src/dynamic_cssc/day2_calibration_authority.py"),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="Git 100644 data blob"):
        authority_module._read_repository_anchor_set(relative_path)  # noqa: SLF001


@pytest.mark.parametrize(
    "relative_path",
    (
        authority_module._PROFILE_ANCHOR_PATH,  # noqa: SLF001
        authority_module._POST_RUN_ANCHOR_PATH,  # noqa: SLF001
    ),
)
def test_repository_day2_anchor_reader_rejects_worktree_only_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: Path,
) -> None:
    repository = _day2_anchor_repository(tmp_path)
    (repository / relative_path).write_bytes(b'{"anchors":[{}],"schema_version":"attack"}\n')
    monkeypatch.setattr(
        authority_module,
        "__file__",
        str(repository / "src/dynamic_cssc/day2_calibration_authority.py"),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="clean|differs from current HEAD"):
        authority_module._read_repository_anchor_set(relative_path)  # noqa: SLF001


def test_synthetic_pre_dispatch_anchor_parser_accepts_one_closed_binding_without_source_sha() -> (
    None
):
    anchor, _payloads = _valid_profile_anchor()
    assert "source_git_sha" not in anchor
    assert "experiment_source_git_sha" not in anchor

    bindings = authority_module._decode_profile_anchor_set(  # noqa: SLF001
        _canonical(
            {
                "anchors": [anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        )
    )

    assert len(bindings) == 1
    assert not hasattr(bindings[0], "source_git_sha")
    assert bindings[0].operation_profile_set_sha256 == anchor["operation_profile_set_sha256"]
    assert bindings[0].contract_bindings_sha256 == anchor["contract_bindings_sha256"]


def test_synthetic_post_run_anchor_parser_accepts_one_evidence_only_binding() -> None:
    archive_bytes, payloads = _archive_bytes()
    anchor = _valid_post_run_anchor(archive_bytes, payloads)

    bindings = authority_module._decode_post_run_anchor_set(  # noqa: SLF001
        _canonical(
            {
                "anchors": [anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        )
    )

    assert len(bindings) == 1
    assert bindings[0].source_git_sha == "a" * 40
    assert bindings[0].experiment_behavior_set_sha256 == anchor["experiment_behavior_set_sha256"]
    assert (
        bindings[0].artifact_behavior_inventory_sha256
        == anchor["artifact_behavior_inventory_sha256"]
    )
    assert bindings[0].outer_archive_sha256 == _sha256(archive_bytes)


def test_anchor_parsers_reject_duplicate_extra_missing_and_malformed_identity_data() -> None:
    profile_anchor, _ = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    valid_profile_document = _canonical(
        {
            "anchors": [profile_anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    missing_profile = deepcopy(profile_anchor)
    missing_profile.pop("contract_bindings_sha256")
    malformed_profile = deepcopy(profile_anchor)
    malformed_profile["operation_profile_set_sha256"] = "not-a-digest"
    self_referential_profile = deepcopy(profile_anchor)
    self_referential_profile["source_git_sha"] = "a" * 40
    profile_attacks = (
        valid_profile_document.replace(b'"anchors":[', b'"anchors":[],"anchors":['),
        _canonical(
            {
                "anchors": [profile_anchor],
                "caller_anchor": True,
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        _canonical(
            {
                "anchors": [missing_profile],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        _canonical(
            {
                "anchors": [profile_anchor, profile_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        _canonical(
            {
                "anchors": [malformed_profile],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        _canonical(
            {
                "anchors": [self_referential_profile],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
    )
    for document in profile_attacks:
        with pytest.raises(Day2CalibrationAuthorityError):
            authority_module._decode_profile_anchor_set(document)  # noqa: SLF001

    valid_post_document = _canonical(
        {
            "anchors": [post_anchor],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    missing_post = deepcopy(post_anchor)
    missing_post.pop("raw_measurement_blocks_sha256")
    malformed_post = deepcopy(post_anchor)
    malformed_post["calibration_projection_sha256"] = "not-a-digest"
    spliced_inventory_post = deepcopy(post_anchor)
    spliced_inventory = spliced_inventory_post["artifact_behavior_inventory"]
    spliced_inventory["entries"][0]["object_id"] = "3" * 40
    spliced_inventory["behavior_set_sha256"] = _sha256(
        _canonical(
            {
                "behavior_set_schema_version": spliced_inventory["behavior_set_schema_version"],
                "entries": spliced_inventory["entries"],
                "role": spliced_inventory["role"],
            }
        )
    )
    spliced_inventory_post["artifact_behavior_inventory_sha256"] = _sha256(
        _canonical(spliced_inventory)
    )
    post_attacks = (
        valid_post_document.replace(b'"anchors":[', b'"anchors":[],"anchors":['),
        _canonical(
            {
                "anchors": [post_anchor],
                "caller_authority": True,
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
        _canonical(
            {
                "anchors": [missing_post],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
        _canonical(
            {
                "anchors": [post_anchor, post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
        _canonical(
            {
                "anchors": [malformed_post],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
        _canonical(
            {
                "anchors": [spliced_inventory_post],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    )
    for document in post_attacks:
        with pytest.raises(Day2CalibrationAuthorityError):
            authority_module._decode_post_run_anchor_set(document)  # noqa: SLF001


def test_pre_dispatch_repository_seam_records_only_hardened_current_day2_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor, _payloads = _valid_profile_anchor()
    profile_document = _canonical(
        {
            "anchors": [anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    empty_post_run = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="a" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256="b" * 64,
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    observed_roles: list[EvidenceRole] = []

    def attest(role: EvidenceRole, repository_root: Path) -> RoleSourceAttestation:
        assert repository_root == Path(authority_module.__file__).resolve().parents[2]
        observed_roles.append(role)
        return attestation

    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: (
            profile_document
            if relative_path == authority_module._PROFILE_ANCHOR_PATH  # noqa: SLF001
            else empty_post_run
        ),
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        attest,
    )
    history_calls: list[EvidenceRole] = []

    def verify_history(role: EvidenceRole, repository_root: Path) -> object:
        assert repository_root == Path(authority_module.__file__).resolve().parents[2]
        history_calls.append(role)
        return SimpleNamespace(
            analysis_source_git_sha="a" * 40,
            day1a_authority_receipt_sha256=anchor["day1a_authority_receipt_sha256"],
        )

    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        verify_history,
    )

    capability = repository_day2_calibration_profile_authority()

    assert capability.experiment_source_git_sha == "a" * 40
    assert capability.experiment_behavior_set_sha256 == "b" * 64
    assert observed_roles == [EvidenceRole.DAY2, EvidenceRole.DAY2]
    assert history_calls == [EvidenceRole.DAY1_REGISTRATION]


def test_pre_dispatch_repository_seam_leaves_live_runtime_isolation_to_the_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor, _payloads = _valid_profile_anchor()
    profile_document = _canonical(
        {
            "anchors": [anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    empty_post_run = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="a" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256="b" * 64,
        behavior_source_blob_sha256={},
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: (
            profile_document
            if relative_path == authority_module._PROFILE_ANCHOR_PATH  # noqa: SLF001
            else empty_post_run
        ),
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha="a" * 40,
            day1a_authority_receipt_sha256=anchor["day1a_authority_receipt_sha256"],
        ),
    )

    capability = repository_day2_calibration_profile_authority()

    assert capability.experiment_source_git_sha == "a" * 40
    assert capability.experiment_behavior_set_sha256 == "b" * 64


@pytest.mark.parametrize(
    ("history_source_sha", "history_receipt_sha", "message"),
    (
        ("f" * 40, None, "history-verified registration/profile source"),
        ("a" * 40, "0" * 64, "history-anchored Day1A authority receipt"),
    ),
)
def test_pre_dispatch_repository_seam_rejects_invalid_registration_profile_history(
    monkeypatch: pytest.MonkeyPatch,
    history_source_sha: str,
    history_receipt_sha: str | None,
    message: str,
) -> None:
    anchor, _payloads = _valid_profile_anchor()
    profile_document = _canonical(
        {
            "anchors": [anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    empty_post_run = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="a" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256="b" * 64,
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: (
            profile_document
            if relative_path == authority_module._PROFILE_ANCHOR_PATH  # noqa: SLF001
            else empty_post_run
        ),
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha=history_source_sha,
            day1a_authority_receipt_sha256=(
                anchor["day1a_authority_receipt_sha256"]
                if history_receipt_sha is None
                else history_receipt_sha
            ),
        ),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        repository_day2_calibration_profile_authority()


def test_pre_dispatch_repository_seam_rejects_anchor_race_during_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor, _payloads = _valid_profile_anchor()
    document = _canonical(
        {
            "anchors": [anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    tampered_anchor = deepcopy(anchor)
    tampered_anchor["operation_profile_set_sha256"] = "0" * 64
    tampered_document = _canonical(
        {
            "anchors": [tampered_anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    profile_documents = iter((document, tampered_document))
    empty_post_run = _canonical(
        {
            "anchors": [],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="a" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256="b" * 64,
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: (
            next(profile_documents)
            if relative_path == authority_module._PROFILE_ANCHOR_PATH  # noqa: SLF001
            else empty_post_run
        ),
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha="a" * 40,
            day1a_authority_receipt_sha256=anchor["day1a_authority_receipt_sha256"],
        ),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="anchor changed"):
        repository_day2_calibration_profile_authority()


def test_pre_dispatch_repository_seam_rejects_existing_post_run_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor, _payloads = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_run_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    profile_document = _canonical(
        {
            "anchors": [anchor],
            "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
        }
    )
    post_run_document = _canonical(
        {
            "anchors": [post_run_anchor],
            "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
        }
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: (
            profile_document
            if relative_path == authority_module._PROFILE_ANCHOR_PATH  # noqa: SLF001
            else post_run_document
        ),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="post-run anchor set.*empty"):
        repository_day2_calibration_profile_authority()


def test_post_run_repository_seam_verifies_s1_compatibility_before_minting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_anchor, _ = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    documents = {
        authority_module._PROFILE_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [profile_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        authority_module._POST_RUN_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    }
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="c" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256=post_anchor["experiment_behavior_set_sha256"],
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    artifact_inventory = payloads["source-provenance.json"]["behavior_inventory"]
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: documents[relative_path],
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha="c" * 40,
            day1a_authority_receipt_sha256=profile_anchor[
                "day1a_authority_receipt_sha256"
            ],
        ),
    )

    def verify_compatibility(**kwargs: object) -> object:
        observed.update(kwargs)
        return SimpleNamespace(
            runtime_execution_isolation_verified=False,
            to_document=lambda: {
                "compatibility_verified": True,
                "post_run_anchor_verified": True,
                "runtime_execution_isolation_verified": False,
                "snapshot_compatibility_verified": True,
            },
        )

    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_evidence_compatibility",
        verify_compatibility,
    )

    capability = repository_day2_calibration_authority()

    assert capability.source_git_sha == "a" * 40
    assert capability.outer_archive_sha256 == _sha256(archive_bytes)
    assert observed["role"] is EvidenceRole.DAY2
    assert observed["experiment_source_git_sha"] == "a" * 40
    assert observed["evidence_freeze_git_sha"] == "c" * 40
    assert observed["analysis_source_git_sha"] == "c" * 40
    assert observed["artifact_sha256"] == _sha256(archive_bytes)
    assert observed["artifact_behavior_inventory"] == artifact_inventory
    assert observed["artifact_behavior_inventory"] is not artifact_inventory


@pytest.mark.parametrize(
    ("history_source_sha", "history_receipt_sha", "message"),
    (
        ("f" * 40, None, "history-verified profile source"),
        ("c" * 40, "0" * 64, "history-anchored Day1A receipt"),
    ),
)
def test_post_run_repository_seam_rejects_invalid_registration_profile_history(
    monkeypatch: pytest.MonkeyPatch,
    history_source_sha: str,
    history_receipt_sha: str | None,
    message: str,
) -> None:
    profile_anchor, _ = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    documents = {
        authority_module._PROFILE_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [profile_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        authority_module._POST_RUN_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    }
    attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="c" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256=post_anchor["experiment_behavior_set_sha256"],
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: documents[relative_path],
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha=history_source_sha,
            day1a_authority_receipt_sha256=(
                profile_anchor["day1a_authority_receipt_sha256"]
                if history_receipt_sha is None
                else history_receipt_sha
            ),
        ),
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_evidence_compatibility",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("compatibility ran before registration/profile history")
        ),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match=message):
        repository_day2_calibration_authority()


def test_changed_day2_validator_behavior_cannot_install_a_post_run_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_anchor, _ = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    documents = {
        authority_module._PROFILE_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [profile_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        authority_module._POST_RUN_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    }
    changed_attestation = RoleSourceAttestation(
        role=EvidenceRole.DAY2,
        git_sha="c" * 40,
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256="d" * 64,
        behavior_source_blob_sha256={},
        runtime_execution_isolation_authority_state="synthetic-test-isolated-runtime-v1",
        runtime_execution_isolation_verified=True,
    )
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: documents[relative_path],
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_current_role_source",
        lambda role, repository_root: changed_attestation,
    )
    monkeypatch.setattr(
        "dynamic_cssc.evidence_compatibility.verify_repository_anchor_history",
        lambda role, repository_root: SimpleNamespace(
            analysis_source_git_sha="c" * 40,
            day1a_authority_receipt_sha256=profile_anchor[
                "day1a_authority_receipt_sha256"
            ],
        ),
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="Behavior Set does not match"):
        repository_day2_calibration_authority()


@pytest.mark.parametrize(
    "tampered_field",
    ("operation_profile_set_sha256", "contract_bindings_sha256"),
)
def test_validly_encoded_post_run_identity_tamper_cannot_cross_the_pre_dispatch_anchor(
    monkeypatch: pytest.MonkeyPatch,
    tampered_field: str,
) -> None:
    profile_anchor, _ = _valid_profile_anchor()
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    post_anchor[tampered_field] = "0" * 64
    documents = {
        authority_module._PROFILE_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [profile_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        authority_module._POST_RUN_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    }
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: documents[relative_path],
    )

    with pytest.raises(Day2CalibrationAuthorityError, match="pre-dispatch profile authority"):
        repository_day2_calibration_authority()


def test_post_run_anchor_alone_cannot_bypass_missing_pre_dispatch_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_bytes, payloads = _archive_bytes()
    post_anchor = _valid_post_run_anchor(archive_bytes, payloads)
    documents = {
        authority_module._PROFILE_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        ),
        authority_module._POST_RUN_ANCHOR_PATH: _canonical(  # noqa: SLF001
            {
                "anchors": [post_anchor],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            }
        ),
    }
    monkeypatch.setattr(
        authority_module,
        "_read_repository_anchor_set",
        lambda relative_path: documents[relative_path],
    )

    with pytest.raises(
        Day2CalibrationAuthorityError,
        match="no repository-approved pre-dispatch calibration profile anchor",
    ):
        repository_day2_calibration_authority()


def test_pre_dispatch_profile_authority_freezes_profiles_day1a_and_contract_identities() -> None:
    anchor, payloads = _valid_profile_anchor()
    profiles = payloads["operation-profile-set.json"]
    rotation_plan = payloads["rotation-key-plan.json"]
    contract = payloads["contract-bindings.json"]
    binding = authority_module._decode_profile_anchor_set(  # noqa: SLF001
        _canonical(
            {
                "anchors": [anchor],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
            }
        )
    )[0]
    capability = authority_module._mint_repository_calibration_profile_authority(  # noqa: SLF001
        anchor=binding,
        experiment_source_git_sha="a" * 40,
        experiment_behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        experiment_behavior_set_sha256="b" * 64,
    )

    assert not hasattr(capability, "source_git_sha")
    assert capability.experiment_source_git_sha == "a" * 40
    assert capability.experiment_behavior_set_sha256 == "b" * 64
    assert capability.operation_profile_set_sha256 == _sha256(_canonical(profiles))
    assert capability.warmup_block_count == 3
    assert capability.rotation_key_plan_sha256 == _sha256(_canonical(rotation_plan))
    assert capability.day1a_authority_receipt_sha256 == "6" * 64
    assert capability.day1a_inventory_sha256 == "7" * 64
    assert (
        capability.validate_pre_dispatch_contract(
            profiles,
            rotation_plan,
            contract,
        )
        is None
    )
    with pytest.raises(TypeError, match="validate_pre_dispatch_contract"):
        bool(capability)

    spliced_profiles = deepcopy(profiles)
    spliced_profiles["profiles"][0]["profile_id"] = "post-run/profile"
    with pytest.raises(Day2CalibrationAuthorityError, match="profile set does not match"):
        capability.validate_pre_dispatch_contract(
            spliced_profiles,
            rotation_plan,
            contract,
        )
    spliced_warmup = deepcopy(profiles)
    spliced_warmup["warmup_block_count"] = 2
    with pytest.raises(Day2CalibrationAuthorityError, match="exactly 3 complete warmup"):
        capability.validate_pre_dispatch_contract(
            spliced_warmup,
            rotation_plan,
            contract,
        )
    spliced_rotation = deepcopy(rotation_plan)
    spliced_rotation["day1a_inventory_sha256"] = "8" * 64
    with pytest.raises(Day2CalibrationAuthorityError, match="Day1A inventory does not match"):
        capability.validate_pre_dispatch_contract(
            profiles,
            spliced_rotation,
            contract,
        )

    spliced_contract = deepcopy(contract)
    spliced_contract["experiment_contract_sha256"] = "1" * 64
    with pytest.raises(Day2CalibrationAuthorityError, match="contract bindings do not match"):
        capability.validate_pre_dispatch_contract(
            profiles,
            rotation_plan,
            spliced_contract,
        )

    with pytest.raises(TypeError):
        capability.validate_pre_dispatch_contract(
            profiles,
            rotation_plan,
            contract,
            source_git_sha="a" * 40,  # type: ignore[call-arg]
        )


def test_repository_minted_authority_is_read_only_and_validates_the_exact_projection() -> None:
    archive_bytes, payloads = _archive_bytes()
    projection = _calibration_projection(payloads)
    capability = authority_module._mint_repository_calibration_authority(  # noqa: SLF001
        source_git_sha="a" * 40,
        outer_archive_sha256=_sha256(archive_bytes),
        raw_measurement_blocks_sha256=_sha256(_canonical(payloads["raw-measurement-blocks.json"])),
        calibration_projection_sha256=_sha256(_canonical(projection)),
    )

    assert capability.source_git_sha == "a" * 40
    assert capability.outer_archive_sha256 == _sha256(archive_bytes)
    assert capability.raw_measurement_blocks_sha256 == _sha256(
        _canonical(payloads["raw-measurement-blocks.json"])
    )
    assert capability.calibration_projection_sha256 == _sha256(_canonical(projection))
    assert (
        capability.validate_calibration_projection(
            projection,
        )
        is None
    )
    with pytest.raises(TypeError, match="validate_calibration_projection"):
        bool(capability)
    assert not hasattr(capability, "__dict__")
    with pytest.raises(AttributeError):
        capability.source_git_sha = "b" * 40  # type: ignore[misc]

    spliced_projection = deepcopy(projection)
    spliced_projection["raw_repetition_blocks"][0]["seconds_by_primitive"][PRIMITIVE_NAMES[0]] = (
        "0.123"
    )
    with pytest.raises(Day2CalibrationAuthorityError, match="projection does not match"):
        capability.validate_calibration_projection(
            spliced_projection,
        )
    with pytest.raises(TypeError):
        capability.validate_calibration_projection(
            projection,
            source_git_sha="a" * 40,  # type: ignore[call-arg]
        )
