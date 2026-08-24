"""Repository-owned authority for publication Day 2 calibration evidence.

The archive inspector in this module is descriptive.  Only the zero-argument
repository seam can ever return an authority value, and the production anchor
set intentionally remains empty until a real evidence bundle is reviewed.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path, PurePosixPath

__all__ = (
    "Day2CalibrationAuthority",
    "Day2CalibrationInspection",
    "Day2CalibrationProfileAuthority",
    "Day2CalibrationAuthorityError",
    "inspect_day2_calibration_archive",
    "repository_day2_calibration_authority",
    "repository_day2_calibration_profile_authority",
    "validate_day2_calibration_post_run_anchor_document",
    "validate_day2_calibration_profile_anchor_document",
)

EVIDENCE_SCOPE = "isolated-14-primitive-fixed-host-calibration-only"
SAMPLER_SCHEMA = "dynamic-cssc-publication-shake256-counter-sampler-v1"
CALIBRATION_OPERATION_ORDER_SEED = 2_026_082_302
CALIBRATION_WARMUP_BLOCK_COUNT = 3
CALIBRATION_MEASUREMENT_BLOCK_COUNT = 14
CALIBRATION_MEASUREMENT_STOP_RULE = (
    "exactly-14-whole-blocks-outcome-independent-no-optional-stopping"
)
CALIBRATION_OPERATION_ORDER_METHOD = "domain-separated-shake256-counter-rejection-fisher-yates-v1"
DAY2_RUNTIME_ISOLATION_CHECKS = (
    "fresh-detached-exact-head-checkout",
    "clean-caller-environment-without-python-or-git-injection",
    "private-build-and-measurement-root-outside-source-checkout",
    "pre-dispatch-profile-authority-consumed-once",
    "source-attestation-stable-before-and-after-production",
)
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
ABLATION_CANDIDATE_IDS = ("packed-coo-client-lane-delta/capacity=128",)
REFERENCE_CANDIDATE_IDS = tuple(
    candidate_id
    for candidate_id in FIXED_CANDIDATE_IDS
    if candidate_id not in ABLATION_CANDIDATE_IDS
)
_PAYLOAD_FILENAMES = (
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
_ARCHIVE_FILENAMES = frozenset((*_PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json", "SHA256SUMS"))
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 200
_MAX_ANCHOR_SET_BYTES = 1024 * 1024
_PROFILE_ANCHOR_PATH = Path("config/day2-calibration-profile-anchors.json")
_POST_RUN_ANCHOR_PATH = Path("config/day2-calibration-anchors.json")
_GITHUB_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "workflow_path",
        "workflow_file_sha256",
        "run_id",
        "run_attempt",
        "event_name",
        "ref",
        "head_sha",
        "artifact_name",
        "artifact_id",
        "artifact_digest",
        "inner_archive_sha256",
    }
)
_RUN_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "evidence_scope",
        "producer_validation_passed",
        "formal_authority_granted",
        "complete_cost_claim_allowed",
        "mixed_circuit_parameter_claim_allowed",
        "r4_claim_allowed",
        "security_claim_allowed",
    }
)
_SOURCE_PROVENANCE_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "git_sha",
        "git_tree",
        "git_status_before_sha256",
        "git_status_after_sha256",
        "tracked_tree_clean_before",
        "tracked_tree_clean_after",
        "untracked_nonignored_clean_before",
        "untracked_nonignored_clean_after",
        "behavior_inventory",
    }
)
_BEHAVIOR_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "role",
        "source_git_sha",
        "behavior_set_schema_version",
        "behavior_set_sha256",
        "entries",
    }
)
_BEHAVIOR_INVENTORY_ENTRY_KEYS = frozenset({"mode", "object_id", "object_type", "path"})
_WORKFLOW_PROVENANCE_KEYS = _GITHUB_METADATA_KEYS - {
    "artifact_id",
    "artifact_digest",
    "inner_archive_sha256",
}
_ROTATION_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "inventory_source_schema_version",
        "day1a_authority_receipt_sha256",
        "day1a_inventory_sha256",
        "effective_slots",
        "required_exact_indices",
        "key_plan_kind",
        "planned_exact_indices",
        "composite_decompositions",
        "eval_rotate_case_ids",
    }
)
_GENERATED_KEY_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "rotation_key_plan_sha256",
        "generated_exact_indices",
        "serialized_rotation_key_inventory_sha256",
        "serialized_rotation_key_bytes",
        "eval_mult_key_generated",
        "serialized_eval_mult_key_sha256",
        "serialized_eval_mult_key_bytes",
    }
)
_PROFILE_SET_KEYS = frozenset(
    {
        "schema_version",
        "primitive_names",
        "warmup_block_count",
        "measurement_block_count",
        "measurement_stop_rule",
        "operation_order_seed",
        "operation_order_method",
        "profiles",
    }
)
_PROFILE_KEYS = frozenset(
    {
        "primitive_name",
        "profile_id",
        "setup_scope",
        "timed_operation",
        "case_aggregation_rule",
        "warmup_policy",
        "measurement_policy",
        "includes_relinearization",
        "randomness_policy",
        "correctness_check_sha256",
        "cases",
    }
)
_PROFILE_CASE_KEYS = frozenset(
    {"case_id", "unit_definition", "input_fixture_contract_sha256", "operation_count"}
)
_RUNTIME_ISOLATION_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "authority_state",
        "formal_authority_granted",
        "source_git_sha",
        "fresh_detached_checkout",
        "clean_environment",
        "isolated_build_root",
        "caller_python_and_git_environment_removed",
        "profile_authority_consumed_once",
        "launcher_source_sha256",
        "producer_source_sha256",
        "isolation_checks",
    }
)
_RAW_BLOCK_SET_KEYS = frozenset(
    {
        "schema_version",
        "clock",
        "clock_unit",
        "primitive_names",
        "warmup_block_count",
        "measurement_block_count",
        "measurement_stop_rule",
        "operation_order_seed",
        "operation_order_method",
        "warmup_blocks",
        "blocks",
    }
)
_RAW_BLOCK_KEYS = frozenset({"ordinal", "operation_order", "samples"})
_RAW_SAMPLE_KEYS = frozenset({"primitive_name", "cases"})
_RAW_CASE_KEYS = frozenset({"case_id", "elapsed_ns", "operation_count"})
_CALIBRATION_PROJECTION_KEYS = frozenset(
    {
        "schema_version",
        "primitive_names",
        "operation_order_seed",
        "measurement_block_count",
        "measurement_stop_rule",
        "raw_repetition_blocks",
    }
)
_CALIBRATION_PROJECTION_BLOCK_KEYS = frozenset(
    {"schema_version", "block_ordinal", "operation_order", "seconds_by_primitive"}
)
_HOST_PROFILE_KEYS = frozenset(
    {"schema_version", "hardware", "os", "compiler", "affinity", "power"}
)
_HOST_HARDWARE_KEYS = frozenset(
    {
        "architecture",
        "cpu_vendor",
        "cpu_model_name",
        "cpu_family",
        "cpu_model",
        "cpu_stepping",
        "microcode",
        "socket_count",
        "physical_core_count",
        "logical_cpu_count",
        "memory_bytes",
        "numa_topology_sha256",
    }
)
_HOST_OS_KEYS = frozenset(
    {
        "distribution_id",
        "distribution_version",
        "kernel_release",
        "kernel_cmdline_sha256",
        "glibc_version",
        "runner_image_identity_sha256",
    }
)
_HOST_COMPILER_KEYS = frozenset({"path", "vendor", "version", "target"})
_HOST_AFFINITY_KEYS = frozenset(
    {
        "requested_cpu_list",
        "verified_probe_cpu_list",
        "probe_affinity_observation_stage",
        "omp_num_threads",
        "omp_proc_bind",
        "omp_places",
        "per_block_allowed_cpu_sets",
    }
)
_HOST_POWER_KEYS = frozenset(
    {
        "scaling_driver",
        "governor_by_cpu",
        "turbo_state",
        "power_source",
        "thermal_throttle_counters_observable",
        "thermal_throttle_count_before",
        "thermal_throttle_count_after",
        "thermal_throttling_observed",
    }
)
_HOST_GOVERNOR_KEYS = frozenset(
    {"cpu", "governor", "min_khz", "max_khz", "energy_performance_preference"}
)
_OPENFHE_BUILD_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "version",
        "commit",
        "source_git_tree",
        "source_tree_clean",
        "source_tree_sha256",
        "cmake_version",
        "ninja_version",
        "cmake_flags",
        "cmake_cache_sha256",
        "compile_commands_sha256",
        "installed_manifest_sha256",
        "openfhe_shared_library_sha256",
        "probe_source_sha256",
        "probe_binary_sha256",
        "manifest_generator_sha256",
        "bundle_validator_sha256",
        "compiler_path",
        "compiler_vendor",
        "compiler_version",
        "compiler_target",
        "effective_compile_flags",
        "linked_library_inventory_sha256",
    }
)
_OPENFHE_CMAKE_FLAGS = {
    "BUILD_BENCHMARKS": "OFF",
    "BUILD_EXAMPLES": "OFF",
    "BUILD_UNITTESTS": "OFF",
    "CMAKE_BUILD_TYPE": "Release",
    "CMAKE_CXX_EXTENSIONS": "OFF",
    "CMAKE_CXX_STANDARD": "17",
    "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
    "WITH_NATIVEOPT": "OFF",
    "WITH_OPENMP": "ON",
}
_CONTRACT_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "experiment_contract_sha256",
        "day1_candidate_registration_receipt_sha256",
        "candidate_catalog_schema_version",
        "candidate_catalog_sha256",
        "fixed_candidate_ids",
        "reference_candidate_ids",
        "ablation_candidate_ids",
        "day1a_count_bundle_schema_version",
        "day1a_count_bundle_sha256",
        "heldout_record_schema_version",
        "primitive_accounting_schema_version",
        "primitive_accounting_mapping_sha256",
        "serialized_object_accounting_schema_version",
        "serialized_object_accounting_contract_sha256",
        "day1a_rotation_inventory_sha256",
        "rotation_key_plan_sha256",
    }
)
_PRODUCER_VALIDATION_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "formal_authority_granted",
        "validator_source_sha256",
        "manifest_generator_sha256",
        "probe_source_sha256",
        "probe_binary_sha256",
        "raw_measurement_blocks_sha256",
        "operation_profile_set_sha256",
        "rotation_key_plan_sha256",
        "generated_key_inventory_sha256",
        "runtime_isolation_receipt_sha256",
        "calibration_projection_sha256",
        "candidate_catalog_sha256",
        "accounting_contract_sha256",
        "all_profiles_correct",
    }
)
_PROFILE_ANCHOR_SET_KEYS = frozenset({"anchors", "schema_version"})
_PROFILE_ANCHOR_KEYS = frozenset(
    {
        "schema_version",
        "operation_profile_set_sha256",
        "warmup_block_count",
        "rotation_key_plan_sha256",
        "rotation_inventory_source_schema_version",
        "day1a_authority_receipt_sha256",
        "day1a_inventory_sha256",
        "contract_bindings_sha256",
        "experiment_contract_sha256",
        "day1_candidate_registration_receipt_sha256",
        "candidate_catalog_schema_version",
        "candidate_catalog_sha256",
        "day1a_count_bundle_schema_version",
        "day1a_count_bundle_sha256",
        "heldout_record_schema_version",
        "primitive_accounting_schema_version",
        "primitive_accounting_mapping_sha256",
        "serialized_object_accounting_schema_version",
        "serialized_object_accounting_contract_sha256",
        "day1a_workflow_run_id",
        "day1a_artifact_id",
        "day1a_artifact_name",
        "day1a_artifact_digest",
    }
)
_POST_RUN_ANCHOR_SET_KEYS = frozenset({"anchors", "schema_version"})
_POST_RUN_ANCHOR_KEYS = frozenset(
    {
        "schema_version",
        "experiment_source_git_sha",
        "experiment_behavior_set_schema_version",
        "experiment_behavior_set_sha256",
        "artifact_behavior_inventory",
        "artifact_behavior_inventory_sha256",
        "outer_archive_sha256",
        "raw_measurement_blocks_sha256",
        "operation_profile_set_sha256",
        "rotation_key_plan_sha256",
        "generated_key_inventory_sha256",
        "runtime_isolation_receipt_sha256",
        "contract_bindings_sha256",
        "calibration_projection_sha256",
    }
)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"


@dataclass(frozen=True, slots=True)
class Day2CalibrationInspection:
    """Descriptive projection of one internally consistent evidence archive."""

    evidence_scope: str
    source_git_sha: str
    workflow_run_id: int
    workflow_run_attempt: int
    primitive_names: tuple[str, ...]
    measurement_block_count: int
    outer_archive_sha256: str
    manifest_sha256: str
    checksums_sha256: str
    raw_measurement_blocks_sha256: str
    operation_profile_set_sha256: str
    rotation_key_plan_sha256: str
    generated_key_inventory_sha256: str
    runtime_isolation_receipt_sha256: str
    contract_bindings_sha256: str
    calibration_projection_sha256: str
    artifact_behavior_inventory_sha256: str
    behavior_set_schema_version: str
    behavior_set_sha256: str

    @property
    def authority_granted(self) -> bool:
        """Archive consistency never grants repository authority."""

        return False


class Day2CalibrationAuthorityError(ValueError):
    """Raised when Day 2 evidence cannot cross the repository authority seam."""


@dataclass(frozen=True, slots=True)
class _Day2CalibrationProfileBinding:
    operation_profile_set_sha256: str
    warmup_block_count: int
    rotation_key_plan_sha256: str
    rotation_inventory_source_schema_version: str
    day1a_authority_receipt_sha256: str
    day1a_inventory_sha256: str
    contract_bindings_sha256: str
    experiment_contract_sha256: str
    day1_candidate_registration_receipt_sha256: str
    candidate_catalog_schema_version: str
    candidate_catalog_sha256: str
    day1a_count_bundle_schema_version: str
    day1a_count_bundle_sha256: str
    heldout_record_schema_version: str
    primitive_accounting_schema_version: str
    primitive_accounting_mapping_sha256: str
    serialized_object_accounting_schema_version: str
    serialized_object_accounting_contract_sha256: str
    day1a_workflow_run_id: int
    day1a_artifact_id: int
    day1a_artifact_name: str
    day1a_artifact_digest: str


@dataclass(frozen=True, slots=True)
class _Day2CalibrationProfileReceiptBinding:
    anchor: _Day2CalibrationProfileBinding
    experiment_source_git_sha: str
    experiment_behavior_set_schema_version: str
    experiment_behavior_set_sha256: str


class Day2CalibrationProfileAuthority:
    """Read-only pre-dispatch profile, Day1A, and contract binding."""

    __slots__ = ("_binding",)

    def __new__(cls) -> Day2CalibrationProfileAuthority:
        raise TypeError(
            "Day2CalibrationProfileAuthority can only be minted by the repository anchor"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Day2CalibrationProfileAuthority bindings are read-only")

    def __bool__(self) -> bool:
        raise TypeError(
            "Day2CalibrationProfileAuthority must be used through validate_pre_dispatch_contract"
        )

    @property
    def experiment_source_git_sha(self) -> str:
        return self._binding.experiment_source_git_sha

    @property
    def experiment_behavior_set_schema_version(self) -> str:
        return self._binding.experiment_behavior_set_schema_version

    @property
    def experiment_behavior_set_sha256(self) -> str:
        return self._binding.experiment_behavior_set_sha256

    @property
    def operation_profile_set_sha256(self) -> str:
        return self._binding.anchor.operation_profile_set_sha256

    @property
    def warmup_block_count(self) -> int:
        return self._binding.anchor.warmup_block_count

    @property
    def rotation_key_plan_sha256(self) -> str:
        return self._binding.anchor.rotation_key_plan_sha256

    @property
    def rotation_inventory_source_schema_version(self) -> str:
        return self._binding.anchor.rotation_inventory_source_schema_version

    @property
    def day1a_authority_receipt_sha256(self) -> str:
        return self._binding.anchor.day1a_authority_receipt_sha256

    @property
    def day1a_inventory_sha256(self) -> str:
        return self._binding.anchor.day1a_inventory_sha256

    @property
    def day1a_workflow_run_id(self) -> int:
        return self._binding.anchor.day1a_workflow_run_id

    @property
    def day1a_artifact_id(self) -> int:
        return self._binding.anchor.day1a_artifact_id

    @property
    def day1a_artifact_name(self) -> str:
        return self._binding.anchor.day1a_artifact_name

    @property
    def day1a_artifact_digest(self) -> str:
        return self._binding.anchor.day1a_artifact_digest

    def validate_pre_dispatch_contract(
        self,
        operation_profile_set: object,
        rotation_key_plan: object,
        contract_bindings: object,
    ) -> None:
        """Require exact pre-dispatch profiles, rotations, and contract identities."""

        if type(rotation_key_plan) is not dict:
            raise Day2CalibrationAuthorityError("rotation key plan must be an object")
        rotation_case_ids = _validate_rotation_key_plan(rotation_key_plan)
        if (
            rotation_key_plan["inventory_source_schema_version"]
            != self.rotation_inventory_source_schema_version
        ):
            raise Day2CalibrationAuthorityError(
                "Day1A inventory source schema does not match pre-dispatch authority"
            )
        if (
            rotation_key_plan["day1a_authority_receipt_sha256"]
            != self.day1a_authority_receipt_sha256
        ):
            raise Day2CalibrationAuthorityError(
                "Day1A authority receipt does not match pre-dispatch authority"
            )
        if rotation_key_plan["day1a_inventory_sha256"] != self.day1a_inventory_sha256:
            raise Day2CalibrationAuthorityError(
                "Day1A inventory does not match pre-dispatch authority"
            )
        if type(operation_profile_set) is not dict:
            raise Day2CalibrationAuthorityError("operation profile set must be an object")
        warmup_count, _, _ = _validate_operation_profiles(
            operation_profile_set,
            rotation_case_ids,
        )
        if warmup_count != self.warmup_block_count:
            raise Day2CalibrationAuthorityError(
                "warmup block count does not match pre-dispatch authority"
            )
        if _sha256(_canonical_json_bytes(operation_profile_set)) != (
            self.operation_profile_set_sha256
        ):
            raise Day2CalibrationAuthorityError(
                "operation profile set does not match pre-dispatch authority"
            )
        if _sha256(_canonical_json_bytes(rotation_key_plan)) != self.rotation_key_plan_sha256:
            raise Day2CalibrationAuthorityError(
                "rotation key plan does not match pre-dispatch authority"
            )
        if type(contract_bindings) is not dict:
            raise Day2CalibrationAuthorityError("contract bindings must be an object")
        _validate_contract_bindings(
            contract_bindings,
            {"rotation-key-plan.json": _canonical_json_bytes(rotation_key_plan)},
        )
        anchor = self._binding.anchor
        contract_identity_fields = (
            "experiment_contract_sha256",
            "day1_candidate_registration_receipt_sha256",
            "candidate_catalog_schema_version",
            "candidate_catalog_sha256",
            "day1a_count_bundle_schema_version",
            "day1a_count_bundle_sha256",
            "heldout_record_schema_version",
            "primitive_accounting_schema_version",
            "primitive_accounting_mapping_sha256",
            "serialized_object_accounting_schema_version",
            "serialized_object_accounting_contract_sha256",
        )
        if (
            any(
                contract_bindings[field] != getattr(anchor, field)
                for field in contract_identity_fields
            )
            or _sha256(_canonical_json_bytes(contract_bindings)) != anchor.contract_bindings_sha256
        ):
            raise Day2CalibrationAuthorityError(
                "contract bindings do not match pre-dispatch authority"
            )


@dataclass(frozen=True, slots=True)
class _Day2CalibrationReceiptBinding:
    source_git_sha: str
    outer_archive_sha256: str
    raw_measurement_blocks_sha256: str
    calibration_projection_sha256: str


@dataclass(frozen=True, slots=True)
class _Day2CalibrationBinding:
    source_git_sha: str
    experiment_behavior_set_schema_version: str
    experiment_behavior_set_sha256: str
    artifact_behavior_inventory_document: bytes
    artifact_behavior_inventory_sha256: str
    outer_archive_sha256: str
    raw_measurement_blocks_sha256: str
    operation_profile_set_sha256: str
    rotation_key_plan_sha256: str
    generated_key_inventory_sha256: str
    runtime_isolation_receipt_sha256: str
    contract_bindings_sha256: str
    calibration_projection_sha256: str


class Day2CalibrationAuthority:
    """Read-only binding capability minted only from a repository anchor."""

    __slots__ = ("_binding",)

    def __new__(cls) -> Day2CalibrationAuthority:
        raise TypeError("Day2CalibrationAuthority can only be minted by the repository anchor")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Day2CalibrationAuthority bindings are read-only")

    def __bool__(self) -> bool:
        raise TypeError(
            "Day2CalibrationAuthority must be used through validate_calibration_projection"
        )

    @property
    def source_git_sha(self) -> str:
        return self._binding.source_git_sha

    @property
    def outer_archive_sha256(self) -> str:
        return self._binding.outer_archive_sha256

    @property
    def raw_measurement_blocks_sha256(self) -> str:
        return self._binding.raw_measurement_blocks_sha256

    @property
    def calibration_projection_sha256(self) -> str:
        return self._binding.calibration_projection_sha256

    def validate_calibration_projection(
        self,
        calibration_projection: object,
    ) -> None:
        """Require an exact canonical calibration-v3 digest match."""

        _validate_calibration_projection_payload(calibration_projection)
        projection_sha256 = _sha256(_canonical_json_bytes(calibration_projection))
        if projection_sha256 != self.calibration_projection_sha256:
            raise Day2CalibrationAuthorityError(
                "calibration projection does not match repository authority"
            )


def _mint_repository_calibration_profile_authority(
    *,
    anchor: _Day2CalibrationProfileBinding,
    experiment_source_git_sha: str,
    experiment_behavior_set_schema_version: str,
    experiment_behavior_set_sha256: str,
) -> Day2CalibrationProfileAuthority:
    if type(anchor) is not _Day2CalibrationProfileBinding:
        raise Day2CalibrationAuthorityError("repository pre-dispatch anchor binding is invalid")
    if (
        anchor.rotation_inventory_source_schema_version
        != "dynamic-cssc-day1a-rotation-inventory-v1"
    ):
        raise Day2CalibrationAuthorityError(
            "repository pre-dispatch rotation inventory schema is not frozen"
        )
    if (
        type(anchor.warmup_block_count) is not int
        or anchor.warmup_block_count != CALIBRATION_WARMUP_BLOCK_COUNT
    ):
        raise Day2CalibrationAuthorityError(
            "repository pre-dispatch warmup block count is not frozen"
        )
    if experiment_behavior_set_schema_version != "dynamic-cssc-day2-behavior-set-v3":
        raise Day2CalibrationAuthorityError(
            "repository pre-dispatch Behavior Set schema is not frozen"
        )
    binding = _Day2CalibrationProfileReceiptBinding(
        anchor=anchor,
        experiment_source_git_sha=_require_lower_git_sha(
            experiment_source_git_sha,
            "repository pre-dispatch experiment source Git SHA",
        ),
        experiment_behavior_set_schema_version=experiment_behavior_set_schema_version,
        experiment_behavior_set_sha256=_require_lower_sha256(
            experiment_behavior_set_sha256,
            "repository pre-dispatch experiment Behavior Set",
        ),
    )
    authority = object.__new__(Day2CalibrationProfileAuthority)
    object.__setattr__(authority, "_binding", binding)
    return authority


def _mint_repository_calibration_authority(
    *,
    source_git_sha: str,
    outer_archive_sha256: str,
    raw_measurement_blocks_sha256: str,
    calibration_projection_sha256: str,
) -> Day2CalibrationAuthority:
    binding = _Day2CalibrationReceiptBinding(
        source_git_sha=_require_lower_git_sha(
            source_git_sha,
            "repository calibration source Git SHA",
        ),
        outer_archive_sha256=_require_lower_sha256(
            outer_archive_sha256,
            "repository calibration outer archive",
        ),
        raw_measurement_blocks_sha256=_require_lower_sha256(
            raw_measurement_blocks_sha256,
            "repository calibration raw measurement blocks",
        ),
        calibration_projection_sha256=_require_lower_sha256(
            calibration_projection_sha256,
            "repository calibration projection",
        ),
    )
    authority = object.__new__(Day2CalibrationAuthority)
    object.__setattr__(authority, "_binding", binding)
    return authority


def _canonical_json_bytes(payload: object) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day2CalibrationAuthorityError(
            "evidence contains a non-canonical JSON value"
        ) from error
    return (rendered + "\n").encode("ascii")


def _json_object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise Day2CalibrationAuthorityError(
                "evidence contains a duplicate key and is not canonical JSON"
            )
        value[key] = item
    return value


class _Shake256CounterSampler:
    __slots__ = ("_buffer", "_counter", "_domain")

    def __init__(self, domain: dict[str, object]) -> None:
        self._domain = _canonical_json_bytes(domain)
        self._counter = 0
        self._buffer = b""

    def _read(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer += hashlib.shake_256(
                self._domain + self._counter.to_bytes(16, "big")
            ).digest(64)
            self._counter += 1
        output, self._buffer = self._buffer[:size], self._buffer[size:]
        return output

    def randbelow(self, upper_bound: int) -> int:
        width = max(1, (upper_bound.bit_length() + 7) // 8)
        space = 1 << (8 * width)
        acceptance_limit = space - (space % upper_bound)
        while True:
            candidate = int.from_bytes(self._read(width), "big")
            if candidate < acceptance_limit:
                return candidate % upper_bound


def _calibration_operation_order(block_ordinal: int) -> tuple[str, ...]:
    sampler = _Shake256CounterSampler(
        {
            "analysis_kind": "calibration-operation-order",
            "block_ordinal": block_ordinal,
            "schema_version": SAMPLER_SCHEMA,
            "seed": CALIBRATION_OPERATION_ORDER_SEED,
        }
    )
    order = list(PRIMITIVE_NAMES)
    for upper in range(len(order) - 1, 0, -1):
        selected = sampler.randbelow(upper + 1)
        order[upper], order[selected] = order[selected], order[upper]
    return tuple(order)


def _decode_json(content: bytes, field: str) -> dict[str, object]:
    try:
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationAuthorityError(f"{field} is not canonical UTF-8 JSON") from error
    if type(payload) is not dict or _canonical_json_bytes(payload) != content:
        raise Day2CalibrationAuthorityError(f"{field} is not canonical JSON")
    return payload


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _fraction_text(value: Fraction) -> str:
    denominator = value.denominator
    terminating = denominator
    powers_of_two = 0
    while terminating % 2 == 0:
        terminating //= 2
        powers_of_two += 1
    powers_of_five = 0
    while terminating % 5 == 0:
        terminating //= 5
        powers_of_five += 1
    if terminating != 1:
        return f"{value.numerator}/{value.denominator}"
    decimal_places = max(powers_of_two, powers_of_five)
    scaled = value.numerator
    scaled *= 2 ** (decimal_places - powers_of_two)
    scaled *= 5 ** (decimal_places - powers_of_five)
    whole, fractional = divmod(scaled, 10**decimal_places)
    if fractional == 0:
        return str(whole)
    return f"{whole}.{fractional:0{decimal_places}d}".rstrip("0")


def _calibration_projection(value: dict[str, object]) -> dict[str, object]:
    projected_blocks: list[dict[str, object]] = []
    for block in value["blocks"]:
        samples = {sample["primitive_name"]: sample for sample in block["samples"]}
        seconds_by_primitive: dict[str, str] = {}
        for primitive_name in PRIMITIVE_NAMES:
            cases = samples[primitive_name]["cases"]
            seconds_by_primitive[primitive_name] = _fraction_text(
                max(
                    Fraction(
                        case["elapsed_ns"],
                        case["operation_count"] * 1_000_000_000,
                    )
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
        "primitive_names": list(PRIMITIVE_NAMES),
        "operation_order_seed": CALIBRATION_OPERATION_ORDER_SEED,
        "measurement_block_count": CALIBRATION_MEASUREMENT_BLOCK_COUNT,
        "measurement_stop_rule": CALIBRATION_MEASUREMENT_STOP_RULE,
        "raw_repetition_blocks": projected_blocks,
    }


def _require_lower_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day2CalibrationAuthorityError(f"{field} must be a lowercase SHA-256")
    return value


def _require_lower_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise Day2CalibrationAuthorityError(f"{field} must be a lowercase Git SHA")
    return value


def _require_positive_int(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise Day2CalibrationAuthorityError(f"{field} must be a positive strict integer")
    return value


def _require_nonempty_str(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise Day2CalibrationAuthorityError(f"{field} must be a nonempty string")
    return value


def _require_exact_keys(value: object, expected: frozenset[str], field: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise Day2CalibrationAuthorityError(f"{field} keys must be exact")


def _require_safe_relative_path(value: object, field: str) -> str:
    path_text = _require_nonempty_str(value, field)
    path = PurePosixPath(path_text)
    if (
        "\\" in path_text
        or path.is_absolute()
        or path.as_posix() != path_text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise Day2CalibrationAuthorityError(f"{field} is not a canonical relative path")
    return path_text


def _decode_profile_anchor_set(content: bytes) -> tuple[_Day2CalibrationProfileBinding, ...]:
    payload = _decode_json(content, "Day 2 pre-dispatch anchor set")
    _require_exact_keys(payload, _PROFILE_ANCHOR_SET_KEYS, "Day 2 pre-dispatch anchor set")
    if payload["schema_version"] != "dynamic-cssc-day2-calibration-profile-anchor-set-v3":
        raise Day2CalibrationAuthorityError("Day 2 pre-dispatch anchor-set schema is not frozen")
    anchors = payload["anchors"]
    if type(anchors) is not list or len(anchors) > 1:
        raise Day2CalibrationAuthorityError(
            "Day 2 pre-dispatch anchor set must contain zero or one binding"
        )
    bindings: list[_Day2CalibrationProfileBinding] = []
    for anchor in anchors:
        _require_exact_keys(anchor, _PROFILE_ANCHOR_KEYS, "Day 2 pre-dispatch anchor")
        if anchor["schema_version"] != "dynamic-cssc-day2-calibration-profile-anchor-v3":
            raise Day2CalibrationAuthorityError("Day 2 pre-dispatch anchor schema is not frozen")
        if (
            type(anchor["warmup_block_count"]) is not int
            or anchor["warmup_block_count"] != CALIBRATION_WARMUP_BLOCK_COUNT
        ):
            raise Day2CalibrationAuthorityError(
                "Day 2 pre-dispatch anchor requires exactly 3 warmup blocks"
            )
        expected_schemas = {
            "rotation_inventory_source_schema_version": (
                "dynamic-cssc-day1a-rotation-inventory-v1"
            ),
            "candidate_catalog_schema_version": "dynamic-cssc-day1-candidate-catalog-v1",
            "day1a_count_bundle_schema_version": "dynamic-cssc-day1a-count-bundle-v1",
            "heldout_record_schema_version": "dynamic-cssc-publication-heldout-record-v4",
            "primitive_accounting_schema_version": (
                "dynamic-cssc-publication-primitive-accounting-v1"
            ),
            "serialized_object_accounting_schema_version": (
                "dynamic-cssc-publication-serialized-object-accounting-v1"
            ),
        }
        for field, expected in expected_schemas.items():
            if anchor[field] != expected:
                raise Day2CalibrationAuthorityError(f"Day 2 pre-dispatch {field} is not frozen")
        for field in ("day1a_workflow_run_id", "day1a_artifact_id"):
            _require_positive_int(anchor[field], f"Day 2 pre-dispatch {field}")
        artifact_name = _require_nonempty_str(
            anchor["day1a_artifact_name"],
            "Day 2 pre-dispatch day1a_artifact_name",
        )
        if not artifact_name.startswith("r2-day1a-publication-"):
            raise Day2CalibrationAuthorityError(
                "Day 2 pre-dispatch Day1A artifact name is not frozen"
            )
        artifact_digest = _require_nonempty_str(
            anchor["day1a_artifact_digest"],
            "Day 2 pre-dispatch day1a_artifact_digest",
        )
        if not artifact_digest.startswith("sha256:"):
            raise Day2CalibrationAuthorityError(
                "Day 2 pre-dispatch Day1A artifact digest is not a SHA-256"
            )
        _require_lower_sha256(
            artifact_digest.removeprefix("sha256:"),
            "Day 2 pre-dispatch Day1A artifact digest",
        )
        digest_fields = _PROFILE_ANCHOR_KEYS - {
            "schema_version",
            "warmup_block_count",
            *expected_schemas,
            "day1a_workflow_run_id",
            "day1a_artifact_id",
            "day1a_artifact_name",
            "day1a_artifact_digest",
        }
        digests = {
            field: _require_lower_sha256(
                anchor[field],
                f"Day 2 pre-dispatch {field}",
            )
            for field in digest_fields
        }
        bindings.append(
            _Day2CalibrationProfileBinding(
                operation_profile_set_sha256=digests["operation_profile_set_sha256"],
                warmup_block_count=anchor["warmup_block_count"],
                rotation_key_plan_sha256=digests["rotation_key_plan_sha256"],
                rotation_inventory_source_schema_version=anchor[
                    "rotation_inventory_source_schema_version"
                ],
                day1a_authority_receipt_sha256=digests["day1a_authority_receipt_sha256"],
                day1a_inventory_sha256=digests["day1a_inventory_sha256"],
                contract_bindings_sha256=digests["contract_bindings_sha256"],
                experiment_contract_sha256=digests["experiment_contract_sha256"],
                day1_candidate_registration_receipt_sha256=digests[
                    "day1_candidate_registration_receipt_sha256"
                ],
                candidate_catalog_schema_version=anchor["candidate_catalog_schema_version"],
                candidate_catalog_sha256=digests["candidate_catalog_sha256"],
                day1a_count_bundle_schema_version=anchor["day1a_count_bundle_schema_version"],
                day1a_count_bundle_sha256=digests["day1a_count_bundle_sha256"],
                heldout_record_schema_version=anchor["heldout_record_schema_version"],
                primitive_accounting_schema_version=anchor["primitive_accounting_schema_version"],
                primitive_accounting_mapping_sha256=digests["primitive_accounting_mapping_sha256"],
                serialized_object_accounting_schema_version=anchor[
                    "serialized_object_accounting_schema_version"
                ],
                serialized_object_accounting_contract_sha256=digests[
                    "serialized_object_accounting_contract_sha256"
                ],
                day1a_workflow_run_id=anchor["day1a_workflow_run_id"],
                day1a_artifact_id=anchor["day1a_artifact_id"],
                day1a_artifact_name=artifact_name,
                day1a_artifact_digest=artifact_digest,
            )
        )
    return tuple(bindings)


def validate_day2_calibration_profile_anchor_document(content: bytes) -> None:
    """Validate the complete closed profile-anchor schema without granting authority."""

    _decode_profile_anchor_set(content)


def _decode_post_run_anchor_set(content: bytes) -> tuple[_Day2CalibrationBinding, ...]:
    payload = _decode_json(content, "Day 2 post-run anchor set")
    _require_exact_keys(payload, _POST_RUN_ANCHOR_SET_KEYS, "Day 2 post-run anchor set")
    if payload["schema_version"] != "dynamic-cssc-day2-calibration-post-run-anchor-set-v4":
        raise Day2CalibrationAuthorityError("Day 2 post-run anchor-set schema is not frozen")
    anchors = payload["anchors"]
    if type(anchors) is not list or len(anchors) > 1:
        raise Day2CalibrationAuthorityError(
            "Day 2 post-run anchor set must contain zero or one binding"
        )
    bindings: list[_Day2CalibrationBinding] = []
    for anchor in anchors:
        _require_exact_keys(anchor, _POST_RUN_ANCHOR_KEYS, "Day 2 post-run anchor")
        if anchor["schema_version"] != "dynamic-cssc-day2-calibration-post-run-anchor-v4":
            raise Day2CalibrationAuthorityError("Day 2 post-run anchor schema is not frozen")
        if anchor["experiment_behavior_set_schema_version"] != "dynamic-cssc-day2-behavior-set-v3":
            raise Day2CalibrationAuthorityError("Day 2 post-run Behavior Set schema is not frozen")
        experiment_source_git_sha = _require_lower_git_sha(
            anchor["experiment_source_git_sha"],
            "Day 2 post-run experiment source Git SHA",
        )
        artifact_behavior_inventory = _validate_artifact_behavior_inventory(
            anchor["artifact_behavior_inventory"],
            source_git_sha=experiment_source_git_sha,
        )
        artifact_behavior_inventory_document = _canonical_json_bytes(artifact_behavior_inventory)
        artifact_behavior_inventory_sha256 = _require_lower_sha256(
            anchor["artifact_behavior_inventory_sha256"],
            "Day 2 post-run artifact Behavior inventory",
        )
        if artifact_behavior_inventory_sha256 != _sha256(artifact_behavior_inventory_document):
            raise Day2CalibrationAuthorityError(
                "Day 2 post-run artifact Behavior inventory digest mismatch"
            )
        if (
            artifact_behavior_inventory["behavior_set_schema_version"]
            != anchor["experiment_behavior_set_schema_version"]
            or artifact_behavior_inventory["behavior_set_sha256"]
            != anchor["experiment_behavior_set_sha256"]
        ):
            raise Day2CalibrationAuthorityError(
                "Day 2 post-run artifact Behavior inventory does not match its S1 binding"
            )
        bindings.append(
            _Day2CalibrationBinding(
                source_git_sha=experiment_source_git_sha,
                experiment_behavior_set_schema_version=anchor[
                    "experiment_behavior_set_schema_version"
                ],
                experiment_behavior_set_sha256=_require_lower_sha256(
                    anchor["experiment_behavior_set_sha256"],
                    "Day 2 post-run experiment Behavior Set",
                ),
                artifact_behavior_inventory_document=artifact_behavior_inventory_document,
                artifact_behavior_inventory_sha256=artifact_behavior_inventory_sha256,
                outer_archive_sha256=_require_lower_sha256(
                    anchor["outer_archive_sha256"],
                    "Day 2 post-run outer archive",
                ),
                raw_measurement_blocks_sha256=_require_lower_sha256(
                    anchor["raw_measurement_blocks_sha256"],
                    "Day 2 post-run raw measurement blocks",
                ),
                operation_profile_set_sha256=_require_lower_sha256(
                    anchor["operation_profile_set_sha256"],
                    "Day 2 post-run operation profile set",
                ),
                rotation_key_plan_sha256=_require_lower_sha256(
                    anchor["rotation_key_plan_sha256"],
                    "Day 2 post-run rotation key plan",
                ),
                generated_key_inventory_sha256=_require_lower_sha256(
                    anchor["generated_key_inventory_sha256"],
                    "Day 2 post-run generated key inventory",
                ),
                runtime_isolation_receipt_sha256=_require_lower_sha256(
                    anchor["runtime_isolation_receipt_sha256"],
                    "Day 2 post-run runtime isolation receipt",
                ),
                contract_bindings_sha256=_require_lower_sha256(
                    anchor["contract_bindings_sha256"],
                    "Day 2 post-run contract bindings",
                ),
                calibration_projection_sha256=_require_lower_sha256(
                    anchor["calibration_projection_sha256"],
                    "Day 2 post-run calibration projection",
                ),
            )
        )
    return tuple(bindings)


def validate_day2_calibration_post_run_anchor_document(content: bytes) -> None:
    """Validate the complete post-run anchor schema without granting authority."""

    _decode_post_run_anchor_set(content)


def _read_repository_anchor_set(relative_path: Path) -> bytes:
    repository_root = Path(__file__).resolve().parents[2]
    if relative_path not in {_PROFILE_ANCHOR_PATH, _POST_RUN_ANCHOR_PATH}:
        raise Day2CalibrationAuthorityError("repository Day 2 anchor path is not approved")
    from dynamic_cssc.evidence_compatibility import (
        EvidenceCompatibilityError,
        EvidenceRole,
        read_current_role_evidence_data,
    )

    try:
        blobs = read_current_role_evidence_data(EvidenceRole.DAY2, repository_root)
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            "repository Day 2 anchor must be a Git 100644 data blob: " + str(error)
        ) from error
    by_path = {blob.path: blob for blob in blobs}
    expected_paths = {
        _PROFILE_ANCHOR_PATH.as_posix(),
        _POST_RUN_ANCHOR_PATH.as_posix(),
        "config/evidence-compatibility-anchors.json",
    }
    if set(by_path) != expected_paths:
        raise Day2CalibrationAuthorityError("repository Day 2 evidence-data path set is not exact")
    content = by_path[relative_path.as_posix()].content
    if len(content) > _MAX_ANCHOR_SET_BYTES:
        raise Day2CalibrationAuthorityError(
            f"repository anchor {relative_path.as_posix()} exceeds the closed size limit"
        )
    return content


def _validate_calibration_projection_payload(value: object) -> None:
    _require_exact_keys(value, _CALIBRATION_PROJECTION_KEYS, "calibration projection")
    if value["schema_version"] != "dynamic-cssc-publication-calibration-v3":
        raise Day2CalibrationAuthorityError("calibration projection schema is not frozen")
    if value["primitive_names"] != list(PRIMITIVE_NAMES):
        raise Day2CalibrationAuthorityError("calibration projection primitive_names are not frozen")
    if (
        type(value["operation_order_seed"]) is not int
        or value["operation_order_seed"] != CALIBRATION_OPERATION_ORDER_SEED
    ):
        raise Day2CalibrationAuthorityError(
            "calibration projection operation-order seed is not frozen"
        )
    if (
        type(value["measurement_block_count"]) is not int
        or value["measurement_block_count"] != CALIBRATION_MEASUREMENT_BLOCK_COUNT
    ):
        raise Day2CalibrationAuthorityError(
            "calibration projection measurement block count is not frozen"
        )
    if value["measurement_stop_rule"] != CALIBRATION_MEASUREMENT_STOP_RULE:
        raise Day2CalibrationAuthorityError(
            "calibration projection measurement stop rule is not frozen"
        )
    blocks = value["raw_repetition_blocks"]
    if type(blocks) is not list or len(blocks) != CALIBRATION_MEASUREMENT_BLOCK_COUNT:
        raise Day2CalibrationAuthorityError(
            "calibration projection must contain exactly 14 whole blocks"
        )
    for block_ordinal, block in enumerate(blocks):
        field = f"calibration projection block {block_ordinal}"
        _require_exact_keys(block, _CALIBRATION_PROJECTION_BLOCK_KEYS, field)
        if block["schema_version"] != "dynamic-cssc-publication-calibration-block-v1":
            raise Day2CalibrationAuthorityError(f"{field} schema is not frozen")
        if type(block["block_ordinal"]) is not int or block["block_ordinal"] != block_ordinal:
            raise Day2CalibrationAuthorityError(
                "calibration projection block ordinals must be exact and contiguous"
            )
        if type(block["operation_order"]) is not list or tuple(
            block["operation_order"]
        ) != _calibration_operation_order(block_ordinal):
            raise Day2CalibrationAuthorityError(
                "calibration projection operation_order is not the frozen permutation"
            )
        seconds_by_primitive = block["seconds_by_primitive"]
        _require_exact_keys(
            seconds_by_primitive,
            frozenset(PRIMITIVE_NAMES),
            f"{field} seconds_by_primitive",
        )
        for primitive_name in PRIMITIVE_NAMES:
            seconds = seconds_by_primitive[primitive_name]
            try:
                parsed_seconds = Fraction(seconds) if type(seconds) is str else Fraction()
            except (ValueError, ZeroDivisionError):
                parsed_seconds = Fraction()
            if (
                type(seconds) is not str
                or parsed_seconds <= 0
                or _fraction_text(parsed_seconds) != seconds
            ):
                raise Day2CalibrationAuthorityError(
                    f"{field} {primitive_name} must be a positive canonical exact rational"
                )


def _read_archive(path: Path) -> tuple[bytes, dict[str, bytes]]:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        raise Day2CalibrationAuthorityError("archive_path must be a regular non-symlink file")
    content = path.read_bytes()
    if len(content) > _MAX_ARCHIVE_BYTES:
        raise Day2CalibrationAuthorityError("archive exceeds the closed size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)) or set(names) != _ARCHIVE_FILENAMES:
                raise Day2CalibrationAuthorityError(
                    "archive members must equal the exact closed evidence file set"
                )
            if len({name.casefold() for name in names}) != len(names):
                raise Day2CalibrationAuthorityError("archive member names collide by case")
            total_size = 0
            for info in infos:
                mode = (info.external_attr >> 16) & 0xFFFF
                if info.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG:
                    raise Day2CalibrationAuthorityError(
                        "archive members must be Unix regular files"
                    )
                if info.flag_bits & 0x1:
                    raise Day2CalibrationAuthorityError("encrypted archive members are forbidden")
                if info.file_size > _MAX_MEMBER_BYTES:
                    raise Day2CalibrationAuthorityError("archive member exceeds the size limit")
                total_size += info.file_size
                if total_size > _MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise Day2CalibrationAuthorityError(
                        "archive exceeds the total uncompressed size limit"
                    )
                if info.file_size and (
                    info.compress_size == 0
                    or info.file_size / info.compress_size > _MAX_COMPRESSION_RATIO
                ):
                    raise Day2CalibrationAuthorityError(
                        "archive member exceeds the compression-ratio limit"
                    )
            members = {info.filename: archive.read(info) for info in infos}
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise Day2CalibrationAuthorityError("archive is not a readable ZIP file") from error
    return content, members


def _validate_github_metadata(value: object, outer_sha256: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != _GITHUB_METADATA_KEYS:
        raise Day2CalibrationAuthorityError("GitHub metadata keys must be exact")
    if value["schema_version"] != "dynamic-cssc-publication-day2-github-artifact-metadata-v2":
        raise Day2CalibrationAuthorityError("GitHub metadata schema is not frozen")
    for field in ("repository", "artifact_name"):
        if type(value[field]) is not str or not value[field]:
            raise Day2CalibrationAuthorityError(f"GitHub metadata {field} is invalid")
    for field in ("repository_id", "run_id", "run_attempt", "artifact_id"):
        if type(value[field]) is not int or value[field] <= 0:
            raise Day2CalibrationAuthorityError(f"GitHub metadata {field} is invalid")
    if value["workflow_path"] != ".github/workflows/day2-publication-calibration.yml":
        raise Day2CalibrationAuthorityError("GitHub metadata workflow_path is not frozen")
    _require_lower_sha256(value["workflow_file_sha256"], "github_metadata.workflow_file_sha256")
    if value["event_name"] != "workflow_dispatch":
        raise Day2CalibrationAuthorityError("GitHub metadata event_name is not frozen")
    if type(value["ref"]) is not str or not value["ref"].startswith("refs/"):
        raise Day2CalibrationAuthorityError("GitHub metadata ref is invalid")
    if type(value["head_sha"]) is not str or _LOWER_GIT_SHA.fullmatch(value["head_sha"]) is None:
        raise Day2CalibrationAuthorityError("GitHub metadata head_sha is invalid")
    artifact_digest = value["artifact_digest"]
    if type(artifact_digest) is not str or not artifact_digest.startswith("sha256:"):
        raise Day2CalibrationAuthorityError("GitHub artifact digest is invalid")
    _require_lower_sha256(
        artifact_digest.removeprefix("sha256:"),
        "github_metadata.artifact_digest",
    )
    if value["inner_archive_sha256"] != outer_sha256:
        raise Day2CalibrationAuthorityError(
            "GitHub metadata inner archive digest does not match the archive"
        )
    return value


def _validate_run_status(value: dict[str, object]) -> None:
    _require_exact_keys(value, _RUN_STATUS_KEYS, "run status")
    expected = {
        "schema_version": "dynamic-cssc-publication-day2-run-status-v1",
        "status": "pass",
        "evidence_scope": EVIDENCE_SCOPE,
        "producer_validation_passed": True,
        "formal_authority_granted": False,
        "complete_cost_claim_allowed": False,
        "mixed_circuit_parameter_claim_allowed": False,
        "r4_claim_allowed": False,
        "security_claim_allowed": False,
    }
    if value["formal_authority_granted"] is not False:
        raise Day2CalibrationAuthorityError("run status cannot grant authority")
    for field, expected_value in expected.items():
        if type(value[field]) is not type(expected_value) or value[field] != expected_value:
            raise Day2CalibrationAuthorityError(f"run status {field} is not frozen")


def _validate_artifact_behavior_inventory(
    value: object,
    *,
    source_git_sha: str,
) -> dict[str, object]:
    _require_exact_keys(value, _BEHAVIOR_INVENTORY_KEYS, "artifact Behavior inventory")
    if value["schema_version"] != "dynamic-cssc-evidence-behavior-inventory-v1":
        raise Day2CalibrationAuthorityError("artifact Behavior inventory schema is not frozen")
    if value["role"] != "day2":
        raise Day2CalibrationAuthorityError("artifact Behavior inventory role is not Day 2")
    if value["source_git_sha"] != source_git_sha:
        raise Day2CalibrationAuthorityError(
            "artifact Behavior inventory source SHA does not match source provenance"
        )
    if value["behavior_set_schema_version"] != "dynamic-cssc-day2-behavior-set-v3":
        raise Day2CalibrationAuthorityError("artifact Day 2 Behavior Set schema is not frozen")
    entries = value["entries"]
    if type(entries) is not list or not entries:
        raise Day2CalibrationAuthorityError("artifact Behavior inventory entries must be nonempty")
    paths: list[str] = []
    for index, entry in enumerate(entries):
        _require_exact_keys(
            entry,
            _BEHAVIOR_INVENTORY_ENTRY_KEYS,
            f"artifact Behavior inventory entry {index}",
        )
        path = _require_safe_relative_path(
            entry["path"],
            f"artifact Behavior inventory entry {index} path",
        )
        if entry["mode"] not in {"100644", "100755"}:
            raise Day2CalibrationAuthorityError(
                "artifact Behavior inventory entry mode must be a regular Git blob mode"
            )
        if entry["object_type"] != "blob":
            raise Day2CalibrationAuthorityError(
                "artifact Behavior inventory entry type must be blob"
            )
        _require_lower_git_sha(
            entry["object_id"],
            f"artifact Behavior inventory entry {index} object ID",
        )
        paths.append(path)
    from dynamic_cssc.evidence_compatibility import EvidenceRole, repository_behavior_paths

    expected_paths = list(repository_behavior_paths(EvidenceRole.DAY2))
    if paths != expected_paths:
        raise Day2CalibrationAuthorityError(
            "artifact Behavior inventory paths must equal the exact repository Day 2 set"
        )
    behavior_set = {
        "behavior_set_schema_version": value["behavior_set_schema_version"],
        "entries": entries,
        "role": value["role"],
    }
    if value["behavior_set_sha256"] != _sha256(_canonical_json_bytes(behavior_set)):
        raise Day2CalibrationAuthorityError(
            "artifact Behavior Set digest does not match the exact central inventory"
        )
    return value


def _validate_source_provenance(value: dict[str, object]) -> dict[str, object]:
    _require_exact_keys(value, _SOURCE_PROVENANCE_KEYS, "source provenance")
    if value["schema_version"] != "dynamic-cssc-publication-day2-source-provenance-v2":
        raise Day2CalibrationAuthorityError("source provenance schema is not frozen")
    _require_nonempty_str(value["repository"], "source provenance repository")
    _require_positive_int(value["repository_id"], "source provenance repository_id")
    _require_lower_git_sha(value["git_sha"], "source provenance git_sha")
    _require_lower_git_sha(value["git_tree"], "source provenance git_tree")
    if (
        value["git_status_before_sha256"] != _EMPTY_SHA256
        or value["git_status_after_sha256"] != _EMPTY_SHA256
        or value["tracked_tree_clean_before"] is not True
        or value["tracked_tree_clean_after"] is not True
        or value["untracked_nonignored_clean_before"] is not True
        or value["untracked_nonignored_clean_after"] is not True
    ):
        raise Day2CalibrationAuthorityError("source tree must be clean before and after capture")
    return _validate_artifact_behavior_inventory(
        value["behavior_inventory"],
        source_git_sha=value["git_sha"],
    )


def _validate_workflow_provenance(
    value: dict[str, object],
    source: dict[str, object],
    github_metadata: dict[str, object],
) -> None:
    _require_exact_keys(value, _WORKFLOW_PROVENANCE_KEYS, "workflow provenance")
    if value["schema_version"] != "dynamic-cssc-publication-day2-workflow-provenance-v1":
        raise Day2CalibrationAuthorityError("workflow provenance schema is not frozen")
    if value["event_name"] != "workflow_dispatch":
        raise Day2CalibrationAuthorityError("workflow event_name is not frozen")
    _require_nonempty_str(value["repository"], "workflow repository")
    _require_positive_int(value["repository_id"], "workflow repository_id")
    if value["workflow_path"] != ".github/workflows/day2-publication-calibration.yml":
        raise Day2CalibrationAuthorityError("workflow path is not frozen")
    _require_lower_sha256(value["workflow_file_sha256"], "workflow file")
    _require_positive_int(value["run_id"], "workflow run_id")
    _require_positive_int(value["run_attempt"], "workflow run_attempt")
    if type(value["ref"]) is not str or not value["ref"].startswith("refs/"):
        raise Day2CalibrationAuthorityError("workflow ref is invalid")
    _require_lower_git_sha(value["head_sha"], "workflow head_sha")
    _require_nonempty_str(value["artifact_name"], "workflow artifact_name")
    if source["git_sha"] != value["head_sha"]:
        raise Day2CalibrationAuthorityError("source and workflow Git SHA do not match")
    if (
        source["repository"] != value["repository"]
        or source["repository_id"] != value["repository_id"]
    ):
        raise Day2CalibrationAuthorityError("source and workflow repository do not match")
    for field in _WORKFLOW_PROVENANCE_KEYS - {"schema_version"}:
        if value[field] != github_metadata[field]:
            raise Day2CalibrationAuthorityError(
                "workflow provenance does not match GitHub metadata"
            )


def _strict_int_list(value: object, field: str) -> list[int]:
    if type(value) is not list or any(type(item) is not int for item in value):
        raise Day2CalibrationAuthorityError(f"{field} must contain strict integers")
    return value


def _canonical_cpu_list(value: object, field: str) -> list[int]:
    cpus = _strict_int_list(value, field)
    if not cpus or cpus != sorted(set(cpus)) or cpus[0] < 0:
        raise Day2CalibrationAuthorityError(
            f"{field} must be a nonempty sorted unique nonnegative CPU list"
        )
    return cpus


def _validate_openfhe_build(value: dict[str, object]) -> None:
    _require_exact_keys(value, _OPENFHE_BUILD_KEYS, "OpenFHE build")
    if value["schema_version"] != "dynamic-cssc-publication-day2-openfhe-build-v1":
        raise Day2CalibrationAuthorityError("OpenFHE build schema is not frozen")
    if value["repository"] != "https://github.com/openfheorg/openfhe-development.git":
        raise Day2CalibrationAuthorityError("OpenFHE repository is not frozen")
    if value["version"] != "1.5.1":
        raise Day2CalibrationAuthorityError("OpenFHE version is not frozen")
    if value["commit"] != _OPENFHE_COMMIT:
        raise Day2CalibrationAuthorityError("OpenFHE commit is not frozen")
    _require_lower_git_sha(value["source_git_tree"], "OpenFHE source Git tree")
    if value["source_tree_clean"] is not True:
        raise Day2CalibrationAuthorityError("OpenFHE source tree must be clean")
    for field in (
        "source_tree_sha256",
        "cmake_cache_sha256",
        "compile_commands_sha256",
        "installed_manifest_sha256",
        "openfhe_shared_library_sha256",
        "probe_source_sha256",
        "probe_binary_sha256",
        "manifest_generator_sha256",
        "bundle_validator_sha256",
        "linked_library_inventory_sha256",
    ):
        _require_lower_sha256(value[field], f"OpenFHE {field}")
    _require_nonempty_str(value["cmake_version"], "OpenFHE CMake version")
    _require_nonempty_str(value["ninja_version"], "OpenFHE Ninja version")
    if type(value["cmake_flags"]) is not dict or value["cmake_flags"] != _OPENFHE_CMAKE_FLAGS:
        raise Day2CalibrationAuthorityError("OpenFHE CMake flags are not frozen")
    for field in (
        "compiler_path",
        "compiler_vendor",
        "compiler_version",
        "compiler_target",
    ):
        _require_nonempty_str(value[field], f"OpenFHE {field}")
    compile_flags = value["effective_compile_flags"]
    if (
        type(compile_flags) is not list
        or not compile_flags
        or any(type(flag) is not str or not flag for flag in compile_flags)
        or len(compile_flags) != len(set(compile_flags))
    ):
        raise Day2CalibrationAuthorityError(
            "OpenFHE effective compile flags must be nonempty and unique"
        )
    if "-O3" not in compile_flags or "-fopenmp" not in compile_flags:
        raise Day2CalibrationAuthorityError(
            "OpenFHE effective compile flags do not match the frozen build profile"
        )
    if any(flag == "-march=native" or flag == "-mtune=native" for flag in compile_flags):
        raise Day2CalibrationAuthorityError("OpenFHE native optimization flags are forbidden")


def _validate_host_profile(
    value: dict[str, object],
    openfhe: dict[str, object],
) -> None:
    _require_exact_keys(value, _HOST_PROFILE_KEYS, "host profile")
    if value["schema_version"] != "dynamic-cssc-publication-day2-host-profile-v2":
        raise Day2CalibrationAuthorityError("host profile schema is not frozen")

    hardware = value["hardware"]
    _require_exact_keys(hardware, _HOST_HARDWARE_KEYS, "host hardware")
    for field in (
        "architecture",
        "cpu_vendor",
        "cpu_model_name",
        "cpu_family",
        "cpu_model",
        "cpu_stepping",
        "microcode",
    ):
        _require_nonempty_str(hardware[field], f"host hardware {field}")
    for field in (
        "socket_count",
        "physical_core_count",
        "logical_cpu_count",
        "memory_bytes",
    ):
        _require_positive_int(hardware[field], f"host hardware {field}")
    if hardware["physical_core_count"] > hardware["logical_cpu_count"]:
        raise Day2CalibrationAuthorityError("host physical cores cannot exceed logical CPUs")
    _require_lower_sha256(hardware["numa_topology_sha256"], "host NUMA topology")

    os_profile = value["os"]
    _require_exact_keys(os_profile, _HOST_OS_KEYS, "host OS")
    for field in (
        "distribution_id",
        "distribution_version",
        "kernel_release",
        "glibc_version",
    ):
        _require_nonempty_str(os_profile[field], f"host OS {field}")
    _require_lower_sha256(os_profile["kernel_cmdline_sha256"], "host kernel cmdline")
    _require_lower_sha256(
        os_profile["runner_image_identity_sha256"],
        "host runner image identity",
    )

    compiler = value["compiler"]
    _require_exact_keys(compiler, _HOST_COMPILER_KEYS, "host compiler")
    compiler_bindings = {
        "path": "compiler_path",
        "vendor": "compiler_vendor",
        "version": "compiler_version",
        "target": "compiler_target",
    }
    for host_field, openfhe_field in compiler_bindings.items():
        _require_nonempty_str(compiler[host_field], f"host compiler {host_field}")
        if compiler[host_field] != openfhe[openfhe_field]:
            raise Day2CalibrationAuthorityError("host compiler does not match the OpenFHE build")

    affinity = value["affinity"]
    _require_exact_keys(affinity, _HOST_AFFINITY_KEYS, "host affinity")
    requested = _canonical_cpu_list(affinity["requested_cpu_list"], "host requested CPU affinity")
    verified = _canonical_cpu_list(
        affinity["verified_probe_cpu_list"], "host verified probe CPU affinity"
    )
    if requested != verified:
        raise Day2CalibrationAuthorityError(
            "host requested and verified probe CPU affinity must match exactly"
        )
    if verified[-1] >= hardware["logical_cpu_count"]:
        raise Day2CalibrationAuthorityError("host CPU affinity exceeds logical CPU count")
    if affinity["probe_affinity_observation_stage"] != "pre-and-post-measurement-identical":
        raise Day2CalibrationAuthorityError("host probe affinity observation is incomplete")
    if type(affinity["omp_num_threads"]) is not int or affinity["omp_num_threads"] != len(
        verified
    ):
        raise Day2CalibrationAuthorityError(
            "host OpenMP thread count must equal the effective CPU affinity"
        )
    if affinity["omp_proc_bind"] != "close" or affinity["omp_places"] != "cores":
        raise Day2CalibrationAuthorityError("host OpenMP affinity policy is not frozen")
    allowed_sets = affinity["per_block_allowed_cpu_sets"]
    if type(allowed_sets) is not list or len(allowed_sets) != CALIBRATION_MEASUREMENT_BLOCK_COUNT:
        raise Day2CalibrationAuthorityError(
            "host affinity must bind exactly one allowed CPU set per measurement block"
        )
    for block_ordinal, allowed in enumerate(allowed_sets):
        if (
            _canonical_cpu_list(allowed, f"host allowed CPU set for block {block_ordinal}")
            != verified
        ):
            raise Day2CalibrationAuthorityError(
                "host allowed CPU sets must equal the verified probe CPU affinity"
            )

    power = value["power"]
    _require_exact_keys(power, _HOST_POWER_KEYS, "host power")
    _require_nonempty_str(power["scaling_driver"], "host power scaling_driver")
    governors = power["governor_by_cpu"]
    if type(governors) is not list or len(governors) != len(verified):
        raise Day2CalibrationAuthorityError(
            "host power governor inventory must exactly cover effective CPUs"
        )
    for index, (entry, expected_cpu) in enumerate(zip(governors, verified, strict=True)):
        _require_exact_keys(entry, _HOST_GOVERNOR_KEYS, f"host governor {index}")
        if type(entry["cpu"]) is not int or entry["cpu"] != expected_cpu:
            raise Day2CalibrationAuthorityError(
                "host power governor CPUs must match effective affinity"
            )
        _require_nonempty_str(entry["governor"], f"host governor {index} policy")
        _require_nonempty_str(
            entry["energy_performance_preference"],
            f"host governor {index} energy preference",
        )
        minimum = _require_positive_int(entry["min_khz"], f"host governor {index} min_khz")
        maximum = _require_positive_int(entry["max_khz"], f"host governor {index} max_khz")
        if minimum > maximum:
            raise Day2CalibrationAuthorityError(
                "host governor minimum frequency exceeds maximum frequency"
            )
    if power["turbo_state"] not in {"enabled", "disabled", "unobservable"}:
        raise Day2CalibrationAuthorityError("host turbo state is invalid")
    if power["power_source"] not in {
        "ac-observed-online",
        "battery-or-disconnected-observed",
        "server-or-vm-no-battery-interface",
        "unobservable",
    }:
        raise Day2CalibrationAuthorityError("host power source is invalid")
    counters_observable = power["thermal_throttle_counters_observable"]
    if type(counters_observable) is not bool:
        raise Day2CalibrationAuthorityError(
            "host thermal throttle observability must be Boolean"
        )
    before_count = power["thermal_throttle_count_before"]
    after_count = power["thermal_throttle_count_after"]
    throttling_observed = power["thermal_throttling_observed"]
    if counters_observable:
        if (
            type(before_count) is not int
            or before_count < 0
            or type(after_count) is not int
            or after_count < before_count
            or type(throttling_observed) is not bool
            or throttling_observed != (after_count > before_count)
        ):
            raise Day2CalibrationAuthorityError(
                "host thermal throttle counters are inconsistent"
            )
    elif before_count is not None or after_count is not None or throttling_observed is not None:
        raise Day2CalibrationAuthorityError(
            "unobservable host thermal throttle fields must remain null"
        )
    if throttling_observed is True:
        raise Day2CalibrationAuthorityError(
            "host thermal throttling was observed during calibration"
        )


def _validate_contract_bindings(
    value: dict[str, object],
    members: dict[str, bytes],
) -> None:
    _require_exact_keys(value, _CONTRACT_BINDING_KEYS, "contract bindings")
    if value["schema_version"] != "dynamic-cssc-publication-day2-contract-bindings-v1":
        raise Day2CalibrationAuthorityError("contract binding schema is not frozen")
    for field in (
        "experiment_contract_sha256",
        "day1_candidate_registration_receipt_sha256",
        "candidate_catalog_sha256",
        "day1a_count_bundle_sha256",
        "primitive_accounting_mapping_sha256",
        "serialized_object_accounting_contract_sha256",
        "day1a_rotation_inventory_sha256",
        "rotation_key_plan_sha256",
    ):
        _require_lower_sha256(value[field], f"contract binding {field}")
    if value["candidate_catalog_schema_version"] != "dynamic-cssc-day1-candidate-catalog-v1":
        raise Day2CalibrationAuthorityError("candidate catalog schema is not frozen")
    if value["fixed_candidate_ids"] != list(FIXED_CANDIDATE_IDS):
        raise Day2CalibrationAuthorityError("fixed candidate IDs are not frozen")
    if value["reference_candidate_ids"] != list(REFERENCE_CANDIDATE_IDS):
        raise Day2CalibrationAuthorityError("reference candidate IDs are not frozen")
    if value["ablation_candidate_ids"] != list(ABLATION_CANDIDATE_IDS):
        raise Day2CalibrationAuthorityError("ablation candidate IDs are not frozen")
    expected_schema_versions = {
        "day1a_count_bundle_schema_version": "dynamic-cssc-day1a-count-bundle-v1",
        "heldout_record_schema_version": "dynamic-cssc-publication-heldout-record-v4",
        "primitive_accounting_schema_version": ("dynamic-cssc-publication-primitive-accounting-v1"),
        "serialized_object_accounting_schema_version": (
            "dynamic-cssc-publication-serialized-object-accounting-v1"
        ),
    }
    for field, expected in expected_schema_versions.items():
        if value[field] != expected:
            label = field.removesuffix("_schema_version").replace("_", " ")
            raise Day2CalibrationAuthorityError(f"{label} schema is not frozen")
    rotation_plan = _decode_json(members["rotation-key-plan.json"], "rotation-key-plan.json")
    if value["day1a_rotation_inventory_sha256"] != rotation_plan["day1a_inventory_sha256"]:
        raise Day2CalibrationAuthorityError(
            "Day1A rotation inventory binding does not match rotation-key-plan.json"
        )
    if value["rotation_key_plan_sha256"] != _sha256(members["rotation-key-plan.json"]):
        raise Day2CalibrationAuthorityError(
            "rotation key-plan binding does not match rotation-key-plan.json"
        )


def _validate_producer_validation(
    value: dict[str, object],
    *,
    openfhe: dict[str, object],
    contract: dict[str, object],
    members: dict[str, bytes],
    calibration_projection_sha256: str,
) -> None:
    _require_exact_keys(value, _PRODUCER_VALIDATION_KEYS, "producer validation")
    if value["schema_version"] != "dynamic-cssc-publication-day2-producer-validation-v1":
        raise Day2CalibrationAuthorityError("producer validation schema is not frozen")
    if value["formal_authority_granted"] is not False:
        raise Day2CalibrationAuthorityError("producer validation cannot grant authority")
    if value["status"] != "pass" or value["all_profiles_correct"] is not True:
        raise Day2CalibrationAuthorityError("producer validation must report exact pass state")
    for field in _PRODUCER_VALIDATION_KEYS - {
        "schema_version",
        "status",
        "formal_authority_granted",
        "all_profiles_correct",
    }:
        _require_lower_sha256(value[field], f"producer validation {field}")
    identity_bindings = {
        "validator_source_sha256": "bundle_validator_sha256",
        "manifest_generator_sha256": "manifest_generator_sha256",
        "probe_source_sha256": "probe_source_sha256",
        "probe_binary_sha256": "probe_binary_sha256",
    }
    if any(
        value[producer_field] != openfhe[openfhe_field]
        for producer_field, openfhe_field in identity_bindings.items()
    ):
        raise Day2CalibrationAuthorityError("producer identities do not match the OpenFHE build")
    file_bindings = {
        "raw_measurement_blocks_sha256": "raw-measurement-blocks.json",
        "operation_profile_set_sha256": "operation-profile-set.json",
        "rotation_key_plan_sha256": "rotation-key-plan.json",
        "generated_key_inventory_sha256": "generated-key-inventory.json",
        "runtime_isolation_receipt_sha256": "runtime-isolation-receipt.json",
    }
    for producer_field, filename in file_bindings.items():
        if value[producer_field] != _sha256(members[filename]):
            label = producer_field.removesuffix("_sha256").replace("_", " ")
            raise Day2CalibrationAuthorityError(f"{label} SHA-256 binding mismatch")
    if value["calibration_projection_sha256"] != calibration_projection_sha256:
        raise Day2CalibrationAuthorityError("calibration projection SHA-256 mismatch")
    if value["candidate_catalog_sha256"] != contract["candidate_catalog_sha256"]:
        raise Day2CalibrationAuthorityError("candidate catalog SHA-256 binding mismatch")
    if value["accounting_contract_sha256"] != contract["primitive_accounting_mapping_sha256"]:
        raise Day2CalibrationAuthorityError("accounting contract SHA-256 binding mismatch")


def _validate_rotation_key_plan(value: dict[str, object]) -> tuple[str, ...]:
    _require_exact_keys(value, _ROTATION_PLAN_KEYS, "rotation key plan")
    if value["schema_version"] != "dynamic-cssc-publication-rotation-key-plan-v2":
        raise Day2CalibrationAuthorityError("rotation key plan schema is not frozen")
    _require_nonempty_str(
        value["inventory_source_schema_version"],
        "rotation inventory source schema",
    )
    _require_lower_sha256(value["day1a_authority_receipt_sha256"], "Day1A authority receipt")
    _require_lower_sha256(value["day1a_inventory_sha256"], "Day1A rotation inventory")
    if type(value["effective_slots"]) is not int or value["effective_slots"] != 4096:
        raise Day2CalibrationAuthorityError("rotation effective_slots must equal 4096")
    required = _strict_int_list(value["required_exact_indices"], "required rotation indices")
    if (
        not required
        or required != sorted(set(required))
        or any(index == 0 or not -4095 <= index <= 4095 for index in required)
    ):
        raise Day2CalibrationAuthorityError(
            "required rotation indices must be canonical, nonzero, and in range"
        )
    if len({index % 4096 for index in required}) != len(required):
        raise Day2CalibrationAuthorityError("rotation inventory contains modulo-congruent aliases")
    planned = _strict_int_list(value["planned_exact_indices"], "planned rotation indices")
    if planned != required:
        raise Day2CalibrationAuthorityError(
            "planned rotation indices must exactly match required indices"
        )
    if value["key_plan_kind"] != "direct-exact-index-v1":
        raise Day2CalibrationAuthorityError("rotation key plan kind is not frozen")
    if type(value["composite_decompositions"]) is not list or value["composite_decompositions"]:
        raise Day2CalibrationAuthorityError("composite rotation decompositions are forbidden in v1")
    expected_case_ids = tuple(f"index={index}" for index in required)
    case_ids = value["eval_rotate_case_ids"]
    if type(case_ids) is not list or tuple(case_ids) != expected_case_ids:
        raise Day2CalibrationAuthorityError(
            "eval_rotate case IDs must exactly cover the required rotation indices"
        )
    return expected_case_ids


def _validate_generated_key_inventory(
    value: dict[str, object],
    rotation_key_plan: dict[str, object],
) -> None:
    _require_exact_keys(value, _GENERATED_KEY_INVENTORY_KEYS, "generated key inventory")
    if value["schema_version"] != "dynamic-cssc-publication-generated-key-inventory-v1":
        raise Day2CalibrationAuthorityError("generated key inventory schema is not frozen")
    if value["rotation_key_plan_sha256"] != _sha256(
        _canonical_json_bytes(rotation_key_plan)
    ):
        raise Day2CalibrationAuthorityError(
            "generated key inventory does not bind the rotation key plan"
        )
    generated = _strict_int_list(value["generated_exact_indices"], "generated rotation indices")
    if generated != rotation_key_plan["required_exact_indices"]:
        raise Day2CalibrationAuthorityError(
            "generated rotation indices must exactly match the pre-dispatch plan"
        )
    _require_lower_sha256(
        value["serialized_rotation_key_inventory_sha256"],
        "serialized rotation-key inventory",
    )
    _require_positive_int(value["serialized_rotation_key_bytes"], "serialized rotation-key bytes")
    if value["eval_mult_key_generated"] is not True:
        raise Day2CalibrationAuthorityError("the evaluation multiplication key must be generated")
    _require_lower_sha256(
        value["serialized_eval_mult_key_sha256"], "serialized evaluation multiplication key"
    )
    _require_positive_int(
        value["serialized_eval_mult_key_bytes"],
        "serialized evaluation multiplication key bytes",
    )


def _validate_runtime_isolation_receipt(
    value: dict[str, object],
    source: dict[str, object],
) -> None:
    _require_exact_keys(value, _RUNTIME_ISOLATION_RECEIPT_KEYS, "runtime isolation receipt")
    if value["schema_version"] != "dynamic-cssc-publication-day2-runtime-isolation-receipt-v1":
        raise Day2CalibrationAuthorityError("runtime isolation receipt schema is not frozen")
    if value["authority_state"] != "descriptive-live-capability-consumed-v1":
        raise Day2CalibrationAuthorityError("runtime isolation authority state is not frozen")
    if value["formal_authority_granted"] is not False:
        raise Day2CalibrationAuthorityError("runtime isolation receipt cannot grant authority")
    if value["source_git_sha"] != source["git_sha"]:
        raise Day2CalibrationAuthorityError("runtime isolation source does not match provenance")
    for field in (
        "fresh_detached_checkout",
        "clean_environment",
        "isolated_build_root",
        "caller_python_and_git_environment_removed",
        "profile_authority_consumed_once",
    ):
        if value[field] is not True:
            raise Day2CalibrationAuthorityError(
                f"runtime isolation receipt {field} is not verified"
            )
    for field in ("launcher_source_sha256", "producer_source_sha256"):
        _require_lower_sha256(value[field], f"runtime isolation receipt {field}")
    if value["isolation_checks"] != list(DAY2_RUNTIME_ISOLATION_CHECKS):
        raise Day2CalibrationAuthorityError("runtime isolation checks are not frozen")


def _validate_operation_profiles(
    value: dict[str, object],
    rotation_case_ids: tuple[str, ...],
) -> tuple[int, int, dict[str, tuple[tuple[str, int], ...]]]:
    _require_exact_keys(value, _PROFILE_SET_KEYS, "operation profile set")
    if value["schema_version"] != "dynamic-cssc-publication-operation-profile-set-v2":
        raise Day2CalibrationAuthorityError("operation profile schema is not frozen")
    if value["primitive_names"] != list(PRIMITIVE_NAMES):
        raise Day2CalibrationAuthorityError(
            "primitive_names must equal the frozen 14-item vocabulary"
        )
    warmups = _require_positive_int(value["warmup_block_count"], "warmup block count")
    if warmups != CALIBRATION_WARMUP_BLOCK_COUNT:
        raise Day2CalibrationAuthorityError("calibration requires exactly 3 complete warmup blocks")
    measurement_count = _require_positive_int(
        value["measurement_block_count"], "measurement block count"
    )
    if measurement_count != CALIBRATION_MEASUREMENT_BLOCK_COUNT:
        raise Day2CalibrationAuthorityError(
            "calibration requires exactly 14 complete measurement blocks"
        )
    if value["measurement_stop_rule"] != CALIBRATION_MEASUREMENT_STOP_RULE:
        raise Day2CalibrationAuthorityError("measurement stop rule is not frozen")
    if value["operation_order_seed"] != CALIBRATION_OPERATION_ORDER_SEED:
        raise Day2CalibrationAuthorityError("operation-order seed is not frozen")
    if value["operation_order_method"] != CALIBRATION_OPERATION_ORDER_METHOD:
        raise Day2CalibrationAuthorityError("operation-order method is not frozen")
    profiles = value["profiles"]
    if type(profiles) is not list or len(profiles) != len(PRIMITIVE_NAMES):
        raise Day2CalibrationAuthorityError("operation profiles must cover all 14 primitives")
    cases_by_primitive: dict[str, tuple[tuple[str, int], ...]] = {}
    for index, (profile, primitive_name) in enumerate(zip(profiles, PRIMITIVE_NAMES, strict=True)):
        if type(profile) is not dict:
            raise Day2CalibrationAuthorityError(f"operation profile {index} must be an object")
        _require_exact_keys(profile, _PROFILE_KEYS, f"operation profile {index}")
        if profile["primitive_name"] != primitive_name:
            raise Day2CalibrationAuthorityError("operation profiles are not in canonical order")
        _require_nonempty_str(profile["profile_id"], f"{primitive_name} profile_id")
        if profile["setup_scope"] != "outside-timed-region":
            raise Day2CalibrationAuthorityError(f"{primitive_name} setup scope is not frozen")
        _require_nonempty_str(profile["timed_operation"], f"{primitive_name} timed operation")
        expected_aggregation = (
            "per-block-max-over-all-exact-indices"
            if primitive_name == "eval_rotate"
            else "per-block-max-over-all-admitted-cases"
        )
        if profile["case_aggregation_rule"] != expected_aggregation:
            raise Day2CalibrationAuthorityError(
                f"{primitive_name} case aggregation rule is not frozen"
            )
        if (
            profile["warmup_policy"] != "complete-profile-blocks-before-measurement"
            or profile["measurement_policy"] != "elapsed-ns-divided-by-operation-count"
        ):
            raise Day2CalibrationAuthorityError(
                f"{primitive_name} measurement policy is not frozen"
            )
        if profile["includes_relinearization"] is not (
            primitive_name == "eval_mult_with_relinearization"
        ):
            raise Day2CalibrationAuthorityError(
                "eval_mult_with_relinearization violates the relinearization pricing contract"
            )
        expected_randomness = (
            "operating-system-csprng-unbiased-rejection-sampling"
            if primitive_name == "mask_random_element"
            else "not-applicable"
        )
        if profile["randomness_policy"] != expected_randomness:
            raise Day2CalibrationAuthorityError(f"{primitive_name} randomness policy is not frozen")
        _require_lower_sha256(
            profile["correctness_check_sha256"], f"{primitive_name} correctness check"
        )
        raw_cases = profile["cases"]
        if type(raw_cases) is not list or not raw_cases:
            raise Day2CalibrationAuthorityError(f"{primitive_name} cases must be nonempty")
        cases: list[tuple[str, int]] = []
        for case_index, case in enumerate(raw_cases):
            if type(case) is not dict:
                raise Day2CalibrationAuthorityError(
                    f"{primitive_name} case {case_index} must be an object"
                )
            _require_exact_keys(
                case,
                _PROFILE_CASE_KEYS,
                f"{primitive_name} profile case {case_index}",
            )
            case_id = _require_nonempty_str(case["case_id"], f"{primitive_name} case_id")
            _require_nonempty_str(case["unit_definition"], f"{primitive_name} unit definition")
            _require_lower_sha256(
                case["input_fixture_contract_sha256"],
                f"{primitive_name} input fixture contract",
            )
            operation_count = _require_positive_int(
                case["operation_count"], f"{primitive_name} operation_count"
            )
            cases.append((case_id, operation_count))
        if len({case_id for case_id, _ in cases}) != len(cases):
            raise Day2CalibrationAuthorityError(f"{primitive_name} case IDs must be unique")
        if (
            primitive_name == "eval_rotate"
            and tuple(case_id for case_id, _ in cases) != rotation_case_ids
        ):
            raise Day2CalibrationAuthorityError(
                "eval_rotate profiles must cover every exact rotation index"
            )
        cases_by_primitive[primitive_name] = tuple(cases)
    return warmups, measurement_count, cases_by_primitive


def _validate_raw_block_sequence(
    blocks: object,
    *,
    expected_count: int,
    phase: str,
    cases_by_primitive: dict[str, tuple[tuple[str, int], ...]],
) -> None:
    if type(blocks) is not list or len(blocks) != expected_count:
        raise Day2CalibrationAuthorityError(
            f"raw evidence must contain every complete {phase} block"
        )
    for block_index, block in enumerate(blocks):
        if type(block) is not dict:
            raise Day2CalibrationAuthorityError(
                f"raw {phase} block {block_index} must be an object"
            )
        _require_exact_keys(block, _RAW_BLOCK_KEYS, f"raw {phase} block {block_index}")
        if type(block["ordinal"]) is not int or block["ordinal"] != block_index:
            raise Day2CalibrationAuthorityError(
                f"raw {phase} block ordinals must be exact and contiguous"
            )
        expected_order = _calibration_operation_order(block_index)
        operation_order = block["operation_order"]
        if type(operation_order) is not list or tuple(operation_order) != expected_order:
            raise Day2CalibrationAuthorityError(
                "raw block operation_order is not the frozen permutation"
            )
        samples = block["samples"]
        if type(samples) is not list or len(samples) != len(PRIMITIVE_NAMES):
            raise Day2CalibrationAuthorityError("each raw block must cover all 14 primitives")
        for sample_index, (sample, primitive_name) in enumerate(
            zip(samples, expected_order, strict=True)
        ):
            if type(sample) is not dict:
                raise Day2CalibrationAuthorityError(
                    f"raw {phase} block {block_index} sample {sample_index} must be an object"
                )
            _require_exact_keys(
                sample,
                _RAW_SAMPLE_KEYS,
                f"raw {phase} block {block_index} sample {sample_index}",
            )
            if sample["primitive_name"] != primitive_name:
                raise Day2CalibrationAuthorityError(
                    "raw primitive samples are not in canonical order"
                )
            raw_cases = sample["cases"]
            expected_cases = cases_by_primitive[primitive_name]
            if type(raw_cases) is not list or len(raw_cases) != len(expected_cases):
                raise Day2CalibrationAuthorityError("raw cases do not match their profile")
            for raw_case, (expected_case_id, expected_operation_count) in zip(
                raw_cases, expected_cases, strict=True
            ):
                if type(raw_case) is not dict or set(raw_case) != _RAW_CASE_KEYS:
                    raise Day2CalibrationAuthorityError("raw case keys must be exact")
                if raw_case["case_id"] != expected_case_id:
                    raise Day2CalibrationAuthorityError("raw cases do not match their profile")
                if type(raw_case["elapsed_ns"]) is not int or raw_case["elapsed_ns"] <= 0:
                    raise Day2CalibrationAuthorityError(
                        "elapsed_ns must be a positive strict integer"
                    )
                if (
                    type(raw_case["operation_count"]) is not int
                    or raw_case["operation_count"] != expected_operation_count
                ):
                    raise Day2CalibrationAuthorityError(
                        "raw operation_count does not match its profile"
                    )


def _validate_raw_blocks(
    value: dict[str, object],
    *,
    warmup_count: int,
    measurement_count: int,
    cases_by_primitive: dict[str, tuple[tuple[str, int], ...]],
) -> None:
    _require_exact_keys(value, _RAW_BLOCK_SET_KEYS, "raw measurement blocks")
    if value["schema_version"] != "dynamic-cssc-publication-raw-measurement-blocks-v1":
        raise Day2CalibrationAuthorityError("raw measurement block schema is not frozen")
    if value["clock"] != "std::chrono::steady_clock" or value["clock_unit"] != "nanosecond":
        raise Day2CalibrationAuthorityError("raw measurement clock is not frozen")
    if value["primitive_names"] != list(PRIMITIVE_NAMES):
        raise Day2CalibrationAuthorityError(
            "primitive_names must equal the frozen 14-item vocabulary"
        )
    if (
        type(value["warmup_block_count"]) is not int
        or value["warmup_block_count"] != warmup_count
        or type(value["measurement_block_count"]) is not int
        or value["measurement_block_count"] != measurement_count
        or value["measurement_stop_rule"] != CALIBRATION_MEASUREMENT_STOP_RULE
        or value["operation_order_seed"] != CALIBRATION_OPERATION_ORDER_SEED
        or value["operation_order_method"] != CALIBRATION_OPERATION_ORDER_METHOD
    ):
        raise Day2CalibrationAuthorityError(
            "raw measurement block contract does not match the operation profiles"
        )
    _validate_raw_block_sequence(
        value["warmup_blocks"],
        expected_count=warmup_count,
        phase="warmup",
        cases_by_primitive=cases_by_primitive,
    )
    _validate_raw_block_sequence(
        value["blocks"],
        expected_count=measurement_count,
        phase="measurement",
        cases_by_primitive=cases_by_primitive,
    )


def _validate_manifest(members: dict[str, bytes]) -> dict[str, object]:
    manifest = _decode_json(members["CALIBRATION-MANIFEST.json"], "CALIBRATION-MANIFEST.json")
    if set(manifest) != {"schema_version", "evidence_scope", "files"}:
        raise Day2CalibrationAuthorityError("calibration manifest keys must be exact")
    if manifest["schema_version"] != "dynamic-cssc-publication-day2-calibration-evidence-v1":
        raise Day2CalibrationAuthorityError("calibration manifest schema is not frozen")
    if manifest["evidence_scope"] != EVIDENCE_SCOPE:
        raise Day2CalibrationAuthorityError("calibration evidence scope is not frozen")
    files = manifest["files"]
    if type(files) is not list or len(files) != len(_PAYLOAD_FILENAMES):
        raise Day2CalibrationAuthorityError("calibration manifest file list is not complete")
    for index, (entry, expected_name) in enumerate(zip(files, _PAYLOAD_FILENAMES, strict=True)):
        if type(entry) is not dict or set(entry) != {"path", "sha256", "bytes"}:
            raise Day2CalibrationAuthorityError(f"manifest.files[{index}] keys must be exact")
        if entry["path"] != expected_name:
            raise Day2CalibrationAuthorityError("calibration manifest paths are not canonical")
        expected_sha256 = _require_lower_sha256(entry["sha256"], f"manifest.files[{index}].sha256")
        if type(entry["bytes"]) is not int or entry["bytes"] < 0:
            raise Day2CalibrationAuthorityError("calibration manifest byte lengths are invalid")
        if len(members[expected_name]) != entry["bytes"]:
            raise Day2CalibrationAuthorityError("calibration manifest byte length mismatch")
        if _sha256(members[expected_name]) != expected_sha256:
            raise Day2CalibrationAuthorityError("calibration manifest SHA-256 mismatch")
    return manifest


def _validate_checksums(members: dict[str, bytes]) -> None:
    expected_names = sorted((*_PAYLOAD_FILENAMES, "CALIBRATION-MANIFEST.json"))
    expected = "".join(f"{_sha256(members[name])}  {name}\n" for name in expected_names).encode(
        "ascii"
    )
    if members["SHA256SUMS"] != expected:
        raise Day2CalibrationAuthorityError("SHA256SUMS is not the exact canonical checksum set")


def inspect_day2_calibration_archive(
    archive_path: Path,
    *,
    expected_outer_sha256: str,
    github_metadata: object,
) -> Day2CalibrationInspection:
    """Inspect one archive without granting authority to it or its caller."""

    expected_outer_sha256 = _require_lower_sha256(expected_outer_sha256, "expected_outer_sha256")
    archive_bytes, members = _read_archive(archive_path)
    outer_sha256 = _sha256(archive_bytes)
    if outer_sha256 != expected_outer_sha256:
        raise Day2CalibrationAuthorityError("outer archive SHA-256 mismatch")
    github = _validate_github_metadata(github_metadata, outer_sha256)
    _validate_manifest(members)
    _validate_checksums(members)
    payloads = {
        name: _decode_json(members[name], name)
        for name in _PAYLOAD_FILENAMES
        if name.endswith(".json")
    }
    source = payloads["source-provenance.json"]
    workflow = payloads["workflow-provenance.json"]
    host = payloads["host-profile.json"]
    openfhe = payloads["openfhe-build.json"]
    contract = payloads["contract-bindings.json"]
    rotation_plan = payloads["rotation-key-plan.json"]
    generated_keys = payloads["generated-key-inventory.json"]
    profiles = payloads["operation-profile-set.json"]
    raw = payloads["raw-measurement-blocks.json"]
    _validate_run_status(payloads["RUN_STATUS.json"])
    artifact_behavior_inventory = _validate_source_provenance(source)
    _validate_workflow_provenance(workflow, source, github)
    _validate_openfhe_build(openfhe)
    rotation_case_ids = _validate_rotation_key_plan(rotation_plan)
    _validate_generated_key_inventory(generated_keys, rotation_plan)
    _validate_contract_bindings(contract, members)
    warmup_count, measurement_count, cases_by_primitive = _validate_operation_profiles(
        profiles,
        rotation_case_ids,
    )
    _validate_raw_blocks(
        raw,
        warmup_count=warmup_count,
        measurement_count=measurement_count,
        cases_by_primitive=cases_by_primitive,
    )
    _validate_runtime_isolation_receipt(
        payloads["runtime-isolation-receipt.json"],
        source,
    )
    _validate_host_profile(host, openfhe)
    projection_sha256 = _sha256(_canonical_json_bytes(_calibration_projection(raw)))
    _validate_producer_validation(
        payloads["producer-validation.json"],
        openfhe=openfhe,
        contract=contract,
        members=members,
        calibration_projection_sha256=projection_sha256,
    )
    return Day2CalibrationInspection(
        evidence_scope=EVIDENCE_SCOPE,
        source_git_sha=str(source["git_sha"]),
        workflow_run_id=int(workflow["run_id"]),
        workflow_run_attempt=int(workflow["run_attempt"]),
        primitive_names=tuple(str(value) for value in profiles["primitive_names"]),
        measurement_block_count=int(raw["measurement_block_count"]),
        outer_archive_sha256=outer_sha256,
        manifest_sha256=_sha256(members["CALIBRATION-MANIFEST.json"]),
        checksums_sha256=_sha256(members["SHA256SUMS"]),
        raw_measurement_blocks_sha256=_sha256(members["raw-measurement-blocks.json"]),
        operation_profile_set_sha256=_sha256(members["operation-profile-set.json"]),
        rotation_key_plan_sha256=_sha256(members["rotation-key-plan.json"]),
        generated_key_inventory_sha256=_sha256(members["generated-key-inventory.json"]),
        runtime_isolation_receipt_sha256=_sha256(members["runtime-isolation-receipt.json"]),
        contract_bindings_sha256=_sha256(members["contract-bindings.json"]),
        calibration_projection_sha256=projection_sha256,
        artifact_behavior_inventory_sha256=_sha256(
            _canonical_json_bytes(artifact_behavior_inventory)
        ),
        behavior_set_schema_version=str(artifact_behavior_inventory["behavior_set_schema_version"]),
        behavior_set_sha256=str(artifact_behavior_inventory["behavior_set_sha256"]),
    )


def repository_day2_calibration_profile_authority() -> Day2CalibrationProfileAuthority:
    """Bind the closed pre-dispatch anchor to the actual clean Day 2 source."""

    anchor_document = _read_repository_anchor_set(_PROFILE_ANCHOR_PATH)
    anchors = _decode_profile_anchor_set(anchor_document)
    if not anchors:
        raise Day2CalibrationAuthorityError(
            "no repository-approved pre-dispatch calibration profile anchor is installed"
        )
    binding = anchors[0]
    post_anchor_document = _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH)
    if _decode_post_run_anchor_set(post_anchor_document):
        raise Day2CalibrationAuthorityError(
            "Day 2 pre-dispatch authority requires the post-run anchor set to remain empty"
        )
    from dynamic_cssc.evidence_compatibility import (
        EvidenceCompatibilityError,
        EvidenceRole,
        verify_current_role_source,
        verify_repository_anchor_history,
    )

    repository_root = Path(__file__).resolve().parents[2]
    try:
        registration_history = verify_repository_anchor_history(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
        attestation = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            f"current Day 2 source attestation failed: {error}"
        ) from error
    if registration_history.analysis_source_git_sha != attestation.git_sha:
        raise Day2CalibrationAuthorityError(
            "Day 2 source does not equal the history-verified registration/profile source"
        )
    if (
        registration_history.day1a_authority_receipt_sha256
        != binding.day1a_authority_receipt_sha256
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 profile does not match the history-anchored Day1A authority receipt"
        )
    if (
        _read_repository_anchor_set(_PROFILE_ANCHOR_PATH) != anchor_document
        or _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH) != post_anchor_document
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 pre-dispatch repository anchor changed during source attestation"
        )
    # This capability binds immutable source/profile identities only.  Runtime
    # isolation is necessarily established later, by the one-use launcher in
    # the live worker process; requiring it on a static source attestation made
    # this seam temporally impossible to satisfy.
    authority = _mint_repository_calibration_profile_authority(
        anchor=binding,
        experiment_source_git_sha=attestation.git_sha,
        experiment_behavior_set_schema_version=(attestation.behavior_set_schema_version),
        experiment_behavior_set_sha256=attestation.behavior_set_sha256,
    )
    try:
        after = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            f"final Day 2 source attestation failed: {error}"
        ) from error
    if after != attestation:
        raise Day2CalibrationAuthorityError(
            "Day 2 source changed while binding pre-dispatch authority"
        )
    if (
        _read_repository_anchor_set(_PROFILE_ANCHOR_PATH) != anchor_document
        or _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH) != post_anchor_document
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 pre-dispatch repository anchor changed while binding authority"
        )
    return authority


def repository_day2_calibration_authority() -> Day2CalibrationAuthority:
    """Verify the S1/S2/S3 evidence chain before minting the final capability."""

    post_anchor_document = _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH)
    anchors = _decode_post_run_anchor_set(post_anchor_document)
    if not anchors:
        raise Day2CalibrationAuthorityError(
            "no repository-approved Day 2 calibration anchor is installed"
        )
    binding = anchors[0]
    profile_anchor_document = _read_repository_anchor_set(_PROFILE_ANCHOR_PATH)
    profile_anchors = _decode_profile_anchor_set(profile_anchor_document)
    if not profile_anchors:
        raise Day2CalibrationAuthorityError(
            "no repository-approved pre-dispatch calibration profile anchor is installed"
        )
    profile_binding = profile_anchors[0]
    if (
        binding.operation_profile_set_sha256 != profile_binding.operation_profile_set_sha256
        or binding.rotation_key_plan_sha256 != profile_binding.rotation_key_plan_sha256
        or binding.contract_bindings_sha256 != profile_binding.contract_bindings_sha256
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 calibration anchor does not match pre-dispatch profile authority"
        )
    from dynamic_cssc.evidence_compatibility import (
        EvidenceCompatibilityError,
        EvidenceRole,
        verify_current_role_source,
        verify_evidence_compatibility,
        verify_repository_anchor_history,
    )

    repository_root = Path(__file__).resolve().parents[2]
    try:
        registration_history = verify_repository_anchor_history(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
        attestation = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            f"current Day 2 source attestation failed: {error}"
        ) from error
    if registration_history.analysis_source_git_sha != attestation.git_sha:
        raise Day2CalibrationAuthorityError(
            "Day 2 post-run source does not equal the history-verified profile source"
        )
    if (
        registration_history.day1a_authority_receipt_sha256
        != profile_binding.day1a_authority_receipt_sha256
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 post-run profile does not match the history-anchored Day1A receipt"
        )
    if (
        _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH) != post_anchor_document
        or _read_repository_anchor_set(_PROFILE_ANCHOR_PATH) != profile_anchor_document
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 repository anchor changed during source attestation"
        )
    if (
        attestation.behavior_set_schema_version != binding.experiment_behavior_set_schema_version
        or attestation.behavior_set_sha256 != binding.experiment_behavior_set_sha256
    ):
        raise Day2CalibrationAuthorityError(
            "current Day 2 Behavior Set does not match the experiment source anchor"
        )
    # Runtime isolation is reviewed through the archive-bound receipt whose
    # digest is part of the post-run anchor.  The generic compatibility receipt
    # intentionally remains runtime-authority-false and must not be treated as
    # a second, impossible live launcher capability after the run.
    artifact_behavior_inventory = _decode_json(
        binding.artifact_behavior_inventory_document,
        "Day 2 post-run artifact Behavior inventory binding",
    )
    try:
        compatibility = verify_evidence_compatibility(
            role=EvidenceRole.DAY2,
            experiment_source_git_sha=binding.source_git_sha,
            evidence_freeze_git_sha=attestation.git_sha,
            analysis_source_git_sha=attestation.git_sha,
            artifact_sha256=binding.outer_archive_sha256,
            artifact_behavior_inventory=artifact_behavior_inventory,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            f"Day 2 evidence compatibility verification failed: {error}"
        ) from error
    document = compatibility.to_document()
    required_receipt_state = (
        "compatibility_verified",
        "post_run_anchor_verified",
        "snapshot_compatibility_verified",
    )
    if type(document) is not dict or any(
        document.get(field) is not True for field in required_receipt_state
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 evidence compatibility receipt cannot grant calibration authority"
        )
    try:
        after = verify_current_role_source(EvidenceRole.DAY2, repository_root)
    except EvidenceCompatibilityError as error:
        raise Day2CalibrationAuthorityError(
            f"final Day 2 source attestation failed: {error}"
        ) from error
    if after != attestation:
        raise Day2CalibrationAuthorityError(
            "Day 2 source changed while binding calibration authority"
        )
    if (
        _read_repository_anchor_set(_POST_RUN_ANCHOR_PATH) != post_anchor_document
        or _read_repository_anchor_set(_PROFILE_ANCHOR_PATH) != profile_anchor_document
    ):
        raise Day2CalibrationAuthorityError(
            "Day 2 repository anchor changed while binding calibration authority"
        )
    return _mint_repository_calibration_authority(
        source_git_sha=binding.source_git_sha,
        outer_archive_sha256=binding.outer_archive_sha256,
        raw_measurement_blocks_sha256=binding.raw_measurement_blocks_sha256,
        calibration_projection_sha256=binding.calibration_projection_sha256,
    )
