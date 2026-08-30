"""Cross-package guard for one Route A native case.

The native runtime verifies each recorded producer package and its independent
loaded-object replay in isolation.  This module owns the remaining case-level
boundary: exactly three recorded lanes, common deterministic inputs and Cloud
program, fresh disposable cryptographic material, unchanged package bytes, and
the qualification-only mechanism coverage obligations.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from fractions import Fraction

from dynamic_cssc.openfhe_query_runner import (
    VerifiedRouteAOpenFHEProducerResult,
    VerifiedRouteAOpenFHEReplayResult,
)
from dynamic_cssc.openfhe_query_runtime import (
    OpenFHEProcessObservation,
    OpenFHERunnerBuildIdentity,
)
from dynamic_cssc.route_a_native_case import RouteANativeCasePlan
from dynamic_cssc.route_a_native_invocation import RouteANativeReplayInspection
from dynamic_cssc.route_a_native_runtime import RouteANativeReplayExecution
from dynamic_cssc.route_a_openfhe_package import (
    RouteAOpenFHEPackageInspection,
    RouteAOpenFHEPackageMember,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)

__all__ = (
    "RouteANativeGuardError",
    "RouteANativeGuardReceipt",
    "guard_route_a_native_replays",
)

_GUARD_SCHEMA = "dynamic-cssc-route-a-native-three-replay-guard-v1"
_QUALIFICATION_STRATEGY = "packed-coo-cloud-segmented-delta/segment-width=128"
_QUALIFICATION_COVERAGE = frozenset(
    {
        "actual_overlap_contributor_group",
        "f1m_random_mask_path",
        "nonempty_auxiliary_segment",
    }
)
_FRESH_ROLES = (
    "secret-key",
    "public-key",
    "evaluation-key-frame",
    "input-ciphertext",
    "producer-result-ciphertext",
)
_COMMON_ROLES = (
    "case-binding",
    "direct-oracle",
    "structural-vector",
    "typed-oracle",
)
_REPLAY_FORBIDDEN_LIFECYCLE_OPERATIONS = (
    "automorphism_key_generation_count",
    "context_generation_count",
    "encrypt_count",
    "eval_mult_key_generation_count",
    "key_generation_count",
)


class RouteANativeGuardError(RuntimeError):
    """Three native packages or replays do not form one accepted case."""


def _role_members(
    package: RouteAOpenFHEPackageInspection,
    role: str,
) -> tuple[RouteAOpenFHEPackageMember, ...]:
    values = tuple(member for member in package.members if member.role == role)
    if not values:
        raise RouteANativeGuardError(f"native package lacks {role}")
    return values


def _singleton_digest(package: RouteAOpenFHEPackageInspection, role: str) -> str:
    values = _role_members(package, role)
    if len(values) != 1:
        raise RouteANativeGuardError(f"native package repeats singleton {role}")
    return values[0].sha256


def _role_root(package: RouteAOpenFHEPackageInspection, role: str) -> str:
    values = _role_members(package, role)
    content = canonical_route_a_document(
        {
            "members": [
                {
                    "byte_count": member.byte_count,
                    "sha256": member.sha256,
                    "subject_id": member.subject_id,
                }
                for member in values
            ],
            "role": role,
            "schema_version": "dynamic-cssc-route-a-native-role-root-v1",
        }
    )
    return hashlib.sha256(content).hexdigest()


@dataclass(frozen=True, slots=True)
class RouteANativeGuardReceipt:
    """Redacted non-authorizing result of the exact three-replay guard."""

    receipt_bytes: bytes
    receipt_sha256: str
    case_binding_sha256: str
    build_manifest_sha256: str
    package_manifest_sha256s: tuple[str, str, str]

    def __post_init__(self) -> None:
        if (
            type(self.receipt_bytes) is not bytes
            or not self.receipt_bytes
            or hashlib.sha256(self.receipt_bytes).hexdigest() != self.receipt_sha256
            or len(self.package_manifest_sha256s) != 3
        ):
            raise RouteANativeGuardError("native guard receipt binding is invalid")


def guard_route_a_native_replays(
    case: RouteANativeCasePlan,
    executions: tuple[
        RouteANativeReplayExecution,
        RouteANativeReplayExecution,
        RouteANativeReplayExecution,
    ],
    *,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteANativeGuardReceipt:
    """Accept exactly three immutable, fresh-key, independently replayed packages."""

    if type(case) is not RouteANativeCasePlan:
        raise TypeError("case must be an exact RouteANativeCasePlan")
    if (
        type(executions) is not tuple
        or len(executions) != 3
        or any(type(execution) is not RouteANativeReplayExecution for execution in executions)
    ):
        raise RouteANativeGuardError("native guard requires exactly three replay executions")
    expected_ordinals = (0, 1, 2)
    first = executions[0]
    first_package = first.package_before
    first_producer = first.producer_result
    first_replay = first.replay_result
    first_runner = first.runner_identity
    if (
        type(first_package) is not RouteAOpenFHEPackageInspection
        or type(first_producer) is not VerifiedRouteAOpenFHEProducerResult
        or type(first_replay) is not VerifiedRouteAOpenFHEReplayResult
        or type(first_runner) is not OpenFHERunnerBuildIdentity
        or first_package.case_binding_sha256 != case.case_binding_sha256
        or _singleton_digest(first_package, "case-binding") != case.case_binding_sha256
        or _singleton_digest(first_package, "direct-oracle") != case.direct_oracle_sha256
        or _singleton_digest(first_package, "structural-vector")
        != case.structural_vector_sha256
    ):
        raise RouteANativeGuardError("native guard first package identity is invalid")

    common_role_digests = {
        role: _singleton_digest(first_package, role) for role in _COMMON_ROLES
    }
    context_parameter_sha256 = first_producer.key_material_receipt.crypto_context_parameter_sha256
    cloud_inventory = first_producer.cloud_program_operation_inventory
    producer_lifecycle = first_producer.lifecycle_operation_inventory
    replay_lifecycle = first_replay.lifecycle_operation_inventory
    fresh_roots: dict[str, list[str]] = {role: [] for role in _FRESH_ROLES}
    package_manifests: list[str] = []
    lane_bindings: list[str] = []
    request_sha256s: list[str] = []
    resource_rows: list[dict[str, int]] = []

    for process_ordinal, execution in zip(expected_ordinals, executions, strict=True):
        package = execution.package_before
        producer = execution.producer_result
        replay = execution.replay_result
        lifecycle = execution.lifecycle_inspection
        lane = execution.lane
        observation = execution.process_observation
        if (
            type(package) is not RouteAOpenFHEPackageInspection
            or type(execution.package_after) is not RouteAOpenFHEPackageInspection
            or type(producer) is not VerifiedRouteAOpenFHEProducerResult
            or type(replay) is not VerifiedRouteAOpenFHEReplayResult
            or type(lifecycle) is not RouteANativeReplayInspection
            or package != execution.package_after
            or type(execution.runner_identity) is not OpenFHERunnerBuildIdentity
            or execution.runner_identity.build_identity_sha256
            != first_runner.build_identity_sha256
            or type(observation) is not OpenFHEProcessObservation
            or observation.runtime_mapping_admission is None
            or lane.execution_process_role != "openfhe-recorded"
            or lane.process_ordinal_or_null != process_ordinal
            or lane.shard_identity_sha256 != case.shard_identity_sha256
            or lane.strategy_candidate_id != case.strategy_candidate_id
            or lane.rho != Fraction(1)
            or lane.unit_attempt_ordinal != case.unit_attempt_ordinal
            or package.case_binding_sha256 != case.case_binding_sha256
            or package.build_manifest_sha256 != first_package.build_manifest_sha256
            or replay.package_manifest_sha256 != package.manifest_sha256
            or _singleton_digest(package, "canonical-request") != producer.request_sha256
            or replay.request_sha256 != producer.request_sha256
            or producer.key_material_receipt.request_sha256 != producer.request_sha256
            or producer.cloud_program_operation_inventory != cloud_inventory
            or replay.cloud_program_operation_inventory != cloud_inventory
            or producer.lifecycle_operation_inventory != producer_lifecycle
            or replay.lifecycle_operation_inventory != replay_lifecycle
            or any(
                dict(replay.lifecycle_operation_inventory).get(operation) != 0
                for operation in _REPLAY_FORBIDDEN_LIFECYCLE_OPERATIONS
            )
            or producer.reconstructed_output != case.direct_oracle_output
            or replay.reconstructed_output != case.direct_oracle_output
            or producer.second_batch_row_zero is not True
            or replay.second_batch_row_zero is not True
            or producer.publication_authority is not False
            or replay.publication_authority is not False
            or producer.key_material_receipt.crypto_context_parameter_sha256
            != context_parameter_sha256
            or producer.key_material_receipt.crypto_context_serialization_sha256
            != _singleton_digest(package, "crypto-context")
            or producer.key_material_receipt.public_key_sha256
            != _singleton_digest(package, "public-key")
            or producer.key_material_receipt.combined_frame_sha256
            != _singleton_digest(package, "evaluation-key-frame")
            or lifecycle.preparation_sha256 != _singleton_digest(package, "preparation")
            or lifecycle.authorization_receipt_sha256
            != _singleton_digest(package, "authorization-receipt")
            or lifecycle.ledger_snapshot_sha256
            != _singleton_digest(package, "consumed-ledger")
            or lifecycle.typed_oracle_sha256 != _singleton_digest(package, "typed-oracle")
            or any(
                _singleton_digest(package, role) != digest
                for role, digest in common_role_digests.items()
            )
            or any(
                type(value) is not int or value < 0
                for value in (
                    observation.elapsed_ns,
                    observation.peak_resident_memory_bytes,
                    observation.peak_scratch_bytes,
                )
            )
        ):
            raise RouteANativeGuardError("native replay package or common binding changed")
        package_manifests.append(package.manifest_sha256)
        lane_bindings.append(package.lane_binding_sha256)
        request_sha256s.append(producer.request_sha256)
        for role in _FRESH_ROLES:
            fresh_roots[role].append(_role_root(package, role))
        resource_rows.append(
            {
                "elapsed_ns": observation.elapsed_ns,
                "peak_resident_memory_bytes": observation.peak_resident_memory_bytes,
                "peak_scratch_bytes": observation.peak_scratch_bytes,
                "process_ordinal": process_ordinal,
            }
        )

    if (
        len(set(package_manifests)) != 3
        or len(set(lane_bindings)) != 3
        or len(set(request_sha256s)) != 3
    ):
        raise RouteANativeGuardError("native recorded package/lane/request identity was reused")
    if any(len(set(values)) != 3 for values in fresh_roots.values()):
        raise RouteANativeGuardError("native disposable cryptographic material was reused")
    coverage = dict(case.mechanism_coverage)
    if case.trace.suite_role == "qualification" and (
        case.trace.scale != "M"
        or case.trace.formal_seed != scientific_profile.qualification_seed
        or case.strategy_candidate_id != _QUALIFICATION_STRATEGY
        or any(coverage.get(name) is not True for name in _QUALIFICATION_COVERAGE)
    ):
        raise RouteANativeGuardError("qualification native mechanism coverage is incomplete")

    receipt_bytes = canonical_route_a_document(
        {
            "accepted": True,
            "authority_granted": False,
            "build_manifest_sha256": first_package.build_manifest_sha256,
            "case_binding_sha256": case.case_binding_sha256,
            "cloud_program_operation_inventory": dict(cloud_inventory),
            "crypto_context_parameter_sha256": context_parameter_sha256,
            "freshness_checks": {
                f"{role.replace('-', '_')}_roots_pairwise_distinct": True
                for role in _FRESH_ROLES
            },
            "lane_binding_sha256s": lane_bindings,
            "mechanism_coverage": coverage,
            "native_resource_observations": resource_rows,
            "package_manifest_sha256s": package_manifests,
            "process_ordinals": list(expected_ordinals),
            "publication_evidence": False,
            "runner_build_identity_sha256": first_runner.build_identity_sha256,
            "schema_version": _GUARD_SCHEMA,
            "structural_vector_sha256": case.structural_vector_sha256,
        }
    )
    return RouteANativeGuardReceipt(
        receipt_bytes=receipt_bytes,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        case_binding_sha256=case.case_binding_sha256,
        build_manifest_sha256=first_package.build_manifest_sha256,
        package_manifest_sha256s=tuple(package_manifests),  # type: ignore[arg-type]
    )
