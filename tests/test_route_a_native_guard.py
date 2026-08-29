from __future__ import annotations

import hashlib
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.openfhe_query_runner import (
    OpenFHEKeyMaterialReceipt,
    VerifiedRouteAOpenFHEProducerResult,
    VerifiedRouteAOpenFHEReplayResult,
)
from dynamic_cssc.openfhe_query_runtime import (
    OpenFHEProcessObservation,
    OpenFHERunnerBuildIdentity,
)
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_native_case import (
    RouteANativeCasePlan,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_native_guard import (
    RouteANativeGuardError,
    guard_route_a_native_replays,
)
from dynamic_cssc.route_a_native_invocation import RouteANativeReplayInspection
from dynamic_cssc.route_a_native_runtime import RouteANativeReplayExecution
from dynamic_cssc.route_a_openfhe_package import (
    RouteAOpenFHEPackageInspection,
    RouteAOpenFHEPackageMember,
)
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

ROOT = Path(__file__).resolve().parents[1]
PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
SHARD = "1" * 64
BUILD = "2" * 64
TYPED_ORACLE = "4" * 64
CONTEXT = "5" * 64


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


@pytest.fixture(scope="module")
def case() -> RouteANativeCasePlan:
    return compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id="periodic-repack/windows=1",
        shard_identity_sha256=SHARD,
        unit_attempt_ordinal=0,
        machine_plan_bytes=PLAN_BYTES,
    )


def _member(role: str, digest: str, *, subject: str | None = None) -> RouteAOpenFHEPackageMember:
    return RouteAOpenFHEPackageMember(
        byte_count=1,
        relative_path=f"{role}-{subject or role}.bin",
        role=role,
        sha256=digest,
        subject_id=subject or role,
    )


def _runner() -> OpenFHERunnerBuildIdentity:
    value = object.__new__(OpenFHERunnerBuildIdentity)
    object.__setattr__(value, "build_identity_sha256", "6" * 64)
    return value


def _key_receipt(ordinal: int) -> OpenFHEKeyMaterialReceipt:
    request_sha256 = _sha(f"request-{ordinal}")
    return OpenFHEKeyMaterialReceipt(
        combined_frame_byte_count=1,
        combined_frame_sha256=_sha(f"evaluation-key-frame-{ordinal}"),
        crypto_context_parameter_sha256="7" * 64,
        crypto_context_serialization_sha256=CONTEXT,
        eval_mult_segment_byte_count=1,
        eval_mult_segment_sha256=_sha(f"eval-mult-{ordinal}"),
        generated_exact_indices=(),
        input_binding_sha256="8" * 64,
        key_generation_plan_sha256="9" * 64,
        key_generation_session_sha256=_sha(f"session-{ordinal}"),
        public_key_sha256=_sha(f"public-key-{ordinal}"),
        request_sha256=request_sha256,
        required_exact_indices=(),
        rotation_key_plan_sha256="a" * 64,
        rotation_segment_byte_count=1,
        rotation_segment_sha256=_sha(f"rotation-{ordinal}"),
    )


def _execution(
    case: RouteANativeCasePlan,
    tmp_path: Path,
    ordinal: int,
) -> RouteANativeReplayExecution:
    request_sha256 = _sha(f"request-{ordinal}")
    members = (
        _member("canonical-request", request_sha256),
        _member("case-binding", case.case_binding_sha256),
        _member("direct-oracle", case.direct_oracle_sha256),
        _member("structural-vector", case.structural_vector_sha256),
        _member("typed-oracle", TYPED_ORACLE),
        _member("preparation", _sha(f"preparation-{ordinal}")),
        _member("authorization-receipt", _sha(f"authorization-{ordinal}")),
        _member("consumed-ledger", _sha(f"ledger-{ordinal}")),
        _member("crypto-context", CONTEXT),
        _member("secret-key", _sha(f"secret-key-{ordinal}")),
        _member("public-key", _sha(f"public-key-{ordinal}")),
        _member("evaluation-key-frame", _sha(f"evaluation-key-frame-{ordinal}")),
        _member("input-ciphertext", _sha(f"input-{ordinal}"), subject="input-0"),
        _member(
            "producer-result-ciphertext",
            _sha(f"result-{ordinal}"),
            subject="result-0",
        ),
    )
    package = RouteAOpenFHEPackageInspection(
        package_root=tmp_path / f"package-{ordinal}",
        manifest_bytes=f"manifest-{ordinal}".encode(),
        manifest_sha256=_sha(f"manifest-{ordinal}"),
        build_manifest_sha256=BUILD,
        case_binding_sha256=case.case_binding_sha256,
        lane_binding_sha256=_sha(f"lane-{ordinal}"),
        members=members,
    )
    producer = VerifiedRouteAOpenFHEProducerResult(
        request_sha256=request_sha256,
        cloud_program_operation_inventory=(("EvalAdd", 1),),
        lifecycle_operation_inventory=(("key_generation_count", 1),),
        decrypted_results=(),
        reconstructed_output=case.direct_oracle_output,
        key_material_receipt=_key_receipt(ordinal),
        serialized_objects=(),
        second_batch_row_zero=True,
        publication_authority=False,
    )
    replay = VerifiedRouteAOpenFHEReplayResult(
        request_sha256=request_sha256,
        package_manifest_sha256=package.manifest_sha256,
        cloud_program_operation_inventory=producer.cloud_program_operation_inventory,
        lifecycle_operation_inventory=(
            ("automorphism_key_generation_count", 0),
            ("context_generation_count", 0),
            ("encrypt_count", 0),
            ("eval_mult_key_generation_count", 0),
            ("key_generation_count", 0),
        ),
        decrypted_results=(),
        reconstructed_output=case.direct_oracle_output,
        serialized_objects=(),
        second_batch_row_zero=True,
        publication_authority=False,
    )
    lane = RouteAEvaluationLane.openfhe_recorded(
        shard_identity_sha256=SHARD,
        strategy_candidate_id=case.strategy_candidate_id,
        rho=Fraction(1),
        unit_attempt_ordinal=0,
        process_ordinal=ordinal,
    )
    observation = OpenFHEProcessObservation(
        elapsed_ns=ordinal + 1,
        peak_resident_memory_bytes=100 + ordinal,
        peak_scratch_bytes=200 + ordinal,
        stdout=b"",
        stderr=b"",
        runtime_mapping_admission=object(),  # type: ignore[arg-type]
    )
    lifecycle = RouteANativeReplayInspection(
        prepared_query=object(),  # type: ignore[arg-type]
        preparation_sha256=_sha(f"preparation-{ordinal}"),
        authorization_receipt_sha256=_sha(f"authorization-{ordinal}"),
        ledger_snapshot_sha256=_sha(f"ledger-{ordinal}"),
        typed_oracle_sha256=TYPED_ORACLE,
    )
    return RouteANativeReplayExecution(
        lane=lane,
        runner_identity=_runner(),
        process_observation=observation,
        lifecycle_inspection=lifecycle,
        producer_result=producer,
        replay_result=replay,
        package_before=package,
        package_after=package,
    )


def test_guard_accepts_exact_three_fresh_recorded_replays(
    case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    executions = tuple(_execution(case, tmp_path, ordinal) for ordinal in range(3))

    receipt = guard_route_a_native_replays(case, executions)  # type: ignore[arg-type]

    assert receipt.package_manifest_sha256s == tuple(
        execution.package_before.manifest_sha256 for execution in executions
    )
    assert receipt.case_binding_sha256 == case.case_binding_sha256
    assert b'"accepted":true' in receipt.receipt_bytes
    assert b'"publication_evidence":false' in receipt.receipt_bytes
    assert b"secret-key-" not in receipt.receipt_bytes


def test_guard_rejects_a_reused_lane_request_even_when_each_package_is_consistent(
    case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    executions = [_execution(case, tmp_path, ordinal) for ordinal in range(3)]
    first_request = executions[0].producer_result.request_sha256
    second = executions[1]
    changed_members = tuple(
        replace(member, sha256=first_request)
        if member.role == "canonical-request"
        else member
        for member in second.package_before.members
    )
    changed_package = replace(second.package_before, members=changed_members)
    changed_producer = replace(
        second.producer_result,
        request_sha256=first_request,
        key_material_receipt=replace(
            second.producer_result.key_material_receipt,
            request_sha256=first_request,
        ),
    )
    executions[1] = replace(
        second,
        package_before=changed_package,
        package_after=changed_package,
        producer_result=changed_producer,
        replay_result=replace(second.replay_result, request_sha256=first_request),
    )

    with pytest.raises(RouteANativeGuardError, match="request identity was reused"):
        guard_route_a_native_replays(case, tuple(executions))  # type: ignore[arg-type]


def test_guard_rejects_reused_secret_key_material(
    case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    executions = [_execution(case, tmp_path, ordinal) for ordinal in range(3)]
    first_secret = next(
        member.sha256
        for member in executions[0].package_before.members
        if member.role == "secret-key"
    )
    second = executions[1].package_before
    changed_members = tuple(
        replace(member, sha256=first_secret) if member.role == "secret-key" else member
        for member in second.members
    )
    changed_package = replace(second, members=changed_members)
    executions[1] = replace(
        executions[1],
        package_before=changed_package,
        package_after=changed_package,
    )

    with pytest.raises(RouteANativeGuardError, match="reused"):
        guard_route_a_native_replays(case, tuple(executions))  # type: ignore[arg-type]


def test_guard_rejects_package_mutation_and_missing_mapping_admission(
    case: RouteANativeCasePlan,
    tmp_path: Path,
) -> None:
    executions = [_execution(case, tmp_path, ordinal) for ordinal in range(3)]
    executions[1] = replace(
        executions[1],
        package_after=replace(executions[1].package_after, manifest_sha256="b" * 64),
    )
    with pytest.raises(RouteANativeGuardError, match="changed"):
        guard_route_a_native_replays(case, tuple(executions))  # type: ignore[arg-type]

    executions = [_execution(case, tmp_path, ordinal) for ordinal in range(3)]
    executions[2] = replace(
        executions[2],
        process_observation=replace(
            executions[2].process_observation,
            runtime_mapping_admission=None,
        ),
    )
    with pytest.raises(RouteANativeGuardError, match="changed"):
        guard_route_a_native_replays(case, tuple(executions))  # type: ignore[arg-type]
