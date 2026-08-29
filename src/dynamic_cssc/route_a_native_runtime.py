"""Owned q3 producer and q4 loaded-object replay for one Route A process lane."""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from dynamic_cssc.openfhe_query_runner import (
    VerifiedRouteAOpenFHEProducerResult,
    VerifiedRouteAOpenFHEReplayResult,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
    verify_route_a_ordinary_openfhe_producer_result,
    verify_route_a_ordinary_openfhe_replay_result,
    verify_route_a_strong_openfhe_producer_result,
    verify_route_a_strong_openfhe_replay_result,
)
from dynamic_cssc.openfhe_query_runtime import (
    OpenFHEProcessObservation,
    OpenFHERunnerBuildIdentity,
    capture_openfhe_runner_build_identity,
    run_controlled_openfhe_process,
)
from dynamic_cssc.ordinary_query_lifecycle import OrdinaryExecutionBundle
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_native_case import RouteANativeCasePlan
from dynamic_cssc.route_a_native_invocation import (
    RouteANativeAuthorizedInvocation,
    RouteANativeProducerCapability,
    RouteANativeReplayInspection,
    claim_route_a_native_producer_capability,
    replay_route_a_native_invocation_read_only,
)
from dynamic_cssc.route_a_openfhe_package import (
    RouteAOpenFHEPackageInspection,
    build_route_a_openfhe_package,
    inspect_route_a_openfhe_package,
    read_route_a_openfhe_package_member,
)
from dynamic_cssc.strong_execution import StrongExecutionBundle

__all__ = (
    "RouteANativeProducerExecution",
    "RouteANativeReplayExecution",
    "RouteANativeRuntimeError",
    "execute_route_a_native_producer",
    "execute_route_a_native_replay",
)

_MAX_RESULT_BYTES = 128 * 1024 * 1024


class RouteANativeRuntimeError(RuntimeError):
    """The owned Route A native process or package changed or exceeded a limit."""


@dataclass(frozen=True, slots=True)
class RouteANativeProducerExecution:
    lane: RouteAEvaluationLane
    runner_identity: OpenFHERunnerBuildIdentity
    process_observation: OpenFHEProcessObservation
    verified_result: VerifiedRouteAOpenFHEProducerResult
    retained_package: RouteAOpenFHEPackageInspection | None


@dataclass(frozen=True, slots=True)
class RouteANativeReplayExecution:
    lane: RouteAEvaluationLane
    runner_identity: OpenFHERunnerBuildIdentity
    process_observation: OpenFHEProcessObservation
    lifecycle_inspection: RouteANativeReplayInspection
    producer_result: VerifiedRouteAOpenFHEProducerResult
    replay_result: VerifiedRouteAOpenFHEReplayResult
    package_before: RouteAOpenFHEPackageInspection
    package_after: RouteAOpenFHEPackageInspection


def _absolute(path: Path, *, field: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise RouteANativeRuntimeError(f"{field} must be one absolute Path")
    return path


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write raises or advances
                raise RouteANativeRuntimeError("native scratch write stalled")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_stable(path: Path, *, maximum: int, field: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise RouteANativeRuntimeError(f"{field} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise RouteANativeRuntimeError(f"{field} is outside its byte bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise RouteANativeRuntimeError(f"{field} changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _request_bytes(authorized: RouteANativeAuthorizedInvocation) -> bytes:
    bundle = authorized.prepared.case.execution_bundle
    prepared = authorized.prepared.prepared_query
    if type(bundle) is OrdinaryExecutionBundle:
        return build_ordinary_openfhe_query_request(bundle, prepared)
    if type(bundle) is StrongExecutionBundle:
        return build_strong_openfhe_query_request(bundle, prepared)
    raise RouteANativeRuntimeError("native execution kind changed")


def _verify_producer(
    authorized: RouteANativeAuthorizedInvocation,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
) -> VerifiedRouteAOpenFHEProducerResult:
    bundle = authorized.prepared.case.execution_bundle
    prepared = authorized.prepared.prepared_query
    arguments = {
        "request_bytes": request_bytes,
        "result_path": result_path,
        "object_root": object_root,
        "expected_output": authorized.typed_oracle_output,
    }
    if type(bundle) is OrdinaryExecutionBundle:
        return verify_route_a_ordinary_openfhe_producer_result(bundle, prepared, **arguments)
    if type(bundle) is StrongExecutionBundle:
        return verify_route_a_strong_openfhe_producer_result(bundle, prepared, **arguments)
    raise RouteANativeRuntimeError("native execution kind changed")


def _verify_replay(
    case: RouteANativeCasePlan,
    prepared: object,
    *,
    request_bytes: bytes,
    manifest_sha256: str,
    result_path: Path,
    object_root: Path,
) -> VerifiedRouteAOpenFHEReplayResult:
    bundle = case.execution_bundle
    arguments = {
        "request_bytes": request_bytes,
        "package_manifest_sha256": manifest_sha256,
        "result_path": result_path,
        "object_root": object_root,
        "expected_output": case.direct_oracle_output,
    }
    if type(bundle) is OrdinaryExecutionBundle:
        return verify_route_a_ordinary_openfhe_replay_result(bundle, prepared, **arguments)
    if type(bundle) is StrongExecutionBundle:
        return verify_route_a_strong_openfhe_replay_result(bundle, prepared, **arguments)
    raise RouteANativeRuntimeError("native execution kind changed")


def _setup_scratch(root: Path) -> tuple[Path, Path, Path]:
    if root.exists() or root.is_symlink():
        raise RouteANativeRuntimeError("native scratch root must be absent")
    root.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    result_path = root / "result.json"
    object_root = root / "objects"
    object_root.mkdir(mode=0o700)
    return root / "request.json", result_path, object_root


def _validate_limits(
    *,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> None:
    if any(
        type(value) is not int or value <= 0
        for value in (
            timeout_seconds,
            resident_memory_limit_bytes,
            scratch_limit_bytes,
        )
    ):
        raise RouteANativeRuntimeError("native limits must be strict positive integers")


def execute_route_a_native_producer(
    capability: RouteANativeProducerCapability,
    *,
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    build_manifest_sha256: str,
    retained_package_directory: Path | None,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> RouteANativeProducerExecution:
    """Consume one launch capability and execute q3 or the discarded warm-up."""

    root = _absolute(repository_root, field="repository_root")
    scratch = _absolute(scratch_root, field="scratch_root")
    _validate_limits(
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
    )
    runner_identity = capture_openfhe_runner_build_identity(root, runner_relative_path)
    runner = root.joinpath(*PurePosixPath(runner_relative_path).parts)
    request_path, result_path, object_root = _setup_scratch(scratch)
    try:
        authorized = claim_route_a_native_producer_capability(capability)
        lane = authorized.prepared.lane
        recorded = lane.execution_process_role == "openfhe-recorded"
        if recorded != (retained_package_directory is not None):
            raise RouteANativeRuntimeError(
                "recorded producer retention differs from its process lane"
            )
        request_bytes = _request_bytes(authorized)
        _write_new(request_path, request_bytes)
        observation = run_controlled_openfhe_process(
            runner,
            repository_root=root,
            scratch_root=scratch,
            request_path=request_path,
            route_a_mode="producer",
            result_path=result_path,
            object_root=object_root,
            timeout_seconds=timeout_seconds,
            scratch_limit_bytes=scratch_limit_bytes,
            runner_identity=runner_identity,
        )
        if observation.peak_resident_memory_bytes > resident_memory_limit_bytes:
            raise RouteANativeRuntimeError("native resident-memory-limit-exceeded")
        result_before = _read_stable(
            result_path,
            maximum=_MAX_RESULT_BYTES,
            field="producer result",
        )
        verified = _verify_producer(
            authorized,
            request_bytes,
            result_path,
            object_root,
        )
        package = None
        if retained_package_directory is not None:
            package = build_route_a_openfhe_package(
                authorized,
                request_bytes=request_bytes,
                producer_result_path=result_path,
                producer_object_root=object_root,
                build_manifest_sha256=build_manifest_sha256,
                output_directory=retained_package_directory,
            )
        if (
            _read_stable(
                result_path,
                maximum=_MAX_RESULT_BYTES,
                field="producer result",
            )
            != result_before
        ):
            raise RouteANativeRuntimeError("producer result changed during verification")
        if capture_openfhe_runner_build_identity(root, runner_relative_path) != runner_identity:
            raise RouteANativeRuntimeError("native runner identity changed during producer")
        return RouteANativeProducerExecution(
            lane=lane,
            runner_identity=runner_identity,
            process_observation=observation,
            verified_result=verified,
            retained_package=package,
        )
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)


def _materialize_producer_objects(
    inspection: RouteAOpenFHEPackageInspection,
    request_bytes: bytes,
    object_root: Path,
) -> None:
    request = json.loads(request_bytes.decode("ascii"))
    ordered = [
        ("crypto-context", None),
        ("secret-key", None),
        ("public-key", None),
        ("evaluation-key-frame", None),
        *(("input-ciphertext", value["ciphertext_id"]) for value in request["ciphertext_values"]),
        *(
            ("producer-result-ciphertext", result_id)
            for result_id in request["program"]["result_ids"]
        ),
    ]
    for ordinal, (role, subject_id) in enumerate(ordered):
        _write_new(
            object_root / f"object-{ordinal:06d}.bin",
            read_route_a_openfhe_package_member(
                inspection,
                role=role,
                subject_id=subject_id,
            ),
        )


def execute_route_a_native_replay(
    case: RouteANativeCasePlan,
    lane: RouteAEvaluationLane,
    *,
    package_root: Path,
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> RouteANativeReplayExecution:
    """Independently re-inspect one package, execute q4, and rehash it again."""

    root = _absolute(repository_root, field="repository_root")
    scratch = _absolute(scratch_root, field="scratch_root")
    package = _absolute(package_root, field="package_root")
    _validate_limits(
        timeout_seconds=timeout_seconds,
        resident_memory_limit_bytes=resident_memory_limit_bytes,
        scratch_limit_bytes=scratch_limit_bytes,
    )
    before = inspect_route_a_openfhe_package(package)
    request_bytes = read_route_a_openfhe_package_member(before, role="canonical-request")
    preparation_bytes = read_route_a_openfhe_package_member(before, role="preparation")
    authorization_bytes = read_route_a_openfhe_package_member(before, role="authorization-receipt")
    consumed_ledger = next(member for member in before.members if member.role == "consumed-ledger")
    lifecycle = replay_route_a_native_invocation_read_only(
        case,
        lane,
        preparation_bytes=preparation_bytes,
        authorization_receipt_bytes=authorization_bytes,
        consumed_ledger_path=package / consumed_ledger.relative_path,
    )
    runner_identity = capture_openfhe_runner_build_identity(root, runner_relative_path)
    runner = root.joinpath(*PurePosixPath(runner_relative_path).parts)
    request_path, result_path, replay_object_root = _setup_scratch(scratch)
    producer_object_root = scratch / "producer-objects"
    producer_object_root.mkdir(mode=0o700)
    producer_result_path = scratch / "producer-result.json"
    # The producer verifier needs only the decoded prepared query and case view;
    # invoke its typed variants directly rather than recreating producer authority.
    bundle = case.execution_bundle
    producer_arguments = {
        "request_bytes": request_bytes,
        "result_path": producer_result_path,
        "object_root": producer_object_root,
        "expected_output": case.direct_oracle_output,
    }
    try:
        _write_new(request_path, request_bytes)
        _write_new(
            producer_result_path,
            read_route_a_openfhe_package_member(before, role="producer-result"),
        )
        _materialize_producer_objects(before, request_bytes, producer_object_root)
        if type(bundle) is OrdinaryExecutionBundle:
            producer_result = verify_route_a_ordinary_openfhe_producer_result(
                bundle, lifecycle.prepared_query, **producer_arguments
            )
        elif type(bundle) is StrongExecutionBundle:
            producer_result = verify_route_a_strong_openfhe_producer_result(
                bundle, lifecycle.prepared_query, **producer_arguments
            )
        else:  # pragma: no cover - case owns the closed union
            raise RouteANativeRuntimeError("native execution kind changed")
        observation = run_controlled_openfhe_process(
            runner,
            repository_root=root,
            scratch_root=scratch,
            request_path=None,
            package_root=package,
            route_a_mode="replay",
            result_path=result_path,
            object_root=replay_object_root,
            timeout_seconds=timeout_seconds,
            scratch_limit_bytes=scratch_limit_bytes,
            runner_identity=runner_identity,
        )
        if observation.peak_resident_memory_bytes > resident_memory_limit_bytes:
            raise RouteANativeRuntimeError("native resident-memory-limit-exceeded")
        replay_result = _verify_replay(
            case,
            lifecycle.prepared_query,
            request_bytes=request_bytes,
            manifest_sha256=before.manifest_sha256,
            result_path=result_path,
            object_root=replay_object_root,
        )
        after = inspect_route_a_openfhe_package(package)
        if (
            after != before
            or producer_result.cloud_program_operation_inventory
            != replay_result.cloud_program_operation_inventory
            or capture_openfhe_runner_build_identity(root, runner_relative_path) != runner_identity
        ):
            raise RouteANativeRuntimeError(
                "native package, Cloud inventory, or runner changed during replay"
            )
        return RouteANativeReplayExecution(
            lane=lane,
            runner_identity=runner_identity,
            process_observation=observation,
            lifecycle_inspection=lifecycle,
            producer_result=producer_result,
            replay_result=replay_result,
            package_before=before,
            package_after=after,
        )
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
