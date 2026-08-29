"""Single-use lifecycle for one terminal Route A native process lane.

This module stops at the cryptographic process boundary.  It prepares one exact
query, consumes its F1-M commitment once, derives the typed oracle by read-only
replay of that consumed ledger, and exposes the immutable bytes a retained
OpenFHE package must bind.  Key generation and ciphertext execution are owned
by the native package runtime, not by this lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import weakref
from dataclasses import dataclass
from typing import TypeAlias

from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.ordinary_query_lifecycle import (
    ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA,
    OrdinaryExecutionAuthorizationReceipt,
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    authorize_ordinary_execution,
    canonical_ordinary_query_preparation_bytes,
    claim_ordinary_execution,
    decode_ordinary_query_preparation_bytes,
    prepare_ordinary_query,
    replay_ordinary_plaintext_read_only,
)
from dynamic_cssc.route_a_contract import RouteAEvaluationLane, RouteAQueryIdentity
from dynamic_cssc.route_a_native_case import RouteANativeCasePlan
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.strong_execution import (
    STRONG_EXECUTION_AUTHORIZATION_SCHEMA,
    PreparedStrongQuery,
    StrongExecutionAuthorizationReceipt,
    StrongExecutionBundle,
    authorize_strong_execution,
    canonical_strong_query_preparation_bytes,
    claim_strong_execution,
    decode_strong_query_preparation_bytes,
    prepare_strong_query,
    replay_strong_plaintext_read_only,
)

__all__ = (
    "RouteANativeAuthorizedInvocation",
    "RouteANativeInvocationError",
    "RouteANativePreparedInvocation",
    "RouteANativeProducerCapability",
    "RouteANativeReplayInspection",
    "abandon_route_a_native_producer_capability",
    "authorize_route_a_native_invocation",
    "claim_route_a_native_producer_capability",
    "prepare_route_a_native_invocation",
    "replay_route_a_native_invocation_read_only",
    "require_route_a_native_producer_capability_consumed",
)

_MODULUS = 65_537
_TYPED_ORACLE_SCHEMA = "dynamic-cssc-route-a-native-typed-oracle-v1"

RouteANativePreparedQuery: TypeAlias = PreparedOrdinaryQuery | PreparedStrongQuery
RouteANativeAuthorizationReceipt: TypeAlias = (
    OrdinaryExecutionAuthorizationReceipt | StrongExecutionAuthorizationReceipt
)


class RouteANativeInvocationError(RuntimeError):
    """One native process lane violated its single-use lifecycle."""


def _stable_file_identity(status: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _read_stable_file(path: os.PathLike[str], *, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RouteANativeInvocationError("native ledger snapshot cannot be opened") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise RouteANativeInvocationError("native ledger snapshot is outside its bound")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
        if (
            len(content) != before.st_size
            or os.read(descriptor, 1)
            or _stable_file_identity(after) != _stable_file_identity(before)
        ):
            raise RouteANativeInvocationError("native ledger snapshot changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def _validate_producer_lane(case: RouteANativeCasePlan, lane: RouteAEvaluationLane) -> None:
    if type(case) is not RouteANativeCasePlan:
        raise TypeError("case must be an exact RouteANativeCasePlan")
    if type(lane) is not RouteAEvaluationLane:
        raise TypeError("lane must be an exact RouteAEvaluationLane")
    if (
        lane.execution_process_role not in {"openfhe-warmup", "openfhe-recorded"}
        or lane.shard_identity_sha256 != case.shard_identity_sha256
        or lane.strategy_candidate_id != case.strategy_candidate_id
        or lane.rho.numerator != 1
        or lane.rho.denominator != 1
        or lane.unit_attempt_ordinal != case.unit_attempt_ordinal
    ):
        raise RouteANativeInvocationError("native process lane differs from its case")


def _validate_replay_lane(case: RouteANativeCasePlan, lane: RouteAEvaluationLane) -> None:
    _validate_producer_lane(case, lane)
    if (
        lane.execution_process_role != "openfhe-recorded"
        or type(lane.process_ordinal_or_null) is not int
        or lane.process_ordinal_or_null not in {0, 1, 2}
    ):
        raise RouteANativeInvocationError("native replay requires one recorded process lane")


def _preparation_bytes(
    case: RouteANativeCasePlan,
    prepared: RouteANativePreparedQuery,
) -> bytes:
    bundle = case.execution_bundle
    if type(bundle) is OrdinaryExecutionBundle and type(prepared) is PreparedOrdinaryQuery:
        return canonical_ordinary_query_preparation_bytes(bundle, prepared)
    if type(bundle) is StrongExecutionBundle and type(prepared) is PreparedStrongQuery:
        return canonical_strong_query_preparation_bytes(bundle, prepared)
    raise RouteANativeInvocationError("native preparation differs from its execution kind")


def _reservation_bindings(
    prepared: RouteANativePreparedQuery,
) -> tuple[tuple[str, str, str, str, str], ...]:
    return tuple(
        operand.binding for operand in prepared.f1m_operands if operand.kind == "random-zero-sum"
    )


def _typed_oracle_bytes(values: tuple[int, ...]) -> bytes:
    return canonical_route_a_document(
        {
            "ordered_modular_outputs": list(values),
            "schema_version": _TYPED_ORACLE_SCHEMA,
        }
    )


@dataclass(frozen=True, slots=True)
class RouteANativePreparedInvocation:
    """One lane-specific private preparation before its one allowed consumption."""

    case: RouteANativeCasePlan
    lane: RouteAEvaluationLane
    query_identity: RouteAQueryIdentity
    prepared_query: RouteANativePreparedQuery
    preparation_bytes: bytes
    preparation_sha256: str

    def __post_init__(self) -> None:
        _validate_producer_lane(self.case, self.lane)
        expected_identity = self.lane.query_identity(self.case.terminal_global_query_ordinal)
        if (
            self.query_identity != expected_identity
            or self.prepared_query.query_id != expected_identity.query_id
            or self.prepared_query.vector != self.case.query_vector.values
            or _preparation_bytes(self.case, self.prepared_query) != self.preparation_bytes
            or hashlib.sha256(self.preparation_bytes).hexdigest() != self.preparation_sha256
        ):
            raise RouteANativeInvocationError("native preparation binding is not exact")


@dataclass(frozen=True, slots=True)
class RouteANativeAuthorizedInvocation:
    """The consumed producer boundary plus its immutable replay inputs."""

    prepared: RouteANativePreparedInvocation
    authorization_receipt: RouteANativeAuthorizationReceipt
    authorization_receipt_bytes: bytes
    typed_oracle_output: tuple[int, ...]
    typed_oracle_bytes: bytes
    typed_oracle_sha256: str
    consumed_ledger_snapshot_bytes: bytes
    consumed_ledger_snapshot_sha256: str

    def __post_init__(self) -> None:
        if (
            _validate_authorization_receipt(
                self.prepared,
                self.authorization_receipt_bytes,
            )
            != hashlib.sha256(self.authorization_receipt_bytes).hexdigest()
            or canonical_route_a_document(self.authorization_receipt.to_document())
            != self.authorization_receipt_bytes
            or self.typed_oracle_output != self.prepared.case.direct_oracle_output
            or _typed_oracle_bytes(self.typed_oracle_output) != self.typed_oracle_bytes
            or hashlib.sha256(self.typed_oracle_bytes).hexdigest() != self.typed_oracle_sha256
            or not self.consumed_ledger_snapshot_bytes.startswith(b"SQLite format 3\x00")
            or hashlib.sha256(self.consumed_ledger_snapshot_bytes).hexdigest()
            != self.consumed_ledger_snapshot_sha256
        ):
            raise RouteANativeInvocationError("authorized native invocation is not closed")


@dataclass(frozen=True, slots=True)
class _RouteANativeProducerBinding:
    authorized: RouteANativeAuthorizedInvocation


class RouteANativeProducerCapability:
    """Opaque single-use authority for exactly one native producer launch."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> RouteANativeProducerCapability:
        raise TypeError("Route A native producer capabilities are lifecycle-minted")

    def __bool__(self) -> bool:
        raise TypeError("Route A native producer capability is not a caller boolean")


_ISSUED_PRODUCER_CAPABILITIES: dict[
    int,
    tuple[
        weakref.ReferenceType[RouteANativeProducerCapability],
        _RouteANativeProducerBinding,
    ],
] = {}
_PRODUCER_CAPABILITY_LOCK = threading.Lock()


def _collected_producer_capability(identifier: int) -> None:
    with _PRODUCER_CAPABILITY_LOCK:
        _ISSUED_PRODUCER_CAPABILITIES.pop(identifier, None)


def _mint_producer_capability(
    authorized: RouteANativeAuthorizedInvocation,
) -> RouteANativeProducerCapability:
    if type(authorized) is not RouteANativeAuthorizedInvocation:
        raise TypeError("authorized must be an exact RouteANativeAuthorizedInvocation")
    capability = object.__new__(RouteANativeProducerCapability)
    binding = _RouteANativeProducerBinding(authorized=authorized)
    object.__setattr__(capability, "_binding", binding)
    identifier = id(capability)
    reference = weakref.ref(
        capability,
        lambda _reference, identifier=identifier: _collected_producer_capability(identifier),
    )
    with _PRODUCER_CAPABILITY_LOCK:
        if identifier in _ISSUED_PRODUCER_CAPABILITIES:  # pragma: no cover - id collision
            raise RouteANativeInvocationError("native producer capability identity collided")
        _ISSUED_PRODUCER_CAPABILITIES[identifier] = (reference, binding)
    return capability


def claim_route_a_native_producer_capability(
    capability: RouteANativeProducerCapability,
) -> RouteANativeAuthorizedInvocation:
    """Atomically consume one launch authority and expose its exact private carrier."""

    if type(capability) is not RouteANativeProducerCapability:
        raise TypeError("producer launch requires one exact lifecycle-minted capability")
    presented = getattr(capability, "_binding", None)
    with _PRODUCER_CAPABILITY_LOCK:
        active = _ISSUED_PRODUCER_CAPABILITIES.pop(id(capability), None)
    if (
        active is None
        or active[0]() is not capability
        or active[1] is not presented
        or type(presented) is not _RouteANativeProducerBinding
    ):
        raise RouteANativeInvocationError(
            "native producer capability is absent, forged, or consumed"
        )
    object.__setattr__(capability, "_binding", None)
    return presented.authorized


def abandon_route_a_native_producer_capability(
    capability: RouteANativeProducerCapability,
) -> None:
    """Consume an unused launch authority without exposing its private carrier."""

    claim_route_a_native_producer_capability(capability)


def require_route_a_native_producer_capability_consumed(
    capability: RouteANativeProducerCapability,
) -> None:
    """Require the terminal state produced by a claim or abandonment."""

    if type(capability) is not RouteANativeProducerCapability:
        raise TypeError("producer launch requires one exact lifecycle-minted capability")
    with _PRODUCER_CAPABILITY_LOCK:
        active = _ISSUED_PRODUCER_CAPABILITIES.get(id(capability))
    if active is not None or getattr(capability, "_binding", capability) is not None:
        raise RouteANativeInvocationError("native producer capability was not consumed")


@dataclass(frozen=True, slots=True)
class RouteANativeReplayInspection:
    """Read-only verification of one producer preparation and consumed ledger."""

    prepared_query: RouteANativePreparedQuery
    preparation_sha256: str
    authorization_receipt_sha256: str
    ledger_snapshot_sha256: str
    typed_oracle_sha256: str


def prepare_route_a_native_invocation(
    case: RouteANativeCasePlan,
    lane: RouteAEvaluationLane,
    *,
    ledger: SQLiteMaskBindingLedger,
) -> RouteANativePreparedInvocation:
    """Reserve and commit one fresh lane-specific F1-M preparation."""

    _validate_producer_lane(case, lane)
    if type(ledger) is not SQLiteMaskBindingLedger or ledger._read_only:  # noqa: SLF001
        raise TypeError("native preparation requires one exact writable SQLite ledger")
    query_identity = lane.query_identity(case.terminal_global_query_ordinal)
    bundle = case.execution_bundle
    if type(bundle) is OrdinaryExecutionBundle:
        prepared: RouteANativePreparedQuery = prepare_ordinary_query(
            bundle,
            query_id=query_identity.query_id,
            vector=case.query_vector.values,
            modulus=_MODULUS,
            ledger=ledger,
        )
    elif type(bundle) is StrongExecutionBundle:
        prepared = prepare_strong_query(
            bundle,
            query_id=query_identity.query_id,
            vector=case.query_vector.values,
            modulus=_MODULUS,
            ledger=ledger,
        )
    else:  # pragma: no cover - RouteANativeCasePlan owns the closed union
        raise AssertionError("native case execution bundle changed type")
    preparation_bytes = _preparation_bytes(case, prepared)
    return RouteANativePreparedInvocation(
        case=case,
        lane=lane,
        query_identity=query_identity,
        prepared_query=prepared,
        preparation_bytes=preparation_bytes,
        preparation_sha256=hashlib.sha256(preparation_bytes).hexdigest(),
    )


def authorize_route_a_native_invocation(
    prepared: RouteANativePreparedInvocation,
    *,
    ledger: SQLiteMaskBindingLedger,
) -> RouteANativeProducerCapability:
    """Consume once, close the typed oracle, and mint one native-launch authority."""

    if type(prepared) is not RouteANativePreparedInvocation:
        raise TypeError("prepared must be an exact RouteANativePreparedInvocation")
    if type(ledger) is not SQLiteMaskBindingLedger or ledger._read_only:  # noqa: SLF001
        raise TypeError("native authorization requires one exact writable SQLite ledger")
    case = prepared.case
    bundle = case.execution_bundle
    query = prepared.prepared_query
    if type(bundle) is OrdinaryExecutionBundle and type(query) is PreparedOrdinaryQuery:
        capability = authorize_ordinary_execution(bundle, query, ledger=ledger)
        receipt: RouteANativeAuthorizationReceipt = claim_ordinary_execution(
            capability,
            bundle,
            query,
        )
    elif type(bundle) is StrongExecutionBundle and type(query) is PreparedStrongQuery:
        capability = authorize_strong_execution(bundle, query, ledger=ledger)
        receipt = claim_strong_execution(capability, bundle, query)
    else:  # pragma: no cover - the prepared wrapper owns the closed union
        raise AssertionError("native prepared query changed execution kind")
    ledger_bytes = _read_stable_file(ledger.path, maximum=64 * 1024 * 1024)
    replay_ledger = SQLiteMaskBindingLedger.open_existing_read_only(ledger.path)
    replay_ledger.verify_closed_consumed_prepared_f1m_ledger(
        commitment_tokens=(query.ledger_commitment_token,),
        reservation_bindings=_reservation_bindings(query),
    )
    if type(bundle) is OrdinaryExecutionBundle and type(query) is PreparedOrdinaryQuery:
        typed_output = replay_ordinary_plaintext_read_only(
            bundle,
            query,
            modulus=_MODULUS,
            ledger=replay_ledger,
        )
    elif type(bundle) is StrongExecutionBundle and type(query) is PreparedStrongQuery:
        typed_output = replay_strong_plaintext_read_only(
            bundle,
            query,
            modulus=_MODULUS,
            ledger=replay_ledger,
        )
    else:  # pragma: no cover - the prepared wrapper owns the closed union
        raise AssertionError("native prepared query changed execution kind")
    if (
        typed_output != case.direct_oracle_output
        or _read_stable_file(ledger.path, maximum=64 * 1024 * 1024) != ledger_bytes
    ):
        raise RouteANativeInvocationError(
            "native typed oracle or consumed ledger changed after authorization"
        )
    typed_bytes = _typed_oracle_bytes(typed_output)
    receipt_bytes = canonical_route_a_document(receipt.to_document())
    return _mint_producer_capability(
        RouteANativeAuthorizedInvocation(
            prepared=prepared,
            authorization_receipt=receipt,
            authorization_receipt_bytes=receipt_bytes,
            typed_oracle_output=typed_output,
            typed_oracle_bytes=typed_bytes,
            typed_oracle_sha256=hashlib.sha256(typed_bytes).hexdigest(),
            consumed_ledger_snapshot_bytes=ledger_bytes,
            consumed_ledger_snapshot_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
        )
    )


def _validate_authorization_receipt(
    prepared: RouteANativePreparedInvocation,
    content: bytes,
) -> str:
    try:
        document = json.loads(content.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteANativeInvocationError(
            "native authorization receipt is not canonical JSON"
        ) from error
    query = prepared.prepared_query
    schema = (
        ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA
        if type(query) is PreparedOrdinaryQuery
        else STRONG_EXECUTION_AUTHORIZATION_SCHEMA
    )
    transition = {
        "execution_binding_digest": query.execution_binding_digest,
        "ledger_commitment_token": query.ledger_commitment_token,
        "query_id": query.query_id,
        "query_preparation_sha256": prepared.preparation_sha256,
        "schema_version": schema,
        "transition": "prepared-to-consumed",
        "version_id": query.version_id,
    }
    expected = {
        "authorization_transition_sha256": hashlib.sha256(
            canonical_route_a_document(transition).rstrip(b"\n")
        ).hexdigest(),
        "execution_binding_digest": query.execution_binding_digest,
        "ledger_commitment_token": query.ledger_commitment_token,
        "query_id": query.query_id,
        "query_preparation_sha256": prepared.preparation_sha256,
        "schema_version": schema,
        "version_id": query.version_id,
    }
    if canonical_route_a_document(document) != content or document != expected:
        raise RouteANativeInvocationError("native authorization receipt binding changed")
    return hashlib.sha256(content).hexdigest()


def replay_route_a_native_invocation_read_only(
    case: RouteANativeCasePlan,
    lane: RouteAEvaluationLane,
    *,
    preparation_bytes: bytes,
    authorization_receipt_bytes: bytes,
    consumed_ledger_path: os.PathLike[str],
) -> RouteANativeReplayInspection:
    """Verify producer lifecycle bytes without consuming or mutating them again."""

    _validate_replay_lane(case, lane)
    query_identity = lane.query_identity(case.terminal_global_query_ordinal)
    bundle = case.execution_bundle
    if type(bundle) is OrdinaryExecutionBundle:
        query: RouteANativePreparedQuery = decode_ordinary_query_preparation_bytes(
            bundle,
            preparation_bytes,
            expected_query_id=query_identity.query_id,
            expected_vector=case.query_vector.values,
        )
    elif type(bundle) is StrongExecutionBundle:
        query = decode_strong_query_preparation_bytes(
            bundle,
            preparation_bytes,
            expected_query_id=query_identity.query_id,
            expected_vector=case.query_vector.values,
        )
    else:  # pragma: no cover - RouteANativeCasePlan owns the closed union
        raise AssertionError("native replay case changed execution kind")
    prepared = RouteANativePreparedInvocation(
        case=case,
        lane=lane,
        query_identity=query_identity,
        prepared_query=query,
        preparation_bytes=preparation_bytes,
        preparation_sha256=hashlib.sha256(preparation_bytes).hexdigest(),
    )
    receipt_sha256 = _validate_authorization_receipt(
        prepared,
        authorization_receipt_bytes,
    )
    ledger_bytes = _read_stable_file(
        consumed_ledger_path,
        maximum=64 * 1024 * 1024,
    )
    ledger = SQLiteMaskBindingLedger.open_existing_read_only(consumed_ledger_path)
    ledger.verify_closed_consumed_prepared_f1m_ledger(
        commitment_tokens=(query.ledger_commitment_token,),
        reservation_bindings=_reservation_bindings(query),
    )
    if type(bundle) is OrdinaryExecutionBundle and type(query) is PreparedOrdinaryQuery:
        typed_output = replay_ordinary_plaintext_read_only(
            bundle,
            query,
            modulus=_MODULUS,
            ledger=ledger,
        )
    elif type(bundle) is StrongExecutionBundle and type(query) is PreparedStrongQuery:
        typed_output = replay_strong_plaintext_read_only(
            bundle,
            query,
            modulus=_MODULUS,
            ledger=ledger,
        )
    else:  # pragma: no cover - the decoded union is closed above
        raise AssertionError("native replay preparation changed execution kind")
    if typed_output != case.direct_oracle_output:
        raise RouteANativeInvocationError("native replay typed oracle differs from direct oracle")
    if _read_stable_file(consumed_ledger_path, maximum=64 * 1024 * 1024) != ledger_bytes:
        raise RouteANativeInvocationError("native replay mutated its consumed ledger")
    typed_bytes = _typed_oracle_bytes(typed_output)
    return RouteANativeReplayInspection(
        prepared_query=query,
        preparation_sha256=prepared.preparation_sha256,
        authorization_receipt_sha256=receipt_sha256,
        ledger_snapshot_sha256=hashlib.sha256(ledger_bytes).hexdigest(),
        typed_oracle_sha256=hashlib.sha256(typed_bytes).hexdigest(),
    )
