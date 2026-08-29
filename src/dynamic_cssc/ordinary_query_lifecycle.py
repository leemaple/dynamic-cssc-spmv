"""Canonical private preparation and single-use execution for ordinary queries.

The common query compiler closes the Cloud-visible DAG, but an ordinary Day1B
candidate also needs a private lifecycle: bind global-column operands, prepare
fresh overlap masks, persist their exact commitment, execute once, and consume
that commitment.  This module owns that lifecycle without knowing about a
process launcher or OpenFHE serialization.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.mask_ledger import (
    PreparedF1MCommitment,
    PreparedF1MCommitmentLedger,
)
from dynamic_cssc.output_plan import PreparedMask, prepare_f1m_masks
from dynamic_cssc.plaintext_oracle import execute_compiled_query, reconstruct_output
from dynamic_cssc.query_compiler import (
    QUERY_PRIVATE_PLAN_FORMAT,
    CompiledQuery,
    ResultRoute,
    canonical_query_private_plan_payload,
    validate_compiled_query,
)

ORDINARY_PRIVATE_PLAN_SCHEMA = QUERY_PRIVATE_PLAN_FORMAT
ORDINARY_QUERY_PREPARATION_SCHEMA = (
    "dynamic-cssc-common-ordinary-query-preparation-v1"
)
ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA = (
    "dynamic-cssc-common-ordinary-execution-authorization-v1"
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
OrdinaryF1MKind = Literal["random-zero-sum"]


class OrdinaryQueryLifecycleError(ValueError):
    """An ordinary query is not its exact canonical single-use lifecycle."""


@dataclass(frozen=True, slots=True)
class OrdinaryExecutionBundle:
    """One validated ordinary compilation plus its private-plan identity."""

    compiled: CompiledQuery
    private_plan_digest: str


@dataclass(frozen=True, slots=True)
class PreparedOrdinaryQueryOperand:
    ciphertext_id: str
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PreparedOrdinaryF1MOperand:
    ciphertext_id: str
    result_id: str
    kind: OrdinaryF1MKind
    query_id: str
    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    values: tuple[int, ...]

    @property
    def binding(self) -> tuple[str, str, str, str, str]:
        return (
            self.query_id,
            self.version_id,
            self.output_plan_digest,
            self.component_id,
            self.output_block_id,
        )


@dataclass(frozen=True, slots=True)
class PreparedOrdinaryQuery:
    """Private query operands bound to one crash-persistent commitment batch."""

    query_id: str
    version_id: str
    modulus: int
    vector: tuple[int, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    ledger_commitment_token: str
    query_operands: tuple[PreparedOrdinaryQueryOperand, ...]
    f1m_operands: tuple[PreparedOrdinaryF1MOperand, ...]


@dataclass(frozen=True, slots=True)
class OrdinaryExecutionAuthorizationReceipt:
    """Non-secret receipt for one durably consumed prepared-query batch."""

    query_id: str
    version_id: str
    ledger_commitment_token: str
    query_preparation_sha256: str
    execution_binding_digest: str
    authorization_transition_sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "authorization_transition_sha256": self.authorization_transition_sha256,
            "execution_binding_digest": self.execution_binding_digest,
            "ledger_commitment_token": self.ledger_commitment_token,
            "query_id": self.query_id,
            "query_preparation_sha256": self.query_preparation_sha256,
            "schema_version": ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA,
            "version_id": self.version_id,
        }


class OrdinaryExecutionCapability:
    """Opaque single-use authorization minted only after ledger consumption."""

    __slots__ = ("_binding", "_claimed", "_lock")

    def __new__(cls) -> OrdinaryExecutionCapability:
        raise TypeError("ordinary execution capabilities are lifecycle-minted")

    def __bool__(self) -> bool:
        raise TypeError("ordinary execution capability is not a caller boolean")


@dataclass(frozen=True, slots=True)
class _OrdinaryExecutionAuthorizationBinding:
    receipt: OrdinaryExecutionAuthorizationReceipt


def _canonical_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise OrdinaryQueryLifecycleError("ordinary query value is not canonical JSON") from error
    return rendered.encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OrdinaryQueryLifecycleError(
                "ordinary query preparation contains a duplicate JSON key"
            )
        result[key] = value
    return result


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_id(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _validated_vector(value: object, *, length: int) -> tuple[int, ...]:
    if type(value) is not tuple or len(value) != length:
        raise OrdinaryQueryLifecycleError(f"vector must be an exact tuple of length {length}")
    if any(not _is_strict_int(element) for element in value):
        raise OrdinaryQueryLifecycleError("vector must contain strict integers")
    return value


def bind_ordinary_execution(compiled: CompiledQuery) -> OrdinaryExecutionBundle:
    """Validate and bind an independently supplied ordinary compilation."""

    try:
        validate_compiled_query(compiled)
        canonical_query_private_plan_payload(compiled)
    except ValueError as error:
        raise OrdinaryQueryLifecycleError("ordinary compilation is not canonical") from error
    if compiled.f1m_policy != "overlap-only":
        raise OrdinaryQueryLifecycleError(
            "ordinary lifecycle requires the exact overlap-only F1-M policy"
        )
    return OrdinaryExecutionBundle(
        compiled=compiled,
        private_plan_digest=compiled.private_plan_digest,
    )


def _validate_bundle(bundle: OrdinaryExecutionBundle) -> None:
    if type(bundle) is not OrdinaryExecutionBundle:
        raise OrdinaryQueryLifecycleError("bundle must be an exact OrdinaryExecutionBundle")
    expected = bind_ordinary_execution(bundle.compiled)
    if bundle != expected:
        raise OrdinaryQueryLifecycleError("ordinary bundle changed after canonical binding")


def canonical_ordinary_private_plan_payload(
    bundle: OrdinaryExecutionBundle,
) -> dict[str, object]:
    """Return private operands and routes; this payload is never Cloud-visible."""

    _validate_bundle(bundle)
    return canonical_query_private_plan_payload(bundle.compiled)


def canonical_ordinary_private_plan_bytes(bundle: OrdinaryExecutionBundle) -> bytes:
    return _canonical_bytes(canonical_ordinary_private_plan_payload(bundle))


def _prepared_f1m_commitments(
    operands: tuple[PreparedOrdinaryF1MOperand, ...],
) -> tuple[PreparedF1MCommitment, ...]:
    return tuple(
        PreparedF1MCommitment(
            query_id=operand.query_id,
            version_id=operand.version_id,
            output_plan_digest=operand.output_plan_digest,
            component_id=operand.component_id,
            output_block_id=operand.output_block_id,
            kind=operand.kind,
            values=operand.values,
        )
        for operand in operands
    )


def _masked_routes(
    compiled: CompiledQuery,
) -> tuple[tuple[ResultRoute, tuple[str, str]], ...]:
    return tuple(
        (route, (route.component_id, route.output_block_id))
        for route in compiled.result_routes
        if route.f1m_ciphertext_id is not None
    )


def prepare_ordinary_query(
    bundle: OrdinaryExecutionBundle,
    *,
    query_id: str,
    vector: tuple[int, ...],
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> PreparedOrdinaryQuery:
    """Reserve fresh masks and durably commit one exact private query batch."""

    _validate_bundle(bundle)
    compiled = bundle.compiled
    dense_vector = _validated_vector(
        vector,
        length=compiled.components[0].layout_spec.cols,
    )
    if not _is_strict_int(modulus) or modulus < 2:
        raise OrdinaryQueryLifecycleError("modulus must be a strict integer of at least two")
    version_id = compiled.cloud_plan.binding.version_id
    try:
        random_masks = prepare_f1m_masks(
            compiled.output_plan,
            query_id=query_id,
            version_id=version_id,
            modulus=modulus,
            ledger=ledger,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise OrdinaryQueryLifecycleError("ordinary overlap-mask preparation failed") from error
    random_by_share = {
        (mask.component_id, mask.output_block_id): mask for mask in random_masks
    }
    query_operands = tuple(
        PreparedOrdinaryQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                dense_vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in compiled.operand_specs
    )
    f1m_operands: list[PreparedOrdinaryF1MOperand] = []
    for route, share_id in _masked_routes(compiled):
        mask: PreparedMask | None = random_by_share.get(share_id)
        if mask is None or route.f1m_ciphertext_id is None:
            raise OrdinaryQueryLifecycleError(
                "ordinary compiled F1-M route lacks its freshly prepared overlap mask"
            )
        f1m_operands.append(
            PreparedOrdinaryF1MOperand(
                ciphertext_id=route.f1m_ciphertext_id,
                result_id=route.result_id,
                kind="random-zero-sum",
                query_id=query_id,
                version_id=version_id,
                output_plan_digest=bundle.compiled.output_plan_digest,
                component_id=route.component_id,
                output_block_id=route.output_block_id,
                values=mask.values,
            )
        )
    prepared_f1m = tuple(f1m_operands)
    if set(random_by_share) != {
        (operand.component_id, operand.output_block_id) for operand in prepared_f1m
    }:
        raise OrdinaryQueryLifecycleError("prepared overlap masks escape the compiled F1-M routes")
    try:
        commitment_token = ledger.commit_prepared_f1m(
            _prepared_f1m_commitments(prepared_f1m),
            query_id=query_id,
            version_id=version_id,
            output_plan_digest=compiled.output_plan_digest,
            private_plan_digest=bundle.private_plan_digest,
            execution_binding_digest=compiled.execution_binding_digest,
            modulus=modulus,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise OrdinaryQueryLifecycleError("ordinary F1-M commitment failed") from error
    prepared = PreparedOrdinaryQuery(
        query_id=query_id,
        version_id=version_id,
        modulus=modulus,
        vector=dense_vector,
        cloud_program_digest=compiled.cloud_program_digest,
        output_plan_digest=compiled.output_plan_digest,
        execution_binding_digest=compiled.execution_binding_digest,
        private_plan_digest=bundle.private_plan_digest,
        ledger_commitment_token=commitment_token,
        query_operands=query_operands,
        f1m_operands=prepared_f1m,
    )
    _validate_prepared(bundle, prepared)
    return prepared


def _validate_prepared(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> None:
    if type(prepared) is not PreparedOrdinaryQuery:
        raise OrdinaryQueryLifecycleError("prepared must be an exact PreparedOrdinaryQuery")
    compiled = bundle.compiled
    if (
        not _valid_id(prepared.query_id)
        or not _valid_id(prepared.version_id)
        or prepared.version_id != compiled.cloud_plan.binding.version_id
        or prepared.cloud_program_digest != compiled.cloud_program_digest
        or prepared.output_plan_digest != compiled.output_plan_digest
        or prepared.execution_binding_digest != compiled.execution_binding_digest
        or prepared.private_plan_digest != bundle.private_plan_digest
        or _LOWER_SHA256.fullmatch(prepared.ledger_commitment_token) is None
        or not _is_strict_int(prepared.modulus)
        or prepared.modulus < 2
    ):
        raise OrdinaryQueryLifecycleError(
            "prepared ordinary query does not match its execution bundle binding"
        )
    dense_vector = _validated_vector(
        prepared.vector,
        length=compiled.components[0].layout_spec.cols,
    )
    expected_queries = tuple(
        PreparedOrdinaryQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                dense_vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in compiled.operand_specs
    )
    if prepared.query_operands != expected_queries:
        raise OrdinaryQueryLifecycleError(
            "prepared ordinary query operands do not match private global columns"
        )

    multiplicity: Counter[int] = Counter(
        logical
        for share in compiled.output_plan.shares
        for _lane, logical in share.slot_to_logical
    )
    overlap = {logical for logical, count in multiplicity.items() if count > 1}
    share_by_id = {
        (share.component_id, share.output_block_id): share
        for share in compiled.output_plan.shares
    }
    routes = _masked_routes(compiled)
    if len(prepared.f1m_operands) != len(routes):
        raise OrdinaryQueryLifecycleError(
            "prepared ordinary query must cover every compiled F1-M route exactly once"
        )
    values_by_share: dict[tuple[str, str], tuple[int, ...]] = {}
    for operand, (route, share_id) in zip(prepared.f1m_operands, routes, strict=True):
        share = share_by_id[share_id]
        mapped_overlap_lanes = {
            lane for lane, logical in share.slot_to_logical if logical in overlap
        }
        if (
            operand.ciphertext_id != route.f1m_ciphertext_id
            or operand.result_id != route.result_id
            or operand.kind != "random-zero-sum"
            or operand.query_id != prepared.query_id
            or operand.version_id != prepared.version_id
            or operand.output_plan_digest != prepared.output_plan_digest
            or (operand.component_id, operand.output_block_id) != share_id
            or type(operand.values) is not tuple
            or len(operand.values) != compiled.output_plan.slot_count
            or any(
                not _is_strict_int(value) or not 0 <= value < prepared.modulus
                for value in operand.values
            )
            or any(
                value and lane not in mapped_overlap_lanes
                for lane, value in enumerate(operand.values)
            )
        ):
            raise OrdinaryQueryLifecycleError(
                "prepared ordinary F1-M operand changed its exact overlap route"
            )
        values_by_share[share_id] = operand.values
    for logical in overlap:
        total = 0
        for share in compiled.output_plan.shares:
            share_id = (share.component_id, share.output_block_id)
            for lane, coordinate in share.slot_to_logical:
                if coordinate == logical:
                    total += values_by_share[share_id][lane]
        if total % prepared.modulus:
            raise OrdinaryQueryLifecycleError(
                "prepared ordinary F1-M values do not cancel per overlapping coordinate"
            )


def canonical_ordinary_query_preparation_payload(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> dict[str, object]:
    """Serialize private execution input; callers must not publish this payload."""

    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    return {
        "bindings": {
            "cloud_program_digest": prepared.cloud_program_digest,
            "execution_binding_digest": prepared.execution_binding_digest,
            "output_plan_digest": prepared.output_plan_digest,
            "private_plan_digest": prepared.private_plan_digest,
        },
        "f1m_operands": [
            {
                "ciphertext_id": operand.ciphertext_id,
                "component_id": operand.component_id,
                "kind": operand.kind,
                "output_block_id": operand.output_block_id,
                "result_id": operand.result_id,
                "values": list(operand.values),
            }
            for operand in prepared.f1m_operands
        ],
        "format": ORDINARY_QUERY_PREPARATION_SCHEMA,
        "ledger_commitment_token": prepared.ledger_commitment_token,
        "modulus": prepared.modulus,
        "query_id": prepared.query_id,
        "query_operands": [
            {
                "ciphertext_id": operand.ciphertext_id,
                "values": list(operand.values),
            }
            for operand in prepared.query_operands
        ],
        "version_id": prepared.version_id,
    }


def canonical_ordinary_query_preparation_bytes(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> bytes:
    return _canonical_bytes(canonical_ordinary_query_preparation_payload(bundle, prepared))


def decode_ordinary_query_preparation_bytes(
    bundle: OrdinaryExecutionBundle,
    content: bytes,
    *,
    expected_query_id: str,
    expected_vector: tuple[int, ...],
) -> PreparedOrdinaryQuery:
    """Decode exact retained private bytes into one bundle-bound replay operand."""

    _validate_bundle(bundle)
    if type(content) is not bytes:
        raise TypeError("ordinary query preparation content must be exact bytes")
    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OrdinaryQueryLifecycleError(
            "ordinary query preparation is not canonical ASCII JSON"
        ) from error
    if type(payload) is not dict or _canonical_bytes(payload) != content:
        raise OrdinaryQueryLifecycleError(
            "ordinary query preparation is not one canonical object"
        )
    if set(payload) != {
        "bindings",
        "f1m_operands",
        "format",
        "ledger_commitment_token",
        "modulus",
        "query_id",
        "query_operands",
        "version_id",
    } or payload.get("format") != ORDINARY_QUERY_PREPARATION_SCHEMA:
        raise OrdinaryQueryLifecycleError(
            "ordinary query preparation does not match its closed schema"
        )
    bindings = payload.get("bindings")
    query_operands = payload.get("query_operands")
    f1m_operands = payload.get("f1m_operands")
    if (
        type(bindings) is not dict
        or set(bindings)
        != {
            "cloud_program_digest",
            "execution_binding_digest",
            "output_plan_digest",
            "private_plan_digest",
        }
        or type(query_operands) is not list
        or type(f1m_operands) is not list
        or payload.get("query_id") != expected_query_id
    ):
        raise OrdinaryQueryLifecycleError(
            "ordinary query preparation differs from its expected replay target"
        )

    def strict_values(value: object, *, label: str) -> tuple[int, ...]:
        if type(value) is not list or any(not _is_strict_int(item) for item in value):
            raise OrdinaryQueryLifecycleError(
                f"ordinary query preparation {label} values are invalid"
            )
        return tuple(value)

    decoded_queries: list[PreparedOrdinaryQueryOperand] = []
    for operand in query_operands:
        if (
            type(operand) is not dict
            or set(operand) != {"ciphertext_id", "values"}
            or not _valid_id(operand.get("ciphertext_id"))
        ):
            raise OrdinaryQueryLifecycleError(
                "ordinary query preparation query operand is invalid"
            )
        decoded_queries.append(
            PreparedOrdinaryQueryOperand(
                ciphertext_id=operand["ciphertext_id"],
                values=strict_values(operand.get("values"), label="query operand"),
            )
        )
    decoded_f1m: list[PreparedOrdinaryF1MOperand] = []
    for operand in f1m_operands:
        if (
            type(operand) is not dict
            or set(operand)
            != {
                "ciphertext_id",
                "component_id",
                "kind",
                "output_block_id",
                "result_id",
                "values",
            }
            or not _valid_id(operand.get("ciphertext_id"))
            or not _valid_id(operand.get("component_id"))
            or operand.get("kind") != "random-zero-sum"
            or not _valid_id(operand.get("output_block_id"))
            or not _valid_id(operand.get("result_id"))
        ):
            raise OrdinaryQueryLifecycleError(
                "ordinary query preparation F1-M operand is invalid"
            )
        decoded_f1m.append(
            PreparedOrdinaryF1MOperand(
                ciphertext_id=operand["ciphertext_id"],
                result_id=operand["result_id"],
                kind="random-zero-sum",
                query_id=expected_query_id,
                version_id=payload["version_id"],
                output_plan_digest=bindings["output_plan_digest"],
                component_id=operand["component_id"],
                output_block_id=operand["output_block_id"],
                values=strict_values(operand.get("values"), label="F1-M operand"),
            )
        )
    prepared = PreparedOrdinaryQuery(
        query_id=expected_query_id,
        version_id=payload.get("version_id"),
        modulus=payload.get("modulus"),
        vector=_validated_vector(
            expected_vector,
            length=bundle.compiled.components[0].layout_spec.cols,
        ),
        cloud_program_digest=bindings.get("cloud_program_digest"),
        output_plan_digest=bindings.get("output_plan_digest"),
        execution_binding_digest=bindings.get("execution_binding_digest"),
        private_plan_digest=bindings.get("private_plan_digest"),
        ledger_commitment_token=payload.get("ledger_commitment_token"),
        query_operands=tuple(decoded_queries),
        f1m_operands=tuple(decoded_f1m),
    )
    _validate_prepared(bundle, prepared)
    if canonical_ordinary_query_preparation_bytes(bundle, prepared) != content:
        raise OrdinaryQueryLifecycleError(
            "decoded ordinary query preparation does not round-trip exactly"
        )
    return prepared


def authorize_ordinary_execution(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
) -> OrdinaryExecutionCapability:
    """Consume one prepared batch and mint the exact launch authorization once."""

    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    preparation_sha256 = hashlib.sha256(
        canonical_ordinary_query_preparation_bytes(bundle, prepared)
    ).hexdigest()
    try:
        ledger.verify_and_consume_prepared_f1m(
            _prepared_f1m_commitments(prepared.f1m_operands),
            commitment_token=prepared.ledger_commitment_token,
            query_id=prepared.query_id,
            version_id=prepared.version_id,
            output_plan_digest=prepared.output_plan_digest,
            private_plan_digest=prepared.private_plan_digest,
            execution_binding_digest=prepared.execution_binding_digest,
            modulus=prepared.modulus,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise OrdinaryQueryLifecycleError("ordinary F1-M commitment consumption failed") from error
    transition = {
        "execution_binding_digest": prepared.execution_binding_digest,
        "ledger_commitment_token": prepared.ledger_commitment_token,
        "query_id": prepared.query_id,
        "query_preparation_sha256": preparation_sha256,
        "schema_version": ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA,
        "transition": "prepared-to-consumed",
        "version_id": prepared.version_id,
    }
    receipt = OrdinaryExecutionAuthorizationReceipt(
        query_id=prepared.query_id,
        version_id=prepared.version_id,
        ledger_commitment_token=prepared.ledger_commitment_token,
        query_preparation_sha256=preparation_sha256,
        execution_binding_digest=prepared.execution_binding_digest,
        authorization_transition_sha256=hashlib.sha256(
            _canonical_bytes(transition)
        ).hexdigest(),
    )
    capability = object.__new__(OrdinaryExecutionCapability)
    object.__setattr__(
        capability,
        "_binding",
        _OrdinaryExecutionAuthorizationBinding(receipt=receipt),
    )
    object.__setattr__(capability, "_claimed", False)
    object.__setattr__(capability, "_lock", threading.Lock())
    return capability


def claim_ordinary_execution(
    capability: OrdinaryExecutionCapability,
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> OrdinaryExecutionAuthorizationReceipt:
    """Consume a lifecycle-minted capability at one exact execution boundary."""

    if type(capability) is not OrdinaryExecutionCapability:
        raise TypeError("capability must be an exact lifecycle-minted authorization")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise OrdinaryQueryLifecycleError("ordinary execution capability is not authoritative")
    with lock:
        if getattr(capability, "_claimed", None) is not False:
            raise OrdinaryQueryLifecycleError("ordinary execution capability is absent or consumed")
        object.__setattr__(capability, "_claimed", True)
        binding = getattr(capability, "_binding", None)
    if type(binding) is not _OrdinaryExecutionAuthorizationBinding:
        raise OrdinaryQueryLifecycleError("ordinary execution capability is not authoritative")
    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    receipt = binding.receipt
    expected_preparation_sha256 = hashlib.sha256(
        canonical_ordinary_query_preparation_bytes(bundle, prepared)
    ).hexdigest()
    if (
        receipt.query_id != prepared.query_id
        or receipt.version_id != prepared.version_id
        or receipt.ledger_commitment_token != prepared.ledger_commitment_token
        or receipt.query_preparation_sha256 != expected_preparation_sha256
        or receipt.execution_binding_digest != prepared.execution_binding_digest
    ):
        raise OrdinaryQueryLifecycleError(
            "ordinary execution capability differs from its prepared query"
        )
    return receipt


def execute_ordinary_plaintext(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> tuple[int, ...]:
    """Consume the committed batch once and execute the exact typed query oracle."""

    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    if not _is_strict_int(modulus) or modulus != prepared.modulus:
        raise OrdinaryQueryLifecycleError(
            "execution modulus must match the prepared ordinary query"
        )
    authorization = authorize_ordinary_execution(bundle, prepared, ledger=ledger)
    claim_ordinary_execution(authorization, bundle, prepared)
    compiled = bundle.compiled
    ciphertext_inputs = {
        spec.value_ciphertext_id: spec.values for spec in compiled.operand_specs
    }
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.query_operands}
    )
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.f1m_operands}
    )
    try:
        returned = execute_compiled_query(
            compiled,
            expected_f1m_policy="overlap-only",
            ciphertext_inputs=ciphertext_inputs,
            plaintext_masks={
                mask.mask_id: mask.values for mask in compiled.cloud_plan.program.plaintext_masks
            },
            modulus=modulus,
        )
        returned_shares = {
            (route.component_id, route.output_block_id): returned[route.result_id]
            for route in compiled.result_routes
        }
        return reconstruct_output(
            compiled.output_plan,
            returned_shares,
            modulus=modulus,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise OrdinaryQueryLifecycleError("ordinary typed execution failed") from error


def replay_ordinary_plaintext_read_only(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> tuple[int, ...]:
    """Verify one consumed batch read-only, then replay its exact typed oracle."""

    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    if not _is_strict_int(modulus) or modulus != prepared.modulus:
        raise OrdinaryQueryLifecycleError(
            "replay modulus must match the prepared ordinary query"
        )
    try:
        ledger.verify_consumed_prepared_f1m(
            _prepared_f1m_commitments(prepared.f1m_operands),
            commitment_token=prepared.ledger_commitment_token,
            query_id=prepared.query_id,
            version_id=prepared.version_id,
            output_plan_digest=prepared.output_plan_digest,
            private_plan_digest=prepared.private_plan_digest,
            execution_binding_digest=prepared.execution_binding_digest,
            modulus=prepared.modulus,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise OrdinaryQueryLifecycleError(
            "ordinary read-only replay ledger verification failed"
        ) from error
    compiled = bundle.compiled
    ciphertext_inputs = {
        spec.value_ciphertext_id: spec.values for spec in compiled.operand_specs
    }
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.query_operands}
    )
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.f1m_operands}
    )
    try:
        returned = execute_compiled_query(
            compiled,
            expected_f1m_policy="overlap-only",
            ciphertext_inputs=ciphertext_inputs,
            plaintext_masks={
                mask.mask_id: mask.values
                for mask in compiled.cloud_plan.program.plaintext_masks
            },
            modulus=modulus,
        )
        returned_shares = {
            (route.component_id, route.output_block_id): returned[route.result_id]
            for route in compiled.result_routes
        }
        return reconstruct_output(
            compiled.output_plan,
            returned_shares,
            modulus=modulus,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise OrdinaryQueryLifecycleError(
            "ordinary read-only typed replay failed"
        ) from error


__all__ = (
    "ORDINARY_EXECUTION_AUTHORIZATION_SCHEMA",
    "ORDINARY_PRIVATE_PLAN_SCHEMA",
    "ORDINARY_QUERY_PREPARATION_SCHEMA",
    "OrdinaryExecutionAuthorizationReceipt",
    "OrdinaryExecutionBundle",
    "OrdinaryExecutionCapability",
    "OrdinaryQueryLifecycleError",
    "PreparedOrdinaryF1MOperand",
    "PreparedOrdinaryQuery",
    "PreparedOrdinaryQueryOperand",
    "authorize_ordinary_execution",
    "bind_ordinary_execution",
    "canonical_ordinary_private_plan_bytes",
    "canonical_ordinary_private_plan_payload",
    "canonical_ordinary_query_preparation_bytes",
    "canonical_ordinary_query_preparation_payload",
    "claim_ordinary_execution",
    "decode_ordinary_query_preparation_bytes",
    "execute_ordinary_plaintext",
    "prepare_ordinary_query",
    "replay_ordinary_plaintext_read_only",
)
