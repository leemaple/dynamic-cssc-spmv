from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.cloud_execution_plan import (
    CloudExecutionPlan,
    CloudPlanCounts,
)
from dynamic_cssc.cssc import PublishedComponent
from dynamic_cssc.mask_ledger import (
    PreparedF1MCommitment,
    PreparedF1MCommitmentLedger,
)
from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputPlanAnalysis,
    PreparedMask,
    prepare_f1m_masks,
)
from dynamic_cssc.plaintext_oracle import execute_cloud_plan, reconstruct_output
from dynamic_cssc.strong_packed_coo import (
    SegmentedDeltaState,
)

OperandSourceKind = Literal["base-chunk", "delta-page"]
F1MOperandKind = Literal["random-zero-sum", "encrypted-zero-dummy"]
STRONG_QUERY_PREPARATION_SCHEMA = (
    "dynamic-cssc-common-strong-query-preparation-v1"
)
STRONG_EXECUTION_AUTHORIZATION_SCHEMA = (
    "dynamic-cssc-common-strong-execution-authorization-v1"
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class StrongExecutionError(ValueError):
    """Raised when a whole-query strong execution bundle is inconsistent."""


@dataclass(frozen=True, slots=True)
class PrivateOperandSpec:
    value_ciphertext_id: str
    query_ciphertext_id: str
    source_kind: OperandSourceKind
    source_ordinal: int
    result_id: str
    values: tuple[int, ...]
    global_column_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PrivateResultRoute:
    result_id: str
    f1m_ciphertext_id: str
    component_id: str
    output_block_id: str

    @property
    def output_share_id(self) -> tuple[str, str]:
        return self.component_id, self.output_block_id


@dataclass(frozen=True, slots=True)
class F1MOperandCounts:
    random_zero_sum_ciphertexts: int
    encrypted_zero_dummy_ciphertexts: int
    random_elements: int
    ciphertext_additions: int


@dataclass(frozen=True, slots=True)
class StrongExecutionBundle:
    base: PublishedComponent
    delta: SegmentedDeltaState
    cloud_plan: CloudExecutionPlan
    output_plan: OutputPlan
    result_routes: tuple[PrivateResultRoute, ...]
    value_operand_specs: tuple[PrivateOperandSpec, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    cloud_counts: CloudPlanCounts
    output_analysis: OutputPlanAnalysis
    f1m_counts: F1MOperandCounts


@dataclass(frozen=True, slots=True)
class PreparedQueryOperand:
    ciphertext_id: str
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PreparedF1MOperand:
    ciphertext_id: str
    result_id: str
    kind: F1MOperandKind
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
class PreparedStrongQuery:
    query_id: str
    version_id: str
    modulus: int
    vector: tuple[int, ...]
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    ledger_commitment_token: str
    query_operands: tuple[PreparedQueryOperand, ...]
    f1m_operands: tuple[PreparedF1MOperand, ...]


@dataclass(frozen=True, slots=True)
class StrongExecutionAuthorizationReceipt:
    """Non-secret receipt for one consumed strong prepared-query batch."""

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
            "schema_version": STRONG_EXECUTION_AUTHORIZATION_SCHEMA,
            "version_id": self.version_id,
        }


class StrongExecutionCapability:
    """Opaque single-use authorization minted after strong ledger consumption."""

    __slots__ = ("_binding", "_claimed", "_lock")

    def __new__(cls) -> StrongExecutionCapability:
        raise TypeError("strong execution capabilities are lifecycle-minted")

    def __bool__(self) -> bool:
        raise TypeError("strong execution capability is not a caller boolean")


@dataclass(frozen=True, slots=True)
class _StrongExecutionAuthorizationBinding:
    receipt: StrongExecutionAuthorizationReceipt


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
        raise StrongExecutionError("strong query value is not canonical JSON") from error


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StrongExecutionError(
                "strong query preparation contains a duplicate JSON key"
            )
        result[key] = value
    return result


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_private_plan_payload(
    specs: tuple[PrivateOperandSpec, ...],
    routes: tuple[PrivateResultRoute, ...],
    output_plan_digest: str,
) -> dict[str, object]:
    return {
        "format": "dynamic-cssc-private-strong-plan-v1",
        "output_plan_digest": output_plan_digest,
        "operands": [
            {
                "global_column_indices": list(spec.global_column_indices),
                "query_ciphertext_id": spec.query_ciphertext_id,
                "result_id": spec.result_id,
                "source_kind": spec.source_kind,
                "source_ordinal": spec.source_ordinal,
                "value_ciphertext_id": spec.value_ciphertext_id,
                "values": list(spec.values),
            }
            for spec in specs
        ],
        "routes": [
            {
                "component_id": route.component_id,
                "f1m_ciphertext_id": route.f1m_ciphertext_id,
                "output_block_id": route.output_block_id,
                "result_id": route.result_id,
            }
            for route in routes
        ],
    }


def canonical_private_plan_payload(bundle: StrongExecutionBundle) -> dict[str, object]:
    """Serialize private whole-query operands and routes for audit evidence.

    This payload contains global ColumnIndex data and is not Cloud-visible.
    """

    _validate_bundle(bundle)
    return _canonical_private_plan_payload(
        bundle.value_operand_specs,
        bundle.result_routes,
        bundle.output_plan_digest,
    )


def _private_plan_digest(
    specs: tuple[PrivateOperandSpec, ...],
    routes: tuple[PrivateResultRoute, ...],
    output_plan_digest: str,
) -> str:
    payload = _canonical_private_plan_payload(specs, routes, output_plan_digest)
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _compile(base: PublishedComponent, delta: SegmentedDeltaState) -> StrongExecutionBundle:
    from dynamic_cssc.query_compiler import QueryCompilerError, compile_query

    try:
        compiled = compile_query(
            (base,),
            segmented_delta=delta,
            f1m_policy="uniform-random-or-zero",
        )
    except QueryCompilerError as error:
        message = str(error)
        if message == "PublishedComponent is invalid":
            message = "base PublishedComponent is invalid"
        elif message == "active source coordinates must not overlap":
            message = "active base and delta coordinates must be disjoint"
        raise StrongExecutionError(message) from error

    source_kind_by_common = {
        "published-chunk": "base-chunk",
        "segmented-delta-page": "delta-page",
    }
    specs = tuple(
        PrivateOperandSpec(
            value_ciphertext_id=spec.value_ciphertext_id,
            query_ciphertext_id=spec.query_ciphertext_id,
            source_kind=source_kind_by_common[spec.source_kind],
            source_ordinal=spec.source_ordinal,
            result_id=spec.result_id,
            values=spec.values,
            global_column_indices=spec.global_column_indices,
        )
        for spec in compiled.operand_specs
    )
    routes = tuple(
        PrivateResultRoute(
            result_id=route.result_id,
            f1m_ciphertext_id=route.f1m_ciphertext_id,
            component_id=route.component_id,
            output_block_id=route.output_block_id,
        )
        for route in compiled.result_routes
        if route.f1m_ciphertext_id is not None
    )
    if len(routes) != len(compiled.result_routes):
        raise AssertionError("the strong adapter requires uniform F1M operands")
    random_ciphertexts = compiled.output_analysis.masked_result_ciphertexts
    return StrongExecutionBundle(
        base=base,
        delta=delta,
        cloud_plan=compiled.cloud_plan,
        output_plan=compiled.output_plan,
        result_routes=routes,
        value_operand_specs=specs,
        cloud_program_digest=compiled.cloud_program_digest,
        output_plan_digest=compiled.output_plan_digest,
        execution_binding_digest=compiled.execution_binding_digest,
        private_plan_digest=_private_plan_digest(specs, routes, compiled.output_plan_digest),
        cloud_counts=compiled.cloud_counts,
        output_analysis=compiled.output_analysis,
        f1m_counts=F1MOperandCounts(
            random_zero_sum_ciphertexts=random_ciphertexts,
            encrypted_zero_dummy_ciphertexts=len(routes) - random_ciphertexts,
            random_elements=compiled.output_analysis.mask_random_elements,
            ciphertext_additions=compiled.cloud_counts.add_f1m_masks,
        ),
    )


def compile_strong_execution(
    base: PublishedComponent,
    delta: SegmentedDeltaState,
) -> StrongExecutionBundle:
    """Compile the actual CSSC base and anonymous strong delta as one bound query plan."""

    return _compile(base, delta)


def _validate_bundle(bundle: StrongExecutionBundle) -> None:
    if not isinstance(bundle, StrongExecutionBundle):
        raise StrongExecutionError("bundle must be a StrongExecutionBundle")
    expected = _compile(bundle.base, bundle.delta)
    if bundle != expected:
        raise StrongExecutionError("bundle does not match its deterministically derived plans")


def _validated_vector(vector: object, *, length: int) -> tuple[int, ...]:
    if not isinstance(vector, tuple) or len(vector) != length:
        raise StrongExecutionError(f"vector must be a tuple of length {length}")
    if not all(_is_strict_int(value) for value in vector):
        raise StrongExecutionError("vector must contain strict integers")
    return vector


def prepare_strong_query(
    bundle: StrongExecutionBundle,
    *,
    query_id: str,
    vector: tuple[int, ...],
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> PreparedStrongQuery:
    """Prepare private global-CI query operands and one bound F1-M operand per result."""

    _validate_bundle(bundle)
    dense_vector = _validated_vector(vector, length=bundle.base.layout_spec.cols)
    if not _is_strict_int(modulus) or modulus < 2:
        raise StrongExecutionError("modulus must be a strict integer of at least two")
    random_masks = prepare_f1m_masks(
        bundle.output_plan,
        query_id=query_id,
        version_id=bundle.base.version_id,
        modulus=modulus,
        ledger=ledger,
    )
    random_by_share = {(mask.component_id, mask.output_block_id): mask for mask in random_masks}
    query_operands = tuple(
        PreparedQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                dense_vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in bundle.value_operand_specs
    )
    f1m_operands = []
    for route in bundle.result_routes:
        mask: PreparedMask | None = random_by_share.get(route.output_share_id)
        f1m_operands.append(
            PreparedF1MOperand(
                ciphertext_id=route.f1m_ciphertext_id,
                result_id=route.result_id,
                kind="random-zero-sum" if mask is not None else "encrypted-zero-dummy",
                query_id=query_id,
                version_id=bundle.base.version_id,
                output_plan_digest=bundle.output_plan_digest,
                component_id=route.component_id,
                output_block_id=route.output_block_id,
                values=mask.values if mask is not None else (0,) * bundle.output_plan.slot_count,
            )
        )
    prepared_f1m_operands = tuple(f1m_operands)
    ledger_commitment_token = ledger.commit_prepared_f1m(
        _prepared_f1m_commitments(prepared_f1m_operands),
        query_id=query_id,
        version_id=bundle.base.version_id,
        output_plan_digest=bundle.output_plan_digest,
        private_plan_digest=bundle.private_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        modulus=modulus,
    )
    return PreparedStrongQuery(
        query_id=query_id,
        version_id=bundle.base.version_id,
        modulus=modulus,
        vector=dense_vector,
        cloud_program_digest=bundle.cloud_program_digest,
        output_plan_digest=bundle.output_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        private_plan_digest=bundle.private_plan_digest,
        ledger_commitment_token=ledger_commitment_token,
        query_operands=query_operands,
        f1m_operands=prepared_f1m_operands,
    )


def _prepared_f1m_commitments(
    operands: tuple[PreparedF1MOperand, ...],
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


def _validate_prepared(bundle: StrongExecutionBundle, prepared: PreparedStrongQuery) -> None:
    if not isinstance(prepared, PreparedStrongQuery):
        raise StrongExecutionError("prepared must be a PreparedStrongQuery")
    if (
        prepared.version_id != bundle.base.version_id
        or prepared.cloud_program_digest != bundle.cloud_program_digest
        or prepared.output_plan_digest != bundle.output_plan_digest
        or prepared.execution_binding_digest != bundle.execution_binding_digest
        or prepared.private_plan_digest != bundle.private_plan_digest
        or type(prepared.query_id) is not str
        or not prepared.query_id
        or type(prepared.version_id) is not str
        or not prepared.version_id
        or type(prepared.ledger_commitment_token) is not str
        or _LOWER_SHA256.fullmatch(prepared.ledger_commitment_token) is None
        or not _is_strict_int(prepared.modulus)
        or prepared.modulus < 2
    ):
        raise StrongExecutionError("prepared query does not match the execution bundle binding")
    vector = _validated_vector(prepared.vector, length=bundle.base.layout_spec.cols)
    expected_queries = tuple(
        PreparedQueryOperand(
            spec.query_ciphertext_id,
            tuple(
                vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in bundle.value_operand_specs
    )
    if prepared.query_operands != expected_queries:
        raise StrongExecutionError("prepared query operands do not match private global CI")

    multiplicity: Counter[int] = Counter(
        logical for share in bundle.output_plan.shares for _, logical in share.slot_to_logical
    )
    overlap = {logical for logical, count in multiplicity.items() if count > 1}
    share_by_id = {
        (share.component_id, share.output_block_id): share for share in bundle.output_plan.shares
    }
    if len(prepared.f1m_operands) != len(bundle.result_routes):
        raise StrongExecutionError("prepared query must contain one F1-M operand per result")
    values_by_share: dict[tuple[str, str], tuple[int, ...]] = {}
    for operand, route in zip(prepared.f1m_operands, bundle.result_routes, strict=True):
        expected_kind: F1MOperandKind = (
            "random-zero-sum"
            if any(
                logical in overlap
                for _, logical in share_by_id[route.output_share_id].slot_to_logical
            )
            else "encrypted-zero-dummy"
        )
        if (
            operand.ciphertext_id != route.f1m_ciphertext_id
            or operand.result_id != route.result_id
            or operand.kind != expected_kind
            or operand.query_id != prepared.query_id
            or operand.version_id != bundle.base.version_id
            or operand.output_plan_digest != bundle.output_plan_digest
            or (operand.component_id, operand.output_block_id) != route.output_share_id
            or len(operand.values) != bundle.output_plan.slot_count
            or any(
                not _is_strict_int(value) or not 0 <= value < prepared.modulus
                for value in operand.values
            )
        ):
            raise StrongExecutionError("prepared F1-M operand does not match its result binding")
        if operand.kind == "encrypted-zero-dummy" and any(operand.values):
            raise StrongExecutionError("encrypted-zero dummy F1-M operand must be exactly zero")
        share = share_by_id[route.output_share_id]
        mapped_overlap_lanes = {
            lane for lane, logical in share.slot_to_logical if logical in overlap
        }
        if any(
            value and lane not in mapped_overlap_lanes for lane, value in enumerate(operand.values)
        ):
            raise StrongExecutionError("random F1-M values may occupy only overlapping lanes")
        values_by_share[route.output_share_id] = operand.values
    for logical in overlap:
        total = 0
        for share in bundle.output_plan.shares:
            for lane, coordinate in share.slot_to_logical:
                if coordinate == logical:
                    total += values_by_share[(share.component_id, share.output_block_id)][lane]
        if total % prepared.modulus:
            raise StrongExecutionError("random F1-M values must sum to zero per coordinate")


def canonical_strong_query_preparation_payload(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
) -> dict[str, object]:
    """Serialize private strong execution input; never publish this payload."""

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
        "format": STRONG_QUERY_PREPARATION_SCHEMA,
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


def canonical_strong_query_preparation_bytes(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
) -> bytes:
    return _canonical_bytes(canonical_strong_query_preparation_payload(bundle, prepared))


def decode_strong_query_preparation_bytes(
    bundle: StrongExecutionBundle,
    content: bytes,
    *,
    expected_query_id: str,
    expected_vector: tuple[int, ...],
) -> PreparedStrongQuery:
    """Decode exact retained private bytes into one bundle-bound replay operand."""

    _validate_bundle(bundle)
    if type(content) is not bytes:
        raise TypeError("strong query preparation content must be exact bytes")
    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StrongExecutionError(
            "strong query preparation is not canonical ASCII JSON"
        ) from error
    if type(payload) is not dict or _canonical_bytes(payload) != content:
        raise StrongExecutionError(
            "strong query preparation is not one canonical object"
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
    } or payload.get("format") != STRONG_QUERY_PREPARATION_SCHEMA:
        raise StrongExecutionError(
            "strong query preparation does not match its closed schema"
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
        raise StrongExecutionError(
            "strong query preparation differs from its expected replay target"
        )

    def strict_values(value: object, *, label: str) -> tuple[int, ...]:
        if type(value) is not list or any(not _is_strict_int(item) for item in value):
            raise StrongExecutionError(
                f"strong query preparation {label} values are invalid"
            )
        return tuple(value)

    decoded_queries: list[PreparedQueryOperand] = []
    for operand in query_operands:
        if (
            type(operand) is not dict
            or set(operand) != {"ciphertext_id", "values"}
            or type(operand.get("ciphertext_id")) is not str
            or not operand["ciphertext_id"]
        ):
            raise StrongExecutionError(
                "strong query preparation query operand is invalid"
            )
        decoded_queries.append(
            PreparedQueryOperand(
                ciphertext_id=operand["ciphertext_id"],
                values=strict_values(operand.get("values"), label="query operand"),
            )
        )
    decoded_f1m: list[PreparedF1MOperand] = []
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
            or any(
                type(operand.get(field)) is not str or not operand[field]
                for field in (
                    "ciphertext_id",
                    "component_id",
                    "output_block_id",
                    "result_id",
                )
            )
            or operand.get("kind")
            not in ("random-zero-sum", "encrypted-zero-dummy")
        ):
            raise StrongExecutionError(
                "strong query preparation F1-M operand is invalid"
            )
        decoded_f1m.append(
            PreparedF1MOperand(
                ciphertext_id=operand["ciphertext_id"],
                result_id=operand["result_id"],
                kind=operand["kind"],
                query_id=expected_query_id,
                version_id=payload["version_id"],
                output_plan_digest=bindings["output_plan_digest"],
                component_id=operand["component_id"],
                output_block_id=operand["output_block_id"],
                values=strict_values(operand.get("values"), label="F1-M operand"),
            )
        )
    prepared = PreparedStrongQuery(
        query_id=expected_query_id,
        version_id=payload.get("version_id"),
        modulus=payload.get("modulus"),
        vector=_validated_vector(
            expected_vector,
            length=bundle.base.layout_spec.cols,
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
    if canonical_strong_query_preparation_bytes(bundle, prepared) != content:
        raise StrongExecutionError(
            "decoded strong query preparation does not round-trip exactly"
        )
    return prepared


def authorize_strong_execution(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    ledger: PreparedF1MCommitmentLedger,
) -> StrongExecutionCapability:
    """Consume one strong prepared batch and mint its launch authorization."""

    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    preparation_sha256 = hashlib.sha256(
        canonical_strong_query_preparation_bytes(bundle, prepared)
    ).hexdigest()
    try:
        ledger.verify_and_consume_prepared_f1m(
            _prepared_f1m_commitments(prepared.f1m_operands),
            commitment_token=prepared.ledger_commitment_token,
            query_id=prepared.query_id,
            version_id=prepared.version_id,
            output_plan_digest=prepared.output_plan_digest,
            private_plan_digest=bundle.private_plan_digest,
            execution_binding_digest=bundle.execution_binding_digest,
            modulus=prepared.modulus,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise StrongExecutionError(
            "strong F1-M commitment consumption failed"
        ) from error
    transition = {
        "execution_binding_digest": prepared.execution_binding_digest,
        "ledger_commitment_token": prepared.ledger_commitment_token,
        "query_id": prepared.query_id,
        "query_preparation_sha256": preparation_sha256,
        "schema_version": STRONG_EXECUTION_AUTHORIZATION_SCHEMA,
        "transition": "prepared-to-consumed",
        "version_id": prepared.version_id,
    }
    receipt = StrongExecutionAuthorizationReceipt(
        query_id=prepared.query_id,
        version_id=prepared.version_id,
        ledger_commitment_token=prepared.ledger_commitment_token,
        query_preparation_sha256=preparation_sha256,
        execution_binding_digest=prepared.execution_binding_digest,
        authorization_transition_sha256=hashlib.sha256(
            _canonical_bytes(transition)
        ).hexdigest(),
    )
    capability = object.__new__(StrongExecutionCapability)
    object.__setattr__(
        capability,
        "_binding",
        _StrongExecutionAuthorizationBinding(receipt=receipt),
    )
    object.__setattr__(capability, "_claimed", False)
    object.__setattr__(capability, "_lock", threading.Lock())
    return capability


def claim_strong_execution(
    capability: StrongExecutionCapability,
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
) -> StrongExecutionAuthorizationReceipt:
    """Consume a lifecycle-minted capability at one exact strong launch seam."""

    if type(capability) is not StrongExecutionCapability:
        raise TypeError("capability must be an exact strong lifecycle authorization")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise StrongExecutionError("strong execution capability is not authoritative")
    with lock:
        if getattr(capability, "_claimed", None) is not False:
            raise StrongExecutionError("strong execution capability is absent or consumed")
        object.__setattr__(capability, "_claimed", True)
        binding = getattr(capability, "_binding", None)
    if type(binding) is not _StrongExecutionAuthorizationBinding:
        raise StrongExecutionError("strong execution capability is not authoritative")
    _validate_bundle(bundle)
    _validate_prepared(bundle, prepared)
    receipt = binding.receipt
    expected_preparation_sha256 = hashlib.sha256(
        canonical_strong_query_preparation_bytes(bundle, prepared)
    ).hexdigest()
    if (
        receipt.query_id != prepared.query_id
        or receipt.version_id != prepared.version_id
        or receipt.ledger_commitment_token != prepared.ledger_commitment_token
        or receipt.query_preparation_sha256 != expected_preparation_sha256
        or receipt.execution_binding_digest != prepared.execution_binding_digest
    ):
        raise StrongExecutionError(
            "strong execution capability differs from its prepared query"
        )
    return receipt


def execute_strong_plaintext(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> tuple[int, ...]:
    """Execute the exact typed whole-query DAG, privately route shares, and reconstruct."""

    _validate_bundle(bundle)
    if not _is_strict_int(modulus) or modulus < 2 or modulus != prepared.modulus:
        raise StrongExecutionError("execution modulus must match the prepared query modulus")
    _validate_prepared(bundle, prepared)
    ledger.verify_and_consume_prepared_f1m(
        _prepared_f1m_commitments(prepared.f1m_operands),
        commitment_token=prepared.ledger_commitment_token,
        query_id=prepared.query_id,
        version_id=prepared.version_id,
        output_plan_digest=prepared.output_plan_digest,
        private_plan_digest=bundle.private_plan_digest,
        execution_binding_digest=bundle.execution_binding_digest,
        modulus=prepared.modulus,
    )
    ciphertext_inputs = {
        spec.value_ciphertext_id: spec.values for spec in bundle.value_operand_specs
    }
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.query_operands}
    )
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.f1m_operands}
    )
    returned = execute_cloud_plan(
        bundle.cloud_plan,
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks={
            mask.mask_id: mask.values for mask in bundle.cloud_plan.program.plaintext_masks
        },
        modulus=modulus,
    )
    returned_shares = {
        route.output_share_id: returned[route.result_id] for route in bundle.result_routes
    }
    return reconstruct_output(bundle.output_plan, returned_shares, modulus=modulus)


def replay_strong_plaintext_read_only(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    modulus: int,
    ledger: PreparedF1MCommitmentLedger,
) -> tuple[int, ...]:
    """Verify one consumed batch read-only, then replay its exact typed oracle."""

    _validate_bundle(bundle)
    if not _is_strict_int(modulus) or modulus < 2 or modulus != prepared.modulus:
        raise StrongExecutionError("replay modulus must match the prepared query modulus")
    _validate_prepared(bundle, prepared)
    try:
        ledger.verify_consumed_prepared_f1m(
            _prepared_f1m_commitments(prepared.f1m_operands),
            commitment_token=prepared.ledger_commitment_token,
            query_id=prepared.query_id,
            version_id=prepared.version_id,
            output_plan_digest=prepared.output_plan_digest,
            private_plan_digest=bundle.private_plan_digest,
            execution_binding_digest=bundle.execution_binding_digest,
            modulus=prepared.modulus,
        )
    except (TypeError, ValueError, RuntimeError) as error:
        raise StrongExecutionError(
            "strong read-only replay ledger verification failed"
        ) from error
    ciphertext_inputs = {
        spec.value_ciphertext_id: spec.values for spec in bundle.value_operand_specs
    }
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.query_operands}
    )
    ciphertext_inputs.update(
        {operand.ciphertext_id: operand.values for operand in prepared.f1m_operands}
    )
    returned = execute_cloud_plan(
        bundle.cloud_plan,
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks={
            mask.mask_id: mask.values for mask in bundle.cloud_plan.program.plaintext_masks
        },
        modulus=modulus,
    )
    returned_shares = {
        route.output_share_id: returned[route.result_id]
        for route in bundle.result_routes
    }
    return reconstruct_output(bundle.output_plan, returned_shares, modulus=modulus)
