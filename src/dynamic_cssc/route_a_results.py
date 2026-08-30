"""Closed Route A strategy-cell documents and the sole rho=10 transform."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)
from dynamic_cssc.route_a_serialized_bytes import (
    ROUTE_A_CANONICAL_METADATA_MAX_BYTES,
    ROUTE_A_CIPHERTEXT_MAX_BYTES,
    ROUTE_A_EVALUATION_KEY_MAX_BYTES,
    ROUTE_A_SERIALIZED_CATEGORIES,
)

__all__ = (
    "ROUTE_A_CELL_SCHEMA",
    "ROUTE_A_MACHINE_PLAN_SHA256",
    "RouteACanonicalStrategyCell",
    "RouteAResultContractError",
    "RouteARho10Projection",
    "canonical_route_a_document",
    "project_route_a_rho10",
    "validate_route_a_strategy_cell",
)

ROUTE_A_CELL_SCHEMA = "dynamic-cssc-route-a-strategy-cell-v2"
ROUTE_A_MACHINE_PLAN_SHA256 = "ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c"
_RHO10_TRANSFORM_ID = "rho1-to-rho10-exact-query-linearity-v1"
_RHO10_ENVELOPE_SCHEMA = "dynamic-cssc-route-a-rho10-integrity-envelope-v1"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL_SECONDS = re.compile(r"(?:0|[1-9][0-9]*)\.[0-9]{9}\Z")
_RHOS = {"1/100", "1/10", "1", "10"}
_DIRECT_RHOS = _RHOS - {"10"}
_STRATEGIES = {
    "periodic-repack/windows=1",
    "padding-reuse",
    "packed-coo-cloud-segmented-delta/segment-width=128",
}
_TOP_LEVEL_FIELDS = (
    "schema_version",
    "identity",
    "evaluation",
    "counts",
    "window_query_counts",
    "primitive_counts",
    "rotation_inventory",
    "serialized_object_multiplicities",
    "serialized_bytes",
    "measurements",
    "correctness",
    "bindings",
)
_IDENTITY_FIELDS = (
    "formal_seed_or_null",
    "object_sha256_or_null",
    "partition_or_null",
    "rho",
    "scale_or_null",
    "semantics_or_null",
    "shard_identity_sha256",
    "source_kind",
    "strategy_candidate_id",
    "suite_role",
    "unit_attempt_ordinal",
)
_EVALUATION_FIELDS = ("mode", "source_rho", "target_rho")
_COUNT_FIELDS = ("queries", "updates", "windows")
_PRIMITIVE_FIELDS = (
    "update_encryptions",
    "update_ciphertexts",
    "compaction_ciphertexts",
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
    "ci_patch_entries",
    "ci_full_sync_entries",
    "metadata_units",
    "overflow_updates",
    "absorbed_updates",
)
_ROTATION_FIELDS = ("measured_counts_by_exact_index", "required_indices")
_MEASUREMENT_FIELDS = (
    "native_latency_seconds",
    "peak_rss_kib",
    "producer_result_assembly_seconds",
    "producer_state_transition_seconds",
    "replay_seconds",
    "scratch_allocated_bytes",
)
_CORRECTNESS_FIELDS = (
    "binding_acceptance",
    "claim_authority",
    "execution_performed",
    "oracle_equality",
    "source_rho",
)
_BINDING_FIELDS = (
    "ledger_root",
    "machine_plan_sha256",
    "prepared_query_root",
    "query_id_root",
    "source_rho1_document_sha256",
    "transform_id",
)
_QUERY_LINEAR_PRIMITIVES = (
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
)
_QUERY_SERIALIZED_CATEGORIES = (
    "query-query-ciphertexts",
    "query-result-ciphertexts",
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
)
_QUERY_MULTIPLICITY_CATEGORIES = (*_QUERY_SERIALIZED_CATEGORIES, "query-version-plan-metadata")


class RouteAResultContractError(ValueError):
    """A Route A result is open, ambiguous, or outside the frozen matrix."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise RouteAResultContractError("Route A document contains a duplicate key")
        document[key] = value
    return document


def _contains_float(value: object) -> bool:
    if type(value) is float:
        return True
    if type(value) is list:
        return any(_contains_float(item) for item in value)
    if type(value) is dict:
        return any(_contains_float(item) for item in value.values())
    return False


def canonical_route_a_document(value: object) -> bytes:
    """Encode one integer/string/null-only closed document deterministically."""

    if _contains_float(value):
        raise RouteAResultContractError("Route A canonical documents forbid JSON floats")
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise RouteAResultContractError("Route A document is not canonical ASCII JSON") from error


def _closed_object(value: object, fields: tuple[str, ...], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(fields):
        raise RouteAResultContractError(f"{label} keys must match the closed {label} schema")
    return value


def _strict_nonnegative(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise RouteAResultContractError(f"{field} must be a nonnegative strict integer")
    return value


def _sha_or_none(value: object, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise RouteAResultContractError(f"{field} must be null or lowercase SHA-256")
    return value


def _seconds_or_none(value: object, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _DECIMAL_SECONDS.fullmatch(value) is None:
        raise RouteAResultContractError(
            f"{field} must be null or one nonnegative nine-place decimal string"
        )
    return value


def _validate_identity(
    identity: dict[str, object],
    scientific_profile: RouteAScientificProfile,
) -> None:
    source_kind = identity["source_kind"]
    suite_role = identity["suite_role"]
    scale = identity["scale_or_null"]
    seed = identity["formal_seed_or_null"]
    object_sha = identity["object_sha256_or_null"]
    partition = identity["partition_or_null"]
    semantics = identity["semantics_or_null"]
    synthetic_qualification = (
        source_kind == "synthetic"
        and suite_role == "qualification"
        and scale == "M"
        and type(seed) is int
        and seed == scientific_profile.qualification_seed
        and object_sha is None
        and partition is None
        and semantics is None
    )
    synthetic_formal = (
        source_kind == "synthetic"
        and suite_role == "formal"
        and scale in {"S", "M"}
        and type(seed) is int
        and seed in scientific_profile.formal_seeds
        and object_sha is None
        and partition is None
        and semantics is None
    )
    snap = (
        source_kind == "snap-a2q"
        and suite_role == "formal"
        and scale is None
        and seed is None
        and type(object_sha) is str
        and _LOWER_SHA256.fullmatch(object_sha) is not None
        and type(partition) is int
        and partition in {0, 1}
        and semantics in {"T1", "T2"}
    )
    if not (synthetic_qualification or synthetic_formal or snap):
        raise RouteAResultContractError("identity source domain is not frozen")
    if (
        type(identity["rho"]) is not str
        or identity["rho"] not in _RHOS
        or type(identity["shard_identity_sha256"]) is not str
        or _LOWER_SHA256.fullmatch(identity["shard_identity_sha256"]) is None
        or type(identity["strategy_candidate_id"]) is not str
        or identity["strategy_candidate_id"] not in _STRATEGIES
        or type(identity["unit_attempt_ordinal"]) is not int
        or identity["unit_attempt_ordinal"] not in {0, 1}
    ):
        raise RouteAResultContractError("identity execution lane is not frozen")


def _validate_counts(document: dict[str, object]) -> None:
    counts = _closed_object(document["counts"], _COUNT_FIELDS, "counts")
    for field in _COUNT_FIELDS:
        _strict_nonnegative(counts[field], f"counts.{field}")
    window_counts = document["window_query_counts"]
    if (
        type(window_counts) is not list
        or len(window_counts) != counts["windows"]
        or any(type(value) is not int or value < 0 for value in window_counts)
        or sum(window_counts) != counts["queries"]
    ):
        raise RouteAResultContractError("window_query_counts do not close counts.queries")


def _validate_primitive_counts(document: dict[str, object]) -> None:
    counts = _closed_object(document["primitive_counts"], _PRIMITIVE_FIELDS, "primitive_counts")
    for field in _PRIMITIVE_FIELDS:
        _strict_nonnegative(counts[field], f"primitive_counts.{field}")
    if counts["metadata_units"] != counts["ci_patch_entries"] + counts["ci_full_sync_entries"]:
        raise RouteAResultContractError("primitive metadata accounting is not closed")
    if counts["cc_multiplications"] != counts["relinearizations"]:
        raise RouteAResultContractError("primitive multiplication/relinearization is not closed")
    if counts["result_ciphertexts"] != counts["decryptions"]:
        raise RouteAResultContractError("primitive result/decryption accounting is not closed")
    if (
        counts["blinding_encryptions"]
        != (counts["blinding_mask_ciphertexts"] + counts["blinding_dummy_ciphertexts"])
        or counts["blinding_additions"] != counts["blinding_encryptions"]
    ):
        raise RouteAResultContractError("primitive F1-M accounting is not closed")


def _validate_rotations(document: dict[str, object]) -> None:
    rotation = _closed_object(
        document["rotation_inventory"], _ROTATION_FIELDS, "rotation_inventory"
    )
    measured = rotation["measured_counts_by_exact_index"]
    required = rotation["required_indices"]
    if type(measured) is not list or type(required) is not list:
        raise RouteAResultContractError("rotation inventory must use ordered arrays")
    previous: int | None = None
    measured_indices: list[int] = []
    for pair in measured:
        if (
            type(pair) is not list
            or len(pair) != 2
            or type(pair[0]) is not int
            or pair[0] == 0
            or type(pair[1]) is not int
            or pair[1] <= 0
            or (previous is not None and pair[0] <= previous)
        ):
            raise RouteAResultContractError("measured rotation inventory is not canonical")
        previous = pair[0]
        measured_indices.append(pair[0])
    if (
        any(type(index) is not int or index == 0 for index in required)
        or required != sorted(set(required))
        or not set(measured_indices).issubset(required)
    ):
        raise RouteAResultContractError("required rotation inventory is not canonical")


def _validate_serialized(document: dict[str, object]) -> None:
    multiplicities = _closed_object(
        document["serialized_object_multiplicities"],
        ROUTE_A_SERIALIZED_CATEGORIES,
        "serialized_object_multiplicities",
    )
    serialized = _closed_object(
        document["serialized_bytes"], ROUTE_A_SERIALIZED_CATEGORIES, "serialized_bytes"
    )
    for category in ROUTE_A_SERIALIZED_CATEGORIES:
        count = _strict_nonnegative(
            multiplicities[category], f"serialized_object_multiplicities.{category}"
        )
        byte_count = _strict_nonnegative(serialized[category], f"serialized_bytes.{category}")
        if category in {
            "update-publication-ciphertexts",
            "query-query-ciphertexts",
            "query-result-ciphertexts",
            "query-f1m-random-mask-ciphertexts",
            "query-f1m-encrypted-zero-dummy-ciphertexts",
        }:
            expected = count * ROUTE_A_CIPHERTEXT_MAX_BYTES
            if byte_count != expected:
                raise RouteAResultContractError(
                    f"serialized_bytes.{category} differs from the frozen projection"
                )
        elif category == "one-time-evaluation-key-material":
            if byte_count != count * ROUTE_A_EVALUATION_KEY_MAX_BYTES:
                raise RouteAResultContractError(
                    "serialized_bytes.one-time-evaluation-key-material differs from "
                    "the frozen projection"
                )
        elif byte_count > count * ROUTE_A_CANONICAL_METADATA_MAX_BYTES:
            raise RouteAResultContractError(
                f"serialized_bytes.{category} exceeds the canonical metadata type bound"
            )


def _validate_measurements(document: dict[str, object]) -> None:
    measurements = _closed_object(document["measurements"], _MEASUREMENT_FIELDS, "measurements")
    for field in (
        "native_latency_seconds",
        "producer_result_assembly_seconds",
        "producer_state_transition_seconds",
        "replay_seconds",
    ):
        _seconds_or_none(measurements[field], f"measurements.{field}")
    for field in ("peak_rss_kib", "scratch_allocated_bytes"):
        value = measurements[field]
        if value is not None:
            _strict_nonnegative(value, f"measurements.{field}")


def _validate_semantics(
    document: dict[str, object],
    scientific_profile: RouteAScientificProfile,
) -> None:
    identity = document["identity"]
    evaluation = _closed_object(document["evaluation"], _EVALUATION_FIELDS, "evaluation")
    correctness = _closed_object(document["correctness"], _CORRECTNESS_FIELDS, "correctness")
    bindings = _closed_object(document["bindings"], _BINDING_FIELDS, "bindings")
    if bindings["machine_plan_sha256"] != scientific_profile.machine_plan_sha256:
        raise RouteAResultContractError("bindings.machine_plan_sha256 is not frozen")
    for field in (
        "ledger_root",
        "prepared_query_root",
        "query_id_root",
        "source_rho1_document_sha256",
    ):
        _sha_or_none(bindings[field], f"bindings.{field}")
    rho = identity["rho"]
    if evaluation["target_rho"] != rho:
        raise RouteAResultContractError("evaluation.target_rho differs from identity.rho")
    direct = (
        rho in _DIRECT_RHOS
        and evaluation
        == {
            "mode": "directly-measured",
            "source_rho": None,
            "target_rho": rho,
        }
        and correctness
        == {
            "binding_acceptance": True,
            "claim_authority": False,
            "execution_performed": True,
            "oracle_equality": True,
            "source_rho": None,
        }
        and bindings["source_rho1_document_sha256"] is None
        and bindings["transform_id"] is None
        and all(
            bindings[field] is not None
            for field in ("query_id_root", "prepared_query_root", "ledger_root")
        )
    )
    projected = (
        rho == "10"
        and evaluation
        == {
            "mode": "exact-query-linear-projection",
            "source_rho": "1",
            "target_rho": "10",
        }
        and correctness
        == {
            "binding_acceptance": None,
            "claim_authority": False,
            "execution_performed": False,
            "oracle_equality": None,
            "source_rho": "1",
        }
        and type(bindings["source_rho1_document_sha256"]) is str
        and bindings["transform_id"] == _RHO10_TRANSFORM_ID
        and all(
            bindings[field] is None
            for field in ("query_id_root", "prepared_query_root", "ledger_root")
        )
        and all(value is None for value in document["measurements"].values())
    )
    if not (direct or projected):
        raise RouteAResultContractError("cell correctness/evaluation authority boundary is invalid")


@dataclass(frozen=True, slots=True)
class RouteACanonicalStrategyCell:
    """An immutable byte projection; callers receive only detached documents."""

    document_bytes: bytes
    sha256: str

    @property
    def document(self) -> dict[str, object]:
        decoded = json.loads(
            self.document_bytes.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs
        )
        if type(decoded) is not dict:  # pragma: no cover - constructor owns bytes
            raise RuntimeError("validated Route A cell changed type")
        return decoded


@dataclass(frozen=True, slots=True)
class RouteARho10Projection:
    source_sha256: str
    target: RouteACanonicalStrategyCell
    integrity_envelope: dict[str, object]
    integrity_envelope_bytes: bytes
    integrity_envelope_sha256: str


def validate_route_a_strategy_cell(
    document: object,
    *,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteACanonicalStrategyCell:
    """Validate the closed strategy-cell schema and cross-field invariants."""

    if type(scientific_profile) is not RouteAScientificProfile:
        raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
    cell = _closed_object(document, _TOP_LEVEL_FIELDS, "top-level")
    if cell["schema_version"] != ROUTE_A_CELL_SCHEMA:
        raise RouteAResultContractError("strategy-cell schema version is not frozen")
    identity = _closed_object(cell["identity"], _IDENTITY_FIELDS, "identity")
    _validate_identity(identity, scientific_profile)
    _validate_counts(cell)
    _validate_primitive_counts(cell)
    _validate_rotations(cell)
    _validate_serialized(cell)
    _validate_measurements(cell)
    _validate_semantics(cell, scientific_profile)
    content = canonical_route_a_document(cell)
    detached = json.loads(content.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs)
    detached_content = canonical_route_a_document(detached)
    return RouteACanonicalStrategyCell(
        document_bytes=detached_content,
        sha256=hashlib.sha256(detached_content).hexdigest(),
    )


def _multiply(document: dict[str, Any], section: str, fields: tuple[str, ...]) -> None:
    values = document[section]
    for field in fields:
        values[field] *= 10


def project_route_a_rho10(
    source: RouteACanonicalStrategyCell,
    *,
    machine_plan_bytes: bytes,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> RouteARho10Projection:
    """Apply only the preregistered non-executing rho=1 to rho=10 transform."""

    if type(source) is not RouteACanonicalStrategyCell:
        raise TypeError("source must be an exact validated Route A strategy cell")
    try:
        scientific_profile.require_machine_plan_bytes(machine_plan_bytes)
    except (TypeError, ValueError) as error:
        raise RouteAResultContractError(
            "machine plan bytes do not match the Stage-1 freeze"
        ) from error
    try:
        plan = json.loads(
            machine_plan_bytes.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteAResultContractError("machine plan is not canonical JSON") from error
    if type(plan) is not dict or plan.get("schema_version") != (
        "dynamic-cssc-route-a-publication-plan-v3"
    ):
        raise RouteAResultContractError("machine plan schema is not the Stage-1 contract")

    document: dict[str, Any] = source.document
    if document["identity"]["rho"] != "1" or document["evaluation"]["mode"] != "directly-measured":
        raise RouteAResultContractError("rho=10 projection requires one direct rho=1 source")

    document["identity"]["rho"] = "10"
    document["evaluation"] = {
        "mode": "exact-query-linear-projection",
        "source_rho": "1",
        "target_rho": "10",
    }
    document["counts"]["queries"] *= 10
    document["window_query_counts"] = [value * 10 for value in document["window_query_counts"]]
    _multiply(document, "primitive_counts", _QUERY_LINEAR_PRIMITIVES)
    document["rotation_inventory"]["measured_counts_by_exact_index"] = [
        [index, count * 10]
        for index, count in document["rotation_inventory"]["measured_counts_by_exact_index"]
    ]
    _multiply(document, "serialized_object_multiplicities", _QUERY_MULTIPLICITY_CATEGORIES)
    _multiply(document, "serialized_bytes", _QUERY_SERIALIZED_CATEGORIES)
    metadata_count = document["serialized_object_multiplicities"]["query-version-plan-metadata"]
    document["serialized_bytes"]["query-version-plan-metadata"] = (
        metadata_count * ROUTE_A_CANONICAL_METADATA_MAX_BYTES
    )
    document["measurements"] = {field: None for field in _MEASUREMENT_FIELDS}
    document["correctness"] = {
        "binding_acceptance": None,
        "claim_authority": False,
        "execution_performed": False,
        "oracle_equality": None,
        "source_rho": "1",
    }
    document["bindings"] = {
        "ledger_root": None,
        "machine_plan_sha256": scientific_profile.machine_plan_sha256,
        "prepared_query_root": None,
        "query_id_root": None,
        "source_rho1_document_sha256": source.sha256,
        "transform_id": _RHO10_TRANSFORM_ID,
    }
    target = validate_route_a_strategy_cell(document, scientific_profile=scientific_profile)
    envelope = {
        "machine_plan_sha256": scientific_profile.machine_plan_sha256,
        "schema_version": _RHO10_ENVELOPE_SCHEMA,
        "source_rho1_document_sha256": source.sha256,
        "transform_id": _RHO10_TRANSFORM_ID,
        "transformed_rho10_document_sha256": target.sha256,
    }
    envelope_bytes = canonical_route_a_document(envelope)
    return RouteARho10Projection(
        source_sha256=source.sha256,
        target=target,
        integrity_envelope=envelope,
        integrity_envelope_bytes=envelope_bytes,
        integrity_envelope_sha256=hashlib.sha256(envelope_bytes).hexdigest(),
    )
