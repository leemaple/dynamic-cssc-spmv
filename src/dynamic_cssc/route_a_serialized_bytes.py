"""Frozen serialized-byte accounting for Route A strategy cells.

Synthetic and SNAP cells never report OpenFHE bytes as if they had been
measured.  Metadata is counted from the exact canonical documents emitted by
the runner; cryptographic objects use the conservative, type-derived maximum
defined in this module.  Native Route A cases use their retained package
receipts instead and do not call this projection seam.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

__all__ = (
    "ROUTE_A_CANONICAL_METADATA_MAX_BYTES",
    "ROUTE_A_CIPHERTEXT_MAX_BYTES",
    "ROUTE_A_EVALUATION_KEY_MAX_BYTES",
    "ROUTE_A_SERIALIZED_CATEGORIES",
    "RouteASerializedByteError",
    "account_route_a_serialized_bytes",
    "route_a_serialized_byte_formula_document",
)


class RouteASerializedByteError(ValueError):
    """The serialized-object inventory is outside the frozen Route A type."""


ROUTE_A_SERIALIZED_CATEGORIES = (
    "update-column-index-synchronization",
    "update-publication-ciphertexts",
    "update-version-plan-metadata",
    "query-query-ciphertexts",
    "query-result-ciphertexts",
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
    "query-version-plan-metadata",
    "one-time-evaluation-key-material",
)

_METADATA_CATEGORIES = (
    "update-column-index-synchronization",
    "update-version-plan-metadata",
    "query-version-plan-metadata",
)
_CIPHERTEXT_CATEGORIES = (
    "update-publication-ciphertexts",
    "query-query-ciphertexts",
    "query-result-ciphertexts",
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
)

# The formula is intentionally conservative and independent of observed formal
# output.  It bounds a cereal-framed BFVRNS ciphertext by one fixed envelope
# plus four DCRT polynomial components, twelve RNS towers, 8,192 coefficients,
# and sixteen bytes per stored coefficient/tower position.  The factor sixteen
# covers an eight-byte native word and an equal type/length overhead allowance.
_RING_DIMENSION = 8_192
_MAX_RNS_TOWERS = 12
_MAX_CIPHERTEXT_COMPONENTS = 4
_COEFFICIENT_AND_OVERHEAD_BYTES = 16
_CIPHERTEXT_ENVELOPE_BYTES = 65_536
ROUTE_A_CIPHERTEXT_MAX_BYTES = _CIPHERTEXT_ENVELOPE_BYTES + (
    _MAX_CIPHERTEXT_COMPONENTS * _MAX_RNS_TOWERS * _RING_DIMENSION * _COEFFICIENT_AND_OVERHEAD_BYTES
)

# One evaluation-key object is separately bounded using the same closed DCRT
# type with a larger key-switch component allowance.  Multiplicity is exact and
# remains a one-time inventory; it is never folded into recurring strategy cost.
_MAX_EVALUATION_KEY_COMPONENTS = 32
_EVALUATION_KEY_ENVELOPE_BYTES = 262_144
ROUTE_A_EVALUATION_KEY_MAX_BYTES = _EVALUATION_KEY_ENVELOPE_BYTES + (
    _MAX_EVALUATION_KEY_COMPONENTS
    * _MAX_RNS_TOWERS
    * _RING_DIMENSION
    * _COEFFICIENT_AND_OVERHEAD_BYTES
)

# Metadata emitters must reject any single canonical document above this bound.
# Direct cells count the exact bytes below the cap.  The rho=10 non-executed
# transform uses the cap per projected metadata object.
ROUTE_A_CANONICAL_METADATA_MAX_BYTES = 262_144


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise RouteASerializedByteError("metadata JSON contains a duplicate key")
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


def _require_canonical_metadata(content: bytes, field: str) -> bytes:
    if (
        type(content) is not bytes
        or not content
        or len(content) > (ROUTE_A_CANONICAL_METADATA_MAX_BYTES)
    ):
        raise RouteASerializedByteError(f"{field} metadata bytes violate the closed bound")
    try:
        text = content.decode("ascii")
        decoded = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RouteASerializedByteError(f"{field} metadata is not canonical ASCII JSON") from error
    if type(decoded) is not dict or _contains_float(decoded):
        raise RouteASerializedByteError(f"{field} metadata is not a canonical JSON object")
    canonical = (
        json.dumps(
            decoded,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    if canonical != content:
        raise RouteASerializedByteError(f"{field} metadata bytes are not canonical")
    return content


def _closed_multiplicities(multiplicities: Mapping[str, int]) -> dict[str, int]:
    if type(multiplicities) is not dict or set(multiplicities) != set(
        ROUTE_A_SERIALIZED_CATEGORIES
    ):
        raise RouteASerializedByteError(
            "serialized-object categories must equal the frozen ordered category set"
        )
    result: dict[str, int] = {}
    for category in ROUTE_A_SERIALIZED_CATEGORIES:
        value = multiplicities[category]
        if type(value) is not int or value < 0:
            raise RouteASerializedByteError(
                f"serialized-object multiplicity for {category} is not a nonnegative integer"
            )
        result[category] = value
    return result


def route_a_serialized_byte_formula_document() -> dict[str, object]:
    """Return the exact integer-only formula frozen into the S1 Behavior Set."""

    return {
        "schema_version": "dynamic-cssc-route-a-serialized-byte-formula-v1",
        "measurement_class": "serialized-byte-upper-bound-projection-not-native-measured",
        "ordered_categories": list(ROUTE_A_SERIALIZED_CATEGORIES),
        "ring_dimension": _RING_DIMENSION,
        "maximum_rns_towers": _MAX_RNS_TOWERS,
        "maximum_ciphertext_components": _MAX_CIPHERTEXT_COMPONENTS,
        "coefficient_and_overhead_bytes": _COEFFICIENT_AND_OVERHEAD_BYTES,
        "ciphertext_envelope_bytes": _CIPHERTEXT_ENVELOPE_BYTES,
        "ciphertext_formula": (
            "ciphertext_envelope_bytes+maximum_ciphertext_components*"
            "maximum_rns_towers*ring_dimension*coefficient_and_overhead_bytes"
        ),
        "ciphertext_max_bytes": ROUTE_A_CIPHERTEXT_MAX_BYTES,
        "maximum_evaluation_key_components": _MAX_EVALUATION_KEY_COMPONENTS,
        "evaluation_key_envelope_bytes": _EVALUATION_KEY_ENVELOPE_BYTES,
        "evaluation_key_formula": (
            "evaluation_key_envelope_bytes+maximum_evaluation_key_components*"
            "maximum_rns_towers*ring_dimension*coefficient_and_overhead_bytes"
        ),
        "evaluation_key_max_bytes": ROUTE_A_EVALUATION_KEY_MAX_BYTES,
        "canonical_metadata_max_bytes": ROUTE_A_CANONICAL_METADATA_MAX_BYTES,
        "direct_metadata_rule": "sum-exact-emitted-canonical-document-bytes",
        "rho10_query_metadata_rule": "projected-multiplicity-times-canonical-metadata-max-bytes",
        "evaluation_key_rule": "separate-one-time-inventory-never-recurring-strategy-total",
    }


def account_route_a_serialized_bytes(
    multiplicities: Mapping[str, int],
    *,
    emitted_metadata_documents: Mapping[str, tuple[bytes, ...]],
) -> dict[str, int]:
    """Close one direct synthetic/SNAP serialized-byte accounting view."""

    counts = _closed_multiplicities(multiplicities)
    if type(emitted_metadata_documents) is not dict or set(emitted_metadata_documents) != set(
        _METADATA_CATEGORIES
    ):
        raise RouteASerializedByteError(
            "metadata document categories must equal the frozen ordered metadata set"
        )

    result: dict[str, int] = {}
    for category in ROUTE_A_SERIALIZED_CATEGORIES:
        if category in _METADATA_CATEGORIES:
            documents = emitted_metadata_documents[category]
            if type(documents) is not tuple or len(documents) != counts[category]:
                raise RouteASerializedByteError(
                    f"{category} metadata multiplicity differs from emitted documents"
                )
            result[category] = sum(
                len(_require_canonical_metadata(document, category)) for document in documents
            )
        elif category in _CIPHERTEXT_CATEGORIES:
            result[category] = counts[category] * ROUTE_A_CIPHERTEXT_MAX_BYTES
        else:
            if category != "one-time-evaluation-key-material":  # pragma: no cover
                raise AssertionError("closed serialized category dispatch changed")
            result[category] = counts[category] * ROUTE_A_EVALUATION_KEY_MAX_BYTES
    return result
