"""Closed mapping from causal strategy metrics to the formal Day 2 vocabulary.

Day 1B counts work; Day 2 prices the same ordered primitive vector.  This
module is the single seam between those two experiments.  It deliberately
contains no timing values and accepts no caller-supplied primitive names.
"""

from __future__ import annotations

from dataclasses import dataclass

from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.metrics import StrategyMetrics


class PublicationPrimitiveAccountingError(ValueError):
    """Raised when strategy metrics do not form one closed protocol inventory."""


@dataclass(frozen=True, slots=True)
class _PrimitiveFormula:
    """One exact nonnegative linear formula over StrategyMetrics fields."""

    metric_fields: tuple[str, ...] = ()
    effective_slot_metric_fields: tuple[str, ...] = ()

    def evaluate(self, metric: StrategyMetrics, effective_slots: int) -> int:
        return sum(getattr(metric, field) for field in self.metric_fields) + effective_slots * sum(
            getattr(metric, field) for field in self.effective_slot_metric_fields
        )

    def document(self) -> dict[str, object]:
        return {
            "metric_fields": list(self.metric_fields),
            "effective_slots_metric_fields": list(self.effective_slot_metric_fields),
        }


def _formula(
    *metric_fields: str,
    effective_slot_metric_fields: tuple[str, ...] = (),
) -> _PrimitiveFormula:
    return _PrimitiveFormula(
        metric_fields=metric_fields,
        effective_slot_metric_fields=effective_slot_metric_fields,
    )


_UPDATE_FORMULAS = (
    ("client_merge", _formula()),
    ("client_reorder_element", _formula()),
    ("decrypt", _formula()),
    ("deserialize_ciphertext", _formula("update_encryptions")),
    ("encode", _formula("update_encryptions")),
    ("encrypt", _formula("update_encryptions")),
    ("eval_add_ciphertext", _formula()),
    ("eval_mult_plaintext_mask", _formula()),
    ("eval_mult_with_relinearization", _formula()),
    ("eval_rotate", _formula()),
    ("mask_map_element", _formula()),
    ("mask_random_element", _formula()),
    ("query_vector_pack", _formula()),
    ("serialize_ciphertext", _formula("update_encryptions")),
)
_QUERY_FORMULAS = (
    ("client_merge", _formula("client_merges")),
    ("client_reorder_element", _formula("client_reorder_elements")),
    ("decrypt", _formula("decryptions")),
    (
        "deserialize_ciphertext",
        _formula("query_ciphertexts", "blinding_encryptions", "result_ciphertexts"),
    ),
    ("encode", _formula("query_ciphertexts", "blinding_encryptions")),
    ("encrypt", _formula("query_ciphertexts", "blinding_encryptions")),
    ("eval_add_ciphertext", _formula("additions", "blinding_additions")),
    ("eval_mult_plaintext_mask", _formula("plaintext_masks")),
    ("eval_mult_with_relinearization", _formula("cc_multiplications")),
    ("eval_rotate", _formula("rotations")),
    ("mask_map_element", _formula("mask_mapped_elements")),
    ("mask_random_element", _formula("mask_random_elements")),
    (
        "query_vector_pack",
        _formula(effective_slot_metric_fields=("query_ciphertexts",)),
    ),
    (
        "serialize_ciphertext",
        _formula("query_ciphertexts", "blinding_encryptions", "result_ciphertexts"),
    ),
)

if tuple(name for name, _ in _UPDATE_FORMULAS) != PRIMITIVE_NAMES:
    raise RuntimeError("update primitive formulas are not in the frozen Day 2 order")
if tuple(name for name, _ in _QUERY_FORMULAS) != PRIMITIVE_NAMES:
    raise RuntimeError("query primitive formulas are not in the frozen Day 2 order")
for _name, _formula_definition in (*_UPDATE_FORMULAS, *_QUERY_FORMULAS):
    for _field in (
        *_formula_definition.metric_fields,
        *_formula_definition.effective_slot_metric_fields,
    ):
        if _field not in StrategyMetrics.__dataclass_fields__:
            raise RuntimeError(f"primitive formula {_name} names an unknown metric field")


def publication_primitive_accounting_contract_document() -> dict[str, object]:
    """Return the exact JSON-safe formula document bound into formal Day 2."""

    return {
        "schema_version": "dynamic-cssc-publication-primitive-accounting-v2",
        "primitive_names": list(PRIMITIVE_NAMES),
        "count_vectors": ["update_primitive_counts", "query_primitive_counts"],
        "vector_index_rule": "primitive_names-canonical-order",
        "formula_rule": ("sum(metric_fields)+effective_slots*sum(effective_slots_metric_fields)"),
        "effective_slots_rule": "positive-strict-integer-from-frozen-publication-domain",
        "update_formulas": {name: formula.document() for name, formula in _UPDATE_FORMULAS},
        "query_formulas": {name: formula.document() for name, formula in _QUERY_FORMULAS},
        "closure_invariants": [
            "metadata_units=ci_patch_entries+ci_full_sync_entries",
            "update_encryptions=update_ciphertexts+compaction_ciphertexts",
            "cc_multiplications=relinearizations",
            "result_ciphertexts=decryptions",
            ("blinding_encryptions=blinding_mask_ciphertexts+blinding_dummy_ciphertexts"),
            "blinding_additions=blinding_encryptions",
            "queries=0-implies-all-query-side-fields=0",
        ],
        "ciphertext_transport_rule": (
            "each-transmitted-ciphertext-counted-once-for-serialize-and-once-for-deserialize"
        ),
        "relinearization_rule": ("count-exactly-once-inside-eval_mult_with_relinearization"),
        "rotation_rule": "count-each-exact-index-call-under-eval_rotate",
        "weighted_count_rule": (
            "window-query-multiplicity-applied-to-StrategyMetrics-before-this-mapping"
        ),
        "incomplete_outcome_rule": "all-measured-quantities-null-no-partial-pricing",
    }


@dataclass(frozen=True, slots=True)
class PublicationPrimitiveAccounting:
    """Exact ordered update/query count vectors consumed by formal calibration."""

    update_counts: tuple[int, ...]
    query_counts: tuple[int, ...]

    def __post_init__(self) -> None:
        expected = len(PRIMITIVE_NAMES)
        for field in ("update_counts", "query_counts"):
            value = getattr(self, field)
            if (
                type(value) is not tuple
                or len(value) != expected
                or any(type(count) is not int or count < 0 for count in value)
            ):
                raise PublicationPrimitiveAccountingError(
                    f"{field} must be the exact nonnegative Day 2 vector"
                )

    def update_document(self) -> dict[str, int]:
        return dict(zip(PRIMITIVE_NAMES, self.update_counts, strict=True))

    def query_document(self) -> dict[str, int]:
        return dict(zip(PRIMITIVE_NAMES, self.query_counts, strict=True))


def _strict_positive(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise PublicationPrimitiveAccountingError(f"{field} must be a positive strict integer")
    return value


def _closed_metric(metric: StrategyMetrics) -> StrategyMetrics:
    if type(metric) is not StrategyMetrics:
        raise TypeError("metric must be an exact StrategyMetrics value")
    for field in metric.__dataclass_fields__:
        if field in {"strategy", "category", "source", "metadata_units"}:
            continue
        value = getattr(metric, field)
        if type(value) is not int or value < 0:
            raise PublicationPrimitiveAccountingError(
                f"StrategyMetrics.{field} must be a nonnegative strict integer"
            )
    if type(metric.metadata_units) is not int or metric.metadata_units < 0:
        raise PublicationPrimitiveAccountingError(
            "StrategyMetrics.metadata_units must be a nonnegative strict integer"
        )
    if metric.metadata_units != metric.ci_patch_entries + metric.ci_full_sync_entries:
        raise PublicationPrimitiveAccountingError("metadata accounting is not closed")
    if metric.update_encryptions != metric.update_ciphertexts + metric.compaction_ciphertexts:
        raise PublicationPrimitiveAccountingError(
            "update encryption and transmitted-ciphertext counts are not closed"
        )
    if metric.cc_multiplications != metric.relinearizations:
        raise PublicationPrimitiveAccountingError(
            "ciphertext multiplication must include exactly one relinearization"
        )
    if metric.result_ciphertexts != metric.decryptions:
        raise PublicationPrimitiveAccountingError(
            "every returned ciphertext must be decrypted exactly once"
        )
    if metric.blinding_encryptions != (
        metric.blinding_mask_ciphertexts + metric.blinding_dummy_ciphertexts
    ):
        raise PublicationPrimitiveAccountingError("F1-M encryption counts are not closed")
    if metric.blinding_additions != metric.blinding_encryptions:
        raise PublicationPrimitiveAccountingError(
            "every F1-M ciphertext must be added exactly once"
        )
    query_fields = (
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
    if metric.queries == 0 and any(getattr(metric, field) for field in query_fields):
        raise PublicationPrimitiveAccountingError(
            "zero-query metrics cannot contain query-side primitive work"
        )
    return metric


def publication_primitive_accounting(
    metric: StrategyMetrics,
    *,
    effective_slots: int,
) -> PublicationPrimitiveAccounting:
    """Map one causal metric aggregate to the frozen 14-primitive vectors.

    Client-side vector primitives are calibrated per element, whereas OpenFHE
    encode/encrypt/serialize/deserialize/decrypt operations are calibrated per
    object.  Each transmitted ciphertext is charged once for serialization at
    its sender and once for deserialization at its recipient.
    """

    metric = _closed_metric(metric)
    effective_slots = _strict_positive(effective_slots, "effective_slots")

    return PublicationPrimitiveAccounting(
        update_counts=tuple(
            formula.evaluate(metric, effective_slots) for _, formula in _UPDATE_FORMULAS
        ),
        query_counts=tuple(
            formula.evaluate(metric, effective_slots) for _, formula in _QUERY_FORMULAS
        ),
    )


__all__ = (
    "PublicationPrimitiveAccounting",
    "PublicationPrimitiveAccountingError",
    "publication_primitive_accounting",
    "publication_primitive_accounting_contract_document",
)
