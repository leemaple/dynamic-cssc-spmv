from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.metrics import StrategyMetrics
from dynamic_cssc.publication_primitive_accounting import (
    PublicationPrimitiveAccountingError,
    publication_primitive_accounting,
    publication_primitive_accounting_contract_document,
)
from dynamic_cssc.publication_statistics import PRIMITIVE_NAMES


def _metric() -> StrategyMetrics:
    return StrategyMetrics(
        strategy="Mini-CSSC-Delta",
        category="reference",
        windows=2,
        queries=3,
        updates=4,
        update_encryptions=5,
        update_ciphertexts=3,
        compaction_ciphertexts=2,
        query_ciphertexts=6,
        result_ciphertexts=9,
        cc_multiplications=6,
        relinearizations=6,
        rotations=12,
        additions=15,
        plaintext_masks=18,
        blinding_mask_ciphertexts=4,
        blinding_dummy_ciphertexts=5,
        blinding_encryptions=9,
        blinding_additions=9,
        decryptions=9,
        client_merges=21,
        mask_random_elements=24,
        mask_mapped_elements=27,
        client_reorder_elements=30,
        ci_patch_entries=2,
        ci_full_sync_entries=3,
        source="persistent-state-predicted",
    )


def test_maps_closed_strategy_metrics_to_the_formal_primitive_order() -> None:
    accounting = publication_primitive_accounting(_metric(), effective_slots=4096)

    assert tuple(accounting.update_document()) == PRIMITIVE_NAMES
    assert tuple(accounting.query_document()) == PRIMITIVE_NAMES
    assert accounting.update_document() == {
        "client_merge": 0,
        "client_reorder_element": 0,
        "decrypt": 0,
        "deserialize_ciphertext": 5,
        "encode": 5,
        "encrypt": 5,
        "eval_add_ciphertext": 0,
        "eval_mult_plaintext_mask": 0,
        "eval_mult_with_relinearization": 0,
        "eval_rotate": 0,
        "mask_map_element": 0,
        "mask_random_element": 0,
        "query_vector_pack": 0,
        "serialize_ciphertext": 5,
    }
    assert accounting.query_document() == {
        "client_merge": 21,
        "client_reorder_element": 30,
        "decrypt": 9,
        "deserialize_ciphertext": 24,
        "encode": 15,
        "encrypt": 15,
        "eval_add_ciphertext": 24,
        "eval_mult_plaintext_mask": 18,
        "eval_mult_with_relinearization": 6,
        "eval_rotate": 12,
        "mask_map_element": 27,
        "mask_random_element": 24,
        "query_vector_pack": 24_576,
        "serialize_ciphertext": 24,
    }


def test_formal_contract_is_the_machine_readable_execution_formula() -> None:
    contract = publication_primitive_accounting_contract_document()

    assert contract["schema_version"] == "dynamic-cssc-publication-primitive-accounting-v2"
    assert contract["primitive_names"] == list(PRIMITIVE_NAMES)
    assert tuple(contract["update_formulas"]) == PRIMITIVE_NAMES
    assert tuple(contract["query_formulas"]) == PRIMITIVE_NAMES
    assert contract["update_formulas"]["encrypt"] == {
        "metric_fields": ["update_encryptions"],
        "effective_slots_metric_fields": [],
    }
    assert contract["query_formulas"]["deserialize_ciphertext"] == {
        "metric_fields": [
            "query_ciphertexts",
            "blinding_encryptions",
            "result_ciphertexts",
        ],
        "effective_slots_metric_fields": [],
    }
    assert contract["query_formulas"]["query_vector_pack"] == {
        "metric_fields": [],
        "effective_slots_metric_fields": ["query_ciphertexts"],
    }

    contract["query_formulas"]["encrypt"]["metric_fields"].append("queries")
    assert (
        publication_primitive_accounting(_metric(), effective_slots=4096).query_document()[
            "encrypt"
        ]
        == 15
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"update_encryptions": 6}, "update encryption"),
        ({"relinearizations": 5}, "relinearization"),
        ({"decryptions": 8}, "decrypted"),
        ({"blinding_encryptions": 8}, "F1-M encryption"),
        ({"blinding_additions": 8}, "F1-M ciphertext"),
    ),
)
def test_rejects_nonclosed_protocol_counts(
    changes: dict[str, int],
    message: str,
) -> None:
    with pytest.raises(PublicationPrimitiveAccountingError, match=message):
        publication_primitive_accounting(replace(_metric(), **changes), effective_slots=4096)


def test_zero_query_metrics_cannot_hide_query_work() -> None:
    metric = StrategyMetrics(
        strategy="PaddingReuse-CSSC",
        category="reference",
        queries=0,
        query_ciphertexts=1,
        cc_multiplications=1,
        relinearizations=1,
        source="persistent-state-predicted",
    )

    with pytest.raises(PublicationPrimitiveAccountingError, match="zero-query"):
        publication_primitive_accounting(metric, effective_slots=4096)


@pytest.mark.parametrize("effective_slots", (True, 0, -1, 4096.0))
def test_effective_slots_is_one_exact_positive_integer(effective_slots: object) -> None:
    with pytest.raises(PublicationPrimitiveAccountingError, match="effective_slots"):
        publication_primitive_accounting(_metric(), effective_slots=effective_slots)  # type: ignore[arg-type]
