from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dynamic_cssc.route_a_controller import _PLAN_SHA256 as CONTROLLER_PLAN_SHA256
from dynamic_cssc.route_a_results import (
    ROUTE_A_CELL_SCHEMA,
    ROUTE_A_MACHINE_PLAN_SHA256,
    RouteAResultContractError,
    canonical_route_a_document,
    project_route_a_rho10,
    validate_route_a_strategy_cell,
)
from dynamic_cssc.route_a_serialized_bytes import (
    ROUTE_A_SERIALIZED_CATEGORIES,
    RouteASerializedByteError,
    account_route_a_serialized_bytes,
    route_a_serialized_byte_formula_document,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_every_runtime_machine_plan_digest_matches_retained_plan_bytes() -> None:
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    retained_digest = hashlib.sha256(plan_bytes).hexdigest()

    assert retained_digest == ROUTE_A_MACHINE_PLAN_SHA256
    assert retained_digest == CONTROLLER_PLAN_SHA256


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _direct_rho1_cell() -> dict[str, object]:
    primitive_fields = (
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
    primitive_counts = {field: 0 for field in primitive_fields}
    primitive_counts.update(
        {
            "query_ciphertexts": 3,
            "result_ciphertexts": 2,
            "cc_multiplications": 4,
            "relinearizations": 4,
            "rotations": 5,
            "additions": 6,
            "plaintext_masks": 7,
            "decryptions": 2,
            "client_merges": 2,
            "client_reorder_elements": 8193,
        }
    )
    multiplicities = {category: 0 for category in ROUTE_A_SERIALIZED_CATEGORIES}
    multiplicities.update(
        {
            "query-query-ciphertexts": 3,
            "query-result-ciphertexts": 2,
            "query-version-plan-metadata": 2,
        }
    )
    serialized_bytes = {category: 0 for category in ROUTE_A_SERIALIZED_CATEGORIES}
    serialized_bytes.update(
        {
            "query-query-ciphertexts": 19_070_976,
            "query-result-ciphertexts": 12_713_984,
            "query-version-plan-metadata": 187,
        }
    )
    return {
        "schema_version": ROUTE_A_CELL_SCHEMA,
        "identity": {
            "formal_seed_or_null": 20260822,
            "object_sha256_or_null": None,
            "partition_or_null": None,
            "rho": "1",
            "scale_or_null": "S",
            "semantics_or_null": None,
            "shard_identity_sha256": _sha("shard"),
            "source_kind": "synthetic",
            "strategy_candidate_id": "padding-reuse",
            "suite_role": "formal",
            "unit_attempt_ordinal": 0,
        },
        "evaluation": {
            "mode": "directly-measured",
            "source_rho": None,
            "target_rho": "1",
        },
        "counts": {"queries": 2, "updates": 512, "windows": 3},
        "window_query_counts": [0, 1, 1],
        "primitive_counts": primitive_counts,
        "rotation_inventory": {
            "measured_counts_by_exact_index": [[-1, 2], [1, 3]],
            "required_indices": [-1, 1],
        },
        "serialized_object_multiplicities": multiplicities,
        "serialized_bytes": serialized_bytes,
        "measurements": {
            "native_latency_seconds": None,
            "peak_rss_kib": 4096,
            "producer_result_assembly_seconds": "0.125000000",
            "producer_state_transition_seconds": "1.500000000",
            "replay_seconds": "1.625000000",
            "scratch_allocated_bytes": 8192,
        },
        "correctness": {
            "binding_acceptance": True,
            "claim_authority": False,
            "execution_performed": True,
            "oracle_equality": True,
            "source_rho": None,
        },
        "bindings": {
            "ledger_root": _sha("ledger"),
            "machine_plan_sha256": ROUTE_A_MACHINE_PLAN_SHA256,
            "prepared_query_root": _sha("prepared"),
            "query_id_root": _sha("query"),
            "source_rho1_document_sha256": None,
            "transform_id": None,
        },
    }


def test_strategy_cell_is_closed_and_canonical() -> None:
    cell = _direct_rho1_cell()
    validated = validate_route_a_strategy_cell(cell)

    assert validated.document == cell
    assert validated.document_bytes.endswith(b"\n")
    assert validated.sha256 == hashlib.sha256(validated.document_bytes).hexdigest()
    assert json.loads(validated.document_bytes) == cell
    assert canonical_route_a_document(cell) == validated.document_bytes


@pytest.mark.parametrize(
    ("mutator", "message"),
    (
        (lambda cell: cell.update(extra=True), "top-level"),
        (lambda cell: cell["identity"].update(extra=True), "identity"),
        (lambda cell: cell["counts"].update(queries=True), "queries"),
        (
            lambda cell: cell["measurements"].update(producer_state_transition_seconds=1.5),
            "decimal",
        ),
        (
            lambda cell: cell["correctness"].update(claim_authority=True),
            "authority",
        ),
    ),
)
def test_strategy_cell_rejects_open_or_ambiguous_values(mutator, message: str) -> None:
    cell = _direct_rho1_cell()
    mutator(cell)

    with pytest.raises(RouteAResultContractError, match=message):
        validate_route_a_strategy_cell(cell)


def test_rho10_projection_changes_only_the_frozen_query_linear_paths() -> None:
    source = validate_route_a_strategy_cell(_direct_rho1_cell())
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()

    projection = project_route_a_rho10(source, machine_plan_bytes=plan_bytes)
    target = projection.target.document

    assert target["identity"]["rho"] == "10"
    assert target["counts"]["queries"] == 20
    assert target["window_query_counts"] == [0, 10, 10]
    assert target["primitive_counts"]["query_ciphertexts"] == 30
    assert target["primitive_counts"]["update_encryptions"] == 0
    assert target["rotation_inventory"]["measured_counts_by_exact_index"] == [
        [-1, 20],
        [1, 30],
    ]
    assert target["measurements"] == {
        "native_latency_seconds": None,
        "peak_rss_kib": None,
        "producer_result_assembly_seconds": None,
        "producer_state_transition_seconds": None,
        "replay_seconds": None,
        "scratch_allocated_bytes": None,
    }
    assert target["correctness"] == {
        "binding_acceptance": None,
        "claim_authority": False,
        "execution_performed": False,
        "oracle_equality": None,
        "source_rho": "1",
    }
    assert target["bindings"]["query_id_root"] is None
    assert target["bindings"]["source_rho1_document_sha256"] == source.sha256
    assert projection.integrity_envelope["transformed_rho10_document_sha256"] == (
        projection.target.sha256
    )


def test_rho10_projection_recomputes_metadata_bound_instead_of_copying_observation() -> None:
    source_document = _direct_rho1_cell()
    source_document["serialized_bytes"]["query-version-plan-metadata"] = 1
    source = validate_route_a_strategy_cell(source_document)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()

    target = project_route_a_rho10(source, machine_plan_bytes=plan_bytes).target.document

    assert target["serialized_object_multiplicities"]["query-version-plan-metadata"] == 20
    assert target["serialized_bytes"]["query-version-plan-metadata"] == 20 * 262_144


def test_rho10_projection_rejects_wrong_plan_or_non_rho1_source() -> None:
    source = validate_route_a_strategy_cell(_direct_rho1_cell())
    with pytest.raises(RouteAResultContractError, match="machine plan"):
        project_route_a_rho10(source, machine_plan_bytes=b"{}\n")

    cell = _direct_rho1_cell()
    cell["identity"]["rho"] = "1/10"
    cell["evaluation"]["target_rho"] = "1/10"
    non_rho1 = validate_route_a_strategy_cell(cell)
    plan_bytes = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()
    with pytest.raises(RouteAResultContractError, match="rho=1"):
        project_route_a_rho10(non_rho1, machine_plan_bytes=plan_bytes)


def test_serialized_byte_formula_is_closed_type_derived_and_integer_only() -> None:
    formula = route_a_serialized_byte_formula_document()

    assert formula["ordered_categories"] == list(ROUTE_A_SERIALIZED_CATEGORIES)
    assert formula["ring_dimension"] == 8192
    assert formula["ciphertext_max_bytes"] == 6_356_992
    assert formula["canonical_metadata_max_bytes"] == 262_144
    assert json.dumps(formula, allow_nan=False)


def test_serialized_byte_accounting_separates_exact_metadata_from_projection() -> None:
    multiplicities = {category: 0 for category in ROUTE_A_SERIALIZED_CATEGORIES}
    multiplicities.update(
        {
            "update-column-index-synchronization": 1,
            "update-publication-ciphertexts": 2,
            "query-query-ciphertexts": 3,
            "query-version-plan-metadata": 2,
        }
    )
    ci = b'{"schema_version":"ci"}\n'
    query_0 = b'{"ordinal":0,"schema_version":"q"}\n'
    query_1 = b'{"ordinal":1,"schema_version":"q"}\n'

    result = account_route_a_serialized_bytes(
        multiplicities,
        emitted_metadata_documents={
            "update-column-index-synchronization": (ci,),
            "update-version-plan-metadata": (),
            "query-version-plan-metadata": (query_0, query_1),
        },
    )

    assert result["update-column-index-synchronization"] == len(ci)
    assert result["query-version-plan-metadata"] == len(query_0) + len(query_1)
    assert result["update-publication-ciphertexts"] == 2 * 6_356_992
    assert result["query-query-ciphertexts"] == 3 * 6_356_992


def test_serialized_byte_accounting_rejects_noncanonical_metadata_and_open_categories() -> None:
    multiplicities = {category: 0 for category in ROUTE_A_SERIALIZED_CATEGORIES}
    multiplicities["query-version-plan-metadata"] = 1
    with pytest.raises(RouteASerializedByteError, match="canonical"):
        account_route_a_serialized_bytes(
            multiplicities,
            emitted_metadata_documents={
                "update-column-index-synchronization": (),
                "update-version-plan-metadata": (),
                "query-version-plan-metadata": (b'{"b":1, "a":2}\n',),
            },
        )

    opened = dict(multiplicities)
    opened["extra"] = 0
    with pytest.raises(RouteASerializedByteError, match="categories"):
        account_route_a_serialized_bytes(
            opened,
            emitted_metadata_documents={
                "update-column-index-synchronization": (),
                "update-version-plan-metadata": (),
                "query-version-plan-metadata": (),
            },
        )


def test_checked_in_json_schema_is_closed_and_bound_to_the_runtime_version() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas/route-a-strategy-cell-v2.schema.json").read_text(
            encoding="ascii"
        )
    )

    assert schema["$id"].endswith("route-a-strategy-cell-v2.schema.json")
    assert schema["properties"]["schema_version"]["const"] == ROUTE_A_CELL_SCHEMA
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(_direct_rho1_cell())
