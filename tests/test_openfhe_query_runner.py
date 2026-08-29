from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_profile as day2_profile
import dynamic_cssc.openfhe_query_runner as runner_contract
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA,
    OPENFHE_QUERY_PARAMETER_PROFILE,
    OPENFHE_QUERY_REQUEST_SCHEMA,
    OPENFHE_QUERY_RESULT_SCHEMA,
    ROUTE_A_OPENFHE_PRODUCER_RESULT_SCHEMA,
    ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA,
    OpenFHEQueryRunnerError,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
    pre_admission_day2_openfhe_key_generation_plan,
    verify_ordinary_openfhe_query_result,
    verify_route_a_ordinary_openfhe_producer_result,
    verify_route_a_ordinary_openfhe_replay_result,
    verify_strong_openfhe_query_result,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.plaintext_oracle import execute_cloud_plan, execute_compiled_query
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
    Day1BCombinedEvaluationKeyFrame,
)
from dynamic_cssc.query_compiler import compile_query
from dynamic_cssc.strong_execution import (
    PreparedStrongQuery,
    StrongExecutionBundle,
    canonical_strong_query_preparation_bytes,
    compile_strong_execution,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import (
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
)
from scripts import run_openfhe_query_smoke as smoke

ROOT = Path(__file__).resolve().parents[1]


def _bundle_and_prepared(tmp_path: Path) -> tuple[OrdinaryExecutionBundle, PreparedOrdinaryQuery]:
    first = publish_component(
        {(0, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="ordinary-openfhe-version-1",
        component_prefix="ordinary-openfhe-a",
    )
    second = publish_component(
        {(0, 1): 3, (1, 2): 4},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="ordinary-openfhe-version-1",
        component_prefix="ordinary-openfhe-b",
    )
    bundle = bind_ordinary_execution(compile_query((second, first), f1m_policy="overlap-only"))
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-openfhe-query-1",
        vector=(5, 7, 11, 13),
        modulus=65537,
        ledger=SQLiteMaskBindingLedger(tmp_path / "ordinary-openfhe-ledger.sqlite3"),
    )
    return bundle, prepared


def _strong_bundle_and_prepared(
    tmp_path: Path,
) -> tuple[StrongExecutionBundle, PreparedStrongQuery]:
    base = publish_component(
        {(0, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="strong-openfhe-version-1",
        component_prefix="strong-openfhe-base",
    )
    empty = initialize_segmented_delta(
        rows=2,
        cols=4,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=7,
        version_id="strong-openfhe-version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 1, 3), StrongEntry(1, 2, 4)),
        version_id="strong-openfhe-version-1",
    ).state
    bundle = compile_strong_execution(base, delta)
    prepared = prepare_strong_query(
        bundle,
        query_id="strong-openfhe-query-1",
        vector=(5, 7, 11, 13),
        modulus=65537,
        ledger=SQLiteMaskBindingLedger(tmp_path / "strong-openfhe-ledger.sqlite3"),
    )
    return bundle, prepared


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _write_generic_result_fixture(
    tmp_path: Path,
    request_bytes: bytes,
    returned: dict[str, tuple[int, ...]],
    operation_counts: dict[str, int],
) -> tuple[Path, Path, dict[str, object]]:
    request = json.loads(request_bytes)
    subjects: list[tuple[str, str]] = [
        ("one-time-evaluation-key-material", "evaluation-key-material")
    ]
    for item in request["ciphertext_values"]:
        if item["role"] == "value":
            category = "update-publication-ciphertexts"
        elif item["role"] == "query":
            category = "query-query-ciphertexts"
        elif item["f1m_kind"] == "random-zero-sum":
            category = "query-f1m-random-mask-ciphertexts"
        else:
            category = "query-f1m-encrypted-zero-dummy-ciphertexts"
        subjects.append((category, item["ciphertext_id"]))
    subjects.extend(
        ("query-result-ciphertexts", result_id) for result_id in request["program"]["result_ids"]
    )
    object_root = tmp_path / "objects"
    object_root.mkdir()
    receipts: list[dict[str, object]] = []
    rotation_segment = b"test-only-rotation-key-inventory"
    eval_mult_segment = b"test-only-eval-mult-keys"
    key_frame = Day1BCombinedEvaluationKeyFrame(
        rotation_key_inventory=rotation_segment,
        eval_mult_keys=eval_mult_segment,
    ).to_bytes()
    for index, (category, subject_id) in enumerate(subjects):
        relative_path = f"object-{index:06d}.bin"
        content = key_frame if index == 0 else f"test-only-openfhe-object-{index}".encode()
        (object_root / relative_path).write_bytes(content)
        receipts.append(
            {
                "byte_count": len(content),
                "category": category,
                "relative_path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": subject_id,
            }
        )
    key_plan = request["key_generation_plan"]
    rotation_plan = key_plan["rotation_key_plan"]
    key_material_receipt = {
        "combined_frame_byte_count": len(key_frame),
        "combined_frame_sha256": hashlib.sha256(key_frame).hexdigest(),
        "crypto_context_parameter_sha256": hashlib.sha256(
            _canonical(request["openfhe"])
        ).hexdigest(),
        "crypto_context_serialization_sha256": "a" * 64,
        "eval_mult_segment_byte_count": len(eval_mult_segment),
        "eval_mult_segment_sha256": hashlib.sha256(eval_mult_segment).hexdigest(),
        "formal_authority_granted": False,
        "framing_schema": DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
        "generated_exact_indices": rotation_plan["required_exact_indices"],
        "input_binding_sha256": runner_contract._key_material_input_binding_sha256(request),
        "key_generation_plan_sha256": hashlib.sha256(_canonical(key_plan)).hexdigest(),
        "key_generation_session_sha256": "0" * 64,
        "publication_authority": False,
        "public_key_sha256": "b" * 64,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "required_exact_indices": rotation_plan["required_exact_indices"],
        "rotation_key_plan_sha256": key_plan["rotation_key_plan_sha256"],
        "rotation_segment_byte_count": len(rotation_segment),
        "rotation_segment_sha256": hashlib.sha256(rotation_segment).hexdigest(),
        "same_crypto_context_generation_session": True,
        "schema_version": OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA,
        "status": "verified-by-runner-pre-admission-only",
    }
    key_material_receipt["key_generation_session_sha256"] = (
        runner_contract._key_generation_session_sha256(key_material_receipt)
    )
    result = {
        "bindings": request["bindings"],
        "decrypted_results": [
            {"result_id": result_id, "values": list(returned[result_id])}
            for result_id in request["program"]["result_ids"]
        ],
        "key_generation_plan": key_plan,
        "key_material_receipt": key_material_receipt,
        "openfhe": request["openfhe"],
        "operation_counts": operation_counts,
        "publication_authority": False,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "schema_version": OPENFHE_QUERY_RESULT_SCHEMA,
        "second_batch_row_zero": True,
        "serialized_objects": receipts,
        "status": "pass",
    }
    result_path = tmp_path / "result.json"
    result_path.write_bytes(_canonical(result))
    return result_path, object_root, result


def _write_result_fixture(
    tmp_path: Path,
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    request_bytes: bytes,
) -> tuple[Path, Path, dict[str, object]]:
    request = json.loads(request_bytes)
    ciphertext_inputs = {
        item["ciphertext_id"]: tuple(item["values"]) for item in request["ciphertext_values"]
    }
    returned = execute_compiled_query(
        bundle.compiled,
        expected_f1m_policy="overlap-only",
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks={
            item["mask_id"]: tuple(item["values"]) for item in request["program"]["plaintext_masks"]
        },
        modulus=prepared.modulus,
    )
    return _write_generic_result_fixture(
        tmp_path,
        request_bytes,
        returned,
        runner_contract._expected_operation_counts(bundle.compiled.cloud_plan.program),
    )


def _write_route_a_result_fixture(
    tmp_path: Path,
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    request_bytes: bytes,
) -> tuple[Path, Path, dict[str, object]]:
    legacy_root = tmp_path / "legacy"
    legacy_root.mkdir()
    legacy_result_path, legacy_objects, legacy = _write_result_fixture(
        legacy_root,
        bundle,
        prepared,
        request_bytes,
    )
    assert legacy_result_path.exists()
    context = b"test-route-a-serialized-context"
    secret = b"test-route-a-secret-key"
    public = b"test-route-a-public-key"
    object_root = tmp_path / "route-a-objects"
    object_root.mkdir()
    physical = [context, secret, public]
    physical.extend(
        (legacy_objects / item["relative_path"]).read_bytes()
        for item in legacy["serialized_objects"]
    )
    subjects = [
        ("route-a-private-replay-crypto-context", "crypto-context"),
        ("route-a-private-replay-secret-key", "secret-key"),
        ("one-time-evaluation-key-material", "public-key"),
        *((item["category"], item["subject_id"]) for item in legacy["serialized_objects"]),
    ]
    receipts: list[dict[str, object]] = []
    for ordinal, (content, (category, subject_id)) in enumerate(
        zip(physical, subjects, strict=True)
    ):
        relative_path = f"object-{ordinal:06d}.bin"
        (object_root / relative_path).write_bytes(content)
        receipts.append(
            {
                "byte_count": len(content),
                "category": category,
                "relative_path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": subject_id,
            }
        )
    key_receipt = deepcopy(legacy["key_material_receipt"])
    key_receipt["crypto_context_serialization_sha256"] = hashlib.sha256(context).hexdigest()
    key_receipt["public_key_sha256"] = hashlib.sha256(public).hexdigest()
    key_receipt["key_generation_session_sha256"] = runner_contract._key_generation_session_sha256(
        key_receipt
    )
    counts = runner_contract._expected_operation_counts(bundle.compiled.cloud_plan.program)
    cloud = {key: counts[key] for key in runner_contract._ROUTE_A_CLOUD_OPERATION_KEYS}
    lifecycle = {key: 0 for key in runner_contract._ROUTE_A_LIFECYCLE_OPERATION_KEYS}
    lifecycle.update(
        {
            "automorphism_key_generation_count": 1,
            "context_generation_count": 1,
            "decrypt_count": counts["decrypt"],
            "encrypt_count": counts["encrypt"],
            "eval_mult_key_generation_count": 1,
            "key_generation_count": 1,
        }
    )
    result = {
        "bindings": legacy["bindings"],
        "cloud_program_operation_inventory": cloud,
        "decrypted_results": legacy["decrypted_results"],
        "key_generation_plan": legacy["key_generation_plan"],
        "key_material_receipt": key_receipt,
        "lifecycle_operation_inventory": lifecycle,
        "mode": "producer",
        "openfhe": legacy["openfhe"],
        "publication_authority": False,
        "request_sha256": legacy["request_sha256"],
        "schema_version": ROUTE_A_OPENFHE_PRODUCER_RESULT_SCHEMA,
        "second_batch_row_zero": True,
        "serialized_objects": receipts,
        "status": "pass",
    }
    result_path = tmp_path / "route-a-result.json"
    result_path.write_bytes(_canonical(result))
    return result_path, object_root, result


def test_request_is_canonical_private_and_explicitly_non_authorizing(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)

    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    request = json.loads(request_bytes)

    assert request_bytes == _canonical(request)
    assert request["schema_version"] == OPENFHE_QUERY_REQUEST_SCHEMA
    assert request["openfhe"]["compiler_profile"] == OPENFHE_QUERY_PARAMETER_PROFILE
    assert request["openfhe"]["authority_state"] == "HOLD-mixed-circuit-parameter-gate"
    assert request["openfhe"]["formal_parameter_claim_allowed"] is False
    assert request["key_generation_plan"]["authority_state"] == "pre-admission-only"
    assert request["key_generation_plan"]["formal_authority_granted"] is False
    assert request["key_generation_plan"]["publication_authority"] is False
    assert request["key_generation_plan"]["rotation_key_plan"]["required_exact_indices"] == [1]
    assert request["bindings"]["cloud_program_sha256"] == bundle.compiled.cloud_program_digest
    assert [item["ciphertext_id"] for item in request["ciphertext_values"]] == sorted(
        item["ciphertext_id"] for item in request["ciphertext_values"]
    )
    assert {item["f1m_kind"] for item in request["ciphertext_values"]} == {
        None,
        "random-zero-sum",
    }


def test_strong_request_uses_the_same_generic_binding_language(tmp_path: Path) -> None:
    bundle, prepared = _strong_bundle_and_prepared(tmp_path)

    request_bytes = build_strong_openfhe_query_request(bundle, prepared)
    request = json.loads(request_bytes)

    assert request_bytes == _canonical(request)
    assert request["schema_version"] == OPENFHE_QUERY_REQUEST_SCHEMA
    assert request["bindings"] == {
        "cloud_program_sha256": bundle.cloud_program_digest,
        "execution_binding": request["bindings"]["execution_binding"],
        "execution_binding_sha256": bundle.execution_binding_digest,
        "execution_kind": "strong",
        "query_preparation_sha256": hashlib.sha256(
            canonical_strong_query_preparation_bytes(bundle, prepared)
        ).hexdigest(),
        "query_private_plan_sha256": bundle.private_plan_digest,
    }
    assert not any("ordinary" in key for key in request["bindings"])
    assert {item["f1m_kind"] for item in request["ciphertext_values"]} == {
        None,
        "random-zero-sum",
    }


def test_strong_verifier_reconstructs_the_same_typed_result(tmp_path: Path) -> None:
    bundle, prepared = _strong_bundle_and_prepared(tmp_path)
    request_bytes = build_strong_openfhe_query_request(bundle, prepared)
    request = json.loads(request_bytes)
    returned = execute_cloud_plan(
        bundle.cloud_plan,
        ciphertext_inputs={
            item["ciphertext_id"]: tuple(item["values"]) for item in request["ciphertext_values"]
        },
        plaintext_masks={
            item["mask_id"]: tuple(item["values"]) for item in request["program"]["plaintext_masks"]
        },
        modulus=prepared.modulus,
    )
    result_path, object_root, _result = _write_generic_result_fixture(
        tmp_path,
        request_bytes,
        returned,
        runner_contract._expected_operation_counts(bundle.cloud_plan.program),
    )

    verified = verify_strong_openfhe_query_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=(31, 44),
    )

    assert verified.reconstructed_output == (31, 44)
    assert verified.publication_authority is False


def test_verifier_binds_decryption_reconstruction_and_every_object(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )

    verified = verify_ordinary_openfhe_query_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=(31, 44),
    )

    assert verified.reconstructed_output == (31, 44)
    assert len(verified.serialized_objects) == 9
    assert verified.key_material_receipt.required_exact_indices == (1,)
    assert verified.key_material_receipt.generated_exact_indices == (1,)
    assert verified.key_material_receipt.to_document() == result["key_material_receipt"]
    assert verified.second_batch_row_zero is True
    assert verified.publication_authority is False


def test_route_a_producer_and_replay_verifiers_split_lifecycle_from_cloud(
    tmp_path: Path,
) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    producer_result_path, producer_objects, producer_document = _write_route_a_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )

    producer = verify_route_a_ordinary_openfhe_producer_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        result_path=producer_result_path,
        object_root=producer_objects,
        expected_output=(31, 44),
    )

    assert dict(producer.lifecycle_operation_inventory)["context_generation_count"] == 1
    assert "encrypt" not in dict(producer.cloud_program_operation_inventory)
    package_sha256 = "d" * 64
    replay_objects = tmp_path / "replay-objects"
    replay_objects.mkdir()
    replay_receipts: list[dict[str, object]] = []
    result_ids = tuple(bundle.compiled.cloud_plan.program.result_ids)
    for ordinal, result_id in enumerate(result_ids):
        content = f"test-route-a-replay-result-{ordinal}".encode()
        relative_path = f"object-{ordinal:06d}.bin"
        (replay_objects / relative_path).write_bytes(content)
        replay_receipts.append(
            {
                "byte_count": len(content),
                "category": "query-result-ciphertexts",
                "relative_path": relative_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": result_id,
            }
        )
    counts = runner_contract._expected_operation_counts(bundle.compiled.cloud_plan.program)
    replay_lifecycle = {key: 0 for key in runner_contract._ROUTE_A_LIFECYCLE_OPERATION_KEYS}
    replay_lifecycle.update(
        {
            "automorphism_key_deserialize_count": 1,
            "crypto_context_deserialize_count": 1,
            "decrypt_count": counts["decrypt"],
            "eval_mult_key_deserialize_count": 1,
            "input_ciphertext_deserialize_count": counts["encrypt"],
            "public_key_deserialize_count": 1,
            "secret_key_deserialize_count": 1,
        }
    )
    replay_document = {
        "bindings": producer_document["bindings"],
        "cloud_program_operation_inventory": producer_document["cloud_program_operation_inventory"],
        "decrypted_results": producer_document["decrypted_results"],
        "lifecycle_operation_inventory": replay_lifecycle,
        "mode": "replay",
        "openfhe": producer_document["openfhe"],
        "package_manifest_sha256": package_sha256,
        "publication_authority": False,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "schema_version": ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA,
        "second_batch_row_zero": True,
        "serialized_objects": replay_receipts,
        "status": "pass",
    }
    replay_result_path = tmp_path / "route-a-replay-result.json"
    replay_result_path.write_bytes(_canonical(replay_document))

    replay = verify_route_a_ordinary_openfhe_replay_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        package_manifest_sha256=package_sha256,
        result_path=replay_result_path,
        object_root=replay_objects,
        expected_output=(31, 44),
    )

    assert replay.cloud_program_operation_inventory == (producer.cloud_program_operation_inventory)
    assert dict(replay.lifecycle_operation_inventory)["context_generation_count"] == 0
    assert dict(replay.lifecycle_operation_inventory)["encrypt_count"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    (("context_generation_count", 1), ("encrypt_count", 1)),
)
def test_route_a_replay_verifier_rejects_generation_or_encryption_counts(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    producer_result_path, producer_objects, producer = _write_route_a_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )
    verify_route_a_ordinary_openfhe_producer_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        result_path=producer_result_path,
        object_root=producer_objects,
        expected_output=(31, 44),
    )
    counts = runner_contract._expected_operation_counts(bundle.compiled.cloud_plan.program)
    lifecycle = {key: 0 for key in runner_contract._ROUTE_A_LIFECYCLE_OPERATION_KEYS}
    lifecycle.update(
        {
            "automorphism_key_deserialize_count": 1,
            "crypto_context_deserialize_count": 1,
            "decrypt_count": counts["decrypt"],
            "eval_mult_key_deserialize_count": 1,
            "input_ciphertext_deserialize_count": counts["encrypt"],
            "public_key_deserialize_count": 1,
            "secret_key_deserialize_count": 1,
            field: value,
        }
    )
    replay_objects = tmp_path / "bad-replay-objects"
    replay_objects.mkdir()
    receipts = []
    for ordinal, result_id in enumerate(bundle.compiled.cloud_plan.program.result_ids):
        content = f"bad-replay-{ordinal}".encode()
        path = replay_objects / f"object-{ordinal:06d}.bin"
        path.write_bytes(content)
        receipts.append(
            {
                "byte_count": len(content),
                "category": "query-result-ciphertexts",
                "relative_path": path.name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": result_id,
            }
        )
    replay_document = {
        "bindings": producer["bindings"],
        "cloud_program_operation_inventory": producer["cloud_program_operation_inventory"],
        "decrypted_results": producer["decrypted_results"],
        "lifecycle_operation_inventory": lifecycle,
        "mode": "replay",
        "openfhe": producer["openfhe"],
        "package_manifest_sha256": "d" * 64,
        "publication_authority": False,
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "schema_version": ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA,
        "second_batch_row_zero": True,
        "serialized_objects": receipts,
        "status": "pass",
    }
    replay_path = tmp_path / "bad-replay-result.json"
    replay_path.write_bytes(_canonical(replay_document))

    with pytest.raises(OpenFHEQueryRunnerError, match="lifecycle"):
        verify_route_a_ordinary_openfhe_replay_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            package_manifest_sha256="d" * 64,
            result_path=replay_path,
            object_root=replay_objects,
            expected_output=(31, 44),
        )


def test_day2_rotation_plan_is_typed_but_remains_pre_admission(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    day2_plan = {
        "composite_decompositions": [],
        "day1a_authority_receipt_sha256": "c" * 64,
        "day1a_inventory_sha256": "d" * 64,
        "effective_slots": 4096,
        "eval_rotate_case_ids": ["index=-1", "index=1", "index=2"],
        "inventory_source_schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": [-1, 1, 2],
        "required_exact_indices": [-1, 1, 2],
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
    }
    day2_plan_bytes = day2_profile._canonical_json_bytes(day2_plan)
    assert day2_plan_bytes == _canonical(day2_plan) + b"\n"
    key_plan = pre_admission_day2_openfhe_key_generation_plan(day2_plan_bytes)
    request_bytes = build_ordinary_openfhe_query_request(
        bundle,
        prepared,
        key_generation_plan=key_plan,
    )
    request = json.loads(request_bytes)
    assert (
        request["key_generation_plan"]["rotation_key_plan_sha256"]
        == hashlib.sha256(day2_plan_bytes).hexdigest()
    )
    assert request["key_generation_plan"]["formal_authority_granted"] is False
    result_path, object_root, _result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )

    verified = verify_ordinary_openfhe_query_result(
        bundle,
        prepared,
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=(31, 44),
        key_generation_plan=key_plan,
    )

    assert verified.key_material_receipt.required_exact_indices == (-1, 1, 2)
    assert (
        verified.key_material_receipt.rotation_key_plan_sha256
        == hashlib.sha256(day2_plan_bytes).hexdigest()
    )
    with pytest.raises(OpenFHEQueryRunnerError, match="request differs"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )


@pytest.mark.parametrize("mutation", ("missing-lf", "extra-lf", "space", "key-order"))
def test_day2_rotation_plan_rejects_noncanonical_producer_member(
    mutation: str,
) -> None:
    plan = {
        "composite_decompositions": [],
        "day1a_authority_receipt_sha256": "c" * 64,
        "day1a_inventory_sha256": "d" * 64,
        "effective_slots": 4096,
        "eval_rotate_case_ids": ["index=-1", "index=1", "index=2"],
        "inventory_source_schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": [-1, 1, 2],
        "required_exact_indices": [-1, 1, 2],
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
    }
    exact = day2_profile._canonical_json_bytes(plan)
    if mutation == "missing-lf":
        changed = exact[:-1]
    elif mutation == "extra-lf":
        changed = exact + b"\n"
    elif mutation == "space":
        changed = exact.replace(b":", b": ", 1)
    else:
        changed = (
            json.dumps(
                dict(reversed(tuple(plan.items()))),
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    with pytest.raises(OpenFHEQueryRunnerError, match="not canonical JSON"):
        pre_admission_day2_openfhe_key_generation_plan(changed)


def test_real_smoke_uses_the_same_exact_day2_producer_member_bytes() -> None:
    smoke_source = (ROOT / "scripts/run_openfhe_query_smoke.py").read_text()
    exact = smoke._day2_plan_smoke_bytes()
    plan = json.loads(exact)
    assert exact == day2_profile._canonical_json_bytes(plan)
    assert "pre_admission_day2_openfhe_key_generation_plan" in smoke_source
    assert "key_generation_plan=" in smoke_source


def test_verifier_rejects_typed_key_receipt_and_frame_splices(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )

    generated_splice = deepcopy(result)
    generated_splice["key_material_receipt"]["generated_exact_indices"] = [2]
    result_path.write_bytes(_canonical(generated_splice))
    with pytest.raises(OpenFHEQueryRunnerError, match="key-material receipt"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )

    segment_splice = deepcopy(result)
    segment_splice["key_material_receipt"]["rotation_segment_sha256"] = "e" * 64
    segment_splice["key_material_receipt"]["key_generation_session_sha256"] = (
        runner_contract._key_generation_session_sha256(segment_splice["key_material_receipt"])
    )
    result_path.write_bytes(_canonical(segment_splice))
    with pytest.raises(OpenFHEQueryRunnerError, match="typed key frame"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )

    frame_splice = bytearray((object_root / "object-000000.bin").read_bytes())
    frame_splice[88] ^= 1
    spliced_frame = bytes(frame_splice)
    (object_root / "object-000000.bin").write_bytes(spliced_frame)
    frame_result = deepcopy(result)
    frame_digest = hashlib.sha256(spliced_frame).hexdigest()
    frame_result["serialized_objects"][0]["sha256"] = frame_digest
    frame_result["key_material_receipt"]["combined_frame_sha256"] = frame_digest
    result_path.write_bytes(_canonical(frame_result))
    with pytest.raises(OpenFHEQueryRunnerError, match="typed key frame"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda result: result.update(second_batch_row_zero=False), "binding/status"),
        (
            lambda result: result["operation_counts"].update(encrypt=5),
            "operation counts",
        ),
        (
            lambda result: result["decrypted_results"][0]["values"].__setitem__(0, 0),
            "differs from the oracle",
        ),
        (
            lambda result: result.update(publication_authority=True),
            "binding/status",
        ),
    ),
)
def test_verifier_rejects_false_passes(
    tmp_path: Path,
    mutation: object,
    message: str,
) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )
    assert callable(mutation)
    mutation(result)
    result_path.write_bytes(_canonical(result))

    with pytest.raises(OpenFHEQueryRunnerError, match=message):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )


def test_verifier_rejects_object_digest_and_directory_aliasing(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, _result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )
    first_object = object_root / "object-000000.bin"
    original_key_frame = first_object.read_bytes()
    first_object.write_bytes(b"same-size-tampered-object!!")

    with pytest.raises(OpenFHEQueryRunnerError, match="size/type changed|digest differs"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )

    first_object.write_bytes(original_key_frame)
    alias = tmp_path / "objects-alias"
    alias.symlink_to(object_root, target_is_directory=True)
    with pytest.raises(OpenFHEQueryRunnerError, match="direct directory"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=alias,
            expected_output=(31, 44),
        )


def test_verifier_rejects_result_symlink(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, _result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )
    alias = tmp_path / "result-alias.json"
    alias.symlink_to(result_path)

    with pytest.raises(OpenFHEQueryRunnerError, match="result is unavailable"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=alias,
            object_root=object_root,
            expected_output=(31, 44),
        )


def test_verifier_rejects_noncanonical_result_json(tmp_path: Path) -> None:
    bundle, prepared = _bundle_and_prepared(tmp_path)
    request_bytes = build_ordinary_openfhe_query_request(bundle, prepared)
    result_path, object_root, result = _write_result_fixture(
        tmp_path, bundle, prepared, request_bytes
    )
    result_path.write_text(json.dumps(result, indent=2))

    with pytest.raises(OpenFHEQueryRunnerError, match="not canonical JSON"):
        verify_ordinary_openfhe_query_result(
            bundle,
            prepared,
            request_bytes=request_bytes,
            result_path=result_path,
            object_root=object_root,
            expected_output=(31, 44),
        )


def test_cpp_runner_contract_uses_real_openfhe_operations_and_serialization() -> None:
    cmake = (ROOT / "cpp/CMakeLists.txt").read_text()
    source = (ROOT / "cpp/openfhe_query_runner.cpp").read_text()

    assert "add_executable(openfhe_query_runner openfhe_query_runner.cpp)" in cmake
    for token in (
        "context->Encrypt",
        "context->EvalMultNoRelin",
        "context->Relinearize",
        "context->EvalRotate",
        "context->EvalMult(source, mask->second)",
        "context->EvalAdd",
        "context->Decrypt",
        "Serial::Serialize",
        "SerializeEvalMultKey",
        "SerializeEvalAutomorphismKey",
        "BuildCombinedEvaluationKeyFrame",
        "D1BKEY01",
        "D1BRDY01",
        "D1BDON01",
        "control-write-fd",
        "control-read-fd",
        "key_generation_session_sha256",
    ):
        assert token in source
    assert "dynamic-cssc-openfhe-key-bundle-v1" not in source
    assert 'HashUtil::HashString(CanonicalJson(plan) + "\\n")' in source
    assert "AppendFramed" not in source
    assert "const auto secretKeyBytes = routeAProducer" in source
    assert "RunLegacyProducer(args)" in source
    assert "publication_authority" in source
    assert "formal_parameter_claim_allowed" in source
