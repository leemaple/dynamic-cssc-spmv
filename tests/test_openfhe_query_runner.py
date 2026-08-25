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
    OpenFHEQueryRunnerError,
    build_ordinary_openfhe_query_request,
    pre_admission_day2_openfhe_key_generation_plan,
    verify_ordinary_openfhe_query_result,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.plaintext_oracle import execute_compiled_query
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
    Day1BCombinedEvaluationKeyFrame,
)
from dynamic_cssc.query_compiler import compile_query
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
    bundle = bind_ordinary_execution(
        compile_query((second, first), f1m_policy="overlap-only")
    )
    prepared = prepare_ordinary_query(
        bundle,
        query_id="ordinary-openfhe-query-1",
        vector=(5, 7, 11, 13),
        modulus=65537,
        ledger=SQLiteMaskBindingLedger(tmp_path / "ordinary-openfhe-ledger.sqlite3"),
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


def _write_result_fixture(
    tmp_path: Path,
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    request_bytes: bytes,
) -> tuple[Path, Path, dict[str, object]]:
    request = json.loads(request_bytes)
    ciphertext_inputs = {
        item["ciphertext_id"]: tuple(item["values"])
        for item in request["ciphertext_values"]
    }
    returned = execute_compiled_query(
        bundle.compiled,
        expected_f1m_policy="overlap-only",
        ciphertext_inputs=ciphertext_inputs,
        plaintext_masks={
            item["mask_id"]: tuple(item["values"])
            for item in request["program"]["plaintext_masks"]
        },
        modulus=prepared.modulus,
    )
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
        ("query-result-ciphertexts", result_id)
        for result_id in request["program"]["result_ids"]
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
        "input_binding_sha256": runner_contract._key_material_input_binding_sha256(
            request
        ),
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
        "operation_counts": {
            "add_f1m_mask": 2,
            "decrypt": 2,
            "encrypt": 6,
            "eval_add_ciphertext": 0,
            "eval_mult_plaintext_mask": 2,
            "eval_rotate": 0,
            "multiply_ciphertexts": 2,
            "relinearize": 2,
            "return_result": 2,
        },
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
    assert request["key_generation_plan"]["rotation_key_plan"][
        "required_exact_indices"
    ] == [1]
    assert request["bindings"]["cloud_program_sha256"] == bundle.compiled.cloud_program_digest
    assert [item["ciphertext_id"] for item in request["ciphertext_values"]] == sorted(
        item["ciphertext_id"] for item in request["ciphertext_values"]
    )
    assert {item["f1m_kind"] for item in request["ciphertext_values"]} == {
        None,
        "random-zero-sum",
    }


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
    assert request["key_generation_plan"]["rotation_key_plan_sha256"] == hashlib.sha256(
        day2_plan_bytes
    ).hexdigest()
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
        changed = json.dumps(
            dict(reversed(tuple(plan.items()))),
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
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
        runner_contract._key_generation_session_sha256(
            segment_splice["key_material_receipt"]
        )
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
    assert "SerializeOpenFHE(keyPair.secretKey" not in source
    assert "publication_authority" in source
    assert "formal_parameter_claim_allowed" in source
