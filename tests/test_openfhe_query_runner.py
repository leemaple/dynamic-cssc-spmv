from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    OPENFHE_QUERY_PARAMETER_PROFILE,
    OPENFHE_QUERY_REQUEST_SCHEMA,
    OPENFHE_QUERY_RESULT_SCHEMA,
    OpenFHEQueryRunnerError,
    build_ordinary_openfhe_query_request,
    verify_ordinary_openfhe_query_result,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.plaintext_oracle import execute_compiled_query
from dynamic_cssc.query_compiler import compile_query

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
    for index, (category, subject_id) in enumerate(subjects):
        relative_path = f"object-{index:06d}.bin"
        content = f"test-only-openfhe-object-{index}".encode()
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
    result = {
        "bindings": request["bindings"],
        "decrypted_results": [
            {"result_id": result_id, "values": list(returned[result_id])}
            for result_id in request["program"]["result_ids"]
        ],
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
    )

    assert verified.reconstructed_output == (31, 44)
    assert len(verified.serialized_objects) == 9
    assert verified.second_batch_row_zero is True
    assert verified.publication_authority is False


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

    first_object.write_bytes(b"test-only-openfhe-object-0")
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
    ):
        assert token in source
    assert "SerializeOpenFHE(keyPair.secretKey" not in source
    assert "publication_authority" in source
    assert "formal_parameter_claim_allowed" in source
