"""Private request and result contract for the generic OpenFHE query runner.

The runner executes one already-compiled query DAG.  It does not choose a
candidate, mutate publication state, grant parameter authority, or consume a
prepared-query ledger commitment.  Those remain controller responsibilities.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.cloud_execution_plan import (
    AddCiphertexts,
    AddF1MMask,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    canonical_cloud_program_payload,
    canonical_execution_binding_payload,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    PreparedOrdinaryQuery,
    canonical_ordinary_query_preparation_bytes,
)
from dynamic_cssc.plaintext_oracle import reconstruct_output

OPENFHE_QUERY_REQUEST_SCHEMA = "dynamic-cssc-full-openfhe-query-request-v1"
OPENFHE_QUERY_RESULT_SCHEMA = "dynamic-cssc-full-openfhe-query-result-v1"
OPENFHE_QUERY_PARAMETER_PROFILE = "day1b-full-query-pre-admission-depth2-0-0-v1"

_PARAMS_PATH = "config/params_manifest.json"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_BYTES_MAXIMUM = 128 * 1024 * 1024
_OPERATION_COUNT_KEYS = (
    "add_f1m_mask",
    "decrypt",
    "encrypt",
    "eval_add_ciphertext",
    "eval_mult_plaintext_mask",
    "multiply_ciphertexts",
    "eval_rotate",
    "relinearize",
    "return_result",
)


class OpenFHEQueryRunnerError(ValueError):
    """A runner request, result, or retained serialized object is not exact."""


@dataclass(frozen=True, slots=True)
class OpenFHESerializedObjectReceipt:
    category: str
    subject_id: str
    relative_path: str
    byte_count: int
    sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedOpenFHEQueryResult:
    request_sha256: str
    operation_counts: tuple[tuple[str, int], ...]
    decrypted_results: tuple[tuple[str, tuple[int, ...]], ...]
    reconstructed_output: tuple[int, ...]
    serialized_objects: tuple[OpenFHESerializedObjectReceipt, ...]
    second_batch_row_zero: bool
    publication_authority: bool


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
        raise OpenFHEQueryRunnerError("OpenFHE runner value is not canonical JSON") from error
    return rendered.encode("ascii")


def _decode_json(content: bytes, *, field: str) -> dict[str, object]:
    if type(content) is not bytes or not content:
        raise OpenFHEQueryRunnerError(f"{field} must be nonempty exact bytes")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, member in pairs:
            if key in value:
                raise OpenFHEQueryRunnerError(f"{field} contains duplicate JSON keys")
            value[key] = member
        return value

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                OpenFHEQueryRunnerError(f"{field} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OpenFHEQueryRunnerError(f"{field} is not canonical ASCII JSON") from error
    if type(value) is not dict:
        raise OpenFHEQueryRunnerError(f"{field} must be one JSON object")
    return value


def _strict_nonnegative(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise OpenFHEQueryRunnerError(f"{field} must be a nonnegative strict integer")
    return value


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise OpenFHEQueryRunnerError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _repository_openfhe_profile(repository_root: Path) -> dict[str, object]:
    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be a pathlib.Path")
    path = repository_root / _PARAMS_PATH
    try:
        content = path.read_bytes()
    except OSError as error:
        raise OpenFHEQueryRunnerError(
            "repository OpenFHE parameter manifest is unavailable"
        ) from error
    document = _decode_json(content, field="OpenFHE parameter manifest")
    openfhe = document.get("openfhe")
    if type(openfhe) is not dict:
        raise OpenFHEQueryRunnerError("parameter manifest lacks the OpenFHE object")
    expected_identity = {
        "batch_size": 8192,
        "bfv_multiplication_technique": "HPSPOVERQLEVELED",
        "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "key_switch_technique": "HYBRID",
        "plaintext_modulus": 65537,
        "repository": "https://github.com/openfheorg/openfhe-development.git",
        "ring_dimension": 8192,
        "scheme": "BFVRNS",
        "security_level": "HEStd_128_classic",
        "version": "1.5.1",
    }
    if any(openfhe.get(key) != value for key, value in expected_identity.items()):
        raise OpenFHEQueryRunnerError(
            "repository OpenFHE identity differs from the frozen baseline"
        )
    profiles = openfhe.get("noise_budget_profiles")
    profile = profiles.get("day2_mult_only") if type(profiles) is dict else None
    if type(profile) is not dict or {
        "multiplicative_depth": profile.get("multiplicative_depth"),
        "eval_add_count": profile.get("eval_add_count"),
        "key_switch_count": profile.get("key_switch_count"),
    } != {
        "multiplicative_depth": 2,
        "eval_add_count": 0,
        "key_switch_count": 0,
    }:
        raise OpenFHEQueryRunnerError("pre-admission full-query noise profile changed")
    mixed = openfhe.get("mixed_workload_parameterization")
    if type(mixed) is not dict or (
        mixed.get("status") != "unfrozen"
        or mixed.get("formal_parameter_claim_allowed") is not False
    ):
        raise OpenFHEQueryRunnerError("mixed-circuit parameter authority is not the exact HOLD")
    return {
        "authority_state": "HOLD-mixed-circuit-parameter-gate",
        "batch_size": expected_identity["batch_size"],
        "compiler_profile": OPENFHE_QUERY_PARAMETER_PROFILE,
        "eval_add_count": 0,
        "formal_parameter_claim_allowed": False,
        "key_switch_count": 0,
        "key_switch_technique": expected_identity["key_switch_technique"],
        "multiplication_technique": expected_identity["bfv_multiplication_technique"],
        "multiplicative_depth": 2,
        "openfhe_commit": expected_identity["commit"],
        "openfhe_repository": expected_identity["repository"],
        "openfhe_version": expected_identity["version"],
        "plaintext_modulus": expected_identity["plaintext_modulus"],
        "ring_dimension": expected_identity["ring_dimension"],
        "scheme": expected_identity["scheme"],
        "security_level": expected_identity["security_level"],
    }


def _ordinary_ciphertext_values(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> list[dict[str, object]]:
    compiled = bundle.compiled
    values = {spec.value_ciphertext_id: spec.values for spec in compiled.operand_specs}
    values.update({operand.ciphertext_id: operand.values for operand in prepared.query_operands})
    values.update({operand.ciphertext_id: operand.values for operand in prepared.f1m_operands})
    f1m_kind = {operand.ciphertext_id: operand.kind for operand in prepared.f1m_operands}
    expected = {operand.ciphertext_id for operand in compiled.cloud_plan.program.ciphertext_inputs}
    if set(values) != expected:
        raise OpenFHEQueryRunnerError(
            "ordinary private values do not exactly cover ciphertext inputs"
        )
    result: list[dict[str, object]] = []
    for operand in sorted(
        compiled.cloud_plan.program.ciphertext_inputs,
        key=lambda item: item.ciphertext_id,
    ):
        vector = values[operand.ciphertext_id]
        if type(vector) is not tuple or len(vector) != operand.length or any(
            type(value) is not int for value in vector
        ):
            raise OpenFHEQueryRunnerError("ordinary ciphertext input vector is not exact")
        kind = f1m_kind.get(operand.ciphertext_id)
        if (operand.role == "f1m-mask") != (kind is not None):
            raise OpenFHEQueryRunnerError("F1-M kind does not match the ciphertext input role")
        result.append(
            {
                "ciphertext_id": operand.ciphertext_id,
                "f1m_kind": kind,
                "role": operand.role,
                "values": list(vector),
            }
        )
    return result


def build_ordinary_openfhe_query_request(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    repository_root: Path | None = None,
) -> bytes:
    """Build one private, non-authorizing request for the generic C++ runner."""

    preparation_bytes = canonical_ordinary_query_preparation_bytes(bundle, prepared)
    compiled = bundle.compiled
    root = (
        Path(__file__).resolve().parents[2]
        if repository_root is None
        else repository_root
    )
    profile = _repository_openfhe_profile(root)
    if prepared.modulus != profile["plaintext_modulus"]:
        raise OpenFHEQueryRunnerError(
            "prepared query modulus differs from the repository OpenFHE profile"
        )
    if compiled.cloud_plan.program.slot_count > profile["batch_size"]:
        raise OpenFHEQueryRunnerError("typed query slot count exceeds the OpenFHE batch size")
    execution_binding = canonical_execution_binding_payload(compiled.cloud_plan.binding)
    request = {
        "bindings": {
            "cloud_program_sha256": compiled.cloud_program_digest,
            "execution_binding": execution_binding,
            "execution_binding_sha256": compiled.execution_binding_digest,
            "ordinary_private_plan_sha256": bundle.private_plan_digest,
            "ordinary_query_preparation_sha256": hashlib.sha256(
                preparation_bytes
            ).hexdigest(),
        },
        "ciphertext_values": _ordinary_ciphertext_values(bundle, prepared),
        "openfhe": profile,
        "program": canonical_cloud_program_payload(compiled.cloud_plan.program),
        "schema_version": OPENFHE_QUERY_REQUEST_SCHEMA,
    }
    return _canonical_bytes(request)


def _expected_operation_counts(bundle: OrdinaryExecutionBundle) -> dict[str, int]:
    program = bundle.compiled.cloud_plan.program
    counts: Counter[str] = Counter()
    for node in program.nodes:
        if isinstance(node, MultiplyCiphertexts):
            counts["multiply_ciphertexts"] += 1
        elif isinstance(node, Relinearize):
            counts["relinearize"] += 1
        elif isinstance(node, Rotate):
            counts["eval_rotate"] += 1
        elif isinstance(node, MultiplyPlaintextMask):
            counts["eval_mult_plaintext_mask"] += 1
        elif isinstance(node, AddCiphertexts):
            counts["eval_add_ciphertext"] += 1
        elif isinstance(node, AddF1MMask):
            counts["add_f1m_mask"] += 1
        elif isinstance(node, ReturnResult):
            counts["return_result"] += 1
        else:  # pragma: no cover - closed compiler vocabulary
            raise OpenFHEQueryRunnerError("typed query contains an unsupported operation")
    counts["encrypt"] = len(program.ciphertext_inputs)
    counts["decrypt"] = len(program.result_ids)
    return {key: counts[key] for key in _OPERATION_COUNT_KEYS}


def _expected_serialized_subjects(
    request: dict[str, object],
) -> tuple[tuple[str, str], ...]:
    ciphertext_values = request["ciphertext_values"]
    program = request["program"]
    assert type(ciphertext_values) is list and type(program) is dict
    subjects: list[tuple[str, str]] = [
        ("one-time-evaluation-key-material", "evaluation-key-material")
    ]
    category_by_role = {
        "query": "query-query-ciphertexts",
        "value": "update-publication-ciphertexts",
    }
    for value in ciphertext_values:
        assert type(value) is dict
        role = value["role"]
        if role == "f1m-mask":
            category = {
                "random-zero-sum": "query-f1m-random-mask-ciphertexts",
                "encrypted-zero-dummy": (
                    "query-f1m-encrypted-zero-dummy-ciphertexts"
                ),
            }[value["f1m_kind"]]
        else:
            category = category_by_role[role]
        subjects.append((category, value["ciphertext_id"]))
    result_ids = program["result_ids"]
    assert type(result_ids) is list
    subjects.extend(("query-result-ciphertexts", value) for value in result_ids)
    return tuple(subjects)


def _read_exact_member(
    directory_descriptor: int,
    relative_path: str,
    *,
    byte_count: int,
    sha256: str,
) -> None:
    try:
        descriptor = os.open(
            relative_path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise OpenFHEQueryRunnerError("serialized OpenFHE object is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != byte_count:
            raise OpenFHEQueryRunnerError("serialized OpenFHE object size/type changed")
        hasher = hashlib.sha256()
        remaining = byte_count
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                raise OpenFHEQueryRunnerError("serialized OpenFHE object ended early")
            hasher.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise OpenFHEQueryRunnerError("serialized OpenFHE object grew while hashing")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
        ):
            raise OpenFHEQueryRunnerError("serialized OpenFHE object changed while hashing")
        if hasher.hexdigest() != sha256:
            raise OpenFHEQueryRunnerError("serialized OpenFHE object digest differs")
    finally:
        os.close(descriptor)


def _read_bounded_exact_file(path: Path, *, maximum: int, field: str) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise OpenFHEQueryRunnerError(f"{field} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OpenFHEQueryRunnerError(f"{field} is not a regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise OpenFHEQueryRunnerError(f"{field} exceeds its fixed byte bounds")
        content = bytearray()
        while len(content) < before.st_size:
            block = os.read(descriptor, min(before.st_size - len(content), 1024 * 1024))
            if not block:
                raise OpenFHEQueryRunnerError(f"{field} ended early")
            content.extend(block)
        if os.read(descriptor, 1):
            raise OpenFHEQueryRunnerError(f"{field} grew while reading")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
        ):
            raise OpenFHEQueryRunnerError(f"{field} changed while reading")
        return bytes(content)
    finally:
        os.close(descriptor)


def verify_ordinary_openfhe_query_result(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
    repository_root: Path | None = None,
) -> VerifiedOpenFHEQueryResult:
    """Verify one C++ result plus every retained serialized-object byte stream."""

    expected_request = build_ordinary_openfhe_query_request(
        bundle,
        prepared,
        repository_root=repository_root,
    )
    if request_bytes != expected_request:
        raise OpenFHEQueryRunnerError("runner request differs from the canonical ordinary request")
    if not isinstance(result_path, Path) or not isinstance(object_root, Path):
        raise TypeError("result_path and object_root must be pathlib.Path values")
    raw = _read_bounded_exact_file(
        result_path,
        maximum=_RESULT_BYTES_MAXIMUM,
        field="OpenFHE query result",
    )
    result = _decode_json(raw, field="OpenFHE query result")
    if raw != _canonical_bytes(result):
        raise OpenFHEQueryRunnerError("OpenFHE query result is not canonical JSON")
    expected_result_keys = {
        "bindings",
        "decrypted_results",
        "openfhe",
        "operation_counts",
        "publication_authority",
        "request_sha256",
        "schema_version",
        "second_batch_row_zero",
        "serialized_objects",
        "status",
    }
    if set(result) != expected_result_keys:
        raise OpenFHEQueryRunnerError("OpenFHE query result keys are not exact")
    request = _decode_json(request_bytes, field="OpenFHE query request")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    if (
        result["schema_version"] != OPENFHE_QUERY_RESULT_SCHEMA
        or result["status"] != "pass"
        or result["request_sha256"] != request_sha256
        or result["bindings"] != request["bindings"]
        or result["openfhe"] != request["openfhe"]
        or result["publication_authority"] is not False
        or result["second_batch_row_zero"] is not True
    ):
        raise OpenFHEQueryRunnerError("OpenFHE query result binding/status is not exact")
    operation_counts = result["operation_counts"]
    if type(operation_counts) is not dict or set(operation_counts) != set(
        _OPERATION_COUNT_KEYS
    ):
        raise OpenFHEQueryRunnerError("OpenFHE operation-count vocabulary is not exact")
    observed_counts = {
        key: _strict_nonnegative(operation_counts[key], field=f"operation count {key}")
        for key in _OPERATION_COUNT_KEYS
    }
    if observed_counts != _expected_operation_counts(bundle):
        raise OpenFHEQueryRunnerError("OpenFHE operation counts differ from the typed DAG")

    decrypted = result["decrypted_results"]
    program = bundle.compiled.cloud_plan.program
    if type(decrypted) is not list or len(decrypted) != len(program.result_ids):
        raise OpenFHEQueryRunnerError("OpenFHE decrypted result cardinality changed")
    decrypted_by_id: dict[str, tuple[int, ...]] = {}
    for index, item in enumerate(decrypted):
        if type(item) is not dict or set(item) != {"result_id", "values"}:
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result keys are not exact")
        result_id = item["result_id"]
        values = item["values"]
        if result_id != program.result_ids[index] or type(values) is not list or len(
            values
        ) != program.slot_count:
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result identity/length changed")
        vector = tuple(values)
        if any(
            type(value) is not int or not 0 <= value < prepared.modulus for value in vector
        ):
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result is outside Z_t")
        decrypted_by_id[result_id] = vector
    returned_shares = {
        (route.component_id, route.output_block_id): decrypted_by_id[route.result_id]
        for route in bundle.compiled.result_routes
    }
    reconstructed = reconstruct_output(
        bundle.compiled.output_plan,
        returned_shares,
        modulus=prepared.modulus,
    )
    if (
        type(expected_output) is not tuple
        or any(type(value) is not int for value in expected_output)
        or len(expected_output) != len(reconstructed)
        or reconstructed != tuple(value % prepared.modulus for value in expected_output)
    ):
        raise OpenFHEQueryRunnerError("OpenFHE reconstructed output differs from the oracle")

    serialized = result["serialized_objects"]
    expected_subjects = _expected_serialized_subjects(request)
    if type(serialized) is not list or len(serialized) != len(expected_subjects):
        raise OpenFHEQueryRunnerError("OpenFHE serialized-object cardinality changed")
    try:
        path_status = object_root.lstat()
    except OSError as error:
        raise OpenFHEQueryRunnerError("OpenFHE serialized-object root is unavailable") from error
    if not stat.S_ISDIR(path_status.st_mode) or stat.S_ISLNK(path_status.st_mode):
        raise OpenFHEQueryRunnerError("OpenFHE serialized-object root is not a direct directory")
    try:
        directory_descriptor = os.open(
            object_root,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise OpenFHEQueryRunnerError("OpenFHE serialized-object root is unavailable") from error
    try:
        root_status = os.fstat(directory_descriptor)
        root_identity = (
            root_status.st_dev,
            root_status.st_ino,
            root_status.st_mode,
            root_status.st_nlink,
        )
        if not stat.S_ISDIR(root_status.st_mode) or (
            path_status.st_dev,
            path_status.st_ino,
            path_status.st_mode,
            path_status.st_nlink,
        ) != root_identity:
            raise OpenFHEQueryRunnerError(
                "OpenFHE serialized-object root is not a direct directory"
            )
        receipts: list[OpenFHESerializedObjectReceipt] = []
        for index, (item, expected_subject) in enumerate(
            zip(serialized, expected_subjects, strict=True)
        ):
            if type(item) is not dict or set(item) != {
                "byte_count",
                "category",
                "relative_path",
                "sha256",
                "subject_id",
            }:
                raise OpenFHEQueryRunnerError("OpenFHE serialized-object keys are not exact")
            relative_path = f"object-{index:06d}.bin"
            byte_count = _strict_nonnegative(
                item["byte_count"],
                field="serialized object byte_count",
            )
            digest = _sha256(item["sha256"], field="serialized object sha256")
            if (
                (item["category"], item["subject_id"]) != expected_subject
                or item["relative_path"] != relative_path
                or byte_count <= 0
            ):
                raise OpenFHEQueryRunnerError("OpenFHE serialized-object identity changed")
            _read_exact_member(
                directory_descriptor,
                relative_path,
                byte_count=byte_count,
                sha256=digest,
            )
            receipts.append(
                OpenFHESerializedObjectReceipt(
                    category=item["category"],
                    subject_id=item["subject_id"],
                    relative_path=relative_path,
                    byte_count=byte_count,
                    sha256=digest,
                )
            )
        try:
            observed_names = set(os.listdir(directory_descriptor))
        except OSError as error:
            raise OpenFHEQueryRunnerError(
                "OpenFHE serialized-object root is unavailable"
            ) from error
        if observed_names != {receipt.relative_path for receipt in receipts}:
            raise OpenFHEQueryRunnerError(
                "OpenFHE serialized-object root has missing or extra members"
            )
        final_status = os.fstat(directory_descriptor)
        if (
            final_status.st_dev,
            final_status.st_ino,
            final_status.st_mode,
            final_status.st_nlink,
        ) != root_identity:
            raise OpenFHEQueryRunnerError(
                "OpenFHE serialized-object root changed during verification"
            )
    finally:
        os.close(directory_descriptor)
    return VerifiedOpenFHEQueryResult(
        request_sha256=request_sha256,
        operation_counts=tuple((key, observed_counts[key]) for key in _OPERATION_COUNT_KEYS),
        decrypted_results=tuple(
            (result_id, decrypted_by_id[result_id]) for result_id in program.result_ids
        ),
        reconstructed_output=reconstructed,
        serialized_objects=tuple(receipts),
        second_batch_row_zero=result["second_batch_row_zero"],
        publication_authority=False,
    )


__all__ = (
    "OPENFHE_QUERY_PARAMETER_PROFILE",
    "OPENFHE_QUERY_REQUEST_SCHEMA",
    "OPENFHE_QUERY_RESULT_SCHEMA",
    "OpenFHEQueryRunnerError",
    "OpenFHESerializedObjectReceipt",
    "VerifiedOpenFHEQueryResult",
    "build_ordinary_openfhe_query_request",
    "verify_ordinary_openfhe_query_result",
)
