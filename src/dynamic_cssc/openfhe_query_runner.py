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
    CloudExecutionPlan,
    CloudProgram,
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
from dynamic_cssc.output_plan import OutputPlan
from dynamic_cssc.plaintext_oracle import reconstruct_output
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
    DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES,
    Day1BCombinedEvaluationKeyFrameStreamReceipt,
    Day1BCombinedEvaluationKeyFrameStreamValidator,
    Day1BCombinedEvaluationKeyFramingError,
)
from dynamic_cssc.strong_execution import (
    PreparedStrongQuery,
    StrongExecutionBundle,
    canonical_strong_query_preparation_bytes,
)

OPENFHE_QUERY_REQUEST_SCHEMA = "dynamic-cssc-full-openfhe-query-request-v4"
OPENFHE_QUERY_RESULT_SCHEMA = "dynamic-cssc-full-openfhe-query-result-v4"
ROUTE_A_OPENFHE_PRODUCER_RESULT_SCHEMA = "dynamic-cssc-route-a-openfhe-producer-result-v1"
ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA = "dynamic-cssc-route-a-openfhe-replay-result-v1"
OPENFHE_QUERY_PARAMETER_PROFILE = "day1b-full-query-pre-admission-depth2-0-0-v1"
OPENFHE_KEY_GENERATION_PLAN_SCHEMA = "dynamic-cssc-openfhe-key-generation-plan-v2"
OPENFHE_QUERY_DERIVED_ROTATION_KEY_PLAN_SCHEMA = (
    "dynamic-cssc-openfhe-query-derived-rotation-key-plan-v1"
)
OPENFHE_KEY_MATERIAL_INPUT_BINDING_SCHEMA = "dynamic-cssc-openfhe-key-material-input-binding-v2"
OPENFHE_KEY_GENERATION_SESSION_SCHEMA = "dynamic-cssc-openfhe-key-generation-session-v2"
OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA = "dynamic-cssc-openfhe-key-material-receipt-v2"

_DAY2_ROTATION_KEY_PLAN_SCHEMA = "dynamic-cssc-publication-rotation-key-plan-v2"

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
_ROUTE_A_CLOUD_OPERATION_KEYS = (
    "add_f1m_mask",
    "eval_add_ciphertext",
    "eval_mult_plaintext_mask",
    "eval_rotate",
    "multiply_ciphertexts",
    "relinearize",
    "return_result",
)
_ROUTE_A_LIFECYCLE_OPERATION_KEYS = (
    "automorphism_key_deserialize_count",
    "automorphism_key_generation_count",
    "context_generation_count",
    "crypto_context_deserialize_count",
    "decrypt_count",
    "encrypt_count",
    "eval_mult_key_deserialize_count",
    "eval_mult_key_generation_count",
    "input_ciphertext_deserialize_count",
    "key_generation_count",
    "public_key_deserialize_count",
    "secret_key_deserialize_count",
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
class OpenFHEKeyGenerationPlan:
    """One canonical non-authorizing rotation plan presented to the C++ runner."""

    rotation_key_plan_bytes: bytes
    rotation_key_plan_sha256: str
    required_exact_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        plan = _decode_json(self.rotation_key_plan_bytes, field="rotation key plan")
        if self.rotation_key_plan_bytes != _canonical_rotation_key_plan_bytes(plan):
            raise OpenFHEQueryRunnerError("rotation key plan is not canonical JSON")
        required = _validate_rotation_key_plan_document(plan)
        if (
            self.rotation_key_plan_sha256
            != hashlib.sha256(self.rotation_key_plan_bytes).hexdigest()
            or self.required_exact_indices != required
        ):
            raise OpenFHEQueryRunnerError("rotation key plan typed binding changed")

    def to_request_document(self) -> dict[str, object]:
        return {
            "authority_state": "pre-admission-only",
            "eval_mult_key_required": True,
            "formal_authority_granted": False,
            "publication_authority": False,
            "rotation_key_plan": _decode_json(
                self.rotation_key_plan_bytes,
                field="rotation key plan",
            ),
            "rotation_key_plan_sha256": self.rotation_key_plan_sha256,
            "schema_version": OPENFHE_KEY_GENERATION_PLAN_SCHEMA,
        }


@dataclass(frozen=True, slots=True)
class OpenFHEKeyMaterialReceipt:
    combined_frame_byte_count: int
    combined_frame_sha256: str
    crypto_context_parameter_sha256: str
    crypto_context_serialization_sha256: str
    eval_mult_segment_byte_count: int
    eval_mult_segment_sha256: str
    generated_exact_indices: tuple[int, ...]
    input_binding_sha256: str
    key_generation_plan_sha256: str
    key_generation_session_sha256: str
    public_key_sha256: str
    request_sha256: str
    required_exact_indices: tuple[int, ...]
    rotation_key_plan_sha256: str
    rotation_segment_byte_count: int
    rotation_segment_sha256: str

    def to_document(self) -> dict[str, object]:
        return {
            "combined_frame_byte_count": self.combined_frame_byte_count,
            "combined_frame_sha256": self.combined_frame_sha256,
            "crypto_context_parameter_sha256": self.crypto_context_parameter_sha256,
            "crypto_context_serialization_sha256": (self.crypto_context_serialization_sha256),
            "eval_mult_segment_byte_count": self.eval_mult_segment_byte_count,
            "eval_mult_segment_sha256": self.eval_mult_segment_sha256,
            "formal_authority_granted": False,
            "framing_schema": DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
            "generated_exact_indices": list(self.generated_exact_indices),
            "input_binding_sha256": self.input_binding_sha256,
            "key_generation_plan_sha256": self.key_generation_plan_sha256,
            "key_generation_session_sha256": self.key_generation_session_sha256,
            "public_key_sha256": self.public_key_sha256,
            "publication_authority": False,
            "request_sha256": self.request_sha256,
            "required_exact_indices": list(self.required_exact_indices),
            "rotation_key_plan_sha256": self.rotation_key_plan_sha256,
            "rotation_segment_byte_count": self.rotation_segment_byte_count,
            "rotation_segment_sha256": self.rotation_segment_sha256,
            "same_crypto_context_generation_session": True,
            "schema_version": OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA,
            "status": "verified-by-runner-pre-admission-only",
        }


@dataclass(frozen=True, slots=True)
class VerifiedOpenFHEQueryResult:
    request_sha256: str
    operation_counts: tuple[tuple[str, int], ...]
    decrypted_results: tuple[tuple[str, tuple[int, ...]], ...]
    reconstructed_output: tuple[int, ...]
    key_material_receipt: OpenFHEKeyMaterialReceipt
    serialized_objects: tuple[OpenFHESerializedObjectReceipt, ...]
    second_batch_row_zero: bool
    publication_authority: bool


@dataclass(frozen=True, slots=True)
class VerifiedRouteAOpenFHEProducerResult:
    request_sha256: str
    cloud_program_operation_inventory: tuple[tuple[str, int], ...]
    lifecycle_operation_inventory: tuple[tuple[str, int], ...]
    decrypted_results: tuple[tuple[str, tuple[int, ...]], ...]
    reconstructed_output: tuple[int, ...]
    key_material_receipt: OpenFHEKeyMaterialReceipt
    serialized_objects: tuple[OpenFHESerializedObjectReceipt, ...]
    second_batch_row_zero: bool
    publication_authority: bool


@dataclass(frozen=True, slots=True)
class VerifiedRouteAOpenFHEReplayResult:
    request_sha256: str
    package_manifest_sha256: str
    cloud_program_operation_inventory: tuple[tuple[str, int], ...]
    lifecycle_operation_inventory: tuple[tuple[str, int], ...]
    decrypted_results: tuple[tuple[str, tuple[int, ...]], ...]
    reconstructed_output: tuple[int, ...]
    serialized_objects: tuple[OpenFHESerializedObjectReceipt, ...]
    second_batch_row_zero: bool
    publication_authority: bool


@dataclass(frozen=True, slots=True)
class _OpenFHEResultRoute:
    result_id: str
    component_id: str
    output_block_id: str


@dataclass(frozen=True, slots=True)
class _PreparedOpenFHEQueryView:
    execution_kind: str
    cloud_plan: CloudExecutionPlan
    output_plan: OutputPlan
    result_routes: tuple[_OpenFHEResultRoute, ...]
    private_plan_sha256: str
    query_preparation_sha256: str
    ciphertext_values: tuple[dict[str, object], ...]
    modulus: int


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


def _canonical_rotation_key_plan_bytes(value: object) -> bytes:
    """Render the exact LF-terminated bytes used by formal Day 2 artifacts."""

    return _canonical_bytes(value) + b"\n"


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


def _strict_exact_indices(value: object, *, field: str) -> tuple[int, ...]:
    if type(value) is not list or not value or any(type(item) is not int for item in value):
        raise OpenFHEQueryRunnerError(f"{field} must be one nonempty strict-integer list")
    indices = tuple(value)
    if (
        list(indices) != sorted(set(indices))
        or any(index == 0 or not -4095 <= index <= 4095 for index in indices)
        or len({index % 4096 for index in indices}) != len(indices)
    ):
        raise OpenFHEQueryRunnerError(
            f"{field} must be canonical, nonzero, in range, and modulo-distinct"
        )
    return indices


def _validate_rotation_key_plan_document(value: dict[str, object]) -> tuple[int, ...]:
    schema = value.get("schema_version")
    if schema == OPENFHE_QUERY_DERIVED_ROTATION_KEY_PLAN_SCHEMA:
        if set(value) != {
            "coverage_kind",
            "required_exact_indices",
            "schema_version",
            "source_cloud_program_sha256",
        }:
            raise OpenFHEQueryRunnerError("query-derived rotation key-plan keys changed")
        if value["coverage_kind"] not in {
            "exact-program-rotation-catalog",
            "minimum-nonempty-program-cover",
        }:
            raise OpenFHEQueryRunnerError("query-derived rotation coverage kind changed")
        _sha256(
            value["source_cloud_program_sha256"],
            field="query-derived source cloud program",
        )
        return _strict_exact_indices(
            value["required_exact_indices"],
            field="query-derived required rotation indices",
        )
    if schema != _DAY2_ROTATION_KEY_PLAN_SCHEMA:
        raise OpenFHEQueryRunnerError("rotation key-plan schema is unsupported")
    if set(value) != {
        "composite_decompositions",
        "day1a_authority_receipt_sha256",
        "day1a_inventory_sha256",
        "effective_slots",
        "eval_rotate_case_ids",
        "inventory_source_schema_version",
        "key_plan_kind",
        "planned_exact_indices",
        "required_exact_indices",
        "schema_version",
    }:
        raise OpenFHEQueryRunnerError("Day 2 rotation key-plan keys changed")
    if (
        type(value["inventory_source_schema_version"]) is not str
        or not value["inventory_source_schema_version"]
        or value["effective_slots"] != 4096
        or value["key_plan_kind"] != "direct-exact-index-v1"
        or type(value["composite_decompositions"]) is not list
        or value["composite_decompositions"]
    ):
        raise OpenFHEQueryRunnerError("Day 2 rotation key-plan structure changed")
    _sha256(
        value["day1a_authority_receipt_sha256"],
        field="Day1A authority receipt",
    )
    _sha256(value["day1a_inventory_sha256"], field="Day1A rotation inventory")
    required = _strict_exact_indices(
        value["required_exact_indices"],
        field="Day 2 required rotation indices",
    )
    if value["planned_exact_indices"] != list(required) or value["eval_rotate_case_ids"] != [
        f"index={index}" for index in required
    ]:
        raise OpenFHEQueryRunnerError("Day 2 planned rotation inventory changed")
    return required


def pre_admission_day2_openfhe_key_generation_plan(
    rotation_key_plan_bytes: bytes,
) -> OpenFHEKeyGenerationPlan:
    """Type one canonical Day 2 plan without granting runtime/publication authority."""

    plan = _decode_json(rotation_key_plan_bytes, field="Day 2 rotation key plan")
    if rotation_key_plan_bytes != _canonical_rotation_key_plan_bytes(plan):
        raise OpenFHEQueryRunnerError("Day 2 rotation key plan is not canonical JSON")
    required = _validate_rotation_key_plan_document(plan)
    if plan["schema_version"] != _DAY2_ROTATION_KEY_PLAN_SCHEMA:
        raise OpenFHEQueryRunnerError("pre-admission Day 2 plan has the wrong schema")
    return OpenFHEKeyGenerationPlan(
        rotation_key_plan_bytes=rotation_key_plan_bytes,
        rotation_key_plan_sha256=hashlib.sha256(rotation_key_plan_bytes).hexdigest(),
        required_exact_indices=required,
    )


def _query_derived_key_generation_plan(
    *,
    cloud_program_sha256: str,
    rotation_entries: tuple[tuple[int, int], ...],
) -> OpenFHEKeyGenerationPlan:
    required = tuple(sorted({openfhe_index for _logical, openfhe_index in rotation_entries}))
    coverage_kind = "exact-program-rotation-catalog"
    if not required:
        required = (1,)
        coverage_kind = "minimum-nonempty-program-cover"
    document = {
        "coverage_kind": coverage_kind,
        "required_exact_indices": list(required),
        "schema_version": OPENFHE_QUERY_DERIVED_ROTATION_KEY_PLAN_SCHEMA,
        "source_cloud_program_sha256": cloud_program_sha256,
    }
    content = _canonical_rotation_key_plan_bytes(document)
    return OpenFHEKeyGenerationPlan(
        rotation_key_plan_bytes=content,
        rotation_key_plan_sha256=hashlib.sha256(content).hexdigest(),
        required_exact_indices=required,
    )


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


def _ciphertext_values(
    *,
    program: CloudProgram,
    value_vectors: tuple[tuple[str, tuple[int, ...]], ...],
    query_vectors: tuple[tuple[str, tuple[int, ...]], ...],
    f1m_vectors: tuple[tuple[str, str, tuple[int, ...]], ...],
) -> tuple[dict[str, object], ...]:
    values = dict(value_vectors)
    values.update(query_vectors)
    values.update((ciphertext_id, vector) for ciphertext_id, _kind, vector in f1m_vectors)
    f1m_kind = {ciphertext_id: kind for ciphertext_id, kind, _vector in f1m_vectors}
    expected = {operand.ciphertext_id for operand in program.ciphertext_inputs}
    if set(values) != expected:
        raise OpenFHEQueryRunnerError("private values do not exactly cover ciphertext inputs")
    result: list[dict[str, object]] = []
    for operand in sorted(
        program.ciphertext_inputs,
        key=lambda item: item.ciphertext_id,
    ):
        vector = values[operand.ciphertext_id]
        if (
            type(vector) is not tuple
            or len(vector) != operand.length
            or any(type(value) is not int for value in vector)
        ):
            raise OpenFHEQueryRunnerError("ciphertext input vector is not exact")
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
    return tuple(result)


def _ordinary_query_view(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
) -> _PreparedOpenFHEQueryView:
    preparation_bytes = canonical_ordinary_query_preparation_bytes(bundle, prepared)
    compiled = bundle.compiled
    return _PreparedOpenFHEQueryView(
        execution_kind="ordinary",
        cloud_plan=compiled.cloud_plan,
        output_plan=compiled.output_plan,
        result_routes=tuple(
            _OpenFHEResultRoute(
                result_id=route.result_id,
                component_id=route.component_id,
                output_block_id=route.output_block_id,
            )
            for route in compiled.result_routes
        ),
        private_plan_sha256=bundle.private_plan_digest,
        query_preparation_sha256=hashlib.sha256(preparation_bytes).hexdigest(),
        ciphertext_values=_ciphertext_values(
            program=compiled.cloud_plan.program,
            value_vectors=tuple(
                (spec.value_ciphertext_id, spec.values) for spec in compiled.operand_specs
            ),
            query_vectors=tuple(
                (operand.ciphertext_id, operand.values) for operand in prepared.query_operands
            ),
            f1m_vectors=tuple(
                (operand.ciphertext_id, operand.kind, operand.values)
                for operand in prepared.f1m_operands
            ),
        ),
        modulus=prepared.modulus,
    )


def _strong_query_view(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
) -> _PreparedOpenFHEQueryView:
    preparation_bytes = canonical_strong_query_preparation_bytes(bundle, prepared)
    return _PreparedOpenFHEQueryView(
        execution_kind="strong",
        cloud_plan=bundle.cloud_plan,
        output_plan=bundle.output_plan,
        result_routes=tuple(
            _OpenFHEResultRoute(
                result_id=route.result_id,
                component_id=route.component_id,
                output_block_id=route.output_block_id,
            )
            for route in bundle.result_routes
        ),
        private_plan_sha256=bundle.private_plan_digest,
        query_preparation_sha256=hashlib.sha256(preparation_bytes).hexdigest(),
        ciphertext_values=_ciphertext_values(
            program=bundle.cloud_plan.program,
            value_vectors=tuple(
                (spec.value_ciphertext_id, spec.values) for spec in bundle.value_operand_specs
            ),
            query_vectors=tuple(
                (operand.ciphertext_id, operand.values) for operand in prepared.query_operands
            ),
            f1m_vectors=tuple(
                (operand.ciphertext_id, operand.kind, operand.values)
                for operand in prepared.f1m_operands
            ),
        ),
        modulus=prepared.modulus,
    )


def _build_openfhe_query_request(
    view: _PreparedOpenFHEQueryView,
    *,
    repository_root: Path | None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None,
) -> bytes:
    cloud_plan = view.cloud_plan
    program = cloud_plan.program
    root = Path(__file__).resolve().parents[2] if repository_root is None else repository_root
    profile = _repository_openfhe_profile(root)
    if view.modulus != profile["plaintext_modulus"]:
        raise OpenFHEQueryRunnerError(
            "prepared query modulus differs from the repository OpenFHE profile"
        )
    if program.slot_count > profile["batch_size"]:
        raise OpenFHEQueryRunnerError("typed query slot count exceeds the OpenFHE batch size")
    execution_binding = canonical_execution_binding_payload(cloud_plan.binding)
    derived_key_plan = _query_derived_key_generation_plan(
        cloud_program_sha256=cloud_plan.binding.cloud_program_digest,
        rotation_entries=program.rotation_catalog.entries,
    )
    if key_generation_plan is None:
        key_plan = derived_key_plan
    elif not isinstance(key_generation_plan, OpenFHEKeyGenerationPlan):
        raise TypeError("key_generation_plan must be an OpenFHEKeyGenerationPlan")
    else:
        key_plan = key_generation_plan
        plan_document = _decode_json(
            key_plan.rotation_key_plan_bytes,
            field="rotation key plan",
        )
        program_indices = {
            openfhe_index for _logical_shift, openfhe_index in program.rotation_catalog.entries
        }
        if not program_indices.issubset(key_plan.required_exact_indices):
            raise OpenFHEQueryRunnerError(
                "key-generation plan does not cover every program rotation"
            )
        if (
            plan_document["schema_version"] == OPENFHE_QUERY_DERIVED_ROTATION_KEY_PLAN_SCHEMA
            and key_plan != derived_key_plan
        ):
            raise OpenFHEQueryRunnerError(
                "query-derived key-generation plan differs from the exact program"
            )
    request = {
        "bindings": {
            "cloud_program_sha256": cloud_plan.binding.cloud_program_digest,
            "execution_binding": execution_binding,
            "execution_binding_sha256": hashlib.sha256(
                _canonical_bytes(execution_binding)
            ).hexdigest(),
            "execution_kind": view.execution_kind,
            "query_preparation_sha256": view.query_preparation_sha256,
            "query_private_plan_sha256": view.private_plan_sha256,
        },
        "ciphertext_values": list(view.ciphertext_values),
        "key_generation_plan": key_plan.to_request_document(),
        "openfhe": profile,
        "program": canonical_cloud_program_payload(program),
        "schema_version": OPENFHE_QUERY_REQUEST_SCHEMA,
    }
    return _canonical_bytes(request)


def build_ordinary_openfhe_query_request(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    repository_root: Path | None = None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> bytes:
    """Build one private, non-authorizing request for the generic C++ runner."""

    return _build_openfhe_query_request(
        _ordinary_query_view(bundle, prepared),
        repository_root=repository_root,
        key_generation_plan=key_generation_plan,
    )


def build_strong_openfhe_query_request(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    repository_root: Path | None = None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> bytes:
    """Build one private, non-authorizing strong request for the same runner."""

    return _build_openfhe_query_request(
        _strong_query_view(bundle, prepared),
        repository_root=repository_root,
        key_generation_plan=key_generation_plan,
    )


def _expected_operation_counts(program: CloudProgram) -> dict[str, int]:
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
                "encrypted-zero-dummy": ("query-f1m-encrypted-zero-dummy-ciphertexts"),
            }[value["f1m_kind"]]
        else:
            category = category_by_role[role]
        subjects.append((category, value["ciphertext_id"]))
    result_ids = program["result_ids"]
    assert type(result_ids) is list
    subjects.extend(("query-result-ciphertexts", value) for value in result_ids)
    return tuple(subjects)


def _route_a_expected_serialized_subjects(
    request: dict[str, object],
) -> tuple[tuple[str, str], ...]:
    return (
        ("route-a-private-replay-crypto-context", "crypto-context"),
        ("route-a-private-replay-secret-key", "secret-key"),
        ("one-time-evaluation-key-material", "public-key"),
        *_expected_serialized_subjects(request),
    )


def _read_exact_member(
    directory_descriptor: int,
    relative_path: str,
    *,
    byte_count: int,
    sha256: str,
    key_frame_validator: Day1BCombinedEvaluationKeyFrameStreamValidator | None = None,
) -> Day1BCombinedEvaluationKeyFrameStreamReceipt | None:
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
            if key_frame_validator is not None:
                try:
                    key_frame_validator.accept(block)
                except Day1BCombinedEvaluationKeyFramingError as error:
                    raise OpenFHEQueryRunnerError(
                        "serialized typed key frame is invalid"
                    ) from error
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
        if key_frame_validator is None:
            return None
        try:
            return key_frame_validator.finish()
        except Day1BCombinedEvaluationKeyFramingError as error:
            raise OpenFHEQueryRunnerError("serialized typed key frame is invalid") from error
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


def _key_material_input_binding_sha256(request: dict[str, object]) -> str:
    key_plan = request["key_generation_plan"]
    assert type(key_plan) is dict
    document = {
        "bindings": request["bindings"],
        "key_generation_plan_sha256": hashlib.sha256(_canonical_bytes(key_plan)).hexdigest(),
        "schema_version": OPENFHE_KEY_MATERIAL_INPUT_BINDING_SCHEMA,
    }
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def _key_generation_session_sha256(receipt: dict[str, object]) -> str:
    document = {
        "crypto_context_parameter_sha256": receipt["crypto_context_parameter_sha256"],
        "crypto_context_serialization_sha256": receipt["crypto_context_serialization_sha256"],
        "eval_mult_segment_byte_count": receipt["eval_mult_segment_byte_count"],
        "eval_mult_segment_sha256": receipt["eval_mult_segment_sha256"],
        "input_binding_sha256": receipt["input_binding_sha256"],
        "key_generation_plan_sha256": receipt["key_generation_plan_sha256"],
        "public_key_sha256": receipt["public_key_sha256"],
        "request_sha256": receipt["request_sha256"],
        "required_exact_indices": receipt["required_exact_indices"],
        "rotation_key_plan_sha256": receipt["rotation_key_plan_sha256"],
        "rotation_segment_byte_count": receipt["rotation_segment_byte_count"],
        "rotation_segment_sha256": receipt["rotation_segment_sha256"],
        "schema_version": OPENFHE_KEY_GENERATION_SESSION_SCHEMA,
    }
    return hashlib.sha256(_canonical_bytes(document)).hexdigest()


def _verify_key_material_receipt(
    value: object,
    *,
    request: dict[str, object],
    request_sha256: str,
) -> OpenFHEKeyMaterialReceipt:
    expected_keys = {
        "combined_frame_byte_count",
        "combined_frame_sha256",
        "crypto_context_parameter_sha256",
        "crypto_context_serialization_sha256",
        "eval_mult_segment_byte_count",
        "eval_mult_segment_sha256",
        "formal_authority_granted",
        "framing_schema",
        "generated_exact_indices",
        "input_binding_sha256",
        "key_generation_plan_sha256",
        "key_generation_session_sha256",
        "publication_authority",
        "public_key_sha256",
        "request_sha256",
        "required_exact_indices",
        "rotation_key_plan_sha256",
        "rotation_segment_byte_count",
        "rotation_segment_sha256",
        "same_crypto_context_generation_session",
        "schema_version",
        "status",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise OpenFHEQueryRunnerError("key-material receipt keys are not exact")
    key_plan = request["key_generation_plan"]
    assert type(key_plan) is dict
    rotation_plan = key_plan["rotation_key_plan"]
    assert type(rotation_plan) is dict
    required = _validate_rotation_key_plan_document(rotation_plan)
    generated = _strict_exact_indices(
        value["generated_exact_indices"],
        field="generated exact rotation indices",
    )
    returned_required = _strict_exact_indices(
        value["required_exact_indices"],
        field="receipt required exact rotation indices",
    )
    rotation_bytes = _strict_nonnegative(
        value["rotation_segment_byte_count"],
        field="rotation segment byte count",
    )
    eval_mult_bytes = _strict_nonnegative(
        value["eval_mult_segment_byte_count"],
        field="eval-mult segment byte count",
    )
    combined_bytes = _strict_nonnegative(
        value["combined_frame_byte_count"],
        field="combined frame byte count",
    )
    digests = {
        field: _sha256(value[field], field=field.replace("_", " "))
        for field in (
            "combined_frame_sha256",
            "crypto_context_parameter_sha256",
            "crypto_context_serialization_sha256",
            "eval_mult_segment_sha256",
            "input_binding_sha256",
            "key_generation_plan_sha256",
            "key_generation_session_sha256",
            "public_key_sha256",
            "request_sha256",
            "rotation_key_plan_sha256",
            "rotation_segment_sha256",
        )
    }
    expected_key_plan_sha256 = hashlib.sha256(_canonical_bytes(key_plan)).hexdigest()
    expected_parameter_sha256 = hashlib.sha256(_canonical_bytes(request["openfhe"])).hexdigest()
    if (
        value["schema_version"] != OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA
        or value["status"] != "verified-by-runner-pre-admission-only"
        or value["framing_schema"] != DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA
        or value["formal_authority_granted"] is not False
        or value["publication_authority"] is not False
        or value["same_crypto_context_generation_session"] is not True
        or returned_required != required
        or generated != required
        or rotation_bytes <= 0
        or eval_mult_bytes <= 0
        or combined_bytes
        != DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES + rotation_bytes + eval_mult_bytes
        or digests["request_sha256"] != request_sha256
        or digests["rotation_key_plan_sha256"] != key_plan["rotation_key_plan_sha256"]
        or digests["key_generation_plan_sha256"] != expected_key_plan_sha256
        or digests["crypto_context_parameter_sha256"] != expected_parameter_sha256
        or digests["input_binding_sha256"] != _key_material_input_binding_sha256(request)
        or digests["key_generation_session_sha256"] != _key_generation_session_sha256(value)
    ):
        raise OpenFHEQueryRunnerError("key-material receipt binding/status is not exact")
    return OpenFHEKeyMaterialReceipt(
        combined_frame_byte_count=combined_bytes,
        combined_frame_sha256=digests["combined_frame_sha256"],
        crypto_context_parameter_sha256=digests["crypto_context_parameter_sha256"],
        crypto_context_serialization_sha256=digests["crypto_context_serialization_sha256"],
        eval_mult_segment_byte_count=eval_mult_bytes,
        eval_mult_segment_sha256=digests["eval_mult_segment_sha256"],
        generated_exact_indices=generated,
        input_binding_sha256=digests["input_binding_sha256"],
        key_generation_plan_sha256=digests["key_generation_plan_sha256"],
        key_generation_session_sha256=digests["key_generation_session_sha256"],
        public_key_sha256=digests["public_key_sha256"],
        request_sha256=request_sha256,
        required_exact_indices=required,
        rotation_key_plan_sha256=digests["rotation_key_plan_sha256"],
        rotation_segment_byte_count=rotation_bytes,
        rotation_segment_sha256=digests["rotation_segment_sha256"],
    )


def _verify_openfhe_query_result(
    view: _PreparedOpenFHEQueryView,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
    repository_root: Path | None = None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> VerifiedOpenFHEQueryResult:
    """Verify one C++ result plus every retained serialized-object byte stream."""

    expected_request = _build_openfhe_query_request(
        view,
        repository_root=repository_root,
        key_generation_plan=key_generation_plan,
    )
    if request_bytes != expected_request:
        raise OpenFHEQueryRunnerError("runner request differs from the canonical typed request")
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
        "key_generation_plan",
        "key_material_receipt",
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
        or result["key_generation_plan"] != request["key_generation_plan"]
        or result["openfhe"] != request["openfhe"]
        or result["publication_authority"] is not False
        or result["second_batch_row_zero"] is not True
    ):
        raise OpenFHEQueryRunnerError("OpenFHE query result binding/status is not exact")
    key_material_receipt = _verify_key_material_receipt(
        result["key_material_receipt"],
        request=request,
        request_sha256=request_sha256,
    )
    operation_counts = result["operation_counts"]
    if type(operation_counts) is not dict or set(operation_counts) != set(_OPERATION_COUNT_KEYS):
        raise OpenFHEQueryRunnerError("OpenFHE operation-count vocabulary is not exact")
    observed_counts = {
        key: _strict_nonnegative(operation_counts[key], field=f"operation count {key}")
        for key in _OPERATION_COUNT_KEYS
    }
    program = view.cloud_plan.program
    if observed_counts != _expected_operation_counts(program):
        raise OpenFHEQueryRunnerError("OpenFHE operation counts differ from the typed DAG")

    decrypted = result["decrypted_results"]
    if type(decrypted) is not list or len(decrypted) != len(program.result_ids):
        raise OpenFHEQueryRunnerError("OpenFHE decrypted result cardinality changed")
    decrypted_by_id: dict[str, tuple[int, ...]] = {}
    for index, item in enumerate(decrypted):
        if type(item) is not dict or set(item) != {"result_id", "values"}:
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result keys are not exact")
        result_id = item["result_id"]
        values = item["values"]
        if (
            result_id != program.result_ids[index]
            or type(values) is not list
            or len(values) != program.slot_count
        ):
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result identity/length changed")
        vector = tuple(values)
        if any(type(value) is not int or not 0 <= value < view.modulus for value in vector):
            raise OpenFHEQueryRunnerError("OpenFHE decrypted result is outside Z_t")
        decrypted_by_id[result_id] = vector
    returned_shares = {
        (route.component_id, route.output_block_id): decrypted_by_id[route.result_id]
        for route in view.result_routes
    }
    reconstructed = reconstruct_output(
        view.output_plan,
        returned_shares,
        modulus=view.modulus,
    )
    if (
        type(expected_output) is not tuple
        or any(type(value) is not int for value in expected_output)
        or len(expected_output) != len(reconstructed)
        or reconstructed != tuple(value % view.modulus for value in expected_output)
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
        if (
            not stat.S_ISDIR(root_status.st_mode)
            or (
                path_status.st_dev,
                path_status.st_ino,
                path_status.st_mode,
                path_status.st_nlink,
            )
            != root_identity
        ):
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
            frame_receipt = _read_exact_member(
                directory_descriptor,
                relative_path,
                byte_count=byte_count,
                sha256=digest,
                key_frame_validator=(
                    Day1BCombinedEvaluationKeyFrameStreamValidator(
                        expected_rotation_key_inventory_bytes=(
                            key_material_receipt.rotation_segment_byte_count
                        ),
                        expected_eval_mult_key_bytes=(
                            key_material_receipt.eval_mult_segment_byte_count
                        ),
                    )
                    if index == 0
                    else None
                ),
            )
            if index == 0:
                if (
                    expected_subject[0] != DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
                    or byte_count != key_material_receipt.combined_frame_byte_count
                    or digest != key_material_receipt.combined_frame_sha256
                    or frame_receipt is None
                    or frame_receipt.rotation_key_inventory_bytes
                    != key_material_receipt.rotation_segment_byte_count
                    or frame_receipt.rotation_key_inventory_sha256
                    != key_material_receipt.rotation_segment_sha256
                    or frame_receipt.eval_mult_key_bytes
                    != key_material_receipt.eval_mult_segment_byte_count
                    or frame_receipt.eval_mult_key_sha256
                    != key_material_receipt.eval_mult_segment_sha256
                ):
                    raise OpenFHEQueryRunnerError(
                        "typed key frame differs from the key-material receipt"
                    )
            elif frame_receipt is not None:  # pragma: no cover - construction invariant
                raise AssertionError("non-key OpenFHE object returned a key-frame receipt")
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
        key_material_receipt=key_material_receipt,
        serialized_objects=tuple(receipts),
        second_batch_row_zero=result["second_batch_row_zero"],
        publication_authority=False,
    )


def verify_ordinary_openfhe_query_result(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
    repository_root: Path | None = None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> VerifiedOpenFHEQueryResult:
    """Verify one ordinary result through the generic typed-result module."""

    return _verify_openfhe_query_result(
        _ordinary_query_view(bundle, prepared),
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
        repository_root=repository_root,
        key_generation_plan=key_generation_plan,
    )


def verify_strong_openfhe_query_result(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
    repository_root: Path | None = None,
    key_generation_plan: OpenFHEKeyGenerationPlan | None = None,
) -> VerifiedOpenFHEQueryResult:
    """Verify one strong result through the same generic typed-result module."""

    return _verify_openfhe_query_result(
        _strong_query_view(bundle, prepared),
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
        repository_root=repository_root,
        key_generation_plan=key_generation_plan,
    )


def _verify_route_a_openfhe_producer_result(
    view: _PreparedOpenFHEQueryView,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEProducerResult:
    raw = _read_bounded_exact_file(
        result_path,
        maximum=_RESULT_BYTES_MAXIMUM,
        field="Route A OpenFHE producer result",
    )
    result = _decode_json(raw, field="Route A OpenFHE producer result")
    if raw != _canonical_bytes(result):
        raise OpenFHEQueryRunnerError("Route A OpenFHE producer result is not canonical JSON")
    expected_result_keys = {
        "bindings",
        "cloud_program_operation_inventory",
        "decrypted_results",
        "key_generation_plan",
        "key_material_receipt",
        "lifecycle_operation_inventory",
        "mode",
        "openfhe",
        "publication_authority",
        "request_sha256",
        "schema_version",
        "second_batch_row_zero",
        "serialized_objects",
        "status",
    }
    if set(result) != expected_result_keys:
        raise OpenFHEQueryRunnerError("Route A producer result keys are not exact")
    request = _decode_json(request_bytes, field="Route A OpenFHE producer request")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    if (
        result["schema_version"] != ROUTE_A_OPENFHE_PRODUCER_RESULT_SCHEMA
        or result["status"] != "pass"
        or result["mode"] != "producer"
        or result["request_sha256"] != request_sha256
        or result["bindings"] != request["bindings"]
        or result["key_generation_plan"] != request["key_generation_plan"]
        or result["openfhe"] != request["openfhe"]
        or result["publication_authority"] is not False
        or result["second_batch_row_zero"] is not True
    ):
        raise OpenFHEQueryRunnerError("Route A producer result binding/status is not exact")
    key_material_receipt = _verify_key_material_receipt(
        result["key_material_receipt"],
        request=request,
        request_sha256=request_sha256,
    )
    expected_counts = _expected_operation_counts(view.cloud_plan.program)
    cloud_inventory = result["cloud_program_operation_inventory"]
    if type(cloud_inventory) is not dict or set(cloud_inventory) != set(
        _ROUTE_A_CLOUD_OPERATION_KEYS
    ):
        raise OpenFHEQueryRunnerError("Route A cloud operation inventory is not exact")
    observed_cloud = {
        key: _strict_nonnegative(cloud_inventory[key], field=f"Route A cloud {key}")
        for key in _ROUTE_A_CLOUD_OPERATION_KEYS
    }
    if observed_cloud != {key: expected_counts[key] for key in _ROUTE_A_CLOUD_OPERATION_KEYS}:
        raise OpenFHEQueryRunnerError("Route A cloud operation inventory changed")
    lifecycle = result["lifecycle_operation_inventory"]
    if type(lifecycle) is not dict or set(lifecycle) != set(_ROUTE_A_LIFECYCLE_OPERATION_KEYS):
        raise OpenFHEQueryRunnerError("Route A producer lifecycle inventory is not exact")
    observed_lifecycle = {
        key: _strict_nonnegative(lifecycle[key], field=f"Route A lifecycle {key}")
        for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS
    }
    expected_lifecycle = {key: 0 for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS}
    expected_lifecycle.update(
        {
            "automorphism_key_generation_count": 1,
            "context_generation_count": 1,
            "decrypt_count": expected_counts["decrypt"],
            "encrypt_count": expected_counts["encrypt"],
            "eval_mult_key_generation_count": 1,
            "key_generation_count": 1,
        }
    )
    if observed_lifecycle != expected_lifecycle:
        raise OpenFHEQueryRunnerError("Route A producer lifecycle inventory changed")

    program = view.cloud_plan.program
    decrypted = result["decrypted_results"]
    if type(decrypted) is not list or len(decrypted) != len(program.result_ids):
        raise OpenFHEQueryRunnerError("Route A decrypted result cardinality changed")
    decrypted_by_id: dict[str, tuple[int, ...]] = {}
    for index, item in enumerate(decrypted):
        if type(item) is not dict or set(item) != {"result_id", "values"}:
            raise OpenFHEQueryRunnerError("Route A decrypted result keys are not exact")
        result_id = item["result_id"]
        values = item["values"]
        if (
            result_id != program.result_ids[index]
            or type(values) is not list
            or len(values) != program.slot_count
        ):
            raise OpenFHEQueryRunnerError("Route A decrypted result identity changed")
        vector = tuple(values)
        if any(type(value) is not int or not 0 <= value < view.modulus for value in vector):
            raise OpenFHEQueryRunnerError("Route A decrypted result is outside Z_t")
        decrypted_by_id[result_id] = vector
    returned_shares = {
        (route.component_id, route.output_block_id): decrypted_by_id[route.result_id]
        for route in view.result_routes
    }
    reconstructed = reconstruct_output(
        view.output_plan,
        returned_shares,
        modulus=view.modulus,
    )
    if (
        type(expected_output) is not tuple
        or any(type(value) is not int for value in expected_output)
        or reconstructed != tuple(value % view.modulus for value in expected_output)
    ):
        raise OpenFHEQueryRunnerError("Route A producer output differs from the oracle")

    serialized = result["serialized_objects"]
    expected_subjects = _route_a_expected_serialized_subjects(request)
    if type(serialized) is not list or len(serialized) != len(expected_subjects):
        raise OpenFHEQueryRunnerError("Route A serialized-object cardinality changed")
    try:
        root_status = object_root.lstat()
        directory_descriptor = os.open(
            object_root,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise OpenFHEQueryRunnerError("Route A object root is unavailable") from error
    try:
        if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
            raise OpenFHEQueryRunnerError("Route A object root is not a direct directory")
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
                raise OpenFHEQueryRunnerError("Route A serialized-object keys are not exact")
            relative_path = f"object-{index:06d}.bin"
            byte_count = _strict_nonnegative(
                item["byte_count"], field="Route A serialized byte_count"
            )
            digest = _sha256(item["sha256"], field="Route A serialized SHA-256")
            if (
                (item["category"], item["subject_id"]) != expected_subject
                or item["relative_path"] != relative_path
                or byte_count <= 0
            ):
                raise OpenFHEQueryRunnerError("Route A serialized-object identity changed")
            frame_receipt = _read_exact_member(
                directory_descriptor,
                relative_path,
                byte_count=byte_count,
                sha256=digest,
                key_frame_validator=(
                    Day1BCombinedEvaluationKeyFrameStreamValidator(
                        expected_rotation_key_inventory_bytes=(
                            key_material_receipt.rotation_segment_byte_count
                        ),
                        expected_eval_mult_key_bytes=(
                            key_material_receipt.eval_mult_segment_byte_count
                        ),
                    )
                    if index == 3
                    else None
                ),
            )
            if index == 0 and digest != key_material_receipt.crypto_context_serialization_sha256:
                raise OpenFHEQueryRunnerError("Route A retained CryptoContext digest changed")
            if index == 2 and digest != key_material_receipt.public_key_sha256:
                raise OpenFHEQueryRunnerError("Route A retained public-key digest changed")
            if index == 3 and (
                digest != key_material_receipt.combined_frame_sha256 or frame_receipt is None
            ):
                raise OpenFHEQueryRunnerError("Route A retained D1BKEY01 frame changed")
            receipts.append(
                OpenFHESerializedObjectReceipt(
                    category=item["category"],
                    subject_id=item["subject_id"],
                    relative_path=relative_path,
                    byte_count=byte_count,
                    sha256=digest,
                )
            )
        if set(os.listdir(directory_descriptor)) != {receipt.relative_path for receipt in receipts}:
            raise OpenFHEQueryRunnerError("Route A object root has missing or extra members")
    finally:
        os.close(directory_descriptor)
    return VerifiedRouteAOpenFHEProducerResult(
        request_sha256=request_sha256,
        cloud_program_operation_inventory=tuple(
            (key, observed_cloud[key]) for key in _ROUTE_A_CLOUD_OPERATION_KEYS
        ),
        lifecycle_operation_inventory=tuple(
            (key, observed_lifecycle[key]) for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS
        ),
        decrypted_results=tuple(
            (result_id, decrypted_by_id[result_id]) for result_id in program.result_ids
        ),
        reconstructed_output=reconstructed,
        key_material_receipt=key_material_receipt,
        serialized_objects=tuple(receipts),
        second_batch_row_zero=True,
        publication_authority=False,
    )


def verify_route_a_ordinary_openfhe_producer_result(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEProducerResult:
    return _verify_route_a_openfhe_producer_result(
        _ordinary_query_view(bundle, prepared),
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
    )


def verify_route_a_strong_openfhe_producer_result(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    request_bytes: bytes,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEProducerResult:
    return _verify_route_a_openfhe_producer_result(
        _strong_query_view(bundle, prepared),
        request_bytes=request_bytes,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
    )


def _verify_route_a_openfhe_replay_result(
    view: _PreparedOpenFHEQueryView,
    *,
    request_bytes: bytes,
    package_manifest_sha256: str,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEReplayResult:
    package_manifest_sha256 = _sha256(
        package_manifest_sha256,
        field="Route A package manifest SHA-256",
    )
    raw = _read_bounded_exact_file(
        result_path,
        maximum=_RESULT_BYTES_MAXIMUM,
        field="Route A OpenFHE replay result",
    )
    result = _decode_json(raw, field="Route A OpenFHE replay result")
    if raw != _canonical_bytes(result):
        raise OpenFHEQueryRunnerError("Route A replay result is not canonical JSON")
    if set(result) != {
        "bindings",
        "cloud_program_operation_inventory",
        "decrypted_results",
        "lifecycle_operation_inventory",
        "mode",
        "openfhe",
        "package_manifest_sha256",
        "publication_authority",
        "request_sha256",
        "schema_version",
        "second_batch_row_zero",
        "serialized_objects",
        "status",
    }:
        raise OpenFHEQueryRunnerError("Route A replay result keys are not exact")
    request = _decode_json(request_bytes, field="Route A OpenFHE replay request")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    if (
        result["schema_version"] != ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA
        or result["status"] != "pass"
        or result["mode"] != "replay"
        or result["request_sha256"] != request_sha256
        or result["package_manifest_sha256"] != package_manifest_sha256
        or result["bindings"] != request["bindings"]
        or result["openfhe"] != request["openfhe"]
        or result["publication_authority"] is not False
        or result["second_batch_row_zero"] is not True
    ):
        raise OpenFHEQueryRunnerError("Route A replay result binding/status is not exact")
    expected_counts = _expected_operation_counts(view.cloud_plan.program)
    cloud_inventory = result["cloud_program_operation_inventory"]
    if type(cloud_inventory) is not dict or set(cloud_inventory) != set(
        _ROUTE_A_CLOUD_OPERATION_KEYS
    ):
        raise OpenFHEQueryRunnerError("Route A replay Cloud inventory is not exact")
    observed_cloud = {
        key: _strict_nonnegative(cloud_inventory[key], field=f"Route A replay {key}")
        for key in _ROUTE_A_CLOUD_OPERATION_KEYS
    }
    if observed_cloud != {key: expected_counts[key] for key in _ROUTE_A_CLOUD_OPERATION_KEYS}:
        raise OpenFHEQueryRunnerError("Route A replay Cloud inventory changed")
    lifecycle = result["lifecycle_operation_inventory"]
    if type(lifecycle) is not dict or set(lifecycle) != set(_ROUTE_A_LIFECYCLE_OPERATION_KEYS):
        raise OpenFHEQueryRunnerError("Route A replay lifecycle inventory is not exact")
    observed_lifecycle = {
        key: _strict_nonnegative(lifecycle[key], field=f"Route A replay lifecycle {key}")
        for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS
    }
    expected_lifecycle = {key: 0 for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS}
    expected_lifecycle.update(
        {
            "automorphism_key_deserialize_count": 1,
            "crypto_context_deserialize_count": 1,
            "decrypt_count": expected_counts["decrypt"],
            "eval_mult_key_deserialize_count": 1,
            "input_ciphertext_deserialize_count": expected_counts["encrypt"],
            "public_key_deserialize_count": 1,
            "secret_key_deserialize_count": 1,
        }
    )
    if observed_lifecycle != expected_lifecycle:
        raise OpenFHEQueryRunnerError("Route A replay lifecycle inventory changed")

    program = view.cloud_plan.program
    decrypted = result["decrypted_results"]
    if type(decrypted) is not list or len(decrypted) != len(program.result_ids):
        raise OpenFHEQueryRunnerError("Route A replay decrypted cardinality changed")
    decrypted_by_id: dict[str, tuple[int, ...]] = {}
    for index, item in enumerate(decrypted):
        if type(item) is not dict or set(item) != {"result_id", "values"}:
            raise OpenFHEQueryRunnerError("Route A replay decrypted keys are not exact")
        result_id = item["result_id"]
        values = item["values"]
        if (
            result_id != program.result_ids[index]
            or type(values) is not list
            or len(values) != program.slot_count
        ):
            raise OpenFHEQueryRunnerError("Route A replay decrypted identity changed")
        vector = tuple(values)
        if any(type(value) is not int or not 0 <= value < view.modulus for value in vector):
            raise OpenFHEQueryRunnerError("Route A replay decrypted value is outside Z_t")
        decrypted_by_id[result_id] = vector
    reconstructed = reconstruct_output(
        view.output_plan,
        {
            (route.component_id, route.output_block_id): decrypted_by_id[route.result_id]
            for route in view.result_routes
        },
        modulus=view.modulus,
    )
    if (
        type(expected_output) is not tuple
        or any(type(value) is not int for value in expected_output)
        or reconstructed != tuple(value % view.modulus for value in expected_output)
    ):
        raise OpenFHEQueryRunnerError("Route A replay output differs from the oracle")

    serialized = result["serialized_objects"]
    expected_subjects = tuple(
        ("query-result-ciphertexts", result_id) for result_id in program.result_ids
    )
    if type(serialized) is not list or len(serialized) != len(expected_subjects):
        raise OpenFHEQueryRunnerError("Route A replay object cardinality changed")
    try:
        root_status = object_root.lstat()
        directory_descriptor = os.open(
            object_root,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise OpenFHEQueryRunnerError("Route A replay object root is unavailable") from error
    try:
        if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
            raise OpenFHEQueryRunnerError("Route A replay object root is not direct")
        receipts: list[OpenFHESerializedObjectReceipt] = []
        for index, (item, expected_subject) in enumerate(
            zip(serialized, expected_subjects, strict=True)
        ):
            relative_path = f"object-{index:06d}.bin"
            if type(item) is not dict or set(item) != {
                "byte_count",
                "category",
                "relative_path",
                "sha256",
                "subject_id",
            }:
                raise OpenFHEQueryRunnerError("Route A replay object keys are not exact")
            byte_count = _strict_nonnegative(
                item["byte_count"], field="Route A replay object byte_count"
            )
            digest = _sha256(item["sha256"], field="Route A replay object SHA-256")
            if (
                (item["category"], item["subject_id"]) != expected_subject
                or item["relative_path"] != relative_path
                or byte_count <= 0
            ):
                raise OpenFHEQueryRunnerError("Route A replay object identity changed")
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
        if set(os.listdir(directory_descriptor)) != {receipt.relative_path for receipt in receipts}:
            raise OpenFHEQueryRunnerError("Route A replay object root changed")
    finally:
        os.close(directory_descriptor)
    return VerifiedRouteAOpenFHEReplayResult(
        request_sha256=request_sha256,
        package_manifest_sha256=package_manifest_sha256,
        cloud_program_operation_inventory=tuple(
            (key, observed_cloud[key]) for key in _ROUTE_A_CLOUD_OPERATION_KEYS
        ),
        lifecycle_operation_inventory=tuple(
            (key, observed_lifecycle[key]) for key in _ROUTE_A_LIFECYCLE_OPERATION_KEYS
        ),
        decrypted_results=tuple(
            (result_id, decrypted_by_id[result_id]) for result_id in program.result_ids
        ),
        reconstructed_output=reconstructed,
        serialized_objects=tuple(receipts),
        second_batch_row_zero=True,
        publication_authority=False,
    )


def verify_route_a_ordinary_openfhe_replay_result(
    bundle: OrdinaryExecutionBundle,
    prepared: PreparedOrdinaryQuery,
    *,
    request_bytes: bytes,
    package_manifest_sha256: str,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEReplayResult:
    return _verify_route_a_openfhe_replay_result(
        _ordinary_query_view(bundle, prepared),
        request_bytes=request_bytes,
        package_manifest_sha256=package_manifest_sha256,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
    )


def verify_route_a_strong_openfhe_replay_result(
    bundle: StrongExecutionBundle,
    prepared: PreparedStrongQuery,
    *,
    request_bytes: bytes,
    package_manifest_sha256: str,
    result_path: Path,
    object_root: Path,
    expected_output: tuple[int, ...],
) -> VerifiedRouteAOpenFHEReplayResult:
    return _verify_route_a_openfhe_replay_result(
        _strong_query_view(bundle, prepared),
        request_bytes=request_bytes,
        package_manifest_sha256=package_manifest_sha256,
        result_path=result_path,
        object_root=object_root,
        expected_output=expected_output,
    )


__all__ = (
    "OPENFHE_QUERY_PARAMETER_PROFILE",
    "OPENFHE_QUERY_REQUEST_SCHEMA",
    "OPENFHE_QUERY_RESULT_SCHEMA",
    "ROUTE_A_OPENFHE_PRODUCER_RESULT_SCHEMA",
    "ROUTE_A_OPENFHE_REPLAY_RESULT_SCHEMA",
    "OPENFHE_KEY_GENERATION_PLAN_SCHEMA",
    "OPENFHE_KEY_GENERATION_SESSION_SCHEMA",
    "OPENFHE_KEY_MATERIAL_INPUT_BINDING_SCHEMA",
    "OPENFHE_KEY_MATERIAL_RECEIPT_SCHEMA",
    "OPENFHE_QUERY_DERIVED_ROTATION_KEY_PLAN_SCHEMA",
    "OpenFHEQueryRunnerError",
    "OpenFHEKeyGenerationPlan",
    "OpenFHEKeyMaterialReceipt",
    "OpenFHESerializedObjectReceipt",
    "VerifiedOpenFHEQueryResult",
    "VerifiedRouteAOpenFHEProducerResult",
    "VerifiedRouteAOpenFHEReplayResult",
    "build_ordinary_openfhe_query_request",
    "build_strong_openfhe_query_request",
    "pre_admission_day2_openfhe_key_generation_plan",
    "verify_ordinary_openfhe_query_result",
    "verify_strong_openfhe_query_result",
    "verify_route_a_ordinary_openfhe_producer_result",
    "verify_route_a_strong_openfhe_producer_result",
    "verify_route_a_ordinary_openfhe_replay_result",
    "verify_route_a_strong_openfhe_replay_result",
)
