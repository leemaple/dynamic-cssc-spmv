"""Execute one same-replay Day 1B representative with an anchored key plan.

This is a capability-composition boundary, not a dispatch boundary.  It consumes
the private representative retained by the repository-owned replay collector and
the single-use Day 2 OpenFHE key-plan capability inside one function.  The exact
ordinary or strong lifecycle is prepared and consumed through the shared native
runtime.  Its receipt binds replay, runtime, and serialized-payload identities,
while every production, dispatch, publication, cost, and performance authority
remains false.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.day2_openfhe_key_plan import (
    Day2OpenFHEKeyPlanCapability,
    Day2OpenFHEKeyPlanError,
    abandon_day2_openfhe_key_plan,
)
from dynamic_cssc.mask_ledger import PreparedF1MCommitmentLedger
from dynamic_cssc.openfhe_query_runtime import (
    ExecutedOpenFHEQuery,
    OpenFHEQueryRuntimeReceipt,
    OpenFHESerializedPayload,
    execute_day2_anchored_openfhe_query,
    execute_day2_anchored_strong_openfhe_query,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.publication_day1b_replay_execution import (
    Day1BCandidateReplayCapability,
    Day1BQueryExecutionBinding,
    Day1BReplayExecutionReceipt,
    claim_day1b_candidate_replay_capability,
)
from dynamic_cssc.strong_execution import prepare_strong_query

DAY1B_REPRESENTATIVE_OPENFHE_RECEIPT_SCHEMA = (
    "dynamic-cssc-publication-day1b-representative-openfhe-receipt-v1"
)
DAY1B_REPRESENTATIVE_PAYLOAD_RECEIPT_STREAM_SCHEMA = (
    "dynamic-cssc-publication-day1b-representative-payload-receipt-stream-v1"
)

_EXPECTED_OUTPUT_SCHEMA = "dynamic-cssc-publication-day1b-query-expected-output-v1"
_QUERY_ID_SCHEMA = "dynamic-cssc-publication-day1b-representative-query-id-v1"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Day1BRepresentativeOpenFHEError(ValueError):
    """The replay representative and anchored runtime failed to compose."""


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
        raise Day1BRepresentativeOpenFHEError(
            "representative OpenFHE receipt is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _sha256_document(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BRepresentativeOpenFHEError(
            f"representative OpenFHE {field} must be one lowercase SHA-256"
        )
    return value


def _output_sha256(values: tuple[int, ...], *, modulus: int) -> str:
    if (
        type(values) is not tuple
        or not values
        or any(type(value) is not int for value in values)
        or type(modulus) is not int
        or modulus < 2
    ):
        raise Day1BRepresentativeOpenFHEError(
            "representative OpenFHE output is not one exact modular vector"
        )
    return _sha256_document(
        {
            "modulus": modulus,
            "schema_version": _EXPECTED_OUTPUT_SCHEMA,
            "values": list(values),
        }
    )


def _representative_query_id(
    replay_receipt: Day1BReplayExecutionReceipt,
    binding: Day1BQueryExecutionBinding,
) -> str:
    return "day1b-representative-" + _sha256_document(
        {
            "candidate_replay_receipt_sha256": replay_receipt.receipt_sha256,
            "representative_query_execution_binding_sha256": binding.binding_sha256,
            "schema_version": _QUERY_ID_SCHEMA,
        }
    )


def _payload_receipt_stream(
    payloads: tuple[OpenFHESerializedPayload, ...],
) -> tuple[str, int, int]:
    if (
        type(payloads) is not tuple
        or not payloads
        or any(type(payload) is not OpenFHESerializedPayload for payload in payloads)
    ):
        raise Day1BRepresentativeOpenFHEError(
            "representative OpenFHE payload inventory is not exact"
        )
    stream = hashlib.sha256()
    for payload in payloads:
        stream.update(_canonical_bytes(payload.receipt_document()))
    root = _sha256_document(
        {
            "element_count": len(payloads),
            "element_stream_sha256": stream.hexdigest(),
            "schema_version": DAY1B_REPRESENTATIVE_PAYLOAD_RECEIPT_STREAM_SCHEMA,
        }
    )
    return root, len(payloads), sum(len(payload.payload) for payload in payloads)


@dataclass(frozen=True, slots=True)
class Day1BRepresentativeOpenFHEReceipt:
    replay_execution_receipt: Day1BReplayExecutionReceipt
    representative_binding: Day1BQueryExecutionBinding
    runtime_receipt: OpenFHEQueryRuntimeReceipt
    query_id: str
    expected_output_sha256: str
    reconstructed_output_sha256: str
    serialized_payload_receipt_stream_sha256: str
    serialized_payload_count: int
    serialized_payload_bytes: int

    def __post_init__(self) -> None:
        replay = self.replay_execution_receipt
        binding = self.representative_binding
        runtime = self.runtime_receipt
        if type(replay) is not Day1BReplayExecutionReceipt:
            raise TypeError("representative execution requires one exact replay receipt")
        if type(binding) is not Day1BQueryExecutionBinding:
            raise TypeError("representative execution requires one exact query binding")
        if type(runtime) is not OpenFHEQueryRuntimeReceipt:
            raise TypeError("representative execution requires one exact runtime receipt")
        runtime.to_document()
        for field in (
            "expected_output_sha256",
            "reconstructed_output_sha256",
            "serialized_payload_receipt_stream_sha256",
        ):
            _require_sha256(getattr(self, field), field)
        authorization = runtime.authorization
        expected_query_id = _representative_query_id(replay, binding)
        if (
            self.query_id != expected_query_id
            or authorization.query_id != expected_query_id
            or authorization.version_id != binding.version_id
            or authorization.execution_binding_digest
            != binding.execution_binding_sha256
            or runtime.execution_kind != binding.execution_kind
            or runtime.day2_key_plan_authorization is None
            or replay.representative_query_execution_binding_sha256
            != binding.binding_sha256
            or replay.candidate_id != binding.candidate_id
            or replay.candidate_role != binding.candidate_role
            or replay.candidate_policy_sha256 != binding.candidate_policy_sha256
            or replay.retained_phases != binding.retained_phases
            or replay.query_vector_sha256 != binding.query_vector_sha256
            or replay.plaintext_modulus != binding.plaintext_modulus
            or replay.representative_phase != binding.phase
            or replay.representative_window_index != binding.window_index
            or binding.retained_private_bundle_count != 1
            or binding.openfhe_execution_count != 0
            or binding.expected_output_sha256 != self.expected_output_sha256
            or self.reconstructed_output_sha256 != self.expected_output_sha256
        ):
            raise Day1BRepresentativeOpenFHEError(
                "representative replay, query binding, and runtime receipt diverged"
            )
        if (
            type(self.serialized_payload_count) is not int
            or self.serialized_payload_count <= 0
            or type(self.serialized_payload_bytes) is not int
            or self.serialized_payload_bytes <= 0
            or runtime.serialized_object_count != self.serialized_payload_count
            or runtime.serialized_object_bytes != self.serialized_payload_bytes
        ):
            raise Day1BRepresentativeOpenFHEError(
                "representative runtime and payload inventory diverged"
            )

    def _body_document(self) -> dict[str, object]:
        return {
            "anchored_day2_key_plan_verified": True,
            "candidate_replay_continuity_verified": True,
            "complete_cost_claim_allowed": False,
            "expected_output_sha256": self.expected_output_sha256,
            "formal_authority_granted": False,
            "heldout_dispatch_authorized": False,
            "performance_claim_allowed": False,
            "production_execution_admissible": False,
            "publication_authority": False,
            "query_id": self.query_id,
            "reconstructed_output_sha256": self.reconstructed_output_sha256,
            "replay_execution_receipt": self.replay_execution_receipt.to_document(),
            "representative_binding": self.representative_binding.to_document(),
            "representative_openfhe_execution_verified": True,
            "runtime_receipt": self.runtime_receipt.to_document(),
            "schema_version": DAY1B_REPRESENTATIVE_OPENFHE_RECEIPT_SCHEMA,
            "security_claim_allowed": False,
            "serialized_payload_bytes": self.serialized_payload_bytes,
            "serialized_payload_count": self.serialized_payload_count,
            "serialized_payload_receipt_stream_sha256": (
                self.serialized_payload_receipt_stream_sha256
            ),
            "status": "verified-representative-pre-admission-only",
        }

    @property
    def receipt_sha256(self) -> str:
        return _sha256_document(self._body_document())

    def to_document(self) -> dict[str, object]:
        body = self._body_document()
        return {**body, "representative_openfhe_receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True, slots=True)
class ExecutedDay1BRepresentativeOpenFHE:
    receipt: Day1BRepresentativeOpenFHEReceipt
    openfhe_execution: ExecutedOpenFHEQuery

    def __post_init__(self) -> None:
        if type(self.receipt) is not Day1BRepresentativeOpenFHEReceipt:
            raise TypeError("executed representative requires one exact composed receipt")
        if type(self.openfhe_execution) is not ExecutedOpenFHEQuery:
            raise TypeError("executed representative requires one exact OpenFHE execution")
        execution = self.openfhe_execution
        payload_root, payload_count, payload_bytes = _payload_receipt_stream(
            execution.serialized_payloads
        )
        reconstructed_sha256 = _output_sha256(
            execution.verified_result.reconstructed_output,
            modulus=self.receipt.representative_binding.plaintext_modulus,
        )
        if (
            execution.runtime_receipt != self.receipt.runtime_receipt
            or payload_root != self.receipt.serialized_payload_receipt_stream_sha256
            or payload_count != self.receipt.serialized_payload_count
            or payload_bytes != self.receipt.serialized_payload_bytes
            or reconstructed_sha256 != self.receipt.reconstructed_output_sha256
            or execution.verified_result.publication_authority is not False
        ):
            raise Day1BRepresentativeOpenFHEError(
                "composed representative receipt differs from its retained execution"
            )


def execute_day1b_representative_openfhe_query(
    *,
    candidate_replay_capability: Day1BCandidateReplayCapability,
    day2_key_plan_capability: Day2OpenFHEKeyPlanCapability,
    ledger: PreparedF1MCommitmentLedger,
    repository_root: Path,
    runner_relative_path: str,
    scratch_root: Path,
    timeout_seconds: int,
    resident_memory_limit_bytes: int,
    scratch_limit_bytes: int,
) -> ExecutedDay1BRepresentativeOpenFHE:
    """Consume both capabilities and execute one canonical representative.

    The caller retains ownership of the persistent ledger storage.  The native
    runtime still owns and removes its exclusive query scratch tree.
    """

    if type(candidate_replay_capability) is not Day1BCandidateReplayCapability:
        raise TypeError("candidate replay must be one exact collector-minted capability")
    if type(day2_key_plan_capability) is not Day2OpenFHEKeyPlanCapability:
        raise TypeError("Day 2 key plan must be one exact repository-minted capability")
    if not all(
        callable(getattr(ledger, operation, None))
        for operation in ("commit_prepared_f1m", "verify_and_consume_prepared_f1m")
    ):
        raise TypeError("representative execution ledger lacks the exact lifecycle methods")

    try:
        representative = claim_day1b_candidate_replay_capability(
            candidate_replay_capability
        )
        replay_receipt = representative.receipt
        binding = representative.binding
        query_id = _representative_query_id(replay_receipt, binding)
        layout = representative.execution
        if layout.ordinary_compilation is not None:
            bundle = bind_ordinary_execution(layout.ordinary_compilation)
            prepared = prepare_ordinary_query(
                bundle,
                query_id=query_id,
                vector=representative.query_vector,
                modulus=representative.modulus,
                ledger=ledger,
            )
            execution = execute_day2_anchored_openfhe_query(
                bundle,
                prepared,
                ledger=ledger,
                expected_output=representative.expected_output,
                day2_key_plan_capability=day2_key_plan_capability,
                repository_root=repository_root,
                runner_relative_path=runner_relative_path,
                scratch_root=scratch_root,
                timeout_seconds=timeout_seconds,
                resident_memory_limit_bytes=resident_memory_limit_bytes,
                scratch_limit_bytes=scratch_limit_bytes,
            )
        else:
            bundle = layout.strong_bundle
            if bundle is None:
                raise Day1BRepresentativeOpenFHEError(
                    "representative layout lost both typed execution paths"
                )
            prepared = prepare_strong_query(
                bundle,
                query_id=query_id,
                vector=representative.query_vector,
                modulus=representative.modulus,
                ledger=ledger,
            )
            execution = execute_day2_anchored_strong_openfhe_query(
                bundle,
                prepared,
                ledger=ledger,
                expected_output=representative.expected_output,
                day2_key_plan_capability=day2_key_plan_capability,
                repository_root=repository_root,
                runner_relative_path=runner_relative_path,
                scratch_root=scratch_root,
                timeout_seconds=timeout_seconds,
                resident_memory_limit_bytes=resident_memory_limit_bytes,
                scratch_limit_bytes=scratch_limit_bytes,
            )
        if type(execution) is not ExecutedOpenFHEQuery:
            raise Day1BRepresentativeOpenFHEError(
                "representative runtime returned a non-exact execution"
            )
        expected_sha256 = _output_sha256(
            representative.expected_output,
            modulus=representative.modulus,
        )
        reconstructed_sha256 = _output_sha256(
            execution.verified_result.reconstructed_output,
            modulus=representative.modulus,
        )
        payload_root, payload_count, payload_bytes = _payload_receipt_stream(
            execution.serialized_payloads
        )
        receipt = Day1BRepresentativeOpenFHEReceipt(
            replay_execution_receipt=replay_receipt,
            representative_binding=binding,
            runtime_receipt=execution.runtime_receipt,
            query_id=query_id,
            expected_output_sha256=expected_sha256,
            reconstructed_output_sha256=reconstructed_sha256,
            serialized_payload_receipt_stream_sha256=payload_root,
            serialized_payload_count=payload_count,
            serialized_payload_bytes=payload_bytes,
        )
        return ExecutedDay1BRepresentativeOpenFHE(
            receipt=receipt,
            openfhe_execution=execution,
        )
    except BaseException:
        with suppress(Day2OpenFHEKeyPlanError):
            abandon_day2_openfhe_key_plan(day2_key_plan_capability)
        raise


__all__ = (
    "DAY1B_REPRESENTATIVE_OPENFHE_RECEIPT_SCHEMA",
    "DAY1B_REPRESENTATIVE_PAYLOAD_RECEIPT_STREAM_SCHEMA",
    "Day1BRepresentativeOpenFHEError",
    "Day1BRepresentativeOpenFHEReceipt",
    "ExecutedDay1BRepresentativeOpenFHE",
    "execute_day1b_representative_openfhe_query",
)
