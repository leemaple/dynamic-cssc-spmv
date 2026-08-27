"""Fail-closed analysis for the preregistered publication experiment.

The identities below are the analysis contract frozen by the preregistration;
they do not admit candidates into the execution registry or grant claim authority.
"""

from __future__ import annotations

import csv
import hashlib
import inspect
import io
import json
import math
import os
import platform
import re
import shutil
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, replace
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.evidence_compatibility import (
    RUNTIME_EXECUTION_ISOLATION_HOLD,
    RUNTIME_EXECUTION_ISOLATION_RECEIPT_SCHEMA,
    RUNTIME_EXECUTION_ISOLATION_REQUIRED_CHECKS,
    EvidenceCompatibilityError,
    EvidenceCompatibilityHold,
    EvidenceRole,
    repository_behavior_paths,
    verify_current_analysis_source,
    verify_evidence_compatibility,
)
from dynamic_cssc.publication_schedule import ACCEPTED_EVENT_SCHEDULE_SCHEMA
from dynamic_cssc.publication_traces import PUBLICATION_SOURCE_PARTITION_COUNT

HELDOUT_SCHEMA = "dynamic-cssc-publication-heldout-v7"
HELDOUT_RECORD_SCHEMA = "dynamic-cssc-publication-heldout-record-v4"
CALIBRATION_SCHEMA = "dynamic-cssc-publication-calibration-v3"
CALIBRATION_BLOCK_SCHEMA = "dynamic-cssc-publication-calibration-block-v1"
TRACE_UNIT_SCHEMA = "dynamic-cssc-publication-trace-unit-binding-v2"
CELL_BINDING_SCHEMA = "dynamic-cssc-publication-cell-binding-v2"
VERDICT_SCHEMA = "dynamic-cssc-publication-verdict-v7"
EVENT_SCHEDULE_SCHEMA = ACCEPTED_EVENT_SCHEDULE_SCHEMA
QUERY_VECTOR_SCHEMA = "dynamic-cssc-publication-query-vector-v1"
SAMPLER_SCHEMA = "dynamic-cssc-publication-shake256-counter-sampler-v1"
SAMPLER_KNOWN_ANSWER_SHA256 = "10246ee8ccdeaf978dba3a1df3739187014e57ebc56fa5f83b24fc010f8bb9ee"
ANALYSIS_RUNTIME_IMPLEMENTATION = "CPython"
ANALYSIS_RUNTIME_VERSION = "3.12.13"
PARTITION_RESAMPLING_SEED = 2_026_082_301
PARTITION_RESAMPLING_REPETITIONS = 10_000
CALIBRATION_CLASSIFICATION_SEED = 2_026_082_301
CALIBRATION_CLASSIFICATION_REPETITIONS = 10_000
CALIBRATION_OPERATION_ORDER_SEED = 2_026_082_302
CALIBRATION_MEASUREMENT_BLOCK_COUNT = 14
CALIBRATION_MEASUREMENT_STOP_RULE = (
    "exactly-14-whole-blocks-outcome-independent-no-optional-stopping"
)
BANDWIDTH_MBPS = 1_000
COMPARATOR_CANDIDATE_ID = "periodic-repack/windows=1"
DATASET_IDS = (
    "stack-overflow",
    "simplewiki-2026-07",
    "nyc-tlc-yellow-2022",
)
SEMANTICS = ("T1", "T2")
FRESHNESS_VALUES = ("0.1", "1")
PRIMARY_CONFIRMATORY_FAMILY = ("T2", "0.1")
RHO_VALUES = ("0.01", "0.03", "0.1", "0.3", "1", "3", "10", "30", "100")
REFERENCE_CANDIDATE_IDS = (
    "padding-reuse",
    "mini-cssc-delta",
    "strict-local-repack",
    "reserved-slack/beta=0",
    "reserved-slack/beta=0.05",
    "reserved-slack/beta=0.1",
    "reserved-slack/beta=0.2",
    "reserved-slack/beta=0.4",
    "periodic-repack/windows=1",
    "periodic-repack/windows=4",
    "periodic-repack/windows=16",
    "periodic-repack/windows=64",
    "packed-coo-cloud-segmented-delta/segment-width=128",
)
ABLATION_CANDIDATE_ID = "packed-coo-client-lane-delta/capacity=128"
_UNAVAILABLE_ORACLE_ID = "diagnostic-oracle/unavailable"
_UNAVAILABLE_SELECTED_ID = "tuned-fixed-policy/unavailable"
FIXED_CANDIDATE_IDS = (
    *REFERENCE_CANDIDATE_IDS[:2],
    ABLATION_CANDIDATE_ID,
    *REFERENCE_CANDIDATE_IDS[2:],
)
_ANALYSIS_BEHAVIOR_PATHS = repository_behavior_paths(EvidenceRole.ANALYZER)
_TEST_ANALYSIS_SOURCE_SHA = "1" * 40
PUBLICATION_ARTIFACT_FILENAMES = (
    "publication-verdict.json",
    "publication-effects.csv",
    "publication-summary.csv",
    "SHA256SUMS",
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "experiment_source_git_sha",
        "measurement_kind",
        "bandwidth_mbps",
        "partition_resampling_seed",
        "partition_resampling_repetitions",
        "calibration_classification_seed",
        "calibration_classification_repetitions",
        "dataset_ids",
        "semantics",
        "evaluated_freshness_seconds",
        "primary_confirmatory_family",
        "rho_values",
        "fixed_candidate_ids",
        "reference_candidate_ids",
        "ablation_candidate_ids",
        "comparator_candidate_id",
        "calibration",
        "trace_units",
        "cell_bindings",
        "records",
    }
)
_CALIBRATION_KEYS = frozenset(
    {
        "schema_version",
        "primitive_names",
        "operation_order_seed",
        "measurement_block_count",
        "measurement_stop_rule",
        "raw_repetition_blocks",
    }
)
_CALIBRATION_BLOCK_KEYS = frozenset(
    {
        "schema_version",
        "block_ordinal",
        "operation_order",
        "seconds_by_primitive",
    }
)
_TRACE_UNIT_KEYS = frozenset(
    {
        "schema_version",
        "experiment_source_git_sha",
        "dataset_id",
        "semantics",
        "source_partition",
        "trace_manifest_sha256",
        "mapping_sha256",
        "accepted_events_sha256",
        "accepted_raw_events_total",
        "warmup_accepted_event_group_range",
        "tuning_accepted_event_group_range",
        "heldout_accepted_event_group_range",
        "accepted_event_group_ranges_sha256",
        "replay_receipt_sha256",
        "source_bundle_sha256",
        "trace_binding_sha256",
    }
)
_CELL_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "experiment_source_git_sha",
        "dataset_id",
        "semantics",
        "source_partition",
        "freshness_seconds",
        "rho",
        "trace_manifest_sha256",
        "mapping_sha256",
        "accepted_events_sha256",
        "accepted_raw_events_total",
        "warmup_accepted_event_group_range",
        "tuning_accepted_event_group_range",
        "heldout_accepted_event_group_range",
        "accepted_event_group_ranges_sha256",
        "replay_receipt_sha256",
        "source_bundle_sha256",
        "trace_binding_sha256",
        "tuning_update_count",
        "tuning_query_count",
        "heldout_update_count",
        "heldout_query_count",
        "event_schedule_schema_version",
        "event_schedule_sha256",
        "query_vector_schema_version",
        "query_vector_sha256",
        "cell_binding_sha256",
    }
)
_TRACE_DIGEST_FIELDS = (
    "trace_manifest_sha256",
    "mapping_sha256",
    "accepted_events_sha256",
    "accepted_event_group_ranges_sha256",
    "replay_receipt_sha256",
    "source_bundle_sha256",
)
_ACCEPTED_EVENT_RANGE_FIELDS = (
    "accepted_raw_events_total",
    "warmup_accepted_event_group_range",
    "tuning_accepted_event_group_range",
    "heldout_accepted_event_group_range",
)
_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "semantics",
        "source_partition",
        "freshness_seconds",
        "rho",
        "phase",
        "record_kind",
        "candidate_id",
        "candidate_role",
        "selection_source",
        "cell_binding_sha256",
        "outcome",
        "failure_reason",
        "update_count",
        "query_count",
        "update_primitive_counts",
        "query_primitive_counts",
        "update_serialized_bytes",
        "query_serialized_bytes",
    }
)
_MEASUREMENT_QUANTITY_FIELDS = (
    "update_primitive_counts",
    "query_primitive_counts",
    "update_serialized_bytes",
    "query_serialized_bytes",
)
_OUTCOMES = frozenset({"complete", "failed", "timeout", "infeasible", "missing", "ineligible"})
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PRACTICAL_THRESHOLD = Fraction(15, 100)


@dataclass(frozen=True, slots=True)
class _Record:
    dataset_id: str
    semantics: str
    source_partition: int
    freshness_seconds: str
    rho: str
    phase: str
    record_kind: str
    candidate_id: str
    candidate_role: str
    selection_source: str
    cell_binding_sha256: str
    outcome: str
    failure_reason: str | None
    update_count: int | None
    query_count: int | None
    update_primitive_counts: tuple[int, ...] | None
    query_primitive_counts: tuple[int, ...] | None
    update_serialized_bytes: int | None
    query_serialized_bytes: int | None

    @property
    def cell_key(self) -> tuple[str, str, int, str, str]:
        return (
            self.dataset_id,
            self.semantics,
            self.source_partition,
            self.freshness_seconds,
            self.rho,
        )


@dataclass(frozen=True, slots=True)
class _Cell:
    key: tuple[str, str, int, str, str]
    tuning_fixed: Mapping[str, _Record]
    heldout_fixed: Mapping[str, _Record]
    selected: _Record
    oracle: _Record


@dataclass(frozen=True, slots=True)
class _CellBinding:
    digest: str
    tuning_update_count: int
    tuning_query_count: int
    heldout_update_count: int
    heldout_query_count: int


@dataclass(frozen=True, slots=True)
class _DecodedInput:
    experiment_source_git_sha: str
    primitive_names: tuple[str, ...]
    raw_repetition_blocks: tuple[tuple[Fraction, ...], ...]
    cells: tuple[_Cell, ...]
    input_sha256: str


@dataclass(frozen=True, slots=True)
class _AnalysisSource:
    git_sha: str
    attestation: str


@dataclass(frozen=True, slots=True)
class _SourceCompatibility:
    evidence_freeze_git_sha: str
    kind: str
    receipt_sha256: str | None
    receipt_document: Mapping[str, object] | None
    post_run_anchor_verified: bool
    runtime_execution_isolation_authority_state: str
    runtime_execution_isolation_verified: bool


@dataclass(frozen=True, slots=True)
class _LinearCostProfile:
    total_coefficients: tuple[tuple[int, Fraction], ...]
    total_byte_seconds: Fraction
    update_bytes: Fraction
    query_coefficients: tuple[tuple[int, Fraction], ...]
    query_byte_seconds: Fraction


@dataclass(frozen=True, slots=True)
class _CalibrationRhoSensitivity:
    median_effect_distribution: tuple[Fraction, ...] | None
    all_positive_match_count: int
    median_threshold_match_count: int
    all_nondominated_match_count: int
    rho_gate_match_count: int


@dataclass(frozen=True, slots=True)
class _CalibrationGroupSensitivity:
    by_rho: Mapping[str, _CalibrationRhoSensitivity]
    adjacent_pairs_match_count: int


def _object(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{field} must be a JSON object")
    return value


def _list(value: object, field: str) -> list[object]:
    if type(value) is not list:
        raise ValueError(f"{field} must be a JSON array")
    return value


def _exact_keys(value: Mapping[str, object], keys: frozenset[str], field: str) -> None:
    if set(value) != keys:
        raise ValueError(
            f"{field} keys must be exact; missing={sorted(keys - set(value))}, "
            f"extra={sorted(set(value) - keys)}"
        )


def _experiment_source_from_document(document: Mapping[str, object]) -> str:
    source_git_sha = document["experiment_source_git_sha"]
    if type(source_git_sha) is not str or _LOWER_GIT_SHA.fullmatch(source_git_sha) is None:
        raise ValueError(
            "heldout input.experiment_source_git_sha must be a lowercase 40-digit Git SHA"
        )
    return source_git_sha


def _strict_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{field} must be a strict integer >= {minimum}")
    return value


def _fraction_from_text(value: object, field: str, *, positive: bool = False) -> Fraction:
    try:
        parsed = Fraction(value) if type(value) is str else Fraction(-1)
    except (ValueError, ZeroDivisionError):
        parsed = Fraction(-1)
    if parsed < 0 or _fraction_text(parsed) != value:
        raise ValueError(f"{field} must be a canonical nonnegative exact rational string")
    if positive and parsed <= 0:
        raise ValueError(f"{field} must be positive")
    return parsed


def _fraction_text(value: Fraction) -> str:
    if value == 0:
        return "0"
    denominator = value.denominator
    terminating = denominator
    powers_of_two = 0
    while terminating % 2 == 0:
        terminating //= 2
        powers_of_two += 1
    powers_of_five = 0
    while terminating % 5 == 0:
        terminating //= 5
        powers_of_five += 1
    if terminating != 1:
        return f"{value.numerator}/{value.denominator}"

    decimal_places = max(powers_of_two, powers_of_five)
    scaled_numerator = abs(value.numerator)
    scaled_numerator *= 2 ** (decimal_places - powers_of_two)
    scaled_numerator *= 5 ** (decimal_places - powers_of_five)
    whole, fractional = divmod(scaled_numerator, 10**decimal_places)
    sign = "-" if value < 0 else ""
    if fractional == 0:
        return f"{sign}{whole}"
    fractional_text = f"{fractional:0{decimal_places}d}".rstrip("0")
    return f"{sign}{whole}.{fractional_text}"


def canonical_json_bytes(payload: object) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("payload must contain only finite canonical JSON values") from error
    return (rendered + "\n").encode("ascii")


class _Shake256CounterSampler:
    """Deterministic XOF stream with exact rejection-based bounded sampling."""

    __slots__ = ("_buffer", "_counter", "_domain")

    def __init__(self, domain: Mapping[str, object]) -> None:
        self._domain = canonical_json_bytes(domain)
        self._counter = 0
        self._buffer = b""

    def _read(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer += hashlib.shake_256(
                self._domain + self._counter.to_bytes(16, "big")
            ).digest(64)
            self._counter += 1
        output, self._buffer = self._buffer[:size], self._buffer[size:]
        return output

    def randbelow(self, upper_bound: int) -> int:
        if type(upper_bound) is not int or upper_bound <= 0:
            raise ValueError("sampler upper_bound must be a strict positive integer")
        width = max(1, (upper_bound.bit_length() + 7) // 8)
        space = 1 << (8 * width)
        acceptance_limit = space - (space % upper_bound)
        while True:
            candidate = int.from_bytes(self._read(width), "big")
            if candidate < acceptance_limit:
                return candidate % upper_bound


def _sampling_domain(
    *,
    analysis_kind: str,
    seed: int,
    semantics: str | None = None,
    freshness_seconds: str | None = None,
    block_ordinal: int | None = None,
) -> dict[str, object]:
    domain: dict[str, object] = {
        "analysis_kind": analysis_kind,
        "schema_version": SAMPLER_SCHEMA,
        "seed": seed,
    }
    if semantics is not None:
        domain["semantics"] = semantics
    if freshness_seconds is not None:
        domain["freshness_seconds"] = freshness_seconds
    if block_ordinal is not None:
        domain["block_ordinal"] = block_ordinal
    return domain


def _sampling_stream(
    *,
    analysis_kind: str,
    seed: int,
    semantics: str | None = None,
    freshness_seconds: str | None = None,
    block_ordinal: int | None = None,
) -> _Shake256CounterSampler:
    return _Shake256CounterSampler(
        _sampling_domain(
            analysis_kind=analysis_kind,
            seed=seed,
            semantics=semantics,
            freshness_seconds=freshness_seconds,
            block_ordinal=block_ordinal,
        )
    )


def _sampling_stream_known_answer_sha256() -> str:
    partition = _sampling_stream(
        analysis_kind="partition-resampling",
        seed=PARTITION_RESAMPLING_SEED,
        semantics=PRIMARY_CONFIRMATORY_FAMILY[0],
        freshness_seconds=PRIMARY_CONFIRMATORY_FAMILY[1],
    )
    calibration = _sampling_stream(
        analysis_kind="calibration-classification",
        seed=CALIBRATION_CLASSIFICATION_SEED,
        semantics=PRIMARY_CONFIRMATORY_FAMILY[0],
        freshness_seconds=PRIMARY_CONFIRMATORY_FAMILY[1],
    )
    answer = {
        "calibration_classification_primary_first_20_randbelow_14": [
            calibration.randbelow(14) for _ in range(20)
        ],
        "partition_resampling_primary_first_20_randbelow_5": [
            partition.randbelow(PUBLICATION_SOURCE_PARTITION_COUNT) for _ in range(20)
        ],
    }
    return hashlib.sha256(canonical_json_bytes(answer)).hexdigest()


def calibration_operation_order(block_ordinal: int) -> tuple[str, ...]:
    """Return the frozen outcome-independent operation order for one raw block."""

    block_ordinal = _strict_int(
        block_ordinal,
        "calibration block ordinal",
    )
    sampler = _sampling_stream(
        analysis_kind="calibration-operation-order",
        seed=CALIBRATION_OPERATION_ORDER_SEED,
        block_ordinal=block_ordinal,
    )
    order = list(PRIMITIVE_NAMES)
    for upper in range(len(order) - 1, 0, -1):
        selected = sampler.randbelow(upper + 1)
        order[upper], order[selected] = order[selected], order[upper]
    return tuple(order)


def _analysis_runtime_identity() -> tuple[str, str]:
    implementation = platform.python_implementation()
    version = ".".join(str(part) for part in sys.version_info[:3])
    if implementation != ANALYSIS_RUNTIME_IMPLEMENTATION or version != ANALYSIS_RUNTIME_VERSION:
        raise ValueError(
            "publication analysis requires the frozen CPython 3.12.13 runtime identity"
        )
    return implementation, version


def _make_test_analysis_source_seam():
    state: ContextVar[bool] = ContextVar(
        "publication_statistics_test_analysis_source",
        default=False,
    )

    @contextmanager
    def inject() -> Iterator[None]:
        """Simulate clean HEAD only from this repository's public-seam pytest module."""

        current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
        expected_caller = (
            Path(__file__).resolve().parents[2] / "tests/test_publication_statistics.py"
        )
        caller_paths = {
            Path(frame_info.filename).resolve() for frame_info in inspect.stack(context=0)[1:6]
        }
        if (
            not current_test.startswith("tests/test_publication_statistics.py::")
            or expected_caller not in caller_paths
        ):
            raise RuntimeError(
                "test-only analysis source seam is unavailable to production callers"
            )
        token = state.set(True)
        try:
            yield
        finally:
            state.reset(token)

    return inject, state.get


_test_only_analysis_source, _test_analysis_source_is_injected = _make_test_analysis_source_seam()


def _analysis_source() -> _AnalysisSource:
    if _test_analysis_source_is_injected():
        return _AnalysisSource(_TEST_ANALYSIS_SOURCE_SHA, "test-only-injected")
    attestation = verify_current_analysis_source(Path(__file__).resolve().parents[2])
    return _AnalysisSource(
        attestation.git_sha,
        attestation.attestation,
    )


def _verify_source_compatibility(
    *,
    experiment_source_git_sha: str,
    analysis_source_git_sha: str,
    evidence_freeze_git_sha: object,
    artifact_behavior_inventory: object,
    decoded_input_sha256: str,
    repository_root: Path,
) -> _SourceCompatibility:
    if experiment_source_git_sha == analysis_source_git_sha:
        if evidence_freeze_git_sha is not None or artifact_behavior_inventory is not None:
            raise ValueError(
                "identical experiment/analysis snapshots do not accept a caller-supplied "
                "post-run compatibility claim"
            )
        return _SourceCompatibility(
            evidence_freeze_git_sha=experiment_source_git_sha,
            kind="identical-snapshot-no-post-run-anchor",
            receipt_sha256=None,
            receipt_document=None,
            post_run_anchor_verified=False,
            runtime_execution_isolation_authority_state=(RUNTIME_EXECUTION_ISOLATION_HOLD),
            runtime_execution_isolation_verified=False,
        )
    try:
        repository_behavior_paths(EvidenceRole.DAY1B)
    except EvidenceCompatibilityHold as error:
        raise ValueError(str(error)) from error
    if type(evidence_freeze_git_sha) is not str or artifact_behavior_inventory is None:
        raise ValueError(
            "different experiment/analysis snapshots require an exact evidence-freeze SHA "
            "and artifact Behavior Set inventory for repository verification"
        )
    try:
        receipt = verify_evidence_compatibility(
            role=EvidenceRole.DAY1B,
            experiment_source_git_sha=experiment_source_git_sha,
            evidence_freeze_git_sha=evidence_freeze_git_sha,
            analysis_source_git_sha=analysis_source_git_sha,
            artifact_sha256=decoded_input_sha256,
            artifact_behavior_inventory=artifact_behavior_inventory,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise ValueError(
            f"repository evidence compatibility verification failed: {error}"
        ) from error
    document = receipt.to_document()
    if document["compatibility_verified"] is not True:
        raise ValueError("repository evidence compatibility receipt is not verified")
    return _SourceCompatibility(
        evidence_freeze_git_sha=receipt.evidence_freeze_git_sha,
        kind="repository-receipt-cross-snapshot",
        receipt_sha256=receipt.receipt_sha256,
        receipt_document=document,
        post_run_anchor_verified=True,
        runtime_execution_isolation_authority_state=(receipt.runtime_execution_isolation_state),
        runtime_execution_isolation_verified=(receipt.runtime_execution_isolation_verified),
    )


def _repository_calibration_authority_verified(
    calibration_projection: object,
    *,
    source_git_sha: str,
) -> bool:
    """Consult only the zero-argument repository seam; archives are not authority."""

    from dynamic_cssc.day2_calibration_authority import (
        Day2CalibrationAuthorityError,
        repository_day2_calibration_authority,
    )

    try:
        capability = repository_day2_calibration_authority()
        if capability.source_git_sha != source_git_sha:
            return False
        capability.validate_calibration_projection(calibration_projection)
    except Day2CalibrationAuthorityError:
        return False
    return True


def _decode_calibration(
    payload: object,
) -> tuple[tuple[str, ...], tuple[tuple[Fraction, ...], ...]]:
    calibration = _object(payload, "calibration")
    _exact_keys(calibration, _CALIBRATION_KEYS, "calibration")
    if calibration["schema_version"] != CALIBRATION_SCHEMA:
        raise ValueError("calibration.schema_version is not the frozen schema")
    names_raw = _list(calibration["primitive_names"], "calibration.primitive_names")
    if not names_raw or any(type(name) is not str for name in names_raw):
        raise ValueError("calibration.primitive_names must contain strings")
    names = tuple(names_raw)
    if names != PRIMITIVE_NAMES:
        raise ValueError("calibration.primitive_names must equal the frozen primitive vocabulary")
    if calibration["operation_order_seed"] != CALIBRATION_OPERATION_ORDER_SEED:
        raise ValueError("calibration.operation_order_seed is not the frozen seed")
    if (
        type(calibration["measurement_block_count"]) is not int
        or calibration["measurement_block_count"] != CALIBRATION_MEASUREMENT_BLOCK_COUNT
    ):
        raise ValueError("calibration.measurement_block_count is not the exact frozen count")
    if calibration["measurement_stop_rule"] != CALIBRATION_MEASUREMENT_STOP_RULE:
        raise ValueError("calibration.measurement_stop_rule is not the frozen stop rule")
    raw_blocks = _list(
        calibration["raw_repetition_blocks"],
        "calibration.raw_repetition_blocks",
    )
    if len(raw_blocks) != CALIBRATION_MEASUREMENT_BLOCK_COUNT:
        raise ValueError(
            "calibration raw blocks must equal the exact outcome-independent frozen count"
        )
    decoded_blocks: list[tuple[Fraction, ...]] = []
    for block_ordinal, raw_block in enumerate(raw_blocks):
        field = f"calibration.raw_repetition_blocks[{block_ordinal}]"
        block = _object(raw_block, field)
        _exact_keys(block, _CALIBRATION_BLOCK_KEYS, field)
        if block["schema_version"] != CALIBRATION_BLOCK_SCHEMA:
            raise ValueError(f"{field}.schema_version is not the frozen schema")
        observed_block_ordinal = _strict_int(
            block["block_ordinal"],
            f"{field}.block_ordinal",
        )
        if observed_block_ordinal != block_ordinal:
            raise ValueError(f"{field}.block_ordinal must equal its canonical array ordinal")
        operation_order = _list(block["operation_order"], f"{field}.operation_order")
        expected_order = calibration_operation_order(block_ordinal)
        if tuple(operation_order) != expected_order:
            raise ValueError(
                f"{field}.operation_order must equal the frozen outcome-independent permutation"
            )
        seconds_by_primitive = _object(
            block["seconds_by_primitive"],
            f"{field}.seconds_by_primitive",
        )
        if set(seconds_by_primitive) != set(names):
            raise ValueError(
                f"{field}.seconds_by_primitive keys must exactly match primitive_names"
            )
        decoded_blocks.append(
            tuple(
                _fraction_from_text(
                    seconds_by_primitive[name],
                    f"{field}.seconds_by_primitive.{name}",
                    positive=True,
                )
                for name in names
            )
        )
    return names, tuple(decoded_blocks)


def _binding_digest(payload: Mapping[str, object], digest_field: str) -> str:
    unsigned = {key: value for key, value in payload.items() if key != digest_field}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _accepted_event_group_range(value: object, field: str) -> tuple[int, int]:
    raw_range = _list(value, field)
    if len(raw_range) != 2:
        raise ValueError(f"{field} must be one exact half-open [start, end] range")
    start = _strict_int(raw_range[0], f"{field}[0]")
    end = _strict_int(raw_range[1], f"{field}[1]")
    if end <= start:
        raise ValueError(f"{field} must be one nonempty half-open [start, end] range")
    return start, end


def _decode_accepted_event_group_ranges(
    payload: Mapping[str, object],
    field: str,
) -> tuple[int, tuple[int, int], tuple[int, int], tuple[int, int], str]:
    total = _strict_int(
        payload["accepted_raw_events_total"],
        f"{field}.accepted_raw_events_total",
        minimum=1,
    )
    warmup = _accepted_event_group_range(
        payload["warmup_accepted_event_group_range"],
        f"{field}.warmup_accepted_event_group_range",
    )
    tuning = _accepted_event_group_range(
        payload["tuning_accepted_event_group_range"],
        f"{field}.tuning_accepted_event_group_range",
    )
    heldout = _accepted_event_group_range(
        payload["heldout_accepted_event_group_range"],
        f"{field}.heldout_accepted_event_group_range",
    )
    expected = (
        (0, total // 10),
        (total // 10, total * 4 // 10),
        (total * 4 // 10, total),
    )
    if (warmup, tuning, heldout) != expected:
        raise ValueError(
            f"{field} accepted-event group ranges must equal the exact common "
            "10/30/60 half-open ordinal split"
        )
    receipt = _require_sha256(
        payload["accepted_event_group_ranges_sha256"],
        f"{field}.accepted_event_group_ranges_sha256",
    )
    receipt_payload = {name: payload[name] for name in _ACCEPTED_EVENT_RANGE_FIELDS}
    if receipt != hashlib.sha256(canonical_json_bytes(receipt_payload)).hexdigest():
        raise ValueError(
            f"{field}.accepted_event_group_ranges_sha256 does not bind the exact ranges"
        )
    return total, warmup, tuning, heldout, receipt


def _phase_query_count(accepted_range: tuple[int, int], rho: str) -> int:
    start, end = accepted_range
    ratio = Fraction(rho)
    return (end * ratio.numerator // ratio.denominator) - (
        start * ratio.numerator // ratio.denominator
    )


def _decode_trace_bindings(
    trace_units_payload: object,
    cell_bindings_payload: object,
    experiment_source_git_sha: str,
) -> dict[tuple[str, str, int, str, str], _CellBinding]:
    raw_trace_units = _list(trace_units_payload, "heldout input.trace_units")
    expected_unit_keys = tuple(
        (dataset_id, semantics, partition)
        for dataset_id in DATASET_IDS
        for semantics in SEMANTICS
        for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
    )
    if len(raw_trace_units) != len(expected_unit_keys):
        raise ValueError("trace_units must contain exactly 30 canonical trace units")

    trace_units: dict[tuple[str, str, int], dict[str, object]] = {}
    for index, (raw, expected_key) in enumerate(
        zip(raw_trace_units, expected_unit_keys, strict=True)
    ):
        field = f"trace_units[{index}]"
        unit = _object(raw, field)
        _exact_keys(unit, _TRACE_UNIT_KEYS, field)
        if unit["schema_version"] != TRACE_UNIT_SCHEMA:
            raise ValueError(f"{field}.schema_version is not the frozen schema")
        if (
            type(unit["experiment_source_git_sha"]) is not str
            or unit["experiment_source_git_sha"] != experiment_source_git_sha
        ):
            raise ValueError(f"{field} does not bind the top-level experiment source Git SHA")
        actual_key = (unit["dataset_id"], unit["semantics"], unit["source_partition"])
        if actual_key != expected_key or any(
            type(value) is not expected_type
            for value, expected_type in zip(actual_key, (str, str, int), strict=True)
        ):
            raise ValueError("trace_units must use the exact canonical unit order")
        for digest_field in _TRACE_DIGEST_FIELDS:
            _require_sha256(unit[digest_field], f"{field}.{digest_field}")
        _decode_accepted_event_group_ranges(unit, field)
        trace_binding = _require_sha256(
            unit["trace_binding_sha256"],
            f"{field}.trace_binding_sha256",
        )
        if trace_binding != _binding_digest(unit, "trace_binding_sha256"):
            raise ValueError(f"{field}.trace_binding_sha256 does not bind the trace unit")
        trace_units[expected_key] = unit

    for dataset_id in DATASET_IDS:
        for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT):
            t1 = trace_units[(dataset_id, "T1", partition)]
            t2 = trace_units[(dataset_id, "T2", partition)]
            for shared_field in (
                "mapping_sha256",
                "accepted_events_sha256",
                *_ACCEPTED_EVENT_RANGE_FIELDS,
                "accepted_event_group_ranges_sha256",
                "source_bundle_sha256",
            ):
                if t1[shared_field] != t2[shared_field]:
                    raise ValueError(
                        "T1 and T2 must bind the same paired raw trace, mapping, and source bundle"
                    )

    raw_cell_bindings = _list(cell_bindings_payload, "heldout input.cell_bindings")
    expected_cell_keys = tuple(
        (dataset_id, semantics, partition, freshness, rho)
        for dataset_id in DATASET_IDS
        for semantics in SEMANTICS
        for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
        for freshness in FRESHNESS_VALUES
        for rho in RHO_VALUES
    )
    if len(raw_cell_bindings) != len(expected_cell_keys):
        raise ValueError("cell_bindings must contain exactly 540 canonical cells")

    cell_binding_by_key: dict[tuple[str, str, int, str, str], _CellBinding] = {}
    event_schedule_by_trace_and_rho: dict[
        tuple[str, str, int, str],
        tuple[str, str, int, int, int, int],
    ] = {}
    event_schedule_rho_by_trace_and_digest: dict[
        tuple[str, str, int, str],
        str,
    ] = {}
    query_vector_by_trace: dict[tuple[str, str, int], tuple[str, str]] = {}
    for index, (raw, expected_key) in enumerate(
        zip(raw_cell_bindings, expected_cell_keys, strict=True)
    ):
        field = f"cell_bindings[{index}]"
        cell = _object(raw, field)
        _exact_keys(cell, _CELL_BINDING_KEYS, field)
        if cell["schema_version"] != CELL_BINDING_SCHEMA:
            raise ValueError(f"{field}.schema_version is not the frozen schema")
        if (
            type(cell["experiment_source_git_sha"]) is not str
            or cell["experiment_source_git_sha"] != experiment_source_git_sha
        ):
            raise ValueError(f"{field} does not bind the top-level experiment source Git SHA")
        actual_key = (
            cell["dataset_id"],
            cell["semantics"],
            cell["source_partition"],
            cell["freshness_seconds"],
            cell["rho"],
        )
        if actual_key != expected_key or any(
            type(value) is not expected_type
            for value, expected_type in zip(
                actual_key,
                (str, str, int, str, str),
                strict=True,
            )
        ):
            raise ValueError("cell_bindings must use the exact canonical cell order")
        unit = trace_units[expected_key[:3]]
        for digest_field in _TRACE_DIGEST_FIELDS:
            _require_sha256(cell[digest_field], f"{field}.{digest_field}")
            if cell[digest_field] != unit[digest_field]:
                raise ValueError(f"{field}.{digest_field} does not match its trace unit")
        _total, _warmup, tuning_range, heldout_range, _receipt = (
            _decode_accepted_event_group_ranges(cell, field)
        )
        for range_field in _ACCEPTED_EVENT_RANGE_FIELDS:
            if cell[range_field] != unit[range_field]:
                raise ValueError(
                    f"{field}.{range_field} does not match its trace unit's common "
                    "accepted-event boundaries"
                )
        trace_binding = _require_sha256(
            cell["trace_binding_sha256"],
            f"{field}.trace_binding_sha256",
        )
        if trace_binding != unit["trace_binding_sha256"]:
            raise ValueError(f"{field}.trace_binding_sha256 splices an unrelated trace")
        tuning_update_count = _strict_int(
            cell["tuning_update_count"],
            f"{field}.tuning_update_count",
            minimum=1,
        )
        tuning_query_count = _strict_int(
            cell["tuning_query_count"],
            f"{field}.tuning_query_count",
            minimum=1,
        )
        heldout_update_count = _strict_int(
            cell["heldout_update_count"],
            f"{field}.heldout_update_count",
            minimum=1,
        )
        heldout_query_count = _strict_int(
            cell["heldout_query_count"],
            f"{field}.heldout_query_count",
            minimum=1,
        )
        expected_phase_counts = (
            tuning_range[1] - tuning_range[0],
            _phase_query_count(tuning_range, expected_key[4]),
            heldout_range[1] - heldout_range[0],
            _phase_query_count(heldout_range, expected_key[4]),
        )
        actual_phase_counts = (
            tuning_update_count,
            tuning_query_count,
            heldout_update_count,
            heldout_query_count,
        )
        if actual_phase_counts != expected_phase_counts:
            raise ValueError(
                f"{field} phase counts must be derived from its accepted-event ranges "
                "and exact rho schedule"
            )
        if cell["event_schedule_schema_version"] != EVENT_SCHEDULE_SCHEMA:
            raise ValueError(
                f"{field}.event_schedule_schema_version is not the frozen "
                "SETs-TICK-queries accepted-event schedule schema"
            )
        event_schedule = _require_sha256(
            cell["event_schedule_sha256"],
            f"{field}.event_schedule_sha256",
        )
        if cell["query_vector_schema_version"] != QUERY_VECTOR_SCHEMA:
            raise ValueError(
                f"{field}.query_vector_schema_version is not the frozen one-vector-per-unit schema"
            )
        query_vector = _require_sha256(
            cell["query_vector_sha256"],
            f"{field}.query_vector_sha256",
        )
        event_schedule_contract = (
            EVENT_SCHEDULE_SCHEMA,
            event_schedule,
            *actual_phase_counts,
        )
        trace_and_rho = (*expected_key[:3], expected_key[4])
        prior_event_schedule_contract = event_schedule_by_trace_and_rho.setdefault(
            trace_and_rho,
            event_schedule_contract,
        )
        if event_schedule_contract != prior_event_schedule_contract:
            raise ValueError(
                "all freshness cells for one trace and rho must bind the same accepted-event "
                "event schedule and phase counts"
            )
        trace_and_event_schedule = (*expected_key[:3], event_schedule)
        prior_event_schedule_rho = event_schedule_rho_by_trace_and_digest.setdefault(
            trace_and_event_schedule,
            expected_key[4],
        )
        if prior_event_schedule_rho != expected_key[4]:
            raise ValueError(
                "one trace cannot bind the same accepted-event event schedule to "
                "different rho values"
            )
        query_vector_contract = (QUERY_VECTOR_SCHEMA, query_vector)
        prior_query_vector_contract = query_vector_by_trace.setdefault(
            expected_key[:3],
            query_vector_contract,
        )
        if query_vector_contract != prior_query_vector_contract:
            raise ValueError(
                "all freshness and rho cells for one trace must bind the same "
                "one-vector-per-unit query vector"
            )
        cell_binding = _require_sha256(
            cell["cell_binding_sha256"],
            f"{field}.cell_binding_sha256",
        )
        if cell_binding != _binding_digest(cell, "cell_binding_sha256"):
            raise ValueError(f"{field}.cell_binding_sha256 does not bind the canonical cell")
        cell_binding_by_key[expected_key] = _CellBinding(
            digest=cell_binding,
            tuning_update_count=tuning_update_count,
            tuning_query_count=tuning_query_count,
            heldout_update_count=heldout_update_count,
            heldout_query_count=heldout_query_count,
        )
    return cell_binding_by_key


def _decode_primitive_counts(
    value: object,
    field: str,
    primitive_names: tuple[str, ...],
) -> tuple[int, ...]:
    counts = _object(value, field)
    if set(counts) != set(primitive_names):
        raise ValueError(f"{field} keys must exactly match calibration primitive_names")
    return tuple(_strict_int(counts[name], f"{field}.{name}") for name in primitive_names)


def _decode_record(
    value: object,
    index: int,
    primitive_names: tuple[str, ...],
) -> _Record:
    field = f"records[{index}]"
    payload = _object(value, field)
    _exact_keys(payload, _RECORD_KEYS, field)
    if payload["schema_version"] != HELDOUT_RECORD_SCHEMA:
        raise ValueError(f"{field}.schema_version is not the frozen schema")

    dataset_id = payload["dataset_id"]
    semantics = payload["semantics"]
    source_partition = payload["source_partition"]
    freshness = payload["freshness_seconds"]
    rho = payload["rho"]
    phase = payload["phase"]
    if type(dataset_id) is not str or dataset_id not in DATASET_IDS:
        raise ValueError(f"{field}.dataset_id is not a frozen primary dataset")
    if type(semantics) is not str or semantics not in SEMANTICS:
        raise ValueError(f"{field}.semantics must be T1 or T2")
    source_partition = _strict_int(source_partition, f"{field}.source_partition")
    if source_partition not in range(PUBLICATION_SOURCE_PARTITION_COUNT):
        raise ValueError(f"{field}.source_partition must be in [0, 4]")
    if type(freshness) is not str or freshness not in FRESHNESS_VALUES:
        raise ValueError(f"{field}.freshness_seconds is not a primary freshness value")
    if type(rho) is not str or rho not in RHO_VALUES:
        raise ValueError(f"{field}.rho is not in the frozen grid")

    record_kind = payload["record_kind"]
    candidate_id = payload["candidate_id"]
    candidate_role = payload["candidate_role"]
    selection_source = payload["selection_source"]
    cell_binding_sha256 = _require_sha256(
        payload["cell_binding_sha256"],
        f"{field}.cell_binding_sha256",
    )
    if type(candidate_id) is not str or candidate_id not in FIXED_CANDIDATE_IDS:
        raise ValueError(f"{field}.candidate_id must identify a frozen fixed candidate")
    if (
        phase == "tuning-prefix"
        and record_kind == "fixed-candidate"
        and candidate_id in REFERENCE_CANDIDATE_IDS
    ):
        expected_identity = ("reference", "fixed-reference-tuning-prefix")
    elif (
        phase == "held-out"
        and record_kind == "fixed-candidate"
        and candidate_id in REFERENCE_CANDIDATE_IDS
    ):
        expected_identity = ("reference", "fixed-reference-held-out")
    elif (
        phase == "held-out"
        and record_kind == "fixed-candidate"
        and candidate_id == ABLATION_CANDIDATE_ID
    ):
        expected_identity = ("ablation", "fixed-ablation-held-out")
    else:
        raise ValueError(
            f"{field} must be a physical fixed execution; aliases, oracle records, "
            "and tuning-prefix ablations are forbidden"
        )
    if (candidate_role, selection_source) != expected_identity:
        raise ValueError(f"{field} candidate role and selection source contradict record_kind")

    outcome = payload["outcome"]
    if type(outcome) is not str or outcome not in _OUTCOMES:
        raise ValueError(f"{field}.outcome is outside the closed outcome taxonomy")
    failure_reason = payload["failure_reason"]
    update_count = _strict_int(payload["update_count"], f"{field}.update_count", minimum=1)
    query_count = _strict_int(payload["query_count"], f"{field}.query_count", minimum=1)
    if outcome == "complete":
        if failure_reason is not None:
            raise ValueError(f"{field}.failure_reason must be null for a complete outcome")
        update_primitive_counts = _decode_primitive_counts(
            payload["update_primitive_counts"],
            f"{field}.update_primitive_counts",
            primitive_names,
        )
        query_primitive_counts = _decode_primitive_counts(
            payload["query_primitive_counts"],
            f"{field}.query_primitive_counts",
            primitive_names,
        )
        update_bytes = _strict_int(
            payload["update_serialized_bytes"],
            f"{field}.update_serialized_bytes",
        )
        query_bytes = _strict_int(
            payload["query_serialized_bytes"],
            f"{field}.query_serialized_bytes",
        )
    else:
        if type(failure_reason) is not str or not failure_reason.strip():
            raise ValueError(f"{field}.failure_reason must describe an incomplete outcome")
        if any(payload[name] is not None for name in _MEASUREMENT_QUANTITY_FIELDS):
            raise ValueError(
                f"{field} incomplete outcomes must not carry partial measured quantities"
            )
        update_primitive_counts = None
        query_primitive_counts = None
        update_bytes = None
        query_bytes = None

    return _Record(
        dataset_id=dataset_id,
        semantics=semantics,
        source_partition=source_partition,
        freshness_seconds=freshness,
        rho=rho,
        phase=phase,
        record_kind=record_kind,
        candidate_id=candidate_id,
        candidate_role=candidate_role,
        selection_source=selection_source,
        cell_binding_sha256=cell_binding_sha256,
        outcome=outcome,
        failure_reason=failure_reason,
        update_count=update_count,
        query_count=query_count,
        update_primitive_counts=update_primitive_counts,
        query_primitive_counts=query_primitive_counts,
        update_serialized_bytes=update_bytes,
        query_serialized_bytes=query_bytes,
    )


def _record_order(record: _Record) -> tuple[int, int, int, int, int, int, int]:
    record_rank = 0 if record.phase == "tuning-prefix" else 1
    candidate_rank = (
        REFERENCE_CANDIDATE_IDS.index(record.candidate_id)
        if record.phase == "tuning-prefix"
        else FIXED_CANDIDATE_IDS.index(record.candidate_id)
    )
    return (
        DATASET_IDS.index(record.dataset_id),
        SEMANTICS.index(record.semantics),
        record.source_partition,
        FRESHNESS_VALUES.index(record.freshness_seconds),
        RHO_VALUES.index(record.rho),
        record_rank,
        candidate_rank,
    )


def _alias_comparison_tuple(record: _Record) -> tuple[object, ...]:
    return (
        record.outcome,
        record.failure_reason,
        record.update_count,
        record.query_count,
        record.update_primitive_counts,
        record.query_primitive_counts,
        record.update_serialized_bytes,
        record.query_serialized_bytes,
    )


def _decode_input(payload: object) -> _DecodedInput:
    document = _object(payload, "heldout input")
    _exact_keys(document, _TOP_LEVEL_KEYS, "heldout input")
    exact_values: tuple[tuple[str, object], ...] = (
        ("schema_version", HELDOUT_SCHEMA),
        (
            "measurement_kind",
            "heldout-calibrated-component-complete-protocol-serialization",
        ),
        ("bandwidth_mbps", BANDWIDTH_MBPS),
        ("partition_resampling_seed", PARTITION_RESAMPLING_SEED),
        ("partition_resampling_repetitions", PARTITION_RESAMPLING_REPETITIONS),
        ("calibration_classification_seed", CALIBRATION_CLASSIFICATION_SEED),
        (
            "calibration_classification_repetitions",
            CALIBRATION_CLASSIFICATION_REPETITIONS,
        ),
        ("dataset_ids", list(DATASET_IDS)),
        ("semantics", list(SEMANTICS)),
        ("evaluated_freshness_seconds", list(FRESHNESS_VALUES)),
        ("primary_confirmatory_family", list(PRIMARY_CONFIRMATORY_FAMILY)),
        ("rho_values", list(RHO_VALUES)),
        ("fixed_candidate_ids", list(FIXED_CANDIDATE_IDS)),
        ("reference_candidate_ids", list(REFERENCE_CANDIDATE_IDS)),
        ("ablation_candidate_ids", [ABLATION_CANDIDATE_ID]),
        ("comparator_candidate_id", COMPARATOR_CANDIDATE_ID),
    )
    for field, expected in exact_values:
        if type(document[field]) is not type(expected) or document[field] != expected:
            raise ValueError(f"heldout input.{field} must equal the exact frozen value")
    experiment_source_git_sha = _experiment_source_from_document(document)

    primitive_names, raw_repetition_blocks = _decode_calibration(document["calibration"])
    cell_binding_by_key = _decode_trace_bindings(
        document["trace_units"],
        document["cell_bindings"],
        experiment_source_git_sha,
    )
    raw_records = _list(document["records"], "heldout input.records")
    records_per_cell = len(REFERENCE_CANDIDATE_IDS) + len(FIXED_CANDIDATE_IDS)
    expected_record_count = 3 * 2 * 5 * 2 * 9 * records_per_cell
    if len(raw_records) != expected_record_count:
        raise ValueError(
            "heldout input must contain the exact 30 units x 2 freshness x 9 rho x "
            "(13 tuning references + 14 held-out fixed executions) record count"
        )
    records = tuple(
        _decode_record(value, index, primitive_names) for index, value in enumerate(raw_records)
    )
    if tuple(_record_order(record) for record in records) != tuple(
        sorted(_record_order(record) for record in records)
    ):
        raise ValueError("heldout records must use the canonical unit/candidate order")

    by_cell: dict[tuple[str, str, int, str, str], list[_Record]] = {}
    for record in records:
        binding = cell_binding_by_key[record.cell_key]
        if record.cell_binding_sha256 != binding.digest:
            raise ValueError("record cell_binding_sha256 does not bind its canonical trace cell")
        expected_counts = (
            (binding.tuning_update_count, binding.tuning_query_count)
            if record.phase == "tuning-prefix"
            else (binding.heldout_update_count, binding.heldout_query_count)
        )
        if (record.update_count, record.query_count) != expected_counts:
            raise ValueError(
                "each physical record's phase update/query counts must equal its cell binding"
            )
        by_cell.setdefault(record.cell_key, []).append(record)
    expected_cell_keys = tuple(
        (dataset_id, semantics, partition, freshness, rho)
        for dataset_id in DATASET_IDS
        for semantics in SEMANTICS
        for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
        for freshness in FRESHNESS_VALUES
        for rho in RHO_VALUES
    )
    if tuple(by_cell) != expected_cell_keys:
        raise ValueError("heldout records must cover each canonical unit/cell exactly once")

    cells: list[_Cell] = []
    point_costs = tuple(
        _median(tuple(block[index] for block in raw_repetition_blocks))
        for index in range(len(primitive_names))
    )
    for cell_key in expected_cell_keys:
        cell_records = by_cell[cell_key]
        tuning_records = [
            record
            for record in cell_records
            if record.phase == "tuning-prefix" and record.record_kind == "fixed-candidate"
        ]
        heldout_records = [
            record
            for record in cell_records
            if record.phase == "held-out" and record.record_kind == "fixed-candidate"
        ]
        if tuple(record.candidate_id for record in tuning_records) != REFERENCE_CANDIDATE_IDS:
            raise ValueError("each cell must contain the exact 13 tuning-prefix references")
        if tuple(record.candidate_id for record in heldout_records) != FIXED_CANDIDATE_IDS:
            raise ValueError("each cell must contain the exact 14 held-out fixed executions")
        tuning_fixed = {record.candidate_id: record for record in tuning_records}
        heldout_fixed = {record.candidate_id: record for record in heldout_records}
        if all(record.outcome == "complete" for record in tuning_records):
            selected_candidate_id = min(
                (
                    _record_cost(record, point_costs)[0],
                    candidate_id,
                )
                for candidate_id, record in tuning_fixed.items()
            )[1]
            selected_basis = heldout_fixed[selected_candidate_id]
            alias = replace(
                selected_basis,
                record_kind="tuned-fixed-policy",
                candidate_role="reference",
                selection_source="tuning-prefix-selected",
            )
        else:
            selected_basis = heldout_fixed[min(REFERENCE_CANDIDATE_IDS)]
            alias = replace(
                selected_basis,
                record_kind="tuned-fixed-policy",
                candidate_id=_UNAVAILABLE_SELECTED_ID,
                candidate_role="reference",
                selection_source="tuning-prefix-selected",
                outcome="ineligible",
                failure_reason=(
                    "tuned policy unavailable because one or more tuning-prefix "
                    "references are incomplete"
                ),
                update_primitive_counts=None,
                query_primitive_counts=None,
                update_serialized_bytes=None,
                query_serialized_bytes=None,
            )
        if all(
            heldout_fixed[candidate_id].outcome == "complete"
            for candidate_id in REFERENCE_CANDIDATE_IDS
        ):
            oracle_candidate_id = min(
                (
                    _record_cost(heldout_fixed[candidate_id], point_costs)[0],
                    candidate_id,
                )
                for candidate_id in REFERENCE_CANDIDATE_IDS
            )[1]
            oracle = replace(
                heldout_fixed[oracle_candidate_id],
                record_kind="diagnostic-oracle",
                candidate_role="reference",
                selection_source="held-out-hindsight-diagnostic-only",
            )
        else:
            oracle = replace(
                selected_basis,
                record_kind="diagnostic-oracle",
                candidate_id=_UNAVAILABLE_ORACLE_ID,
                candidate_role="reference",
                selection_source="held-out-hindsight-diagnostic-only",
                outcome="ineligible",
                failure_reason=(
                    "diagnostic oracle unavailable because one or more held-out "
                    "references are incomplete"
                ),
                update_primitive_counts=None,
                query_primitive_counts=None,
                update_serialized_bytes=None,
                query_serialized_bytes=None,
            )
        tuning_counts = {
            (record.update_count, record.query_count)
            for record in tuning_records
            if record.outcome == "complete"
        }
        heldout_counts = {
            (record.update_count, record.query_count)
            for record in heldout_records
            if record.outcome == "complete"
        }
        if len(tuning_counts) > 1:
            raise ValueError("tuning-prefix candidates must share paired update/query counts")
        if len(heldout_counts) > 1:
            raise ValueError("complete held-out candidates must share paired update/query counts")
        cells.append(
            _Cell(
                key=cell_key,
                tuning_fixed=tuning_fixed,
                heldout_fixed=heldout_fixed,
                selected=alias,
                oracle=oracle,
            )
        )

    return _DecodedInput(
        experiment_source_git_sha=experiment_source_git_sha,
        primitive_names=primitive_names,
        raw_repetition_blocks=raw_repetition_blocks,
        cells=tuple(cells),
        input_sha256=hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    )


def _quantile(values: Sequence[Fraction], numerator: int, denominator: int) -> Fraction:
    if not values:
        raise ValueError("cannot compute a quantile of an empty sequence")
    ordered = sorted(values)
    position = Fraction((len(ordered) - 1) * numerator, denominator)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _median(values: Sequence[Fraction]) -> Fraction:
    return _quantile(values, 1, 2)


def _point_costs(decoded: _DecodedInput) -> tuple[Fraction, ...]:
    return tuple(
        _median(tuple(block[index] for block in decoded.raw_repetition_blocks))
        for index in range(len(decoded.primitive_names))
    )


def _complete_quantities(
    record: _Record,
) -> tuple[int, int, tuple[int, ...], tuple[int, ...], int, int]:
    values = (
        record.update_count,
        record.query_count,
        record.update_primitive_counts,
        record.query_primitive_counts,
        record.update_serialized_bytes,
        record.query_serialized_bytes,
    )
    if (
        record.outcome != "complete"
        or not isinstance(values[0], int)
        or not isinstance(values[1], int)
        or not isinstance(values[2], tuple)
        or not isinstance(values[3], tuple)
        or not isinstance(values[4], int)
        or not isinstance(values[5], int)
    ):
        raise ValueError("cannot price a record without complete validated quantities")
    return values


def _record_cost(
    record: _Record,
    primitive_costs: Sequence[Fraction],
) -> tuple[Fraction, Fraction, Fraction]:
    (
        update_count,
        query_count,
        update_primitive_counts,
        query_primitive_counts,
        update_serialized_bytes,
        query_serialized_bytes,
    ) = _complete_quantities(record)
    update_compute = (
        sum(
            (
                count * cost
                for count, cost in zip(update_primitive_counts, primitive_costs, strict=True)
            ),
            Fraction(),
        )
        / update_count
    )
    query_compute = (
        sum(
            (
                count * cost
                for count, cost in zip(query_primitive_counts, primitive_costs, strict=True)
            ),
            Fraction(),
        )
        / query_count
    )
    update_bytes = Fraction(update_serialized_bytes, update_count)
    query_bytes = Fraction(query_serialized_bytes, query_count)
    query_time = query_compute + Fraction(8, BANDWIDTH_MBPS * 1_000_000) * query_bytes
    rho = Fraction(record.rho)
    total = (
        update_compute + Fraction(8, BANDWIDTH_MBPS * 1_000_000) * update_bytes + rho * query_time
    )
    return total, update_bytes, query_time


def _unit_effect(
    cell: _Cell,
    primitive_costs: Sequence[Fraction],
) -> tuple[Fraction | None, dict[str, object]]:
    selected = cell.selected
    comparator = cell.heldout_fixed[COMPARATOR_CANDIDATE_ID]
    all_tuning_complete = all(record.outcome == "complete" for record in cell.tuning_fixed.values())
    all_reference_complete = all(
        cell.heldout_fixed[candidate_id].outcome == "complete"
        for candidate_id in REFERENCE_CANDIDATE_IDS
    )
    all_candidate_complete = all_tuning_complete and all(
        record.outcome == "complete" for record in cell.heldout_fixed.values()
    )
    selected_complete = selected.outcome == "complete"
    comparator_complete = comparator.outcome == "complete"
    effect: Fraction | None = None
    selected_total: Fraction | None = None
    comparator_total: Fraction | None = None
    non_dominated = False
    dominators: list[str] = []
    selected_update_bytes: Fraction | None = None
    selected_query_time: Fraction | None = None
    if selected_complete and comparator_complete:
        selected_total, selected_update_bytes, selected_query_time = _record_cost(
            selected,
            primitive_costs,
        )
        comparator_total, _comparator_bytes, _comparator_query_time = _record_cost(
            comparator,
            primitive_costs,
        )
        if comparator_total <= 0:
            raise ValueError("the recompress-every-window comparator cost must be positive")
        effect = (comparator_total - selected_total) / comparator_total

    if all_reference_complete and selected_complete:
        if selected_update_bytes is None or selected_query_time is None:
            raise RuntimeError("complete selected record did not produce a Pareto point")
        for candidate_id in REFERENCE_CANDIDATE_IDS:
            record = cell.heldout_fixed[candidate_id]
            if candidate_id == selected.candidate_id:
                continue
            _total, update_bytes, query_time = _record_cost(record, primitive_costs)
            if (
                update_bytes <= selected_update_bytes
                and query_time <= selected_query_time
                and (update_bytes < selected_update_bytes or query_time < selected_query_time)
            ):
                dominators.append(candidate_id)
        non_dominated = not dominators

    def view_record(record: _Record, *, physical_execution: bool) -> dict[str, object]:
        total_cost = (
            _record_cost(record, primitive_costs)[0] if record.outcome == "complete" else None
        )
        return {
            "record_kind": record.record_kind,
            "candidate_id": record.candidate_id,
            "candidate_role": record.candidate_role,
            "selection_source": record.selection_source,
            "outcome": record.outcome,
            "failure_reason": record.failure_reason,
            "physical_execution": physical_execution,
            "cost_seconds": None if total_cost is None else _fraction_text(total_cost),
        }

    heldout_view = [
        view_record(cell.heldout_fixed[candidate_id], physical_execution=True)
        for candidate_id in FIXED_CANDIDATE_IDS
    ] + [
        view_record(selected, physical_execution=False),
        view_record(cell.oracle, physical_execution=False),
    ]
    dataset_id, semantics, partition, freshness, rho = cell.key
    output: dict[str, object] = {
        "dataset_id": dataset_id,
        "semantics": semantics,
        "source_partition": partition,
        "freshness_seconds": freshness,
        "rho": rho,
        "cell_binding_sha256": selected.cell_binding_sha256,
        "selected_candidate_id": selected.candidate_id,
        "selected_outcome": selected.outcome,
        "comparator_candidate_id": COMPARATOR_CANDIDATE_ID,
        "comparator_outcome": comparator.outcome,
        "all_tuning_outcomes_complete": all_tuning_complete,
        "all_reference_outcomes_complete": all_reference_complete,
        "all_candidate_outcomes_complete": all_candidate_complete,
        "ablation_candidate_id": ABLATION_CANDIDATE_ID,
        "ablation_outcome": cell.heldout_fixed[ABLATION_CANDIDATE_ID].outcome,
        "diagnostic_oracle_candidate_id": cell.oracle.candidate_id,
        "diagnostic_oracle_outcome": cell.oracle.outcome,
        "heldout_view": heldout_view,
        "effect": None if effect is None else _fraction_text(effect),
        "selected_cost_seconds": (
            None if selected_total is None else _fraction_text(selected_total)
        ),
        "comparator_cost_seconds": (
            None if comparator_total is None else _fraction_text(comparator_total)
        ),
        "selected_update_bytes_per_accepted_event_group": (
            None if selected_update_bytes is None else _fraction_text(selected_update_bytes)
        ),
        "selected_query_time_seconds_per_query": (
            None if selected_query_time is None else _fraction_text(selected_query_time)
        ),
        "selected_non_dominated": non_dominated,
        "dominating_candidate_ids": dominators,
    }
    return effect, output


def _partition_resampling_group(
    effects: Mapping[tuple[str, int, str], Fraction],
    *,
    sampler: _Shake256CounterSampler,
) -> dict[str, tuple[Fraction, ...] | None]:
    if len(effects) != len(DATASET_IDS) * 5 * len(RHO_VALUES):
        return {rho: None for rho in RHO_VALUES}
    distributions: dict[str, list[Fraction]] = {rho: [] for rho in RHO_VALUES}
    for _ in range(PARTITION_RESAMPLING_REPETITIONS):
        sampled_partitions = {
            dataset_id: tuple(
                sampler.randbelow(PUBLICATION_SOURCE_PARTITION_COUNT)
                for _ in range(PUBLICATION_SOURCE_PARTITION_COUNT)
            )
            for dataset_id in DATASET_IDS
        }
        for rho in RHO_VALUES:
            sample = [
                effects[(dataset_id, partition, rho)]
                for dataset_id in DATASET_IDS
                for partition in sampled_partitions[dataset_id]
            ]
            distributions[rho].append(_median(sample))
    return {rho: tuple(distributions[rho]) for rho in RHO_VALUES}


def _adjacent_pairs(summaries: Sequence[dict[str, object]], gate_field: str) -> list[list[str]]:
    passing = {summary["rho"] for summary in summaries if summary[gate_field] is True}
    return [
        [left, right]
        for left, right in zip(RHO_VALUES, RHO_VALUES[1:], strict=False)
        if left in passing and right in passing
    ]


def _nested_group(
    cells: Mapping[tuple[str, int, str], _Cell],
    raw_repetition_blocks: tuple[tuple[Fraction, ...], ...],
    *,
    sampler: _Shake256CounterSampler,
    point_classifications: Mapping[str, tuple[bool, bool, bool, bool]],
    point_adjacent_pairs: tuple[tuple[str, str], ...],
) -> _CalibrationGroupSensitivity:
    empty = _CalibrationGroupSensitivity(
        by_rho={
            rho: _CalibrationRhoSensitivity(
                median_effect_distribution=None,
                all_positive_match_count=0,
                median_threshold_match_count=0,
                all_nondominated_match_count=0,
                rho_gate_match_count=0,
            )
            for rho in RHO_VALUES
        },
        adjacent_pairs_match_count=0,
    )
    if len(cells) != len(DATASET_IDS) * 5 * len(RHO_VALUES):
        return empty
    if any(
        any(record.outcome != "complete" for record in cell.tuning_fixed.values())
        or any(record.outcome != "complete" for record in cell.heldout_fixed.values())
        for cell in cells.values()
    ):
        return empty
    if set(point_classifications) != set(RHO_VALUES):
        raise ValueError("calibration point classifications must cover every frozen rho")

    def linear_profile(record: _Record) -> _LinearCostProfile:
        (
            update_count_total,
            query_count_total,
            update_primitive_counts,
            query_primitive_counts,
            update_serialized_bytes,
            query_serialized_bytes,
        ) = _complete_quantities(record)
        rho_value = Fraction(record.rho)
        coefficients = tuple(
            (index, coefficient)
            for index, (update_count, query_count) in enumerate(
                zip(update_primitive_counts, query_primitive_counts, strict=True)
            )
            if (
                coefficient := (
                    Fraction(update_count, update_count_total)
                    + rho_value * Fraction(query_count, query_count_total)
                )
            )
            != 0
        )
        byte_seconds = Fraction(8, BANDWIDTH_MBPS * 1_000_000) * (
            Fraction(update_serialized_bytes, update_count_total)
            + rho_value * Fraction(query_serialized_bytes, query_count_total)
        )
        query_coefficients = tuple(
            (index, Fraction(count, query_count_total))
            for index, count in enumerate(query_primitive_counts)
            if count != 0
        )
        return _LinearCostProfile(
            total_coefficients=coefficients,
            total_byte_seconds=byte_seconds,
            update_bytes=Fraction(update_serialized_bytes, update_count_total),
            query_coefficients=query_coefficients,
            query_byte_seconds=(
                Fraction(8, BANDWIDTH_MBPS * 1_000_000)
                * Fraction(query_serialized_bytes, query_count_total)
            ),
        )

    profiles = {
        key: (
            tuple(
                (
                    candidate_id,
                    linear_profile(cell.tuning_fixed[candidate_id]),
                    linear_profile(cell.heldout_fixed[candidate_id]),
                )
                for candidate_id in REFERENCE_CANDIDATE_IDS
            ),
            linear_profile(cell.heldout_fixed[COMPARATOR_CANDIDATE_ID]),
        )
        for key, cell in cells.items()
    }

    def profile_cost(
        profile: _LinearCostProfile,
        primitive_costs: tuple[Fraction, ...],
    ) -> Fraction:
        return profile.total_byte_seconds + sum(
            (
                coefficient * primitive_costs[index]
                for index, coefficient in profile.total_coefficients
            ),
            Fraction(),
        )

    def profile_pareto_point(
        profile: _LinearCostProfile,
        primitive_costs: tuple[Fraction, ...],
    ) -> tuple[Fraction, Fraction]:
        query_time = profile.query_byte_seconds + sum(
            (
                coefficient * primitive_costs[index]
                for index, coefficient in profile.query_coefficients
            ),
            Fraction(),
        )
        return profile.update_bytes, query_time

    def selected_candidate_id(
        tuning_profiles: tuple[
            tuple[
                str,
                _LinearCostProfile,
                _LinearCostProfile,
            ],
            ...,
        ],
        sampled_fractions: tuple[Fraction, ...],
    ) -> str:
        return min(
            (profile_cost(tuning_profile, sampled_fractions), candidate_id)
            for candidate_id, tuning_profile, _heldout_profile in tuning_profiles
        )[1]

    replicate_cache: dict[
        tuple[Fraction, ...],
        tuple[
            tuple[tuple[str, Fraction, bool, bool, bool, bool], ...],
            tuple[tuple[str, str], ...],
        ],
    ] = {}
    distributions: dict[str, list[Fraction]] = {rho: [] for rho in RHO_VALUES}
    all_positive_matches = {rho: 0 for rho in RHO_VALUES}
    median_threshold_matches = {rho: 0 for rho in RHO_VALUES}
    all_nondominated_matches = {rho: 0 for rho in RHO_VALUES}
    rho_gate_matches = {rho: 0 for rho in RHO_VALUES}
    adjacent_pairs_match_count = 0
    for _ in range(CALIBRATION_CLASSIFICATION_REPETITIONS):
        sampled_block_indices = tuple(
            sampler.randbelow(len(raw_repetition_blocks)) for _ in raw_repetition_blocks
        )
        sampled_fractions = tuple(
            _median(
                tuple(
                    raw_repetition_blocks[block_index][primitive_index]
                    for block_index in sampled_block_indices
                )
            )
            for primitive_index in range(len(PRIMITIVE_NAMES))
        )
        cached = replicate_cache.get(sampled_fractions)
        if cached is None:
            effects_by_cell: dict[tuple[str, int, str], Fraction] = {}
            nondominated_by_cell: dict[tuple[str, int, str], bool] = {}
            for key in cells:
                tuning_profiles, comparator_profile = profiles[key]
                winner = selected_candidate_id(
                    tuning_profiles,
                    sampled_fractions,
                )
                heldout_profile = next(
                    profile
                    for candidate_id, _tuning_profile, profile in tuning_profiles
                    if candidate_id == winner
                )
                selected_cost = profile_cost(heldout_profile, sampled_fractions)
                comparator_cost = profile_cost(comparator_profile, sampled_fractions)
                if comparator_cost <= 0:
                    raise ValueError("nested calibration produced a nonpositive comparator cost")
                effects_by_cell[key] = (comparator_cost - selected_cost) / comparator_cost
                selected_point = profile_pareto_point(heldout_profile, sampled_fractions)
                nondominated_by_cell[key] = not any(
                    (
                        candidate_point[0] <= selected_point[0]
                        and candidate_point[1] <= selected_point[1]
                        and candidate_point != selected_point
                    )
                    for candidate_id, _tuning_profile, candidate_profile in tuning_profiles
                    if candidate_id != winner
                    for candidate_point in (
                        profile_pareto_point(candidate_profile, sampled_fractions),
                    )
                )
            classifications: list[tuple[str, Fraction, bool, bool, bool, bool]] = []
            for rho in RHO_VALUES:
                effects = [
                    effects_by_cell[(dataset_id, partition, rho)]
                    for dataset_id in DATASET_IDS
                    for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
                ]
                median = _median(effects)
                all_positive = all(effect > 0 for effect in effects)
                median_threshold = median >= _PRACTICAL_THRESHOLD
                all_nondominated = all(
                    nondominated_by_cell[(dataset_id, partition, rho)]
                    for dataset_id in DATASET_IDS
                    for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
                )
                rho_gate = all_positive and median_threshold and all_nondominated
                classifications.append(
                    (
                        rho,
                        median,
                        all_positive,
                        median_threshold,
                        all_nondominated,
                        rho_gate,
                    )
                )
            passing = {
                rho
                for (
                    rho,
                    _median_effect,
                    _positive,
                    _threshold,
                    _nondominated,
                    gate,
                ) in classifications
                if gate
            }
            adjacent_pairs = tuple(
                (left, right)
                for left, right in zip(RHO_VALUES, RHO_VALUES[1:], strict=False)
                if left in passing and right in passing
            )
            cached = (tuple(classifications), adjacent_pairs)
            replicate_cache[sampled_fractions] = cached
        classifications, adjacent_pairs = cached
        for (
            rho,
            median,
            all_positive,
            median_threshold,
            all_nondominated,
            rho_gate,
        ) in classifications:
            expected_positive, expected_threshold, expected_nondominated, expected_gate = (
                point_classifications[rho]
            )
            distributions[rho].append(median)
            all_positive_matches[rho] += all_positive == expected_positive
            median_threshold_matches[rho] += median_threshold == expected_threshold
            all_nondominated_matches[rho] += all_nondominated == expected_nondominated
            rho_gate_matches[rho] += rho_gate == expected_gate
        adjacent_pairs_match_count += adjacent_pairs == point_adjacent_pairs
    return _CalibrationGroupSensitivity(
        by_rho={
            rho: _CalibrationRhoSensitivity(
                median_effect_distribution=tuple(distributions[rho]),
                all_positive_match_count=all_positive_matches[rho],
                median_threshold_match_count=median_threshold_matches[rho],
                all_nondominated_match_count=all_nondominated_matches[rho],
                rho_gate_match_count=rho_gate_matches[rho],
            )
            for rho in RHO_VALUES
        },
        adjacent_pairs_match_count=adjacent_pairs_match_count,
    )


def analyze_publication_results(
    payload: object,
    *,
    evidence_freeze_git_sha: object = None,
    artifact_behavior_inventory: object = None,
) -> dict[str, object]:
    """Validate and analyze the frozen paired held-out publication experiment.

    The interface deliberately accepts only canonical trace-unit records.  It
    does not accept windows, repeated-measurement seeds, precomputed effects,
    summaries, candidate-role overrides, or a replacement comparator.
    """

    source_document = _object(deepcopy(payload), "heldout input")
    _exact_keys(source_document, _TOP_LEVEL_KEYS, "heldout input")
    analysis_runtime_implementation, analysis_runtime_version = _analysis_runtime_identity()
    analysis_source = _analysis_source()
    decoded = _decode_input(source_document)
    experiment_source_git_sha = decoded.experiment_source_git_sha
    source_compatibility = _verify_source_compatibility(
        experiment_source_git_sha=experiment_source_git_sha,
        analysis_source_git_sha=analysis_source.git_sha,
        evidence_freeze_git_sha=evidence_freeze_git_sha,
        artifact_behavior_inventory=artifact_behavior_inventory,
        decoded_input_sha256=decoded.input_sha256,
        repository_root=Path(__file__).resolve().parents[2],
    )
    sampler_known_answer_sha256 = _sampling_stream_known_answer_sha256()
    if sampler_known_answer_sha256 != SAMPLER_KNOWN_ANSWER_SHA256:
        raise RuntimeError("publication sampling stream failed its frozen known-answer test")
    point_costs = _point_costs(decoded)
    effects_by_group: dict[tuple[str, str], dict[tuple[str, int, str], Fraction]] = {
        (semantics, freshness): {} for semantics in SEMANTICS for freshness in FRESHNESS_VALUES
    }
    cells_by_group: dict[tuple[str, str], dict[tuple[str, int, str], _Cell]] = {
        key: {} for key in effects_by_group
    }
    unit_effects: list[dict[str, object]] = []
    all_candidate_outcomes_complete = True
    for cell in decoded.cells:
        effect, output = _unit_effect(cell, point_costs)
        unit_effects.append(output)
        dataset_id, semantics, partition, freshness, rho = cell.key
        group_key = (semantics, freshness)
        cells_by_group[group_key][(dataset_id, partition, rho)] = cell
        if effect is not None:
            effects_by_group[group_key][(dataset_id, partition, rho)] = effect
        if output["all_candidate_outcomes_complete"] is not True:
            all_candidate_outcomes_complete = False

    partition_resampling_by_group = {
        group_key: _partition_resampling_group(
            effects,
            sampler=_sampling_stream(
                analysis_kind="partition-resampling",
                seed=PARTITION_RESAMPLING_SEED,
                semantics=group_key[0],
                freshness_seconds=group_key[1],
            ),
        )
        for group_key, effects in effects_by_group.items()
    }
    summaries: list[dict[str, object]] = []
    summary_groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for group_key in effects_by_group:
        semantics, freshness = group_key
        group_summaries: list[dict[str, object]] = []
        for rho in RHO_VALUES:
            points = [
                item
                for item in unit_effects
                if item["semantics"] == semantics
                and item["freshness_seconds"] == freshness
                and item["rho"] == rho
            ]
            effect_values = [
                effects_by_group[group_key][(dataset_id, partition, rho)]
                for dataset_id in DATASET_IDS
                for partition in range(PUBLICATION_SOURCE_PARTITION_COUNT)
                if (dataset_id, partition, rho) in effects_by_group[group_key]
            ]
            complete_effects = len(effect_values) == 15
            distribution = partition_resampling_by_group[group_key][rho]
            median = _median(effect_values) if complete_effects else None
            lower_quartile = _quantile(effect_values, 1, 4) if complete_effects else None
            upper_quartile = _quantile(effect_values, 3, 4) if complete_effects else None
            ci_lower = _quantile(distribution, 25, 1000) if distribution is not None else None
            ci_upper = _quantile(distribution, 975, 1000) if distribution is not None else None
            positive_effect_count = sum(effect > 0 for effect in effect_values)
            all_effects_positive = complete_effects and positive_effect_count == 15
            all_outcomes_complete = all(
                point["all_candidate_outcomes_complete"] is True for point in points
            )
            all_non_dominated = all(point["selected_non_dominated"] is True for point in points)
            summary: dict[str, object] = {
                "semantics": semantics,
                "freshness_seconds": freshness,
                "analysis_role": (
                    "sole-confirmatory-primary"
                    if group_key == PRIMARY_CONFIRMATORY_FAMILY
                    else "prespecified-secondary-robustness"
                ),
                "is_primary_confirmatory_family": group_key == PRIMARY_CONFIRMATORY_FAMILY,
                "rho": rho,
                "unit_count": 15,
                "complete_effect_count": len(effect_values),
                "effect_median": None if median is None else _fraction_text(median),
                "effect_iqr": (
                    None
                    if lower_quartile is None or upper_quartile is None
                    else [_fraction_text(lower_quartile), _fraction_text(upper_quartile)]
                ),
                "partition_resampling_stability_interval_95": (
                    None
                    if ci_lower is None or ci_upper is None
                    else [_fraction_text(ci_lower), _fraction_text(ci_upper)]
                ),
                "positive_effect_count": positive_effect_count,
                "all_15_unit_effects_positive": all_effects_positive,
                "all_candidate_outcomes_complete": all_outcomes_complete,
                "all_units_non_dominated": all_non_dominated,
                "finite_corpus_rho_gate_passed": (
                    median is not None
                    and median >= _PRACTICAL_THRESHOLD
                    and all_effects_positive
                    and all_outcomes_complete
                    and all_non_dominated
                ),
                "calibration_median_effect_stability_interval_95": None,
                "calibration_all_15_positive_match_count": 0,
                "calibration_median_threshold_match_count": 0,
                "calibration_all_units_nondominated_match_count": 0,
                "calibration_rho_gate_match_count": 0,
                "calibration_all_15_positive_classification_stable": False,
                "calibration_median_threshold_classification_stable": False,
                "calibration_all_units_nondominated_classification_stable": False,
                "calibration_rho_gate_classification_stable": False,
                "all_points": points,
            }
            group_summaries.append(summary)
        summaries.extend(group_summaries)
        summary_groups[group_key] = group_summaries

    primary_group_verdicts: list[dict[str, object]] = []
    for group_key, group_summaries in summary_groups.items():
        pairs = _adjacent_pairs(group_summaries, "finite_corpus_rho_gate_passed")
        primary_group_verdicts.append(
            {
                "semantics": group_key[0],
                "freshness_seconds": group_key[1],
                "analysis_role": (
                    "sole-confirmatory-primary"
                    if group_key == PRIMARY_CONFIRMATORY_FAMILY
                    else "prespecified-secondary-robustness"
                ),
                "adjacent_passing_rho_pairs": pairs,
                "finite_corpus_adjacent_pair_classification_passed": bool(pairs),
                "is_primary_confirmatory_family": group_key == PRIMARY_CONFIRMATORY_FAMILY,
            }
        )

    nested_by_group: dict[tuple[str, str], _CalibrationGroupSensitivity] = {}
    for group_verdict in primary_group_verdicts:
        group_key = (
            str(group_verdict["semantics"]),
            str(group_verdict["freshness_seconds"]),
        )
        group_summaries = summary_groups[group_key]
        point_classifications = {
            str(summary["rho"]): (
                summary["all_15_unit_effects_positive"] is True,
                (
                    summary["effect_median"] is not None
                    and Fraction(str(summary["effect_median"])) >= _PRACTICAL_THRESHOLD
                ),
                summary["all_units_non_dominated"] is True,
                summary["finite_corpus_rho_gate_passed"] is True,
            )
            for summary in group_summaries
        }
        point_adjacent_pairs = tuple(
            (str(pair[0]), str(pair[1]))
            for pair in group_verdict["adjacent_passing_rho_pairs"]  # type: ignore[union-attr]
        )
        nested_by_group[group_key] = _nested_group(
            cells_by_group[group_key],
            decoded.raw_repetition_blocks,
            sampler=_sampling_stream(
                analysis_kind="calibration-classification",
                seed=CALIBRATION_CLASSIFICATION_SEED,
                semantics=group_key[0],
                freshness_seconds=group_key[1],
            ),
            point_classifications=point_classifications,
            point_adjacent_pairs=point_adjacent_pairs,
        )
    sensitivity_group_verdicts: list[dict[str, object]] = []
    for group_verdict in primary_group_verdicts:
        group_key = (
            str(group_verdict["semantics"]),
            str(group_verdict["freshness_seconds"]),
        )
        group_summaries = summary_groups[group_key]
        for summary in group_summaries:
            result = nested_by_group[group_key].by_rho[str(summary["rho"])]
            distribution = result.median_effect_distribution
            if distribution is not None:
                summary["calibration_median_effect_stability_interval_95"] = [
                    _fraction_text(_quantile(distribution, 25, 1000)),
                    _fraction_text(_quantile(distribution, 975, 1000)),
                ]
            summary["calibration_all_15_positive_match_count"] = result.all_positive_match_count
            summary["calibration_median_threshold_match_count"] = (
                result.median_threshold_match_count
            )
            summary["calibration_all_units_nondominated_match_count"] = (
                result.all_nondominated_match_count
            )
            summary["calibration_rho_gate_match_count"] = result.rho_gate_match_count
            summary["calibration_all_15_positive_classification_stable"] = (
                result.all_positive_match_count == CALIBRATION_CLASSIFICATION_REPETITIONS
            )
            summary["calibration_median_threshold_classification_stable"] = (
                result.median_threshold_match_count == CALIBRATION_CLASSIFICATION_REPETITIONS
            )
            summary["calibration_all_units_nondominated_classification_stable"] = (
                result.all_nondominated_match_count == CALIBRATION_CLASSIFICATION_REPETITIONS
            )
            summary["calibration_rho_gate_classification_stable"] = (
                result.rho_gate_match_count == CALIBRATION_CLASSIFICATION_REPETITIONS
            )
        adjacent_match_count = nested_by_group[group_key].adjacent_pairs_match_count
        sensitivity_group_verdicts.append(
            {
                "semantics": group_key[0],
                "freshness_seconds": group_key[1],
                "analysis_role": (
                    "sole-confirmatory-primary"
                    if group_key == PRIMARY_CONFIRMATORY_FAMILY
                    else "prespecified-secondary-robustness"
                ),
                "is_primary_confirmatory_family": group_key == PRIMARY_CONFIRMATORY_FAMILY,
                "point_adjacent_passing_rho_pairs": group_verdict["adjacent_passing_rho_pairs"],
                "calibration_adjacent_pairs_match_count": adjacent_match_count,
                "all_positive_classification_stable": all(
                    summary["calibration_all_15_positive_classification_stable"] is True
                    for summary in group_summaries
                ),
                "median_threshold_classification_stable": all(
                    summary["calibration_median_threshold_classification_stable"] is True
                    for summary in group_summaries
                ),
                "all_units_nondominated_classification_stable": all(
                    summary["calibration_all_units_nondominated_classification_stable"] is True
                    for summary in group_summaries
                ),
                "rho_gate_classification_stable": all(
                    summary["calibration_rho_gate_classification_stable"] is True
                    for summary in group_summaries
                ),
                "adjacent_pairs_classification_stable": (
                    adjacent_match_count == CALIBRATION_CLASSIFICATION_REPETITIONS
                ),
            }
        )

    primary_group_matches = [
        verdict
        for verdict in primary_group_verdicts
        if (verdict["semantics"], verdict["freshness_seconds"]) == PRIMARY_CONFIRMATORY_FAMILY
    ]
    primary_sensitivity_matches = [
        verdict
        for verdict in sensitivity_group_verdicts
        if (verdict["semantics"], verdict["freshness_seconds"]) == PRIMARY_CONFIRMATORY_FAMILY
    ]
    if len(primary_group_matches) != 1 or len(primary_sensitivity_matches) != 1:
        raise RuntimeError("the sole confirmatory family must resolve exactly once")
    primary_group = primary_group_matches[0]
    primary_sensitivity = primary_sensitivity_matches[0]
    calibration_stable = (
        primary_sensitivity["all_positive_classification_stable"] is True
        and primary_sensitivity["median_threshold_classification_stable"] is True
        and primary_sensitivity["all_units_nondominated_classification_stable"] is True
        and primary_sensitivity["rho_gate_classification_stable"] is True
        and primary_sensitivity["adjacent_pairs_classification_stable"] is True
    )
    primary_gate = (
        primary_group["finite_corpus_adjacent_pair_classification_passed"] is True
        and primary_group["is_primary_confirmatory_family"] is True
    )
    statistical_gate_calculation_passed = all_candidate_outcomes_complete and primary_gate
    clean_head_verified = analysis_source.attestation == "repository-clean-head"
    trace_source_authority_verified = False
    day1b_producer_authority_verified = False
    calibration_measurement_authority_verified = _repository_calibration_authority_verified(
        source_document["calibration"],
        source_git_sha=experiment_source_git_sha,
    )
    mixed_circuit_authority_verified = False
    source_snapshot_compatibility_verified = True
    evidence_compatibility_verified = source_compatibility.post_run_anchor_verified
    evidence_chain_authority_verified = all(
        (
            clean_head_verified,
            source_snapshot_compatibility_verified,
            source_compatibility.post_run_anchor_verified,
            source_compatibility.runtime_execution_isolation_verified,
            trace_source_authority_verified,
            day1b_producer_authority_verified,
            calibration_measurement_authority_verified,
            mixed_circuit_authority_verified,
        )
    )
    artifact_evidence_chain_verified = evidence_chain_authority_verified
    failures = [
        {
            "dataset_id": record.dataset_id,
            "semantics": record.semantics,
            "source_partition": record.source_partition,
            "freshness_seconds": record.freshness_seconds,
            "rho": record.rho,
            "phase": record.phase,
            "record_kind": record.record_kind,
            "candidate_id": record.candidate_id,
            "outcome": record.outcome,
            "failure_reason": record.failure_reason,
        }
        for cell in decoded.cells
        for record in (*cell.tuning_fixed.values(), *cell.heldout_fixed.values())
        if record.outcome != "complete"
    ]
    if _analysis_source() != analysis_source:
        raise RuntimeError(
            "analysis source changed during publication analysis; refusing to render"
        )
    return {
        "schema_version": VERDICT_SCHEMA,
        "experiment_source_git_sha": decoded.experiment_source_git_sha,
        "evidence_freeze_git_sha": source_compatibility.evidence_freeze_git_sha,
        "analysis_source_git_sha": analysis_source.git_sha,
        "analysis_source_attestation": analysis_source.attestation,
        "analysis_source_clean_head_verified": clean_head_verified,
        "evidence_compatibility_kind": source_compatibility.kind,
        "source_snapshot_compatibility_verified": source_snapshot_compatibility_verified,
        "evidence_compatibility_verified": evidence_compatibility_verified,
        "evidence_compatibility_receipt_sha256": source_compatibility.receipt_sha256,
        "evidence_compatibility_receipt": source_compatibility.receipt_document,
        "evidence_compatibility_post_run_anchor_verified": (
            source_compatibility.post_run_anchor_verified
        ),
        "runtime_execution_isolation_authority_state": (
            source_compatibility.runtime_execution_isolation_authority_state
        ),
        "runtime_execution_isolation_required_checks": list(
            RUNTIME_EXECUTION_ISOLATION_REQUIRED_CHECKS
        ),
        "runtime_execution_isolation_receipt_schema_version": (
            RUNTIME_EXECUTION_ISOLATION_RECEIPT_SCHEMA
        ),
        "runtime_execution_isolation_verified": (
            source_compatibility.runtime_execution_isolation_verified
        ),
        "analysis_runtime_implementation": analysis_runtime_implementation,
        "analysis_runtime_version": analysis_runtime_version,
        "analysis_runtime_identity_verified": True,
        "sampling_stream_schema_version": SAMPLER_SCHEMA,
        "sampling_stream_known_answer_sha256": sampler_known_answer_sha256,
        "sampling_stream_known_answer_verified": True,
        "sampling_stream_domains": [
            {
                "analysis_kind": analysis_kind,
                "semantics": semantics,
                "freshness_seconds": freshness,
                "domain_sha256": hashlib.sha256(
                    canonical_json_bytes(
                        _sampling_domain(
                            analysis_kind=analysis_kind,
                            seed=(
                                PARTITION_RESAMPLING_SEED
                                if analysis_kind == "partition-resampling"
                                else CALIBRATION_CLASSIFICATION_SEED
                            ),
                            semantics=semantics,
                            freshness_seconds=freshness,
                        )
                    )
                ).hexdigest(),
            }
            for analysis_kind in (
                "partition-resampling",
                "calibration-classification",
            )
            for semantics in SEMANTICS
            for freshness in FRESHNESS_VALUES
        ],
        "trace_source_authority_verified": trace_source_authority_verified,
        "day1b_producer_authority_verified": day1b_producer_authority_verified,
        "mixed_circuit_authority_verified": mixed_circuit_authority_verified,
        "evidence_chain_authority_verified": evidence_chain_authority_verified,
        "artifact_evidence_chain_verified": artifact_evidence_chain_verified,
        "analysis_behavior_source_paths": list(_ANALYSIS_BEHAVIOR_PATHS),
        "canonical_input_sha256": decoded.input_sha256,
        "analysis_completed": True,
        "paired_analysis_unit": "dataset-semantics-source-partition-trace",
        "unit_count": 30,
        "unit_count_per_semantics": 15,
        "trace_binding_count": 30,
        "cell_binding_count": 540,
        "trace_bindings_descriptive_only": True,
        "bandwidth_mbps": BANDWIDTH_MBPS,
        "primary_effect_definition": "(C_recompress-C_selected)/C_recompress",
        "primary_confirmatory_family": {
            "semantics": PRIMARY_CONFIRMATORY_FAMILY[0],
            "freshness_seconds": PRIMARY_CONFIRMATORY_FAMILY[1],
            "analysis_role": "sole-confirmatory-primary",
            "is_primary_confirmatory_family": True,
        },
        "secondary_robustness_families": [
            {
                "semantics": semantics,
                "freshness_seconds": freshness,
                "analysis_role": "prespecified-secondary-robustness",
                "is_primary_confirmatory_family": False,
            }
            for semantics in SEMANTICS
            for freshness in FRESHNESS_VALUES
            if (semantics, freshness) != PRIMARY_CONFIRMATORY_FAMILY
        ],
        "physical_records_per_cell": len(REFERENCE_CANDIDATE_IDS) + len(FIXED_CANDIDATE_IDS),
        "heldout_view_records_per_cell": len(FIXED_CANDIDATE_IDS) + 2,
        "fixed_candidate_count": len(FIXED_CANDIDATE_IDS),
        "reference_candidate_count": len(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_count": 1,
        "derived_alias_count": 2,
        "comparator_candidate_id": COMPARATOR_CANDIDATE_ID,
        "inference_scope": "fixed-three-dataset-corpus-no-population-inference",
        "partition_resampling_method": ("dataset-stratified-paired-source-partition-resampling"),
        "partition_resampling_sampler": "domain-separated-shake256-counter-rejection-v1",
        "resampling_interval_role": "descriptive-partition-weighting-stability",
        "partition_resampling_percentile_method": "central-95%-type-7-linear-interpolation",
        "partition_resampling_seed": PARTITION_RESAMPLING_SEED,
        "partition_resampling_repetitions": PARTITION_RESAMPLING_REPETITIONS,
        "primitive_names": list(decoded.primitive_names),
        "point_calibration_estimator": "whole-block-primitive-median",
        "calibration_raw_block_count": len(decoded.raw_repetition_blocks),
        "calibration_measurement_block_count": CALIBRATION_MEASUREMENT_BLOCK_COUNT,
        "calibration_measurement_stop_rule": CALIBRATION_MEASUREMENT_STOP_RULE,
        "calibration_measurements_descriptive_only": True,
        "calibration_measurement_authority_verified": (calibration_measurement_authority_verified),
        "calibration_operation_order_seed": CALIBRATION_OPERATION_ORDER_SEED,
        "calibration_operation_order_method": (
            "domain-separated-shake256-counter-rejection-fisher-yates-v1"
        ),
        "calibration_block_resampling": True,
        "calibration_block_covariance_preserved": True,
        "calibration_sensitivity_method": (
            "whole-block-resampling-with-fixed-15-unit-corpus-and-tuning-reselection"
        ),
        "calibration_partition_resampling": False,
        "calibration_classification_seed": CALIBRATION_CLASSIFICATION_SEED,
        "calibration_classification_repetitions": CALIBRATION_CLASSIFICATION_REPETITIONS,
        "calibration_classification_match_rule": (
            "all-replicates-exactly-match-point-classification"
        ),
        "nested_tuning_reselection": True,
        "nested_tuning_tie_break": "canonical-candidate-id",
        "hypothesis_test_method": "none-deterministic-partitions-are-not-independent-trials",
        "multiple_testing_method": "none-no-population-hypothesis-tests",
        "finite_corpus_decision_rule": (
            "two-adjacent-rho-with-15-of-15-positive-effects-median-at-least-15-percent-"
            "all-units-nondominated"
        ),
        "all_candidate_outcomes_complete": all_candidate_outcomes_complete,
        "primary_finite_corpus_decision_calculation_passed": primary_gate,
        "statistical_gate_calculation_passed": statistical_gate_calculation_passed,
        "finite_corpus_decision_calculation_passed": statistical_gate_calculation_passed,
        "preregistered_finite_corpus_gate_passed": (
            statistical_gate_calculation_passed
            and calibration_stable
            and artifact_evidence_chain_verified
        ),
        "calibration_sensitivity_stable": calibration_stable,
        "headline_stability_calculation_passed": (
            statistical_gate_calculation_passed and calibration_stable
        ),
        "calibrated_component_result_stable": (
            statistical_gate_calculation_passed
            and calibration_stable
            and artifact_evidence_chain_verified
        ),
        "headline_claim_allowed": False,
        "complete_cost_claim_allowed": False,
        "formal_performance_claim_allowed": False,
        "security_claim_allowed": False,
        "group_verdicts": primary_group_verdicts,
        "calibration_sensitivity": sensitivity_group_verdicts,
        "summaries": summaries,
        "unit_effects": unit_effects,
        "failed_outcomes": failures,
    }


def _csv_bytes(rows: Sequence[Mapping[str, object]], fieldnames: Sequence[str]) -> bytes:
    def canonical_cell(value: object) -> object:
        if value is None:
            return ""
        if type(value) is bool:
            return "true" if value else "false"
        if isinstance(value, (dict, list)):
            return json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        return value

    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: canonical_cell(row[field]) for field in fieldnames})
    return handle.getvalue().encode("utf-8")


def render_publication_analysis_artifacts(
    payload: object,
    *,
    evidence_freeze_git_sha: object = None,
    artifact_behavior_inventory: object = None,
) -> dict[str, bytes]:
    """Return the closed canonical verdict artifact without writing to disk."""

    verdict = analyze_publication_results(
        payload,
        evidence_freeze_git_sha=evidence_freeze_git_sha,
        artifact_behavior_inventory=artifact_behavior_inventory,
    )
    verdict_bytes = canonical_json_bytes(verdict)
    effect_fields = (
        "dataset_id",
        "semantics",
        "source_partition",
        "freshness_seconds",
        "rho",
        "cell_binding_sha256",
        "selected_candidate_id",
        "selected_outcome",
        "comparator_candidate_id",
        "comparator_outcome",
        "all_tuning_outcomes_complete",
        "all_reference_outcomes_complete",
        "all_candidate_outcomes_complete",
        "ablation_candidate_id",
        "ablation_outcome",
        "diagnostic_oracle_candidate_id",
        "diagnostic_oracle_outcome",
        "heldout_view",
        "effect",
        "selected_cost_seconds",
        "comparator_cost_seconds",
        "selected_update_bytes_per_accepted_event_group",
        "selected_query_time_seconds_per_query",
        "selected_non_dominated",
        "dominating_candidate_ids",
    )
    summary_fields = (
        "semantics",
        "freshness_seconds",
        "analysis_role",
        "is_primary_confirmatory_family",
        "rho",
        "unit_count",
        "complete_effect_count",
        "effect_median",
        "effect_iqr",
        "partition_resampling_stability_interval_95",
        "positive_effect_count",
        "all_15_unit_effects_positive",
        "all_candidate_outcomes_complete",
        "all_units_non_dominated",
        "finite_corpus_rho_gate_passed",
        "calibration_median_effect_stability_interval_95",
        "calibration_all_15_positive_match_count",
        "calibration_median_threshold_match_count",
        "calibration_all_units_nondominated_match_count",
        "calibration_rho_gate_match_count",
        "calibration_all_15_positive_classification_stable",
        "calibration_median_threshold_classification_stable",
        "calibration_all_units_nondominated_classification_stable",
        "calibration_rho_gate_classification_stable",
    )
    effects_csv = _csv_bytes(verdict["unit_effects"], effect_fields)  # type: ignore[arg-type]
    summaries_csv = _csv_bytes(verdict["summaries"], summary_fields)  # type: ignore[arg-type]
    artifacts = {
        "publication-verdict.json": verdict_bytes,
        "publication-effects.csv": effects_csv,
        "publication-summary.csv": summaries_csv,
    }
    checksum_lines = [
        f"{hashlib.sha256(content).hexdigest()}  {filename}\n"
        for filename, content in artifacts.items()
    ]
    artifacts["SHA256SUMS"] = "".join(checksum_lines).encode("ascii")
    return artifacts


def write_publication_analysis_artifacts(
    output_dir: Path,
    payload: object,
    *,
    evidence_freeze_git_sha: object = None,
    artifact_behavior_inventory: object = None,
) -> dict[str, str]:
    """Atomically publish the validated, closed artifact set into a new directory."""

    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must not already exist")
    artifacts = render_publication_analysis_artifacts(
        payload,
        evidence_freeze_git_sha=evidence_freeze_git_sha,
        artifact_behavior_inventory=artifact_behavior_inventory,
    )
    artifact_sha256 = {
        filename: hashlib.sha256(content).hexdigest() for filename, content in artifacts.items()
    }
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.publication-analysis-staging-",
            dir=output_dir.parent,
        )
    )
    lock_path = output_dir.with_name(f".{output_dir.name}.publication-analysis.lock")
    lock_fd: int | None = None
    try:
        for filename, content in artifacts.items():
            with (staging_dir / filename).open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        try:
            lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise ValueError("another publication analysis is claiming output_dir") from error
        if output_dir.exists() or output_dir.is_symlink():
            raise ValueError("output_dir must not already exist")
        os.rename(staging_dir, output_dir)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)
        shutil.rmtree(staging_dir, ignore_errors=True)
    return artifact_sha256


__all__ = (
    "ABLATION_CANDIDATE_ID",
    "ANALYSIS_RUNTIME_IMPLEMENTATION",
    "ANALYSIS_RUNTIME_VERSION",
    "BANDWIDTH_MBPS",
    "CALIBRATION_CLASSIFICATION_REPETITIONS",
    "CALIBRATION_CLASSIFICATION_SEED",
    "CALIBRATION_BLOCK_SCHEMA",
    "CALIBRATION_MEASUREMENT_BLOCK_COUNT",
    "CALIBRATION_MEASUREMENT_STOP_RULE",
    "CALIBRATION_OPERATION_ORDER_SEED",
    "CALIBRATION_SCHEMA",
    "CELL_BINDING_SCHEMA",
    "COMPARATOR_CANDIDATE_ID",
    "DATASET_IDS",
    "EVENT_SCHEDULE_SCHEMA",
    "FRESHNESS_VALUES",
    "FIXED_CANDIDATE_IDS",
    "HELDOUT_RECORD_SCHEMA",
    "HELDOUT_SCHEMA",
    "PUBLICATION_ARTIFACT_FILENAMES",
    "PARTITION_RESAMPLING_REPETITIONS",
    "PARTITION_RESAMPLING_SEED",
    "PRIMITIVE_NAMES",
    "PRIMARY_CONFIRMATORY_FAMILY",
    "QUERY_VECTOR_SCHEMA",
    "REFERENCE_CANDIDATE_IDS",
    "RHO_VALUES",
    "SEMANTICS",
    "SAMPLER_SCHEMA",
    "SAMPLER_KNOWN_ANSWER_SHA256",
    "TRACE_UNIT_SCHEMA",
    "VERDICT_SCHEMA",
    "analyze_publication_results",
    "calibration_operation_order",
    "canonical_json_bytes",
    "render_publication_analysis_artifacts",
    "write_publication_analysis_artifacts",
)
