"""Closed producer/replay seam for the preregistered validation-scaling study.

The public surface is intentionally two operations.  Callers cannot select a
seed, strategy, rho, order, clock, source trace, target, or machine plan.  The
module owns those decisions and returns one deterministic canonical payload
archive.  Provider receipts, GitHub identities, and aggregate statistics live
outside this scientific seam.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import stat
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Literal

import dynamic_cssc.query_compiler as query_compiler_module
import dynamic_cssc.simulator as simulator_module
from dynamic_cssc.route_a_artifacts import (
    inspect_route_a_synthetic_cell_archive,
    produce_route_a_synthetic_cell_archive,
)
from dynamic_cssc.route_a_evaluation import (
    RouteASyntheticCellRun,
    evaluate_route_a_synthetic_cell,
)
from dynamic_cssc.route_a_replay import (
    RouteASyntheticCellReplay,
    RouteASyntheticCellTarget,
    replay_route_a_synthetic_cell,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_workloads import (
    RouteASyntheticTrace,
    generate_route_a_formal_trace,
)

__all__ = (
    "produce_validation_scaling_seed_shard",
    "replay_validation_scaling_seed_shard",
)

_STUDY_ID = "dynamic-cssc-validation-scaling-2026-09-01"
_PLAN_SCHEMA = "dynamic-cssc-validation-scaling-study-v2"
_PLAN_SHA256 = "337de174c6cc445fe9ab54c64dda74b0e9fb6d070e7b5478e09def8940a3b712"
_MACHINE_PLAN_SHA256 = "ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c"
_SOURCE_TAG = "validation-scaling-source-v2"
_PAYLOAD_SCHEMA = "dynamic-cssc-validation-scaling-seed-payload-v1"
_BINDING_SCHEMA = "dynamic-cssc-validation-scaling-producer-binding-v1"
_PRODUCTION_PROFILE_ID = _STUDY_ID
_SCALE = "S"
_STRATEGIES = (
    "periodic-repack/windows=1",
    "padding-reuse",
    "packed-coo-cloud-segmented-delta/segment-width=128",
)
_RHOS = (Fraction(1, 100), Fraction(1, 10), Fraction(1))
_QUERY_COUNTS = {
    Fraction(1, 100): 5,
    Fraction(1, 10): 51,
    Fraction(1): 512,
}
_STRATEGY_ORDERS = (
    _STRATEGIES,
    (_STRATEGIES[1], _STRATEGIES[2], _STRATEGIES[0]),
    (_STRATEGIES[2], _STRATEGIES[0], _STRATEGIES[1]),
)
_RHO_ORDERS = (
    _RHOS,
    (_RHOS[1], _RHOS[2], _RHOS[0]),
    (_RHOS[2], _RHOS[0], _RHOS[1]),
)
_SEMANTIC_FIELDS = (
    "schema_version",
    "identity",
    "evaluation",
    "counts",
    "window_query_counts",
    "primitive_counts",
    "rotation_inventory",
    "serialized_object_multiplicities",
    "serialized_bytes",
    "correctness",
    "bindings",
)
_CELL_ROW_FIELDS = (
    "strategy_candidate_id",
    "rho",
    "formal_seed",
    "seed_ordinal",
    "role",
    "query_count",
    "compile_query_call_count",
    "operation_wall_nanoseconds",
    "operation_process_nanoseconds",
    "producer_cell_archive_wall_nanoseconds_or_null",
    "producer_cell_archive_process_nanoseconds_or_null",
    "producer_state_transition_nanoseconds_or_null",
    "producer_result_assembly_nanoseconds_or_null",
    "replay_elapsed_nanoseconds_or_null",
    "semantic_projection_sha256",
    "source_trace_sha256",
    "machine_plan_sha256",
)
_MANIFEST_FIELDS = (
    "schema_version",
    "study_id",
    "artifact_role",
    "seed_ordinal",
    "formal_seed",
    "scale",
    "stage0_plan_sha256",
    "source_tag",
    "source_trace_sha256",
    "machine_plan_sha256",
    "cell_count",
    "cell_order",
    "member_count",
    "members",
    "retention_days",
    "private_material_included",
    "producer_payload_sha256_or_null",
    "claim_scope",
    "formal_authority_granted",
)
_PRODUCER_BINDING_FIELDS = (
    "schema_version",
    "producer_payload_sha256",
    "producer_cell_archive_sha256",
    "producer_cell_archive_byte_count",
    "producer_cell_sha256",
    "producer_semantic_projection_sha256",
    "producer_timing_row_sha256",
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SECONDS = re.compile(r"(?:0|[1-9][0-9]*)\.([0-9]{9})\Z")
_MAX_PAYLOAD_BYTES = 18 * 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_ZIP_MODE = stat.S_IFREG | 0o644


class _ValidationScalingError(ValueError):
    """The study input or retained evidence is outside the frozen contract."""


@dataclass(frozen=True, slots=True)
class _SeedRecord:
    ordinal: int
    formal_seed: int
    strategy_order: tuple[str, str, str]
    rho_order: tuple[Fraction, Fraction, Fraction]


@dataclass(frozen=True, slots=True)
class _StudyClocks:
    wall_ns: Callable[[], int]
    process_ns: Callable[[], int]


@dataclass(frozen=True, slots=True)
class _ValidationScalingDomain:
    profile: RouteAScientificProfile
    records: tuple[_SeedRecord, _SeedRecord, _SeedRecord]
    plan_bytes: bytes
    plan_sha256: str
    clocks: _StudyClocks
    production: bool

    def record(self, ordinal: int) -> _SeedRecord:
        if type(ordinal) is not int or ordinal not in {1, 2, 3}:
            raise _ValidationScalingError("seed_ordinal must be the strict integer 1, 2, or 3")
        return self.records[ordinal - 1]


@dataclass(frozen=True, slots=True)
class _MeasuredCell:
    row_bytes: bytes
    semantic_bytes: bytes
    retained_bytes: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class _ProducerCellInput:
    row_bytes: bytes
    semantic_bytes: bytes
    archive_bytes: bytes
    run: RouteASyntheticCellRun


@dataclass(frozen=True, slots=True)
class _PretraceProducerPayload:
    source_trace_sha256: str
    cells: tuple[_ProducerCellInput, ...]


@dataclass(slots=True)
class _CompileCounter:
    original: Callable[..., object]
    wrapper: Callable[..., object]
    count: int = 0


def _repository_root() -> Path:
    return Path(__file__).resolve(strict=True).parents[2]


def _read_closed_repository_file(relative_path: str, expected_sha256: str) -> bytes:
    path = _repository_root() / relative_path
    try:
        observed = path.lstat()
    except OSError as error:
        raise _ValidationScalingError(
            f"required repository file is unavailable: {relative_path}"
        ) from error
    if path.is_symlink() or not stat.S_ISREG(observed.st_mode):
        raise _ValidationScalingError(
            f"required repository file is not direct regular bytes: {relative_path}"
        )
    try:
        content = path.read_bytes()
    except OSError as error:
        raise _ValidationScalingError(
            f"required repository file cannot be read: {relative_path}"
        ) from error
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise _ValidationScalingError(f"required repository file digest changed: {relative_path}")
    return content


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _ValidationScalingError("canonical JSON contains a duplicate key")
        result[key] = value
    return result


def _canonical_object(content: bytes, *, label: str) -> dict[str, object]:
    if type(content) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    try:
        decoded = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _ValidationScalingError(f"{label} is not canonical ASCII JSON") from error
    if type(decoded) is not dict or canonical_route_a_document(decoded) != content:
        raise _ValidationScalingError(f"{label} is not one canonical object")
    return decoded


def _exact_frozen_object(content: bytes, *, label: str) -> dict[str, object]:
    """Decode already hash-bound frozen JSON without changing its pretty layout."""

    try:
        decoded = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _ValidationScalingError(f"{label} is not exact ASCII JSON") from error
    if type(decoded) is not dict:
        raise _ValidationScalingError(f"{label} is not one object")
    return decoded


def _scientific_values(
    plan: dict[str, object],
) -> tuple[tuple[int, int, int], int]:
    matrix = plan.get("matrix")
    if type(matrix) is not dict:
        raise _ValidationScalingError("Stage-0 matrix is not one closed object")
    records = matrix.get("formal_seeds")
    query_vector_seed = matrix.get("query_vector_seed")
    if type(records) is not list or len(records) != 3:
        raise _ValidationScalingError("Stage-0 formal seed matrix is not closed")
    seeds: list[int] = []
    for expected_ordinal, record in enumerate(records, start=1):
        if (
            type(record) is not dict
            or record.get("ordinal") != expected_ordinal
            or type(record.get("seed")) is not int
            or record["seed"] < 0
        ):
            raise _ValidationScalingError("Stage-0 formal seed record changed")
        seeds.append(record["seed"])
    if (
        type(query_vector_seed) is not int
        or query_vector_seed < 0
        or len(set(seeds)) != 3
        or query_vector_seed in seeds
    ):
        raise _ValidationScalingError("Stage-0 scientific seed domain changed")
    return (seeds[0], seeds[1], seeds[2]), query_vector_seed


def _registered_scientific_values() -> tuple[tuple[int, int, int], int]:
    plan_bytes = _read_closed_repository_file(
        "config/validation-scaling-study.json",
        _PLAN_SHA256,
    )
    return _scientific_values(_exact_frozen_object(plan_bytes, label="Stage-0 v2 plan"))


def _unused_qualification_seed(
    formal_seeds: tuple[int, int, int],
    query_vector_seed: int,
) -> int:
    candidate = int.from_bytes(
        hashlib.sha256(f"{_STUDY_ID}|unused-qualification".encode("ascii")).digest()[:4],
        "big",
    ) & 0x7FFF_FFFF
    if candidate in {*formal_seeds, query_vector_seed}:
        raise AssertionError("unused qualification seed collided with the frozen study")
    return candidate


def _production_domain(plan_bytes: bytes) -> _ValidationScalingDomain:
    if type(plan_bytes) is not bytes:
        raise TypeError("plan_bytes must be exact bytes")
    expected = _read_closed_repository_file(
        "config/validation-scaling-study.json",
        _PLAN_SHA256,
    )
    if plan_bytes != expected:
        raise _ValidationScalingError("plan_bytes differ from the exact Stage-0 v2 plan")
    plan = _exact_frozen_object(plan_bytes, label="Stage-0 v2 plan")
    if plan.get("schema_version") != _PLAN_SCHEMA or plan.get("study_id") != _STUDY_ID:
        raise _ValidationScalingError("Stage-0 v2 plan identity changed")
    formal_seeds, query_vector_seed = _scientific_values(plan)
    profile = RouteAScientificProfile(
        profile_id=_PRODUCTION_PROFILE_ID,
        qualification_seed=_unused_qualification_seed(formal_seeds, query_vector_seed),
        formal_seeds=formal_seeds,
        query_vector_seed=query_vector_seed,
        machine_plan_sha256=_MACHINE_PLAN_SHA256,
    )
    records = tuple(
        _SeedRecord(
            ordinal=index + 1,
            formal_seed=formal_seeds[index],
            strategy_order=_STRATEGY_ORDERS[index],
            rho_order=_RHO_ORDERS[index],
        )
        for index in range(3)
    )
    return _ValidationScalingDomain(
        profile=profile,
        records=records,  # type: ignore[arg-type]
        plan_bytes=plan_bytes,
        plan_sha256=_PLAN_SHA256,
        clocks=_StudyClocks(time.perf_counter_ns, time.process_time_ns),
        production=True,
    )


def _make_validation_scaling_sentinel_domain(
    *,
    qualification_seed: int,
    formal_seeds: tuple[int, int, int],
    query_vector_seed: int,
    wall_clock_ns: Callable[[], int],
    process_clock_ns: Callable[[], int],
) -> _ValidationScalingDomain:
    """Construct the only successful test domain; never accepts production seeds."""

    seeds = (qualification_seed, *formal_seeds, query_vector_seed)
    registered_formal_seeds, registered_query_vector_seed = _registered_scientific_values()
    registered_qualification_seed = _unused_qualification_seed(
        registered_formal_seeds,
        registered_query_vector_seed,
    )
    if (
        type(qualification_seed) is not int
        or type(formal_seeds) is not tuple
        or len(formal_seeds) != 3
        or any(type(seed) is not int or seed < 0 for seed in seeds)
        or len(set(seeds)) != len(seeds)
        or set(seeds)
        & {
            *registered_formal_seeds,
            registered_query_vector_seed,
            registered_qualification_seed,
        }
        or not callable(wall_clock_ns)
        or not callable(process_clock_ns)
    ):
        raise _ValidationScalingError("sentinel domain is not disjoint from production")
    profile = RouteAScientificProfile(
        profile_id="dynamic-cssc-validation-scaling-sentinel-only",
        qualification_seed=qualification_seed,
        formal_seeds=formal_seeds,
        query_vector_seed=query_vector_seed,
        machine_plan_sha256=_MACHINE_PLAN_SHA256,
    )
    records = tuple(
        _SeedRecord(
            ordinal=index + 1,
            formal_seed=formal_seeds[index],
            strategy_order=_STRATEGY_ORDERS[index],
            rho_order=_RHO_ORDERS[index],
        )
        for index in range(3)
    )
    sentinel_plan = canonical_route_a_document(
        {
            "schema_version": "dynamic-cssc-validation-scaling-sentinel-domain-v1",
            "formal_seeds": list(formal_seeds),
            "qualification_seed": qualification_seed,
            "query_vector_seed": query_vector_seed,
        }
    )
    return _ValidationScalingDomain(
        profile=profile,
        records=records,  # type: ignore[arg-type]
        plan_bytes=sentinel_plan,
        plan_sha256=hashlib.sha256(sentinel_plan).hexdigest(),
        clocks=_StudyClocks(wall_clock_ns, process_clock_ns),
        production=False,
    )


def _load_machine_plan_bytes() -> bytes:
    return _read_closed_repository_file(
        "config/route-a-publication-plan.json",
        _MACHINE_PLAN_SHA256,
    )


def _validate_scratch_root(scratch_root: Path) -> None:
    if not isinstance(scratch_root, Path) or not scratch_root.is_absolute():
        raise TypeError("scratch_root must be one absolute pathlib.Path")
    if scratch_root == Path(scratch_root.anchor):
        raise _ValidationScalingError("scratch_root cannot be a filesystem root")
    try:
        observed = scratch_root.lstat()
        entries = tuple(scratch_root.iterdir())
    except OSError as error:
        raise _ValidationScalingError("scratch_root is unavailable") from error
    if (
        scratch_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or stat.S_IMODE(observed.st_mode) != 0o700
        or entries
    ):
        raise _ValidationScalingError(
            "scratch_root must be a direct empty mode-0700 directory"
        )


def _destroy_owned_root(scratch_root: Path) -> None:
    try:
        observed = scratch_root.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise _ValidationScalingError("owned scratch_root cannot be re-inspected") from error
    if scratch_root.is_symlink() or not stat.S_ISDIR(observed.st_mode):
        raise _ValidationScalingError("owned scratch_root changed type before cleanup")
    shutil.rmtree(scratch_root)


def _clock_value(clock: Callable[[], int], *, label: str) -> int:
    value = clock()
    if type(value) is not int or value < 0:
        raise _ValidationScalingError(f"{label} returned a nonnegative strict-integer violation")
    return value


def _elapsed(start: int, stop: int, *, label: str) -> int:
    if type(start) is not int or type(stop) is not int or start < 0 or stop < start:
        raise _ValidationScalingError(f"{label} clock moved backwards")
    return stop - start


@contextmanager
def _count_compile_queries() -> Iterator[_CompileCounter]:
    original_query = query_compiler_module.compile_query
    original_simulator = simulator_module.compile_query
    if original_query is not original_simulator:
        raise _ValidationScalingError("compile_query bindings differ before instrumentation")
    counter: _CompileCounter

    def counted(*args: object, **kwargs: object) -> object:
        counter.count += 1
        return counter.original(*args, **kwargs)

    counter = _CompileCounter(original=original_query, wrapper=counted)
    query_compiler_module.compile_query = counted  # type: ignore[assignment]
    simulator_module.compile_query = counted  # type: ignore[assignment]
    try:
        yield counter
        if (
            query_compiler_module.compile_query is not counted
            or simulator_module.compile_query is not counted
        ):
            raise _ValidationScalingError("compile_query binding mutated during a measured cell")
    finally:
        query_compiler_module.compile_query = original_query
        simulator_module.compile_query = original_simulator


def _measure_call(
    clocks: _StudyClocks,
    operation: Callable[[], object],
) -> tuple[object, int, int]:
    wall_start = _clock_value(clocks.wall_ns, label="wall clock")
    process_start = _clock_value(clocks.process_ns, label="process clock")
    result = operation()
    wall_stop = _clock_value(clocks.wall_ns, label="wall clock")
    process_stop = _clock_value(clocks.process_ns, label="process clock")
    return (
        result,
        _elapsed(wall_start, wall_stop, label="wall"),
        _elapsed(process_start, process_stop, label="process"),
    )


def _rho_text(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"


def _seconds_to_nanoseconds(value: object, *, label: str) -> int:
    if type(value) is not str:
        raise _ValidationScalingError(f"{label} is not canonical nine-place seconds")
    match = _SECONDS.fullmatch(value)
    if match is None:
        raise _ValidationScalingError(f"{label} is not canonical nine-place seconds")
    whole, fractional = value.split(".", 1)
    return int(whole) * 1_000_000_000 + int(fractional)


def _semantic_projection(cell_document: dict[str, object]) -> bytes:
    if set(_SEMANTIC_FIELDS) - set(cell_document):
        raise _ValidationScalingError("canonical cell omitted a semantic projection field")
    return canonical_route_a_document(
        {field: cell_document[field] for field in _SEMANTIC_FIELDS}
    )


def _shard_identity(domain: _ValidationScalingDomain, trace: RouteASyntheticTrace) -> str:
    return _shard_identity_from_source(
        domain,
        formal_seed=trace.formal_seed,
        scale=trace.scale,
        source_trace_sha256=trace.event_trace_sha256,
    )


def _shard_identity_from_source(
    domain: _ValidationScalingDomain,
    *,
    formal_seed: int,
    scale: str,
    source_trace_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_route_a_document(
            {
                "formal_seed": formal_seed,
                "plan_sha256": domain.plan_sha256,
                "scale": scale,
                "source_tag": _SOURCE_TAG,
                "source_trace_sha256": source_trace_sha256,
                "study_id": _STUDY_ID,
                "unit_attempt_ordinal": 0,
            }
        )
    ).hexdigest()


def _validate_compile_count(query_count: object, compile_count: int) -> int:
    if (
        type(query_count) is not int
        or query_count <= 0
        or type(compile_count) is not int
        or not query_count <= compile_count <= 2 * query_count
    ):
        raise _ValidationScalingError("cell violates Q <= compile_query calls <= 2Q")
    return query_count


def _producer_row(
    *,
    run: RouteASyntheticCellRun,
    record: _SeedRecord,
    strategy: str,
    rho: Fraction,
    compile_count: int,
    operation_wall_ns: int,
    operation_process_ns: int,
    archive_wall_ns: int,
    archive_process_ns: int,
    trace: RouteASyntheticTrace,
    semantic_bytes: bytes,
) -> tuple[bytes, bytes]:
    document = run.cell.document
    query_count = _validate_compile_count(document["counts"]["queries"], compile_count)  # type: ignore[index]
    if query_count != _QUERY_COUNTS[rho]:
        raise _ValidationScalingError("cell query count differs from the registered rho")
    measurements = document["measurements"]
    assert type(measurements) is dict
    row = {
        "strategy_candidate_id": strategy,
        "rho": _rho_text(rho),
        "formal_seed": record.formal_seed,
        "seed_ordinal": record.ordinal,
        "role": "producer",
        "query_count": query_count,
        "compile_query_call_count": compile_count,
        "operation_wall_nanoseconds": operation_wall_ns,
        "operation_process_nanoseconds": operation_process_ns,
        "producer_cell_archive_wall_nanoseconds_or_null": archive_wall_ns,
        "producer_cell_archive_process_nanoseconds_or_null": archive_process_ns,
        "producer_state_transition_nanoseconds_or_null": _seconds_to_nanoseconds(
            measurements["producer_state_transition_seconds"],
            label="producer state transition seconds",
        ),
        "producer_result_assembly_nanoseconds_or_null": _seconds_to_nanoseconds(
            measurements["producer_result_assembly_seconds"],
            label="producer result assembly seconds",
        ),
        "replay_elapsed_nanoseconds_or_null": None,
        "semantic_projection_sha256": hashlib.sha256(semantic_bytes).hexdigest(),
        "source_trace_sha256": trace.event_trace_sha256,
        "machine_plan_sha256": _MACHINE_PLAN_SHA256,
    }
    return canonical_route_a_document(row), semantic_bytes


def _replay_row(
    *,
    replay: RouteASyntheticCellReplay,
    record: _SeedRecord,
    strategy: str,
    rho: Fraction,
    compile_count: int,
    operation_wall_ns: int,
    operation_process_ns: int,
    trace: RouteASyntheticTrace,
) -> tuple[bytes, bytes]:
    document = replay.final_cell.document
    query_count = _validate_compile_count(document["counts"]["queries"], compile_count)  # type: ignore[index]
    if query_count != _QUERY_COUNTS[rho]:
        raise _ValidationScalingError("replay query count differs from the registered rho")
    projection = _semantic_projection(document)
    measurements = document["measurements"]
    assert type(measurements) is dict
    row = {
        "strategy_candidate_id": strategy,
        "rho": _rho_text(rho),
        "formal_seed": record.formal_seed,
        "seed_ordinal": record.ordinal,
        "role": "independent-replay",
        "query_count": query_count,
        "compile_query_call_count": compile_count,
        "operation_wall_nanoseconds": operation_wall_ns,
        "operation_process_nanoseconds": operation_process_ns,
        "producer_cell_archive_wall_nanoseconds_or_null": None,
        "producer_cell_archive_process_nanoseconds_or_null": None,
        "producer_state_transition_nanoseconds_or_null": None,
        "producer_result_assembly_nanoseconds_or_null": None,
        "replay_elapsed_nanoseconds_or_null": _seconds_to_nanoseconds(
            measurements["replay_seconds"],
            label="replay seconds",
        ),
        "semantic_projection_sha256": hashlib.sha256(projection).hexdigest(),
        "source_trace_sha256": trace.event_trace_sha256,
        "machine_plan_sha256": _MACHINE_PLAN_SHA256,
    }
    return canonical_route_a_document(row), projection


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = _ZIP_MODE << 16
    return info


def _producer_paths() -> tuple[str, ...]:
    return tuple(
        path
        for cell_ordinal in range(9)
        for path in (
            f"cells/{cell_ordinal:02d}/timing-row.json",
            f"cells/{cell_ordinal:02d}/semantic-projection.json",
            f"cells/{cell_ordinal:02d}/producer-cell.zip",
        )
    ) + ("manifest.json",)


def _replay_paths() -> tuple[str, ...]:
    return tuple(
        path
        for cell_ordinal in range(9)
        for path in (
            f"cells/{cell_ordinal:02d}/timing-row.json",
            f"cells/{cell_ordinal:02d}/final-cell.json",
            f"cells/{cell_ordinal:02d}/semantic-projection.json",
            f"cells/{cell_ordinal:02d}/replay-receipt.json",
            f"cells/{cell_ordinal:02d}/producer-binding.json",
        )
    ) + ("manifest.json",)


def _cell_order(record: _SeedRecord) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    ordinal = 0
    for strategy in record.strategy_order:
        for rho in record.rho_order:
            rows.append(
                {
                    "cell_ordinal": ordinal,
                    "query_count": _QUERY_COUNTS[rho],
                    "rho": _rho_text(rho),
                    "strategy_candidate_id": strategy,
                }
            )
            ordinal += 1
    return rows


def _payload_manifest(
    *,
    role: Literal["producer", "independent-replay"],
    domain: _ValidationScalingDomain,
    record: _SeedRecord,
    source_trace_sha256: str,
    members: tuple[tuple[str, bytes], ...],
    producer_payload_sha256: str | None,
) -> bytes:
    return canonical_route_a_document(
        {
            "schema_version": _PAYLOAD_SCHEMA,
            "study_id": _STUDY_ID,
            "artifact_role": role,
            "seed_ordinal": record.ordinal,
            "formal_seed": record.formal_seed,
            "scale": _SCALE,
            "stage0_plan_sha256": domain.plan_sha256,
            "source_tag": _SOURCE_TAG,
            "source_trace_sha256": source_trace_sha256,
            "machine_plan_sha256": _MACHINE_PLAN_SHA256,
            "cell_count": 9,
            "cell_order": _cell_order(record),
            "member_count": len(members),
            "members": [
                {
                    "path": path,
                    "byte_count": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for path, content in members
            ],
            "retention_days": 1 if role == "producer" else 90,
            "private_material_included": role == "producer",
            "producer_payload_sha256_or_null": producer_payload_sha256,
            "claim_scope": "validation-scaling-only",
            "formal_authority_granted": False,
        }
    )


def _write_payload(paths: tuple[str, ...], members: dict[str, bytes]) -> bytes:
    if tuple(members) != paths:
        raise AssertionError("payload member order is not closed")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in paths:
            archive.writestr(_zip_info(path), members[path])
    content = buffer.getvalue()
    if len(content) > _MAX_PAYLOAD_BYTES:
        raise _ValidationScalingError("seed payload exceeds its closed byte bound")
    return content


def _read_payload(
    payload_bytes: bytes,
    *,
    expected_paths: tuple[str, ...],
) -> dict[str, bytes]:
    if type(payload_bytes) is not bytes:
        raise TypeError("producer_package_bytes must be exact bytes")
    if not payload_bytes or len(payload_bytes) > _MAX_PAYLOAD_BYTES:
        raise _ValidationScalingError("producer payload is empty or exceeds its byte bound")
    try:
        with zipfile.ZipFile(io.BytesIO(payload_bytes), "r") as archive:
            infos = archive.infolist()
            names = tuple(info.filename for info in infos)
            if names != expected_paths or len(set(names)) != len(names):
                raise _ValidationScalingError(
                    "canonical payload members are missing, extra, repeated, or reordered"
                )
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    info.flag_bits & 0x1
                    or info.is_dir()
                    or not stat.S_ISREG(mode)
                    or stat.S_IMODE(mode) != 0o644
                    or info.create_system != 3
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.date_time != _ZIP_TIME
                    or info.extra
                    or info.comment
                    or info.file_size > _MAX_MEMBER_BYTES
                    or info.compress_size != info.file_size
                ):
                    raise _ValidationScalingError("canonical payload member metadata changed")
                members[info.filename] = archive.read(info)
            if archive.comment:
                raise _ValidationScalingError("canonical payload has an archive comment")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise _ValidationScalingError("producer payload is not a safe canonical ZIP") from error
    return members


def _validate_cell_identity(
    document: dict[str, object],
    *,
    record: _SeedRecord,
    strategy: str,
    rho: Fraction,
    shard_identity: str,
) -> None:
    identity = document.get("identity")
    if type(identity) is not dict or identity != {
        "formal_seed_or_null": record.formal_seed,
        "object_sha256_or_null": None,
        "partition_or_null": None,
        "rho": _rho_text(rho),
        "scale_or_null": _SCALE,
        "semantics_or_null": None,
        "shard_identity_sha256": shard_identity,
        "source_kind": "synthetic",
        "strategy_candidate_id": strategy,
        "suite_role": "formal",
        "unit_attempt_ordinal": 0,
    }:
        raise _ValidationScalingError("cell identity differs from the registered target")


def _validate_row(
    content: bytes,
    *,
    role: Literal["producer", "independent-replay"],
    record: _SeedRecord,
    strategy: str,
    rho: Fraction,
    source_trace_sha256: str,
    semantic_bytes: bytes,
) -> dict[str, object]:
    row = _canonical_object(content, label="cell timing row")
    if set(row) != set(_CELL_ROW_FIELDS):
        raise _ValidationScalingError("cell timing row fields are not closed")
    if (
        row["strategy_candidate_id"] != strategy
        or row["rho"] != _rho_text(rho)
        or row["formal_seed"] != record.formal_seed
        or row["seed_ordinal"] != record.ordinal
        or row["role"] != role
        or row["query_count"] != _QUERY_COUNTS[rho]
        or row["source_trace_sha256"] != source_trace_sha256
        or row["machine_plan_sha256"] != _MACHINE_PLAN_SHA256
        or row["semantic_projection_sha256"]
        != hashlib.sha256(semantic_bytes).hexdigest()
    ):
        raise _ValidationScalingError("cell timing row binding changed")
    for field in (
        "query_count",
        "compile_query_call_count",
        "operation_wall_nanoseconds",
        "operation_process_nanoseconds",
    ):
        if type(row[field]) is not int or row[field] < 0:
            raise _ValidationScalingError(f"cell timing row {field} is not nonnegative int")
    _validate_compile_count(row["query_count"], row["compile_query_call_count"])  # type: ignore[arg-type]
    producer_fields = (
        "producer_cell_archive_wall_nanoseconds_or_null",
        "producer_cell_archive_process_nanoseconds_or_null",
        "producer_state_transition_nanoseconds_or_null",
        "producer_result_assembly_nanoseconds_or_null",
    )
    if role == "producer":
        if any(type(row[field]) is not int or row[field] < 0 for field in producer_fields):
            raise _ValidationScalingError("producer supporting timings are not closed integers")
        if row["replay_elapsed_nanoseconds_or_null"] is not None:
            raise _ValidationScalingError("producer row contains a replay timing")
    else:
        if any(row[field] is not None for field in producer_fields):
            raise _ValidationScalingError("replay row contains a producer timing")
        replay_ns = row["replay_elapsed_nanoseconds_or_null"]
        if type(replay_ns) is not int or replay_ns < 0:
            raise _ValidationScalingError("replay supporting timing is not a closed integer")
    return row


def _produce_payload(
    domain: _ValidationScalingDomain,
    record: _SeedRecord,
    machine_plan_bytes: bytes,
    scratch_root: Path,
) -> bytes:
    trace = generate_route_a_formal_trace(
        scale=_SCALE,
        formal_seed=record.formal_seed,
        scientific_profile=domain.profile,
    )
    shard_identity = _shard_identity(domain, trace)
    members: dict[str, bytes] = {}
    cell_ordinal = 0
    for strategy in record.strategy_order:
        for rho in record.rho_order:
            child = scratch_root / f"cell-{cell_ordinal:02d}"
            child.mkdir(mode=0o700)
            try:
                with _count_compile_queries() as counter:
                    measured, wall_ns, process_ns = _measure_call(
                        domain.clocks,
                        lambda strategy=strategy, rho=rho, child=child: (
                            evaluate_route_a_synthetic_cell(
                            trace,
                            strategy_candidate_id=strategy,
                            rho=rho,
                            shard_identity_sha256=shard_identity,
                            unit_attempt_ordinal=0,
                            machine_plan_bytes=machine_plan_bytes,
                            scratch_directory=child,
                            scientific_profile=domain.profile,
                            )
                        ),
                    )
                if type(measured) is not RouteASyntheticCellRun:
                    raise _ValidationScalingError("producer returned an unexpected cell type")
                run = measured
                _validate_cell_identity(
                    run.cell.document,
                    record=record,
                    strategy=strategy,
                    rho=rho,
                    shard_identity=shard_identity,
                )
                semantic_bytes = _semantic_projection(run.cell.document)
                archive_result, archive_wall_ns, archive_process_ns = _measure_call(
                    domain.clocks,
                    lambda run=run: produce_route_a_synthetic_cell_archive(run),
                )
                if type(archive_result) is not bytes:
                    raise _ValidationScalingError("producer cell archive is not exact bytes")
                row_bytes, semantic_bytes = _producer_row(
                    run=run,
                    record=record,
                    strategy=strategy,
                    rho=rho,
                    compile_count=counter.count,
                    operation_wall_ns=wall_ns,
                    operation_process_ns=process_ns,
                    archive_wall_ns=archive_wall_ns,
                    archive_process_ns=archive_process_ns,
                    trace=trace,
                    semantic_bytes=semantic_bytes,
                )
                prefix = f"cells/{cell_ordinal:02d}"
                members[f"{prefix}/timing-row.json"] = row_bytes
                members[f"{prefix}/semantic-projection.json"] = semantic_bytes
                members[f"{prefix}/producer-cell.zip"] = archive_result
            finally:
                shutil.rmtree(child, ignore_errors=False)
            cell_ordinal += 1
    payload_members = tuple(members.items())
    members["manifest.json"] = _payload_manifest(
        role="producer",
        domain=domain,
        record=record,
        source_trace_sha256=trace.event_trace_sha256,
        members=payload_members,
        producer_payload_sha256=None,
    )
    return _write_payload(_producer_paths(), members)


def _pretrace_producer_payload(
    domain: _ValidationScalingDomain,
    record: _SeedRecord,
    payload_bytes: bytes,
) -> _PretraceProducerPayload:
    """Close every producer envelope field before regenerating a formal trace."""

    members = _read_payload(payload_bytes, expected_paths=_producer_paths())
    manifest = _canonical_object(members["manifest.json"], label="producer manifest")
    if set(manifest) != set(_MANIFEST_FIELDS):
        raise _ValidationScalingError("producer manifest fields are not closed")
    source_trace_sha256 = manifest.get("source_trace_sha256")
    if (
        type(source_trace_sha256) is not str
        or _LOWER_SHA256.fullmatch(source_trace_sha256) is None
    ):
        raise _ValidationScalingError("producer source trace digest is malformed")
    payload_members = tuple(
        (path, members[path]) for path in _producer_paths() if path != "manifest.json"
    )
    expected_manifest = _payload_manifest(
        role="producer",
        domain=domain,
        record=record,
        source_trace_sha256=source_trace_sha256,
        members=payload_members,
        producer_payload_sha256=None,
    )
    if members["manifest.json"] != expected_manifest:
        raise _ValidationScalingError("producer manifest differs from its exact members")
    shard_identity = _shard_identity_from_source(
        domain,
        formal_seed=record.formal_seed,
        scale=_SCALE,
        source_trace_sha256=source_trace_sha256,
    )
    cells: list[_ProducerCellInput] = []
    cell_ordinal = 0
    for strategy in record.strategy_order:
        for rho in record.rho_order:
            prefix = f"cells/{cell_ordinal:02d}"
            row_bytes = members[f"{prefix}/timing-row.json"]
            semantic_bytes = members[f"{prefix}/semantic-projection.json"]
            semantic = _canonical_object(semantic_bytes, label="semantic projection")
            if set(semantic) != set(_SEMANTIC_FIELDS):
                raise _ValidationScalingError("semantic projection fields are not closed")
            archive_bytes = members[f"{prefix}/producer-cell.zip"]
            try:
                inspection = inspect_route_a_synthetic_cell_archive(
                    archive_bytes,
                    scientific_profile=domain.profile,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as error:
                raise _ValidationScalingError(
                    "nested producer archive failed pre-trace inspection"
                ) from error
            run = inspection.cell_run
            _validate_cell_identity(
                run.cell.document,
                record=record,
                strategy=strategy,
                rho=rho,
                shard_identity=shard_identity,
            )
            expected_semantic = _semantic_projection(run.cell.document)
            if semantic_bytes != expected_semantic:
                raise _ValidationScalingError(
                    "producer semantic projection differs from its nested cell"
                )
            row = _validate_row(
                row_bytes,
                role="producer",
                record=record,
                strategy=strategy,
                rho=rho,
                source_trace_sha256=source_trace_sha256,
                semantic_bytes=semantic_bytes,
            )
            measurements = run.cell.document["measurements"]
            assert type(measurements) is dict
            if (
                row["producer_state_transition_nanoseconds_or_null"]
                != _seconds_to_nanoseconds(
                    measurements["producer_state_transition_seconds"],
                    label="producer state transition seconds",
                )
                or row["producer_result_assembly_nanoseconds_or_null"]
                != _seconds_to_nanoseconds(
                    measurements["producer_result_assembly_seconds"],
                    label="producer result assembly seconds",
                )
            ):
                raise _ValidationScalingError("producer supporting timing differs from its cell")
            cells.append(
                _ProducerCellInput(
                    row_bytes=row_bytes,
                    semantic_bytes=semantic_bytes,
                    archive_bytes=archive_bytes,
                    run=run,
                )
            )
            cell_ordinal += 1
    return _PretraceProducerPayload(
        source_trace_sha256=source_trace_sha256,
        cells=tuple(cells),
    )


def _decode_producer_payload(
    domain: _ValidationScalingDomain,
    record: _SeedRecord,
    trace: RouteASyntheticTrace,
    payload_bytes: bytes,
    *,
    predecoded_payload: _PretraceProducerPayload | None = None,
) -> tuple[_ProducerCellInput, ...]:
    predecoded = (
        _pretrace_producer_payload(domain, record, payload_bytes)
        if predecoded_payload is None
        else predecoded_payload
    )
    if predecoded.source_trace_sha256 != trace.event_trace_sha256:
        raise _ValidationScalingError("producer source trace differs from registered regeneration")
    return predecoded.cells


def _replay_payload(
    domain: _ValidationScalingDomain,
    record: _SeedRecord,
    machine_plan_bytes: bytes,
    producer_payload_bytes: bytes,
    scratch_root: Path,
) -> bytes:
    predecoded_payload = _pretrace_producer_payload(
        domain,
        record,
        producer_payload_bytes,
    )
    trace = generate_route_a_formal_trace(
        scale=_SCALE,
        formal_seed=record.formal_seed,
        scientific_profile=domain.profile,
    )
    producer_cells = _decode_producer_payload(
        domain,
        record,
        trace,
        producer_payload_bytes,
        predecoded_payload=predecoded_payload,
    )
    producer_payload_sha256 = hashlib.sha256(producer_payload_bytes).hexdigest()
    shard_identity = _shard_identity(domain, trace)
    members: dict[str, bytes] = {}
    cell_ordinal = 0
    for strategy in record.strategy_order:
        for rho in record.rho_order:
            producer = producer_cells[cell_ordinal]
            child = scratch_root / f"cell-{cell_ordinal:02d}"
            child.mkdir(mode=0o700)
            try:
                target = RouteASyntheticCellTarget.for_synthetic_trace(
                    trace,
                    strategy_candidate_id=strategy,
                    rho=rho,
                    shard_identity_sha256=shard_identity,
                    unit_attempt_ordinal=0,
                    scientific_profile=domain.profile,
                )
                with _count_compile_queries() as counter:
                    measured, wall_ns, process_ns = _measure_call(
                        domain.clocks,
                        lambda producer=producer, target=target, child=child: (
                            replay_route_a_synthetic_cell(
                                trace,
                                archive_bytes=producer.archive_bytes,
                                expected_target=target,
                                machine_plan_bytes=machine_plan_bytes,
                                scratch_directory=child,
                                scientific_profile=domain.profile,
                            )
                        ),
                    )
                if type(measured) is not RouteASyntheticCellReplay:
                    raise _ValidationScalingError("replay returned an unexpected cell type")
                replay = measured
                _validate_cell_identity(
                    replay.final_cell.document,
                    record=record,
                    strategy=strategy,
                    rho=rho,
                    shard_identity=shard_identity,
                )
                row_bytes, semantic_bytes = _replay_row(
                    replay=replay,
                    record=record,
                    strategy=strategy,
                    rho=rho,
                    compile_count=counter.count,
                    operation_wall_ns=wall_ns,
                    operation_process_ns=process_ns,
                    trace=trace,
                )
                if semantic_bytes != producer.semantic_bytes:
                    raise _ValidationScalingError(
                        "producer/replay semantic projections are not byte-identical"
                    )
                binding_bytes = canonical_route_a_document(
                    {
                        "schema_version": _BINDING_SCHEMA,
                        "producer_payload_sha256": producer_payload_sha256,
                        "producer_cell_archive_sha256": hashlib.sha256(
                            producer.archive_bytes
                        ).hexdigest(),
                        "producer_cell_archive_byte_count": len(producer.archive_bytes),
                        "producer_cell_sha256": producer.run.cell.sha256,
                        "producer_semantic_projection_sha256": hashlib.sha256(
                            producer.semantic_bytes
                        ).hexdigest(),
                        "producer_timing_row_sha256": hashlib.sha256(
                            producer.row_bytes
                        ).hexdigest(),
                    }
                )
                prefix = f"cells/{cell_ordinal:02d}"
                members[f"{prefix}/timing-row.json"] = row_bytes
                members[f"{prefix}/final-cell.json"] = replay.final_cell.document_bytes
                members[f"{prefix}/semantic-projection.json"] = semantic_bytes
                members[f"{prefix}/replay-receipt.json"] = replay.receipt_bytes
                members[f"{prefix}/producer-binding.json"] = binding_bytes
            finally:
                shutil.rmtree(child, ignore_errors=False)
            cell_ordinal += 1
    payload_members = tuple(members.items())
    members["manifest.json"] = _payload_manifest(
        role="independent-replay",
        domain=domain,
        record=record,
        source_trace_sha256=trace.event_trace_sha256,
        members=payload_members,
        producer_payload_sha256=producer_payload_sha256,
    )
    return _write_payload(_replay_paths(), members)


def _run_owned(
    *,
    domain: _ValidationScalingDomain,
    seed_ordinal: int,
    scratch_root: Path,
    producer_payload_bytes: bytes | None,
) -> bytes:
    record = domain.record(seed_ordinal)
    _validate_scratch_root(scratch_root)
    try:
        machine_plan_bytes = _load_machine_plan_bytes()
        domain.profile.require_machine_plan_bytes(machine_plan_bytes)
        if producer_payload_bytes is None:
            return _produce_payload(
                domain,
                record,
                machine_plan_bytes,
                scratch_root,
            )
        return _replay_payload(
            domain,
            record,
            machine_plan_bytes,
            producer_payload_bytes,
            scratch_root,
        )
    finally:
        _destroy_owned_root(scratch_root)


def produce_validation_scaling_seed_shard(
    *,
    plan_bytes: bytes,
    seed_ordinal: int,
    scratch_root: Path,
) -> bytes:
    """Produce one exact nine-cell private payload for a registered seed ordinal."""

    domain = _production_domain(plan_bytes)
    return _run_owned(
        domain=domain,
        seed_ordinal=seed_ordinal,
        scratch_root=scratch_root,
        producer_payload_bytes=None,
    )


def replay_validation_scaling_seed_shard(
    *,
    plan_bytes: bytes,
    producer_package_bytes: bytes,
    seed_ordinal: int,
    scratch_root: Path,
) -> bytes:
    """Reinspect and independently replay one exact producer payload."""

    domain = _production_domain(plan_bytes)
    if type(producer_package_bytes) is not bytes:
        raise TypeError("producer_package_bytes must be exact bytes")
    if not producer_package_bytes:
        raise _ValidationScalingError("producer_package_bytes must be nonempty")
    return _run_owned(
        domain=domain,
        seed_ordinal=seed_ordinal,
        scratch_root=scratch_root,
        producer_payload_bytes=producer_package_bytes,
    )
