"""Typed deterministic primitives for the preregistered Route A runner."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)

__all__ = (
    "RouteAEvaluationLane",
    "RouteAQueryIdentity",
    "RouteAQueryVector",
    "RouteAQueryVectorDomain",
    "generate_route_a_query_vector",
    "route_a_query_batch_counts",
)

_DOMAIN_SCHEMA = "dynamic-cssc-route-a-query-vector-domain-v1"
_VECTOR_SCHEMA = "dynamic-cssc-route-a-query-vector-v1"
_QUERY_VECTOR_LENGTH = 8_193
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ROUTE_A_RHOS = frozenset({Fraction(1, 100), Fraction(1, 10), Fraction(1), Fraction(10)})
_STRATEGY_IDS = frozenset(
    {
        "periodic-repack/windows=1",
        "padding-reuse",
        "packed-coo-cloud-segmented-delta/segment-width=128",
    }
)
_LANE_SCHEMA = "dynamic-cssc-route-a-evaluation-lane-identity-v2"
_QUERY_ID_SCHEMA = "dynamic-cssc-route-a-query-id-v1"


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("Route A identity is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


@dataclass(frozen=True, slots=True)
class RouteAQueryVectorDomain:
    """Closed identity domain for one public deterministic query vector."""

    kind: Literal["synthetic", "snap-a2q"]
    suite_role: Literal["qualification", "formal"]
    scale: Literal["S", "M"] | None
    formal_seed: int | None
    object_sha256: str | None = None
    mapping_sha256: str | None = None
    partition: int | None = None
    semantics: Literal["T1", "T2"] | None = None
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE

    def __post_init__(self) -> None:
        if type(self.scientific_profile) is not RouteAScientificProfile:
            raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
        qualification = (
            self.kind == "synthetic"
            and self.suite_role == "qualification"
            and self.scale == "M"
            and type(self.formal_seed) is int
            and self.formal_seed == self.scientific_profile.qualification_seed
            and self.object_sha256 is None
            and self.mapping_sha256 is None
            and self.partition is None
            and self.semantics is None
        )
        formal_synthetic = (
            self.kind == "synthetic"
            and self.suite_role == "formal"
            and self.scale in {"S", "M"}
            and type(self.formal_seed) is int
            and self.formal_seed in self.scientific_profile.formal_seeds
            and self.object_sha256 is None
            and self.mapping_sha256 is None
            and self.partition is None
            and self.semantics is None
        )
        snap = (
            self.kind == "snap-a2q"
            and self.suite_role == "formal"
            and self.scale is None
            and self.formal_seed is None
            and type(self.object_sha256) is str
            and _LOWER_SHA256.fullmatch(self.object_sha256) is not None
            and type(self.mapping_sha256) is str
            and _LOWER_SHA256.fullmatch(self.mapping_sha256) is not None
            and type(self.partition) is int
            and self.partition in {0, 1}
            and self.semantics in {"T1", "T2"}
        )
        if not (qualification or formal_synthetic or snap):
            raise ValueError("Route A query-vector domain is not one closed source identity")

    @classmethod
    def qualification_synthetic(
        cls,
        *,
        scale: str,
        qualification_seed: int,
        scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    ) -> RouteAQueryVectorDomain:
        if type(scientific_profile) is not RouteAScientificProfile:
            raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
        try:
            scientific_profile.require_trace_scope(
                suite_role="qualification",
                scale=scale,
                seed=qualification_seed,
            )
        except (TypeError, ValueError) as error:
            raise ValueError("qualification query-vector scope must be M/20260821") from error
        return cls(
            kind="synthetic",
            suite_role="qualification",
            scale="M",
            formal_seed=qualification_seed,
            scientific_profile=scientific_profile,
        )

    @classmethod
    def formal_synthetic(
        cls,
        *,
        scale: str,
        formal_seed: int,
        scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    ) -> RouteAQueryVectorDomain:
        if type(scientific_profile) is not RouteAScientificProfile:
            raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
        try:
            scientific_profile.require_trace_scope(
                suite_role="formal",
                scale=scale,
                seed=formal_seed,
            )
        except (TypeError, ValueError) as error:
            raise ValueError(
                "formal query-vector scope requires S/M and seed 20260822..20260824"
            ) from error
        return cls(
            kind="synthetic",
            suite_role="formal",
            scale=scale,  # type: ignore[arg-type]
            formal_seed=formal_seed,
            scientific_profile=scientific_profile,
        )

    @classmethod
    def snap_a2q(
        cls,
        *,
        object_sha256: str,
        mapping_sha256: str,
        partition: int,
        semantics: str,
        scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
    ) -> RouteAQueryVectorDomain:
        if type(scientific_profile) is not RouteAScientificProfile:
            raise TypeError("scientific_profile must be an exact RouteAScientificProfile")
        return cls(
            kind="snap-a2q",
            suite_role="formal",
            scale=None,
            formal_seed=None,
            object_sha256=object_sha256,
            mapping_sha256=mapping_sha256,
            partition=partition,
            semantics=semantics,  # type: ignore[arg-type]
            scientific_profile=scientific_profile,
        )

    def to_document(self) -> dict[str, object]:
        if self.kind == "synthetic":
            return {
                "formal_seed": self.formal_seed,
                "kind": self.kind,
                "length": _QUERY_VECTOR_LENGTH,
                "scale": self.scale,
                "schema_version": _DOMAIN_SCHEMA,
                "seed": self.scientific_profile.query_vector_seed,
            }
        return {
            "kind": self.kind,
            "length": _QUERY_VECTOR_LENGTH,
            "mapping_sha256": self.mapping_sha256,
            "object_sha256": self.object_sha256,
            "partition": self.partition,
            "schema_version": _DOMAIN_SCHEMA,
            "seed": self.scientific_profile.query_vector_seed,
            "semantics": self.semantics,
        }


@dataclass(frozen=True, slots=True)
class RouteAQueryVector:
    """Canonical vector bytes plus their independently reusable typed values."""

    suite_role: Literal["qualification", "formal"]
    domain_bytes: bytes
    domain_sha256: str
    vector_bytes: bytes
    vector_sha256: str
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class RouteAQueryIdentity:
    """One canonical query-ID document and its lowercase SHA-256 identifier."""

    document_bytes: bytes
    query_id: str
    global_query_ordinal: int


@dataclass(frozen=True, slots=True)
class RouteAEvaluationLane:
    """One attempt- and process-bound namespace for direct query execution."""

    shard_identity_sha256: str
    strategy_candidate_id: str
    rho: Fraction
    unit_attempt_ordinal: int
    execution_process_role: Literal[
        "simulator",
        "openfhe-warmup",
        "openfhe-recorded",
    ]
    process_ordinal_or_null: int | None

    def __post_init__(self) -> None:
        if (
            type(self.shard_identity_sha256) is not str
            or _LOWER_SHA256.fullmatch(self.shard_identity_sha256) is None
            or self.strategy_candidate_id not in _STRATEGY_IDS
            or type(self.rho) is not Fraction
            or self.rho not in _ROUTE_A_RHOS - {Fraction(10)}
            or type(self.unit_attempt_ordinal) is not int
            or self.unit_attempt_ordinal not in {0, 1}
            or type(self.execution_process_role) is not str
            or (
                self.execution_process_role == "simulator"
                and self.process_ordinal_or_null is not None
            )
            or (
                self.execution_process_role == "openfhe-warmup"
                and (
                    type(self.process_ordinal_or_null) is not int
                    or self.process_ordinal_or_null != 0
                )
            )
            or (
                self.execution_process_role == "openfhe-recorded"
                and (
                    type(self.process_ordinal_or_null) is not int
                    or self.process_ordinal_or_null not in {0, 1, 2}
                )
            )
            or self.execution_process_role
            not in {"simulator", "openfhe-warmup", "openfhe-recorded"}
        ):
            raise ValueError("Route A evaluation lane is not a closed identity")

    @classmethod
    def simulator(
        cls,
        *,
        shard_identity_sha256: str,
        strategy_candidate_id: str,
        rho: Fraction,
        unit_attempt_ordinal: int,
    ) -> RouteAEvaluationLane:
        return cls(
            shard_identity_sha256=shard_identity_sha256,
            strategy_candidate_id=strategy_candidate_id,
            rho=rho,
            unit_attempt_ordinal=unit_attempt_ordinal,
            execution_process_role="simulator",
            process_ordinal_or_null=None,
        )

    @classmethod
    def openfhe_warmup(
        cls,
        *,
        shard_identity_sha256: str,
        strategy_candidate_id: str,
        rho: Fraction,
        unit_attempt_ordinal: int,
    ) -> RouteAEvaluationLane:
        return cls(
            shard_identity_sha256=shard_identity_sha256,
            strategy_candidate_id=strategy_candidate_id,
            rho=rho,
            unit_attempt_ordinal=unit_attempt_ordinal,
            execution_process_role="openfhe-warmup",
            process_ordinal_or_null=0,
        )

    @classmethod
    def openfhe_recorded(
        cls,
        *,
        shard_identity_sha256: str,
        strategy_candidate_id: str,
        rho: Fraction,
        unit_attempt_ordinal: int,
        process_ordinal: int,
    ) -> RouteAEvaluationLane:
        return cls(
            shard_identity_sha256=shard_identity_sha256,
            strategy_candidate_id=strategy_candidate_id,
            rho=rho,
            unit_attempt_ordinal=unit_attempt_ordinal,
            execution_process_role="openfhe-recorded",
            process_ordinal_or_null=process_ordinal,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "execution_process_role": self.execution_process_role,
            "process_ordinal_or_null": self.process_ordinal_or_null,
            "rho": _rho_string(self.rho),
            "schema_version": _LANE_SCHEMA,
            "shard_identity_sha256": self.shard_identity_sha256,
            "strategy_candidate_id": self.strategy_candidate_id,
            "unit_attempt_ordinal": self.unit_attempt_ordinal,
        }

    @property
    def document_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_document())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.document_bytes).hexdigest()

    def query_identity(self, global_query_ordinal: int) -> RouteAQueryIdentity:
        if type(global_query_ordinal) is not int or global_query_ordinal < 0:
            raise ValueError("global_query_ordinal must be a nonnegative strict integer")
        document_bytes = _canonical_json_bytes(
            {
                "evaluation_lane_identity_sha256": self.sha256,
                "global_query_ordinal": global_query_ordinal,
                "schema_version": _QUERY_ID_SCHEMA,
            }
        )
        return RouteAQueryIdentity(
            document_bytes=document_bytes,
            query_id=hashlib.sha256(document_bytes).hexdigest(),
            global_query_ordinal=global_query_ordinal,
        )


def generate_route_a_query_vector(domain: RouteAQueryVectorDomain) -> RouteAQueryVector:
    """Generate the exact public ternary vector fixed by the Route A contract."""

    if type(domain) is not RouteAQueryVectorDomain:
        raise TypeError("domain must be an exact RouteAQueryVectorDomain")
    domain_bytes = _canonical_json_bytes(domain.to_document())
    values = [1]
    for coordinate in range(1, _QUERY_VECTOR_LENGTH - 1):
        attempt = 0
        while True:
            sample = hashlib.shake_256(
                domain_bytes
                + coordinate.to_bytes(8, "big", signed=False)
                + attempt.to_bytes(8, "big", signed=False)
            ).digest(1)[0]
            if sample != 255:
                values.append((-1, 0, 1)[sample % 3])
                break
            attempt += 1
            if attempt >= 1 << 64:  # pragma: no cover - cryptographic exhaustion bound
                raise RuntimeError("Route A query-vector rejection counter exhausted")
    values.append(-1)
    frozen_values = tuple(values)
    domain_sha256 = hashlib.sha256(domain_bytes).hexdigest()
    vector_bytes = _canonical_json_bytes(
        {
            "domain_sha256": domain_sha256,
            "schema_version": _VECTOR_SCHEMA,
            "values": frozen_values,
        }
    )
    return RouteAQueryVector(
        suite_role=domain.suite_role,
        domain_bytes=domain_bytes,
        domain_sha256=domain_sha256,
        vector_bytes=vector_bytes,
        vector_sha256=hashlib.sha256(vector_bytes).hexdigest(),
        values=frozen_values,
    )


def route_a_query_batch_counts(
    accepted_group_count: int,
    rho: Fraction,
) -> tuple[int, ...]:
    """Return the preregistered exact query count after every accepted group."""

    if type(accepted_group_count) is not int or accepted_group_count <= 0:
        raise ValueError("accepted_group_count must be a positive strict integer")
    if type(rho) is not Fraction or rho not in _ROUTE_A_RHOS:
        raise ValueError("rho must be one exact preregistered Route A ratio")
    numerator = rho.numerator
    denominator = rho.denominator
    return tuple(
        ((ordinal + 1) * numerator // denominator) - (ordinal * numerator // denominator)
        for ordinal in range(accepted_group_count)
    )


def _rho_string(rho: Fraction) -> str:
    return str(rho.numerator) if rho.denominator == 1 else f"{rho.numerator}/{rho.denominator}"
