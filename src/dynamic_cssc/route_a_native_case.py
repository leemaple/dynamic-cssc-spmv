"""Compile one terminal Route A case without executing OpenFHE.

Native cases intentionally execute only the query emitted after the final
accepted group.  Earlier query arrivals still advance the exact global query
cursor, but their query-side plans are never assembled or executed here.  The
result is one deep, typed boundary shared by qualification and the six formal
OpenFHE cases; key generation, encryption, package retention, and replay remain
the responsibility of the native package runtime.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from fractions import Fraction
from typing import Literal, TypeAlias

from dynamic_cssc.cloud_execution_plan import (
    CloudExecutionPlan,
    CloudPlanCounts,
    canonical_cloud_visible_payload,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    bind_ordinary_execution,
    canonical_ordinary_private_plan_payload,
)
from dynamic_cssc.output_plan import OutputPlan, canonical_output_plan_payload
from dynamic_cssc.plaintext_oracle import direct_spmv
from dynamic_cssc.route_a_contract import (
    RouteAQueryVector,
    RouteAQueryVectorDomain,
    generate_route_a_query_vector,
)
from dynamic_cssc.route_a_results import (
    ROUTE_A_MACHINE_PLAN_SHA256,
    canonical_route_a_document,
)
from dynamic_cssc.route_a_schedule import compile_route_a_window_trace
from dynamic_cssc.route_a_strategy import (
    ROUTE_A_STRATEGY_CANDIDATES,
    RouteACandidateState,
    advance_route_a_candidate_state_only,
    advance_route_a_candidate_timed,
    initialize_route_a_candidate,
)
from dynamic_cssc.route_a_workloads import (
    RouteASyntheticTrace,
    validate_route_a_synthetic_trace,
)
from dynamic_cssc.simulator import (
    account_strong_transition_with_bundle,
    account_transition_with_compiled,
)
from dynamic_cssc.strategy_state import StrongTransition, Transition
from dynamic_cssc.strong_execution import (
    StrongExecutionBundle,
    canonical_private_plan_payload,
)

__all__ = (
    "RouteANativeCaseError",
    "RouteANativeCasePlan",
    "compile_route_a_terminal_native_case",
)

_MODULUS = 65_537
_RHO = Fraction(1)
_FRESHNESS = Fraction(1)
_CASE_SCHEMA = "dynamic-cssc-route-a-terminal-native-case-v1"
_STRUCTURAL_SCHEMA = "dynamic-cssc-route-a-native-structural-vector-v1"
_DIRECT_ORACLE_SCHEMA = "dynamic-cssc-route-a-native-direct-oracle-v1"
_INPUT_STREAM_SCHEMA = "dynamic-cssc-route-a-native-canonical-input-stream-v1"

RouteANativeExecutionBundle: TypeAlias = OrdinaryExecutionBundle | StrongExecutionBundle


class RouteANativeCaseError(ValueError):
    """A terminal native case differs from the frozen Route A contract."""


def _canonical_input_root(inputs: tuple[tuple[str, bytes], ...]) -> str:
    digest = hashlib.sha256()
    schema = _INPUT_STREAM_SCHEMA.encode("ascii")
    digest.update(len(schema).to_bytes(8, "big"))
    digest.update(schema)
    digest.update(len(inputs).to_bytes(8, "big"))
    for name, content in inputs:
        name_bytes = name.encode("ascii")
        digest.update(len(name_bytes).to_bytes(8, "big"))
        digest.update(name_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _query_domain(trace: RouteASyntheticTrace) -> RouteAQueryVectorDomain:
    if trace.suite_role == "qualification":
        return RouteAQueryVectorDomain.qualification_synthetic(
            scale=trace.scale,
            qualification_seed=trace.formal_seed,
        )
    return RouteAQueryVectorDomain.formal_synthetic(
        scale=trace.scale,
        formal_seed=trace.formal_seed,
    )


def _bundle_views(
    transition: Transition | StrongTransition,
) -> tuple[
    Literal["ordinary", "strong"],
    RouteANativeExecutionBundle,
    bytes,
    dict[str, int],
    dict[str, int],
]:
    """Close one terminal transition into a shared native execution view."""

    if type(transition) is StrongTransition:
        accounting, bundle = account_strong_transition_with_bundle(transition)
        if bundle is None or transition.execution_bundle != bundle:
            raise RouteANativeCaseError("terminal strong transition lacks its exact bundle")
        private_plan_bytes = canonical_route_a_document(canonical_private_plan_payload(bundle))
        mechanism = {
            "actual_overlap_contributor_group": int(bundle.output_analysis.overlap_coordinates > 0),
            "f1m_random_mask_path": int(bundle.f1m_counts.random_zero_sum_ciphertexts > 0),
            "nonempty_auxiliary_segment": int(bool(bundle.delta.segments)),
        }
        topology = {
            "auxiliary_segment_count": len(bundle.delta.segments),
            "component_count": 1 + int(bool(bundle.delta.segments)),
            "output_share_count": len(bundle.output_plan.shares),
            "overlap_coordinate_count": bundle.output_analysis.overlap_coordinates,
            "page_count": len(bundle.value_operand_specs),
        }
        execution_kind: Literal["ordinary", "strong"] = "strong"
    elif type(transition) is Transition:
        accounting, compiled = account_transition_with_compiled(transition)
        if compiled is None:
            raise RouteANativeCaseError("terminal ordinary transition lacks compilation")
        bundle = bind_ordinary_execution(compiled)
        private_plan_bytes = canonical_route_a_document(
            canonical_ordinary_private_plan_payload(bundle)
        )
        mechanism = {
            "actual_overlap_contributor_group": int(
                compiled.output_analysis.overlap_coordinates > 0
            ),
            "f1m_random_mask_path": int(compiled.output_analysis.masked_result_ciphertexts > 0),
            "nonempty_auxiliary_segment": int(
                compiled.segmented_delta is not None or bool(compiled.client_lane_segments)
            ),
        }
        topology = {
            "auxiliary_segment_count": (
                len(compiled.segmented_delta.segments)
                if compiled.segmented_delta is not None
                else len(compiled.client_lane_segments)
            ),
            "component_count": len(compiled.components),
            "output_share_count": len(compiled.output_plan.shares),
            "overlap_coordinate_count": compiled.output_analysis.overlap_coordinates,
            "page_count": len(compiled.operand_specs),
        }
        execution_kind = "ordinary"
    else:  # pragma: no cover - the candidate union is closed
        raise TypeError("terminal Route A transition has the wrong exact type")
    if accounting.metrics.queries != 1 or accounting.query_plan is None:
        raise RouteANativeCaseError("terminal native transition is not exactly one query")
    return execution_kind, bundle, private_plan_bytes, mechanism, topology


def _cloud_plan(bundle: RouteANativeExecutionBundle) -> CloudExecutionPlan:
    if type(bundle) is OrdinaryExecutionBundle:
        return bundle.compiled.cloud_plan
    return bundle.cloud_plan


def _output_plan(bundle: RouteANativeExecutionBundle) -> OutputPlan:
    if type(bundle) is OrdinaryExecutionBundle:
        return bundle.compiled.output_plan
    return bundle.output_plan


def _cloud_counts(bundle: RouteANativeExecutionBundle) -> CloudPlanCounts:
    if type(bundle) is OrdinaryExecutionBundle:
        return bundle.compiled.cloud_counts
    return bundle.cloud_counts


@dataclass(frozen=True, slots=True)
class RouteANativeCasePlan:
    """One terminal typed case, direct oracle, and closed pre-process byte set."""

    trace: RouteASyntheticTrace
    strategy_candidate_id: str
    shard_identity_sha256: str
    unit_attempt_ordinal: int
    execution_kind: Literal["ordinary", "strong"]
    execution_bundle: RouteANativeExecutionBundle
    query_vector: RouteAQueryVector
    terminal_global_query_ordinal: int
    terminal_window_ordinal: int
    terminal_version_id: str
    direct_oracle_output: tuple[int, ...]
    direct_oracle_bytes: bytes
    direct_oracle_sha256: str
    retained_canonical_inputs: tuple[tuple[str, bytes], ...]
    retained_canonical_input_root: str
    structural_vector_bytes: bytes
    structural_vector_sha256: str
    mechanism_coverage: tuple[tuple[str, bool], ...]
    case_binding_bytes: bytes
    case_binding_sha256: str

    def __post_init__(self) -> None:
        names = tuple(name for name, _content in self.retained_canonical_inputs)
        if (
            self.strategy_candidate_id not in ROUTE_A_STRATEGY_CANDIDATES
            or self.execution_kind not in {"ordinary", "strong"}
            or type(self.terminal_global_query_ordinal) is not int
            or self.terminal_global_query_ordinal < 0
            or type(self.terminal_window_ordinal) is not int
            or self.terminal_window_ordinal < 0
            or len(set(names)) != len(names)
            or names != tuple(sorted(names))
            or any(
                type(content) is not bytes or not content
                for _, content in self.retained_canonical_inputs
            )
            or _canonical_input_root(self.retained_canonical_inputs)
            != self.retained_canonical_input_root
            or hashlib.sha256(self.direct_oracle_bytes).hexdigest() != self.direct_oracle_sha256
            or hashlib.sha256(self.structural_vector_bytes).hexdigest()
            != self.structural_vector_sha256
            or hashlib.sha256(self.case_binding_bytes).hexdigest() != self.case_binding_sha256
        ):
            raise RouteANativeCaseError("terminal native case binding is not closed")
        if (self.execution_kind == "ordinary") != (
            type(self.execution_bundle) is OrdinaryExecutionBundle
        ):
            raise RouteANativeCaseError("native execution kind differs from its bundle")


def compile_route_a_terminal_native_case(
    trace: RouteASyntheticTrace,
    *,
    strategy_candidate_id: str,
    shard_identity_sha256: str,
    unit_attempt_ordinal: int,
    machine_plan_bytes: bytes,
) -> RouteANativeCasePlan:
    """Compile only the fixed terminal query while retaining all source bytes."""

    trace = validate_route_a_synthetic_trace(trace)
    if strategy_candidate_id not in ROUTE_A_STRATEGY_CANDIDATES:
        raise RouteANativeCaseError("native strategy candidate is not preregistered")
    if (
        type(unit_attempt_ordinal) is not int
        or unit_attempt_ordinal not in {0, 1}
        or type(machine_plan_bytes) is not bytes
        or hashlib.sha256(machine_plan_bytes).hexdigest() != ROUTE_A_MACHINE_PLAN_SHA256
    ):
        raise RouteANativeCaseError("native attempt or machine-plan binding is invalid")

    window_trace = compile_route_a_window_trace(
        trace.accepted_groups,
        source_event_trace_sha256=trace.event_trace_sha256,
        shard_identity_sha256=shard_identity_sha256,
        rho=_RHO,
        freshness=_FRESHNESS,
    )
    terminal_window = window_trace.ordered_windows[-1]
    final_group_ordinal = len(trace.accepted_groups) - 1
    if (
        terminal_window.query_count != 1
        or terminal_window.first_global_query_ordinal_or_null is None
        or terminal_window.last_event_group_ordinal_or_null != final_group_ordinal
        or not terminal_window.ordered_set_transition_references
        or terminal_window.ordered_set_transition_references[-1].accepted_group_ordinal
        != final_group_ordinal
    ):
        raise RouteANativeCaseError("rho=1 did not produce the exact terminal query")

    candidate: RouteACandidateState = initialize_route_a_candidate(
        strategy_candidate_id,
        trace.initial_state(),
        rows=trace.rows,
    )
    padding_replacement_count = 0
    for window in window_trace.ordered_windows[:-1]:
        state_advance = advance_route_a_candidate_state_only(
            candidate,
            trace.accepted_groups,
            window,
        )
        candidate = state_advance.candidate
        facts = state_advance.transition.facts
        padding_replacement_count += (
            facts.absorbed_tombstone + facts.absorbed_natural_padding + facts.absorbed_reserved
        )
    terminal = advance_route_a_candidate_timed(
        candidate,
        trace.accepted_groups,
        terminal_window,
    ).advance
    facts = terminal.transition.facts
    padding_replacement_count += (
        facts.absorbed_tombstone + facts.absorbed_natural_padding + facts.absorbed_reserved
    )
    execution_kind, bundle, private_plan_bytes, mechanism, topology = _bundle_views(
        terminal.transition
    )
    mechanism["padding_or_tombstone_replacement"] = int(padding_replacement_count > 0)
    if (
        strategy_candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128"
        and not mechanism["nonempty_auxiliary_segment"]
    ):
        raise RouteANativeCaseError("strong terminal snapshot lacks an auxiliary segment")
    if (
        trace.scale == "M"
        and strategy_candidate_id == ("packed-coo-cloud-segmented-delta/segment-width=128")
        and not (
            mechanism["actual_overlap_contributor_group"] and mechanism["f1m_random_mask_path"]
        )
    ):
        raise RouteANativeCaseError("strong M terminal snapshot lacks overlap/F1-M coverage")
    if (
        trace.scale == "M"
        and strategy_candidate_id == "padding-reuse"
        and not mechanism["padding_or_tombstone_replacement"]
    ):
        raise RouteANativeCaseError("padding M terminal snapshot lacks replacement coverage")

    query_vector = generate_route_a_query_vector(_query_domain(trace))
    direct_output = direct_spmv(
        terminal.candidate.state.logical,
        query_vector.values,
        rows=trace.rows,
        cols=trace.columns,
        modulus=_MODULUS,
    )
    direct_oracle_bytes = canonical_route_a_document(
        {
            "ordered_modular_outputs": list(direct_output),
            "schema_version": _DIRECT_ORACLE_SCHEMA,
        }
    )
    cloud_plan = _cloud_plan(bundle)
    output_plan = _output_plan(bundle)
    cloud_visible_bytes = canonical_route_a_document(canonical_cloud_visible_payload(cloud_plan))
    output_plan_bytes = canonical_route_a_document(canonical_output_plan_payload(output_plan))
    retained_inputs = tuple(
        sorted(
            (
                ("cloud-visible-plan.json", cloud_visible_bytes),
                ("machine-plan.json", machine_plan_bytes),
                ("output-plan.json", output_plan_bytes),
                ("private-plan.json", private_plan_bytes),
                ("query-vector-domain.json", query_vector.domain_bytes),
                ("query-vector.json", query_vector.vector_bytes),
                ("synthetic-event-trace.json", trace.event_trace_bytes),
                ("synthetic-initial-state.json", trace.initial_state_bytes),
                ("window-trace-rho1.json", window_trace.document_bytes),
            )
        )
    )
    input_root = _canonical_input_root(retained_inputs)
    counts = _cloud_counts(bundle)
    program = cloud_plan.program
    ciphertext_roles: dict[str, int] = {}
    for item in program.ciphertext_inputs:
        ciphertext_roles[item.role] = ciphertext_roles.get(item.role, 0) + 1
    structural_vector_bytes = canonical_route_a_document(
        {
            "canonical_input_byte_counts": {
                name: len(content) for name, content in retained_inputs
            },
            "ciphertext_input_multiplicities_by_role": ciphertext_roles,
            "cloud_plan_counts": asdict(counts),
            "execution_kind": execution_kind,
            "mechanism_coverage": {key: bool(value) for key, value in sorted(mechanism.items())},
            "ordered_operation_types": [type(node).__name__ for node in program.nodes],
            "result_ciphertext_count": len(program.result_ids),
            "rotation_key_indices": [
                openfhe_index for _logical_shift, openfhe_index in program.rotation_catalog.entries
            ],
            "schema_version": _STRUCTURAL_SCHEMA,
            "topology": topology,
        }
    )
    structural_sha256 = hashlib.sha256(structural_vector_bytes).hexdigest()
    direct_sha256 = hashlib.sha256(direct_oracle_bytes).hexdigest()
    terminal_version_id = cloud_plan.binding.version_id
    case_binding_bytes = canonical_route_a_document(
        {
            "authority": {
                "formal_artifact": False,
                "publication_authority": False,
            },
            "bindings": {
                "cloud_program_digest": cloud_plan.binding.cloud_program_digest,
                "direct_oracle_sha256": direct_sha256,
                "execution_binding_digest": (
                    bundle.compiled.execution_binding_digest
                    if type(bundle) is OrdinaryExecutionBundle
                    else bundle.execution_binding_digest
                ),
                "machine_plan_sha256": ROUTE_A_MACHINE_PLAN_SHA256,
                "output_plan_digest": cloud_plan.binding.output_plan_digest,
                "query_vector_sha256": query_vector.vector_sha256,
                "retained_canonical_input_root": input_root,
                "structural_vector_sha256": structural_sha256,
                "window_trace_sha256": window_trace.sha256,
            },
            "identity": {
                "execution_kind": execution_kind,
                "formal_seed": trace.formal_seed,
                "rho": "1",
                "scale": trace.scale,
                "shard_identity_sha256": shard_identity_sha256,
                "strategy_candidate_id": strategy_candidate_id,
                "suite_role": trace.suite_role,
                "terminal_global_query_ordinal": (
                    terminal_window.first_global_query_ordinal_or_null
                ),
                "terminal_version_id": terminal_version_id,
                "terminal_window_ordinal": terminal_window.window_ordinal,
                "unit_attempt_ordinal": unit_attempt_ordinal,
            },
            "schema_version": _CASE_SCHEMA,
        }
    )
    return RouteANativeCasePlan(
        trace=trace,
        strategy_candidate_id=strategy_candidate_id,
        shard_identity_sha256=shard_identity_sha256,
        unit_attempt_ordinal=unit_attempt_ordinal,
        execution_kind=execution_kind,
        execution_bundle=bundle,
        query_vector=query_vector,
        terminal_global_query_ordinal=(terminal_window.first_global_query_ordinal_or_null),
        terminal_window_ordinal=terminal_window.window_ordinal,
        terminal_version_id=terminal_version_id,
        direct_oracle_output=direct_output,
        direct_oracle_bytes=direct_oracle_bytes,
        direct_oracle_sha256=direct_sha256,
        retained_canonical_inputs=retained_inputs,
        retained_canonical_input_root=input_root,
        structural_vector_bytes=structural_vector_bytes,
        structural_vector_sha256=structural_sha256,
        mechanism_coverage=tuple((key, bool(value)) for key, value in sorted(mechanism.items())),
        case_binding_bytes=case_binding_bytes,
        case_binding_sha256=hashlib.sha256(case_binding_bytes).hexdigest(),
    )
