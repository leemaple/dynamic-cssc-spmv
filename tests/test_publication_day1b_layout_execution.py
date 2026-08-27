from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import build_ordinary_openfhe_query_request
from dynamic_cssc.ordinary_query_lifecycle import (
    bind_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.publication_day1b_layout_execution import (
    Day1BLayoutExecutionError,
    Day1BQueryLayoutExecution,
)
from dynamic_cssc.query_compiler import compile_query
from dynamic_cssc.simulator import QueryPlanAccounting


def _ordinary_layout() -> Day1BQueryLayoutExecution:
    component = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="layout-execution-v1",
        component_prefix="layout-execution",
    )
    compiled = compile_query((component,), f1m_policy="overlap-only")
    plan = QueryPlanAccounting(
        version_id=compiled.cloud_plan.binding.version_id,
        cloud_program_digest=compiled.cloud_program_digest,
        output_plan_digest=compiled.output_plan_digest,
        execution_binding_digest=compiled.execution_binding_digest,
        private_plan_digest=compiled.private_plan_digest,
        returned_share_count=len(compiled.result_routes),
        f1m_routes=(),
    )
    return Day1BQueryLayoutExecution(
        phase="held-out",
        window_index=7,
        accepted_group_start=100,
        accepted_group_end=108,
        first_global_query_ordinal=200,
        query_count=11,
        query_plan=plan,
        ordinary_compilation=compiled,
    )


def test_layout_execution_binds_the_exact_compiler_output() -> None:
    execution = _ordinary_layout()
    compiled = execution.ordinary_compilation

    assert execution.execution_kind == "ordinary"
    assert compiled is not None
    assert execution.query_plan.cloud_program_digest == compiled.cloud_program_digest
    assert execution.query_plan.output_plan_digest == compiled.output_plan_digest
    assert (
        execution.query_plan.execution_binding_digest
        == compiled.execution_binding_digest
    )
    assert execution.query_plan.private_plan_digest == compiled.private_plan_digest


def test_streamed_ordinary_compilation_reaches_the_canonical_runner_request(
    tmp_path: Path,
) -> None:
    execution = _ordinary_layout()
    compiled = execution.ordinary_compilation
    assert compiled is not None
    bundle = bind_ordinary_execution(compiled)
    prepared = prepare_ordinary_query(
        bundle,
        query_id="layout-execution-query-1",
        vector=(3, 5),
        modulus=65537,
        ledger=SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3"),
    )

    request = json.loads(build_ordinary_openfhe_query_request(bundle, prepared))

    assert request["bindings"]["cloud_program_sha256"] == (
        execution.query_plan.cloud_program_digest
    )
    assert request["bindings"]["execution_binding_sha256"] == (
        execution.query_plan.execution_binding_digest
    )
    assert request["bindings"]["query_private_plan_sha256"] == (
        execution.query_plan.private_plan_digest
    )
    assert request["bindings"]["execution_kind"] == "ordinary"


def test_layout_execution_rejects_absent_or_ambiguous_bundles() -> None:
    execution = _ordinary_layout()

    with pytest.raises(Day1BLayoutExecutionError, match="exactly one"):
        replace(execution, ordinary_compilation=None)
    with pytest.raises(Day1BLayoutExecutionError, match="exactly one"):
        replace(execution, strong_bundle=object())  # type: ignore[arg-type]


def test_layout_execution_rejects_a_rehashed_compact_plan_splice() -> None:
    execution = _ordinary_layout()
    changed_plan = replace(
        execution.query_plan,
        cloud_program_digest="0" * 64,
    )

    with pytest.raises(Day1BLayoutExecutionError, match="differs from its compact"):
        replace(execution, query_plan=changed_plan)


def test_layout_execution_exposes_no_authority_or_admission_field() -> None:
    fields = set(Day1BQueryLayoutExecution.__dataclass_fields__)

    assert not any(
        "authority" in field or "admiss" in field or "dispatch" in field
        for field in fields
    )
