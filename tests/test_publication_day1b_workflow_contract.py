from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/publication-day1b-preparatory.yml"
EXPECTED_TEST_PATHS = (
    "tests/test_evidence_compatibility.py",
    "tests/test_openfhe_query_runner.py",
    "tests/test_openfhe_query_runtime.py",
    "tests/test_ordinary_query_lifecycle.py",
    "tests/test_publication_day1b.py",
    "tests/test_publication_day1b_accounting.py",
    "tests/test_publication_day1b_worker_protocol.py",
    "tests/test_publication_day1b_workflow_contract.py",
    "tests/test_query_accounting.py",
    "tests/test_strong_day1_simulator.py",
)


def _workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_day1b_preparatory_workflow_is_manual_inert_and_has_no_inputs() -> None:
    workflow = _workflow()

    assert re.search(r"(?m)^on:\n  workflow_dispatch: \{\}$", workflow)
    assert "inputs:" not in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert (
        "concurrency:\n"
        "  group: publication-day1b-pre-s1-preparatory\n"
        "  cancel-in-progress: false\n" in workflow
    )
    assert "permissions:\n  contents: read\n" in workflow


def test_day1b_preparatory_workflow_uses_exact_pinned_runtime_and_lock() -> None:
    workflow = _workflow()

    assert workflow.count("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683") == 1
    assert workflow.count("actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065") == 1
    assert workflow.count("python-version: '3.12.13'") == 1
    assert (
        workflow.count(".venv/bin/python -m pip install --require-hashes -r requirements-ci.txt")
        == 1
    )
    assert (
        workflow.count(
            ".venv/bin/python -m pip install --require-hashes -r requirements-publication.txt"
        )
        == 1
    )
    assert "uv" not in workflow.lower()
    assert "actions/cache" not in workflow
    assert "pip install -e" not in workflow


def test_day1b_preparatory_workflow_only_validates_the_frozen_hold_contract() -> None:
    workflow = _workflow()
    lowered = workflow.lower()

    pytest_block = workflow[
        workflow.index(".venv/bin/python -m pytest -q") : workflow.index(
            ".venv/bin/python -m ruff check"
        )
    ]
    assert tuple(re.findall(r"tests/[a-z0-9_]+\.py", pytest_block)) == EXPECTED_TEST_PATHS
    assert workflow.count("scripts/run_publication_day1b.py") == 1
    assert ".venv/bin/python scripts/run_publication_day1b.py" not in workflow
    assert "actions/upload-artifact" not in workflow
    assert "actions/download-artifact" not in workflow
    for forbidden in (
        "--trace-bundle-dir",
        "--output-dir",
        "acquire_publication_sources",
        "prepare_publication_traces",
        "heldout",
        "dataset-id",
        "source-partition",
        "install anchor",
        "write anchor",
        "analyze_publication_results",
        "run_publication_analysis",
        "github.event.inputs",
        "github.repository_dispatch",
    ):
        assert forbidden not in lowered


def test_day1b_workflow_declares_pre_s1_preparatory_hold_without_artifact_steps() -> None:
    workflow = _workflow()

    assert "PRE-S1 preparatory validation only" in workflow
    assert "PENDING-FREEZE" in workflow
    assert "generic OpenFHE query runtime passed a non-authorizing smoke" in workflow
    assert "production Day1B candidate worker and admission receipt remain absent" in workflow
    assert "No publication execution or artifact production is permitted" in workflow
    assert "upload" not in workflow.lower()


def test_preregistration_and_roadmap_keep_preparatory_inventory_non_authorizing() -> None:
    preregistration = (ROOT / "docs/paper/publication-preregistration-draft.md").read_text(
        encoding="utf-8"
    )
    roadmap = (ROOT / "docs/paper/publication-roadmap.md").read_text(encoding="utf-8")
    combined = preregistration + roadmap

    for required in (
        "dynamic-cssc-day1b-preparatory-behavior-set-v8",
        "publication-day1b-preparatory.yml",
        "Source inventory is not dispatch authority",
        "controlled-scratch high-water",
        "candidate-cell worker",
        "single-use ordinary-query authorization",
        "TRACE post-run anchor",
        "Day-1 registration anchor",
        "Behavior Set version bump",
        "sole numeric exception",
    ):
        assert required in combined
    assert "> **Status date:** 2026-08-24 (Asia/Shanghai)" in roadmap
