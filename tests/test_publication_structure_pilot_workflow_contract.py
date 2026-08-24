from __future__ import annotations

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/publication-structure-pilot.yml"


def _workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_structure_pilot_workflow_is_manual_with_no_caller_inputs() -> None:
    workflow = _workflow()

    assert re.search(r"(?m)^on:\n  workflow_dispatch: \{\}$", workflow)
    assert "inputs:" not in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow


def test_structure_pilot_runs_one_fixed_job_against_external_corpus_mounts() -> None:
    workflow = _workflow()

    assert (
        "concurrency:\n"
        "  group: publication-structure-pilot\n"
        "  cancel-in-progress: false\n" in workflow
    )
    assert workflow.count("runs-on: [self-hosted, linux, x64, publication-corpus]") == 1
    assert (
        "PUBLICATION_ACQUISITION_BUNDLE_ROOT: "
        "/mnt/dynamic-cssc-publication-corpus/acquisition-bundles"
    ) in workflow
    assert (
        "PUBLICATION_STRUCTURE_PILOT_OUTPUT_PARENT: /mnt/dynamic-cssc-publication-pilot-output"
    ) in workflow
    assert (
        "PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT: /mnt/dynamic-cssc-publication-pilot-scratch"
    ) in workflow
    assert workflow.count("scripts/run_publication_structure_pilot.py") == 1
    assert workflow.count('--acquisition-bundle-root "$PUBLICATION_ACQUISITION_BUNDLE_ROOT"') == 1
    assert workflow.count('--output-dir "$PUBLICATION_STRUCTURE_PILOT_OUTPUT_DIR"') == 1
    run_step = workflow[
        workflow.index("- name: Run the fixed outcome-blind structure pilot") : workflow.index(
            "- name: Guard the exact structure-pilot output tree"
        )
    ]
    assert (
        run_step.count("\n          TMPDIR: ${{ env.PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT }}")
        == 1
    )
    assert (
        run_step.count(
            "\n          SQLITE_TMPDIR: ${{ env.PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT }}"
        )
        == 1
    )
    assert "--scratch" not in workflow


def test_workflow_installs_only_the_frozen_publication_runtime_lock() -> None:
    workflow = _workflow()

    install = ".venv/bin/python -m pip install --require-hashes -r requirements-publication.txt"
    assert workflow.count(install) == 1
    assert "requirements-ci.txt" not in workflow
    assert "uv.lock" not in workflow
    assert "pip install -e" not in workflow


def test_workflow_uploads_only_a_successful_nonadmissible_pilot_tree() -> None:
    workflow = _workflow()
    run_index = workflow.index("scripts/run_publication_structure_pilot.py")
    guard_index = workflow.index("Guard the exact structure-pilot output tree")
    upload_index = workflow.index("uses: actions/upload-artifact@v4")

    assert run_index < guard_index < upload_index
    assert "{'checksums.sha256', 'structure-pilot-report.json'}" in workflow
    assert "assert actual_names == expected_names" in workflow
    assert "path.is_file() and not path.is_symlink()" in workflow
    assert "sha256sum --check --strict checksums.sha256" in workflow
    assert workflow.count("uses: actions/upload-artifact@v4") == 1
    assert "if: ${{ success() }}" in workflow[run_index : upload_index + 200]
    assert (
        "name: NONADMISSIBLE-structure-pilot-${{ github.run_id }}-"
        "${{ github.run_attempt }}" in workflow
    )
    assert (
        "path: ${{ env.PUBLICATION_STRUCTURE_PILOT_OUTPUT_PARENT }}/"
        "NONADMISSIBLE-structure-pilot-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    )
    assert "if-no-files-found: error" in workflow
    assert "if: always()" not in workflow
    assert "if: ${{ failure() }}" not in workflow


def test_embedded_output_guard_is_syntax_valid() -> None:
    workflow = _workflow()
    blocks = re.findall(
        r"(?ms)^ {10}\.venv/bin/python - <<'PY'\n(.*?)^ {10}PY$",
        workflow,
    )

    assert len(blocks) == 1
    compile(textwrap.dedent(blocks[0]), "structure-pilot-output-guard.py", "exec")


def test_workflow_cannot_enter_acquisition_heldout_or_evidence_paths() -> None:
    workflow = _workflow().lower()

    for forbidden in (
        "download",
        "schedule",
        "cron",
        "acquire_publication_sources.py",
        "prepare_publication_traces.py",
        "day1b",
        "evidence",
        "analyze_publication_results.py",
        "candidate",
        "--dataset-id",
        "--semantics",
        "--source-partition",
        "--rho",
        "--freshness-seconds",
        "--seed",
        "--source-sha",
        "--authority",
        "--retry",
    ):
        assert forbidden not in workflow
