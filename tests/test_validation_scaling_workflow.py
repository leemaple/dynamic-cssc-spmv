from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/validation-scaling-study.yml"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
STAGE0_TAG = "validation-scaling-stage0-v2"
ALLOWED_PATHS = {
    ".github/workflows/validation-scaling-study.yml",
    "docs/reviews/validation-scaling-stage1-review.md",
    "schemas/validation-scaling-evidence-v1.schema.json",
    "scripts/run_validation_scaling_study.py",
    "scripts/validate_validation_scaling_study.py",
    "src/dynamic_cssc/validation_scaling_study.py",
    "tests/test_validation_scaling_study.py",
    "tests/test_validation_scaling_workflow.py",
}
STAGE0_OBJECTS = (
    "config/validation-scaling-study.json",
    "docs/paper/validation-scaling-claim-ledger.md",
    "docs/paper/validation-scaling-preregistration.md",
    "schemas/validation-scaling-study-v2.schema.json",
    "config/validation-scaling-stage0-manifest.json",
)


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=REPOSITORY_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def test_workflow_exposes_only_one_manual_trigger() -> None:
    trigger_block = WORKFLOW.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger_block
    assert "push:" not in trigger_block
    assert "pull_request:" not in trigger_block
    assert "schedule:" not in trigger_block


def test_workflow_has_exact_three_by_three_by_one_job_topology() -> None:
    jobs = WORKFLOW.split("jobs:\n", 1)[1]
    job_ids = re.findall(r"^  ([a-z][a-z0-9_-]*):$", jobs, flags=re.MULTILINE)
    assert job_ids == ["producer", "replay", "aggregate"]
    assert WORKFLOW.count("seed_ordinal: [1, 2, 3]") == 2
    assert WORKFLOW.count("name: producer-seed-${{ matrix.seed_ordinal }}") == 1
    assert WORKFLOW.count("name: replay-seed-${{ matrix.seed_ordinal }}") == 1
    assert WORKFLOW.count("name: aggregate") == 1
    assert WORKFLOW.count("needs: producer") == 1
    assert WORKFLOW.count("needs: replay") == 1


def test_workflow_freezes_runner_timeouts_environment_and_python() -> None:
    assert WORKFLOW.count("runs-on: ubuntu-24.04") == 3
    assert WORKFLOW.count("timeout-minutes: 40") == 2
    assert WORKFLOW.count("timeout-minutes: 20") == 1
    assert WORKFLOW.count("python-version: '3.12.13'") == 3
    assert WORKFLOW.count("python -m pip install --require-hashes -r requirements-ci.txt") == 3
    for name, value in {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "PYTHONHASHSEED": "0",
    }.items():
        assert WORKFLOW.count(f"{name}: '{value}'") == 1


def test_workflow_uses_only_exactly_pinned_actions() -> None:
    assert WORKFLOW.count(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    ) == 3
    assert WORKFLOW.count(
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
    ) == 3
    assert WORKFLOW.count(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ) == 3
    assert WORKFLOW.count(
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    ) == 7
    assert not re.search(r"uses:\s+[^\s]+@v[0-9]", WORKFLOW)
    assert WORKFLOW.count("persist-credentials: false") == 3


def test_workflow_freezes_seven_artifact_names_and_retention_classes() -> None:
    assert WORKFLOW.count(
        "name: validation-scaling-producer-seed-${{ matrix.seed_ordinal }}-v1"
    ) == 2
    assert WORKFLOW.count(
        "name: validation-scaling-replay-seed-${{ matrix.seed_ordinal }}-v1"
    ) == 1
    for ordinal in (1, 2, 3):
        assert WORKFLOW.count(f"name: validation-scaling-producer-seed-{ordinal}-v1") == 1
        assert WORKFLOW.count(f"name: validation-scaling-replay-seed-{ordinal}-v1") == 1
    assert WORKFLOW.count("name: validation-scaling-aggregate-v1") == 1
    assert WORKFLOW.count("retention-days: 1") == 1
    assert WORKFLOW.count("retention-days: 90") == 2
    assert WORKFLOW.count("if-no-files-found: error") == 3


def test_workflow_has_no_retry_fallback_or_partial_reporting_surface() -> None:
    forbidden = (
        "continue-on-error",
        "cancel-in-progress",
        "fail-fast: false",
        "rerun",
        "retry",
        "fallback",
        "allow-partial",
    )
    for token in forbidden:
        assert token not in WORKFLOW.lower()
    assert WORKFLOW.count("GITHUB_RUN_ATTEMPT\" = 1") == 3
    assert WORKFLOW.count("formal run inventory is not exactly one") == 0


def test_workflow_checks_exact_tags_stage0_bytes_and_source_whitelist() -> None:
    assert WORKFLOW.count("ref: validation-scaling-source-v2") == 3
    assert WORKFLOW.count(
        "git cat-file -t refs/tags/validation-scaling-source-v2"
    ) == 3
    assert WORKFLOW.count(
        "git cat-file -t refs/tags/validation-scaling-stage0-v2"
    ) == 3
    assert WORKFLOW.count(
        "git diff --name-only refs/tags/validation-scaling-stage0-v2^{} HEAD"
    ) == 3
    for path in STAGE0_OBJECTS:
        assert WORKFLOW.count(path) >= 3
    for path in ALLOWED_PATHS:
        assert WORKFLOW.count(path) >= 3


def test_stage0_objects_remain_byte_identical() -> None:
    for path in STAGE0_OBJECTS:
        expected = _git("show", f"{STAGE0_TAG}^{{}}:{path}")
        assert (REPOSITORY_ROOT / path).read_bytes() == expected


def test_every_current_change_is_in_the_eight_path_whitelist() -> None:
    committed = {
        line
        for line in _git("diff", "--name-only", f"{STAGE0_TAG}^{{}}", "HEAD")
        .decode("utf-8")
        .splitlines()
        if line
    }
    working = {
        line[3:]
        for line in _git("status", "--short").decode("utf-8").splitlines()
        if line
    }
    assert committed | working <= ALLOWED_PATHS


def test_registered_seed_literals_remain_inside_stage0_objects_only() -> None:
    plan = json.loads(
        (REPOSITORY_ROOT / "config/validation-scaling-study.json").read_text(
            encoding="utf-8"
        )
    )
    seeds = [record["seed"] for record in plan["matrix"]["formal_seeds"]]
    seeds.append(plan["matrix"]["query_vector_seed"])
    allowed = set(STAGE0_OBJECTS[:4])
    suffixes = {".py", ".json", ".md", ".yml", ".yaml", ".toml", ".txt"}
    for seed in seeds:
        locations: set[str] = set()
        for path in REPOSITORY_ROOT.rglob("*"):
            if (
                not path.is_file()
                or path.suffix not in suffixes
                or ".git" in path.parts
                or "__pycache__" in path.parts
            ):
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if str(seed) in content:
                locations.add(path.relative_to(REPOSITORY_ROOT).as_posix())
        assert locations <= allowed


def test_evidence_schema_field_inventories_equal_the_stage0_plan() -> None:
    plan = json.loads(
        (REPOSITORY_ROOT / "config/validation-scaling-study.json").read_text(
            encoding="utf-8"
        )
    )
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas/validation-scaling-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["$defs"]["cellRow"]["required"] == plan["measurements"]["cell_fields"]
    assert schema["$defs"]["executionReceipt"]["required"] == plan["measurements"][
        "seed_execution_receipt_fields"
    ]
    assert schema["$defs"]["providerObservation"]["required"] == plan["measurements"][
        "provider_dependency_job_fields"
    ]
