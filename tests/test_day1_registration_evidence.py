from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from inspect import signature
from pathlib import Path

import pytest

from dynamic_cssc.day1_registration_evidence import (
    Day1RegistrationEvidenceError,
    Day1RegistrationEvidenceHold,
    inspect_day1_registration_evidence_archive,
    produce_day1_registration_evidence_archive,
)
from dynamic_cssc.evidence_compatibility import (
    DAY1_REGISTRATION_ANCHOR_PATH,
    STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
    EvidenceRole,
    repository_behavior_paths,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEDICATED_WORKFLOW_PATH = ".github/workflows/day1-registration-evidence.yml"
PRODUCER_BEHAVIOR_PATHS = (
    "scripts/produce_day1_registration_evidence.py",
    "src/dynamic_cssc/day1_registration_evidence.py",
    "tests/test_day1_registration_evidence.py",
)
ARCHIVE_FILENAMES = {
    "SHA256SUMS",
    "accounting-evidence.json",
    "artifact-behavior-inventory.json",
    "day1-registration-evidence-manifest.json",
    "registration-evidence.json",
    "strong-correctness-identity.json",
    "workflow-provenance.json",
}
FIXED_CANDIDATE_IDS = (
    "padding-reuse",
    "mini-cssc-delta",
    "packed-coo-client-lane-delta/capacity=128",
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


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _integrated_clean_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "registration-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "registration-producer@example.invalid")
    _git(repository, "config", "user.name", "Registration Producer Test")
    (repository / ".gitignore").write_text("*.pyc\n__pycache__/\n", encoding="utf-8")
    paths = (
        *repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION),
        *PRODUCER_BEHAVIOR_PATHS,
        STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
        DAY1_REGISTRATION_ANCHOR_PATH,
    )
    for relative_path in dict.fromkeys(paths):
        source = REPOSITORY_ROOT / relative_path
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    # This fixture models the exact pre-S1 repository consumed by the
    # registration producer.  Reset the copied phase-transition state so the
    # fixture remains pre-S1 after the real repository installs an S2 anchor.
    (repository / DAY1_REGISTRATION_ANCHOR_PATH).write_bytes(
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        )
    )

    # The private archive fixture intentionally does not claim a historical-source
    # attestation. Keep its descriptive strong anchor readable while the central
    # hardened source-attestation migration is landing concurrently.
    strong_anchor_path = repository / STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH
    strong_anchor = json.loads(strong_anchor_path.read_bytes())
    strong_record = strong_anchor["anchors"][0]
    strong_record.setdefault(
        "source_behavior_set_schema_version",
        "dynamic-cssc-strong-correctness-behavior-set-v1",
    )
    strong_record.setdefault("source_behavior_set_sha256", "0" * 64)
    strong_anchor_path.write_bytes(_canonical(strong_anchor))
    historical_source_sha = strong_record["receipt"]["source_git_sha"]
    _git(
        repository,
        "fetch",
        "-q",
        str(REPOSITORY_ROOT),
        f"{historical_source_sha}:refs/tags/historical-strong-source",
    )

    central_path = repository / "src/dynamic_cssc/evidence_compatibility.py"
    central_source = central_path.read_text(encoding="utf-8")
    registration_start = central_source.index("_DAY1_REGISTRATION_BEHAVIOR_PATHS = (\n")
    registration_end = central_source.index(
        "\n)\n\n# This is deliberately a PRE-S1",
        registration_start,
    )
    registration_block = central_source[registration_start:registration_end]
    missing_paths = [
        path for path in PRODUCER_BEHAVIOR_PATHS if f'    "{path}",' not in registration_block
    ]
    if missing_paths:
        additions = "".join(f'    "{path}",\n' for path in missing_paths)
        central_path.write_text(
            central_source[:registration_end]
            + "\n"
            + additions
            + central_source[registration_end:],
            encoding="utf-8",
        )
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "integrated registration producer S1")
    return repository, _git(repository, "rev-parse", "HEAD")


def _producer_environment(source_sha: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.update(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "leemaple/dynamic-cssc-spmv",
            "GITHUB_REPOSITORY_ID": "1341939625",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "456789",
            "GITHUB_SHA": source_sha,
            "GITHUB_WORKFLOW_REF": (
                f"leemaple/dynamic-cssc-spmv/{DEDICATED_WORKFLOW_PATH}@refs/heads/main"
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _run_producer(
    repository: Path,
    source_sha: str,
    output_dir: Path,
    *,
    test_core: bool = False,
    prelude: str = "",
    environment_updates: dict[str, str | None] | None = None,
) -> subprocess.CompletedProcess[str]:
    producer_name = (
        "_produce_day1_registration_evidence_archive_for_test"
        if test_core
        else "produce_day1_registration_evidence_archive"
    )
    program = f"""
import json
import sys
from pathlib import Path
sys.path.insert(0, {str(repository / "src")!r})
from dynamic_cssc.day1_registration_evidence import {producer_name}
{prelude}
try:
    archive = {producer_name}(Path({str(output_dir)!r}))
except Exception as error:
    print(f"{{type(error).__name__}}: {{error}}", file=sys.stderr)
    raise SystemExit(2)
print(json.dumps({{"manifest_sha256": archive.manifest_sha256}}, sort_keys=True))
"""
    environment = _producer_environment(source_sha)
    for name, value in (environment_updates or {}).items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return subprocess.run(
        (sys.executable, "-c", program),
        cwd=repository.parent,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _refresh_checksums(archive_dir: Path) -> None:
    names = sorted(ARCHIVE_FILENAMES - {"SHA256SUMS"})
    checksums = "".join(
        f"{hashlib.sha256((archive_dir / name).read_bytes()).hexdigest()}  {name}\n"
        for name in names
    )
    (archive_dir / "SHA256SUMS").write_text(checksums, encoding="ascii")


def _refresh_archive_bindings(archive_dir: Path) -> None:
    workflow_bytes = (archive_dir / "workflow-provenance.json").read_bytes()
    accounting_path = archive_dir / "accounting-evidence.json"
    accounting = json.loads(accounting_path.read_bytes())
    accounting["workflow_provenance_sha256"] = hashlib.sha256(workflow_bytes).hexdigest()
    accounting_path.write_bytes(_canonical(accounting))

    registration_path = archive_dir / "registration-evidence.json"
    registration = json.loads(registration_path.read_bytes())
    registration["accounting_evidence_sha256"] = hashlib.sha256(
        accounting_path.read_bytes()
    ).hexdigest()
    registration_path.write_bytes(_canonical(registration))

    manifest_path = archive_dir / "day1-registration-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for file_record in manifest["files"]:
        member = archive_dir / file_record["path"]
        file_record["bytes"] = len(member.read_bytes())
        file_record["sha256"] = hashlib.sha256(member.read_bytes()).hexdigest()
    registration_sha256 = hashlib.sha256(registration_path.read_bytes()).hexdigest()
    manifest["registration_evidence_sha256"] = registration_sha256
    required = manifest["future_repository_anchor_projection"]["required_fields"]
    required["artifact_sha256"] = registration_sha256
    required["registration_evidence"] = registration
    manifest_path.write_bytes(_canonical(manifest))
    _refresh_checksums(archive_dir)


def test_public_interfaces_are_path_only_and_missing_observed_context_holds_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(signature(produce_day1_registration_evidence_archive).parameters) == (
        "output_dir",
    )
    assert tuple(signature(inspect_day1_registration_evidence_archive).parameters) == (
        "archive_dir",
    )
    output_dir = tmp_path / "registration-evidence"
    for name in tuple(os.environ):
        if name.startswith("GITHUB_"):
            monkeypatch.delenv(name, raising=False)

    with pytest.raises(
        (Day1RegistrationEvidenceHold, Day1RegistrationEvidenceError),
        match=(
            "Behavior Set|source attestation|registration run identity|"
            "observed GitHub Actions environment"
        ),
    ):
        produce_day1_registration_evidence_archive(output_dir)

    assert not output_dir.exists()


def test_cli_exposes_only_output_dir_and_rejects_run_or_identity_injection(
    tmp_path: Path,
) -> None:
    script = REPOSITORY_ROOT / "scripts/produce_day1_registration_evidence.py"
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GITHUB_")
    }
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    output_dir = tmp_path / "registration-evidence"

    held = subprocess.run(
        (sys.executable, str(script), "--output-dir", str(output_dir)),
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    injected = subprocess.run(
        (
            sys.executable,
            str(script),
            "--output-dir",
            str(output_dir),
            "--run-id",
            "456789",
        ),
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert held.returncode == 2
    assert held.stdout == ""
    assert injected.returncode == 2
    assert "unrecognized arguments: --run-id" in injected.stderr
    assert not output_dir.exists()


def test_cli_produces_the_same_closed_descriptive_variant_from_exact_context(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    environment = _producer_environment(source_sha)
    environment["PYTHONPATH"] = str(repository / "src")

    completed = subprocess.run(
        (
            sys.executable,
            str(repository / "scripts/produce_day1_registration_evidence.py"),
            "--output-dir",
            str(output_dir),
        ),
        cwd=repository.parent,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["schema_version"] == ("dynamic-cssc-day1-registration-evidence-cli-receipt-v1")
    assert receipt["archive_dir"] == str(output_dir.resolve())
    assert len(receipt["manifest_sha256"]) == 64
    assert len(receipt["registration_evidence_sha256"]) == 64
    workflow = json.loads((output_dir / "workflow-provenance.json").read_bytes())
    assert workflow["run_identity_authority_state"] == (
        "descriptive-github-actions-environment-claims-only"
    )
    assert workflow["provider_receipt_verified"] is False


def test_clean_integrated_s1_produces_a_closed_observed_environment_archive(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir)

    assert completed.returncode == 0, completed.stderr
    assert {path.name for path in output_dir.iterdir()} == ARCHIVE_FILENAMES
    manifest = json.loads((output_dir / "day1-registration-evidence-manifest.json").read_bytes())
    strong = json.loads((output_dir / "strong-correctness-identity.json").read_bytes())
    workflow = json.loads((output_dir / "workflow-provenance.json").read_bytes())

    assert workflow == {
        "dedicated_registration_workflow_path": DEDICATED_WORKFLOW_PATH,
        "descriptive_day1_workflow_path": ".github/workflows/day1-cost-model.yml",
        "event_name": "workflow_dispatch",
        "experiment_source_git_sha": source_sha,
        "experiment_source_tree_git_sha": _git(repository, "rev-parse", "HEAD^{tree}"),
        "formal_authority_granted": False,
        "head_sha": source_sha,
        "production_eligible": False,
        "provider_receipt_verified": False,
        "ref": "refs/heads/main",
        "repository": "leemaple/dynamic-cssc-spmv",
        "repository_id": 1341939625,
        "run_attempt": 1,
        "run_id": 456789,
        "run_identity_authority_state": ("descriptive-github-actions-environment-claims-only"),
        "schema_version": "dynamic-cssc-day1-registration-run-provenance-v2",
        "workflow_file_sha256": hashlib.sha256(
            (repository / DEDICATED_WORKFLOW_PATH).read_bytes()
        ).hexdigest(),
        "workflow_path": DEDICATED_WORKFLOW_PATH,
        "workflow_ref": (f"leemaple/dynamic-cssc-spmv/{DEDICATED_WORKFLOW_PATH}@refs/heads/main"),
    }
    assert manifest["authority"] == {
        "candidate_registration_allowed": False,
        "catalog_authority_minted": False,
        "complete_reference_set": False,
        "formal_authority_granted": False,
        "repository_anchor_installed": False,
        "review_required_before_s2_anchor": True,
    }
    assert strong["source_attestation"] == {
        "authority_state": "historical-source-git-object-attested-descriptive",
        "schema_version": "dynamic-cssc-strong-source-attestation-status-v1",
        "verified": True,
    }
    assert "repository_worktree_stable_through_install" not in workflow
    assert "repository_worktree_stable_through_install" not in manifest
    assert not (output_dir / DAY1_REGISTRATION_ANCHOR_PATH).exists()


@pytest.mark.parametrize(
    "environment_updates",
    (
        {"GITHUB_ACTIONS": None},
        {"GITHUB_EVENT_NAME": "push"},
        {"GITHUB_REF": "refs/heads/not-main"},
        {"GITHUB_REPOSITORY": "attacker/dynamic-cssc-spmv"},
        {"GITHUB_REPOSITORY_ID": "123456"},
        {"GITHUB_RUN_ATTEMPT": "0"},
        {"GITHUB_RUN_ID": "0456789"},
        {"GITHUB_SHA": "f" * 40},
        {
            "GITHUB_WORKFLOW_REF": (
                "leemaple/dynamic-cssc-spmv/.github/workflows/day1-cost-model.yml@refs/heads/main"
            )
        },
    ),
)
def test_observed_workflow_context_mismatch_holds_before_writing(
    tmp_path: Path,
    environment_updates: dict[str, str | None],
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        environment_updates=environment_updates,
    )

    assert completed.returncode == 2
    assert "HOLD" in completed.stderr
    assert not output_dir.exists()
    assert not list(tmp_path.glob(".*registration-evidence*stage-*"))


@pytest.mark.parametrize("drift", ("missing", "mode", "blob"))
def test_dedicated_workflow_drift_holds_before_writing(
    tmp_path: Path,
    drift: str,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    workflow_path = repository / DEDICATED_WORKFLOW_PATH
    if drift == "missing":
        workflow_path.unlink()
    elif drift == "mode":
        workflow_path.chmod(0o755)
    else:
        with workflow_path.open("a", encoding="utf-8") as handle:
            handle.write("\n# drift\n")
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir)

    assert completed.returncode == 2
    assert "HOLD" in completed.stderr or "source attestation" in completed.stderr
    assert not output_dir.exists()


def test_clean_s1_still_rejects_an_executable_dedicated_workflow(tmp_path: Path) -> None:
    repository, _source_sha = _integrated_clean_repository(tmp_path)
    workflow_path = repository / DEDICATED_WORKFLOW_PATH
    workflow_path.chmod(0o755)
    _git(repository, "add", DEDICATED_WORKFLOW_PATH)
    _git(repository, "commit", "-qm", "invalid executable workflow mode")
    source_sha = _git(repository, "rev-parse", "HEAD")
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir)

    assert completed.returncode == 2
    assert "workflow" in completed.stderr
    assert "100644" in completed.stderr
    assert not output_dir.exists()


def test_dedicated_workflow_is_manual_pinned_non_dispatching_and_descriptive() -> None:
    workflow_path = REPOSITORY_ROOT / DEDICATED_WORKFLOW_PATH
    workflow = workflow_path.read_text(encoding="utf-8")

    assert workflow_path.stat().st_mode & 0o777 == 0o644
    assert "workflow_dispatch: {}" in workflow
    assert "inputs:" not in workflow
    assert "contents: read" in workflow
    assert "concurrency:" in workflow
    assert "cancel-in-progress: false" in workflow
    pins = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s]+)$", workflow, flags=re.MULTILINE)
    assert len(pins) == 3
    assert all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in pins)
    assert "ref: ${{ github.sha }}" in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert "python-version: '3.12.13'" in workflow
    assert "pip install --require-hashes -r requirements-ci.txt" in workflow
    assert "actions/cache" not in workflow
    assert re.search(r"\buv\b", workflow) is None
    assert "config/day1-registration-anchors.json" not in workflow
    assert "git push" not in workflow
    assert "repository_dispatch" not in workflow
    assert "workflow_call" not in workflow
    assert "schedule:" not in workflow
    assert "ARCHIVE_DIR: ${{ runner.temp }}/day1-registration-evidence" in workflow
    assert workflow.index("Reinspect the closed archive in a second process") < workflow.index(
        "Upload only the descriptive review input"
    )
    day1_registration_paths = set(repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION))
    assert DEDICATED_WORKFLOW_PATH in day1_registration_paths
    assert "src/dynamic_cssc/publication_artifact_install.py" in day1_registration_paths


def test_production_archive_never_installs_anchor_and_catalog_remains_on_hold(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    anchor_path = repository / DAY1_REGISTRATION_ANCHOR_PATH
    empty_anchor = (
        b'{"anchors":[],"schema_version":"dynamic-cssc-day1-registration-anchor-set-v1"}\n'
    )
    assert anchor_path.read_bytes() == empty_anchor
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir)

    assert completed.returncode == 0, completed.stderr
    assert anchor_path.read_bytes() == empty_anchor
    catalog_program = f"""
import sys
sys.path.insert(0, {str(repository / "src")!r})
from dynamic_cssc.day1_registry import repository_day1_candidate_catalog
try:
    repository_day1_candidate_catalog()
except Exception as error:
    print(f"{{type(error).__name__}}: {{error}}", file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(0)
"""
    catalog = subprocess.run(
        (sys.executable, "-c", catalog_program),
        cwd=repository.parent,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )
    assert catalog.returncode == 2
    assert "no repository-approved Day-1 composite registration anchor" in catalog.stderr


def test_private_fixed_run_core_produces_a_closed_non_authoritative_anchor_projection(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir, test_core=True)

    assert completed.returncode == 0, completed.stderr
    assert {path.name for path in output_dir.iterdir()} == ARCHIVE_FILENAMES
    manifest_bytes = (output_dir / "day1-registration-evidence-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    registration_bytes = (output_dir / "registration-evidence.json").read_bytes()
    registration = json.loads(registration_bytes)
    accounting = json.loads((output_dir / "accounting-evidence.json").read_bytes())
    inventory = json.loads((output_dir / "artifact-behavior-inventory.json").read_bytes())
    strong = json.loads((output_dir / "strong-correctness-identity.json").read_bytes())
    workflow = json.loads((output_dir / "workflow-provenance.json").read_bytes())

    assert manifest_bytes == _canonical(manifest)
    assert registration_bytes == _canonical(registration)
    assert manifest["experiment_source_git_sha"] == source_sha
    assert len(manifest["experiment_source_tree_git_sha"]) == 40
    assert (
        manifest["artifact_behavior_inventory_sha256"]
        == hashlib.sha256(_canonical(inventory)).hexdigest()
    )
    assert registration == {
        "accounting_evidence_sha256": hashlib.sha256(_canonical(accounting)).hexdigest(),
        "correctness_artifact_sha256": (
            "c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe"
        ),
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
        "run_id": 456789,
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": source_sha,
    }
    assert accounting["candidate_roster"]["fixed_candidate_ids"] == list(FIXED_CANDIDATE_IDS)
    assert accounting["candidate_roster"]["fixed_candidate_count"] == 14
    assert accounting["candidate_roster"]["reference_candidate_count"] == 13
    assert accounting["candidate_roster"]["ablation_candidate_count"] == 1
    assert accounting["report_contract"]["causal_schema"] == "day1-causal-predicted-v2"
    assert accounting["report_contract"]["completion_proof_schema"] == (
        "day1-causal-completion-proof-v1"
    )
    assert accounting["report_contract"]["accounting_invariants"] == [
        "metadata_units=ci_patch_entries+ci_full_sync_entries",
        "update_encryptions=update_ciphertexts+compaction_ciphertexts",
        "query_ciphertexts=cc_multiplications=relinearizations",
        "result_ciphertexts=decryptions",
        "blinding_encryptions=blinding_mask_ciphertexts+blinding_dummy_ciphertexts",
        "blinding_additions=blinding_encryptions",
        "rotations=sum(measured_counts_by_exact_index)",
    ]
    assert {binding["path"] for binding in accounting["validation_source_bindings"]} >= {
        "scripts/aggregate_day1_shards.py",
        "src/dynamic_cssc/day1a_export.py",
        "src/dynamic_cssc/report.py",
        "src/dynamic_cssc/simulator.py",
        "tests/test_day1_registry.py",
        "tests/test_day1_shard_aggregation.py",
        "tests/test_day1_workflow_contract.py",
        "tests/test_query_accounting.py",
        "tests/test_report.py",
        "tests/test_strong_day1_simulator.py",
    }
    assert strong["projection"]["authority_state"] == "historical-descriptive-only"
    assert strong["projection"]["formal_authority_granted"] is False
    assert workflow["run_id"] == 456789
    assert workflow["run_identity_authority_state"] == ("private-fixed-test-fixture-non-production")
    assert workflow["production_eligible"] is False
    assert manifest["authority"] == {
        "candidate_registration_allowed": False,
        "catalog_authority_minted": False,
        "complete_reference_set": False,
        "formal_authority_granted": False,
        "repository_anchor_installed": False,
        "review_required_before_s2_anchor": True,
    }
    projection = manifest["future_repository_anchor_projection"]
    assert (
        projection["required_fields"]["artifact_sha256"]
        == hashlib.sha256(registration_bytes).hexdigest()
    )
    assert projection["required_fields"]["registration_evidence"] == registration
    assert projection["formal_authority_granted"] is False
    assert projection["repository_anchor_installed"] is False
    assert not (output_dir / DAY1_REGISTRATION_ANCHOR_PATH).exists()

    inspection = inspect_day1_registration_evidence_archive(output_dir)
    assert inspection.registration_evidence_sha256 == hashlib.sha256(registration_bytes).hexdigest()
    assert inspection.formal_authority_granted is False


def test_private_fixture_producer_holds_outside_pytest_context(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        test_core=True,
        environment_updates={"PYTEST_CURRENT_TEST": None},
    )

    assert completed.returncode == 2
    assert "private fixed fixture" in completed.stderr
    assert not output_dir.exists()


def test_caller_cannot_inject_roster_source_strong_identity_run_or_authority(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "registration-evidence"
    forbidden = (
        {"candidate_ids": FIXED_CANDIDATE_IDS},
        {"source_git_sha": "a" * 40},
        {"correctness_artifact_sha256": "b" * 64},
        {"run_id": 456789},
        {"formal_authority_granted": True},
        {"receipt": object()},
    )
    for injected in forbidden:
        with pytest.raises(TypeError):
            produce_day1_registration_evidence_archive(output_dir, **injected)  # type: ignore[call-arg]


def test_observed_context_is_exact_non_boolean_and_single_use() -> None:
    import dynamic_cssc.day1_registration_evidence as producer_module

    context = producer_module._observed_run_context_from_document(
        {
            "event_name": "workflow_dispatch",
            "formal_authority_granted": False,
            "head_sha": "a" * 40,
            "provider_receipt_verified": False,
            "ref": "refs/heads/main",
            "repository": "leemaple/dynamic-cssc-spmv",
            "repository_id": 1341939625,
            "run_attempt": 1,
            "run_id": 456789,
            "run_identity_authority_state": ("descriptive-github-actions-environment-claims-only"),
            "workflow_file_sha256": "b" * 64,
            "workflow_path": DEDICATED_WORKFLOW_PATH,
            "workflow_ref": (
                f"leemaple/dynamic-cssc-spmv/{DEDICATED_WORKFLOW_PATH}@refs/heads/main"
            ),
        }
    )

    with pytest.raises(TypeError, match="not an authority Boolean"):
        bool(context)
    assert context.consume()["run_id"] == 456789
    with pytest.raises(Day1RegistrationEvidenceHold, match="cannot be replayed"):
        context.consume()
    replay = producer_module._observed_run_context_from_document(context.document())
    with pytest.raises(Day1RegistrationEvidenceHold, match="cannot be replayed"):
        replay.consume()


def test_dirty_s1_fails_before_any_archive_member_is_written(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    with (repository / "src/dynamic_cssc/report.py").open("a", encoding="utf-8") as handle:
        handle.write("\n# uncommitted attack\n")

    completed = _run_producer(repository, source_sha, output_dir, test_core=True)

    assert completed.returncode == 2
    assert "stable fully clean" in completed.stderr
    assert not output_dir.exists()
    assert not list(tmp_path.glob(".registration-evidence.day1-registration-*"))


def test_process_environment_cannot_retarget_archive_to_an_old_source(tmp_path: Path) -> None:
    repository, old_source_sha = _integrated_clean_repository(tmp_path)
    (repository / ".gitignore").write_text(
        "*.pyc\n__pycache__/\n.test-source-advance\n",
        encoding="utf-8",
    )
    _git(repository, "add", ".gitignore")
    _git(repository, "commit", "-qm", "advance clean source")
    actual_source_sha = _git(repository, "rev-parse", "HEAD")
    assert actual_source_sha != old_source_sha
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(
        repository,
        old_source_sha,
        output_dir,
        test_core=True,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output_dir / "day1-registration-evidence-manifest.json").read_bytes())
    assert manifest["experiment_source_git_sha"] == actual_source_sha
    assert manifest["experiment_source_git_sha"] != old_source_sha


def test_inline_dependency_monkeypatch_cannot_replace_isolated_repository_facts(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    prelude = """
import dynamic_cssc.day1_registration_evidence as producer_module
producer_module._isolated_repository_facts_document = lambda: {
    'experiment_source_git_sha': 'a' * 40,
    'strong_projection': {'artifact_sha256': 'b' * 64},
}
"""

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        prelude=prelude,
    )

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads((output_dir / "day1-registration-evidence-manifest.json").read_bytes())
    assert manifest["experiment_source_git_sha"] == source_sha
    assert manifest["experiment_source_git_sha"] != "a" * 40


def test_inspector_rejects_missing_extra_symlink_and_unrehash_tamper(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    original = tmp_path / "registration-evidence"
    completed = _run_producer(repository, source_sha, original, test_core=True)
    assert completed.returncode == 0, completed.stderr

    missing = tmp_path / "missing"
    shutil.copytree(original, missing)
    (missing / "workflow-provenance.json").unlink()
    with pytest.raises(ValueError, match="member names"):
        inspect_day1_registration_evidence_archive(missing)

    extra = tmp_path / "extra"
    shutil.copytree(original, extra)
    (extra / "self-minted-anchor.json").write_text("{}\n", encoding="ascii")
    with pytest.raises(ValueError, match="member names"):
        inspect_day1_registration_evidence_archive(extra)

    symlinked = tmp_path / "symlinked"
    shutil.copytree(original, symlinked)
    (symlinked / "registration-evidence.json").unlink()
    (symlinked / "registration-evidence.json").symlink_to(original / "registration-evidence.json")
    with pytest.raises(ValueError, match="descriptor-bound verification"):
        inspect_day1_registration_evidence_archive(symlinked)

    tampered = tmp_path / "tampered"
    shutil.copytree(original, tampered)
    registration = json.loads((tampered / "registration-evidence.json").read_bytes())
    registration["run_id"] += 1
    (tampered / "registration-evidence.json").write_bytes(_canonical(registration))
    with pytest.raises(ValueError, match="SHA256SUMS"):
        inspect_day1_registration_evidence_archive(tampered)


@pytest.mark.parametrize("mutation", ("add-member", "replace-member", "replace-root"))
def test_existing_archive_view_rejects_tree_changes_during_semantic_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    import dynamic_cssc.day1_registration_evidence as producer_module

    repository, source_sha = _integrated_clean_repository(tmp_path)
    archive_dir = tmp_path / "registration-evidence"
    completed = _run_producer(repository, source_sha, archive_dir, test_core=True)
    assert completed.returncode == 0, completed.stderr
    original_validate = producer_module._validate_manifest

    def mutate_during_validation(*args: object, **kwargs: object) -> tuple[str, str]:
        if mutation == "add-member":
            (archive_dir / "late-extra.txt").write_text("late\n", encoding="ascii")
        elif mutation == "replace-member":
            member = archive_dir / "workflow-provenance.json"
            content = member.read_bytes()
            member.unlink()
            member.write_bytes(content)
        else:
            displaced = tmp_path / "displaced-registration-evidence"
            archive_dir.rename(displaced)
            shutil.copytree(displaced, archive_dir)
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(producer_module, "_validate_manifest", mutate_during_validation)

    with pytest.raises(ValueError, match="descriptor-bound verification"):
        inspect_day1_registration_evidence_archive(archive_dir)


def test_rehashed_self_minted_authority_is_rejected_semantically(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    original = tmp_path / "registration-evidence"
    completed = _run_producer(repository, source_sha, original, test_core=True)
    assert completed.returncode == 0, completed.stderr

    output_dir = tmp_path / "self-minted"
    shutil.copytree(original, output_dir)
    manifest_path = output_dir / "day1-registration-evidence-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["authority"]["catalog_authority_minted"] = True
    manifest["future_repository_anchor_projection"]["formal_authority_granted"] = True
    manifest["future_repository_anchor_projection"]["repository_anchor_installed"] = True
    manifest_path.write_bytes(_canonical(manifest))
    _refresh_checksums(output_dir)

    with pytest.raises(ValueError, match="must be exact false"):
        inspect_day1_registration_evidence_archive(output_dir)

    retargeted = tmp_path / "strong-retargeted"
    shutil.copytree(original, retargeted)
    strong_path = retargeted / "strong-correctness-identity.json"
    registration_path = retargeted / "registration-evidence.json"
    retargeted_manifest_path = retargeted / "day1-registration-evidence-manifest.json"
    strong = json.loads(strong_path.read_bytes())
    registration = json.loads(registration_path.read_bytes())
    retargeted_manifest = json.loads(retargeted_manifest_path.read_bytes())
    strong["projection"]["artifact_sha256"] = "f" * 64
    registration["correctness_artifact_sha256"] = "f" * 64
    strong_path.write_bytes(_canonical(strong))
    registration_path.write_bytes(_canonical(registration))
    for file_record in retargeted_manifest["files"]:
        member = retargeted / file_record["path"]
        file_record["bytes"] = len(member.read_bytes())
        file_record["sha256"] = hashlib.sha256(member.read_bytes()).hexdigest()
    registration_sha256 = hashlib.sha256(registration_path.read_bytes()).hexdigest()
    retargeted_manifest["registration_evidence_sha256"] = registration_sha256
    required = retargeted_manifest["future_repository_anchor_projection"]["required_fields"]
    required["artifact_sha256"] = registration_sha256
    required["registration_evidence"] = registration
    retargeted_manifest_path.write_bytes(_canonical(retargeted_manifest))
    _refresh_checksums(retargeted)

    with pytest.raises(ValueError, match="historical strong artifact identity"):
        inspect_day1_registration_evidence_archive(retargeted)


@pytest.mark.parametrize(
    ("field", "forged_value", "message"),
    (
        ("provider_receipt_verified", True, "must be exact false"),
        ("formal_authority_granted", True, "must be exact false"),
        ("production_eligible", True, "must be exact false"),
        ("run_identity_authority_state", "caller-minted-authority", "variant"),
    ),
)
def test_rehashed_workflow_authority_or_alias_is_never_admitted(
    tmp_path: Path,
    field: str,
    forged_value: object,
    message: str,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    original = tmp_path / "registration-evidence"
    completed = _run_producer(repository, source_sha, original)
    assert completed.returncode == 0, completed.stderr
    forged = tmp_path / f"forged-{field}"
    shutil.copytree(original, forged)
    workflow_path = forged / "workflow-provenance.json"
    workflow = json.loads(workflow_path.read_bytes())
    workflow[field] = forged_value
    workflow_path.write_bytes(_canonical(workflow))
    _refresh_archive_bindings(forged)

    with pytest.raises(ValueError, match=message):
        inspect_day1_registration_evidence_archive(forged)


def test_rehashed_workflow_sha_cannot_detach_from_the_behavior_source_binding(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    original = tmp_path / "registration-evidence"
    completed = _run_producer(repository, source_sha, original)
    assert completed.returncode == 0, completed.stderr
    forged = tmp_path / "forged-workflow-sha"
    shutil.copytree(original, forged)
    workflow_path = forged / "workflow-provenance.json"
    workflow = json.loads(workflow_path.read_bytes())
    workflow["workflow_file_sha256"] = "f" * 64
    workflow_path.write_bytes(_canonical(workflow))
    _refresh_archive_bindings(forged)

    with pytest.raises(ValueError, match="workflow source binding"):
        inspect_day1_registration_evidence_archive(forged)


def test_failed_shared_install_retains_the_whole_owned_staging_tree(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    prelude = """
import dynamic_cssc.day1_registration_evidence as producer_module
from dynamic_cssc.publication_artifact_install import PublicationArtifactInstallError
def fail_install(*args, **kwargs):
    raise PublicationArtifactInstallError('injected shared install failure')
producer_module.install_verified_directory = fail_install
"""

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        test_core=True,
        prelude=prelude,
    )

    assert completed.returncode == 2
    assert "installation failed closed" in completed.stderr
    assert not output_dir.exists()
    retained = list(tmp_path.glob(".*registration-evidence*retained-staging-*"))
    assert len(retained) == 1
    assert {path.name for path in retained[0].iterdir()} == ARCHIVE_FILENAMES


def test_write_failure_never_unlinks_a_foreign_same_name_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dynamic_cssc.day1_registration_evidence as producer_module

    target = tmp_path / "member.json"
    displaced = tmp_path / "member.json.owned-before-write-failure"
    real_fdopen = producer_module.os.fdopen

    class SwapThenFail:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self) -> SwapThenFail:
            self.handle.__enter__()  # type: ignore[attr-defined]
            return self

        def __exit__(self, *arguments: object) -> object:
            return self.handle.__exit__(*arguments)  # type: ignore[attr-defined]

        def write(self, content: bytes) -> int:
            target.rename(displaced)
            target.write_bytes(b"foreign-same-name-entry\n")
            raise OSError("injected descriptor write failure")

        def __getattr__(self, name: str) -> object:
            return getattr(self.handle, name)

    def attacking_fdopen(descriptor: int, *arguments: object, **keywords: object) -> object:
        return SwapThenFail(real_fdopen(descriptor, *arguments, **keywords))

    monkeypatch.setattr(producer_module.os, "fdopen", attacking_fdopen)

    with pytest.raises(OSError, match="injected descriptor write failure"):
        producer_module._write_file(target, b"owned transaction bytes\n")

    assert target.read_bytes() == b"foreign-same-name-entry\n"
    assert displaced.exists()


def test_shared_install_rejects_staging_root_substitution_without_losing_owned_tree(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    displaced = tmp_path / "displaced-owned-staging"
    prelude = f"""
import dynamic_cssc.day1_registration_evidence as producer_module
real_install = producer_module.install_verified_directory
def replace_staging_root(staging, output, **kwargs):
    staging.rename({str(displaced)!r})
    staging.mkdir()
    return real_install(staging, output, **kwargs)
producer_module.install_verified_directory = replace_staging_root
"""

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        test_core=True,
        prelude=prelude,
    )

    assert completed.returncode == 2
    assert "installation failed closed" in completed.stderr
    assert not output_dir.exists()
    assert {path.name for path in displaced.iterdir()} == ARCHIVE_FILENAMES


def test_existing_output_is_never_replaced(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    first = _run_producer(repository, source_sha, output_dir, test_core=True)
    assert first.returncode == 0, first.stderr
    before = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output_dir.iterdir()
    }

    second = _run_producer(repository, source_sha, output_dir, test_core=True)

    assert second.returncode == 2
    assert "new path" in second.stderr
    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output_dir.iterdir()
    } == before
