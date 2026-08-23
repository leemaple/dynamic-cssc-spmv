from __future__ import annotations

import hashlib
import json
import os
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

    central_path = repository / "src/dynamic_cssc/evidence_compatibility.py"
    central_source = central_path.read_text(encoding="utf-8")
    marker = '    "tests/test_strong_day1_simulator.py",\n'
    assert central_source.count(marker) == 1
    missing_paths = [
        path for path in PRODUCER_BEHAVIOR_PATHS if f'    "{path}",' not in central_source
    ]
    if missing_paths:
        additions = "".join(f'    "{path}",\n' for path in missing_paths)
        central_path.write_text(
            central_source.replace(marker, marker + additions),
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
            "GITHUB_REPOSITORY": "example/dynamic-cssc-spmv",
            "GITHUB_REPOSITORY_ID": "123456",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_RUN_ID": "456789",
            "GITHUB_SHA": source_sha,
            "GITHUB_WORKFLOW_REF": (
                "example/dynamic-cssc-spmv/.github/workflows/day1-cost-model.yml@refs/heads/main"
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
    return subprocess.run(
        (sys.executable, "-c", program),
        cwd=repository.parent,
        env=_producer_environment(source_sha),
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


def test_public_interfaces_are_path_only_and_hold_before_output_until_central_integration(
    tmp_path: Path,
) -> None:
    assert tuple(signature(produce_day1_registration_evidence_archive).parameters) == (
        "output_dir",
    )
    assert tuple(signature(inspect_day1_registration_evidence_archive).parameters) == (
        "archive_dir",
    )
    output_dir = tmp_path / "registration-evidence"

    with pytest.raises(
        (Day1RegistrationEvidenceHold, Day1RegistrationEvidenceError),
        match="Behavior Set|source attestation|registration run identity",
    ):
        produce_day1_registration_evidence_archive(output_dir)

    assert not output_dir.exists()


def test_cli_exposes_only_output_dir_and_rejects_run_or_identity_injection(
    tmp_path: Path,
) -> None:
    script = REPOSITORY_ROOT / "scripts/produce_day1_registration_evidence.py"
    environment = {**os.environ, "PYTHONPATH": str(REPOSITORY_ROOT / "src")}
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


def test_clean_integrated_s1_still_holds_without_a_repository_owned_run_identity(
    tmp_path: Path,
) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"

    completed = _run_producer(repository, source_sha, output_dir)

    assert completed.returncode == 2
    assert "HOLD" in completed.stderr
    assert "registration run identity" in completed.stderr
    assert not output_dir.exists()


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
        "src/dynamic_cssc/report.py",
        "src/dynamic_cssc/simulator.py",
        "tests/test_day1_registry.py",
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


def test_inline_dependency_monkeypatch_cannot_mint_a_public_archive(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    prelude = """
import dynamic_cssc.day1_registration_evidence as producer_module
producer_module._collect_repository_facts_in_isolated_interpreter = lambda: {
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

    assert completed.returncode == 2
    assert "registration run identity" in completed.stderr
    assert not output_dir.exists()


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
    with pytest.raises(ValueError, match="no-follow regular file"):
        inspect_day1_registration_evidence_archive(symlinked)

    tampered = tmp_path / "tampered"
    shutil.copytree(original, tampered)
    registration = json.loads((tampered / "registration-evidence.json").read_bytes())
    registration["run_id"] += 1
    (tampered / "registration-evidence.json").write_bytes(_canonical(registration))
    with pytest.raises(ValueError, match="SHA256SUMS"):
        inspect_day1_registration_evidence_archive(tampered)


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


def test_atomic_install_cleans_stage_and_lock_when_final_rename_fails(tmp_path: Path) -> None:
    repository, source_sha = _integrated_clean_repository(tmp_path)
    output_dir = tmp_path / "registration-evidence"
    prelude = """
import dynamic_cssc.day1_registration_evidence as producer_module
def fail_rename(source, destination):
    raise OSError('injected rename failure')
producer_module.os.rename = fail_rename
"""

    completed = _run_producer(
        repository,
        source_sha,
        output_dir,
        test_core=True,
        prelude=prelude,
    )

    assert completed.returncode == 2
    assert "injected rename failure" in completed.stderr
    assert not output_dir.exists()
    assert not list(tmp_path.glob(".registration-evidence.day1-registration-*"))
