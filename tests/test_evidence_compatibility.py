from __future__ import annotations

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

import dynamic_cssc.publication_day1b as day1b_module
from dynamic_cssc.evidence_compatibility import (
    DAY1_REGISTRATION_ANCHOR_PATH,
    EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
    STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
    EvidenceCompatibilityError,
    EvidenceCompatibilityReceipt,
    EvidenceRole,
    capture_behavior_inventory,
    repository_behavior_paths,
    verify_current_role_source,
    verify_evidence_compatibility,
    verify_repository_anchor_history,
)

TRACE_BEHAVIOR_PATHS = (
    ".github/workflows/publication-structure-pilot.yml",
    "config/params_manifest.json",
    "docs/paper/publication-preregistration-draft.md",
    "docs/research/publication-venues-datasets-preregistration.md",
    "pyproject.toml",
    "requirements-publication.txt",
    "scripts/prepare_publication_traces.py",
    "scripts/run_publication_structure_pilot.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/publication_acquisition.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_structure_pilot.py",
    "src/dynamic_cssc/publication_traces.py",
)
ANALYZER_BEHAVIOR_PATHS = (
    "config/day2-calibration-profile-anchors.json",
    "config/publication-runtime-policy.json",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "requirements-publication.txt",
    "scripts/analyze_publication_results.py",
    "scripts/run_publication_analysis_isolated.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/day2_calibration_authority.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/publication_runtime.py",
    "src/dynamic_cssc/publication_schedule.py",
    "src/dynamic_cssc/publication_statistics.py",
    "src/dynamic_cssc/publication_traces.py",
)
DAY1B_PREPARATORY_BEHAVIOR_PATHS = (
    ".github/workflows/publication-day1b-preparatory.yml",
    "config/params_manifest.json",
    "config/params_manifest.schema.json",
    "config/publication-day1b-resource-policy.json",
    "docs/decisions/0003-f1m-hidden-rowmap.md",
    "docs/decisions/0005-output-plan-overlap-blinding.md",
    "docs/decisions/0006-persistent-strategy-snapshots.md",
    "docs/decisions/0007-anonymous-fixed-segment-primitive.md",
    "docs/decisions/0008-strong-whole-query-execution-bundle.md",
    "docs/decisions/0009-fail-closed-role-aware-day1-catalog.md",
    "docs/decisions/0010-separate-experiment-and-evidence-freeze-snapshots.md",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "requirements-publication.txt",
    "scripts/run_publication_day1b.py",
    "scripts/validate_manifest.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/day1_registry.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/metrics.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_day1b.py",
    "src/dynamic_cssc/publication_day1b_worker_protocol.py",
    "src/dynamic_cssc/publication_schedule.py",
    "src/dynamic_cssc/publication_statistics.py",
    "src/dynamic_cssc/publication_traces.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/selection.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "tests/test_evidence_compatibility.py",
    "tests/test_publication_day1b.py",
    "tests/test_publication_day1b_worker_protocol.py",
    "tests/test_publication_day1b_workflow_contract.py",
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _canonical(payload: object) -> str:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )


def _write(repository: Path, relative_path: str, content: str) -> None:
    path = repository / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", message)
    return _git(repository, "rev-parse", "HEAD")


def _install_trace_anchor(
    repository: Path,
    *,
    experiment_sha: str,
    artifact_sha256: str,
    inventory: dict[str, object],
) -> str:
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    return _commit(repository, "install post-run anchor")


def _trace_anchor_record(
    *,
    experiment_sha: str,
    artifact_sha256: str,
    inventory: dict[str, object],
) -> dict[str, object]:
    return {
        "artifact_sha256": artifact_sha256,
        "behavior_set_schema_version": inventory["behavior_set_schema_version"],
        "behavior_set_sha256": inventory["behavior_set_sha256"],
        "experiment_source_git_sha": experiment_sha,
        "role": "trace",
        "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
    }


def _acquisition_anchor_record(
    *,
    experiment_sha: str,
    artifact_sha256: str = "a" * 64,
    behavior_set_sha256: str = "1" * 64,
) -> dict[str, object]:
    return {
        "artifact_sha256": artifact_sha256,
        "behavior_set_schema_version": "dynamic-cssc-acquisition-behavior-set-v2",
        "behavior_set_sha256": behavior_set_sha256,
        "experiment_source_git_sha": experiment_sha,
        "role": "acquisition",
        "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
    }


def _write_compatibility_anchors(
    repository: Path,
    anchors: list[dict[str, object]],
) -> None:
    _write(
        repository,
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
        _canonical(
            {
                "anchors": anchors,
                "schema_version": "dynamic-cssc-evidence-compatibility-anchor-set-v1",
            }
        ),
    )


def _write_day2_post_run_anchors(
    repository: Path,
    anchors: list[dict[str, object]],
) -> None:
    _write(
        repository,
        "config/day2-calibration-anchors.json",
        _canonical(
            {
                "anchors": anchors,
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v2",
            }
        ),
    )


def _write_trace_anchor(
    repository: Path,
    *,
    experiment_sha: str,
    artifact_sha256: str,
    inventory: dict[str, object],
) -> None:
    _write_compatibility_anchors(
        repository,
        [
            _trace_anchor_record(
                experiment_sha=experiment_sha,
                artifact_sha256=artifact_sha256,
                inventory=inventory,
            )
        ],
    )


def _day1_registration_record(
    *,
    experiment_sha: str,
    inventory: dict[str, object],
    accounting_evidence_sha256: str = "3" * 64,
    policy_contract_sha256: str = (
        "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
    ),
    registration_schema: str = "dynamic-cssc-day1-registration-evidence-v1",
) -> dict[str, object]:
    registration = {
        "accounting_evidence_sha256": accounting_evidence_sha256,
        "correctness_artifact_sha256": (
            "c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe"
        ),
        "policy_contract_sha256": policy_contract_sha256,
        "run_id": 123,
        "schema_version": registration_schema,
        "source_git_sha": experiment_sha,
    }
    return {
        "artifact_behavior_inventory": inventory,
        "artifact_sha256": hashlib.sha256(_canonical(registration).encode("ascii")).hexdigest(),
        "experiment_source_git_sha": experiment_sha,
        "registration_evidence": registration,
        "role": "day1-registration",
        "schema_version": "dynamic-cssc-day1-registration-anchor-v1",
    }


def _write_day1_registration_anchor(
    repository: Path,
    record: dict[str, object],
) -> None:
    _write(
        repository,
        DAY1_REGISTRATION_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [record],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        ),
    )


@pytest.fixture
def trace_repository(tmp_path: Path) -> tuple[Path, str, dict[str, object]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "compatibility-test@example.invalid")
    _git(repository, "config", "user.name", "Compatibility Test")
    _write(repository, ".gitignore", "*.pyc\nsitecustomize.py\n")

    # The production interface owns this exact path inventory; the fixture merely
    # materializes it in a real Git repository so tests cross the Git-object seam.
    provisional_sha = "0" * 40
    for relative_path in sorted(set(TRACE_BEHAVIOR_PATHS) | set(ANALYZER_BEHAVIOR_PATHS)):
        _write(repository, relative_path, f"fixture for {relative_path}\n")
    _write(
        repository,
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-evidence-compatibility-anchor-set-v1",
            }
        ),
    )
    experiment_sha = _commit(repository, "experiment")
    assert experiment_sha != provisional_sha
    inventory = capture_behavior_inventory(
        EvidenceRole.TRACE,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    return repository, experiment_sha, inventory


@pytest.fixture
def day1_registration_repository(
    tmp_path: Path,
) -> tuple[Path, str, str, str, dict[str, object], dict[str, object]]:
    repository = tmp_path / "day1-registration-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "registration-test@example.invalid")
    _git(repository, "config", "user.name", "Registration Test")
    _write(repository, ".gitignore", "*.pyc\n__pycache__/\n")
    for relative_path in repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION):
        _write(repository, relative_path, f"fixture for {relative_path}\n")
    _write(
        repository,
        DAY1_REGISTRATION_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        ),
    )
    experiment_sha = _commit(repository, "registration experiment")
    inventory = capture_behavior_inventory(
        EvidenceRole.DAY1_REGISTRATION,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    record = _day1_registration_record(
        experiment_sha=experiment_sha,
        inventory=inventory,
    )
    _write_day1_registration_anchor(repository, record)
    evidence_freeze_sha = _commit(repository, "install registration anchor")
    _git(repository, "commit", "--allow-empty", "-qm", "analysis snapshot")
    analysis_sha = _git(repository, "rev-parse", "HEAD")
    return (
        repository,
        experiment_sha,
        evidence_freeze_sha,
        analysis_sha,
        inventory,
        record,
    )


@pytest.fixture
def day1b_preparatory_repository(tmp_path: Path) -> tuple[Path, str, dict[str, object]]:
    repository = tmp_path / "day1b-preparatory-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "day1b-preparatory-test@example.invalid")
    _git(repository, "config", "user.name", "Day1B Preparatory Test")
    _write(repository, ".gitignore", "*.pyc\n__pycache__/\n")
    policy_bytes = (REPOSITORY_ROOT / "config/publication-day1b-resource-policy.json").read_text(
        encoding="ascii"
    )
    for relative_path in DAY1B_PREPARATORY_BEHAVIOR_PATHS:
        content = (
            policy_bytes
            if relative_path == "config/publication-day1b-resource-policy.json"
            else f"fixture for {relative_path}\n"
        )
        _write(repository, relative_path, content)
    source_git_sha = _commit(repository, "Day1B preparatory source")
    inventory = capture_behavior_inventory(
        EvidenceRole.DAY1B,
        source_git_sha=source_git_sha,
        repository_root=repository,
    )
    return repository, source_git_sha, inventory


def test_repository_history_uniquely_locates_first_anchor_commit_without_caller_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, evidence_sha, analysis_sha, inventory, record = (
        day1_registration_repository
    )

    attestation = verify_repository_anchor_history(
        EvidenceRole.DAY1_REGISTRATION,
        repository,
    )

    assert attestation.role is EvidenceRole.DAY1_REGISTRATION
    assert attestation.experiment_source_git_sha == experiment_sha
    assert attestation.evidence_freeze_git_sha == evidence_sha
    assert attestation.analysis_source_git_sha == analysis_sha
    assert attestation.artifact_sha256 == record["artifact_sha256"]
    assert attestation.artifact_behavior_inventory == inventory
    assert attestation.registration_evidence == record["registration_evidence"]
    assert attestation.compatibility_verified is True
    assert attestation.runtime_execution_isolation_verified is False
    assert attestation.formal_authority_granted is False

    with pytest.raises(TypeError):
        verify_repository_anchor_history(  # type: ignore[call-arg]
            EvidenceRole.DAY1_REGISTRATION,
            repository,
            evidence_freeze_git_sha=evidence_sha,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "missing-record-field",
        "extra-record-field",
        "inventory-missing-entry",
        "inventory-extra-entry",
        "inventory-mode",
        "inventory-type",
        "inventory-object-id",
        "inventory-digest",
        "artifact-digest",
        "accounting",
        "policy",
        "schema",
    ),
)
def test_repository_history_rejects_closed_record_inventory_and_digest_attacks(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
    mutation: str,
) -> None:
    repository, _experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    attacked = deepcopy(record)
    inventory = attacked["artifact_behavior_inventory"]
    registration = attacked["registration_evidence"]
    assert isinstance(inventory, dict)
    assert isinstance(registration, dict)
    entries = inventory["entries"]
    assert isinstance(entries, list)
    if mutation == "missing-record-field":
        attacked.pop("artifact_sha256")
    elif mutation == "extra-record-field":
        attacked["compatibility_verified"] = True
    elif mutation == "inventory-missing-entry":
        entries.pop()
    elif mutation == "inventory-extra-entry":
        entries.append(deepcopy(entries[-1]))
    elif mutation == "inventory-mode":
        entries[0]["mode"] = "100755"
    elif mutation == "inventory-type":
        entries[0]["object_type"] = "tree"
    elif mutation == "inventory-object-id":
        entries[0]["object_id"] = "0" * 40
    elif mutation == "inventory-digest":
        inventory["behavior_set_sha256"] = "0" * 64
    elif mutation == "artifact-digest":
        attacked["artifact_sha256"] = "0" * 64
    elif mutation == "accounting":
        registration["accounting_evidence_sha256"] = "0" * 64
        attacked["artifact_sha256"] = hashlib.sha256(
            _canonical(registration).encode("ascii")
        ).hexdigest()
    elif mutation == "policy":
        registration["policy_contract_sha256"] = "0" * 64
        attacked["artifact_sha256"] = hashlib.sha256(
            _canonical(registration).encode("ascii")
        ).hexdigest()
    else:
        registration["schema_version"] = "dynamic-cssc-day1-registration-evidence-v2"
        attacked["artifact_sha256"] = hashlib.sha256(
            _canonical(registration).encode("ascii")
        ).hexdigest()
    _write_day1_registration_anchor(repository, attacked)
    _commit(repository, f"retarget {mutation}")

    with pytest.raises(EvidenceCompatibilityError):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


@pytest.mark.parametrize("encoding", ("noncanonical", "duplicate-key"))
def test_repository_history_rejects_noncanonical_or_duplicate_anchor_data(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
    encoding: str,
) -> None:
    repository, _experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    if encoding == "noncanonical":
        content = json.dumps(
            {
                "anchors": [record],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            },
            indent=2,
        )
    else:
        encoded_record = json.dumps(record, sort_keys=True, separators=(",", ":"))
        content = (
            '{"anchors":[' + encoded_record + '],"anchors":[],"schema_version":'
            '"dynamic-cssc-day1-registration-anchor-set-v1"}\n'
        )
    _write(repository, DAY1_REGISTRATION_ANCHOR_PATH, content)
    _commit(repository, f"install {encoding} attack")

    with pytest.raises(EvidenceCompatibilityError, match="canonical|duplicate"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_remove_then_readd_replay(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, _experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    _write(
        repository,
        DAY1_REGISTRATION_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        ),
    )
    _commit(repository, "remove registration anchor")
    _write_day1_registration_anchor(repository, record)
    _commit(repository, "replay registration anchor")

    with pytest.raises(EvidenceCompatibilityError, match="removed|replayed"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_two_independent_first_anchor_commits(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    primary_branch = _git(repository, "branch", "--show-current")
    _git(repository, "checkout", "-qb", "independent-anchor", experiment_sha)
    _write_day1_registration_anchor(repository, record)
    _commit(repository, "independent anchor installation")
    _git(repository, "checkout", "-q", primary_branch)
    _git(
        repository,
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "merge independent anchor history",
        "independent-anchor",
    )

    with pytest.raises(EvidenceCompatibilityError, match="one unique first"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


@pytest.mark.parametrize("mutation", ("executable", "symlink"))
def test_registration_anchor_path_mode_and_type_are_data_only(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
    mutation: str,
) -> None:
    repository, *_rest = day1_registration_repository
    anchor_path = repository / DAY1_REGISTRATION_ANCHOR_PATH
    if mutation == "executable":
        anchor_path.chmod(0o755)
    else:
        anchor_path.unlink()
        anchor_path.symlink_to("../strong-reference-evidence-anchors.json")
    _commit(repository, f"{mutation} registration anchor")

    with pytest.raises(EvidenceCompatibilityError, match="data blob"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_registration_anchor_set_rejects_an_extra_record(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, _experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    _write(
        repository,
        DAY1_REGISTRATION_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [record, deepcopy(record)],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        ),
    )
    _commit(repository, "append extra registration anchor")

    with pytest.raises(EvidenceCompatibilityError, match="at most one"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_extra_tree_drift_after_registration(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, *_rest = day1_registration_repository
    _write(repository, "README.md", "unapproved post-registration drift\n")
    _commit(repository, "extra drift")

    with pytest.raises(EvidenceCompatibilityError, match="post-registration drift"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_behavior_drift_restored_between_s1_and_terminal_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, _evidence_sha, _analysis_sha, _inventory, record = (
        day1_registration_repository
    )
    _git(repository, "checkout", "-q", "--detach", experiment_sha)
    readme = repository / "README.md"
    _write(repository, "README.md", "temporary pre-freeze behavior-adjacent drift\n")
    _commit(repository, "temporarily add documentation before terminal S2")
    readme.unlink()
    _commit(repository, "restore pre-freeze documentation tree")
    _write_day1_registration_anchor(repository, record)
    _commit(repository, "install terminal registration anchor")
    _git(repository, "commit", "--allow-empty", "-qm", "analysis snapshot")

    with pytest.raises(EvidenceCompatibilityError, match="S1-to-S2 history.*drift"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_behavior_drift_restored_after_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, *_rest = day1_registration_repository
    readme = repository / "README.md"
    _write(repository, "README.md", "temporary behavior-adjacent drift\n")
    _commit(repository, "temporarily add unapproved documentation")
    readme.unlink()
    _commit(repository, "restore documentation tree")

    with pytest.raises(EvidenceCompatibilityError, match="history.*drift"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_compatibility_anchor_remove_then_readd_after_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, *_rest = day1_registration_repository
    anchor = _acquisition_anchor_record(experiment_sha=experiment_sha)
    _write_compatibility_anchors(repository, [anchor])
    _commit(repository, "install shared compatibility anchor")
    (repository / EVIDENCE_COMPATIBILITY_ANCHOR_PATH).unlink()
    _commit(repository, "temporarily remove shared compatibility anchor")
    _write_compatibility_anchors(repository, [anchor])
    _commit(repository, "restore shared compatibility anchor")

    with pytest.raises(EvidenceCompatibilityError, match="history.*remove or retarget"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_day2_binding_retarget_then_restore_after_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, *_rest = day1_registration_repository
    binding = {"binding": "day2-evidence"}
    _write_day2_post_run_anchors(repository, [binding])
    _commit(repository, "install Day2 post-run binding")
    _write_day2_post_run_anchors(repository, [{"binding": "retargeted-evidence"}])
    _commit(repository, "temporarily retarget Day2 post-run binding")
    _write_day2_post_run_anchors(repository, [binding])
    _commit(repository, "restore Day2 post-run binding")

    with pytest.raises(EvidenceCompatibilityError, match="history.*Day2.*remove or retarget"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_allows_the_day2_post_run_data_anchor_after_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, _experiment_sha, evidence_sha, _analysis_sha, _inventory, _record = (
        day1_registration_repository
    )
    _write_day2_post_run_anchors(repository, [])
    current_sha = _commit(repository, "install Day2 post-run calibration anchor")

    attestation = verify_repository_anchor_history(
        EvidenceRole.DAY1_REGISTRATION,
        repository,
    )

    assert attestation.evidence_freeze_git_sha == evidence_sha
    assert attestation.analysis_source_git_sha == current_sha


def test_repository_history_rejects_predispatch_day2_profile_anchor_after_s2(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, *_rest = day1_registration_repository
    _write(
        repository,
        "config/day2-calibration-profile-anchors.json",
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v1",
            }
        ),
    )
    _commit(repository, "attempt late Day2 pre-dispatch profile anchor")

    with pytest.raises(EvidenceCompatibilityError, match="post-registration drift"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_executable_cross_role_anchor_data(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, *_rest = day1_registration_repository
    path = repository / "config/day2-calibration-anchors.json"
    _write_day2_post_run_anchors(repository, [])
    path.chmod(0o755)
    _commit(repository, "install executable cross-role data anchor")

    with pytest.raises(EvidenceCompatibilityError, match="100644 data blob"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_nonancestor_registration_source(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, _evidence_sha, analysis_sha, _inventory, _record = (
        day1_registration_repository
    )
    _git(repository, "checkout", "-qb", "sibling-registration", experiment_sha)
    _git(repository, "commit", "--allow-empty", "-qm", "sibling registration source")
    sibling_sha = _git(repository, "rev-parse", "HEAD")
    sibling_inventory = capture_behavior_inventory(
        EvidenceRole.DAY1_REGISTRATION,
        source_git_sha=sibling_sha,
        repository_root=repository,
    )
    sibling_record = _day1_registration_record(
        experiment_sha=sibling_sha,
        inventory=sibling_inventory,
    )
    _git(repository, "checkout", "-q", analysis_sha)
    _write_day1_registration_anchor(repository, sibling_record)
    _commit(repository, "retarget to nonancestor source")

    with pytest.raises(EvidenceCompatibilityError, match="not an ancestor"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)


def test_repository_history_rejects_replace_refs_and_shallow_history(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
    tmp_path: Path,
) -> None:
    repository, experiment_sha, _evidence_sha, analysis_sha, _inventory, _record = (
        day1_registration_repository
    )
    _git(repository, "replace", experiment_sha, analysis_sha)
    with pytest.raises(EvidenceCompatibilityError, match="replacement refs"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, repository)
    _git(repository, "replace", "-d", experiment_sha)

    shallow = tmp_path / "shallow-registration"
    subprocess.run(
        ("git", "clone", "-q", "--depth", "1", f"file://{repository}", str(shallow)),
        check=True,
    )
    with pytest.raises(EvidenceCompatibilityError, match="shallow"):
        verify_repository_anchor_history(EvidenceRole.DAY1_REGISTRATION, shallow)


def test_registration_role_forbids_the_old_caller_selected_s2_interface(
    day1_registration_repository: tuple[
        Path,
        str,
        str,
        str,
        dict[str, object],
        dict[str, object],
    ],
) -> None:
    repository, experiment_sha, evidence_sha, analysis_sha, inventory, record = (
        day1_registration_repository
    )
    with pytest.raises(EvidenceCompatibilityError, match="forbid caller-supplied S2"):
        verify_evidence_compatibility(
            role=EvidenceRole.DAY1_REGISTRATION,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=str(record["artifact_sha256"]),
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_producer_cannot_omit_a_repository_owned_behavior_file(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    assert "src/dynamic_cssc/publication_traces.py" in {
        entry["path"] for entry in inventory["entries"]
    }
    inventory["entries"] = [
        entry
        for entry in inventory["entries"]
        if entry["path"] != "src/dynamic_cssc/publication_traces.py"
    ]
    inventory["behavior_set_sha256"] = hashlib.sha256(
        _canonical(
            {
                "behavior_set_schema_version": inventory["behavior_set_schema_version"],
                "entries": inventory["entries"],
                "role": inventory["role"],
            }
        ).encode("ascii")
    ).hexdigest()

    with pytest.raises(EvidenceCompatibilityError, match="artifact behavior inventory"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=experiment_sha,
            artifact_sha256="a" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_equal_snapshot_is_only_an_identity_compatibility_shortcut(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=experiment_sha,
        analysis_source_git_sha=experiment_sha,
        artifact_sha256="a" * 64,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )
    document = receipt.to_document()

    assert document["experiment_source"]["git_sha"] == experiment_sha
    assert document["evidence_freeze_source"]["git_sha"] == experiment_sha
    assert document["analysis_source"]["git_sha"] == experiment_sha
    assert document["experiment_source"]["behavior_set_sha256"] == inventory["behavior_set_sha256"]
    assert (
        document["evidence_freeze_source"]["behavior_set_sha256"]
        == inventory["behavior_set_sha256"]
    )
    assert (
        document["analysis_source"]["experiment_role_behavior_set_sha256"]
        == inventory["behavior_set_sha256"]
    )
    assert document["snapshot_identity_shortcut"] is True
    assert document["post_run_anchor_verified"] is False
    assert document["runtime_execution_isolation_verified"] is False
    assert document["formal_authority_granted"] is False
    assert document["snapshot_compatibility_verified"] is True
    assert document["compatibility_verified"] is False


def test_post_run_anchor_allows_s1_with_anchor_only_s2_s3(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    evidence_freeze_sha = _install_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _git(repository, "commit", "--allow-empty", "-qm", "analysis snapshot metadata only")
    analysis_sha = _git(repository, "rev-parse", "HEAD")

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=evidence_freeze_sha,
        analysis_source_git_sha=analysis_sha,
        artifact_sha256=artifact_sha256,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )
    document = receipt.to_document()

    assert document["snapshot_identity_shortcut"] is False
    assert len({experiment_sha, evidence_freeze_sha, analysis_sha}) == 3
    assert document["post_run_anchor_verified"] is True
    assert document["compatibility_verified"] is True
    assert document["evidence_only_changed_paths"] == [EVIDENCE_COMPATIBILITY_ANCHOR_PATH]
    assert document["analysis_only_changed_paths"] == []
    assert len(document["changed_path_allowlist_sha256"]) == 64
    assert (
        receipt.receipt_sha256 == hashlib.sha256(_canonical(document).encode("ascii")).hexdigest()
    )
    assert document["runtime_execution_isolation_verified"] is False
    assert document["formal_authority_granted"] is False
    with pytest.raises(EvidenceCompatibilityError, match="post-run artifact anchor is absent"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256="0" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_post_run_anchor_set_may_grow_monotonically_across_roles(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    evidence_freeze_sha = _commit(repository, "freeze trace evidence")

    acquisition_anchor = _acquisition_anchor_record(experiment_sha=experiment_sha)
    _write_compatibility_anchors(repository, [acquisition_anchor, trace_anchor])
    analysis_sha = _commit(repository, "append acquisition evidence anchor")

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=evidence_freeze_sha,
        analysis_source_git_sha=analysis_sha,
        artifact_sha256=artifact_sha256,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )

    assert receipt.to_document()["evidence_to_analysis_changed_paths"] == [
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH
    ]
    assert receipt.to_document()["post_run_anchor_verified"] is True


@pytest.mark.parametrize("mutation", ("removed", "retargeted"))
def test_analysis_anchor_set_may_not_remove_or_retarget_evidence_records(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    acquisition_anchor = _acquisition_anchor_record(experiment_sha=experiment_sha)
    _write_compatibility_anchors(repository, [acquisition_anchor, trace_anchor])
    evidence_freeze_sha = _commit(repository, "freeze two evidence records")
    if mutation == "removed":
        analysis_anchors = [trace_anchor]
    else:
        analysis_anchors = [
            _acquisition_anchor_record(
                experiment_sha=experiment_sha,
                behavior_set_sha256="2" * 64,
            ),
            trace_anchor,
        ]
    _write_compatibility_anchors(repository, analysis_anchors)
    analysis_sha = _commit(repository, f"{mutation} acquisition evidence record")

    with pytest.raises(EvidenceCompatibilityError, match="remove or retarget"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize("mutation", ("remove-readd", "retarget-restore"))
def test_analysis_anchor_history_may_not_temporarily_remove_or_retarget_records(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    evidence_freeze_sha = _commit(repository, "freeze trace evidence")
    if mutation == "remove-readd":
        _write_compatibility_anchors(repository, [])
    else:
        retargeted = dict(trace_anchor)
        retargeted["artifact_sha256"] = "0" * 64
        _write_compatibility_anchors(repository, [retargeted])
    _commit(repository, f"temporarily {mutation} trace evidence")
    _write_compatibility_anchors(repository, [trace_anchor])
    analysis_sha = _commit(repository, "restore trace evidence")

    with pytest.raises(EvidenceCompatibilityError, match="history.*remove or retarget"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_analysis_anchor_history_may_not_retarget_and_restore_day2_binding(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    binding = {"binding": "day2-evidence"}
    _write_day2_post_run_anchors(repository, [binding])
    evidence_freeze_sha = _commit(repository, "freeze trace and Day2 evidence")
    _write_day2_post_run_anchors(repository, [{"binding": "retargeted-evidence"}])
    _commit(repository, "temporarily retarget Day2 evidence")
    _write_day2_post_run_anchors(repository, [binding])
    analysis_sha = _commit(repository, "restore Day2 evidence")

    with pytest.raises(EvidenceCompatibilityError, match="history.*Day2.*remove or retarget"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_analysis_anchor_history_checks_merge_dag_retarget_then_restore(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    evidence_freeze_sha = _commit(repository, "freeze trace evidence")
    main_branch = _git(repository, "branch", "--show-current")
    _git(repository, "checkout", "-q", "-b", "retarget-evidence-branch")
    retargeted = dict(trace_anchor)
    retargeted["artifact_sha256"] = "0" * 64
    _write_compatibility_anchors(repository, [retargeted])
    _commit(repository, "retarget trace evidence on side branch")
    _git(repository, "checkout", "-q", main_branch)
    _git(repository, "commit", "--allow-empty", "-qm", "advance main analysis lineage")
    _git(
        repository,
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "merge retargeted evidence branch",
        "retarget-evidence-branch",
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    analysis_sha = _commit(repository, "restore trace evidence after merge")

    with pytest.raises(EvidenceCompatibilityError, match="history.*remove or retarget"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_evidence_anchor_set_may_not_remove_an_experiment_record(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, _initial_sha, _initial_inventory = trace_repository
    acquisition_anchor = _acquisition_anchor_record(
        experiment_sha="0" * 40,
    )
    _write_compatibility_anchors(repository, [acquisition_anchor])
    experiment_sha = _commit(repository, "experiment with an existing repository anchor")
    acquisition_anchor["experiment_source_git_sha"] = experiment_sha
    _write_compatibility_anchors(repository, [acquisition_anchor])
    experiment_sha = _commit(repository, "bind existing anchor to earlier experiment")
    inventory = capture_behavior_inventory(
        EvidenceRole.TRACE,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    evidence_freeze_sha = _commit(repository, "remove old anchor while freezing trace")

    with pytest.raises(EvidenceCompatibilityError, match="may not remove"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize("mutation", ("duplicate", "noncanonical-order"))
def test_growing_anchor_set_remains_unique_and_canonically_ordered(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "b" * 64
    trace_anchor = _trace_anchor_record(
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_compatibility_anchors(repository, [trace_anchor])
    evidence_freeze_sha = _commit(repository, "freeze trace evidence")
    acquisition_anchor = _acquisition_anchor_record(experiment_sha=experiment_sha)
    analysis_anchors = (
        [trace_anchor, trace_anchor]
        if mutation == "duplicate"
        else [trace_anchor, acquisition_anchor]
    )
    _write_compatibility_anchors(repository, analysis_anchors)
    analysis_sha = _commit(repository, f"install {mutation} anchor set")

    with pytest.raises(EvidenceCompatibilityError, match="unique and canonically ordered"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_cross_role_data_anchors_may_accrue_in_both_snapshot_windows(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "c" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write_day2_post_run_anchors(repository, [])
    evidence_freeze_sha = _commit(repository, "freeze trace and Day2 data anchors")
    _write_day2_post_run_anchors(repository, [{"binding": "day2-evidence"}])
    analysis_sha = _commit(repository, "install one Day2 post-run binding")

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=evidence_freeze_sha,
        analysis_source_git_sha=analysis_sha,
        artifact_sha256=artifact_sha256,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )
    document = receipt.to_document()

    assert document["experiment_to_evidence_changed_paths"] == [
        "config/day2-calibration-anchors.json",
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
    ]
    assert document["evidence_to_analysis_changed_paths"] == [
        "config/day2-calibration-anchors.json"
    ]
    allowed_data_paths = [
        "config/day2-calibration-anchors.json",
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
    ]
    allowlist_sha256 = hashlib.sha256(_canonical(allowed_data_paths).encode("ascii")).hexdigest()
    assert document["evidence_only_allowlist_sha256"] == allowlist_sha256
    assert document["analysis_only_allowlist_sha256"] == allowlist_sha256
    assert (
        document["changed_path_allowlist_sha256"]
        == hashlib.sha256(
            _canonical(
                {
                    "analysis_only_paths": allowed_data_paths,
                    "evidence_only_paths": allowed_data_paths,
                    "role": "trace",
                    "schema_version": "dynamic-cssc-evidence-changed-path-allowlist-v1",
                }
            ).encode("ascii")
        ).hexdigest()
    )


@pytest.mark.parametrize("mutation", ("removed", "retargeted", "duplicate"))
def test_day2_post_run_binding_is_append_once_and_then_immutable(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "c" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    binding = {"binding": "day2-evidence"}
    _write_day2_post_run_anchors(repository, [binding])
    evidence_freeze_sha = _commit(repository, "freeze trace and Day2 binding")
    if mutation == "removed":
        analysis_bindings: list[dict[str, object]] = []
    elif mutation == "retargeted":
        analysis_bindings = [{"binding": "different-evidence"}]
    else:
        analysis_bindings = [binding, binding]
    _write_day2_post_run_anchors(repository, analysis_bindings)
    analysis_sha = _commit(repository, f"install {mutation} Day2 binding")

    with pytest.raises(EvidenceCompatibilityError, match="Day2 post-run"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_day2_post_run_anchor_set_uses_the_closed_v2_top_level_schema(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "c" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write(
        repository,
        "config/day2-calibration-anchors.json",
        _canonical(
            {
                "anchors": [],
                "schema_version": "dynamic-cssc-day2-calibration-post-run-anchor-set-v1",
            }
        ),
    )
    evidence_freeze_sha = _commit(repository, "install obsolete Day2 anchor-set schema")

    with pytest.raises(EvidenceCompatibilityError, match="Day2 post-run.*schema"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "config/day2-calibration-profile-anchors.json",
        DAY1_REGISTRATION_ANCHOR_PATH,
        STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
    ),
)
def test_generic_compatibility_rejects_anchors_owned_by_special_or_predispatch_seams(
    trace_repository: tuple[Path, str, dict[str, object]],
    relative_path: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "c" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write(repository, relative_path, "{}\n")
    evidence_freeze_sha = _commit(repository, f"attempt generic {relative_path} addition")

    with pytest.raises(EvidenceCompatibilityError, match="extra drift"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_compatibility_anchor_set_must_be_a_non_executable_git_blob(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "d" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    (repository / EVIDENCE_COMPATIBILITY_ANCHOR_PATH).chmod(0o755)
    evidence_freeze_sha = _commit(repository, "install executable compatibility anchor")

    with pytest.raises(EvidenceCompatibilityError, match="100644|non-executable"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize("mutation", ("executable-at-evidence", "deleted-at-analysis"))
def test_changed_data_only_anchor_paths_must_end_as_git_100644_blobs(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "e" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    if mutation == "executable-at-evidence":
        data_path = repository / "config/day2-calibration-anchors.json"
        _write_day2_post_run_anchors(repository, [])
        data_path.chmod(0o755)
        evidence_freeze_sha = _commit(repository, "install executable Day2 data anchor")
        analysis_sha = evidence_freeze_sha
    else:
        data_path = repository / "config/day2-calibration-anchors.json"
        _write_day2_post_run_anchors(repository, [])
        evidence_freeze_sha = _commit(repository, "install strong data anchor")
        data_path.unlink()
        analysis_sha = _commit(repository, "delete strong data anchor")

    with pytest.raises(EvidenceCompatibilityError, match="100644 data blob"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_analyzer_role_rejects_cross_snapshot_post_run_compatibility(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, _trace_inventory = trace_repository
    inventory = capture_behavior_inventory(
        EvidenceRole.ANALYZER,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    artifact_sha256 = "f" * 64
    _write_compatibility_anchors(
        repository,
        [
            {
                "artifact_sha256": artifact_sha256,
                "behavior_set_schema_version": inventory["behavior_set_schema_version"],
                "behavior_set_sha256": inventory["behavior_set_sha256"],
                "experiment_source_git_sha": experiment_sha,
                "role": "analyzer",
                "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
            }
        ],
    )
    evidence_freeze_sha = _commit(repository, "attempt post-run analyzer anchor")

    with pytest.raises(EvidenceCompatibilityError, match="ANALYZER.*identity"):
        verify_evidence_compatibility(
            role=EvidenceRole.ANALYZER,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "docs/paper/publication-preregistration-draft.md",
        "src/dynamic_cssc/publication_statistics.py",
    ),
)
def test_post_outcome_decision_or_preregistration_change_is_never_analysis_only(
    trace_repository: tuple[Path, str, dict[str, object]],
    relative_path: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "9" * 64
    evidence_freeze_sha = _install_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write(repository, relative_path, "post-outcome decision drift\n")
    analysis_sha = _commit(repository, "post-outcome decision drift")

    with pytest.raises(EvidenceCompatibilityError, match="Behavior Set|extra drift"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_day1b_preparatory_behavior_inventory_is_exact_but_non_authorizing(
    day1b_preparatory_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, source_git_sha, inventory = day1b_preparatory_repository

    attestation = verify_current_role_source(EvidenceRole.DAY1B, repository)

    assert tuple(repository_behavior_paths(EvidenceRole.DAY1B)) == (
        DAY1B_PREPARATORY_BEHAVIOR_PATHS
    )
    assert inventory["behavior_set_schema_version"] == (
        "dynamic-cssc-day1b-preparatory-behavior-set-v1"
    )
    assert inventory["role"] == "day1b"
    assert inventory["source_git_sha"] == source_git_sha
    assert [entry["path"] for entry in inventory["entries"]] == list(
        DAY1B_PREPARATORY_BEHAVIOR_PATHS
    )
    assert attestation.runtime_execution_isolation_verified is False
    assert "dispatch_authorized" not in inventory
    assert "formal_authority_granted" not in inventory
    with pytest.raises(day1b_module.PublicationDay1BHold, match="PENDING-FREEZE"):
        day1b_module._require_repository_day1b_resource_policy(repository)


@pytest.mark.parametrize(
    ("relative_path", "mutation"),
    (
        ("src/dynamic_cssc/publication_day1b.py", "blob"),
        ("src/dynamic_cssc/publication_day1b_worker_protocol.py", "mode"),
        ("config/publication-day1b-resource-policy.json", "missing"),
        ("untracked-extra.txt", "extra"),
    ),
)
def test_day1b_preparatory_source_drift_is_rejected_before_dispatch(
    day1b_preparatory_repository: tuple[Path, str, dict[str, object]],
    relative_path: str,
    mutation: str,
) -> None:
    repository, _source_git_sha, _inventory = day1b_preparatory_repository
    path = repository / relative_path
    if mutation == "blob":
        path.write_text("changed Day1B behavior\n", encoding="utf-8")
    elif mutation == "mode":
        path.chmod(0o755)
    elif mutation == "missing":
        path.unlink()
    else:
        path.write_text("unexpected source\n", encoding="utf-8")

    with pytest.raises(EvidenceCompatibilityError, match="clean|changed|missing|untracked"):
        verify_current_role_source(EvidenceRole.DAY1B, repository)


def test_clean_day1b_source_cannot_promote_the_pending_policy_in_place(
    day1b_preparatory_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, _source_git_sha, _inventory = day1b_preparatory_repository
    policy_path = repository / "config/publication-day1b-resource-policy.json"
    policy = json.loads(policy_path.read_bytes())
    policy["limits"]["wall_clock_seconds_per_candidate_cell"] = 1
    policy_path.write_text(_canonical(policy), encoding="ascii")
    _commit(repository, "attempt in-place Day1B policy promotion")

    assert verify_current_role_source(EvidenceRole.DAY1B, repository).role is EvidenceRole.DAY1B
    with pytest.raises(
        day1b_module.PublicationDay1BHold,
        match="pending resource policy is invalid.*placeholder",
    ):
        day1b_module._require_repository_day1b_resource_policy(repository)


def test_role_sets_freeze_entrypoint_workflow_build_lock_runtime_and_transitive_code() -> None:
    acquisition_paths = set(repository_behavior_paths(EvidenceRole.ACQUISITION))
    trace_paths = set(repository_behavior_paths(EvidenceRole.TRACE))
    day1b_paths = set(repository_behavior_paths(EvidenceRole.DAY1B))
    day2_paths = set(repository_behavior_paths(EvidenceRole.DAY2))
    analyzer_paths = set(repository_behavior_paths(EvidenceRole.ANALYZER))
    strong_correctness_paths = set(repository_behavior_paths(EvidenceRole.STRONG_CORRECTNESS))
    day1_registration_paths = set(repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION))

    assert {
        "config/params_manifest.json",
        "docs/paper/publication-preregistration-draft.md",
        "docs/research/publication-dataset-citation-record.md",
        "docs/research/publication-venues-datasets-preregistration.md",
        "pyproject.toml",
        "requirements-acquisition.txt",
        "scripts/acquire_publication_sources.py",
        "scripts/prepare_publication_traces.py",
        "src/dynamic_cssc/__init__.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/publication_acquisition.py",
        "src/dynamic_cssc/publication_artifact_install.py",
        "src/dynamic_cssc/publication_traces.py",
    } == acquisition_paths
    assert set(TRACE_BEHAVIOR_PATHS) == trace_paths
    assert day1b_paths == set(DAY1B_PREPARATORY_BEHAVIOR_PATHS)
    assert {
        ".github/workflows/day2-microbench.yml",
        "cpp/CMakeLists.txt",
        "config/day2-calibration-profile-anchors.json",
        "cpp/include/args.hpp",
        "cpp/microbench.cpp",
        "requirements-ci.txt",
        "scripts/bootstrap_openfhe.sh",
        "scripts/build_cpp.sh",
        "src/dynamic_cssc/day2_calibration_authority.py",
        "src/dynamic_cssc/plaintext_oracle.py",
        "src/dynamic_cssc/query_compiler.py",
        "src/dynamic_cssc/strategy_state.py",
        "src/dynamic_cssc/strong_execution.py",
    } <= day2_paths
    assert {
        "config/day2-calibration-profile-anchors.json",
        "config/publication-runtime-policy.json",
        "scripts/analyze_publication_results.py",
        "scripts/run_publication_analysis_isolated.py",
        "requirements-ci.txt",
        "src/dynamic_cssc/day2_calibration_authority.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/publication_runtime.py",
        "src/dynamic_cssc/publication_schedule.py",
        "src/dynamic_cssc/publication_statistics.py",
        "src/dynamic_cssc/publication_traces.py",
    } <= analyzer_paths
    assert {
        ".github/workflows/strong-whole-query-witness.yml",
        "config/params_manifest.json",
        "cpp/CMakeLists.txt",
        "cpp/include/args.hpp",
        "cpp/strong_whole_query_witness.cpp",
        "requirements-ci.txt",
        "scripts/bootstrap_openfhe.sh",
        "scripts/build_cpp.sh",
        "scripts/make_strong_whole_query_witness_binding.py",
        "scripts/property_contract.py",
        "scripts/property_contract_spec.py",
        "scripts/validate_property_contract.py",
        "scripts/validate_strong_whole_query_witness.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/strong_reference_receipt.py",
        "src/dynamic_cssc/strong_whole_query_witness.py",
    } <= strong_correctness_paths
    assert {
        ".github/workflows/day1-cost-model.yml",
        ".github/workflows/day1-registration-evidence.yml",
        "config/params_manifest.json",
        "requirements-ci.txt",
        "scripts/aggregate_day1_shards.py",
        "scripts/replay_day1_shard.py",
        "scripts/run_day1_suite.py",
        "scripts/produce_day1_registration_evidence.py",
        "src/dynamic_cssc/day1a_export.py",
        "src/dynamic_cssc/day1_registration_evidence.py",
        "src/dynamic_cssc/day1_registry.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/metrics.py",
        "src/dynamic_cssc/plaintext_oracle.py",
        "src/dynamic_cssc/publication_artifact_install.py",
        "src/dynamic_cssc/report.py",
        "src/dynamic_cssc/selection.py",
        "src/dynamic_cssc/strong_reference_receipt.py",
        "tests/test_day1_registration_evidence.py",
        "tests/test_day1_shard_aggregation.py",
        "tests/test_day1_workflow_contract.py",
    } <= day1_registration_paths
    assert STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH not in strong_correctness_paths
    assert DAY1_REGISTRATION_ANCHOR_PATH not in day1_registration_paths
    assert all(
        "uv.lock" not in paths
        for paths in (
            acquisition_paths,
            trace_paths,
            day1b_paths,
            day2_paths,
            analyzer_paths,
            strong_correctness_paths,
            day1_registration_paths,
        )
    )


def test_day1_workflow_does_not_run_unfrozen_repository_wide_gates() -> None:
    workflow = (REPOSITORY_ROOT / ".github/workflows/day1-cost-model.yml").read_text(
        encoding="utf-8"
    )

    assert "PYTHONPATH=src:. .venv/bin/python -m pytest -q\n" not in workflow
    assert ".venv/bin/python -m ruff check ." not in workflow
    for test_path in (
        "tests/test_day1_registry.py",
        "tests/test_query_accounting.py",
        "tests/test_report.py",
        "tests/test_strong_day1_simulator.py",
    ):
        assert test_path in workflow


def test_repository_ci_uses_the_frozen_runtime_complete_history_and_budget() -> None:
    workflow = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow
    assert "python-version: '3.12.13'" in workflow
    assert "timeout-minutes: 60" in workflow


@pytest.mark.parametrize(
    "runtime_path",
    [
        "config/publication-runtime-policy.json",
        "scripts/run_publication_analysis_isolated.py",
        "src/dynamic_cssc/publication_runtime.py",
    ],
)
def test_analyzer_artifact_inventory_cannot_omit_runtime_behavior(
    trace_repository: tuple[Path, str, dict[str, object]],
    runtime_path: str,
) -> None:
    repository, experiment_sha, _trace_inventory = trace_repository
    inventory = capture_behavior_inventory(
        EvidenceRole.ANALYZER,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    omitted = deepcopy(inventory)
    omitted["entries"] = [entry for entry in omitted["entries"] if entry["path"] != runtime_path]

    with pytest.raises(EvidenceCompatibilityError, match="exactly equal"):
        verify_evidence_compatibility(
            role=EvidenceRole.ANALYZER,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=experiment_sha,
            artifact_sha256="9" * 64,
            artifact_behavior_inventory=omitted,
            repository_root=repository,
        )


@pytest.mark.parametrize(
    ("runtime_path", "drift"),
    [
        ("config/publication-runtime-policy.json", "blob"),
        ("scripts/run_publication_analysis_isolated.py", "mode"),
        ("src/dynamic_cssc/publication_runtime.py", "missing"),
    ],
)
def test_analyzer_runtime_behavior_drift_after_experiment_is_rejected(
    trace_repository: tuple[Path, str, dict[str, object]],
    runtime_path: str,
    drift: str,
) -> None:
    repository, experiment_sha, _trace_inventory = trace_repository
    inventory = capture_behavior_inventory(
        EvidenceRole.ANALYZER,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    path = repository / runtime_path
    if drift == "blob":
        path.write_text("post-experiment runtime drift\n", encoding="utf-8")
    elif drift == "mode":
        path.chmod(0o755)
    else:
        path.unlink()
    analysis_sha = _commit(repository, f"{drift} runtime behavior")

    with pytest.raises(EvidenceCompatibilityError, match="Behavior Set|absent"):
        verify_evidence_compatibility(
            role=EvidenceRole.ANALYZER,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256="9" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_repository_anchor_data_is_canonical_in_empty_or_installed_state() -> None:
    compatibility_bytes = (REPOSITORY_ROOT / EVIDENCE_COMPATIBILITY_ANCHOR_PATH).read_bytes()
    compatibility = json.loads(compatibility_bytes)
    assert _canonical(compatibility).encode("ascii") == compatibility_bytes
    assert set(compatibility) == {"anchors", "schema_version"}
    assert compatibility["schema_version"] == ("dynamic-cssc-evidence-compatibility-anchor-set-v1")
    assert type(compatibility["anchors"]) is list

    registration_bytes = (REPOSITORY_ROOT / DAY1_REGISTRATION_ANCHOR_PATH).read_bytes()
    registration = json.loads(registration_bytes)
    assert _canonical(registration).encode("ascii") == registration_bytes
    assert set(registration) == {"anchors", "schema_version"}
    assert registration["schema_version"] == ("dynamic-cssc-day1-registration-anchor-set-v1")
    assert type(registration["anchors"]) is list
    assert len(registration["anchors"]) <= 1

    strong_anchor_bytes = (REPOSITORY_ROOT / STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH).read_bytes()
    strong_anchor = json.loads(strong_anchor_bytes)
    assert _canonical(strong_anchor).encode("ascii") == strong_anchor_bytes
    assert set(strong_anchor) == {"anchors", "schema_version"}
    assert strong_anchor["schema_version"] == (
        "dynamic-cssc-strong-reference-evidence-anchor-set-v1"
    )
    assert len(strong_anchor["anchors"]) == 1


@pytest.mark.parametrize("mutation", ("executable", "symlink"))
def test_behavior_entry_mode_or_symlink_change_is_not_compatible(
    trace_repository: tuple[Path, str, dict[str, object]],
    mutation: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    behavior_path = repository / "src/dynamic_cssc/publication_traces.py"
    if mutation == "executable":
        behavior_path.chmod(0o755)
    else:
        behavior_path.unlink()
        behavior_path.symlink_to("publication_statistics.py")
    changed_sha = _commit(repository, f"{mutation} behavior drift")

    with pytest.raises(EvidenceCompatibilityError, match="Behavior Set"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=changed_sha,
            analysis_source_git_sha=changed_sha,
            artifact_sha256="c" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_nonbehavior_extra_drift_is_not_accepted_by_name_or_ancestry(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "d" * 64
    _write_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256=artifact_sha256,
        inventory=inventory,
    )
    _write(repository, "README.md", "unallowlisted drift\n")
    evidence_freeze_sha = _commit(repository, "anchor plus extra drift")

    with pytest.raises(EvidenceCompatibilityError, match="extra drift.*README"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_empty_anchor_set_rejects_different_snapshot_shas(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    _git(repository, "commit", "--allow-empty", "-qm", "later snapshot without anchor")
    later_sha = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(EvidenceCompatibilityError, match="post-run artifact anchor is absent"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=later_sha,
            analysis_source_git_sha=later_sha,
            artifact_sha256="e" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_evidence_freeze_must_be_an_ancestor_of_current_analysis(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    evidence_freeze_sha = _install_trace_anchor(
        repository,
        experiment_sha=experiment_sha,
        artifact_sha256="f" * 64,
        inventory=inventory,
    )
    _git(repository, "checkout", "-q", "-b", "unrelated-analysis", experiment_sha)
    _git(repository, "commit", "--allow-empty", "-qm", "sibling analysis")
    analysis_sha = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(EvidenceCompatibilityError, match="evidence-freeze.*ancestor"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=analysis_sha,
            artifact_sha256="f" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_git_replace_refs_are_rejected_even_though_git_object_reads_disable_them(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    _git(repository, "commit", "--allow-empty", "-qm", "replacement target")
    replacement_sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "replace", experiment_sha, replacement_sha)

    with pytest.raises(EvidenceCompatibilityError, match="replacement refs are forbidden"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=replacement_sha,
            evidence_freeze_git_sha=replacement_sha,
            analysis_source_git_sha=replacement_sha,
            artifact_sha256="1" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_git_dir_environment_cannot_retarget_repository_object_reads(
    trace_repository: tuple[Path, str, dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    _git(attacker, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(attacker / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(attacker))

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=experiment_sha,
        analysis_source_git_sha=experiment_sha,
        artifact_sha256="2" * 64,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )

    assert receipt.experiment_source_git_sha == experiment_sha


def test_commit_names_are_not_accepted_in_place_of_exact_object_ids(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository

    with pytest.raises(EvidenceCompatibilityError, match="exact lowercase 40-digit"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha="HEAD",
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=experiment_sha,
            artifact_sha256="3" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_anchor_cannot_self_mint_with_an_evidence_freeze_sha_field(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    artifact_sha256 = "4" * 64
    anchor = {
        "artifact_sha256": artifact_sha256,
        "behavior_set_schema_version": inventory["behavior_set_schema_version"],
        "behavior_set_sha256": inventory["behavior_set_sha256"],
        "evidence_freeze_git_sha": "0" * 40,
        "experiment_source_git_sha": experiment_sha,
        "role": "trace",
        "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
    }
    _write(
        repository,
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
        _canonical(
            {
                "anchors": [anchor],
                "schema_version": "dynamic-cssc-evidence-compatibility-anchor-set-v1",
            }
        ),
    )
    evidence_freeze_sha = _commit(repository, "self-referential anchor attempt")

    with pytest.raises(EvidenceCompatibilityError, match="anchor 0 keys must be exact"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=evidence_freeze_sha,
            analysis_source_git_sha=evidence_freeze_sha,
            artifact_sha256=artifact_sha256,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_identity_receipt_is_not_a_post_run_authority_capability(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=experiment_sha,
        analysis_source_git_sha=experiment_sha,
        artifact_sha256="5" * 64,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )

    with pytest.raises(TypeError, match="repository verification"):
        EvidenceCompatibilityReceipt()
    assert not hasattr(receipt, "validate_compatibility_for_analysis")


@pytest.mark.parametrize("field", ("role", "schema_version"))
def test_artifact_inventory_role_and_schema_must_exactly_match_repository_set(
    trace_repository: tuple[Path, str, dict[str, object]],
    field: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    forged_inventory = deepcopy(inventory)
    forged_inventory[field] = "day2" if field == "role" else "invented-schema-v99"

    with pytest.raises(EvidenceCompatibilityError, match="artifact behavior inventory"):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=experiment_sha,
            artifact_sha256="6" * 64,
            artifact_behavior_inventory=forged_inventory,
            repository_root=repository,
        )


@pytest.mark.parametrize("index_flag", ("--assume-unchanged", "--skip-worktree"))
def test_index_flags_cannot_hide_modified_analysis_code(
    trace_repository: tuple[Path, str, dict[str, object]],
    index_flag: str,
) -> None:
    repository, experiment_sha, inventory = trace_repository
    analysis_path = repository / "src/dynamic_cssc/publication_statistics.py"
    relative_path = str(analysis_path.relative_to(repository))
    if index_flag == "--skip-worktree":
        _git(repository, "update-index", index_flag, relative_path)
    analysis_path.write_text("uncommitted analyzer replacement\n", encoding="utf-8")
    if index_flag == "--assume-unchanged":
        _git(repository, "update-index", index_flag, relative_path)
    assert _git(repository, "status", "--porcelain=v1") == ""

    with pytest.raises(
        EvidenceCompatibilityError,
        match="index flags|differs from current HEAD",
    ):
        verify_evidence_compatibility(
            role=EvidenceRole.TRACE,
            experiment_source_git_sha=experiment_sha,
            evidence_freeze_git_sha=experiment_sha,
            analysis_source_git_sha=experiment_sha,
            artifact_sha256="7" * 64,
            artifact_behavior_inventory=inventory,
            repository_root=repository,
        )


def test_ignored_runtime_injection_never_upgrades_runtime_isolation(
    trace_repository: tuple[Path, str, dict[str, object]],
) -> None:
    repository, experiment_sha, inventory = trace_repository
    (repository / "sitecustomize.py").write_text("raise SystemExit('injected')\n", encoding="utf-8")
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""

    receipt = verify_evidence_compatibility(
        role=EvidenceRole.TRACE,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=experiment_sha,
        analysis_source_git_sha=experiment_sha,
        artifact_sha256="8" * 64,
        artifact_behavior_inventory=inventory,
        repository_root=repository,
    )

    assert receipt.runtime_execution_isolation_verified is False
    document = receipt.to_document()
    assert document["formal_authority_granted"] is False
    assert document["runtime_execution_isolation_receipt_schema_version"] == (
        "dynamic-cssc-runtime-execution-isolation-receipt-v1"
    )
    assert document["runtime_execution_isolation_required_checks"] == [
        "fresh-detached-checkout",
        "user-site-and-caller-pythonpath-disabled",
        "isolated-bytecode-cache-no-pth-sitecustomize",
        "exact-cpython-3.12.13",
        "hash-locked-wheel-set",
        "exact-import-origins-and-byte-hashes",
        "exact-analysis-invocation",
        "source-attestation-before-decode",
        "source-attestation-after-analysis",
        "source-attestation-after-render-and-atomic-install",
    ]


def test_shallow_repository_cannot_claim_complete_ancestry(
    trace_repository: tuple[Path, str, dict[str, object]],
    tmp_path: Path,
) -> None:
    repository, experiment_sha, _inventory = trace_repository
    shallow = tmp_path / "shallow"
    subprocess.run(
        ("git", "clone", "-q", "--depth", "1", f"file://{repository}", str(shallow)),
        check=True,
    )

    with pytest.raises(EvidenceCompatibilityError, match="shallow"):
        capture_behavior_inventory(
            EvidenceRole.TRACE,
            source_git_sha=experiment_sha,
            repository_root=shallow,
        )
