from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from dynamic_cssc.followup_performance_lineage import (
    FOLLOWUP_BEHAVIOR_ROLES,
    FOLLOWUP_REGISTRATION_ANCHOR_PATH,
    FollowupLineageError,
    build_followup_registration_anchor,
    capture_followup_behavior_inventory,
    inspect_followup_registration_archive,
    produce_followup_registration_archive,
    verify_followup_s1_s2_compatibility,
    verify_followup_s1_s2_s3_analysis_compatibility,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = (tmp_path / "repository").resolve()
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Followup Test")
    _git(repository, "config", "user.email", "followup@example.invalid")
    stage1 = repository / "stage1.txt"
    stage1.write_text("frozen-stage1\n", encoding="ascii")
    roles: dict[str, object] = {}
    for role in FOLLOWUP_BEHAVIOR_ROLES:
        path = f"role-files/{role}.txt"
        target = repository / path
        target.parent.mkdir(exist_ok=True)
        target.write_text(f"{role}-behavior\n", encoding="ascii")
        roles[role] = {
            "paths": sorted(
                [
                    "config/followup-performance-behavior-sets.json",
                    path,
                ]
            ),
            "schema_version": (
                f"dynamic-cssc-followup-performance-{role}-behavior-set-v1"
            ),
        }
    config = repository / "config"
    config.mkdir()
    registry = {
        "roles": roles,
        "schema_version": (
            "dynamic-cssc-followup-performance-behavior-set-registry-v1"
        ),
        "stage1_documents": {
            "stage1.txt": hashlib.sha256(stage1.read_bytes()).hexdigest()
        },
    }
    (config / "followup-performance-behavior-sets.json").write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    (repository / FOLLOWUP_REGISTRATION_ANCHOR_PATH).write_text(
        '{"anchors":[],"schema_version":'
        '"dynamic-cssc-followup-performance-registration-anchor-set-v1"}\n',
        encoding="ascii",
    )
    s1 = _commit(repository, "followup S1")
    anchor = build_followup_registration_anchor(repository, s1=s1)
    (repository / FOLLOWUP_REGISTRATION_ANCHOR_PATH).write_bytes(anchor)
    s2 = _commit(repository, "followup S2 data anchor")
    return repository, s1, s2


def test_followup_s1_s2_registration_round_trip_is_deterministic(
    tmp_path: Path,
) -> None:
    repository, s1, s2 = _repository(tmp_path)

    receipt = verify_followup_s1_s2_compatibility(repository, s1=s1, s2=s2)
    archive = produce_followup_registration_archive(repository, s1=s1, s2=s2)
    inspection = inspect_followup_registration_archive(
        repository,
        s1=s1,
        s2=s2,
        archive_bytes=archive.archive_bytes,
    )

    assert receipt.document["compatibility_verified"] is True
    assert receipt.document["formal_execution_authorized"] is False
    assert archive.compatibility_receipt_sha256 == receipt.sha256
    assert archive.archive_sha256 == inspection.archive_sha256
    assert archive.artifact_name == inspection.artifact_name
    assert archive.artifact_name.startswith(
        "followup-performance-v1-control-registration-"
    )
    assert inspection.envelope.document["experiment_source_S1_sha"] == s1
    assert inspection.envelope.document["evidence_freeze_S2_sha"] == s2
    assert inspection.envelope.document["authority"] is False


def test_followup_data_only_s2_anchor_is_not_a_behavior_path() -> None:
    registry = json.loads(
        (REPOSITORY_ROOT / "config/followup-performance-behavior-sets.json").read_text(
            encoding="ascii"
        )
    )

    assert all(
        FOLLOWUP_REGISTRATION_ANCHOR_PATH not in role["paths"]
        for role in registry["roles"].values()
    )


def test_followup_production_registry_accepts_data_only_s2_round_trip(
    tmp_path: Path,
) -> None:
    repository = (tmp_path / "production-registry-repository").resolve()
    subprocess.run(
        (
            "git",
            "clone",
            "--quiet",
            "--shared",
            str(REPOSITORY_ROOT),
            str(repository),
        ),
        check=True,
    )
    _git(repository, "config", "user.name", "Followup Test")
    _git(repository, "config", "user.email", "followup@example.invalid")
    registry_path = "config/followup-performance-behavior-sets.json"
    (repository / registry_path).write_bytes(
        (REPOSITORY_ROOT / registry_path).read_bytes()
    )
    (repository / FOLLOWUP_REGISTRATION_ANCHOR_PATH).write_text(
        '{"anchors":[],"schema_version":'
        '"dynamic-cssc-followup-performance-registration-anchor-set-v1"}\n',
        encoding="ascii",
    )
    _git(repository, "add", registry_path, FOLLOWUP_REGISTRATION_ANCHOR_PATH)
    _git(repository, "commit", "--allow-empty", "-m", "synthetic production S1")
    s1 = _git(repository, "rev-parse", "HEAD")
    (repository / FOLLOWUP_REGISTRATION_ANCHOR_PATH).write_bytes(
        build_followup_registration_anchor(repository, s1=s1)
    )
    s2 = _commit(repository, "synthetic production S2")

    receipt = verify_followup_s1_s2_compatibility(repository, s1=s1, s2=s2)

    assert receipt.document["changed_paths"] == [FOLLOWUP_REGISTRATION_ANCHOR_PATH]
    assert receipt.document["compatibility_verified"] is True
    assert receipt.document["formal_execution_authorized"] is False


def test_followup_behavior_inventory_is_exact_git_object_not_worktree(
    tmp_path: Path,
) -> None:
    repository, s1, _s2 = _repository(tmp_path)
    before = capture_followup_behavior_inventory(repository, s1, "qualification")
    (repository / "role-files/qualification.txt").write_text(
        "uncommitted-substitution\n",
        encoding="ascii",
    )

    after = capture_followup_behavior_inventory(repository, s1, "qualification")

    assert before == after


@pytest.mark.parametrize("role", FOLLOWUP_BEHAVIOR_ROLES)
def test_followup_behavior_set_closes_python_imports_and_native_build_inputs(
    role: str,
) -> None:
    registry = json.loads(
        (REPOSITORY_ROOT / "config/followup-performance-behavior-sets.json").read_text(
            encoding="ascii"
        )
    )
    role_paths = set(registry["roles"][role]["paths"])
    stack = [
        Path(path)
        for path in role_paths
        if path.endswith(".py")
        and (path.startswith("scripts/") or path.startswith("src/"))
    ]
    visited: set[Path] = set()
    while stack:
        relative = stack.pop()
        if relative in visited:
            continue
        visited.add(relative)
        tree = ast.parse((REPOSITORY_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                modules = (node.module,)
            else:
                continue
            for module in modules:
                imported: Path | None = None
                if module.startswith("dynamic_cssc."):
                    imported = Path("src") / Path(module.replace(".", "/")).with_suffix(
                        ".py"
                    )
                elif module.startswith("scripts."):
                    imported = Path(module.replace(".", "/")).with_suffix(".py")
                if imported is not None and (REPOSITORY_ROOT / imported).is_file():
                    assert imported.as_posix() in role_paths
                    stack.append(imported)

    native_build_inputs = {
        "config/params_manifest.json",
        "cpp/CMakeLists.txt",
        "cpp/include/args.hpp",
        "cpp/microbench.cpp",
        "cpp/openfhe_query_runner.cpp",
        "cpp/rotation_probe.cpp",
        "cpp/strong_packed_coo_witness.cpp",
        "cpp/strong_whole_query_witness.cpp",
        "scripts/bootstrap_openfhe.sh",
        "scripts/build_cpp.sh",
    }
    if role == "formal":
        assert native_build_inputs <= role_paths


def test_followup_behavior_registry_covers_every_followup_owned_behavior_path() -> None:
    """An orphan follow-up workflow, action, script, or module must fail CI."""

    registry = json.loads(
        (REPOSITORY_ROOT / "config/followup-performance-behavior-sets.json").read_text(
            encoding="ascii"
        )
    )
    registered = {
        path
        for role in registry["roles"].values()
        for path in role["paths"]
    }
    candidates = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for pattern in (
            ".github/workflows/followup-performance-*.yml",
            ".github/actions/followup-*/action.yml",
            "src/dynamic_cssc/followup_performance_*.py",
            "scripts/*followup_performance*.py",
            "scripts/verify_followup_*.py",
        )
        for path in REPOSITORY_ROOT.glob(pattern)
        if path.is_file()
    }

    assert candidates - registered == set()


def test_followup_registration_rejects_dirty_or_non_exact_s2_checkout(
    tmp_path: Path,
) -> None:
    repository, s1, s2 = _repository(tmp_path)
    (repository / "untracked.txt").write_text("dirty\n", encoding="ascii")

    with pytest.raises(FollowupLineageError, match="clean exact-S2"):
        produce_followup_registration_archive(repository, s1=s1, s2=s2)


def test_followup_s2_rejects_a_predecessor_or_extra_anchor_shape(
    tmp_path: Path,
) -> None:
    repository, s1, _s2 = _repository(tmp_path)
    _git(repository, "checkout", "--detach", s1)
    (repository / FOLLOWUP_REGISTRATION_ANCHOR_PATH).write_text(
        '{"anchors":[],"schema_version":'
        '"dynamic-cssc-route-a-registration-anchor-set-v1"}\n',
        encoding="ascii",
    )
    invalid_s2 = _commit(repository, "predecessor anchor")

    with pytest.raises(FollowupLineageError, match="differs from exact S1"):
        verify_followup_s1_s2_compatibility(repository, s1=s1, s2=invalid_s2)


def test_followup_analysis_requires_one_empty_direct_s3_with_exact_analyzer(
    tmp_path: Path,
) -> None:
    repository, s1, s2 = _repository(tmp_path)
    _git(repository, "commit", "--allow-empty", "-m", "follow-up analysis S3")
    s3 = _git(repository, "rev-parse", "HEAD")

    receipt = verify_followup_s1_s2_s3_analysis_compatibility(
        repository,
        s1=s1,
        s2=s2,
        s3=s3,
    )

    assert receipt.document["analysis_compatibility_verified"] is True
    assert receipt.document["analyzer_behavior_set_exact"] is True
    assert receipt.document["analysis_source_S3_sha"] == s3
    assert receipt.document["analysis_execution_authorized"] is False
    assert receipt.document["s2_to_s3_changed_paths"] == []


def test_followup_analysis_rejects_changed_or_nondirect_s3(tmp_path: Path) -> None:
    repository, s1, s2 = _repository(tmp_path)
    (repository / "outcome-informed.txt").write_text("forbidden\n", encoding="ascii")
    changed_s3 = _commit(repository, "changed S3")
    with pytest.raises(FollowupLineageError, match="direct empty child"):
        verify_followup_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=changed_s3,
        )

    _git(repository, "checkout", "--detach", s2)
    _git(repository, "commit", "--allow-empty", "-m", "empty intermediate")
    _git(repository, "commit", "--allow-empty", "-m", "too-deep S3")
    deep_s3 = _git(repository, "rev-parse", "HEAD")
    with pytest.raises(FollowupLineageError, match="direct empty child"):
        verify_followup_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=deep_s3,
        )
