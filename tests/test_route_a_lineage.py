from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dynamic_cssc.route_a_lineage import (
    ROUTE_A_BEHAVIOR_ROLES,
    ROUTE_A_REGISTRATION_ANCHOR_PATH,
    RouteALineageError,
    build_route_a_registration_anchor,
    capture_route_a_behavior_inventory,
    inspect_route_a_registration_archive,
    produce_route_a_registration_archive,
    verify_route_a_s1_s2_compatibility,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="ascii")


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(
        repository,
        "-c",
        "user.name=Route A Test",
        "-c",
        "user.email=route-a@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _write(repository / "behavior.py", "VALUE = 1\n")
    _write(repository / "analyzer.py", "VALUE = 2\n")
    plan_bytes = b'{"schema_version":"p"}\n'
    (repository / "config").mkdir(parents=True, exist_ok=True)
    (repository / "config/route-a-publication-plan.json").write_bytes(plan_bytes)
    _write(
        repository / ROUTE_A_REGISTRATION_ANCHOR_PATH,
        '{"anchors":[],"schema_version":"dynamic-cssc-route-a-registration-anchor-set-v1"}\n',
    )
    roles = {
        role: {
            "paths": [
                "behavior.py" if role != "analyzer" else "analyzer.py",
                "config/route-a-behavior-sets.json",
                "config/route-a-publication-plan.json",
            ],
            "schema_version": f"dynamic-cssc-route-a-{role}-behavior-set-v1",
        }
        for role in ROUTE_A_BEHAVIOR_ROLES
    }
    _write(
        repository / "config/route-a-behavior-sets.json",
        json.dumps(
            {
                "roles": roles,
                "schema_version": "dynamic-cssc-route-a-behavior-set-registry-v1",
                "stage1_documents": {
                    "config/route-a-publication-plan.json": hashlib.sha256(plan_bytes).hexdigest()
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    return repository, _commit(repository, "S1")


def test_capture_inventory_reads_exact_git_objects_and_is_repeatable(tmp_path: Path) -> None:
    repository, s1 = _repository(tmp_path)

    first = capture_route_a_behavior_inventory(repository, s1, "formal")
    second = capture_route_a_behavior_inventory(repository, s1, "formal")

    assert first.document_bytes == second.document_bytes
    assert first.sha256 == hashlib.sha256(first.document_bytes).hexdigest()
    assert first.document["role"] == "formal"
    assert first.document["source_git_sha"] == s1
    assert [entry["path"] for entry in first.document["entries"]] == [
        "behavior.py",
        "config/route-a-behavior-sets.json",
        "config/route-a-publication-plan.json",
    ]
    assert all(entry["mode"] == "100644" for entry in first.document["entries"])
    assert all(entry["type"] == "blob" for entry in first.document["entries"])


def test_capture_ignores_worktree_bytes_but_registration_requires_clean_head(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    before = capture_route_a_behavior_inventory(repository, s1, "formal")
    _write(repository / "behavior.py", "VALUE = 999\n")

    after = capture_route_a_behavior_inventory(repository, s1, "formal")
    assert after.document_bytes == before.document_bytes
    with pytest.raises(RouteALineageError, match="clean exact S1"):
        produce_route_a_registration_archive(repository, s1)


def test_registration_archive_is_deterministic_and_independently_reinspected(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)

    first = produce_route_a_registration_archive(repository, s1)
    second = produce_route_a_registration_archive(repository, s1)
    inspection = inspect_route_a_registration_archive(repository, s1, first.archive_bytes)

    assert first.archive_bytes == second.archive_bytes
    assert first.archive_sha256 == second.archive_sha256
    assert inspection.archive_sha256 == first.archive_sha256
    assert inspection.registration_evidence_sha256 == first.registration_evidence_sha256
    assert inspection.formal_authority_granted is False
    assert set(inspection.behavior_inventory_sha256) == set(ROUTE_A_BEHAVIOR_ROLES)


def test_registration_reinspection_rejects_archive_tampering(tmp_path: Path) -> None:
    repository, s1 = _repository(tmp_path)
    archive = produce_route_a_registration_archive(repository, s1).archive_bytes
    tampered = archive[:-1] + bytes([archive[-1] ^ 1])

    with pytest.raises(RouteALineageError, match="archive"):
        inspect_route_a_registration_archive(repository, s1, tampered)


def test_registration_cli_produces_and_reinspects_without_installing_anchor(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    archive = tmp_path / "registration.zip"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.fspath(REPOSITORY_ROOT / "src")

    producer = subprocess.run(
        [
            sys.executable,
            os.fspath(REPOSITORY_ROOT / "scripts/produce_route_a_registration.py"),
            "--repository-root",
            os.fspath(repository),
            "--expected-s1",
            s1,
            "--output",
            os.fspath(archive),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    inspector = subprocess.run(
        [
            sys.executable,
            os.fspath(REPOSITORY_ROOT / "scripts/verify_route_a_registration.py"),
            "--repository-root",
            os.fspath(repository),
            "--expected-s1",
            s1,
            "--archive",
            os.fspath(archive),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )

    produced = json.loads(producer.stdout)
    inspected = json.loads(inspector.stdout)
    assert produced["archive_sha256"] == inspected["archive_sha256"]
    assert produced["formal_authority_granted"] is False
    assert inspected["repository_anchor_installed"] is False


def test_s1_s2_compatibility_accepts_only_the_reviewed_data_anchor(tmp_path: Path) -> None:
    repository, s1 = _repository(tmp_path)
    registration = produce_route_a_registration_archive(repository, s1)
    inspection = inspect_route_a_registration_archive(repository, s1, registration.archive_bytes)
    anchor_bytes = build_route_a_registration_anchor(
        inspection,
        provider_run_id=123,
        provider_artifact_id=456,
        provider_artifact_digest="sha256:" + "a" * 64,
    )
    (repository / ROUTE_A_REGISTRATION_ANCHOR_PATH).write_bytes(anchor_bytes)
    s2 = _commit(repository, "S2")

    receipt = verify_route_a_s1_s2_compatibility(repository, s1=s1, s2=s2)

    assert receipt.document["compatibility_verified"] is True
    assert receipt.document["formal_authority_granted"] is False
    assert receipt.document["experiment_source_git_sha"] == s1
    assert receipt.document["evidence_freeze_git_sha"] == s2
    assert receipt.document["changed_paths"] == [ROUTE_A_REGISTRATION_ANCHOR_PATH]
    assert receipt.sha256 == hashlib.sha256(receipt.document_bytes).hexdigest()


def test_s1_s2_compatibility_rejects_extra_source_change(tmp_path: Path) -> None:
    repository, s1 = _repository(tmp_path)
    registration = produce_route_a_registration_archive(repository, s1)
    inspection = inspect_route_a_registration_archive(repository, s1, registration.archive_bytes)
    (repository / ROUTE_A_REGISTRATION_ANCHOR_PATH).write_bytes(
        build_route_a_registration_anchor(
            inspection,
            provider_run_id=123,
            provider_artifact_id=456,
            provider_artifact_digest="sha256:" + "a" * 64,
        )
    )
    _write(repository / "behavior.py", "VALUE = 2\n")
    s2 = _commit(repository, "bad S2")

    with pytest.raises(RouteALineageError, match="only the registration anchor"):
        verify_route_a_s1_s2_compatibility(repository, s1=s1, s2=s2)


def test_s1_s2_compatibility_rejects_non_parent_or_empty_anchor(tmp_path: Path) -> None:
    repository, s1 = _repository(tmp_path)
    _write(repository / "unrelated", "data\n")
    s2 = _commit(repository, "not an S2")

    with pytest.raises(RouteALineageError):
        verify_route_a_s1_s2_compatibility(repository, s1=s1, s2=s2)


@pytest.mark.parametrize("role", ["", "FORMAL", "unknown", True])
def test_capture_rejects_caller_invented_roles(tmp_path: Path, role: object) -> None:
    repository, s1 = _repository(tmp_path)
    with pytest.raises((TypeError, RouteALineageError)):
        capture_route_a_behavior_inventory(repository, s1, role)  # type: ignore[arg-type]
