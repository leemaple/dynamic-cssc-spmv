from __future__ import annotations

import ast
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
    verify_route_a_s1_s2_s3_analysis_compatibility,
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


def _empty_commit(repository: Path, message: str) -> str:
    _git(
        repository,
        "-c",
        "user.name=Route A Test",
        "-c",
        "user.email=route-a@example.invalid",
        "commit",
        "--allow-empty",
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
                "schema_version": "dynamic-cssc-route-a-behavior-set-registry-v3",
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


def test_current_head_registry_is_capturable_for_qualification() -> None:
    head = _git(REPOSITORY_ROOT, "rev-parse", "HEAD")

    inventory = capture_route_a_behavior_inventory(
        REPOSITORY_ROOT,
        head,
        "qualification",
    )

    assert inventory.document["source_git_sha"] == head
    assert inventory.document["role"] == "qualification"
    assert inventory.sha256 == hashlib.sha256(inventory.document_bytes).hexdigest()


def test_route_a_registered_validation_tests_are_frozen() -> None:
    registry = json.loads(
        (REPOSITORY_ROOT / "config/route-a-behavior-sets.json").read_text(
            encoding="ascii"
        )
    )
    qualification = set(registry["roles"]["qualification"]["paths"])
    route_a_tests = {
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in (REPOSITORY_ROOT / "tests").glob("test_route_a_*.py")
    }
    route_a_tests.add("tests/test_run_route_a_native_qualification.py")
    proof_boundary_tests = {
        "tests/test_cloud_execution_plan.py",
        "tests/test_cssc.py",
        "tests/test_ordinary_query_lifecycle.py",
        "tests/test_output_plan.py",
        "tests/test_plaintext_oracle.py",
        "tests/test_query_compiler.py",
        "tests/test_strong_execution_bundle.py",
        "tests/test_strong_output_plan.py",
        "tests/test_strong_packed_coo_state.py",
        "tests/test_strong_packed_coo_witness_contract.py",
    }
    assert route_a_tests | proof_boundary_tests <= qualification
    control = set(registry["roles"]["control-registration"]["paths"])
    assert {
        "tests/test_route_a_controller.py",
        "tests/test_route_a_controller_github.py",
        "tests/test_route_a_lineage.py",
        "tests/test_route_a_live_stop_loss.py",
    } <= control


@pytest.mark.parametrize("role", ROUTE_A_BEHAVIOR_ROLES)
def test_route_a_behavior_set_closes_dynamic_cssc_imports(role: str) -> None:
    registry = json.loads(
        (REPOSITORY_ROOT / "config/route-a-behavior-sets.json").read_text(
            encoding="ascii"
        )
    )
    registered = set(registry["roles"][role]["paths"])
    pending = [path for path in registered if path.endswith(".py")]
    inspected: set[str] = set()

    def repository_module_path(base: Path) -> str | None:
        for candidate in (base.with_suffix(".py"), base / "__init__.py"):
            relative = candidate.as_posix()
            if (REPOSITORY_ROOT / relative).is_file():
                return relative
        return None

    while pending:
        path = pending.pop()
        if path in inspected:
            continue
        inspected.add(path)
        tree = ast.parse((REPOSITORY_ROOT / path).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "dynamic_cssc" or alias.name.startswith(
                        "dynamic_cssc."
                    ):
                        dependency = repository_module_path(
                            Path("src") / Path(*alias.name.split("."))
                        )
                        if dependency is not None:
                            imported.add(dependency)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = Path(path).parent
                    for _ in range(node.level - 1):
                        base = base.parent
                    if node.module is not None:
                        dependency = repository_module_path(
                            base / Path(*node.module.split("."))
                        )
                        if dependency is not None:
                            imported.add(dependency)
                    else:
                        for alias in node.names:
                            dependency = repository_module_path(base / alias.name)
                            if dependency is not None:
                                imported.add(dependency)
                elif node.module == "dynamic_cssc" or (
                    node.module is not None
                    and node.module.startswith("dynamic_cssc.")
                ):
                    dependency = repository_module_path(
                        Path("src") / Path(*node.module.split("."))
                    )
                    if dependency is not None:
                        imported.add(dependency)
        for dependency in imported:
            assert dependency in registered, (
                f"{role} Behavior Set omits imported module {dependency} "
                f"required by {path}"
            )
            pending.append(dependency)


def _install_s2(repository: Path, s1: str) -> str:
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
    return _commit(repository, "S2")


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


def test_s1_s2_s3_analysis_compatibility_binds_all_three_snapshots(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    s3 = _empty_commit(repository, "S3 analysis snapshot")

    receipt = verify_route_a_s1_s2_s3_analysis_compatibility(
        repository,
        s1=s1,
        s2=s2,
        s3=s3,
    )

    assert receipt.document["analysis_compatibility_verified"] is True
    assert receipt.document["experiment_source_git_sha"] == s1
    assert receipt.document["evidence_freeze_git_sha"] == s2
    assert receipt.document["analysis_source_git_sha"] == s3
    assert receipt.document["analyzer_behavior_set_exact"] is True
    assert receipt.document["analysis_execution_authorized"] is False
    assert receipt.document["runtime_execution_isolation_verified"] is False
    assert receipt.document["formal_authority_granted"] is False
    assert receipt.document["registration_compatibility_receipt_sha256"] == (
        verify_route_a_s1_s2_compatibility(repository, s1=s1, s2=s2).sha256
    )
    assert receipt.sha256 == hashlib.sha256(receipt.document_bytes).hexdigest()


@pytest.mark.parametrize("mutation", ["bytes", "mode"])
def test_s1_s2_s3_analysis_compatibility_rejects_analyzer_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    if mutation == "bytes":
        _write(repository / "analyzer.py", "VALUE = 999\n")
    else:
        (repository / "analyzer.py").chmod(0o755)
    s3 = _commit(repository, "drifted S3")

    with pytest.raises(RouteALineageError, match="analyzer Behavior Set changed"):
        verify_route_a_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=s3,
        )


def test_s1_s2_s3_analysis_compatibility_rejects_non_descendant_s3(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    _git(repository, "checkout", "-q", s1)
    s3 = _empty_commit(repository, "unrelated S3")

    with pytest.raises(RouteALineageError, match="descend from exact S2"):
        verify_route_a_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=s3,
        )


def test_s1_s2_s3_analysis_compatibility_rejects_removed_s2_anchor(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    (repository / ROUTE_A_REGISTRATION_ANCHOR_PATH).unlink()
    s3 = _commit(repository, "removed S2 anchor")

    with pytest.raises(RouteALineageError, match="data-only history"):
        verify_route_a_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=s3,
        )


def test_s1_s2_s3_analysis_compatibility_rejects_intermediate_drift_then_restore(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    _write(repository / "behavior.py", "VALUE = 999\n")
    _commit(repository, "intermediate behavior drift")
    _write(repository / "behavior.py", "VALUE = 1\n")
    s3 = _commit(repository, "restored endpoint bytes")

    with pytest.raises(RouteALineageError, match="data-only history"):
        verify_route_a_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=s3,
        )


def test_s1_s2_s3_analysis_compatibility_rejects_drift_restored_on_merged_parent(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    s2_branch = _git(repository, "branch", "--show-current")
    _git(repository, "checkout", "-q", "-b", "outside-history", s1)
    _write(repository / "behavior.py", "VALUE = 999\n")
    _commit(repository, "outside behavior drift")
    _write(repository / "behavior.py", "VALUE = 1\n")
    _commit(repository, "outside endpoint restore")
    _git(repository, "checkout", "-q", s2_branch)
    _git(
        repository,
        "-c",
        "user.name=Route A Test",
        "-c",
        "user.email=route-a@example.invalid",
        "merge",
        "--no-ff",
        "outside-history",
        "-m",
        "merge restored outside history",
    )
    s3 = _git(repository, "rev-parse", "HEAD")

    with pytest.raises(RouteALineageError, match="data-only history"):
        verify_route_a_s1_s2_s3_analysis_compatibility(
            repository,
            s1=s1,
            s2=s2,
            s3=s3,
        )


def test_s1_s2_s3_analysis_compatibility_allows_monotonic_data_anchor_addition(
    tmp_path: Path,
) -> None:
    repository, s1 = _repository(tmp_path)
    s2 = _install_s2(repository, s1)
    _write(
        repository / "config/evidence-compatibility-anchors.json",
        json.dumps(
            {
                "anchors": [
                    {
                        "artifact_sha256": "b" * 64,
                        "behavior_set_schema_version": (
                            "dynamic-cssc-acquisition-behavior-set-v2"
                        ),
                        "behavior_set_sha256": "c" * 64,
                        "experiment_source_git_sha": s1,
                        "role": "acquisition",
                        "schema_version": (
                            "dynamic-cssc-evidence-compatibility-anchor-v1"
                        ),
                    }
                ],
                "schema_version": (
                    "dynamic-cssc-evidence-compatibility-anchor-set-v1"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    s3 = _commit(repository, "append monotonic data anchor")

    receipt = verify_route_a_s1_s2_s3_analysis_compatibility(
        repository,
        s1=s1,
        s2=s2,
        s3=s3,
    )

    assert receipt.document["analysis_compatibility_verified"] is True
    assert receipt.document["s2_to_s3_changed_paths"] == [
        "config/evidence-compatibility-anchors.json"
    ]


@pytest.mark.parametrize("role", ["", "FORMAL", "unknown", True])
def test_capture_rejects_caller_invented_roles(tmp_path: Path, role: object) -> None:
    repository, s1 = _repository(tmp_path)
    with pytest.raises((TypeError, RouteALineageError)):
        capture_route_a_behavior_inventory(repository, s1, role)  # type: ignore[arg-type]
