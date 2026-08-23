from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import dynamic_cssc.evidence_compatibility as compatibility
import dynamic_cssc.publication_runtime as runtime
from dynamic_cssc.evidence_compatibility import (
    EvidenceCompatibilityError,
    EvidenceRole,
    RuntimeAdmissionCapability,
    admit_isolated_publication_run,
    repository_behavior_paths,
)
from dynamic_cssc.publication_runtime import (
    RUNTIME_AUTHORITY_HOLD,
    RUNTIME_RECEIPT_FILENAME,
    RUNTIME_RECEIPT_SCHEMA,
    RUNTIME_RECEIPT_SHA_FILENAME,
    PublicationRuntimeError,
    PublicationRuntimeHold,
    PublicationRuntimeReceipt,
    run_publication_analysis_isolated,
)

_ROOT = Path(__file__).resolve().parents[1]
_POLICY = json.loads((_ROOT / "config/publication-runtime-policy.json").read_bytes())
_FIXTURE_HASH = "a" * 64
_FIXTURE_LOCK = f"fixture==1.0 \\\n    --hash=sha256:{_FIXTURE_HASH}\n"
_FIXTURE_ANALYZER = """\
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--input", required=True, type=Path)
parser.add_argument("--input-sha256", required=True)
parser.add_argument("--output-dir", required=True, type=Path)
args = parser.parse_args()
args.output_dir.mkdir()
files = {
    "publication-effects.csv": b"effect\\n",
    "publication-summary.csv": b"summary\\n",
    "publication-verdict.json": b"{}\\n",
    "SHA256SUMS": b"fixture\\n",
}
for name, content in files.items():
    (args.output_dir / name).write_bytes(content)
receipt = {
    "artifact_sha256": {
        name: hashlib.sha256(content).hexdigest()
        for name, content in files.items()
    },
    "input_path": str(args.input),
    "input_sha256": args.input_sha256,
    "output_dir": str(args.output_dir),
    "schema_version": "dynamic-cssc-publication-analysis-cli-receipt-v1",
}
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
"""


def _git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {
        "GIT_AUTHOR_EMAIL": "runtime@example.invalid",
        "GIT_AUTHOR_NAME": "Runtime Fixture",
        "GIT_COMMITTER_EMAIL": "runtime@example.invalid",
        "GIT_COMMITTER_NAME": "Runtime Fixture",
        "HOME": str(repository.parent),
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run(
        ("/usr/bin/git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )


def _fixture_repository(tmp_path: Path, *, analyzer: str = _FIXTURE_ANALYZER) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    for relative_path in _POLICY["behavior_paths"]:
        path = repository / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative_path == "config/publication-runtime-policy.json":
            content = json.dumps(_POLICY, sort_keys=True, separators=(",", ":")) + "\n"
        elif relative_path == "scripts/analyze_publication_results.py":
            content = analyzer
        elif relative_path in {"requirements-ci.txt", "requirements-publication.txt"}:
            content = _FIXTURE_LOCK
        else:
            content = f"# synthetic fixture: {relative_path}\n"
        path.write_text(content, encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "synthetic S3")
    return repository


def _commit(repository: Path, message: str) -> None:
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", message)


def _execute_fixture_repository(
    tmp_path: Path,
    repository: Path,
    *,
    input_artifact: Path | None = None,
    output_directory: Path | None = None,
    after_checkout_hook: object | None = None,
    after_worker_hook: object | None = None,
    before_install_hook: object | None = None,
    interpreter: Path | None = None,
) -> PublicationRuntimeReceipt:
    if input_artifact is None:
        input_artifact = tmp_path / "input.json"
        input_artifact.write_bytes(b'{"synthetic":true}\n')
    if output_directory is None:
        output_directory = tmp_path / "output"
    context = runtime._RuntimeContext(
        repository_root=repository,
        interpreter=interpreter or Path(sys.executable),
        after_checkout_hook=after_checkout_hook,
        after_worker_hook=after_worker_hook,
        before_install_hook=before_install_hook,
    )
    return runtime._run_isolated(input_artifact, output_directory, context)


def _run_fixture(
    tmp_path: Path,
    *,
    analyzer: str = _FIXTURE_ANALYZER,
    after_checkout_hook: object | None = None,
    after_worker_hook: object | None = None,
    before_install_hook: object | None = None,
    interpreter: Path | None = None,
) -> PublicationRuntimeReceipt:
    repository = _fixture_repository(tmp_path, analyzer=analyzer)
    return _execute_fixture_repository(
        tmp_path,
        repository,
        after_checkout_hook=after_checkout_hook,
        after_worker_hook=after_worker_hook,
        before_install_hook=before_install_hook,
        interpreter=interpreter,
    )


def test_public_launcher_has_only_closed_artifact_paths() -> None:
    assert tuple(inspect.signature(run_publication_analysis_isolated).parameters) == (
        "input_artifact",
        "output_directory",
    )


def test_runtime_policy_uses_the_central_analyzer_behavior_set_exactly() -> None:
    assert tuple(_POLICY["behavior_paths"]) == repository_behavior_paths(EvidenceRole.ANALYZER)


def test_central_runtime_admission_is_one_argument_and_nonreplayable(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(admit_isolated_publication_run).parameters) == (
        "runtime_receipt",
    )
    receipt = _run_fixture(tmp_path)

    capability = admit_isolated_publication_run(receipt)

    assert type(capability) is RuntimeAdmissionCapability
    assert capability.runtime_execution_isolation_verified is True
    assert capability.formal_authority_granted is False
    with pytest.raises(TypeError, match="not caller-supplied booleans"):
        bool(capability)
    audit = capability.to_audit_document()
    assert "runtime_execution_isolation_verified" not in audit
    assert True not in audit.values()
    assert receipt.to_document()["runtime_execution_isolation_verified"] is False
    with pytest.raises(PublicationRuntimeError, match="already consumed|isolated runner"):
        admit_isolated_publication_run(receipt)


def test_central_runtime_admission_rejects_caller_authority_inputs(tmp_path: Path) -> None:
    receipt = _run_fixture(tmp_path)

    with pytest.raises(TypeError):
        admit_isolated_publication_run(  # type: ignore[call-arg]
            receipt,
            source_git_sha="0" * 40,
            policy={"runtime_verified": True},
            authority=True,
        )


def test_caller_cannot_forge_runner_or_final_admission_capabilities(
    tmp_path: Path,
) -> None:
    receipt = _run_fixture(tmp_path)
    forged_receipt = object.__new__(PublicationRuntimeReceipt)
    object.__setattr__(forged_receipt, "_binding", receipt._binding)

    with pytest.raises(PublicationRuntimeError, match="isolated runner|already consumed"):
        admit_isolated_publication_run(forged_receipt)

    forged_admission = object.__new__(RuntimeAdmissionCapability)
    object.__setattr__(forged_admission, "_binding", object())
    with pytest.raises(EvidenceCompatibilityError, match="not minted"):
        _ = forged_admission.runtime_execution_isolation_verified


def test_runtime_authority_has_no_directly_importable_private_minter() -> None:
    assert not hasattr(runtime, "_mint_receipt")
    assert not hasattr(compatibility, "_mint_runtime_admission")


def test_disk_receipt_success_boolean_cannot_self_admit(tmp_path: Path) -> None:
    receipt = _run_fixture(tmp_path)
    receipt_path = receipt.output_directory / RUNTIME_RECEIPT_FILENAME
    document = json.loads(receipt_path.read_bytes())
    document["runtime_execution_isolation_verified"] = True
    document["formal_authority_granted"] = True
    changed = runtime._canonical_json_bytes(document)
    receipt_path.write_bytes(changed)
    (receipt.output_directory / RUNTIME_RECEIPT_SHA_FILENAME).write_text(
        f"{hashlib.sha256(changed).hexdigest()}  {RUNTIME_RECEIPT_FILENAME}\n",
        encoding="ascii",
    )

    with pytest.raises(PublicationRuntimeError, match="differs|descriptive"):
        admit_isolated_publication_run(receipt)


@pytest.mark.parametrize(
    "installed_name",
    [
        "SHA256SUMS",
        "publication-effects.csv",
        "publication-summary.csv",
        "publication-verdict.json",
        RUNTIME_RECEIPT_FILENAME,
        RUNTIME_RECEIPT_SHA_FILENAME,
    ],
)
def test_central_admission_rehashes_every_installed_artifact(
    tmp_path: Path,
    installed_name: str,
) -> None:
    receipt = _run_fixture(tmp_path)
    target = receipt.output_directory / installed_name
    target.write_bytes(target.read_bytes() + b"attacker\n")

    with pytest.raises(PublicationRuntimeError, match="changed|canonical|checksum|differs"):
        admit_isolated_publication_run(receipt)


def test_central_admission_rejects_missing_and_extra_installed_files(tmp_path: Path) -> None:
    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    missing_receipt = _run_fixture(missing_root)
    (missing_receipt.output_directory / "publication-summary.csv").unlink()
    with pytest.raises(PublicationRuntimeError, match="file set is not exact"):
        admit_isolated_publication_run(missing_receipt)

    extra_root = tmp_path / "extra"
    extra_root.mkdir()
    extra_receipt = _run_fixture(extra_root)
    (extra_receipt.output_directory / "attacker.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    with pytest.raises(PublicationRuntimeError, match="file set is not exact"):
        admit_isolated_publication_run(extra_receipt)


def test_central_admission_rejects_current_s3_drift_after_run(tmp_path: Path) -> None:
    repository = _fixture_repository(tmp_path)
    receipt = _execute_fixture_repository(tmp_path, repository)
    (repository / "src/dynamic_cssc/publication_runtime.py").write_text(
        "# post-run drift\n",
        encoding="utf-8",
    )

    with pytest.raises(PublicationRuntimeError, match="fully clean"):
        admit_isolated_publication_run(receipt)


def test_receipt_is_not_a_caller_minted_boolean() -> None:
    with pytest.raises(TypeError, match="only be minted"):
        PublicationRuntimeReceipt()

    with pytest.raises(TypeError):
        run_publication_analysis_isolated(  # type: ignore[call-arg]
            Path("input.json"),
            Path("output"),
            source_git_sha="0" * 40,
            runtime_verified=True,
        )


def test_cli_rejects_caller_source_and_authority_claims(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(_ROOT / "src")
    completed = subprocess.run(
        (
            sys.executable,
            str(_ROOT / "scripts/run_publication_analysis_isolated.py"),
            "--input-artifact",
            str(tmp_path / "input.json"),
            "--output-directory",
            str(tmp_path / "output"),
            "--source-git-sha",
            "0" * 40,
            "--runtime-verified",
        ),
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == 2
    assert "unrecognized arguments" in completed.stderr


def test_synthetic_isolated_run_mints_canonical_hold_receipt(tmp_path: Path) -> None:
    receipt = _run_fixture(tmp_path)

    document = receipt.to_document()
    assert document["schema_version"] == RUNTIME_RECEIPT_SCHEMA
    assert document["runtime_execution_isolation_verified"] is False
    assert document["formal_authority_granted"] is False
    assert document["authority_state"] == RUNTIME_AUTHORITY_HOLD
    assert document["third_party_wheel_set"] == []
    assert (
        document["source_attestation_before_decode"]
        == document["source_attestation_after_analysis"]
    )
    assert (
        document["source_attestation_before_decode"]
        == document["source_attestation_after_render_and_atomic_install_expected"]
    )
    assert document["fresh_checkout"]["detached"] is True
    assert document["fresh_checkout"]["fresh_private_checkout"] is True
    assert all(
        entry["origin"]["root"] in {"checkout", "stdlib"}
        for entry in document["import_manifest"]["entries"]
        if entry["origin_kind"] == "file"
    )
    assert not {
        "site",
        "sitecustomize",
        "usercustomize",
    } & {entry["name"] for entry in document["import_manifest"]["entries"]}
    assert receipt.formal_authority_granted is False
    with pytest.raises(TypeError, match="not caller-supplied booleans"):
        bool(receipt)

    receipt_path = receipt.output_directory / RUNTIME_RECEIPT_FILENAME
    checksum_path = receipt.output_directory / RUNTIME_RECEIPT_SHA_FILENAME
    assert receipt_path.read_bytes() == runtime._canonical_json_bytes(document)
    assert checksum_path.read_text(encoding="ascii") == (
        f"{receipt.receipt_sha256}  {RUNTIME_RECEIPT_FILENAME}\n"
    )
    assert sorted(path.name for path in receipt.output_directory.iterdir()) == sorted(
        [
            *_POLICY["analysis_output_files"],
            RUNTIME_RECEIPT_FILENAME,
            RUNTIME_RECEIPT_SHA_FILENAME,
        ]
    )
    assert document["analysis_cli_receipt"]["artifact_sha256"] == {
        entry["path"]: entry["sha256"] for entry in document["analysis_output_files"]
    }


def test_dirty_source_fails_before_decode_and_installs_nothing(tmp_path: Path) -> None:
    repository = _fixture_repository(tmp_path)
    (repository / "pyproject.toml").write_text("# dirty\n", encoding="utf-8")

    with pytest.raises(PublicationRuntimeError, match="fully clean"):
        _execute_fixture_repository(tmp_path, repository)

    assert not (tmp_path / "output").exists()


def test_fresh_checkout_must_remain_detached(tmp_path: Path) -> None:
    def attach_head(checkout: Path) -> None:
        _git(checkout, "switch", "--quiet", "-c", "attacker")

    with pytest.raises(PublicationRuntimeError, match="must be detached"):
        _run_fixture(tmp_path, after_checkout_hook=attach_head)


def test_wrong_python_version_fails_closed(tmp_path: Path) -> None:
    fake = tmp_path / "wrong-python"
    fake.write_text(
        "#!/bin/sh\n"
        'printf \'%s\\n\' \'{"base_prefix":"/none","environment_names":[],'
        '"executable":"/none","flags":{"ignore_environment":1,'
        '"isolated":1,"no_site":1,"no_user_site":1,"safe_path":true},'
        '"implementation":"CPython","prefix":"/none",'
        '"stdlib":"/none","sys_path":[],"version":"3.12.12"}\'\n',
        encoding="utf-8",
    )
    fake.chmod(0o700)

    with pytest.raises(PublicationRuntimeHold, match="3.12.13"):
        _run_fixture(tmp_path, interpreter=fake)


def test_caller_git_pythonpath_and_user_site_are_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_DIR", "/attacker/git")
    monkeypatch.setenv("GIT_WORK_TREE", "/attacker/tree")
    monkeypatch.setenv("PYTHONPATH", "/attacker/python")
    monkeypatch.setenv("PYTHONUSERBASE", "/attacker/user-site")

    document = _run_fixture(tmp_path).to_document()

    assert {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "PYTHONPATH",
        "PYTHONUSERBASE",
    } <= set(document["caller_environment_names_removed"])
    child_environment = document["exact_invocation"]["environment"]
    assert "/attacker" not in json.dumps(child_environment)
    assert not any(name.startswith("PYTHON") for name in child_environment)


@pytest.mark.parametrize("name", ["attacker.pth", "sitecustomize.py", "usercustomize.py"])
def test_committed_import_injection_files_are_rejected(tmp_path: Path, name: str) -> None:
    repository = _fixture_repository(tmp_path)
    (repository / "src" / name).write_text("raise RuntimeError('attacker')\n", encoding="utf-8")
    _commit(repository, f"add {name}")

    with pytest.raises(PublicationRuntimeHold, match="forbidden injection file"):
        _execute_fixture_repository(tmp_path, repository)


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_input_must_be_a_no_follow_regular_file(tmp_path: Path, kind: str) -> None:
    repository = tmp_path / "unused-repository"
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    artifact = tmp_path / "input.json"
    if kind == "symlink":
        artifact.symlink_to(target)
    else:
        os.mkfifo(artifact)
    context = runtime._RuntimeContext(repository, Path(sys.executable))

    with pytest.raises(PublicationRuntimeError, match="symlink|regular file"):
        runtime._run_isolated(artifact, tmp_path / "output", context)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_output_must_be_all_new(tmp_path: Path, kind: str) -> None:
    repository = tmp_path / "unused-repository"
    input_artifact = tmp_path / "input.json"
    input_artifact.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "output"
    if kind == "directory":
        output.mkdir()
    elif kind == "file":
        output.write_text("attacker\n", encoding="utf-8")
    else:
        output.symlink_to(input_artifact)
    context = runtime._RuntimeContext(repository, Path(sys.executable))

    with pytest.raises(PublicationRuntimeError, match="all-new"):
        runtime._run_isolated(input_artifact, output, context)


def test_import_outside_checkout_and_stdlib_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "attacker.py").write_text("VALUE = 1\n", encoding="utf-8")
    analyzer = _FIXTURE_ANALYZER.replace(
        "import argparse\n",
        f"import argparse\nimport sys\nsys.path.insert(0, {str(outside)!r})\nimport attacker\n",
    )

    with pytest.raises(
        PublicationRuntimeError,
        match="outside checkout and approved stdlib|sys.path changed",
    ):
        _run_fixture(tmp_path, analyzer=analyzer)


def test_loaded_checkout_module_tamper_is_rejected(tmp_path: Path) -> None:
    def tamper(checkout: Path, _manifest: object) -> None:
        (checkout / "scripts/analyze_publication_results.py").write_text(
            "# tampered after import\n",
            encoding="utf-8",
        )

    with pytest.raises(PublicationRuntimeError, match="fully clean|import bytes changed"):
        _run_fixture(tmp_path, after_worker_hook=tamper)


def test_clean_but_unhashed_lock_is_rejected(tmp_path: Path) -> None:
    repository = _fixture_repository(tmp_path)
    (repository / "requirements-ci.txt").write_text("fixture==2.0\n", encoding="utf-8")
    _commit(repository, "malformed runtime lock")

    with pytest.raises(PublicationRuntimeError, match="hashes are absent"):
        _execute_fixture_repository(tmp_path, repository)


def test_clean_but_changed_invocation_policy_is_rejected(tmp_path: Path) -> None:
    repository = _fixture_repository(tmp_path)
    policy_path = repository / "config/publication-runtime-policy.json"
    policy = json.loads(policy_path.read_bytes())
    policy["interpreter_options"].append("-E")
    policy_path.write_bytes(runtime._canonical_json_bytes(policy))
    _commit(repository, "tamper invocation")

    with pytest.raises(PublicationRuntimeError, match="invocation is not exact"):
        _execute_fixture_repository(tmp_path, repository)


def test_output_install_race_does_not_replace_attacker_path(tmp_path: Path) -> None:
    def race(output: Path, _checkout: Path) -> None:
        output.mkdir()

    with pytest.raises(PublicationRuntimeError, match="all-new"):
        _run_fixture(tmp_path, before_install_hook=race)

    assert (tmp_path / "output").is_dir()
    assert list((tmp_path / "output").iterdir()) == []


def test_source_drift_after_render_prevents_capability_mint(tmp_path: Path) -> None:
    def drift(_output: Path, checkout: Path) -> None:
        (checkout / "pyproject.toml").write_text("# post-render drift\n", encoding="utf-8")

    with pytest.raises(PublicationRuntimeError, match="fully clean"):
        _run_fixture(tmp_path, before_install_hook=drift)

    installed = json.loads((tmp_path / "output" / RUNTIME_RECEIPT_FILENAME).read_bytes())
    assert installed["formal_authority_granted"] is False


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_analyzer_cannot_install_special_output_files(tmp_path: Path, kind: str) -> None:
    def replace_output(checkout: Path, _manifest: object) -> None:
        output = checkout.parent / "analysis-output"
        target = output / "publication-effects.csv"
        target.unlink()
        if kind == "symlink":
            target.symlink_to(output / "publication-summary.csv")
        else:
            os.mkfifo(target)

    with pytest.raises(PublicationRuntimeError, match="symlink|regular file"):
        _run_fixture(tmp_path, after_worker_hook=replace_output)
