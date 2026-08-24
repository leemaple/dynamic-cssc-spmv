from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.day2_calibration_github as github
from dynamic_cssc.day1a_export import (
    AUTHORITY_RECEIPT_FILENAME,
    COUNT_BUNDLE_FILENAME,
    ROTATION_INVENTORY_FILENAME,
)
from dynamic_cssc.day2_calibration_github import Day2CalibrationGitHubError


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _environment(source_sha: str) -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "leemaple/dynamic-cssc-spmv",
        "GITHUB_REPOSITORY_ID": "1341939625",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": source_sha,
        "GITHUB_WORKFLOW_REF": (
            "leemaple/dynamic-cssc-spmv/.github/workflows/"
            "day2-publication-calibration.yml@refs/heads/main"
        ),
        "GITHUB_RUN_ID": "456",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_TOKEN": "provider-token",
    }


def _artifact(
    *,
    artifact_id: int,
    run_id: int,
    name: str,
    digest: str,
    source_sha: str,
) -> dict[str, object]:
    return {
        "id": artifact_id,
        "name": name,
        "expired": False,
        "digest": digest,
        "archive_download_url": "https://api.github.test/artifact.zip",
        "size_in_bytes": 123,
        "workflow_run": {
            "id": run_id,
            "head_sha": source_sha,
            "repository_id": 1_341_939_625,
        },
    }


def test_provider_digest_normalization_preserves_wrapper_identity() -> None:
    digest = "a" * 64
    assert github._normalize_provider_digest(digest, "digest") == f"sha256:{digest}"
    assert github._normalize_provider_digest(f"sha256:{digest}", "digest") == (
        f"sha256:{digest}"
    )
    with pytest.raises(Day2CalibrationGitHubError, match="not a SHA-256"):
        github._normalize_provider_digest("A" * 64, "digest")


def test_day1a_capture_joins_anchor_api_receipt_and_historical_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = "a" * 40
    run_id = 123
    artifact_id = 789
    artifact_name = f"r2-day1a-publication-{source_sha}-20260821"
    artifact_digest = "sha256:" + "b" * 64
    day1a = tmp_path / "day1a"
    day1a.mkdir()
    (day1a / COUNT_BUNDLE_FILENAME).write_bytes(_canonical({"value": 1}))
    (day1a / ROTATION_INVENTORY_FILENAME).write_bytes(_canonical({"value": 2}))
    (day1a / AUTHORITY_RECEIPT_FILENAME).write_bytes(
        _canonical({"source_git_sha": source_sha})
    )
    monkeypatch.setattr(
        github,
        "_formal_environment",
        lambda _workflow: _environment("c" * 40),
    )
    monkeypatch.setattr(
        github,
        "_profile_anchor",
        lambda _root: {
            "day1a_workflow_run_id": run_id,
            "day1a_artifact_id": artifact_id,
            "day1a_artifact_name": artifact_name,
            "day1a_artifact_digest": artifact_digest,
        },
    )
    run = {
        "id": run_id,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": source_sha,
        "head_branch": "main",
        "path": ".github/workflows/day1a-publication-cost-model.yml@main",
        "run_attempt": 3,
        "repository": {
            "id": 1_341_939_625,
            "full_name": "leemaple/dynamic-cssc-spmv",
        },
    }
    artifact = _artifact(
        artifact_id=artifact_id,
        run_id=run_id,
        name=artifact_name,
        digest=artifact_digest,
        source_sha=source_sha,
    )
    monkeypatch.setattr(
        github,
        "_api_json",
        lambda endpoint, _token: run if endpoint == f"actions/runs/{run_id}" else artifact,
    )
    workflow_bytes = b"name: historical-day1a\n"
    monkeypatch.setattr(github, "_git_blob", lambda *_arguments: workflow_bytes)
    output = tmp_path / "day1a-metadata.json"

    captured = github.capture_repository_day1a_github_metadata(day1a, output)

    assert captured == output.absolute()
    metadata = json.loads(output.read_bytes())
    assert metadata["head_sha"] == source_sha
    assert metadata["run_id"] == run_id
    assert metadata["run_attempt"] == 3
    assert metadata["artifact_id"] == artifact_id
    assert metadata["artifact_digest"] == artifact_digest
    assert metadata["workflow_file_sha256"] == github._sha256(workflow_bytes)
    assert output.read_bytes() == _canonical(metadata)


def test_day1a_capture_rejects_provider_digest_that_differs_from_anchor(
    tmp_path: Path,
) -> None:
    artifact = _artifact(
        artifact_id=1,
        run_id=2,
        name="artifact",
        digest="sha256:" + "b" * 64,
        source_sha="a" * 40,
    )
    with pytest.raises(Day2CalibrationGitHubError, match="does not match its anchor"):
        github._validate_artifact(
            artifact,
            artifact_id=1,
            run_id=2,
            artifact_name="artifact",
            artifact_digest="sha256:" + "c" * 64,
            source_sha="a" * 40,
        )


def test_day2_capture_records_distinct_provider_and_inner_digests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = "c" * 40
    environment = _environment(source_sha)
    environment.update(
        {
            "DAY2_UPLOADED_ARTIFACT_ID": "987",
            "DAY2_UPLOADED_ARTIFACT_DIGEST": "d" * 64,
        }
    )
    provenance = {
        "schema_version": "dynamic-cssc-publication-day2-workflow-provenance-v1",
        "repository": "leemaple/dynamic-cssc-spmv",
        "repository_id": 1_341_939_625,
        "workflow_path": ".github/workflows/day2-publication-calibration.yml",
        "workflow_file_sha256": "e" * 64,
        "run_id": 456,
        "run_attempt": 2,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "head_sha": source_sha,
        "artifact_name": f"r3-day2-calibration-{source_sha}-456-2",
    }
    inner_sha256 = "f" * 64
    monkeypatch.setattr(github, "_formal_environment", lambda _workflow: environment)
    monkeypatch.setattr(
        github,
        "_archive_workflow_provenance",
        lambda _archive: (provenance, inner_sha256),
    )
    monkeypatch.setattr(
        github,
        "_api_json",
        lambda _endpoint, _token: _artifact(
            artifact_id=987,
            run_id=456,
            name=provenance["artifact_name"],
            digest="sha256:" + "d" * 64,
            source_sha=source_sha,
        ),
    )
    monkeypatch.setattr(
        github,
        "inspect_day2_calibration_archive",
        lambda *_args, **_kwargs: SimpleNamespace(outer_archive_sha256=inner_sha256),
    )
    output = tmp_path / "day2-metadata.json"

    github.capture_repository_day2_github_metadata(tmp_path / "archive.zip", output)

    metadata = json.loads(output.read_bytes())
    assert metadata["artifact_digest"] == "sha256:" + "d" * 64
    assert metadata["inner_archive_sha256"] == inner_sha256
    assert metadata["artifact_digest"].removeprefix("sha256:") != inner_sha256


def test_metadata_capture_never_replaces_an_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "metadata.json"
    output.write_text("owned\n", encoding="utf-8")
    with pytest.raises(Day2CalibrationGitHubError, match="must be absent"):
        github._write_new_canonical_json(output, {"value": 1})
    assert output.read_text(encoding="utf-8") == "owned\n"
