from __future__ import annotations

import json
from pathlib import Path

import pytest

from dynamic_cssc.route_a_controller import (
    GitHubActionsQualificationProvider,
    RouteAControllerError,
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


class _MemoryHttpReader:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, int]] = []

    def get(self, url: str, *, headers: dict[str, str], maximum_bytes: int) -> bytes:
        assert headers["Authorization"] == "Bearer secret-token"
        assert headers["Accept"] == "application/vnd.github+json"
        self.requests.append((url, maximum_bytes))
        try:
            content = self.responses[url]
        except KeyError as error:  # pragma: no cover - fixture route is exact
            raise OSError(f"unexpected URL: {url}") from error
        if len(content) > maximum_bytes:
            raise OSError("response too large")
        return content


def _provider(
    repository_root: Path,
    responses: dict[str, bytes],
) -> tuple[GitHubActionsQualificationProvider, _MemoryHttpReader]:
    reader = _MemoryHttpReader(responses)
    return (
        GitHubActionsQualificationProvider(
            repository_root=repository_root,
            repository_slug="owner/repository",
            token="secret-token",
            api_url="https://api.example.test",
            http_reader=reader,
        ),
        reader,
    )


def _responses() -> dict[str, bytes]:
    run_url = "https://api.example.test/repos/owner/repository/actions/runs/999"
    jobs_url = run_url + "/jobs?per_page=100"
    artifacts_url = run_url + "/artifacts?per_page=100"
    archive_url = "https://api.example.test/artifacts/77/zip"
    names = (
        "qualification-simulator-producer",
        "qualification-simulator-independent-replay-and-guard",
        "qualification-native-case-shaped-producer",
        "qualification-native-independent-replay-and-guard",
        "qualification-combined-guard",
        "qualification-postrun-resource-admission",
    )
    jobs = [
        {
            "completed_at": f"2026-08-28T0{index + 1}:05:00Z",
            "conclusion": "success",
            "id": 100 + index,
            "name": name,
            "started_at": f"2026-08-28T0{index + 1}:00:00Z",
            "status": "completed",
        }
        for index, name in enumerate(names)
    ]
    return {
        run_url: _json_bytes(
            {
                "conclusion": "success",
                "created_at": "2026-08-28T00:59:00Z",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": "a" * 40,
                "id": 999,
                "run_attempt": 1,
                "status": "completed",
                "updated_at": "2026-08-28T06:06:00Z",
            }
        ),
        jobs_url: _json_bytes({"jobs": jobs, "total_count": 6}),
        artifacts_url: _json_bytes(
            {
                "artifacts": [
                    {
                        "archive_download_url": archive_url,
                        "digest": "sha256:" + "b" * 64,
                        "expired": False,
                        "id": 77,
                        "name": "q6-postrun-resource-admission-record",
                        "size_in_bytes": 13,
                        "workflow_run": {"head_sha": "a" * 40},
                    }
                ],
                "total_count": 1,
            }
        ),
        archive_url: b"archive-bytes",
    }


def test_github_provider_normalizes_only_the_frozen_api_fields(tmp_path: Path) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    provider, reader = _provider(tmp_path, _responses())

    observation = provider.read_qualification(999)

    assert observation.run.database_id == 999
    assert observation.run.head_sha == "a" * 40
    assert [job.database_id for job in observation.jobs] == list(range(100, 106))
    assert observation.q6_artifact.database_id == 77
    assert observation.q6_archive_bytes == b"archive-bytes"
    assert observation.plan_bytes == plan_source.read_bytes()
    assert [maximum for _, maximum in reader.requests] == [
        2 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        2 * 1024 * 1024,
    ]


def test_github_provider_rejects_missing_or_duplicate_q6_artifact(tmp_path: Path) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    responses = _responses()
    artifact_url = (
        "https://api.example.test/repos/owner/repository/actions/runs/999/artifacts?per_page=100"
    )
    artifact = json.loads(responses[artifact_url])["artifacts"][0]
    responses[artifact_url] = _json_bytes(
        {"artifacts": [artifact, dict(artifact, id=78)], "total_count": 2}
    )
    provider, _ = _provider(tmp_path, responses)

    with pytest.raises(RouteAControllerError, match="q6 artifact"):
        provider.read_qualification(999)


@pytest.mark.parametrize("run_id", [0, -1, True, "999"])
def test_github_provider_rejects_nonpositive_strict_run_id(
    tmp_path: Path,
    run_id: object,
) -> None:
    provider, _ = _provider(tmp_path, {})
    with pytest.raises((TypeError, RouteAControllerError)):
        provider.read_qualification(run_id)  # type: ignore[arg-type]


def test_github_provider_rejects_open_repository_identity(tmp_path: Path) -> None:
    with pytest.raises(RouteAControllerError, match="repository"):
        GitHubActionsQualificationProvider(
            repository_root=tmp_path,
            repository_slug="owner/repository/extra",
            token="secret-token",
            http_reader=_MemoryHttpReader({}),
        )
