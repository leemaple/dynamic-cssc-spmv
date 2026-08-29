from __future__ import annotations

import json
from email.message import Message
from pathlib import Path
from urllib.request import Request

import pytest

import dynamic_cssc.route_a_controller as controller_module
from dynamic_cssc.route_a_controller import (
    GitHubActionsQualificationProvider,
    RouteAControllerError,
)

ARTIFACT_NAMES = (
    "q1-simulator-pre-replay-handoff",
    "q2-simulator-guarded-receipt",
    "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4-native-guarded-case-bundle",
    "q5-combined-guard-bundle",
    "q6-postrun-resource-admission-record",
)


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


class _MemoryHttpReader:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, int]] = []
        self.posts: list[tuple[str, int]] = []

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

    def post(self, url: str, *, headers: dict[str, str], maximum_bytes: int) -> bytes:
        assert headers["Authorization"] == "Bearer secret-token"
        assert headers["Accept"] == "application/vnd.github+json"
        self.posts.append((url, maximum_bytes))
        return b""


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
                        "archive_download_url": (
                            archive_url
                            if name == "q6-postrun-resource-admission-record"
                            else f"https://api.example.test/artifacts/{72 + index}/zip"
                        ),
                        "digest": "sha256:" + f"{index + 1:x}" * 64,
                        "expired": False,
                        "id": 72 + index,
                        "name": name,
                        "size_in_bytes": 13,
                        "workflow_run": {"head_sha": "a" * 40, "id": 999},
                    }
                    for index, name in enumerate(ARTIFACT_NAMES)
                ],
                "total_count": 6,
            }
        ),
        archive_url: b"archive-bytes",
    }


def test_urllib_redirect_strips_token_at_a_foreign_https_origin() -> None:
    request = Request(
        "https://api.github.com/repos/owner/repository/actions/artifacts/77/zip",
        headers={"Authorization": "Bearer secret-token"},
    )
    redirect_headers = Message()
    redirected = controller_module._HttpsTokenStrippingRedirectHandler().redirect_request(
        request,
        None,
        302,
        "Found",
        redirect_headers,
        "https://objects.githubusercontent.com/artifact.zip",
    )

    assert redirected is not None
    assert redirected.full_url == "https://objects.githubusercontent.com/artifact.zip"
    assert redirected.get_header("Authorization") is None


def test_urllib_redirect_rejects_a_non_https_destination() -> None:
    request = Request(
        "https://api.github.com/repos/owner/repository/actions/artifacts/77/zip",
        headers={"Authorization": "Bearer secret-token"},
    )

    with pytest.raises(controller_module.RouteAControllerError, match="redirect"):
        controller_module._HttpsTokenStrippingRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            Message(),
            "http://objects.githubusercontent.com/artifact.zip",
        )


def test_urllib_redirect_preserves_token_only_at_the_same_https_origin() -> None:
    request = Request(
        "https://api.github.com/repos/owner/repository/actions/runs/999",
        headers={"Authorization": "Bearer secret-token"},
    )
    redirected = controller_module._HttpsTokenStrippingRedirectHandler().redirect_request(
        request,
        None,
        302,
        "Found",
        Message(),
        "https://api.github.com/repositories/123/actions/runs/999",
    )

    assert redirected is not None
    assert redirected.get_header("Authorization") == "Bearer secret-token"


def test_urllib_reader_posts_exact_empty_cancel_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Response:
        status = 202

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, maximum_bytes: int) -> bytes:
            assert maximum_bytes == 65
            return b""

    class _Opener:
        def open(self, request: Request, *, timeout: int) -> _Response:
            assert timeout == 30
            assert request.full_url.endswith("/actions/runs/999/cancel")
            assert request.method == "POST"
            assert request.data == b""
            assert request.get_header("Authorization") == "Bearer secret-token"
            return _Response()

    def build_opener(handler: object) -> _Opener:
        assert isinstance(handler, controller_module._HttpsTokenStrippingRedirectHandler)
        return _Opener()

    monkeypatch.setattr(controller_module, "build_opener", build_opener)

    assert controller_module._UrllibHttpReader().post(
        "https://api.github.com/repos/owner/repository/actions/runs/999/cancel",
        headers={"Authorization": "Bearer secret-token"},
        maximum_bytes=64,
    ) == b""


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


def test_github_provider_normalizes_job_presentation_order(tmp_path: Path) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    responses = _responses()
    jobs_url = "https://api.example.test/repos/owner/repository/actions/runs/999/jobs?per_page=100"
    jobs = json.loads(responses[jobs_url])
    jobs["jobs"].reverse()
    responses[jobs_url] = _json_bytes(jobs)
    provider, _ = _provider(tmp_path, responses)

    observation = provider.read_qualification(999)

    assert [job.database_id for job in observation.jobs] == list(range(100, 106))


def test_github_provider_normalizes_live_state_and_posts_exact_cancel_endpoint(
    tmp_path: Path,
) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    provider, reader = _provider(tmp_path, _responses())

    observation = provider.read_live_qualification(999)
    provider.cancel_qualification(999)

    assert observation.run.database_id == 999
    assert observation.run.status == "completed"
    assert len(observation.jobs) == 6
    assert reader.posts == [
        (
            "https://api.example.test/repos/owner/repository/actions/runs/999/cancel",
            64 * 1024,
        )
    ]


def test_github_provider_rejects_duplicate_qualification_artifact(tmp_path: Path) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    responses = _responses()
    artifact_url = (
        "https://api.example.test/repos/owner/repository/actions/runs/999/artifacts?per_page=100"
    )
    document = json.loads(responses[artifact_url])
    document["artifacts"][0] = dict(
        document["artifacts"][1],
        id=document["artifacts"][0]["id"],
    )
    responses[artifact_url] = _json_bytes(document)
    provider, _ = _provider(tmp_path, responses)

    with pytest.raises(RouteAControllerError, match="artifact identity"):
        provider.read_qualification(999)


def test_github_provider_never_forwards_its_token_to_a_foreign_archive_origin(
    tmp_path: Path,
) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    responses = _responses()
    artifact_url = (
        "https://api.example.test/repos/owner/repository/actions/runs/999/artifacts?per_page=100"
    )
    document = json.loads(responses[artifact_url])
    document["artifacts"][-1]["archive_download_url"] = (
        "https://attacker.example/artifact.zip"
    )
    responses[artifact_url] = _json_bytes(document)
    provider, reader = _provider(tmp_path, responses)

    with pytest.raises(RouteAControllerError, match="foreign HTTPS origin"):
        provider.read_qualification(999)

    assert all("attacker.example" not in url for url, _maximum in reader.requests)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda artifact: artifact.update(expired=True), "provider binding"),
        (
            lambda artifact: artifact.update(digest="sha256:not-a-digest"),
            "provider binding",
        ),
        (
            lambda artifact: artifact["workflow_run"].update(id=1000),
            "provider binding",
        ),
        (
            lambda artifact: artifact["workflow_run"].update(head_sha="b" * 40),
            "provider binding",
        ),
    ],
)
def test_github_provider_rejects_invalid_member_of_six_artifact_set(
    tmp_path: Path,
    mutation: object,
    message: str,
) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    responses = _responses()
    artifact_url = (
        "https://api.example.test/repos/owner/repository/actions/runs/999/artifacts?per_page=100"
    )
    document = json.loads(responses[artifact_url])
    mutation(document["artifacts"][0])  # type: ignore[operator]
    responses[artifact_url] = _json_bytes(document)
    provider, _ = _provider(tmp_path, responses)

    with pytest.raises(RouteAControllerError, match=message):
        provider.read_qualification(999)


def test_github_provider_rejects_missing_or_seventh_artifact(tmp_path: Path) -> None:
    plan_source = Path(__file__).resolve().parents[1] / "config/route-a-publication-plan.json"
    (tmp_path / "config").mkdir()
    (tmp_path / "config/route-a-publication-plan.json").write_bytes(plan_source.read_bytes())
    artifact_url = (
        "https://api.example.test/repos/owner/repository/actions/runs/999/artifacts?per_page=100"
    )
    for extra in (False, True):
        responses = _responses()
        document = json.loads(responses[artifact_url])
        if extra:
            document["artifacts"].append(
                dict(document["artifacts"][0], id=9999, name="unexpected")
            )
        else:
            document["artifacts"].pop(0)
        document["total_count"] = len(document["artifacts"])
        responses[artifact_url] = _json_bytes(document)
        provider, _ = _provider(tmp_path, responses)

        with pytest.raises(RouteAControllerError, match="six-object set"):
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
