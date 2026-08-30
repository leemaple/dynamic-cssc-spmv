from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from dynamic_cssc.followup_performance_analysis_binding import (
    build_followup_analysis_claim,
    build_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_campaign import open_followup_campaign_state
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
)
from dynamic_cssc.followup_performance_controller import (
    FollowupDispatchPrerequisites,
    FollowupQualificationOpening,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.followup_performance_github import (
    GitHubFollowupCampaignProvider,
    GitHubHttpResponse,
)
from dynamic_cssc.followup_performance_qualification_binding import (
    build_followup_qualification_watch_binding,
)
from dynamic_cssc.followup_performance_terminal_binding import (
    build_followup_terminal_claim,
    build_followup_terminal_watch_binding,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"github-adapter-sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="github-adapter-sentinel",
    qualification_seed=97_001,
    formal_seeds=(97_002, 97_003, 97_004),
    query_vector_seed=9_700_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)
S2 = "2" * 40
S3 = "3" * 40
RUN_ID = 91_001


def _json_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class _FakeGitHubTransport:
    def __init__(
        self,
        *,
        successful: bool = True,
        qualification: bool = False,
    ) -> None:
        self.successful = successful
        self.qualification = qualification
        self.current_ref = "a" * 40
        self.candidate_index = 1
        self.calls: list[tuple[str, str, bytes | None]] = []
        self.cancelled: list[int] = []
        self.terminal_dispatched = False
        self.analysis_dispatched = False
        self.terminal_blob_oid = "c" * 40
        self.terminal_tree_oid = "d" * 40
        self.observed_at = (
            datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=10)
            if qualification
            else datetime(2026, 8, 30, 0, 10, tzinfo=UTC)
        )
        self.qualification_base = self.observed_at

    @staticmethod
    def _time(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def _response(self, status: int, body: bytes) -> GitHubHttpResponse:
        self.observed_at += timedelta(seconds=1)
        return GitHubHttpResponse(
            status=status,
            provider_observed_at=self.observed_at,
            body=body,
        )

    def _run(self) -> dict[str, object]:
        if self.analysis_dispatched:
            return {
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": S3,
                "id": RUN_ID,
                "path": ".github/workflows/followup-performance-analysis.yml",
                "run_attempt": 1,
                "status": "completed",
            }
        if self.terminal_dispatched:
            return {
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": S2,
                "id": RUN_ID,
                "path": ".github/workflows/followup-performance-terminal.yml",
                "run_attempt": 1,
                "status": "completed",
            }
        if self.qualification:
            return {
                "conclusion": "success",
                "created_at": self._time(
                    self.qualification_base - timedelta(minutes=8)
                ),
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": S2,
                "id": RUN_ID,
                "path": ".github/workflows/followup-performance-qualification.yml",
                "run_attempt": 1,
                "status": "completed",
                "updated_at": self._time(
                    self.qualification_base - timedelta(seconds=1)
                ),
            }
        return {
            "conclusion": "success" if self.successful else "failure",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": S2,
            "id": RUN_ID,
            "path": ".github/workflows/followup-performance-formal-unit.yml",
            "run_attempt": 1,
            "status": "completed",
        }

    def _jobs(self) -> dict[str, object]:
        if self.analysis_dispatched:
            return {
                "jobs": [
                    {
                        "completed_at": "2026-08-30T00:05:00Z",
                        "conclusion": "success",
                        "id": 96_001,
                        "name": "isolated-descriptive-analysis",
                        "run_attempt": 1,
                        "run_id": RUN_ID,
                        "started_at": "2026-08-30T00:00:00Z",
                        "status": "completed",
                    }
                ],
                "total_count": 1,
            }
        if self.terminal_dispatched:
            return {
                "jobs": [
                    {
                        "completed_at": "2026-08-30T00:10:00Z",
                        "conclusion": "success",
                        "id": 94_001,
                        "name": "formal-terminal-admission-and-aggregate",
                        "run_attempt": 1,
                        "run_id": RUN_ID,
                        "started_at": "2026-08-30T00:00:00Z",
                        "status": "completed",
                    }
                ],
                "total_count": 1,
            }
        if self.qualification:
            names = (
                "qualification-simulator-producer",
                "qualification-simulator-independent-replay-and-guard",
                "qualification-native-case-shaped-producer",
                "qualification-native-independent-replay-and-guard",
                "qualification-combined-guard",
                "qualification-postrun-resource-admission",
            )
            started = self.qualification_base - timedelta(minutes=7)
            rows = []
            for ordinal, name in enumerate(names):
                job_started = started + timedelta(minutes=ordinal)
                rows.append(
                    {
                        "completed_at": self._time(
                            job_started + timedelta(minutes=1)
                        ),
                        "conclusion": "success",
                        "id": 92_001 + ordinal,
                        "name": name,
                        "run_attempt": 1,
                        "run_id": RUN_ID,
                        "started_at": self._time(job_started),
                        "status": "completed",
                    }
                )
            return {"jobs": rows, "total_count": 6}
        producer = {
            "completed_at": "2026-08-30T00:05:00Z",
            "conclusion": "success" if self.successful else "startup_failure",
            "id": 92_001,
            "name": "formal-00-acquisition-producer",
            "run_attempt": 1,
            "run_id": RUN_ID,
            "started_at": "2026-08-30T00:00:00Z",
            "status": "completed",
        }
        if not self.successful:
            return {"jobs": [producer], "total_count": 1}
        guard = {
            "completed_at": "2026-08-30T00:10:00Z",
            "conclusion": "success",
            "id": 92_002,
            "name": "formal-00-acquisition-independent-replay-and-guard",
            "run_attempt": 1,
            "run_id": RUN_ID,
            "started_at": "2026-08-30T00:05:00Z",
            "status": "completed",
        }
        return {"jobs": [producer, guard], "total_count": 2}

    def _artifacts(self) -> dict[str, object]:
        if self.analysis_dispatched:
            rows = [
                {
                    "digest": f"sha256:{'a' * 64}",
                    "expired": False,
                    "id": 97_001,
                    "name": "followup-performance-v1-analysis-sentinel",
                    "size_in_bytes": 505,
                    "workflow_run": {"head_sha": S3, "id": RUN_ID},
                }
            ]
            return {"artifacts": rows, "total_count": 1}
        if self.terminal_dispatched:
            rows = [
                {
                    "digest": f"sha256:{'8' * 64}",
                    "expired": False,
                    "id": 95_001,
                    "name": (
                        "followup-performance-v1-formal-terminal-admission-sentinel"
                    ),
                    "size_in_bytes": 303,
                    "workflow_run": {"head_sha": S2, "id": RUN_ID},
                },
                {
                    "digest": f"sha256:{'9' * 64}",
                    "expired": False,
                    "id": 95_002,
                    "name": "followup-performance-v1-formal-aggregate-sentinel",
                    "size_in_bytes": 404,
                    "workflow_run": {"head_sha": S2, "id": RUN_ID},
                },
            ]
            return {"artifacts": rows, "total_count": 2}
        if self.qualification:
            rows = [
                {
                    "digest": f"sha256:{ordinal + 1:064x}",
                    "expired": False,
                    "id": 93_001 + ordinal,
                    "name": (
                        f"followup-performance-v1-qualification-q{ordinal + 1}-test"
                    ),
                    "size_in_bytes": 101 + ordinal,
                    "workflow_run": {"head_sha": S2, "id": RUN_ID},
                }
                for ordinal in range(6)
            ]
            return {"artifacts": rows, "total_count": 6}
        if not self.successful:
            return {"artifacts": [], "total_count": 0}
        rows = [
            {
                "digest": f"sha256:{'6' * 64}",
                "expired": False,
                "id": 93_001,
                "name": "followup-performance-v1-formal-acquisition-private",
                "size_in_bytes": 101,
                "workflow_run": {"head_sha": S2, "id": RUN_ID},
            },
            {
                "digest": f"sha256:{'7' * 64}",
                "expired": False,
                "id": 93_002,
                "name": "followup-performance-v1-formal-acquisition-guarded",
                "size_in_bytes": 202,
                "workflow_run": {"head_sha": S2, "id": RUN_ID},
            },
        ]
        return {"artifacts": rows, "total_count": 2}

    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse:
        del expected_statuses, maximum_bytes
        self.calls.append((method, path, payload))
        if method == "POST" and path.endswith("/git/commits"):
            assert payload is not None
            request = json.loads(payload)
            candidate = f"{self.candidate_index:040x}"
            self.candidate_index += 1
            return self._response(
                201,
                _json_bytes(
                    {
                        "message": request["message"],
                        "parents": [{"sha": request["parents"][0]}],
                        "sha": candidate,
                        "tree": {"sha": request["tree"]},
                    }
                ),
            )
        if method == "GET" and path == "/repos/example/project":
            return self._response(200, _json_bytes({"node_id": "R_fake"}))
        if method == "GET" and path.endswith(
            "/actions/workflows/followup-performance-qualification.yml/runs?per_page=100"
        ):
            return self._response(
                200,
                _json_bytes({"total_count": 0, "workflow_runs": []}),
            )
        if method == "GET" and path.endswith(
            "/actions/workflows/followup-performance-terminal.yml/runs?per_page=100"
        ):
            return self._response(
                200,
                _json_bytes({"total_count": 0, "workflow_runs": []}),
            )
        if method == "GET" and path.endswith(
            "/actions/workflows/followup-performance-analysis.yml/runs?per_page=100"
        ):
            return self._response(
                200,
                _json_bytes({"total_count": 0, "workflow_runs": []}),
            )
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return self._response(
                200,
                _json_bytes(
                    {
                        "object": {"sha": S3, "type": "commit"},
                        "ref": "refs/heads/main",
                    }
                ),
            )
        if method == "GET" and path.endswith(f"/git/commits/{S2}"):
            return self._response(
                200,
                _json_bytes({"sha": S2, "tree": {"sha": "b" * 40}}),
            )
        if method == "GET" and path.endswith(f"/git/commits/{self.current_ref}"):
            return self._response(
                200,
                _json_bytes(
                    {
                        "sha": self.current_ref,
                        "tree": {"sha": self.terminal_tree_oid},
                    }
                ),
            )
        if method == "POST" and path.endswith("/git/refs"):
            assert payload is not None
            request = json.loads(payload)
            self.current_ref = request["sha"]
            return self._response(
                201,
                _json_bytes(
                    {
                        "object": {"sha": request["sha"], "type": "commit"},
                        "ref": request["ref"],
                    }
                ),
            )
        if method == "POST" and path.endswith("/git/blobs"):
            assert payload is not None
            request = json.loads(payload)
            assert request["encoding"] == "base64"
            return self._response(
                201,
                _json_bytes({"sha": self.terminal_blob_oid}),
            )
        if method == "POST" and path.endswith("/git/trees"):
            assert payload is not None
            request = json.loads(payload)
            assert request["tree"][0]["sha"] == self.terminal_blob_oid
            return self._response(
                201,
                _json_bytes({"sha": self.terminal_tree_oid}),
            )
        if method == "GET" and path.endswith(
            f"/git/trees/{self.terminal_tree_oid}"
        ):
            return self._response(
                200,
                _json_bytes(
                    {
                        "sha": self.terminal_tree_oid,
                        "tree": [
                            {
                                "mode": "100644",
                                "path": "campaign-evidence.zip",
                                "sha": self.terminal_blob_oid,
                                "type": "blob",
                            }
                        ],
                        "truncated": False,
                    }
                ),
            )
        if method == "POST" and path == "/graphql":
            assert payload is not None
            request = json.loads(payload)
            update = request["variables"]["input"]["refUpdates"][0]
            assert update["beforeOid"] == self.current_ref
            assert update["force"] is False
            self.current_ref = update["afterOid"]
            client = request["variables"]["input"]["clientMutationId"]
            return self._response(
                200,
                _json_bytes(
                    {"data": {"updateRefs": {"clientMutationId": client}}}
                ),
            )
        if method == "GET" and "/git/ref/tags/" in path:
            ref_name = "refs/" + path.split("/git/ref/", 1)[1]
            return self._response(
                200,
                _json_bytes(
                    {
                        "object": {"sha": self.current_ref, "type": "commit"},
                        "ref": ref_name,
                    }
                ),
            )
        if method == "POST" and path.endswith(
            "/actions/workflows/followup-performance-terminal.yml/dispatches"
        ):
            self.terminal_dispatched = True
            return self._response(
                200,
                _json_bytes(
                    {
                        "html_url": f"https://github.com/example/project/actions/runs/{RUN_ID}",
                        "run_url": (
                            "https://api.github.com/repos/example/project/actions/runs/"
                            f"{RUN_ID}"
                        ),
                        "workflow_run_id": RUN_ID,
                    }
                ),
            )
        if method == "POST" and path.endswith(
            "/actions/workflows/followup-performance-analysis.yml/dispatches"
        ):
            self.analysis_dispatched = True
            return self._response(
                200,
                _json_bytes(
                    {
                        "html_url": f"https://github.com/example/project/actions/runs/{RUN_ID}",
                        "run_url": (
                            "https://api.github.com/repos/example/project/actions/runs/"
                            f"{RUN_ID}"
                        ),
                        "workflow_run_id": RUN_ID,
                    }
                ),
            )
        if method == "POST" and path.endswith(
            "/actions/workflows/followup-performance-qualification.yml/dispatches"
        ):
            return self._response(
                200,
                _json_bytes(
                    {
                        "html_url": f"https://github.com/example/project/actions/runs/{RUN_ID}",
                        "run_url": (
                            "https://api.github.com/repos/example/project/actions/runs/"
                            f"{RUN_ID}"
                        ),
                        "workflow_run_id": RUN_ID,
                    }
                ),
            )
        if method == "POST" and path.endswith(
            "/actions/workflows/followup-performance-formal-unit.yml/dispatches"
        ):
            return self._response(
                200,
                _json_bytes(
                    {
                        "html_url": f"https://github.com/example/project/actions/runs/{RUN_ID}",
                        "run_url": (
                            "https://api.github.com/repos/example/project/actions/runs/"
                            f"{RUN_ID}"
                        ),
                        "workflow_run_id": RUN_ID,
                    }
                ),
            )
        if method == "GET" and path.endswith(f"/actions/runs/{RUN_ID}"):
            return self._response(200, _json_bytes(self._run()))
        if method == "GET" and path.endswith(
            f"/actions/runs/{RUN_ID}/jobs?per_page=100"
        ):
            return self._response(200, _json_bytes(self._jobs()))
        if method == "GET" and path.endswith(
            f"/actions/runs/{RUN_ID}/artifacts?per_page=100"
        ):
            return self._response(200, _json_bytes(self._artifacts()))
        if method == "POST" and path.endswith(f"/actions/runs/{RUN_ID}/cancel"):
            self.cancelled.append(RUN_ID)
            return self._response(202, b"")
        raise AssertionError((method, path))

    def request_bytes(self, *, path: str, maximum_bytes: int) -> bytes:
        del maximum_bytes
        if path.endswith("/actions/jobs/96001/logs"):
            receipt = {
                "analysis_compatibility_receipt_sha256": "5" * 64,
                "analysis_sha256": "6" * 64,
                "artifact_name": "followup-performance-v1-analysis-sentinel",
                "schema_version": (
                    "dynamic-cssc-followup-performance-analysis-phase-receipt-v1"
                ),
                "unit_identity_sha256": "7" * 64,
            }
            return (
                b"2026-08-30T00:05:00Z FOLLOWUP_ANALYSIS_PHASE_RECEIPT_V1="
                + json.dumps(
                    receipt,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            )
        if path.endswith("/actions/jobs/94001/logs"):
            receipt = {
                "aggregate": {
                    "aggregate_sha256": "a" * 64,
                    "artifact_name": (
                        "followup-performance-v1-formal-aggregate-sentinel"
                    ),
                    "unit_identity_sha256": "b" * 64,
                },
                "schema_version": (
                    "dynamic-cssc-followup-performance-terminal-phase-receipt-v1"
                ),
                "terminal": {
                    "artifact_name": (
                        "followup-performance-v1-formal-terminal-admission-sentinel"
                    ),
                    "formal_artifact_set_sha256": "c" * 64,
                    "formal_timing_ledger_sha256": "6" * 64,
                    "unit_identity_sha256": "d" * 64,
                },
            }
            return (
                b"2026-08-30T00:10:00Z FOLLOWUP_TERMINAL_PHASE_RECEIPT_V1="
                + json.dumps(
                    receipt,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                + b"\n"
            )
        assert path.endswith("/actions/jobs/92002/logs")
        return (
            b"2026-08-30T00:09:59Z guard completed\n"
            b"2026-08-30T00:10:00Z FOLLOWUP_FORMAL_PHASE_RECEIPT_V1="
            b'{"artifact_name":"followup-performance-v1-formal-acquisition-guarded",'
            b'"unit_identity_sha256":"8888888888888888888888888888888888888888888888888888888888888888",'
            b'"unit_output_envelope_sha256":"9999999999999999999999999999999999999999999999999999999999999999"}\n'
        )


class _DeadlineCancellationTransport(_FakeGitHubTransport):
    """Keep one formal run live until the watcher requests cancellation."""

    def __init__(self, *, empty_jobs: bool = False) -> None:
        super().__init__()
        self.empty_jobs = empty_jobs
        self.run_reads = 0
        self.run_reads_at_cancel: list[int] = []
        self.cancel_was_posted = False

    def _run(self) -> dict[str, object]:
        completed = self.cancel_was_posted and (
            not self.empty_jobs or self.run_reads >= 7
        )
        return {
            "conclusion": "cancelled" if completed else None,
            "created_at": "2026-08-30T00:00:00Z",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": S2,
            "id": RUN_ID,
            "path": ".github/workflows/followup-performance-formal-unit.yml",
            "run_attempt": 1,
            "status": "completed" if completed else "in_progress",
            "updated_at": (
                "2026-08-30T00:20:01Z"
                if completed
                else "2026-08-30T00:19:59Z"
            ),
        }

    def _jobs(self) -> dict[str, object]:
        if self.empty_jobs:
            return {"jobs": [], "total_count": 0}
        completed = self.cancel_was_posted
        producer = {
            "completed_at": "2026-08-30T00:20:00Z" if completed else None,
            "conclusion": "cancelled" if completed else None,
            "id": 92_001,
            "name": "formal-00-acquisition-producer",
            "run_attempt": 1,
            "run_id": RUN_ID,
            "started_at": "2026-08-30T00:00:00Z",
            "status": "completed" if completed else "in_progress",
        }
        return {"jobs": [producer], "total_count": 1}

    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse:
        if method == "GET" and path.endswith(f"/actions/runs/{RUN_ID}"):
            self.run_reads += 1
        if method == "POST" and path.endswith(
            f"/actions/runs/{RUN_ID}/cancel"
        ):
            self.run_reads_at_cancel.append(self.run_reads)
            self.cancel_was_posted = True
        return super().request(
            method=method,
            path=path,
            payload=payload,
            expected_statuses=expected_statuses,
            maximum_bytes=maximum_bytes,
        )


class _CancelThenSuccessTransport(_DeadlineCancellationTransport):
    """Model the provider reporting success only after cancellation was sent."""

    def _run(self) -> dict[str, object]:
        document = super()._run()
        if self.cancel_was_posted:
            document["conclusion"] = "success"
            document["status"] = "completed"
            document["updated_at"] = "2026-08-30T00:20:01Z"
        return document


class _CancelThenStartupFailureTransport(_DeadlineCancellationTransport):
    """A post-cancel startup_failure cannot retroactively authorize retry."""

    def _jobs(self) -> dict[str, object]:
        document = super()._jobs()
        if self.cancel_was_posted:
            rows = document["jobs"]
            assert type(rows) is list and len(rows) == 1
            row = rows[0]
            assert type(row) is dict
            row["conclusion"] = "startup_failure"
        return document


class _LostCompareAndSwapTransport(_FakeGitHubTransport):
    """Model a competing controller moving the ref during updateRefs."""

    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse:
        if method == "POST" and path == "/graphql":
            self.calls.append((method, path, payload))
            self.current_ref = "f" * 40
            return self._response(
                200,
                _json_bytes(
                    {
                        "errors": [{"message": "beforeOid no longer matches"}],
                    }
                ),
            )
        return super().request(
            method=method,
            path=path,
            payload=payload,
            expected_statuses=expected_statuses,
            maximum_bytes=maximum_bytes,
        )


class _DuplicateQualificationClaimTransport(_FakeGitHubTransport):
    """Share one provider ref namespace across two controller instances."""

    def __init__(self) -> None:
        super().__init__(qualification=True)
        self.claim_created = False

    def request(
        self,
        *,
        method: str,
        path: str,
        payload: bytes | None,
        expected_statuses: frozenset[int],
        maximum_bytes: int,
    ) -> GitHubHttpResponse:
        if method == "POST" and path.endswith("/git/refs"):
            if self.claim_created:
                raise FollowupCampaignControlError(
                    "provider ref already exists"
                )
            self.claim_created = True
        return super().request(
            method=method,
            path=path,
            payload=payload,
            expected_statuses=expected_statuses,
            maximum_bytes=maximum_bytes,
        )


class _ArtifactIdentityDriftTransport(_FakeGitHubTransport):
    def __init__(self, drift: str) -> None:
        super().__init__()
        self.drift = drift

    def _artifacts(self) -> dict[str, object]:
        document = super()._artifacts()
        rows = document["artifacts"]
        assert type(rows) is list and rows and type(rows[0]) is dict
        if self.drift == "expired":
            rows[0]["expired"] = True
        elif self.drift == "wrong-run":
            workflow_run = rows[0]["workflow_run"]
            assert type(workflow_run) is dict
            workflow_run["id"] = RUN_ID + 1
        else:  # pragma: no cover - the test owns the closed drift domain
            raise AssertionError(self.drift)
        return document


class _UnclassifiedProviderFailureTransport(_FakeGitHubTransport):
    def __init__(self) -> None:
        super().__init__(successful=False)

    def _jobs(self) -> dict[str, object]:
        document = super()._jobs()
        rows = document["jobs"]
        assert type(rows) is list and rows and type(rows[0]) is dict
        rows[0]["conclusion"] = "failure"
        return document


def _provider(transport: _FakeGitHubTransport) -> GitHubFollowupCampaignProvider:
    return GitHubFollowupCampaignProvider(
        repository="example/project",
        expected_s2_sha=S2,
        transport=transport,
        poll_interval_seconds=1,
        assignment_timeout_seconds=30,
        cancellation_observation_seconds=30,
    )


def _inputs() -> dict[str, str]:
    return {
        "expected_campaign_id": "3" * 64,
        "expected_compatibility_receipt_sha256": "4" * 64,
        "expected_job_token": "formal-00-acquisition",
        "expected_reservation_oid": "a" * 40,
        "expected_reservation_minutes": "20",
        "expected_s1_git_sha": "1" * 40,
        "expected_s2_git_sha": S2,
        "formal_unit_ordinal": "0",
        "unit_attempt_ordinal": "1",
    }


def _qualification_request() -> FollowupDispatchPrerequisites:
    return FollowupDispatchPrerequisites(
        expected_s1_git_sha="1" * 40,
        expected_s2_git_sha=S2,
        expected_compatibility_receipt_sha256="4" * 64,
        ci_run_id=1,
        pre_s1_run_id=2,
        registration_run_id=3,
        source_anchor_run_id=4,
        independent_review_run_id=5,
    )


def test_github_qualification_claim_dispatch_watch_cas_and_terminal_evidence() -> None:
    transport = _FakeGitHubTransport(qualification=True)
    provider = _provider(transport)
    opening = FollowupQualificationOpening(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
    )

    claim_oid, tree_oid = provider.open_qualification(opening)
    run_id = provider.dispatch_qualification_run(
        inputs={
            "expected_authority_claim_oid": claim_oid,
            "expected_compatibility_receipt_sha256": "4" * 64,
            "expected_s1_git_sha": "1" * 40,
            "expected_s2_git_sha": S2,
        }
    )
    watcher = provider.start_qualification_watch(
        provider_run_id=run_id,
        request=_qualification_request(),
    )
    binding = build_followup_qualification_watch_binding(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
        provider_run_id=run_id,
        watcher_session_sha256=watcher.session_sha256,
        workflow_ref=provider.qualification_workflow_ref,
    )
    binding_oid = provider.install_qualification_watch_binding(
        expected_claim_oid=claim_oid,
        expected_tree_oid=tree_oid,
        binding=binding,
    )
    result = watcher.wait()
    evidence = provider.read_qualification_terminal_evidence(run_id)

    assert claim_oid == S2
    assert tree_oid == "b" * 40
    assert binding_oid == "0" * 39 + "1"
    assert result.qualification_decision == "qualification-go"
    assert json.loads(evidence.run_json)["id"] == RUN_ID
    assert json.loads(evidence.jobs_json)["total_count"] == 6
    assert json.loads(evidence.artifacts_json)["total_count"] == 6
    graphql_payload = next(
        payload
        for method, path, payload in transport.calls
        if method == "POST" and path == "/graphql"
    )
    assert graphql_payload is not None
    update = json.loads(graphql_payload)["variables"]["input"]["refUpdates"][0]
    assert update["name"].endswith(
        "dynamic-cssc-followup-performance-qualification-authority-v1"
    )


def test_two_controllers_cannot_both_create_the_provider_global_qualification_claim() -> None:
    transport = _DuplicateQualificationClaimTransport()
    first = _provider(transport)
    second = _provider(transport)
    opening = FollowupQualificationOpening(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
    )

    assert first.open_qualification(opening)[0] == S2
    with pytest.raises(FollowupCampaignControlError, match="already exists"):
        second.open_qualification(opening)


def test_github_terminal_transport_claim_dispatch_and_watch_cas() -> None:
    transport_adapter = _FakeGitHubTransport()
    provider = _provider(transport_adapter)
    content = b"campaign-transport-sentinel"
    transport = FollowupCampaignTransport(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        member_count=180,
        expanded_bytes=2_000_000,
    )
    claim = build_followup_terminal_claim(
        campaign_id="3" * 64,
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
        final_progress_oid="a" * 40,
        campaign_selection_sha256="5" * 64,
        formal_timing_ledger_sha256="6" * 64,
        campaign_transport_sha256=transport.sha256,
        campaign_transport_member_count=transport.member_count,
        campaign_transport_expanded_bytes=transport.expanded_bytes,
    )

    claim_oid, tree_oid = provider.open_terminal(claim, transport)
    run_id = provider.dispatch_terminal_run(
        inputs={
            "expected_campaign_id": "3" * 64,
            "expected_compatibility_receipt_sha256": "4" * 64,
            "expected_s1_git_sha": "1" * 40,
            "expected_s2_git_sha": S2,
            "expected_terminal_claim_oid": claim_oid,
        }
    )
    watcher = provider.start_terminal_watch(
        provider_run_id=run_id,
        claim=claim,
    )
    binding = build_followup_terminal_watch_binding(
        claim,
        claim_oid=claim_oid,
        provider_run_id=run_id,
        watcher_session_sha256=watcher.session_sha256,
        workflow_ref=provider.terminal_workflow_ref,
    )
    binding_oid = provider.install_terminal_watch_binding(
        expected_claim_oid=claim_oid,
        expected_tree_oid=tree_oid,
        binding=binding,
    )
    outcome = watcher.wait()
    outcome_oid = provider.install_terminal_outcome(
        expected_binding_oid=binding_oid,
        expected_tree_oid=tree_oid,
        outcome=outcome,
    )

    assert claim_oid == "0" * 39 + "1"
    assert tree_oid == "d" * 40
    assert run_id == RUN_ID
    assert binding_oid == "0" * 39 + "2"
    assert outcome.decision == "success"
    assert outcome.runner_seconds_or_null == 600
    assert outcome_oid == "0" * 39 + "3"
    graphql_payloads = [
        payload
        for method, path, payload in transport_adapter.calls
        if method == "POST" and path == "/graphql"
    ]
    assert len(graphql_payloads) == 2
    for payload in graphql_payloads:
        assert payload is not None
        update = json.loads(payload)["variables"]["input"]["refUpdates"][0]
        assert update["name"].endswith(
            "dynamic-cssc-followup-performance-formal-terminal-v1"
        )


def test_github_analysis_claim_dispatch_watch_and_outcome_cas() -> None:
    transport = _FakeGitHubTransport()
    terminal_outcome_oid = "f" * 40
    transport.current_ref = terminal_outcome_oid
    provider = _provider(transport)
    claim = build_followup_analysis_claim(
        campaign_id="3" * 64,
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        analysis_source_s3_sha=S3,
        registration_compatibility_receipt_sha256="4" * 64,
        analysis_compatibility_receipt_sha256="5" * 64,
        terminal_outcome_oid=terminal_outcome_oid,
        terminal_provider_run_id=90_001,
        terminal_run_admission_sha256="6" * 64,
        terminal_watcher_receipt_sha256="7" * 64,
        terminal_runner_seconds=10 * 60,
        campaign_transport_sha256="8" * 64,
        campaign_transport_member_count=180,
        campaign_transport_expanded_bytes=2_000_000,
        terminal_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=95_001,
            artifact_name=(
                "followup-performance-v1-formal-terminal-admission-sentinel"
            ),
            provider_digest=f"sha256:{'9' * 64}",
            size_in_bytes=303,
        ),
        aggregate_artifact=FollowupTerminalArtifactBinding(
            provider_artifact_id=95_002,
            artifact_name="followup-performance-v1-formal-aggregate-sentinel",
            provider_digest=f"sha256:{'a' * 64}",
            size_in_bytes=404,
        ),
    )

    claim_oid, tree_oid = provider.open_analysis(claim)
    run_id = provider.dispatch_analysis_run(
        inputs={
            "expected_analysis_claim_oid": claim_oid,
            "expected_analysis_compatibility_receipt_sha256": "5" * 64,
            "expected_campaign_id": "3" * 64,
            "expected_registration_compatibility_receipt_sha256": "4" * 64,
            "expected_s1_git_sha": "1" * 40,
            "expected_s2_git_sha": S2,
            "expected_s3_git_sha": S3,
        }
    )
    watcher = provider.start_analysis_watch(provider_run_id=run_id, claim=claim)
    binding = build_followup_analysis_watch_binding(
        claim,
        claim_oid=claim_oid,
        provider_run_id=run_id,
        watcher_session_sha256=watcher.session_sha256,
        workflow_ref=provider.analysis_workflow_ref,
    )
    binding_oid = provider.install_analysis_watch_binding(
        expected_claim_oid=claim_oid,
        expected_tree_oid=tree_oid,
        binding=binding,
    )
    outcome = watcher.wait()
    outcome_oid = provider.install_analysis_outcome(
        expected_binding_oid=binding_oid,
        expected_tree_oid=tree_oid,
        outcome=outcome,
    )

    assert claim_oid == "0" * 39 + "1"
    assert tree_oid == "d" * 40
    assert binding_oid == "0" * 39 + "2"
    assert outcome_oid == "0" * 39 + "3"
    assert outcome.decision == "success"
    assert outcome.runner_seconds_or_null == 5 * 60
    assert json.loads(outcome.watcher_receipt_bytes)[
        "terminal_segment_seconds_or_null"
    ] == 15 * 60
    graphql_payloads = [
        payload
        for method, path, payload in transport.calls
        if method == "POST" and path == "/graphql"
    ]
    assert len(graphql_payloads) == 2
    for payload in graphql_payloads:
        assert payload is not None
        update = json.loads(payload)["variables"]["input"]["refUpdates"][0]
        assert update["name"].endswith(
            "dynamic-cssc-followup-performance-analysis-v1"
        )


def test_github_state_install_uses_one_update_refs_compare_and_swap() -> None:
    transport = _FakeGitHubTransport()
    provider = _provider(transport)
    state = open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
        qualification_run_id=7001,
        qualification_q6_artifact_id=8001,
        qualification_q6_artifact_digest=f"sha256:{'5' * 64}",
        scientific_profile=PROFILE,
    )

    oid = provider.install_campaign_state(
        expected_oid="a" * 40,
        expected_tree_oid="b" * 40,
        state=state,
    )

    assert oid == "0" * 39 + "1"
    graphql = next(payload for method, path, payload in transport.calls if path == "/graphql")
    assert graphql is not None
    update = json.loads(graphql)["variables"]["input"]["refUpdates"]
    assert update == [
        {
            "afterOid": oid,
            "beforeOid": "a" * 40,
            "force": False,
            "name": (
                "refs/tags/"
                "dynamic-cssc-followup-performance-formal-authority-v1"
            ),
        }
    ]


def test_github_state_install_rejects_a_lost_compare_and_swap() -> None:
    transport = _LostCompareAndSwapTransport()
    provider = _provider(transport)
    state = open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
        qualification_run_id=7001,
        qualification_q6_artifact_id=8001,
        qualification_q6_artifact_digest=f"sha256:{'5' * 64}",
        scientific_profile=PROFILE,
    )

    with pytest.raises(FollowupCampaignControlError, match="candidate was not installed"):
        provider.install_campaign_state(
            expected_oid="a" * 40,
            expected_tree_oid="b" * 40,
            state=state,
        )

    assert transport.current_ref == "f" * 40


def test_github_campaign_open_creates_the_progress_ref_at_the_opening_commit() -> None:
    transport = _FakeGitHubTransport()
    provider = _provider(transport)
    opened = open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="4" * 64,
        qualification_run_id=7001,
        qualification_q6_artifact_id=8001,
        qualification_q6_artifact_digest=f"sha256:{'5' * 64}",
        scientific_profile=PROFILE,
    )

    opening_oid, tree_oid = provider.open_campaign(opened)

    assert opening_oid == "0" * 39 + "1"
    assert tree_oid == "b" * 40
    create_ref = next(
        payload
        for method, path, payload in transport.calls
        if method == "POST" and path.endswith("/git/refs")
    )
    assert create_ref is not None
    assert json.loads(create_ref) == {
        "ref": (
            "refs/tags/"
            "dynamic-cssc-followup-performance-formal-authority-v1"
        ),
        "sha": opening_oid,
    }


def test_github_dispatch_returns_exact_run_and_watcher_closes_success() -> None:
    transport = _FakeGitHubTransport()
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]

    run_id = provider.dispatch_formal_unit(inputs=_inputs())
    watcher = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    )
    outcome = watcher.wait()

    assert run_id == RUN_ID
    assert outcome.decision == "success"
    assert outcome.artifact_id_or_null == 93_002
    assert outcome.unit_output_envelope_sha256_or_null == "9" * 64
    assert outcome.provider_guard_receipt_bytes_or_null is not None
    assert hashlib.sha256(outcome.watcher_receipt_bytes).hexdigest() == (
        outcome.watcher_receipt_sha256
    )


def test_github_watcher_only_classifies_explicit_startup_failure_for_retry() -> None:
    transport = _FakeGitHubTransport(successful=False)
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "provider-failure"
    assert (
        outcome.provider_failure_class_or_null
        == "hosted-runner-assignment-failure"
    )
    assert outcome.provider_failure_evidence_bytes_or_null is not None
    assert hashlib.sha256(
        outcome.provider_failure_evidence_bytes_or_null
    ).hexdigest() == outcome.provider_failure_evidence_sha256_or_null


def test_github_watcher_does_not_retry_an_unclassified_provider_failure() -> None:
    transport = _UnclassifiedProviderFailureTransport()
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "no-go"
    assert outcome.provider_failure_class_or_null is None
    assert outcome.no_go_reason_or_null == "scientific-or-guard-failure"


@pytest.mark.parametrize("drift", ["expired", "wrong-run"])
def test_github_watcher_rejects_stale_or_wrong_run_artifact_metadata(
    drift: str,
) -> None:
    transport = _ArtifactIdentityDriftTransport(drift)
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())

    with pytest.raises(
        FollowupCampaignControlError,
        match="formal watcher failed closed",
    ) as caught:
        provider.start_formal_unit_watch(
            provider_run_id=run_id,
            spec=spec,
            reservation_minutes=spec.reservation_minutes,
        ).wait()

    assert caught.value.__cause__ is not None
    assert "provider identity" in str(caught.value.__cause__)


def test_formal_watcher_uses_the_later_jobs_provider_date_for_stop_loss() -> None:
    transport = _DeadlineCancellationTransport()
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())
    transport.observed_at = datetime(2026, 8, 30, 0, 19, 58, tzinfo=UTC)

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "no-go"
    assert outcome.no_go_reason_or_null == "budget-exhausted"
    receipt = json.loads(outcome.watcher_receipt_bytes)
    cancellation = receipt["cancellation_ledger"]
    assert set(cancellation) == {
        "ack_to_watch_decision_seconds",
        "cancel_request_utc",
        "controller_detection_utc",
        "final_conclusion",
        "provider_api_ack_utc",
        "provider_terminal_updated_utc",
        "request_to_ack_seconds",
        "threshold_utc",
        "watch_decided_utc",
    }
    assert cancellation["threshold_utc"] == "2026-08-30T00:20:00Z"
    assert cancellation["final_conclusion"] == "cancelled"
    assert cancellation["provider_terminal_updated_utc"] is not None
    assert cancellation["request_to_ack_seconds"] >= 0
    assert cancellation["ack_to_watch_decision_seconds"] >= 0
    # Dispatch verification and the initial watcher read are the first two run
    # reads.  The third belongs to cancel_formal_unit, proving that the jobs
    # response at the exact deadline triggered cancellation without another poll.
    assert transport.run_reads_at_cancel == [3]
    assert transport.cancelled == [RUN_ID]


def test_formal_assignment_stop_loss_submits_only_one_cancel_request() -> None:
    transport = _DeadlineCancellationTransport(empty_jobs=True)
    provider = GitHubFollowupCampaignProvider(
        repository="example/project",
        expected_s2_sha=S2,
        transport=transport,
        poll_interval_seconds=1,
        assignment_timeout_seconds=1,
        cancellation_observation_seconds=30,
    )
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "no-go"
    assert outcome.no_go_reason_or_null == "budget-exhausted"
    assert transport.run_reads_at_cancel == [4]
    assert transport.cancelled == [RUN_ID]


def test_formal_watcher_never_admits_success_observed_after_cancel_request() -> None:
    transport = _CancelThenSuccessTransport()
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())
    transport.observed_at = datetime(2026, 8, 30, 0, 19, 58, tzinfo=UTC)

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "no-go"
    assert outcome.no_go_reason_or_null == "budget-exhausted"
    assert outcome.artifact_id_or_null is None
    receipt = json.loads(outcome.watcher_receipt_bytes)
    assert receipt["cancellation_ledger"]["final_conclusion"] == "success"
    assert transport.cancelled == [RUN_ID]


def test_formal_watcher_never_reclassifies_a_deadline_cancel_as_provider_retry() -> None:
    transport = _CancelThenStartupFailureTransport()
    provider = _provider(transport)
    spec = followup_formal_unit_specs(PROFILE)[0]
    run_id = provider.dispatch_formal_unit(inputs=_inputs())
    transport.observed_at = datetime(2026, 8, 30, 0, 19, 58, tzinfo=UTC)

    outcome = provider.start_formal_unit_watch(
        provider_run_id=run_id,
        spec=spec,
        reservation_minutes=spec.reservation_minutes,
    ).wait()

    assert outcome.decision == "no-go"
    assert outcome.no_go_reason_or_null == "budget-exhausted"
    assert outcome.provider_failure_class_or_null is None
    assert transport.cancelled == [RUN_ID]
