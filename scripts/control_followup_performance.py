#!/usr/bin/env python3
"""Operate the sole follow-up qualification and formal authority transitions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote

from dynamic_cssc.followup_performance_analysis_execution import (
    execute_followup_analysis,
)
from dynamic_cssc.followup_performance_campaign import open_followup_campaign_state
from dynamic_cssc.followup_performance_campaign_execution import (
    execute_followup_formal_campaign,
)
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_controller import (
    FollowupArtifactSnapshot,
    FollowupControllerError,
    FollowupControlObservation,
    FollowupDispatchPrerequisites,
    FollowupFormalAdmissionRequest,
    FollowupFormalLiveJobSnapshot,
    FollowupFormalLiveObservation,
    FollowupFormalLiveRunSnapshot,
    FollowupJobSnapshot,
    FollowupOneShotInventoryObservation,
    FollowupPrerequisiteObservation,
    FollowupProviderAuthoritySnapshot,
    FollowupQualificationObservation,
    FollowupRunSnapshot,
    FollowupWorkflowInventoryObservation,
    authorize_followup_formal_campaign,
    authorize_followup_qualification_dispatch,
    consume_followup_formal_campaign_capability,
)
from dynamic_cssc.followup_performance_github import GitHubFollowupCampaignProvider
from dynamic_cssc.followup_performance_qualification_execution import (
    execute_followup_qualification,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    execute_followup_terminal,
)
from dynamic_cssc.route_a_controller import (
    RouteALiveJobSnapshot,
    RouteALiveQualificationObservation,
    RouteALiveRunSnapshot,
)

_CONTROL_KINDS = (
    "ci",
    "pre-s1",
    "registration",
    "source-anchor",
    "independent-review",
)
_QUALIFICATION_WORKFLOW = "followup-performance-qualification.yml"
_FORMAL_WORKFLOW = "followup-performance-formal-unit.yml"
_AUTHORITY_REFS = {
    "qualification": (
        "refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1"
    ),
    "formal": "refs/tags/dynamic-cssc-followup-performance-formal-authority-v1",
}
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_CONTROL_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_Q6_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_HTTP_HEADER_BYTES = 64 * 1024


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise FollowupControllerError(f"GitHub response contains duplicate key {key!r}")
        document[key] = value
    return document


def _json_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupControllerError(f"{label} contains non-finite {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupControllerError(f"{label} is not readable JSON") from error
    if type(value) is not dict:
        raise FollowupControllerError(f"{label} is not one JSON object")
    return value


def _integer(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupControllerError(f"{field} is not a positive strict integer")
    return value


def _string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise FollowupControllerError(f"{field} is not a nonempty string")
    return value


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _timestamp(value: object, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp") from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise FollowupControllerError(f"{field} is not a canonical UTC timestamp")
    return parsed


def _optional_timestamp(value: object, field: str) -> datetime | None:
    return None if value is None else _timestamp(value, field)


class GitHubFollowupAdapter:
    """Small GitHub CLI adapter behind the controller's normalized interfaces."""

    def __init__(self, *, repository: str) -> None:
        if (
            type(repository) is not str
            or repository.count("/") != 1
            or any(not token for token in repository.split("/"))
        ):
            raise FollowupControllerError("GitHub repository must be owner/name")
        self._repository = repository
        self._last_provider_date: datetime | None = None

    def _gh(
        self,
        *arguments: str,
        maximum_bytes: int,
        input_bytes: bytes | None = None,
    ) -> bytes:
        environment = os.environ.copy()
        environment["GH_PAGER"] = "cat"
        try:
            completed = subprocess.run(
                ("gh", *arguments),
                input=input_bytes,
                check=True,
                capture_output=True,
                env=environment,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise FollowupControllerError("GitHub CLI request failed") from error
        if len(completed.stdout) > maximum_bytes:
            raise FollowupControllerError("GitHub CLI response exceeded its byte bound")
        return completed.stdout

    def _included_api_response(
        self,
        path: str,
        *,
        maximum_bytes: int,
    ) -> tuple[bytes, datetime]:
        included = self._gh(
            "api",
            "--include",
            path,
            maximum_bytes=maximum_bytes + _MAX_HTTP_HEADER_BYTES,
        )
        separators = tuple(
            (included.find(marker), marker)
            for marker in (b"\r\n\r\n", b"\n\n")
            if included.find(marker) >= 0
        )
        if not separators:
            raise FollowupControllerError("GitHub API response lacks an HTTP header block")
        offset, marker = min(separators, key=lambda item: item[0])
        if offset <= 0 or offset > _MAX_HTTP_HEADER_BYTES:
            raise FollowupControllerError("GitHub API header block exceeded its byte bound")
        raw_headers = included[:offset].replace(b"\r\n", b"\n")
        body = included[offset + len(marker) :]
        lines = raw_headers.split(b"\n")
        try:
            status = lines[0].decode("ascii")
            headers = [line.decode("ascii") for line in lines[1:] if line]
        except UnicodeDecodeError as error:
            raise FollowupControllerError("GitHub API headers are not ASCII") from error
        status_fields = status.split()
        if (
            len(status_fields) < 2
            or not status_fields[0].startswith("HTTP/")
            or status_fields[1] != "200"
            or body.startswith((b"HTTP/", b"HTTP\\"))
            or len(body) > maximum_bytes
        ):
            raise FollowupControllerError(
                "GitHub API response redirected, failed, or exceeded its byte bound"
            )
        date_values = [
            value.strip()
            for line in headers
            if ":" in line
            for name, value in (line.split(":", 1),)
            if name.strip().lower() == "date"
        ]
        if len(date_values) != 1:
            raise FollowupControllerError("GitHub API response lacks one provider Date")
        try:
            provider_date = parsedate_to_datetime(date_values[0])
        except (TypeError, ValueError) as error:
            raise FollowupControllerError("GitHub provider Date is invalid") from error
        if provider_date.tzinfo is None:
            raise FollowupControllerError("GitHub provider Date lacks a UTC offset")
        provider_date = provider_date.astimezone(UTC)
        if (
            self._last_provider_date is not None
            and provider_date < self._last_provider_date
        ):
            raise FollowupControllerError("GitHub provider Date moved backwards")
        self._last_provider_date = provider_date
        return body, provider_date

    def _provider_observed_at(self) -> datetime:
        if self._last_provider_date is None:
            raise FollowupControllerError("GitHub provider time was not observed")
        return self._last_provider_date

    def _api_json(self, path: str) -> dict[str, object]:
        content, _provider_date = self._included_api_response(
            path,
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return _json_object(content, label=f"GitHub API {path}")

    def _api_bytes(self, path: str, *, maximum_bytes: int) -> bytes:
        return self._gh("api", path, maximum_bytes=maximum_bytes)

    def _run_document(self, run_id: int) -> dict[str, object]:
        return self._api_json(
            f"/repos/{self._repository}/actions/runs/{_integer(run_id, 'run ID')}"
        )

    def _workflow_path(self, run: dict[str, object]) -> str:
        path = run.get("path")
        if type(path) is str and path:
            return path
        workflow_id = _integer(run.get("workflow_id"), "run.workflow_id")
        workflow = self._api_json(
            f"/repos/{self._repository}/actions/workflows/{workflow_id}"
        )
        return _string(workflow.get("path"), "workflow.path")

    def _run_snapshot(
        self,
        document: dict[str, object],
        *,
        workflow_path: str,
    ) -> FollowupRunSnapshot:
        return FollowupRunSnapshot(
            database_id=_integer(document.get("id"), "run.id"),
            workflow_path=workflow_path,
            event=_string(document.get("event"), "run.event"),
            head_sha=_string(document.get("head_sha"), "run.head_sha"),
            head_branch=_string(document.get("head_branch"), "run.head_branch"),
            attempt=_integer(document.get("run_attempt"), "run.run_attempt"),
            status=_string(document.get("status"), "run.status"),
            conclusion=_string(document.get("conclusion"), "run.conclusion"),
            created_at=_timestamp(document.get("created_at"), "run.created_at"),
            updated_at=_timestamp(document.get("updated_at"), "run.updated_at"),
        )

    def _terminal_run(self, document: dict[str, object]) -> FollowupRunSnapshot:
        return self._run_snapshot(
            document,
            workflow_path=self._workflow_path(document),
        )

    def _jobs_document(self, run_id: int) -> dict[str, object]:
        return self._api_json(
            f"/repos/{self._repository}/actions/runs/{run_id}/jobs?per_page=100"
        )

    def _terminal_jobs(self, run_id: int) -> tuple[FollowupJobSnapshot, ...]:
        document = self._jobs_document(run_id)
        rows = document.get("jobs")
        if (
            type(rows) is not list
            or document.get("total_count") != len(rows)
            or len(rows) > 100
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupControllerError("GitHub terminal job list is incomplete")
        return tuple(
            FollowupJobSnapshot(
                database_id=_integer(row.get("id"), "job.id"),
                name=_string(row.get("name"), "job.name"),
                started_at=_timestamp(row.get("started_at"), "job.started_at"),
                completed_at=_timestamp(row.get("completed_at"), "job.completed_at"),
                status=_string(row.get("status"), "job.status"),
                conclusion=_string(row.get("conclusion"), "job.conclusion"),
            )
            for row in rows
        )

    def _artifacts_document(self, run_id: int) -> dict[str, object]:
        return self._api_json(
            f"/repos/{self._repository}/actions/runs/{run_id}/artifacts?per_page=100"
        )

    def _artifact(
        self,
        row: dict[str, object],
    ) -> FollowupArtifactSnapshot:
        workflow_run = row.get("workflow_run")
        if type(workflow_run) is not dict or type(row.get("expired")) is not bool:
            raise FollowupControllerError("GitHub artifact provider binding is malformed")
        return FollowupArtifactSnapshot(
            database_id=_integer(row.get("id"), "artifact.id"),
            name=_string(row.get("name"), "artifact.name"),
            digest=_string(row.get("digest"), "artifact.digest"),
            size_in_bytes=_integer(row.get("size_in_bytes"), "artifact.size_in_bytes"),
            expired=row["expired"],
            workflow_run_id=_integer(workflow_run.get("id"), "artifact.workflow_run.id"),
            workflow_run_head_sha=_string(
                workflow_run.get("head_sha"),
                "artifact.workflow_run.head_sha",
            ),
        )

    def _artifacts(
        self,
        run_id: int,
    ) -> tuple[tuple[FollowupArtifactSnapshot, dict[str, object]], ...]:
        document = self._artifacts_document(run_id)
        rows = document.get("artifacts")
        if (
            type(rows) is not list
            or document.get("total_count") != len(rows)
            or len(rows) > 100
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupControllerError("GitHub artifact list is incomplete")
        return tuple((self._artifact(row), row) for row in rows)

    def _download_artifact(
        self,
        row: dict[str, object],
        *,
        maximum_bytes: int,
    ) -> bytes:
        artifact_id = _integer(row.get("id"), "artifact.id")
        return self._api_bytes(
            f"/repos/{self._repository}/actions/artifacts/{artifact_id}/zip",
            maximum_bytes=maximum_bytes,
        )

    def _workflow_run_rows(
        self,
        workflow: str,
    ) -> tuple[dict[str, object], ...]:
        encoded = quote(workflow, safe="")
        document = self._api_json(
            f"/repos/{self._repository}/actions/workflows/{encoded}/runs?per_page=100"
        )
        rows = document.get("workflow_runs")
        if (
            type(rows) is not list
            or document.get("total_count") != len(rows)
            or len(rows) > 100
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupControllerError("GitHub workflow-run inventory is incomplete")
        return tuple(rows)

    def _workflow_run_ids(self, workflow: str) -> tuple[int, ...]:
        return tuple(
            _integer(row.get("id"), "workflow_run.id")
            for row in self._workflow_run_rows(workflow)
        )

    def _workflow_inventory_runs(
        self,
        workflow: str,
    ) -> tuple[FollowupRunSnapshot, ...]:
        return tuple(
            self._run_snapshot(
                row,
                workflow_path=_string(row.get("path"), "workflow_run.path"),
            )
            for row in self._workflow_run_rows(workflow)
        )

    def _authority_binding(
        self,
        *,
        kind: str,
        expected_s2: str,
    ) -> FollowupProviderAuthoritySnapshot:
        if kind not in _AUTHORITY_REFS:
            raise FollowupControllerError("provider authority kind is outside its domain")
        authority_ref = _AUTHORITY_REFS[kind]
        ref_path = quote(authority_ref.removeprefix("refs/"), safe="/")
        ref_document = self._api_json(
            f"/repos/{self._repository}/git/ref/{ref_path}"
        )
        target = ref_document.get("object")
        if (
            ref_document.get("ref") != authority_ref
            or type(target) is not dict
            or target.get("type") != "commit"
        ):
            raise FollowupControllerError("provider authority ref is malformed")
        target_oid = _string(target.get("sha"), "authority.target.sha")
        commit = self._api_json(
            f"/repos/{self._repository}/git/commits/{target_oid}"
        )
        claim = self._api_json(
            f"/repos/{self._repository}/git/commits/{expected_s2}"
        )
        tree = commit.get("tree")
        claim_tree = claim.get("tree")
        parents = commit.get("parents")
        if (
            type(tree) is not dict
            or type(claim_tree) is not dict
            or type(parents) is not list
            or any(type(parent) is not dict for parent in parents)
        ):
            raise FollowupControllerError("provider authority commit is malformed")
        return FollowupProviderAuthoritySnapshot(
            ref_name=authority_ref,
            target_oid=target_oid,
            commit_message=_string(commit.get("message"), "authority.commit.message"),
            tree_oid=_string(tree.get("sha"), "authority.commit.tree.sha"),
            claim_tree_oid=_string(
                claim_tree.get("sha"),
                "authority.claim.tree.sha",
            ),
            parent_oids=tuple(
                _string(parent.get("sha"), "authority.commit.parent.sha")
                for parent in parents
            ),
        )

    def read_prerequisites(
        self,
        run_ids: tuple[int, ...],
    ) -> FollowupPrerequisiteObservation:
        if (
            type(run_ids) is not tuple
            or len(run_ids) != len(_CONTROL_KINDS)
            or any(type(run_id) is not int or run_id <= 0 for run_id in run_ids)
        ):
            raise FollowupControllerError("control run-ID request is malformed")
        controls: list[FollowupControlObservation] = []
        for kind, run_id in zip(_CONTROL_KINDS, run_ids, strict=True):
            run = self._terminal_run(self._run_document(run_id))
            jobs = self._terminal_jobs(run_id)
            artifacts = self._artifacts(run_id)
            if len(artifacts) != 1:
                raise FollowupControllerError("control run does not expose exactly one artifact")
            artifact, row = artifacts[0]
            controls.append(
                FollowupControlObservation(
                    kind=kind,  # type: ignore[arg-type]
                    run=run,
                    jobs=jobs,
                    artifact=artifact,
                    provider_archive_bytes=self._download_artifact(
                        row,
                        maximum_bytes=_MAX_CONTROL_ARCHIVE_BYTES,
                    ),
                )
            )
        qualification_run_ids = self._workflow_run_ids(_QUALIFICATION_WORKFLOW)
        formal_run_ids = self._workflow_run_ids(_FORMAL_WORKFLOW)
        return FollowupPrerequisiteObservation(
            observed_at=self._provider_observed_at(),
            controls=tuple(controls),
            qualification_run_ids=qualification_run_ids,
            formal_run_ids=formal_run_ids,
        )

    def read_one_shot_inventory(self) -> FollowupOneShotInventoryObservation:
        """Reread only mutable workflow inventories after heavy byte validation."""

        qualification_runs = self._workflow_inventory_runs(_QUALIFICATION_WORKFLOW)
        qualification_observed_at = self._provider_observed_at()
        formal_runs = self._workflow_inventory_runs(_FORMAL_WORKFLOW)
        formal_observed_at = self._provider_observed_at()
        return FollowupOneShotInventoryObservation(
            qualification=FollowupWorkflowInventoryObservation(
                observed_at=qualification_observed_at,
                runs=qualification_runs,
            ),
            formal=FollowupWorkflowInventoryObservation(
                observed_at=formal_observed_at,
                runs=formal_runs,
            ),
        )

    def read_qualification(self, run_id: int) -> FollowupQualificationObservation:
        run = self._terminal_run(self._run_document(run_id))
        jobs = self._terminal_jobs(run_id)
        artifacts_with_rows = self._artifacts(run_id)
        q6_rows = tuple(
            row
            for artifact, row in artifacts_with_rows
            if artifact.name.startswith("followup-performance-v1-qualification-q6-")
        )
        if len(q6_rows) != 1:
            raise FollowupControllerError("qualification does not expose one q6 artifact")
        return FollowupQualificationObservation(
            observed_at=self._provider_observed_at(),
            run=run,
            jobs=jobs,
            artifacts=tuple(artifact for artifact, _row in artifacts_with_rows),
            q6_provider_archive_bytes=self._download_artifact(
                q6_rows[0],
                maximum_bytes=_MAX_Q6_ARCHIVE_BYTES,
            ),
            authority_binding=self._authority_binding(
                kind="qualification",
                expected_s2=run.head_sha,
            ),
        )

    def read_live_qualification(
        self,
        run_id: int,
    ) -> RouteALiveQualificationObservation:
        document = self._run_document(run_id)
        jobs_document = self._jobs_document(run_id)
        rows = jobs_document.get("jobs")
        if (
            type(rows) is not list
            or jobs_document.get("total_count") != len(rows)
            or len(rows) > 100
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupControllerError("GitHub live job list is incomplete")
        observed_at = datetime.now(UTC)
        provider_observed_at = self._provider_observed_at()
        return RouteALiveQualificationObservation(
            observed_at=observed_at,
            provider_observed_at=provider_observed_at,
            run=RouteALiveRunSnapshot(
                database_id=_integer(document.get("id"), "run.id"),
                event=_string(document.get("event"), "run.event"),
                head_sha=_string(document.get("head_sha"), "run.head_sha"),
                head_branch=_string(document.get("head_branch"), "run.head_branch"),
                attempt=_integer(document.get("run_attempt"), "run.run_attempt"),
                status=_string(document.get("status"), "run.status"),
                conclusion=_optional_string(document.get("conclusion"), "run.conclusion"),
                created_at=_timestamp(document.get("created_at"), "run.created_at"),
                updated_at=_timestamp(document.get("updated_at"), "run.updated_at"),
            ),
            jobs=tuple(
                RouteALiveJobSnapshot(
                    database_id=_integer(row.get("id"), "job.id"),
                    name=_string(row.get("name"), "job.name"),
                    started_at=_optional_timestamp(row.get("started_at"), "job.started_at"),
                    completed_at=_optional_timestamp(
                        row.get("completed_at"),
                        "job.completed_at",
                    ),
                    status=_string(row.get("status"), "job.status"),
                    conclusion=_optional_string(row.get("conclusion"), "job.conclusion"),
                )
                for row in rows
            ),
        )

    def cancel_qualification(self, run_id: int) -> None:
        self._gh(
            "run",
            "cancel",
            str(_integer(run_id, "run ID")),
            "--repo",
            self._repository,
            maximum_bytes=64 * 1024,
        )

    def read_live_formal(self, run_id: int) -> FollowupFormalLiveObservation:
        document = self._run_document(run_id)
        workflow_path = self._workflow_path(document)
        jobs_document = self._jobs_document(run_id)
        rows = jobs_document.get("jobs")
        if (
            type(rows) is not list
            or jobs_document.get("total_count") != len(rows)
            or len(rows) > 100
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupControllerError("GitHub formal live job list is incomplete")
        provider_observed_at = self._provider_observed_at()
        return FollowupFormalLiveObservation(
            observed_at=datetime.now(UTC),
            provider_observed_at=provider_observed_at,
            run=FollowupFormalLiveRunSnapshot(
                database_id=_integer(document.get("id"), "run.id"),
                workflow_path=workflow_path,
                event=_string(document.get("event"), "run.event"),
                head_sha=_string(document.get("head_sha"), "run.head_sha"),
                head_branch=_string(document.get("head_branch"), "run.head_branch"),
                attempt=_integer(document.get("run_attempt"), "run.run_attempt"),
                status=_string(document.get("status"), "run.status"),
                conclusion=_optional_string(document.get("conclusion"), "run.conclusion"),
                created_at=_timestamp(document.get("created_at"), "run.created_at"),
                updated_at=_timestamp(document.get("updated_at"), "run.updated_at"),
            ),
            jobs=tuple(
                FollowupFormalLiveJobSnapshot(
                    database_id=_integer(row.get("id"), "job.id"),
                    name=_string(row.get("name"), "job.name"),
                    started_at=_optional_timestamp(row.get("started_at"), "job.started_at"),
                    completed_at=_optional_timestamp(
                        row.get("completed_at"),
                        "job.completed_at",
                    ),
                    status=_string(row.get("status"), "job.status"),
                    conclusion=_optional_string(row.get("conclusion"), "job.conclusion"),
                )
                for row in rows
            ),
            authority_binding=self._authority_binding(
                kind="formal",
                expected_s2=_string(document.get("head_sha"), "run.head_sha"),
            ),
        )

    def cancel_formal(self, run_id: int) -> None:
        self._gh(
            "run",
            "cancel",
            str(_integer(run_id, "run ID")),
            "--repo",
            self._repository,
            maximum_bytes=64 * 1024,
        )

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "execute-qualification",
            "execute-formal",
            "execute-analysis",
        ),
    )
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-s1-git-sha", required=True)
    parser.add_argument("--expected-s2-git-sha", required=True)
    parser.add_argument("--expected-compatibility-receipt-sha256", required=True)
    parser.add_argument("--ci-run-id", type=int)
    parser.add_argument("--pre-s1-run-id", type=int)
    parser.add_argument("--registration-run-id", type=int)
    parser.add_argument("--source-anchor-run-id", type=int)
    parser.add_argument("--independent-review-run-id", type=int)
    parser.add_argument("--qualification-run-id", type=int)
    parser.add_argument("--qualification-evidence-root", type=Path)
    parser.add_argument("--campaign-evidence-root", type=Path)
    parser.add_argument("--terminal-evidence-root", type=Path)
    parser.add_argument("--expected-s3-git-sha")
    parser.add_argument("--expected-analysis-compatibility-receipt-sha256")
    parser.add_argument("--analysis-evidence-root", type=Path)
    parser.add_argument("--poll-interval-seconds", type=int, default=15)
    return parser


def _prerequisites(arguments: argparse.Namespace) -> FollowupDispatchPrerequisites:
    control_run_ids = (
        arguments.ci_run_id,
        arguments.pre_s1_run_id,
        arguments.registration_run_id,
        arguments.source_anchor_run_id,
        arguments.independent_review_run_id,
    )
    if any(type(run_id) is not int or run_id <= 0 for run_id in control_run_ids):
        raise FollowupControllerError(
            "five positive control run IDs are required"
        )
    return FollowupDispatchPrerequisites(
        expected_s1_git_sha=arguments.expected_s1_git_sha,
        expected_s2_git_sha=arguments.expected_s2_git_sha,
        expected_compatibility_receipt_sha256=(
            arguments.expected_compatibility_receipt_sha256
        ),
        ci_run_id=arguments.ci_run_id,
        pre_s1_run_id=arguments.pre_s1_run_id,
        registration_run_id=arguments.registration_run_id,
        source_anchor_run_id=arguments.source_anchor_run_id,
        independent_review_run_id=arguments.independent_review_run_id,
    )


def _main(arguments: argparse.Namespace) -> int:
    root = arguments.repository_root.resolve(strict=True)
    if arguments.command == "execute-analysis":
        if any(
            value is not None
            for value in (
                arguments.ci_run_id,
                arguments.pre_s1_run_id,
                arguments.registration_run_id,
                arguments.source_anchor_run_id,
                arguments.independent_review_run_id,
                arguments.qualification_run_id,
                arguments.qualification_evidence_root,
            )
        ):
            raise FollowupControllerError(
                "pre-analysis control inputs are forbidden during analysis"
            )
        if (
            arguments.campaign_evidence_root is None
            or arguments.terminal_evidence_root is None
            or arguments.analysis_evidence_root is None
            or arguments.expected_s3_git_sha is None
            or arguments.expected_analysis_compatibility_receipt_sha256 is None
        ):
            raise FollowupControllerError(
                "campaign, terminal, S3, compatibility, and analysis evidence inputs are required"
            )
        provider = GitHubFollowupCampaignProvider(
            repository=arguments.repository,
            expected_s2_sha=arguments.expected_s2_git_sha,
            poll_interval_seconds=arguments.poll_interval_seconds,
        )
        result = execute_followup_analysis(
            repository_root=root,
            campaign_evidence_root=arguments.campaign_evidence_root.resolve(
                strict=True
            ),
            terminal_evidence_root=arguments.terminal_evidence_root.resolve(
                strict=True
            ),
            analysis_source_s3_sha=arguments.expected_s3_git_sha,
            expected_analysis_compatibility_receipt_sha256=(
                arguments.expected_analysis_compatibility_receipt_sha256
            ),
            provider=provider,
            evidence_root=arguments.analysis_evidence_root.resolve(),
        )
        watcher_document = _json_object(
            result.watch_outcome.watcher_receipt_bytes,
            label="analysis watcher receipt",
        )
        document = {
            "analysis_runner_seconds_or_null": (
                result.watch_outcome.runner_seconds_or_null
            ),
            "analysis_evidence_root": str(result.evidence_root),
            "analysis_provider_run_id": result.provider_run_id,
            "analysis_run_admission_sha256": result.run_admission.sha256,
            "authority_persisted": False,
            "decision": result.decision,
            "terminal_segment_seconds_or_null": (
                watcher_document.get("terminal_segment_seconds_or_null")
            ),
        }
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
        return 0
    prerequisites = _prerequisites(arguments)
    adapter = GitHubFollowupAdapter(repository=arguments.repository)
    if arguments.command == "execute-qualification":
        if (
            arguments.qualification_run_id is not None
            or arguments.campaign_evidence_root is not None
            or arguments.terminal_evidence_root is not None
            or arguments.expected_s3_git_sha is not None
            or arguments.expected_analysis_compatibility_receipt_sha256 is not None
            or arguments.analysis_evidence_root is not None
        ):
            raise FollowupControllerError(
                "formal inputs are forbidden during qualification execution"
            )
        if arguments.qualification_evidence_root is None:
            raise FollowupControllerError(
                "qualification evidence root is required"
            )
        capability = authorize_followup_qualification_dispatch(
            root,
            adapter,
            prerequisites,
        )
        live_provider = GitHubFollowupCampaignProvider(
            repository=arguments.repository,
            expected_s2_sha=prerequisites.expected_s2_git_sha,
            poll_interval_seconds=arguments.poll_interval_seconds,
        )
        result = execute_followup_qualification(
            capability,
            prerequisites,
            live_provider,
            evidence_root=arguments.qualification_evidence_root.resolve(),
        )
        document = {
            "authority_persisted": False,
            "binding_oid": result.binding_oid,
            "operation": "sole-qualification-executed-under-mandatory-watch",
            "evidence_root": str(result.evidence_root),
            "run_admission_sha256": result.run_admission.sha256,
            "run_id": result.provider_run_id,
            "watch": result.watch_result.document,
        }
    else:
        if (
            arguments.qualification_evidence_root is not None
            or arguments.expected_s3_git_sha is not None
            or arguments.expected_analysis_compatibility_receipt_sha256 is not None
            or arguments.analysis_evidence_root is not None
        ):
            raise FollowupControllerError(
                "qualification evidence root is forbidden during formal execution"
            )
        if arguments.qualification_run_id is None:
            raise FollowupControllerError("qualification run ID is required")
        formal_request = FollowupFormalAdmissionRequest(
            prerequisites=prerequisites,
            qualification_run_id=arguments.qualification_run_id,
        )
        if arguments.campaign_evidence_root is None:
            raise FollowupControllerError(
                "campaign evidence root is required for formal execution"
            )
        if arguments.terminal_evidence_root is None:
            raise FollowupControllerError(
                "terminal evidence root is required for formal execution"
            )
        capability = authorize_followup_formal_campaign(
            root,
            adapter,
            adapter,
            formal_request,
        )
        opening = consume_followup_formal_campaign_capability(
            capability,
            formal_request,
        )
        scientific = materialize_followup_scientific_plan(root)
        opened = open_followup_campaign_state(
            experiment_source_s1_sha=opening.experiment_source_s1_sha,
            evidence_freeze_s2_sha=opening.evidence_freeze_s2_sha,
            compatibility_receipt_sha256=(
                opening.compatibility_receipt_sha256
            ),
            qualification_run_id=opening.qualification_run_id,
            qualification_q6_artifact_id=(
                opening.qualification_q6_artifact_id
            ),
            qualification_q6_artifact_digest=(
                opening.qualification_q6_artifact_digest
            ),
            scientific_profile=scientific.scientific_profile,
        )
        campaign_provider = GitHubFollowupCampaignProvider(
            repository=arguments.repository,
            expected_s2_sha=opening.evidence_freeze_s2_sha,
            poll_interval_seconds=arguments.poll_interval_seconds,
        )
        progress_oid, evidence_tree_oid = campaign_provider.open_campaign(opened)
        result = execute_followup_formal_campaign(
            opened,
            progress_oid=progress_oid,
            evidence_tree_oid=evidence_tree_oid,
            scientific_profile=scientific.scientific_profile,
            provider=campaign_provider,
            evidence_root=arguments.campaign_evidence_root.resolve(),
        )
        terminal = (
            None
            if result.decision != "ready-for-terminal"
            else execute_followup_terminal(
                result,
                scientific_profile=scientific.scientific_profile,
                provider=campaign_provider,
                evidence_root=arguments.terminal_evidence_root.resolve(),
            )
        )
        document = {
            "authority_persisted": False,
            "campaign_id": opened.document["campaign_id"],
            "campaign_selection_sha256_or_null": (
                None if result.selection is None else result.selection.sha256
            ),
            "decision": result.decision,
            "evidence_root": str(result.evidence_root),
            "qualification_run_id": arguments.qualification_run_id,
            "timing_ledger_sha256_or_null": (
                None if result.timing is None else result.timing.sha256
            ),
            "terminal_decision_or_null": (
                None if terminal is None else terminal.decision
            ),
            "terminal_evidence_root_or_null": (
                None if terminal is None else str(terminal.evidence_root)
            ),
            "terminal_provider_run_id_or_null": (
                None if terminal is None else terminal.provider_run_id
            ),
            "terminal_run_admission_sha256_or_null": (
                None if terminal is None else terminal.run_admission.sha256
            ),
        }
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError) as error:
        print(f"follow-up controller failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
