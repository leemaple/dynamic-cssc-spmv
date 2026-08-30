"""GitHub adapter for the follow-up campaign's atomic provider seam.

The controller owns all state transitions.  This module owns only GitHub's
transport, exact compare-and-swap installation, exact dispatch response, and
one low-frequency watcher that starts before the workflow may cross its seed
gate.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisClaim,
    FollowupAnalysisWatchBinding,
)
from dynamic_cssc.followup_performance_analysis_execution import (
    FollowupAnalysisArtifactBinding,
    FollowupAnalysisWatch,
    FollowupAnalysisWatchOutcome,
    build_followup_analysis_watch_outcome,
    inspect_followup_analysis_phase_receipt,
)
from dynamic_cssc.followup_performance_campaign import (
    FOLLOWUP_FORMAL_PROGRESS_REF,
    FollowupCampaignState,
)
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
    FollowupFormalUnitWatch,
    FollowupFormalUnitWatchOutcome,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
)
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_STUDY_ID,
    _canonical_json_bytes,
)
from dynamic_cssc.followup_performance_controller import (
    FollowupDispatchPrerequisites,
    FollowupFormalAdmissionRequest,
    FollowupQualificationOpening,
    FollowupQualificationWatchResult,
    watch_followup_qualification,
)
from dynamic_cssc.followup_performance_formal_matrix import FollowupFormalUnitSpec
from dynamic_cssc.followup_performance_github_transport import (
    FollowupGitHubTransport as _GitHubTransport,
)
from dynamic_cssc.followup_performance_github_transport import (
    GitHubCliTransport,
    GitHubHttpResponse,
)
from dynamic_cssc.followup_performance_qualification_binding import (
    FollowupQualificationWatchBinding,
)
from dynamic_cssc.followup_performance_qualification_evidence import (
    FollowupQualificationProviderEvidence,
)
from dynamic_cssc.followup_performance_terminal_binding import (
    FollowupTerminalClaim,
    FollowupTerminalWatchBinding,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
    FollowupTerminalWatch,
    FollowupTerminalWatchOutcome,
    build_followup_terminal_watch_outcome,
    inspect_followup_terminal_phase_receipt,
)
from dynamic_cssc.route_a_controller import (
    RouteALiveJobSnapshot,
    RouteALiveQualificationObservation,
    RouteALiveRunSnapshot,
)

__all__ = (
    "GitHubCliTransport",
    "GitHubFollowupCampaignProvider",
    "GitHubHttpResponse",
)

_FORMAL_WORKFLOW = "followup-performance-formal-unit.yml"
_FORMAL_WORKFLOW_PATH = f".github/workflows/{_FORMAL_WORKFLOW}"
_QUALIFICATION_WORKFLOW = "followup-performance-qualification.yml"
_QUALIFICATION_WORKFLOW_PATH = f".github/workflows/{_QUALIFICATION_WORKFLOW}"
_TERMINAL_WORKFLOW = "followup-performance-terminal.yml"
_TERMINAL_WORKFLOW_PATH = f".github/workflows/{_TERMINAL_WORKFLOW}"
_ANALYSIS_WORKFLOW = "followup-performance-analysis.yml"
_ANALYSIS_WORKFLOW_PATH = f".github/workflows/{_ANALYSIS_WORKFLOW}"
_QUALIFICATION_PROGRESS_REF = (
    "refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1"
)
_TERMINAL_PROGRESS_REF = (
    "refs/tags/dynamic-cssc-followup-performance-formal-terminal-v1"
)
_ANALYSIS_PROGRESS_REF = (
    "refs/tags/dynamic-cssc-followup-performance-analysis-v1"
)
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_ARTIFACT_NAME = re.compile(
    r"followup-performance-v1-[a-z0-9][a-z0-9._-]{0,254}\Z"
)
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_LOG_BYTES = 64 * 1024 * 1024
_UPDATE_REFS_MUTATION = """mutation FollowupCampaignCAS($input: UpdateRefsInput!) {
  updateRefs(input: $input) { clientMutationId }
}"""


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise FollowupCampaignControlError(
                f"GitHub JSON contains duplicate key {key!r}"
            )
        value[key] = item
    return value


def _json_object(content: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupCampaignControlError(
                    f"{label} contains non-finite {token}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupCampaignControlError(f"{label} is not readable JSON") from error
    if type(value) is not dict:
        raise FollowupCampaignControlError(f"{label} is not one JSON object")
    return value


def _positive_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupCampaignControlError(f"{field} is not a positive integer")
    return value


def _string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise FollowupCampaignControlError(f"{field} is not a nonempty string")
    return value


def _timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise FollowupCampaignControlError(f"{field} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise FollowupCampaignControlError(f"{field} is not a UTC timestamp") from error
    if parsed.microsecond != 0 or parsed.isoformat().replace("+00:00", "Z") != value:
        raise FollowupCampaignControlError(f"{field} is not canonical UTC seconds")
    return parsed


def _optional_timestamp(value: object, *, field: str) -> datetime | None:
    return None if value is None else _timestamp(value, field=field)


@dataclass(frozen=True, slots=True)
class _DispatchContext:
    inputs: dict[str, str]
    spec_job_token: str


def _response_json(response: GitHubHttpResponse, *, label: str) -> dict[str, object]:
    return _json_object(response.body, label=label)


def _controller_now() -> datetime:
    return datetime.now(UTC)


def _render_utc(value: datetime, *, field: str) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise FollowupCampaignControlError(f"{field} is not timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _elapsed_ceiling(start: datetime, end: datetime, *, field: str) -> int:
    seconds = (end - start).total_seconds()
    if seconds < 0:
        raise FollowupCampaignControlError(f"{field} moved backwards")
    return math.ceil(seconds)


class GitHubFollowupCampaignProvider:
    """Production adapter satisfying the campaign controller's provider seam."""

    def __init__(
        self,
        *,
        repository: str,
        expected_s2_sha: str,
        transport: _GitHubTransport | None = None,
        poll_interval_seconds: int = 15,
        assignment_timeout_seconds: int = 30 * 60,
        cancellation_observation_seconds: int = 5 * 60,
    ) -> None:
        if type(repository) is not str or _REPOSITORY.fullmatch(repository) is None:
            raise FollowupCampaignControlError("GitHub repository must be owner/name")
        if (
            type(expected_s2_sha) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_s2_sha) is None
        ):
            raise FollowupCampaignControlError("GitHub expected S2 is invalid")
        for value, field in (
            (poll_interval_seconds, "poll interval"),
            (assignment_timeout_seconds, "assignment timeout"),
            (cancellation_observation_seconds, "cancellation observation"),
        ):
            if type(value) is not int or value <= 0:
                raise FollowupCampaignControlError(f"GitHub {field} is invalid")
        self._repository = repository
        self._expected_s2 = expected_s2_sha
        self._transport = transport or GitHubCliTransport()
        self._poll_interval = poll_interval_seconds
        self._assignment_timeout = assignment_timeout_seconds
        self._cancellation_observation = cancellation_observation_seconds
        self._repository_node_id: str | None = None
        self._dispatches: dict[int, _DispatchContext] = {}
        self._analysis_claim: FollowupAnalysisClaim | None = None
        self._analysis_claim_oid: str | None = None
        self._analysis_tree_oid: str | None = None

    def _json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[dict[str, object], GitHubHttpResponse]:
        payload_bytes = (
            None
            if payload is None
            else json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        )
        response = self._transport.request(
            method=method,
            path=path,
            payload=payload_bytes,
            expected_statuses=expected_statuses,
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return _response_json(response, label=f"GitHub {path}"), response

    def _target_for_ref(self, ref_name: str) -> str:
        if (
            type(ref_name) is not str
            or not ref_name.startswith("refs/tags/")
            or ".." in ref_name
        ):
            raise FollowupCampaignControlError("GitHub progress ref changed")
        ref_path = quote(ref_name.removeprefix("refs/"), safe="/")
        document, _response = self._json(
            "GET",
            f"/repos/{self._repository}/git/ref/{ref_path}",
        )
        target = document.get("object")
        oid = target.get("sha") if type(target) is dict else None
        if (
            document.get("ref") != ref_name
            or type(target) is not dict
            or target.get("type") != "commit"
            or type(oid) is not str
            or _LOWER_GIT_SHA.fullmatch(oid) is None
        ):
            raise FollowupCampaignControlError("GitHub progress ref changed")
        return oid

    def _main_target(self) -> str:
        document, _response = self._json(
            "GET",
            f"/repos/{self._repository}/git/ref/heads/main",
        )
        target = document.get("object")
        oid = target.get("sha") if type(target) is dict else None
        if (
            document.get("ref") != "refs/heads/main"
            or type(target) is not dict
            or target.get("type") != "commit"
            or type(oid) is not str
            or _LOWER_GIT_SHA.fullmatch(oid) is None
        ):
            raise FollowupCampaignControlError("GitHub main ref changed")
        return oid

    def _ref_target(self) -> str:
        return self._target_for_ref(FOLLOWUP_FORMAL_PROGRESS_REF)

    def _node_id(self) -> str:
        if self._repository_node_id is None:
            document, _response = self._json(
                "GET", f"/repos/{self._repository}"
            )
            node_id = _string(document.get("node_id"), field="repository.node_id")
            self._repository_node_id = node_id
        return self._repository_node_id

    def _create_message_commit(
        self,
        *,
        parent_oid: str,
        tree_oid: str,
        message: str,
    ) -> str:
        if (
            _LOWER_GIT_SHA.fullmatch(parent_oid) is None
            or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
            or type(message) is not str
            or not message
            or len(message.encode("utf-8")) > 64 * 1024
        ):
            raise FollowupCampaignControlError("campaign state commit input changed")
        commit, _response = self._json(
            "POST",
            f"/repos/{self._repository}/git/commits",
            payload={
                "message": message,
                "parents": [parent_oid],
                "tree": tree_oid,
            },
            expected_statuses=frozenset({201}),
        )
        tree = commit.get("tree")
        parents = commit.get("parents")
        candidate_oid = commit.get("sha")
        if (
            type(candidate_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(candidate_oid) is None
            or commit.get("message") != message
            or type(tree) is not dict
            or tree.get("sha") != tree_oid
            or type(parents) is not list
            or len(parents) != 1
            or type(parents[0]) is not dict
            or parents[0].get("sha") != parent_oid
        ):
            raise FollowupCampaignControlError(
                "created campaign state commit changed"
            )
        return candidate_oid

    def _create_state_commit(
        self,
        *,
        parent_oid: str,
        tree_oid: str,
        state: FollowupCampaignState,
    ) -> str:
        return self._create_message_commit(
            parent_oid=parent_oid,
            tree_oid=tree_oid,
            message=state.document_bytes.decode("ascii"),
        )

    def open_campaign(
        self,
        opened: FollowupCampaignState,
    ) -> tuple[str, str]:
        """Atomically create the sole progress ref at ``campaign-open``."""

        if (
            type(opened) is not FollowupCampaignState
            or opened.state != "campaign-open"
            or opened.document["evidence_freeze_S2_sha"] != self._expected_s2
        ):
            raise FollowupCampaignControlError("campaign opening state changed")
        commit, _response = self._json(
            "GET",
            f"/repos/{self._repository}/git/commits/{self._expected_s2}",
        )
        tree = commit.get("tree")
        tree_oid = tree.get("sha") if type(tree) is dict else None
        if (
            commit.get("sha") != self._expected_s2
            or type(tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
        ):
            raise FollowupCampaignControlError("evidence-freeze tree changed")
        opening_oid = self._create_state_commit(
            parent_oid=self._expected_s2,
            tree_oid=tree_oid,
            state=opened,
        )
        created, _created_response = self._json(
            "POST",
            f"/repos/{self._repository}/git/refs",
            payload={"ref": FOLLOWUP_FORMAL_PROGRESS_REF, "sha": opening_oid},
            expected_statuses=frozenset({201}),
        )
        target = created.get("object")
        if (
            created.get("ref") != FOLLOWUP_FORMAL_PROGRESS_REF
            or type(target) is not dict
            or target.get("type") != "commit"
            or target.get("sha") != opening_oid
            or self._ref_target() != opening_oid
        ):
            raise FollowupCampaignControlError(
                "campaign progress ref creation changed"
            )
        return opening_oid, tree_oid

    def _compare_and_swap_ref(
        self,
        *,
        ref_name: str,
        expected_oid: str,
        candidate_oid: str,
        client_mutation_id: str,
    ) -> str:
        if (
            type(ref_name) is not str
            or not ref_name.startswith("refs/tags/")
            or _LOWER_GIT_SHA.fullmatch(expected_oid) is None
            or _LOWER_GIT_SHA.fullmatch(candidate_oid) is None
            or type(client_mutation_id) is not str
            or not client_mutation_id
        ):
            raise FollowupCampaignControlError("GitHub updateRefs input changed")
        mutation_error: BaseException | None = None
        try:
            graphql, _graphql_response = self._json(
                "POST",
                "/graphql",
                payload={
                    "query": _UPDATE_REFS_MUTATION,
                    "variables": {
                        "input": {
                            "clientMutationId": client_mutation_id,
                            "repositoryId": self._node_id(),
                            "refUpdates": [
                                {
                                    "afterOid": candidate_oid,
                                    "beforeOid": expected_oid,
                                    "force": False,
                                    "name": ref_name,
                                }
                            ],
                        }
                    },
                },
            )
            data = graphql.get("data")
            update = data.get("updateRefs") if type(data) is dict else None
            if (
                "errors" in graphql
                or type(update) is not dict
                or update.get("clientMutationId") != client_mutation_id
            ):
                raise FollowupCampaignControlError(
                    "GitHub updateRefs response changed"
                )
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            mutation_error = error
        observed_oid = self._target_for_ref(ref_name)
        if observed_oid == candidate_oid:
            return candidate_oid
        if mutation_error is not None:
            raise FollowupCampaignControlError(
                "GitHub updateRefs failed and the candidate was not installed"
            ) from mutation_error
        raise FollowupCampaignControlError(
            "GitHub updateRefs did not install the exact candidate"
        )

    def install_campaign_state(
        self,
        *,
        expected_oid: str,
        expected_tree_oid: str,
        state: FollowupCampaignState,
    ) -> str:
        if (
            type(expected_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_oid) is None
            or type(expected_tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_tree_oid) is None
            or type(state) is not FollowupCampaignState
        ):
            raise FollowupCampaignControlError("campaign CAS input changed")
        candidate_oid = self._create_state_commit(
            parent_oid=expected_oid,
            tree_oid=expected_tree_oid,
            state=state,
        )
        return self._compare_and_swap_ref(
            ref_name=FOLLOWUP_FORMAL_PROGRESS_REF,
            expected_oid=expected_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=f"followup-{state.sha256}",
        )

    def _run_document(self, provider_run_id: int) -> tuple[dict[str, object], bytes]:
        document, response = self._json(
            "GET",
            f"/repos/{self._repository}/actions/runs/{provider_run_id}",
        )
        return document, response.body

    @property
    def qualification_workflow_ref(self) -> str:
        return f"{self._repository}/{_QUALIFICATION_WORKFLOW_PATH}@refs/heads/main"

    def open_qualification(
        self,
        opening: FollowupQualificationOpening,
    ) -> tuple[str, str]:
        """Create the one claim ref before the sole qualification dispatch."""

        if (
            type(opening) is not FollowupQualificationOpening
            or opening.evidence_freeze_s2_sha != self._expected_s2
        ):
            raise FollowupCampaignControlError("qualification opening changed")
        workflow = quote(_QUALIFICATION_WORKFLOW, safe="")
        inventory, _inventory_response = self._json(
            "GET",
            f"/repos/{self._repository}/actions/workflows/{workflow}/runs?per_page=100",
        )
        rows = inventory.get("workflow_runs")
        if (
            inventory.get("total_count") != 0
            or type(rows) is not list
            or rows
        ):
            raise FollowupCampaignControlError(
                "qualification workflow already has a provider run"
            )
        commit, _response = self._json(
            "GET",
            f"/repos/{self._repository}/git/commits/{self._expected_s2}",
        )
        tree = commit.get("tree")
        tree_oid = tree.get("sha") if type(tree) is dict else None
        if (
            commit.get("sha") != self._expected_s2
            or type(tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
        ):
            raise FollowupCampaignControlError("qualification S2 tree changed")
        created, _created_response = self._json(
            "POST",
            f"/repos/{self._repository}/git/refs",
            payload={"ref": _QUALIFICATION_PROGRESS_REF, "sha": self._expected_s2},
            expected_statuses=frozenset({201}),
        )
        target = created.get("object")
        if (
            created.get("ref") != _QUALIFICATION_PROGRESS_REF
            or type(target) is not dict
            or target.get("type") != "commit"
            or target.get("sha") != self._expected_s2
            or self._target_for_ref(_QUALIFICATION_PROGRESS_REF)
            != self._expected_s2
        ):
            raise FollowupCampaignControlError(
                "qualification claim ref creation changed"
            )
        return self._expected_s2, tree_oid

    def dispatch_qualification_run(self, *, inputs: dict[str, str]) -> int:
        expected_fields = {
            "expected_authority_claim_oid",
            "expected_compatibility_receipt_sha256",
            "expected_s1_git_sha",
            "expected_s2_git_sha",
        }
        if (
            type(inputs) is not dict
            or set(inputs) != expected_fields
            or any(type(key) is not str or type(value) is not str for key, value in inputs.items())
            or inputs.get("expected_authority_claim_oid") != self._expected_s2
            or inputs.get("expected_s2_git_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("qualification dispatch inputs changed")
        workflow = quote(_QUALIFICATION_WORKFLOW, safe="")
        document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/actions/workflows/{workflow}/dispatches",
            payload={"inputs": inputs, "ref": "main"},
        )
        run_id = _positive_integer(
            document.get("workflow_run_id"),
            field="qualification dispatch.workflow_run_id",
        )
        expected_url = (
            f"https://api.github.com/repos/{self._repository}/actions/runs/{run_id}"
        )
        if document.get("run_url") != expected_url:
            raise FollowupCampaignControlError(
                "qualification dispatch run URL changed"
            )
        run, _raw = self._run_document(run_id)
        if (
            run.get("id") != run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != _QUALIFICATION_WORKFLOW_PATH
            or run.get("head_sha") != self._expected_s2
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
        ):
            raise FollowupCampaignControlError(
                "dispatched qualification run identity changed"
            )
        return run_id

    def install_qualification_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupQualificationWatchBinding,
    ) -> str:
        if (
            expected_claim_oid != self._expected_s2
            or _LOWER_GIT_SHA.fullmatch(expected_tree_oid) is None
            or type(binding) is not FollowupQualificationWatchBinding
            or binding.document["evidence_freeze_S2_sha"] != self._expected_s2
        ):
            raise FollowupCampaignControlError(
                "qualification watch binding input changed"
            )
        candidate_oid = self._create_message_commit(
            parent_oid=expected_claim_oid,
            tree_oid=expected_tree_oid,
            message=binding.document_bytes.decode("ascii"),
        )
        return self._compare_and_swap_ref(
            ref_name=_QUALIFICATION_PROGRESS_REF,
            expected_oid=expected_claim_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=f"followup-qualification-{binding.sha256}",
        )

    def read_live_qualification(
        self,
        provider_run_id: int,
    ) -> RouteALiveQualificationObservation:
        run_response = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{provider_run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        jobs_response = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{provider_run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        run = _response_json(run_response, label="qualification watcher run")
        jobs = _response_json(jobs_response, label="qualification watcher jobs")
        rows = jobs.get("jobs")
        if (
            run.get("id") != provider_run_id
            or run.get("path") != _QUALIFICATION_WORKFLOW_PATH
            or type(rows) is not list
            or jobs.get("total_count") != len(rows)
            or len(rows) > 6
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                "qualification watcher provider identity changed"
            )
        return RouteALiveQualificationObservation(
            observed_at=datetime.now(UTC),
            provider_observed_at=jobs_response.provider_observed_at,
            run=RouteALiveRunSnapshot(
                database_id=_positive_integer(run.get("id"), field="run.id"),
                event=_string(run.get("event"), field="run.event"),
                head_sha=_string(run.get("head_sha"), field="run.head_sha"),
                head_branch=_string(
                    run.get("head_branch"), field="run.head_branch"
                ),
                attempt=_positive_integer(
                    run.get("run_attempt"), field="run.run_attempt"
                ),
                status=_string(run.get("status"), field="run.status"),
                conclusion=(
                    None
                    if run.get("conclusion") is None
                    else _string(run.get("conclusion"), field="run.conclusion")
                ),
                created_at=_timestamp(run.get("created_at"), field="run.created_at"),
                updated_at=_timestamp(run.get("updated_at"), field="run.updated_at"),
            ),
            jobs=tuple(
                RouteALiveJobSnapshot(
                    database_id=_positive_integer(row.get("id"), field="job.id"),
                    name=_string(row.get("name"), field="job.name"),
                    started_at=_optional_timestamp(
                        row.get("started_at"), field="job.started_at"
                    ),
                    completed_at=_optional_timestamp(
                        row.get("completed_at"), field="job.completed_at"
                    ),
                    status=_string(row.get("status"), field="job.status"),
                    conclusion=(
                        None
                        if row.get("conclusion") is None
                        else _string(
                            row.get("conclusion"), field="job.conclusion"
                        )
                    ),
                )
                for row in rows
                if type(row) is dict
            ),
        )

    def start_qualification_watch(
        self,
        *,
        provider_run_id: int,
        request: FollowupDispatchPrerequisites,
    ) -> _GitHubQualificationWatch:
        initial = self.read_live_qualification(provider_run_id)
        return _GitHubQualificationWatch(
            provider=self,
            repository=self._repository,
            provider_run_id=provider_run_id,
            request=request,
            initial_observation=initial,
            poll_interval_seconds=self._poll_interval,
        )

    def read_qualification_terminal_evidence(
        self,
        provider_run_id: int,
    ) -> FollowupQualificationProviderEvidence:
        """Read one fresh terminal provider projection after the watcher closes."""

        run_id = _positive_integer(provider_run_id, field="qualification run ID")
        run_response = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        jobs_response = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{run_id}/jobs?per_page=100",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        artifacts_response = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{run_id}"
                "/artifacts?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        run = _response_json(run_response, label="qualification terminal run")
        jobs = _response_json(jobs_response, label="qualification terminal jobs")
        artifacts = _response_json(
            artifacts_response,
            label="qualification terminal artifacts",
        )
        job_rows = jobs.get("jobs")
        artifact_rows = artifacts.get("artifacts")
        if (
            run.get("id") != run_id
            or run.get("path") != _QUALIFICATION_WORKFLOW_PATH
            or run.get("event") != "workflow_dispatch"
            or run.get("head_sha") != self._expected_s2
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
            or run.get("status") != "completed"
            or type(run.get("conclusion")) is not str
            or type(job_rows) is not list
            or jobs.get("total_count") != len(job_rows)
            or len(job_rows) > 6
            or type(artifact_rows) is not list
            or artifacts.get("total_count") != len(artifact_rows)
            or len(artifact_rows) > 6
        ):
            raise FollowupCampaignControlError(
                "qualification terminal evidence identity changed"
            )
        return FollowupQualificationProviderEvidence(
            observed_at=artifacts_response.provider_observed_at,
            run_json=run_response.body,
            jobs_json=jobs_response.body,
            artifacts_json=artifacts_response.body,
        )

    @property
    def terminal_workflow_ref(self) -> str:
        return f"{self._repository}/{_TERMINAL_WORKFLOW_PATH}@refs/heads/main"

    def _create_terminal_blob(self, transport: FollowupCampaignTransport) -> str:
        if (
            type(transport) is not FollowupCampaignTransport
            or not transport.content
            or hashlib.sha256(transport.content).hexdigest() != transport.sha256
        ):
            raise FollowupCampaignControlError("terminal transport identity changed")
        document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/git/blobs",
            payload={
                "content": base64.b64encode(transport.content).decode("ascii"),
                "encoding": "base64",
            },
            expected_statuses=frozenset({201}),
        )
        blob_oid = document.get("sha")
        if type(blob_oid) is not str or _LOWER_GIT_SHA.fullmatch(blob_oid) is None:
            raise FollowupCampaignControlError("terminal transport blob changed")
        return blob_oid

    def _create_terminal_tree(self, blob_oid: str) -> str:
        if type(blob_oid) is not str or _LOWER_GIT_SHA.fullmatch(blob_oid) is None:
            raise FollowupCampaignControlError("terminal blob OID changed")
        document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/git/trees",
            payload={
                "tree": [
                    {
                        "mode": "100644",
                        "path": "campaign-evidence.zip",
                        "sha": blob_oid,
                        "type": "blob",
                    }
                ]
            },
            expected_statuses=frozenset({201}),
        )
        tree_oid = document.get("sha")
        if type(tree_oid) is not str or _LOWER_GIT_SHA.fullmatch(tree_oid) is None:
            raise FollowupCampaignControlError("terminal evidence tree changed")
        observed, _observed_response = self._json(
            "GET",
            f"/repos/{self._repository}/git/trees/{tree_oid}",
        )
        rows = observed.get("tree")
        if (
            observed.get("sha") != tree_oid
            or observed.get("truncated") is not False
            or type(rows) is not list
            or rows
            != [
                {
                    "mode": "100644",
                    "path": "campaign-evidence.zip",
                    "sha": blob_oid,
                    "type": "blob",
                }
            ]
        ):
            raise FollowupCampaignControlError("terminal evidence tree changed")
        return tree_oid

    def open_terminal(
        self,
        claim: FollowupTerminalClaim,
        transport: FollowupCampaignTransport,
    ) -> tuple[str, str]:
        """Install one immutable evidence claim before terminal dispatch."""

        if (
            type(claim) is not FollowupTerminalClaim
            or type(transport) is not FollowupCampaignTransport
            or claim.document.get("evidence_freeze_S2_sha") != self._expected_s2
            or claim.document.get("campaign_transport_sha256") != transport.sha256
            or claim.document.get("campaign_transport_member_count")
            != transport.member_count
            or claim.document.get("campaign_transport_expanded_bytes")
            != transport.expanded_bytes
        ):
            raise FollowupCampaignControlError("terminal opening changed")
        final_progress_oid = claim.document.get("final_progress_oid")
        if (
            type(final_progress_oid) is not str
            or self._target_for_ref(FOLLOWUP_FORMAL_PROGRESS_REF)
            != final_progress_oid
        ):
            raise FollowupCampaignControlError(
                "terminal opening is not the final campaign progress"
            )
        workflow = quote(_TERMINAL_WORKFLOW, safe="")
        inventory, _inventory_response = self._json(
            "GET",
            f"/repos/{self._repository}/actions/workflows/{workflow}/runs?per_page=100",
        )
        rows = inventory.get("workflow_runs")
        if inventory.get("total_count") != 0 or type(rows) is not list or rows:
            raise FollowupCampaignControlError("terminal workflow already has a run")
        blob_oid = self._create_terminal_blob(transport)
        tree_oid = self._create_terminal_tree(blob_oid)
        claim_oid = self._create_message_commit(
            parent_oid=final_progress_oid,
            tree_oid=tree_oid,
            message=claim.document_bytes.decode("ascii"),
        )
        created, _created_response = self._json(
            "POST",
            f"/repos/{self._repository}/git/refs",
            payload={"ref": _TERMINAL_PROGRESS_REF, "sha": claim_oid},
            expected_statuses=frozenset({201}),
        )
        target = created.get("object")
        if (
            created.get("ref") != _TERMINAL_PROGRESS_REF
            or type(target) is not dict
            or target.get("type") != "commit"
            or target.get("sha") != claim_oid
            or self._target_for_ref(_TERMINAL_PROGRESS_REF) != claim_oid
        ):
            raise FollowupCampaignControlError("terminal claim ref creation changed")
        return claim_oid, tree_oid

    def dispatch_terminal_run(self, *, inputs: dict[str, str]) -> int:
        expected_fields = {
            "expected_campaign_id",
            "expected_compatibility_receipt_sha256",
            "expected_s1_git_sha",
            "expected_s2_git_sha",
            "expected_terminal_claim_oid",
        }
        if (
            type(inputs) is not dict
            or set(inputs) != expected_fields
            or any(
                type(key) is not str or type(value) is not str
                for key, value in inputs.items()
            )
            or inputs.get("expected_s2_git_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("terminal dispatch inputs changed")
        workflow = quote(_TERMINAL_WORKFLOW, safe="")
        document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/actions/workflows/{workflow}/dispatches",
            payload={"inputs": inputs, "ref": "main"},
        )
        run_id = _positive_integer(
            document.get("workflow_run_id"),
            field="terminal dispatch.workflow_run_id",
        )
        if document.get("run_url") != (
            f"https://api.github.com/repos/{self._repository}/actions/runs/{run_id}"
        ):
            raise FollowupCampaignControlError("terminal dispatch run URL changed")
        run, _raw = self._run_document(run_id)
        if (
            run.get("id") != run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != _TERMINAL_WORKFLOW_PATH
            or run.get("head_sha") != self._expected_s2
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
        ):
            raise FollowupCampaignControlError(
                "dispatched terminal run identity changed"
            )
        return run_id

    def install_terminal_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupTerminalWatchBinding,
    ) -> str:
        if (
            type(expected_claim_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_claim_oid) is None
            or type(expected_tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_tree_oid) is None
            or type(binding) is not FollowupTerminalWatchBinding
            or binding.document.get("claim_oid") != expected_claim_oid
            or binding.document.get("evidence_freeze_S2_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("terminal watch binding input changed")
        candidate_oid = self._create_message_commit(
            parent_oid=expected_claim_oid,
            tree_oid=expected_tree_oid,
            message=binding.document_bytes.decode("ascii"),
        )
        return self._compare_and_swap_ref(
            ref_name=_TERMINAL_PROGRESS_REF,
            expected_oid=expected_claim_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=f"followup-terminal-{binding.sha256}",
        )

    def start_terminal_watch(
        self,
        *,
        provider_run_id: int,
        claim: FollowupTerminalClaim,
    ) -> FollowupTerminalWatch:
        run_id = _positive_integer(provider_run_id, field="terminal run ID")
        if (
            type(claim) is not FollowupTerminalClaim
            or claim.document.get("evidence_freeze_S2_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("terminal watcher claim changed")
        initial_run = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        initial_jobs = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return _GitHubTerminalWatch(
            repository=self._repository,
            expected_s2=self._expected_s2,
            transport=self._transport,
            cancel=self.cancel_terminal_run,
            provider_run_id=run_id,
            claim=claim,
            initial_run=initial_run,
            initial_jobs=initial_jobs,
            poll_interval_seconds=self._poll_interval,
            assignment_timeout_seconds=self._assignment_timeout,
            cancellation_observation_seconds=self._cancellation_observation,
        )

    def install_terminal_outcome(
        self,
        *,
        expected_binding_oid: str,
        expected_tree_oid: str,
        outcome: FollowupTerminalWatchOutcome,
    ) -> str:
        if (
            type(expected_binding_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_binding_oid) is None
            or type(expected_tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_tree_oid) is None
            or type(outcome) is not FollowupTerminalWatchOutcome
            or hashlib.sha256(outcome.watcher_receipt_bytes).hexdigest()
            != outcome.watcher_receipt_sha256
        ):
            raise FollowupCampaignControlError("terminal outcome input changed")
        candidate_oid = self._create_message_commit(
            parent_oid=expected_binding_oid,
            tree_oid=expected_tree_oid,
            message=outcome.watcher_receipt_bytes.decode("ascii"),
        )
        return self._compare_and_swap_ref(
            ref_name=_TERMINAL_PROGRESS_REF,
            expected_oid=expected_binding_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=(
                f"followup-terminal-outcome-{outcome.watcher_receipt_sha256}"
            ),
        )

    def cancel_terminal_run(self, provider_run_id: int) -> None:
        run_id = _positive_integer(provider_run_id, field="terminal run ID")
        run, _raw = self._run_document(run_id)
        if run.get("status") == "completed":
            return
        self._transport.request(
            method="POST",
            path=f"/repos/{self._repository}/actions/runs/{run_id}/cancel",
            payload=None,
            expected_statuses=frozenset({202}),
            maximum_bytes=64 * 1024,
        )

    @property
    def analysis_workflow_ref(self) -> str:
        return f"{self._repository}/{_ANALYSIS_WORKFLOW_PATH}@refs/heads/main"

    def open_analysis(self, claim: FollowupAnalysisClaim) -> tuple[str, str]:
        """Install the sole S3 claim on the terminal evidence tree."""

        if (
            type(claim) is not FollowupAnalysisClaim
            or claim.document.get("evidence_freeze_S2_sha") != self._expected_s2
            or self._main_target() != claim.document.get("analysis_source_S3_sha")
        ):
            raise FollowupCampaignControlError("analysis opening changed")
        terminal_outcome_oid = claim.document.get("terminal_outcome_oid")
        if (
            type(terminal_outcome_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(terminal_outcome_oid) is None
            or self._target_for_ref(_TERMINAL_PROGRESS_REF)
            != terminal_outcome_oid
        ):
            raise FollowupCampaignControlError(
                "analysis opening is not the terminal outcome"
            )
        workflow = quote(_ANALYSIS_WORKFLOW, safe="")
        inventory, _inventory_response = self._json(
            "GET",
            f"/repos/{self._repository}/actions/workflows/{workflow}/runs?per_page=100",
        )
        rows = inventory.get("workflow_runs")
        if inventory.get("total_count") != 0 or type(rows) is not list or rows:
            raise FollowupCampaignControlError("analysis workflow already has a run")
        commit, _commit_response = self._json(
            "GET",
            f"/repos/{self._repository}/git/commits/{terminal_outcome_oid}",
        )
        tree = commit.get("tree")
        tree_oid = tree.get("sha") if type(tree) is dict else None
        if (
            commit.get("sha") != terminal_outcome_oid
            or type(tree_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(tree_oid) is None
        ):
            raise FollowupCampaignControlError("analysis evidence tree changed")
        observed, _tree_response = self._json(
            "GET",
            f"/repos/{self._repository}/git/trees/{tree_oid}",
        )
        tree_rows = observed.get("tree")
        if (
            observed.get("sha") != tree_oid
            or observed.get("truncated") is not False
            or type(tree_rows) is not list
            or len(tree_rows) != 1
            or type(tree_rows[0]) is not dict
            or tree_rows[0].get("mode") != "100644"
            or tree_rows[0].get("path") != "campaign-evidence.zip"
            or tree_rows[0].get("type") != "blob"
            or type(tree_rows[0].get("sha")) is not str
            or _LOWER_GIT_SHA.fullmatch(tree_rows[0]["sha"]) is None
        ):
            raise FollowupCampaignControlError("analysis evidence tree changed")
        claim_oid = self._create_message_commit(
            parent_oid=terminal_outcome_oid,
            tree_oid=tree_oid,
            message=claim.document_bytes.decode("ascii"),
        )
        created, _created_response = self._json(
            "POST",
            f"/repos/{self._repository}/git/refs",
            payload={"ref": _ANALYSIS_PROGRESS_REF, "sha": claim_oid},
            expected_statuses=frozenset({201}),
        )
        target = created.get("object")
        if (
            created.get("ref") != _ANALYSIS_PROGRESS_REF
            or type(target) is not dict
            or target.get("type") != "commit"
            or target.get("sha") != claim_oid
            or self._target_for_ref(_ANALYSIS_PROGRESS_REF) != claim_oid
        ):
            raise FollowupCampaignControlError("analysis claim ref creation changed")
        self._analysis_claim = claim
        self._analysis_claim_oid = claim_oid
        self._analysis_tree_oid = tree_oid
        return claim_oid, tree_oid

    def dispatch_analysis_run(self, *, inputs: dict[str, str]) -> int:
        claim = self._analysis_claim
        expected_fields = {
            "expected_analysis_claim_oid",
            "expected_analysis_compatibility_receipt_sha256",
            "expected_campaign_id",
            "expected_registration_compatibility_receipt_sha256",
            "expected_s1_git_sha",
            "expected_s2_git_sha",
            "expected_s3_git_sha",
        }
        if (
            type(inputs) is not dict
            or set(inputs) != expected_fields
            or any(
                type(key) is not str or type(value) is not str
                for key, value in inputs.items()
            )
            or type(claim) is not FollowupAnalysisClaim
            or inputs.get("expected_analysis_claim_oid")
            != self._analysis_claim_oid
            or inputs.get("expected_analysis_compatibility_receipt_sha256")
            != claim.document["analysis_compatibility_receipt_sha256"]
            or inputs.get("expected_campaign_id") != claim.document["campaign_id"]
            or inputs.get("expected_registration_compatibility_receipt_sha256")
            != claim.document["registration_compatibility_receipt_sha256"]
            or inputs.get("expected_s1_git_sha")
            != claim.document["experiment_source_S1_sha"]
            or inputs.get("expected_s2_git_sha")
            != claim.document["evidence_freeze_S2_sha"]
            or inputs.get("expected_s3_git_sha")
            != claim.document["analysis_source_S3_sha"]
            or self._main_target() != claim.document["analysis_source_S3_sha"]
        ):
            raise FollowupCampaignControlError("analysis dispatch inputs changed")
        workflow = quote(_ANALYSIS_WORKFLOW, safe="")
        document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/actions/workflows/{workflow}/dispatches",
            payload={"inputs": inputs, "ref": "main"},
        )
        run_id = _positive_integer(
            document.get("workflow_run_id"),
            field="analysis dispatch.workflow_run_id",
        )
        if document.get("run_url") != (
            f"https://api.github.com/repos/{self._repository}/actions/runs/{run_id}"
        ):
            raise FollowupCampaignControlError("analysis dispatch run URL changed")
        run, _raw = self._run_document(run_id)
        if (
            run.get("id") != run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != _ANALYSIS_WORKFLOW_PATH
            or run.get("head_sha") != claim.document["analysis_source_S3_sha"]
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
        ):
            raise FollowupCampaignControlError(
                "dispatched analysis run identity changed"
            )
        return run_id

    def start_analysis_watch(
        self,
        *,
        provider_run_id: int,
        claim: FollowupAnalysisClaim,
    ) -> FollowupAnalysisWatch:
        run_id = _positive_integer(provider_run_id, field="analysis run ID")
        if (
            type(claim) is not FollowupAnalysisClaim
            or claim != self._analysis_claim
            or claim.document.get("evidence_freeze_S2_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("analysis watcher claim changed")
        initial_run = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        initial_jobs = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return _GitHubAnalysisWatch(
            repository=self._repository,
            transport=self._transport,
            cancel=self.cancel_analysis_run,
            provider_run_id=run_id,
            claim=claim,
            initial_run=initial_run,
            initial_jobs=initial_jobs,
            poll_interval_seconds=self._poll_interval,
            assignment_timeout_seconds=self._assignment_timeout,
            cancellation_observation_seconds=self._cancellation_observation,
        )

    def install_analysis_watch_binding(
        self,
        *,
        expected_claim_oid: str,
        expected_tree_oid: str,
        binding: FollowupAnalysisWatchBinding,
    ) -> str:
        claim = self._analysis_claim
        if (
            expected_claim_oid != self._analysis_claim_oid
            or expected_tree_oid != self._analysis_tree_oid
            or type(binding) is not FollowupAnalysisWatchBinding
            or type(claim) is not FollowupAnalysisClaim
            or binding.document.get("claim_oid") != expected_claim_oid
            or binding.document.get("analysis_source_S3_sha")
            != claim.document["analysis_source_S3_sha"]
        ):
            raise FollowupCampaignControlError("analysis watch binding input changed")
        candidate_oid = self._create_message_commit(
            parent_oid=expected_claim_oid,
            tree_oid=expected_tree_oid,
            message=binding.document_bytes.decode("ascii"),
        )
        return self._compare_and_swap_ref(
            ref_name=_ANALYSIS_PROGRESS_REF,
            expected_oid=expected_claim_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=f"followup-analysis-{binding.sha256}",
        )

    def install_analysis_outcome(
        self,
        *,
        expected_binding_oid: str,
        expected_tree_oid: str,
        outcome: FollowupAnalysisWatchOutcome,
    ) -> str:
        if (
            type(expected_binding_oid) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_binding_oid) is None
            or expected_tree_oid != self._analysis_tree_oid
            or type(outcome) is not FollowupAnalysisWatchOutcome
            or hashlib.sha256(outcome.watcher_receipt_bytes).hexdigest()
            != outcome.watcher_receipt_sha256
        ):
            raise FollowupCampaignControlError("analysis outcome input changed")
        candidate_oid = self._create_message_commit(
            parent_oid=expected_binding_oid,
            tree_oid=expected_tree_oid,
            message=outcome.watcher_receipt_bytes.decode("ascii"),
        )
        return self._compare_and_swap_ref(
            ref_name=_ANALYSIS_PROGRESS_REF,
            expected_oid=expected_binding_oid,
            candidate_oid=candidate_oid,
            client_mutation_id=(
                f"followup-analysis-outcome-{outcome.watcher_receipt_sha256}"
            ),
        )

    def cancel_analysis_run(self, provider_run_id: int) -> None:
        run_id = _positive_integer(provider_run_id, field="analysis run ID")
        run, _raw = self._run_document(run_id)
        if run.get("status") == "completed":
            return
        self._transport.request(
            method="POST",
            path=f"/repos/{self._repository}/actions/runs/{run_id}/cancel",
            payload=None,
            expected_statuses=frozenset({202}),
            maximum_bytes=64 * 1024,
        )

    def cancel_qualification(self, provider_run_id: int) -> None:
        run_id = _positive_integer(provider_run_id, field="qualification run ID")
        run, _raw = self._run_document(run_id)
        if run.get("status") == "completed":
            return
        self._transport.request(
            method="POST",
            path=f"/repos/{self._repository}/actions/runs/{run_id}/cancel",
            payload=None,
            expected_statuses=frozenset({202}),
            maximum_bytes=64 * 1024,
        )

    def dispatch_formal_unit(self, *, inputs: dict[str, str]) -> int:
        if (
            type(inputs) is not dict
            or not inputs
            or any(type(key) is not str or type(value) is not str for key, value in inputs.items())
            or inputs.get("expected_s2_git_sha") != self._expected_s2
        ):
            raise FollowupCampaignControlError("formal dispatch inputs changed")
        workflow = quote(_FORMAL_WORKFLOW, safe="")
        response_document, _response = self._json(
            "POST",
            f"/repos/{self._repository}/actions/workflows/{workflow}/dispatches",
            payload={"inputs": inputs, "ref": "main"},
        )
        run_id = _positive_integer(
            response_document.get("workflow_run_id"),
            field="dispatch.workflow_run_id",
        )
        expected_run_url = (
            f"https://api.github.com/repos/{self._repository}/actions/runs/{run_id}"
        )
        if response_document.get("run_url") != expected_run_url:
            raise FollowupCampaignControlError("formal dispatch run URL changed")
        run, _raw = self._run_document(run_id)
        if (
            run.get("id") != run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != _FORMAL_WORKFLOW_PATH
            or run.get("head_sha") != self._expected_s2
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
        ):
            raise FollowupCampaignControlError("dispatched formal run identity changed")
        job_token = _string(inputs.get("expected_job_token"), field="job token")
        self._dispatches[run_id] = _DispatchContext(
            inputs=dict(inputs),
            spec_job_token=job_token,
        )
        return run_id

    def start_formal_unit_watch(
        self,
        *,
        provider_run_id: int,
        spec: FollowupFormalUnitSpec,
        reservation_minutes: int,
    ) -> FollowupFormalUnitWatch:
        context = self._dispatches.get(provider_run_id)
        if (
            type(spec) is not FollowupFormalUnitSpec
            or type(reservation_minutes) is not int
            or reservation_minutes != spec.reservation_minutes
            or context is None
            or context.spec_job_token != spec.job_token
            or context.inputs.get("formal_unit_ordinal") != str(spec.ordinal)
        ):
            raise FollowupCampaignControlError("formal watcher binding changed")
        initial_run = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{provider_run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        initial_jobs = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{provider_run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return _GitHubFormalUnitWatch(
            repository=self._repository,
            expected_s2=self._expected_s2,
            transport=self._transport,
            cancel=self.cancel_formal_unit,
            provider_run_id=provider_run_id,
            spec=spec,
            reservation_minutes=reservation_minutes,
            campaign_id=context.inputs["expected_campaign_id"],
            unit_attempt_ordinal=int(context.inputs["unit_attempt_ordinal"]),
            initial_run=initial_run,
            initial_jobs=initial_jobs,
            poll_interval_seconds=self._poll_interval,
            assignment_timeout_seconds=self._assignment_timeout,
            cancellation_observation_seconds=self._cancellation_observation,
        )

    def cancel_formal_unit(self, provider_run_id: int) -> None:
        run_id = _positive_integer(provider_run_id, field="formal run ID")
        run, _raw = self._run_document(run_id)
        if run.get("status") == "completed":
            return
        self._transport.request(
            method="POST",
            path=f"/repos/{self._repository}/actions/runs/{run_id}/cancel",
            payload=None,
            expected_statuses=frozenset({202}),
            maximum_bytes=64 * 1024,
        )


class _GitHubQualificationWatch:
    """Background stop-loss that exists before the qualification binding CAS."""

    def __init__(
        self,
        *,
        provider: GitHubFollowupCampaignProvider,
        repository: str,
        provider_run_id: int,
        request: FollowupDispatchPrerequisites,
        initial_observation: RouteALiveQualificationObservation,
        poll_interval_seconds: int,
    ) -> None:
        if (
            type(provider_run_id) is not int
            or provider_run_id <= 0
            or type(request) is not FollowupDispatchPrerequisites
            or type(initial_observation) is not RouteALiveQualificationObservation
            or initial_observation.run.database_id != provider_run_id
        ):
            raise FollowupCampaignControlError(
                "qualification watcher opening changed"
            )
        self._provider = provider
        self._run_id = provider_run_id
        self._request = request
        self._initial: RouteALiveQualificationObservation | None = (
            initial_observation
        )
        self._initial_lock = threading.Lock()
        self._poll_interval = poll_interval_seconds
        session = _canonical_json_bytes(
            {
                "authority": False,
                "evidence_freeze_S2_sha": request.expected_s2_git_sha,
                "provider_run_id": provider_run_id,
                "publication_evidence_admitted": False,
                "repository": repository,
                "schema_version": (
                    "dynamic-cssc-followup-performance-qualification-watcher-session-v1"
                ),
                "study_id": FOLLOWUP_STUDY_ID,
            }
        )
        self._session_sha256 = hashlib.sha256(session).hexdigest()
        self._result: FollowupQualificationWatchResult | None = None
        self._error: BaseException | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"followup-qualification-watch-{provider_run_id}",
            daemon=True,
        )
        self._thread.start()

    @property
    def session_sha256(self) -> str:
        return self._session_sha256

    def read_live_qualification(
        self,
        provider_run_id: int,
    ) -> RouteALiveQualificationObservation:
        if provider_run_id != self._run_id:
            raise FollowupCampaignControlError(
                "qualification watcher run identity changed"
            )
        with self._initial_lock:
            if self._initial is not None:
                observed = self._initial
                self._initial = None
                return observed
        return self._provider.read_live_qualification(provider_run_id)

    def cancel_qualification(self, provider_run_id: int) -> None:
        self._provider.cancel_qualification(provider_run_id)

    def _thread_main(self) -> None:
        try:
            self._result = watch_followup_qualification(
                self,
                FollowupFormalAdmissionRequest(
                    prerequisites=self._request,
                    qualification_run_id=self._run_id,
                ),
                poll_interval_seconds=self._poll_interval,
            )
        except BaseException as error:  # stored and re-raised by wait()
            self._error = error
        finally:
            self._done.set()

    def wait(self) -> FollowupQualificationWatchResult:
        self._done.wait()
        if self._error is not None:
            raise FollowupCampaignControlError(
                "GitHub qualification watcher failed closed"
            ) from self._error
        if self._result is None:
            raise FollowupCampaignControlError(
                "GitHub qualification watcher lost its result"
            )
        return self._result


@dataclass(frozen=True, slots=True)
class _JobProjection:
    document: dict[str, object]
    started_at: datetime | None
    completed_at: datetime | None


class _GitHubTerminalWatch:
    """One background stop-loss for terminal admission and aggregation."""

    _LABEL = "terminal"
    _JOB_NAME = "formal-terminal-admission-and-aggregate"
    _LIMIT = timedelta(minutes=30)
    _WORKFLOW_PATH = _TERMINAL_WORKFLOW_PATH

    def __init__(
        self,
        *,
        repository: str,
        expected_s2: str,
        transport: _GitHubTransport,
        cancel: Callable[[int], None],
        provider_run_id: int,
        claim: FollowupTerminalClaim,
        initial_run: GitHubHttpResponse,
        initial_jobs: GitHubHttpResponse,
        poll_interval_seconds: int,
        assignment_timeout_seconds: int,
        cancellation_observation_seconds: int,
    ) -> None:
        self._repository = repository
        self._expected_head = expected_s2
        self._transport = transport
        self._cancel = cancel
        self._run_id = provider_run_id
        self._claim = claim
        self._initial_run = initial_run
        self._initial_jobs = initial_jobs
        self._poll_interval = poll_interval_seconds
        self._assignment_timeout = assignment_timeout_seconds
        self._cancellation_observation = cancellation_observation_seconds
        self._started_monotonic = time.monotonic()
        session_bytes = _canonical_json_bytes(
            {
                "authority": False,
                "campaign_id": claim.document["campaign_id"],
                "provider_run_id": provider_run_id,
                "publication_evidence_admitted": False,
                "repository": repository,
                "schema_version": (
                    "dynamic-cssc-followup-performance-terminal-watcher-session-v1"
                ),
                "terminal_claim_sha256": claim.sha256,
                "terminal_segment_minutes": 30,
            }
        )
        self._session_sha256 = hashlib.sha256(session_bytes).hexdigest()
        self._outcome: FollowupTerminalWatchOutcome | None = None
        self._error: BaseException | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"followup-terminal-watch-{provider_run_id}",
            daemon=True,
        )
        self._thread.start()

    @property
    def session_sha256(self) -> str:
        return self._session_sha256

    def wait(self) -> FollowupTerminalWatchOutcome:
        self._done.wait()
        if self._error is not None:
            raise FollowupCampaignControlError(
                f"GitHub {self._LABEL} watcher failed closed"
            ) from self._error
        if self._outcome is None:
            raise FollowupCampaignControlError(
                f"GitHub {self._LABEL} watcher lost its outcome"
            )
        return self._outcome

    def _thread_main(self) -> None:
        try:
            self._outcome = self._observe()
        except BaseException as error:  # stored and re-raised by wait()
            self._error = error
        finally:
            self._done.set()

    def _run(self, response: GitHubHttpResponse) -> dict[str, object]:
        run = _response_json(response, label=f"{self._LABEL} watcher run")
        status = run.get("status")
        conclusion = run.get("conclusion")
        if (
            run.get("id") != self._run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != self._WORKFLOW_PATH
            or run.get("head_sha") != self._expected_head
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
            or status not in {"queued", "in_progress", "completed"}
            or (status == "completed" and type(conclusion) is not str)
            or (status != "completed" and conclusion is not None)
        ):
            raise FollowupCampaignControlError(
                f"watched {self._LABEL} run identity changed"
            )
        return run

    def _jobs(self, response: GitHubHttpResponse) -> _JobProjection | None:
        document = _response_json(
            response, label=f"{self._LABEL} watcher jobs"
        )
        rows = document.get("jobs")
        if (
            type(rows) is not list
            or document.get("total_count") != len(rows)
            or len(rows) > 1
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                f"{self._LABEL} watcher job list changed"
            )
        if not rows:
            return None
        raw = rows[0]
        assert type(raw) is dict
        status = raw.get("status")
        conclusion = raw.get("conclusion")
        started_at = _optional_timestamp(
            raw.get("started_at"), field=f"{self._LABEL} job.started_at"
        )
        completed_at = _optional_timestamp(
            raw.get("completed_at"), field=f"{self._LABEL} job.completed_at"
        )
        if (
            raw.get("name") != self._JOB_NAME
            or type(raw.get("id")) is not int
            or raw["id"] <= 0
            or raw.get("run_id") != self._run_id
            or raw.get("run_attempt") != 1
            or status
            not in {"queued", "in_progress", "completed", "waiting", "pending"}
            or (status == "completed" and type(conclusion) is not str)
            or (status != "completed" and conclusion is not None)
            or (status == "completed" and completed_at is None)
            or (status != "completed" and completed_at is not None)
            or (started_at is not None and completed_at is not None and completed_at < started_at)
        ):
            raise FollowupCampaignControlError(
                f"{self._LABEL} watcher job identity changed"
            )
        return _JobProjection(
            document=raw,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _request_observation(
        self,
    ) -> tuple[GitHubHttpResponse, GitHubHttpResponse]:
        run = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{self._run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        jobs = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{self._run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return run, jobs

    def _artifacts(self) -> GitHubHttpResponse:
        return self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{self._run_id}"
                "/artifacts?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )

    def _phase_receipt(self, job: _JobProjection) -> bytes:
        job_id = _positive_integer(job.document.get("id"), field="terminal job ID")
        log = self._transport.request_bytes(
            path=f"/repos/{self._repository}/actions/jobs/{job_id}/logs",
            maximum_bytes=_MAX_LOG_BYTES,
        )
        marker = b"FOLLOWUP_TERMINAL_PHASE_RECEIPT_V1="
        candidates: list[bytes] = []
        for line in log.splitlines():
            offset = line.find(marker)
            if offset >= 0:
                candidates.append(line[offset + len(marker) :].strip())
        if len(candidates) != 1:
            raise FollowupCampaignControlError(
                "terminal log lacks one phase receipt"
            )
        receipt = inspect_followup_terminal_phase_receipt(
            candidates[0],
            expected_formal_timing_ledger_sha256=self._claim.document[
                "formal_timing_ledger_sha256"
            ],  # type: ignore[arg-type]
        )
        return receipt.document_bytes

    def _artifact_bindings(
        self,
        response: GitHubHttpResponse,
        *,
        phase_receipt_bytes: bytes,
    ) -> tuple[FollowupTerminalArtifactBinding, FollowupTerminalArtifactBinding]:
        document = _response_json(response, label="terminal watcher artifacts")
        rows = document.get("artifacts")
        if (
            type(rows) is not list
            or document.get("total_count") != 2
            or len(rows) != 2
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                "successful terminal run lacks two exact artifacts"
            )
        phase = inspect_followup_terminal_phase_receipt(
            phase_receipt_bytes,
            expected_formal_timing_ledger_sha256=self._claim.document[
                "formal_timing_ledger_sha256"
            ],  # type: ignore[arg-type]
        )
        expected_names = {
            phase.document["terminal"]["artifact_name"],  # type: ignore[index]
            phase.document["aggregate"]["artifact_name"],  # type: ignore[index]
        }
        by_name: dict[str, FollowupTerminalArtifactBinding] = {}
        for raw in rows:
            assert type(raw) is dict
            name = raw.get("name")
            workflow_run = raw.get("workflow_run")
            if (
                type(name) is not str
                or name not in expected_names
                or name in by_name
                or type(raw.get("id")) is not int
                or raw["id"] <= 0
                or type(raw.get("size_in_bytes")) is not int
                or raw["size_in_bytes"] <= 0
                or type(raw.get("digest")) is not str
                or _PROVIDER_DIGEST.fullmatch(raw["digest"]) is None
                or raw.get("expired") is not False
                or type(workflow_run) is not dict
                or workflow_run.get("id") != self._run_id
                or workflow_run.get("head_sha") != self._expected_head
            ):
                raise FollowupCampaignControlError(
                    "terminal artifact provider identity changed"
                )
            by_name[name] = FollowupTerminalArtifactBinding(
                provider_artifact_id=raw["id"],
                artifact_name=name,
                provider_digest=raw["digest"],
                size_in_bytes=raw["size_in_bytes"],
            )
        terminal_name = phase.document["terminal"]["artifact_name"]  # type: ignore[index]
        aggregate_name = phase.document["aggregate"]["artifact_name"]  # type: ignore[index]
        assert type(terminal_name) is str and type(aggregate_name) is str
        return by_name[terminal_name], by_name[aggregate_name]

    def _success(
        self,
        *,
        run_response: GitHubHttpResponse,
        jobs_response: GitHubHttpResponse,
        job: _JobProjection,
    ) -> FollowupTerminalWatchOutcome:
        assert job.started_at is not None and job.completed_at is not None
        if job.completed_at - job.started_at > self._LIMIT:
            raise FollowupCampaignControlError(
                "successful terminal run exceeded its reservation"
            )
        phase_bytes = self._phase_receipt(job)
        artifacts_response = self._artifacts()
        terminal_artifact, aggregate_artifact = self._artifact_bindings(
            artifacts_response,
            phase_receipt_bytes=phase_bytes,
        )
        return build_followup_terminal_watch_outcome(
            claim=self._claim,
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_phase_receipt_bytes_or_null=phase_bytes,
            provider_observed_at=artifacts_response.provider_observed_at,
            decision="success",
            job_started_at_or_null=job.started_at,
            job_completed_at_or_null=job.completed_at,
            terminal_artifact_or_null=terminal_artifact,
            aggregate_artifact_or_null=aggregate_artifact,
            cancellation_requested_at_or_null=None,
            cancellation_acknowledged_at_or_null=None,
            no_go_reason_or_null=None,
        )

    def _no_go(
        self,
        *,
        run_response: GitHubHttpResponse,
        jobs_response: GitHubHttpResponse,
        job: _JobProjection | None,
        reason: str,
        cancellation_requested_at: datetime | None,
        cancellation_acknowledged_at: datetime | None,
    ) -> FollowupTerminalWatchOutcome:
        artifacts_response = self._artifacts()
        artifacts = _response_json(
            artifacts_response, label="terminal NO-GO artifacts"
        )
        rows = artifacts.get("artifacts")
        if (
            type(rows) is not list
            or artifacts.get("total_count") != len(rows)
            or len(rows) > 2
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                "terminal NO-GO artifact inventory changed"
            )
        return build_followup_terminal_watch_outcome(
            claim=self._claim,
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_phase_receipt_bytes_or_null=None,
            provider_observed_at=artifacts_response.provider_observed_at,
            decision="no-go",
            job_started_at_or_null=None if job is None else job.started_at,
            job_completed_at_or_null=None if job is None else job.completed_at,
            terminal_artifact_or_null=None,
            aggregate_artifact_or_null=None,
            cancellation_requested_at_or_null=cancellation_requested_at,
            cancellation_acknowledged_at_or_null=cancellation_acknowledged_at,
            no_go_reason_or_null=reason,
        )

    def _observe(self) -> FollowupTerminalWatchOutcome:
        run_response = self._initial_run
        jobs_response = self._initial_jobs
        cancellation_requested_at: datetime | None = None
        cancellation_acknowledged_at: datetime | None = None
        cancellation_monotonic: float | None = None
        local_deadline_monotonic: float | None = None
        reason = f"{self._LABEL} provider run did not succeed"
        while True:
            run = self._run(run_response)
            job = self._jobs(jobs_response)
            provider_now = max(
                run_response.provider_observed_at,
                jobs_response.provider_observed_at,
            )
            monotonic_now = time.monotonic()
            if job is not None and job.started_at is not None:
                provider_deadline = job.started_at + self._LIMIT
                remaining = max(
                    0.0,
                    (provider_deadline - provider_now).total_seconds(),
                )
                candidate = monotonic_now + remaining
                if (
                    local_deadline_monotonic is None
                    or candidate < local_deadline_monotonic
                ):
                    local_deadline_monotonic = candidate
            terminal_success = (
                run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and job is not None
                and job.document.get("status") == "completed"
                and job.document.get("conclusion") == "success"
                and job.started_at is not None
                and job.completed_at is not None
                and job.completed_at <= job.started_at + self._LIMIT
                and cancellation_requested_at is None
            )
            if terminal_success:
                return self._success(
                    run_response=run_response,
                    jobs_response=jobs_response,
                    job=job,
                )
            if run.get("status") == "completed":
                return self._no_go(
                    run_response=run_response,
                    jobs_response=jobs_response,
                    job=job,
                    reason=reason,
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                )
            should_cancel = False
            if job is None or job.started_at is None:
                if monotonic_now - self._started_monotonic >= self._assignment_timeout:
                    reason = f"{self._LABEL} runner assignment gate reached"
                    should_cancel = True
            else:
                provider_deadline = job.started_at + self._LIMIT
                if (
                    provider_now >= provider_deadline
                    or (
                        local_deadline_monotonic is not None
                        and monotonic_now >= local_deadline_monotonic
                    )
                ):
                    reason = f"{self._LABEL} shared segment gate reached"
                    should_cancel = True
                elif (
                    job.document.get("status") == "completed"
                    and job.document.get("conclusion") != "success"
                ):
                    reason = f"{self._LABEL} job failed"
                    should_cancel = True
            if should_cancel and cancellation_requested_at is None:
                cancellation_requested_at = datetime.now(UTC)
                self._cancel(self._run_id)
                cancellation_acknowledged_at = datetime.now(UTC)
                cancellation_monotonic = time.monotonic()
            if (
                cancellation_monotonic is not None
                and monotonic_now - cancellation_monotonic
                >= self._cancellation_observation
            ):
                raise FollowupCampaignControlError(
                    f"cancelled {self._LABEL} run did not reach provider terminal state"
                )
            threading.Event().wait(self._poll_interval)
            run_response, jobs_response = self._request_observation()


class _GitHubAnalysisWatch(_GitHubTerminalWatch):
    """One background stop-loss for the isolated S3 analysis segment."""

    _LABEL = "analysis"
    _JOB_NAME = "isolated-descriptive-analysis"
    _WORKFLOW_PATH = _ANALYSIS_WORKFLOW_PATH

    def __init__(
        self,
        *,
        repository: str,
        transport: _GitHubTransport,
        cancel: Callable[[int], None],
        provider_run_id: int,
        claim: FollowupAnalysisClaim,
        initial_run: GitHubHttpResponse,
        initial_jobs: GitHubHttpResponse,
        poll_interval_seconds: int,
        assignment_timeout_seconds: int,
        cancellation_observation_seconds: int,
    ) -> None:
        limit = claim.document.get("analysis_runner_seconds_limit")
        expected_head = claim.document.get("analysis_source_S3_sha")
        terminal_seconds = claim.document.get("terminal_runner_seconds")
        if (
            type(limit) is not int
            or not 0 < limit <= 30 * 60
            or type(expected_head) is not str
            or _LOWER_GIT_SHA.fullmatch(expected_head) is None
            or type(terminal_seconds) is not int
            or terminal_seconds + limit != 30 * 60
        ):
            raise FollowupCampaignControlError("analysis watcher budget changed")
        self._repository = repository
        self._expected_head = expected_head
        self._transport = transport
        self._cancel = cancel
        self._run_id = provider_run_id
        self._claim = claim
        self._initial_run = initial_run
        self._initial_jobs = initial_jobs
        self._poll_interval = poll_interval_seconds
        self._assignment_timeout = assignment_timeout_seconds
        self._cancellation_observation = cancellation_observation_seconds
        self._started_monotonic = time.monotonic()
        self._LIMIT = timedelta(seconds=limit)
        session_bytes = _canonical_json_bytes(
            {
                "analysis_claim_sha256": claim.sha256,
                "analysis_runner_seconds_limit": limit,
                "authority": False,
                "campaign_id": claim.document["campaign_id"],
                "provider_run_id": provider_run_id,
                "publication_evidence_admitted": False,
                "repository": repository,
                "schema_version": (
                    "dynamic-cssc-followup-performance-analysis-watcher-session-v1"
                ),
                "terminal_runner_seconds": terminal_seconds,
            }
        )
        self._session_sha256 = hashlib.sha256(session_bytes).hexdigest()
        self._outcome: FollowupAnalysisWatchOutcome | None = None
        self._error: BaseException | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"followup-analysis-watch-{provider_run_id}",
            daemon=True,
        )
        self._thread.start()

    def wait(self) -> FollowupAnalysisWatchOutcome:
        self._done.wait()
        if self._error is not None:
            raise FollowupCampaignControlError(
                "GitHub analysis watcher failed closed"
            ) from self._error
        if type(self._outcome) is not FollowupAnalysisWatchOutcome:
            raise FollowupCampaignControlError(
                "GitHub analysis watcher lost its outcome"
            )
        return self._outcome

    def _phase_receipt(self, job: _JobProjection) -> bytes:
        job_id = _positive_integer(job.document.get("id"), field="analysis job ID")
        log = self._transport.request_bytes(
            path=f"/repos/{self._repository}/actions/jobs/{job_id}/logs",
            maximum_bytes=_MAX_LOG_BYTES,
        )
        marker = b"FOLLOWUP_ANALYSIS_PHASE_RECEIPT_V1="
        candidates: list[bytes] = []
        for line in log.splitlines():
            offset = line.find(marker)
            if offset >= 0:
                candidates.append(line[offset + len(marker) :].strip())
        if len(candidates) != 1:
            raise FollowupCampaignControlError(
                "analysis log lacks one phase receipt"
            )
        expected = self._claim.document.get(
            "analysis_compatibility_receipt_sha256"
        )
        if type(expected) is not str:
            raise FollowupCampaignControlError(
                "analysis compatibility identity changed"
            )
        receipt = inspect_followup_analysis_phase_receipt(
            candidates[0],
            expected_analysis_compatibility_receipt_sha256=expected,
        )
        return receipt.document_bytes

    def _artifact_binding(
        self,
        response: GitHubHttpResponse,
        *,
        phase_receipt_bytes: bytes,
    ) -> FollowupAnalysisArtifactBinding:
        document = _response_json(response, label="analysis watcher artifacts")
        rows = document.get("artifacts")
        if (
            type(rows) is not list
            or document.get("total_count") != 1
            or len(rows) != 1
            or type(rows[0]) is not dict
        ):
            raise FollowupCampaignControlError(
                "successful analysis run lacks one exact artifact"
            )
        expected = self._claim.document.get(
            "analysis_compatibility_receipt_sha256"
        )
        if type(expected) is not str:
            raise FollowupCampaignControlError(
                "analysis compatibility identity changed"
            )
        phase = inspect_followup_analysis_phase_receipt(
            phase_receipt_bytes,
            expected_analysis_compatibility_receipt_sha256=expected,
        )
        raw = rows[0]
        assert type(raw) is dict
        name = raw.get("name")
        workflow_run = raw.get("workflow_run")
        if (
            name != phase.document["artifact_name"]
            or type(name) is not str
            or _ARTIFACT_NAME.fullmatch(name) is None
            or not name.startswith("followup-performance-v1-analysis-")
            or type(raw.get("id")) is not int
            or raw["id"] <= 0
            or type(raw.get("size_in_bytes")) is not int
            or raw["size_in_bytes"] <= 0
            or type(raw.get("digest")) is not str
            or _PROVIDER_DIGEST.fullmatch(raw["digest"]) is None
            or raw.get("expired") is not False
            or type(workflow_run) is not dict
            or workflow_run.get("id") != self._run_id
            or workflow_run.get("head_sha") != self._expected_head
        ):
            raise FollowupCampaignControlError(
                "analysis artifact provider identity changed"
            )
        return FollowupAnalysisArtifactBinding(
            provider_artifact_id=raw["id"],
            artifact_name=name,
            provider_digest=raw["digest"],
            size_in_bytes=raw["size_in_bytes"],
        )

    def _success(
        self,
        *,
        run_response: GitHubHttpResponse,
        jobs_response: GitHubHttpResponse,
        job: _JobProjection,
    ) -> FollowupAnalysisWatchOutcome:
        assert job.started_at is not None and job.completed_at is not None
        if job.completed_at - job.started_at > self._LIMIT:
            raise FollowupCampaignControlError(
                "successful analysis run exceeded its shared reservation"
            )
        phase_bytes = self._phase_receipt(job)
        artifacts_response = self._artifacts()
        artifact = self._artifact_binding(
            artifacts_response,
            phase_receipt_bytes=phase_bytes,
        )
        return build_followup_analysis_watch_outcome(
            claim=self._claim,
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_phase_receipt_bytes_or_null=phase_bytes,
            provider_observed_at=artifacts_response.provider_observed_at,
            decision="success",
            job_started_at_or_null=job.started_at,
            job_completed_at_or_null=job.completed_at,
            analysis_artifact_or_null=artifact,
            cancellation_requested_at_or_null=None,
            cancellation_acknowledged_at_or_null=None,
            no_go_reason_or_null=None,
        )

    def _no_go(
        self,
        *,
        run_response: GitHubHttpResponse,
        jobs_response: GitHubHttpResponse,
        job: _JobProjection | None,
        reason: str,
        cancellation_requested_at: datetime | None,
        cancellation_acknowledged_at: datetime | None,
    ) -> FollowupAnalysisWatchOutcome:
        artifacts_response = self._artifacts()
        artifacts = _response_json(
            artifacts_response, label="analysis NO-GO artifacts"
        )
        rows = artifacts.get("artifacts")
        if (
            type(rows) is not list
            or artifacts.get("total_count") != len(rows)
            or len(rows) > 1
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                "analysis NO-GO artifact inventory changed"
            )
        return build_followup_analysis_watch_outcome(
            claim=self._claim,
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_phase_receipt_bytes_or_null=None,
            provider_observed_at=artifacts_response.provider_observed_at,
            decision="no-go",
            job_started_at_or_null=None if job is None else job.started_at,
            job_completed_at_or_null=None if job is None else job.completed_at,
            analysis_artifact_or_null=None,
            cancellation_requested_at_or_null=cancellation_requested_at,
            cancellation_acknowledged_at_or_null=cancellation_acknowledged_at,
            no_go_reason_or_null=reason,
        )


class _GitHubFormalUnitWatch:
    def __init__(
        self,
        *,
        repository: str,
        expected_s2: str,
        transport: _GitHubTransport,
        cancel: Callable[[int], None],
        provider_run_id: int,
        spec: FollowupFormalUnitSpec,
        reservation_minutes: int,
        campaign_id: str,
        unit_attempt_ordinal: int,
        initial_run: GitHubHttpResponse,
        initial_jobs: GitHubHttpResponse,
        poll_interval_seconds: int,
        assignment_timeout_seconds: int,
        cancellation_observation_seconds: int,
    ) -> None:
        self._repository = repository
        self._expected_s2 = expected_s2
        self._transport = transport
        self._cancel = cancel
        self._run_id = provider_run_id
        self._spec = spec
        self._reservation_minutes = reservation_minutes
        self._campaign_id = campaign_id
        self._unit_attempt = unit_attempt_ordinal
        self._initial_run = initial_run
        self._initial_jobs = initial_jobs
        self._poll_interval = poll_interval_seconds
        self._assignment_timeout = assignment_timeout_seconds
        self._cancellation_observation = cancellation_observation_seconds
        self._started_monotonic = time.monotonic()
        session_bytes = _canonical_json_bytes(
            {
                "authority": False,
                "campaign_id": campaign_id,
                "formal_unit_ordinal": spec.ordinal,
                "provider_run_id": provider_run_id,
                "publication_evidence_admitted": False,
                "repository": repository,
                "reservation_minutes": reservation_minutes,
                "schema_version": (
                    "dynamic-cssc-followup-performance-watcher-session-v1"
                ),
                "unit_attempt_ordinal": unit_attempt_ordinal,
            }
        )
        self._session_sha256 = hashlib.sha256(session_bytes).hexdigest()
        self._outcome: FollowupFormalUnitWatchOutcome | None = None
        self._error: BaseException | None = None
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._thread_main,
            name=f"followup-watch-{provider_run_id}",
            daemon=True,
        )
        self._thread.start()

    @property
    def session_sha256(self) -> str:
        return self._session_sha256

    def wait(self) -> FollowupFormalUnitWatchOutcome:
        self._done.wait()
        if self._error is not None:
            raise FollowupCampaignControlError(
                "GitHub formal watcher failed closed"
            ) from self._error
        if self._outcome is None:
            raise FollowupCampaignControlError("GitHub formal watcher lost its outcome")
        return self._outcome

    def _thread_main(self) -> None:
        try:
            self._outcome = self._observe()
        except BaseException as error:  # stored and re-raised at the interface
            self._error = error
        finally:
            self._done.set()

    def _run(self, response: GitHubHttpResponse) -> dict[str, object]:
        run = _response_json(response, label="formal watcher run")
        if (
            run.get("id") != self._run_id
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != _FORMAL_WORKFLOW_PATH
            or run.get("head_sha") != self._expected_s2
            or run.get("head_branch") != "main"
            or run.get("run_attempt") != 1
            or run.get("status") not in {"queued", "in_progress", "completed"}
        ):
            raise FollowupCampaignControlError("watched formal run identity changed")
        return run

    def _jobs(
        self,
        response: GitHubHttpResponse,
    ) -> dict[str, _JobProjection]:
        document = _response_json(response, label="formal watcher jobs")
        rows = document.get("jobs")
        if (
            type(rows) is not list
            or document.get("total_count") != len(rows)
            or len(rows) > 2
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError("formal watcher job list changed")
        expected = {self._spec.producer_job_name, self._spec.guard_job_name}
        result: dict[str, _JobProjection] = {}
        for raw in rows:
            assert type(raw) is dict
            name = raw.get("name")
            if (
                type(name) is not str
                or name not in expected
                or name in result
                or type(raw.get("id")) is not int
                or raw["id"] <= 0
                or raw.get("run_id") != self._run_id
                or raw.get("run_attempt") != 1
                or raw.get("status")
                not in {"queued", "in_progress", "completed", "waiting", "pending"}
                or (
                    raw.get("conclusion") is not None
                    and type(raw.get("conclusion")) is not str
                )
            ):
                raise FollowupCampaignControlError("formal watcher job identity changed")
            result[name] = _JobProjection(
                document=raw,
                started_at=_optional_timestamp(
                    raw.get("started_at"), field=f"{name}.started_at"
                ),
                completed_at=_optional_timestamp(
                    raw.get("completed_at"), field=f"{name}.completed_at"
                ),
            )
        return result

    def _request_observation(
        self,
    ) -> tuple[GitHubHttpResponse, GitHubHttpResponse]:
        run = self._transport.request(
            method="GET",
            path=f"/repos/{self._repository}/actions/runs/{self._run_id}",
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        jobs = self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{self._run_id}"
                "/jobs?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )
        return run, jobs

    def _artifacts(self) -> GitHubHttpResponse:
        return self._transport.request(
            method="GET",
            path=(
                f"/repos/{self._repository}/actions/runs/{self._run_id}"
                "/artifacts?per_page=100"
            ),
            payload=None,
            expected_statuses=frozenset({200}),
            maximum_bytes=_MAX_JSON_BYTES,
        )

    def _provider_failure(
        self,
        jobs: dict[str, _JobProjection],
        *,
        run_bytes: bytes,
        jobs_bytes: bytes,
    ) -> tuple[str, bytes] | None:
        if any(
            job.document.get("conclusion") == "startup_failure"
            for job in jobs.values()
        ):
            evidence = _canonical_json_bytes(
                {
                    "authority": False,
                    "classification": "hosted-runner-assignment-failure",
                    "jobs_api_sha256": hashlib.sha256(jobs_bytes).hexdigest(),
                    "provider_run_id": self._run_id,
                    "publication_evidence_admitted": False,
                    "run_api_sha256": hashlib.sha256(run_bytes).hexdigest(),
                    "schema_version": (
                        "dynamic-cssc-followup-performance-provider-failure-v1"
                    ),
                }
            )
            return "hosted-runner-assignment-failure", evidence
        return None

    def _guard_receipt(
        self,
        guard: _JobProjection,
    ) -> tuple[dict[str, object], bytes]:
        job_id = _positive_integer(guard.document.get("id"), field="guard job ID")
        log = self._transport.request_bytes(
            path=f"/repos/{self._repository}/actions/jobs/{job_id}/logs",
            maximum_bytes=_MAX_LOG_BYTES,
        )
        marker = b"FOLLOWUP_FORMAL_PHASE_RECEIPT_V1="
        candidates: list[bytes] = []
        for line in log.splitlines():
            offset = line.find(marker)
            if offset >= 0:
                candidates.append(line[offset + len(marker) :].strip())
        if len(candidates) != 1:
            raise FollowupCampaignControlError(
                "guard log lacks one formal phase receipt"
            )
        receipt = _json_object(candidates[0], label="formal guard phase receipt")
        if (
            type(receipt.get("artifact_name")) is not str
            or _ARTIFACT_NAME.fullmatch(receipt["artifact_name"]) is None
            or type(receipt.get("unit_identity_sha256")) is not str
            or _LOWER_SHA256.fullmatch(receipt["unit_identity_sha256"]) is None
            or type(receipt.get("unit_output_envelope_sha256")) is not str
            or _LOWER_SHA256.fullmatch(
                receipt["unit_output_envelope_sha256"]
            )
            is None
        ):
            raise FollowupCampaignControlError("formal guard phase receipt changed")
        return receipt, _canonical_json_bytes(receipt)

    def _success_outcome(
        self,
        *,
        run_response: GitHubHttpResponse,
        jobs_response: GitHubHttpResponse,
        jobs: dict[str, _JobProjection],
        producer_started: datetime,
        guard_completed: datetime,
    ) -> FollowupFormalUnitWatchOutcome:
        if guard_completed - producer_started > timedelta(
            minutes=self._reservation_minutes
        ):
            raise FollowupCampaignControlError(
                "successful formal run exceeded its reservation"
            )
        artifacts_response = self._artifacts()
        artifacts_document = _response_json(
            artifacts_response, label="formal watcher artifacts"
        )
        rows = artifacts_document.get("artifacts")
        if (
            type(rows) is not list
            or artifacts_document.get("total_count") != 2
            or len(rows) != 2
            or any(type(row) is not dict for row in rows)
        ):
            raise FollowupCampaignControlError(
                "successful formal run lacks two exact artifacts"
            )
        by_name: dict[str, dict[str, object]] = {}
        for raw in rows:
            assert type(raw) is dict
            name = raw.get("name")
            workflow_run = raw.get("workflow_run")
            if (
                type(name) is not str
                or _ARTIFACT_NAME.fullmatch(name) is None
                or name in by_name
                or type(raw.get("id")) is not int
                or raw["id"] <= 0
                or type(raw.get("size_in_bytes")) is not int
                or raw["size_in_bytes"] <= 0
                or type(raw.get("digest")) is not str
                or _PROVIDER_DIGEST.fullmatch(raw["digest"]) is None
                or raw.get("expired") is not False
                or type(workflow_run) is not dict
                or workflow_run.get("id") != self._run_id
                or workflow_run.get("head_sha") != self._expected_s2
            ):
                raise FollowupCampaignControlError(
                    "formal artifact provider identity changed"
                )
            by_name[name] = raw
        guard = jobs[self._spec.guard_job_name]
        phase_receipt, guard_receipt_bytes = self._guard_receipt(guard)
        artifact_name = phase_receipt["artifact_name"]
        assert type(artifact_name) is str
        final = by_name.get(artifact_name)
        if final is None:
            raise FollowupCampaignControlError(
                "guard receipt does not name a provider artifact"
            )
        artifact_id = _positive_integer(final.get("id"), field="final artifact ID")
        artifact_digest = _string(
            final.get("digest"), field="final artifact digest"
        )
        envelope_sha = _string(
            phase_receipt.get("unit_output_envelope_sha256"),
            field="unit output envelope",
        )
        receipt_bytes = _canonical_json_bytes(
            {
                "artifact_id": artifact_id,
                "artifact_name": artifact_name,
                "artifact_provider_digest": artifact_digest,
                "artifacts_api_sha256": hashlib.sha256(
                    artifacts_response.body
                ).hexdigest(),
                "authority": False,
                "campaign_id": self._campaign_id,
                "cancellation_ledger": None,
                "critical_path_seconds": int(
                    (guard_completed - producer_started).total_seconds()
                ),
                "decision": "success",
                "formal_unit_ordinal": self._spec.ordinal,
                "guard_receipt_bytes_sha256": hashlib.sha256(
                    guard_receipt_bytes
                ).hexdigest(),
                "jobs_api_sha256": hashlib.sha256(jobs_response.body).hexdigest(),
                "provider_run_id": self._run_id,
                "publication_evidence_admitted": False,
                "reservation_minutes": self._reservation_minutes,
                "run_api_sha256": hashlib.sha256(run_response.body).hexdigest(),
                "schema_version": (
                    "dynamic-cssc-followup-performance-watcher-receipt-v3"
                ),
                "unit_attempt_ordinal": self._unit_attempt,
                "unit_output_envelope_sha256": envelope_sha,
                "watcher_session_sha256": self._session_sha256,
            }
        )
        return FollowupFormalUnitWatchOutcome(
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            watcher_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
            watcher_receipt_bytes=receipt_bytes,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_guard_receipt_bytes_or_null=guard_receipt_bytes,
            decision="success",
            artifact_id_or_null=artifact_id,
            artifact_name_or_null=artifact_name,
            artifact_provider_digest_or_null=artifact_digest,
            unit_output_envelope_sha256_or_null=envelope_sha,
            provider_failure_class_or_null=None,
            provider_failure_evidence_sha256_or_null=None,
            provider_failure_evidence_bytes_or_null=None,
            no_go_reason_or_null=None,
        )

    def _terminal_non_success(
        self,
        *,
        run_response: GitHubHttpResponse,
        run: dict[str, object],
        jobs_response: GitHubHttpResponse,
        jobs: dict[str, _JobProjection],
        cancelled_for_deadline: bool,
        cancellation_threshold: datetime | None,
        controller_detection_at: datetime | None,
        cancellation_requested_at: datetime | None,
        cancellation_acknowledged_at: datetime | None,
        watch_decided_at: datetime,
    ) -> FollowupFormalUnitWatchOutcome:
        artifacts_response = self._artifacts()
        classification = (
            None
            if cancelled_for_deadline
            else self._provider_failure(
                jobs,
                run_bytes=run_response.body,
                jobs_bytes=jobs_response.body,
            )
        )
        if classification is None:
            decision = "no-go"
            failure_class = None
            failure_bytes = None
            failure_sha = None
            reason = (
                "budget-exhausted"
                if cancelled_for_deadline
                else "scientific-or-guard-failure"
            )
        else:
            decision = "provider-failure"
            failure_class, failure_bytes = classification
            failure_sha = hashlib.sha256(failure_bytes).hexdigest()
            reason = None
        if cancellation_requested_at is None:
            if any(
                value is not None
                for value in (
                    cancellation_threshold,
                    controller_detection_at,
                    cancellation_acknowledged_at,
                )
            ):
                raise FollowupCampaignControlError(
                    "formal cancellation ledger is partially absent"
                )
            cancellation_ledger = None
        else:
            if (
                controller_detection_at is None
                or cancellation_acknowledged_at is None
            ):
                raise FollowupCampaignControlError(
                    "formal cancellation ledger is partially absent"
                )
            terminal_updated = _timestamp(
                run.get("updated_at"),
                field="formal terminal run updated_at",
            )
            final_conclusion = _string(
                run.get("conclusion"),
                field="formal terminal run conclusion",
            )
            cancellation_ledger = {
                "ack_to_watch_decision_seconds": _elapsed_ceiling(
                    cancellation_acknowledged_at,
                    watch_decided_at,
                    field="formal cancellation ack-to-decision clock",
                ),
                "cancel_request_utc": _render_utc(
                    cancellation_requested_at,
                    field="formal cancellation request",
                ),
                "controller_detection_utc": _render_utc(
                    controller_detection_at,
                    field="formal cancellation detection",
                ),
                "final_conclusion": final_conclusion,
                "provider_api_ack_utc": _render_utc(
                    cancellation_acknowledged_at,
                    field="formal cancellation acknowledgement",
                ),
                "provider_terminal_updated_utc": _render_utc(
                    terminal_updated,
                    field="formal terminal provider update",
                ),
                "request_to_ack_seconds": _elapsed_ceiling(
                    cancellation_requested_at,
                    cancellation_acknowledged_at,
                    field="formal cancellation request-to-ack clock",
                ),
                "threshold_utc": (
                    None
                    if cancellation_threshold is None
                    else _render_utc(
                        cancellation_threshold,
                        field="formal provider threshold",
                    )
                ),
                "watch_decided_utc": _render_utc(
                    watch_decided_at,
                    field="formal watcher decision",
                ),
            }
        receipt_bytes = _canonical_json_bytes(
            {
                "artifacts_api_sha256": hashlib.sha256(
                    artifacts_response.body
                ).hexdigest(),
                "authority": False,
                "campaign_id": self._campaign_id,
                "cancellation_ledger": cancellation_ledger,
                "decision": decision,
                "formal_unit_ordinal": self._spec.ordinal,
                "jobs_api_sha256": hashlib.sha256(jobs_response.body).hexdigest(),
                "no_go_reason_or_null": reason,
                "provider_failure_class_or_null": failure_class,
                "provider_failure_evidence_sha256_or_null": failure_sha,
                "provider_run_id": self._run_id,
                "publication_evidence_admitted": False,
                "run_api_sha256": hashlib.sha256(run_response.body).hexdigest(),
                "schema_version": (
                    "dynamic-cssc-followup-performance-watcher-receipt-v3"
                ),
                "unit_attempt_ordinal": self._unit_attempt,
                "watcher_session_sha256": self._session_sha256,
            }
        )
        return FollowupFormalUnitWatchOutcome(
            provider_run_id=self._run_id,
            watcher_session_sha256=self._session_sha256,
            watcher_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
            watcher_receipt_bytes=receipt_bytes,
            provider_run_json=run_response.body,
            provider_jobs_json=jobs_response.body,
            provider_artifacts_json=artifacts_response.body,
            provider_guard_receipt_bytes_or_null=None,
            decision=decision,  # type: ignore[arg-type]
            artifact_id_or_null=None,
            artifact_name_or_null=None,
            artifact_provider_digest_or_null=None,
            unit_output_envelope_sha256_or_null=None,
            provider_failure_class_or_null=failure_class,
            provider_failure_evidence_sha256_or_null=failure_sha,
            provider_failure_evidence_bytes_or_null=failure_bytes,
            no_go_reason_or_null=reason,
        )

    def _observe(self) -> FollowupFormalUnitWatchOutcome:
        run_response = self._initial_run
        jobs_response = self._initial_jobs
        cancelled_for_deadline = False
        cancelled_at: datetime | None = None
        cancellation_threshold: datetime | None = None
        controller_detection_at: datetime | None = None
        cancellation_requested_at: datetime | None = None
        cancellation_acknowledged_at: datetime | None = None
        while True:
            run = self._run(run_response)
            jobs = self._jobs(jobs_response)
            provider_now = max(
                run_response.provider_observed_at,
                jobs_response.provider_observed_at,
            )
            producer = jobs.get(self._spec.producer_job_name)
            guard = jobs.get(self._spec.guard_job_name)
            producer_started = None if producer is None else producer.started_at
            guard_completed = None if guard is None else guard.completed_at
            if (
                producer_started is None
                and not cancelled_for_deadline
                and (
                    time.monotonic() - self._started_monotonic
                    >= self._assignment_timeout
                )
            ):
                controller_detection_at = _controller_now()
                cancellation_requested_at = _controller_now()
                self._cancel(self._run_id)
                cancellation_acknowledged_at = _controller_now()
                cancelled_for_deadline = True
                cancelled_at = provider_now
            if producer_started is not None:
                deadline = producer_started + timedelta(
                    minutes=self._reservation_minutes
                )
                guard_closed_in_time = (
                    guard is not None
                    and guard.document.get("status") == "completed"
                    and guard.document.get("conclusion") == "success"
                    and guard_completed is not None
                    and guard_completed <= deadline
                )
                if (
                    not guard_closed_in_time
                    and provider_now >= deadline
                    and not cancelled_for_deadline
                ):
                    cancellation_threshold = deadline
                    controller_detection_at = _controller_now()
                    cancellation_requested_at = _controller_now()
                    self._cancel(self._run_id)
                    cancellation_acknowledged_at = _controller_now()
                    cancelled_for_deadline = True
                    cancelled_at = provider_now
            if run.get("status") == "completed":
                if run.get("conclusion") == "success" and not cancelled_for_deadline:
                    if (
                        set(jobs)
                        != {self._spec.producer_job_name, self._spec.guard_job_name}
                        or producer is None
                        or guard is None
                        or producer.document.get("conclusion") != "success"
                        or guard.document.get("conclusion") != "success"
                        or producer_started is None
                        or guard_completed is None
                    ):
                        raise FollowupCampaignControlError(
                            "successful formal run job closure changed"
                        )
                    return self._success_outcome(
                        run_response=run_response,
                        jobs_response=jobs_response,
                        jobs=jobs,
                        producer_started=producer_started,
                        guard_completed=guard_completed,
                    )
                return self._terminal_non_success(
                    run_response=run_response,
                    run=run,
                    jobs_response=jobs_response,
                    jobs=jobs,
                    cancelled_for_deadline=cancelled_for_deadline,
                    cancellation_threshold=cancellation_threshold,
                    controller_detection_at=controller_detection_at,
                    cancellation_requested_at=cancellation_requested_at,
                    cancellation_acknowledged_at=cancellation_acknowledged_at,
                    watch_decided_at=_controller_now(),
                )
            if (
                cancelled_at is not None
                and provider_now
                >= cancelled_at + timedelta(seconds=self._cancellation_observation)
            ):
                raise FollowupCampaignControlError(
                    "cancelled formal run did not reach a provider terminal state"
                )
            threading.Event().wait(self._poll_interval)
            run_response, jobs_response = self._request_observation()
