from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import dynamic_cssc.followup_performance_campaign_execution as execution_module
from dynamic_cssc.followup_performance_campaign import open_followup_campaign_state
from dynamic_cssc.followup_performance_campaign_bundle import (
    FollowupCampaignEvidenceBundleError,
    inspect_followup_campaign_evidence_bundle,
)
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
    FollowupFormalUnitWatchOutcome,
)
from dynamic_cssc.followup_performance_campaign_execution import (
    execute_followup_formal_campaign,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
    build_followup_campaign_transport,
    install_followup_campaign_transport,
)
from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from dynamic_cssc.followup_performance_controller import FollowupControllerError
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
)
from dynamic_cssc.followup_performance_terminal_evidence import (
    inspect_followup_terminal_evidence_bundle,
)
from dynamic_cssc.followup_performance_terminal_execution import (
    FollowupTerminalArtifactBinding,
    FollowupTerminalWatchOutcome,
    build_followup_terminal_watch_outcome,
    execute_followup_terminal,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"campaign-execution-sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="campaign-execution-sentinel",
    qualification_seed=98_001,
    formal_seeds=(98_002, 98_003, 98_004),
    query_vector_seed=9_800_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)
S2 = "2" * 40


def _opened():  # type: ignore[no-untyped-def]
    return open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha=S2,
        compatibility_receipt_sha256="3" * 64,
        qualification_run_id=7_001,
        qualification_q6_artifact_id=8_001,
        qualification_q6_artifact_digest=f"sha256:{'4' * 64}",
        scientific_profile=PROFILE,
    )


def _render(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Watch:
    def __init__(self, outcome: FollowupFormalUnitWatchOutcome) -> None:
        self._outcome = outcome

    @property
    def session_sha256(self) -> str:
        return self._outcome.watcher_session_sha256

    def wait(self) -> FollowupFormalUnitWatchOutcome:
        return self._outcome


class _SerialProvider:
    def __init__(self, *, provider_failure_ordinal: int | None = None) -> None:
        self.provider_failure_ordinal = provider_failure_ordinal
        self._failed_once = False
        self._oid = 1
        self._run_id = 20_000
        self._artifact_id = 30_000
        self._cursor = datetime(2026, 8, 30, 0, 0, tzinfo=UTC)
        self._dispatch: dict[int, dict[str, str]] = {}
        self.cancelled: list[int] = []

    def install_campaign_state(self, **_kwargs: object) -> str:
        oid = f"{self._oid:040x}"
        self._oid += 1
        return oid

    def dispatch_formal_unit(self, *, inputs: dict[str, str]) -> int:
        run_id = self._run_id
        self._run_id += 1
        self._dispatch[run_id] = dict(inputs)
        return run_id

    def _documents(
        self,
        *,
        run_id: int,
        spec: FollowupFormalUnitSpec,
        successful: bool,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        start = self._cursor
        producer_end = start + timedelta(seconds=3)
        producer = {
            "completed_at": _render(producer_end),
            "conclusion": "success" if successful else "cancelled",
            "id": run_id * 10,
            "name": spec.producer_job_name,
            "run_attempt": 1,
            "run_id": run_id,
            "started_at": _render(start),
            "status": "completed",
        }
        jobs = [producer]
        if successful:
            guard_start = producer_end + timedelta(seconds=1)
            guard_end = guard_start + timedelta(seconds=3)
            jobs.append(
                {
                    "completed_at": _render(guard_end),
                    "conclusion": "success",
                    "id": run_id * 10 + 1,
                    "name": spec.guard_job_name,
                    "run_attempt": 1,
                    "run_id": run_id,
                    "started_at": _render(guard_start),
                    "status": "completed",
                }
            )
            updated = guard_end + timedelta(seconds=1)
        else:
            jobs.append(
                {
                    "completed_at": None,
                    "conclusion": "skipped",
                    "id": run_id * 10 + 1,
                    "name": spec.guard_job_name,
                    "run_attempt": 1,
                    "run_id": run_id,
                    "started_at": None,
                    "status": "completed",
                }
            )
            updated = producer_end + timedelta(seconds=1)
        run = {
            "conclusion": "success" if successful else "cancelled",
            "created_at": _render(start),
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": S2,
            "id": run_id,
            "path": ".github/workflows/followup-performance-formal-unit.yml",
            "run_attempt": 1,
            "status": "completed",
            "updated_at": _render(updated),
        }
        self._cursor = updated + timedelta(seconds=1)
        if successful:
            private_name = (
                f"followup-performance-v1-{spec.unit_kind}-{spec.ordinal:02d}-private"
            )
            final_name = (
                f"followup-performance-v1-{spec.unit_kind}-{spec.ordinal:02d}-final"
            )
            artifacts = [
                {
                    "digest": f"sha256:{self._artifact_id:064x}",
                    "expired": False,
                    "id": self._artifact_id,
                    "name": private_name,
                    "workflow_run": {"head_sha": S2, "id": run_id},
                },
                {
                    "digest": f"sha256:{self._artifact_id + 1:064x}",
                    "expired": False,
                    "id": self._artifact_id + 1,
                    "name": final_name,
                    "workflow_run": {"head_sha": S2, "id": run_id},
                },
            ]
            self._artifact_id += 2
        else:
            artifacts = []
        return (
            _canonical_json_bytes(run),
            _canonical_json_bytes({"jobs": jobs, "total_count": len(jobs)}),
            _canonical_json_bytes(
                {"artifacts": artifacts, "total_count": len(artifacts)}
            ),
            final_name.encode("ascii") if successful else b"",
        )

    def start_formal_unit_watch(
        self,
        *,
        provider_run_id: int,
        spec: FollowupFormalUnitSpec,
        reservation_minutes: int,
    ) -> _Watch:
        del reservation_minutes
        inputs = self._dispatch[provider_run_id]
        attempt = int(inputs["unit_attempt_ordinal"])
        fail = (
            self.provider_failure_ordinal == spec.ordinal
            and attempt == 1
            and not self._failed_once
        )
        if fail:
            self._failed_once = True
        run, jobs, artifacts, final_name_bytes = self._documents(
            run_id=provider_run_id,
            spec=spec,
            successful=not fail,
        )
        session = f"{provider_run_id + 100_000:064x}"
        if fail:
            failure = _canonical_json_bytes(
                {
                    "classification": "hosted-runner-loss-or-shutdown",
                    "provider_run_id": provider_run_id,
                }
            )
            failure_sha = hashlib.sha256(failure).hexdigest()
            guard_log = None
            decision = "provider-failure"
            artifact_id = None
            artifact_name = None
            artifact_digest = None
            envelope = None
            failure_class = "hosted-runner-loss-or-shutdown"
        else:
            failure = None
            failure_sha = None
            guard_log = _canonical_json_bytes(
                {"guard_receipt_sentinel": provider_run_id}
            )
            decision = "success"
            artifact_id = self._artifact_id - 1
            artifact_name = final_name_bytes.decode("ascii")
            artifact_digest = f"sha256:{artifact_id:064x}"
            envelope = f"{provider_run_id + 200_000:064x}"
            failure_class = None
        receipt_document = {
            "artifacts_api_sha256": hashlib.sha256(artifacts).hexdigest(),
            "decision": decision,
            "jobs_api_sha256": hashlib.sha256(jobs).hexdigest(),
            "provider_run_id": provider_run_id,
            "run_api_sha256": hashlib.sha256(run).hexdigest(),
            "watcher_session_sha256": session,
        }
        if guard_log is not None:
            receipt_document["guard_receipt_bytes_sha256"] = hashlib.sha256(
                guard_log
            ).hexdigest()
        receipt = _canonical_json_bytes(receipt_document)
        return _Watch(
            FollowupFormalUnitWatchOutcome(
                provider_run_id=provider_run_id,
                watcher_session_sha256=session,
                watcher_receipt_sha256=hashlib.sha256(receipt).hexdigest(),
                watcher_receipt_bytes=receipt,
                provider_run_json=run,
                provider_jobs_json=jobs,
                provider_artifacts_json=artifacts,
                provider_guard_receipt_bytes_or_null=guard_log,
                decision=decision,  # type: ignore[arg-type]
                artifact_id_or_null=artifact_id,
                artifact_name_or_null=artifact_name,
                artifact_provider_digest_or_null=artifact_digest,
                unit_output_envelope_sha256_or_null=envelope,
                provider_failure_class_or_null=failure_class,
                provider_failure_evidence_sha256_or_null=failure_sha,
                provider_failure_evidence_bytes_or_null=failure,
                no_go_reason_or_null=None,
            )
        )

    def cancel_formal_unit(self, provider_run_id: int) -> None:
        self.cancelled.append(provider_run_id)


@pytest.mark.parametrize("replacement_ordinal", [None, 4])
def test_serial_campaign_rebuilds_complete_selection_timing_and_watcher_evidence(
    tmp_path: Path,
    replacement_ordinal: int | None,
) -> None:
    provider = _SerialProvider(provider_failure_ordinal=replacement_ordinal)
    evidence_root = (tmp_path / "campaign").resolve()

    result = execute_followup_formal_campaign(
        _opened(),
        progress_oid="a" * 40,
        evidence_tree_oid="b" * 40,
        scientific_profile=PROFILE,
        provider=provider,
        evidence_root=evidence_root,
    )
    bundle = inspect_followup_campaign_evidence_bundle(
        evidence_root,
        scientific_profile=PROFILE,
    )

    assert result.decision == "ready-for-terminal"
    assert result.selection is not None
    assert len(bundle.attempts) == (18 if replacement_ordinal is not None else 17)
    assert bundle.timing.document["provider_retry_used"] is (
        replacement_ordinal is not None
    )
    if replacement_ordinal is not None:
        assert bundle.selection.units[replacement_ordinal][
            "unit_attempt_ordinal"
        ] == 2

    watcher = (
        evidence_root / "attempts" / "00-attempt-1" / "watcher-receipt.json"
    )
    watcher.chmod(0o600)
    watcher.write_bytes(watcher.read_bytes() + b" ")
    with pytest.raises(FollowupCampaignEvidenceBundleError, match="watcher"):
        inspect_followup_campaign_evidence_bundle(
            evidence_root,
            scientific_profile=PROFILE,
        )


def test_final_selection_or_timing_failure_closes_provider_campaign_no_go(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _SerialProvider()
    monkeypatch.setattr(
        execution_module,
        "inspect_followup_formal_timing_campaign",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("drift")),
    )

    result = execute_followup_formal_campaign(
        _opened(),
        progress_oid="a" * 40,
        evidence_tree_oid="b" * 40,
        scientific_profile=PROFILE,
        provider=provider,
        evidence_root=(tmp_path / "campaign-no-go").resolve(),
    )

    assert result.decision == "no-go"
    assert result.final_state.state == "campaign-no-go"
    assert result.final_state.document["terminal_reason_code_or_null"] == (
        "identity-invalid"
    )
    assert (result.evidence_root / "campaign-no-go.json").is_file()


def test_campaign_evidence_transport_round_trips_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    provider = _SerialProvider(provider_failure_ordinal=4)
    evidence_root = (tmp_path / "campaign-source").resolve()
    result = execute_followup_formal_campaign(
        _opened(),
        progress_oid="a" * 40,
        evidence_tree_oid="b" * 40,
        scientific_profile=PROFILE,
        provider=provider,
        evidence_root=evidence_root,
    )
    assert result.decision == "ready-for-terminal"

    transport = build_followup_campaign_transport(
        evidence_root,
        scientific_profile=PROFILE,
    )
    installed = install_followup_campaign_transport(
        transport,
        (tmp_path / "campaign-installed").resolve(),
        scientific_profile=PROFILE,
    )

    assert installed.selection.sha256 == result.selection.sha256  # type: ignore[union-attr]
    assert transport.member_count > 17
    assert transport.expanded_bytes > len(transport.content)
    corrupted = FollowupCampaignTransport(
        content=transport.content[:-1] + bytes([transport.content[-1] ^ 1]),
        sha256=transport.sha256,
        member_count=transport.member_count,
        expanded_bytes=transport.expanded_bytes,
    )
    with pytest.raises(FollowupCampaignControlError, match="identity"):
        install_followup_campaign_transport(
            corrupted,
            (tmp_path / "campaign-corrupt").resolve(),
            scientific_profile=PROFILE,
        )


class _TerminalWatch:
    def __init__(self, outcome: FollowupTerminalWatchOutcome) -> None:
        self._outcome = outcome

    @property
    def session_sha256(self) -> str:
        return self._outcome.watcher_session_sha256

    def wait(self) -> FollowupTerminalWatchOutcome:
        return self._outcome


class _TerminalProvider:
    terminal_workflow_ref = (
        "example/project/.github/workflows/"
        "followup-performance-terminal.yml@refs/heads/main"
    )

    def __init__(self) -> None:
        self.claim = None
        self.run_id = 71_001
        self.watcher_started = False
        self.binding_installed_after_watch = False
        self.cancelled: list[int] = []

    def open_terminal(self, claim, transport):  # type: ignore[no-untyped-def]
        assert transport.sha256 == claim.document["campaign_transport_sha256"]
        self.claim = claim
        return "b" * 40, "c" * 40

    def dispatch_terminal_run(self, *, inputs: dict[str, str]) -> int:
        assert inputs["expected_terminal_claim_oid"] == "b" * 40
        return self.run_id

    def start_terminal_watch(self, *, provider_run_id, claim):  # type: ignore[no-untyped-def]
        assert provider_run_id == self.run_id
        self.watcher_started = True
        phase = _canonical_json_bytes(
            {
                "aggregate": {
                    "aggregate_sha256": "8" * 64,
                    "artifact_name": (
                        "followup-performance-v1-formal-aggregate-sentinel"
                    ),
                    "unit_identity_sha256": "9" * 64,
                },
                "schema_version": (
                    "dynamic-cssc-followup-performance-terminal-phase-receipt-v1"
                ),
                "terminal": {
                    "artifact_name": (
                        "followup-performance-v1-formal-terminal-admission-sentinel"
                    ),
                    "formal_artifact_set_sha256": "a" * 64,
                    "formal_timing_ledger_sha256": claim.document[
                        "formal_timing_ledger_sha256"
                    ],
                    "unit_identity_sha256": "b" * 64,
                },
            }
        )
        started = datetime(2026, 8, 30, 8, 0, tzinfo=UTC)
        completed = started + timedelta(minutes=8)
        run = _canonical_json_bytes(
            {
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": S2,
                "id": self.run_id,
                "path": ".github/workflows/followup-performance-terminal.yml",
                "run_attempt": 1,
                "status": "completed",
            }
        )
        jobs = _canonical_json_bytes(
            {
                "jobs": [
                    {
                        "completed_at": _render(completed),
                        "conclusion": "success",
                        "id": 72_001,
                        "name": "formal-terminal-admission-and-aggregate",
                        "run_attempt": 1,
                        "run_id": self.run_id,
                        "started_at": _render(started),
                        "status": "completed",
                    }
                ],
                "total_count": 1,
            }
        )
        terminal = FollowupTerminalArtifactBinding(
            provider_artifact_id=73_001,
            artifact_name=(
                "followup-performance-v1-formal-terminal-admission-sentinel"
            ),
            provider_digest=f"sha256:{'c' * 64}",
            size_in_bytes=500,
        )
        aggregate = FollowupTerminalArtifactBinding(
            provider_artifact_id=73_002,
            artifact_name="followup-performance-v1-formal-aggregate-sentinel",
            provider_digest=f"sha256:{'d' * 64}",
            size_in_bytes=600,
        )
        artifacts = _canonical_json_bytes(
            {
                "artifacts": [
                    {
                        "digest": terminal.provider_digest,
                        "expired": False,
                        "id": terminal.provider_artifact_id,
                        "name": terminal.artifact_name,
                        "size_in_bytes": terminal.size_in_bytes,
                        "workflow_run": {"head_sha": S2, "id": self.run_id},
                    },
                    {
                        "digest": aggregate.provider_digest,
                        "expired": False,
                        "id": aggregate.provider_artifact_id,
                        "name": aggregate.artifact_name,
                        "size_in_bytes": aggregate.size_in_bytes,
                        "workflow_run": {"head_sha": S2, "id": self.run_id},
                    },
                ],
                "total_count": 2,
            }
        )
        outcome = build_followup_terminal_watch_outcome(
            claim=claim,
            provider_run_id=self.run_id,
            watcher_session_sha256="e" * 64,
            provider_run_json=run,
            provider_jobs_json=jobs,
            provider_artifacts_json=artifacts,
            provider_phase_receipt_bytes_or_null=phase,
            provider_observed_at=completed + timedelta(seconds=2),
            decision="success",
            job_started_at_or_null=started,
            job_completed_at_or_null=completed,
            terminal_artifact_or_null=terminal,
            aggregate_artifact_or_null=aggregate,
            cancellation_requested_at_or_null=None,
            cancellation_acknowledged_at_or_null=None,
            no_go_reason_or_null=None,
        )
        return _TerminalWatch(outcome)

    def install_terminal_watch_binding(self, **_kwargs: object) -> str:
        assert self.watcher_started
        self.binding_installed_after_watch = True
        return "f" * 40

    def install_terminal_outcome(self, **_kwargs: object) -> str:
        assert self.binding_installed_after_watch
        return "0" * 39 + "1"

    def cancel_terminal_run(self, provider_run_id: int) -> None:
        self.cancelled.append(provider_run_id)


def test_terminal_execution_arms_watch_before_binding_and_closes_evidence(
    tmp_path: Path,
) -> None:
    campaign_provider = _SerialProvider()
    campaign = execute_followup_formal_campaign(
        _opened(),
        progress_oid="a" * 40,
        evidence_tree_oid="b" * 40,
        scientific_profile=PROFILE,
        provider=campaign_provider,
        evidence_root=(tmp_path / "campaign-terminal-source").resolve(),
    )
    terminal_provider = _TerminalProvider()
    terminal = execute_followup_terminal(
        campaign,
        scientific_profile=PROFILE,
        provider=terminal_provider,
        evidence_root=(tmp_path / "terminal-evidence").resolve(),
    )
    inspected = inspect_followup_terminal_evidence_bundle(terminal.evidence_root)

    assert terminal.decision == "ready-for-analysis"
    assert terminal.watch_outcome.runner_seconds_or_null == 8 * 60
    assert terminal_provider.binding_installed_after_watch
    assert inspected.controller["outcome_oid"] == "0" * 39 + "1"
    watcher = terminal.evidence_root / "watcher-receipt.json"
    watcher.chmod(0o600)
    watcher.write_bytes(watcher.read_bytes() + b" ")
    with pytest.raises(FollowupControllerError, match="watcher"):
        inspect_followup_terminal_evidence_bundle(terminal.evidence_root)
