"""Filesystem closure for one complete multi-run formal campaign.

The external controller records provider API observations and immutable campaign
state receipts here.  Terminal admission, aggregation, and S3 analysis all call
the same inspector instead of reconstructing different views of the campaign.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from dynamic_cssc.followup_performance_campaign import (
    FollowupCampaignError,
    FollowupCampaignSelection,
    build_followup_campaign_run_admission_receipt,
    inspect_followup_campaign_run_admission,
    inspect_followup_campaign_selection,
    inspect_followup_campaign_state,
)
from dynamic_cssc.followup_performance_contract import (
    _canonical_json_bytes,
    _parse_ascii_json,
)
from dynamic_cssc.followup_performance_formal_artifacts import (
    _direct_directory,
    _stable_read,
)
from dynamic_cssc.followup_performance_formal_timing import (
    FollowupFormalRunEvidence,
    FollowupFormalTimingLedger,
    inspect_followup_formal_timing_campaign,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FollowupCampaignEvidenceBundle",
    "FollowupCampaignEvidenceBundleError",
    "inspect_followup_campaign_evidence_bundle",
)


class FollowupCampaignEvidenceBundleError(FollowupCampaignError):
    """The controller's campaign evidence directory failed closed."""


@dataclass(frozen=True, slots=True)
class FollowupCampaignEvidenceBundle:
    root: Path
    selection: FollowupCampaignSelection
    timing: FollowupFormalTimingLedger
    committed_state_bytes: tuple[bytes, ...]
    attempts: tuple[FollowupFormalRunEvidence, ...]


def _direct_file_bytes(
    path: Path,
    *,
    label: str,
    maximum: int | None = None,
) -> bytes:
    try:
        return _stable_read(path) if maximum is None else _stable_read(path, maximum=maximum)
    except OSError as error:
        raise FollowupCampaignEvidenceBundleError(f"{label} is unreadable") from error


def inspect_followup_campaign_evidence_bundle(
    root: Path,
    *,
    scientific_profile: RouteAScientificProfile,
    expected_head_branch: str = "main",
) -> FollowupCampaignEvidenceBundle:
    """Rebuild campaign selection and timing from one exact closed directory."""

    root = _direct_directory(root, label="follow-up campaign evidence root")
    entries = {entry.name: entry for entry in root.iterdir()}
    if set(entries) != {
        "attempts",
        "campaign-open-controller.json",
        "campaign-open.json",
        "committed-states",
        "selection.json",
        "timing-ledger.json",
    }:
        raise FollowupCampaignEvidenceBundleError(
            "campaign evidence top-level members changed"
        )
    opened = inspect_followup_campaign_state(
        _direct_file_bytes(entries["campaign-open.json"], label="campaign open")
    )
    open_controller_bytes = _direct_file_bytes(
        entries["campaign-open-controller.json"],
        label="campaign open controller",
    )
    open_controller = _parse_ascii_json(
        open_controller_bytes,
        label="campaign open controller",
    )
    if (
        opened.state != "campaign-open"
        or type(open_controller) is not dict
        or _canonical_json_bytes(open_controller) != open_controller_bytes
        or open_controller.get("campaign_id") != opened.document["campaign_id"]
        or open_controller.get("authority") is not False
        or open_controller.get("publication_evidence_admitted") is not False
    ):
        raise FollowupCampaignEvidenceBundleError(
            "campaign opening evidence changed"
        )
    committed_root = _direct_directory(
        entries["committed-states"],
        label="campaign committed-state root",
    )
    expected_committed_names = {f"{ordinal:02d}.json" for ordinal in range(17)}
    committed_entries = {entry.name: entry for entry in committed_root.iterdir()}
    if set(committed_entries) != expected_committed_names:
        raise FollowupCampaignEvidenceBundleError(
            "campaign committed-state member set changed"
        )
    committed_state_bytes = tuple(
        _direct_file_bytes(
            committed_entries[f"{ordinal:02d}.json"],
            label=f"committed state {ordinal}",
        )
        for ordinal in range(17)
    )
    selection_content = _direct_file_bytes(
        entries["selection.json"],
        label="campaign selection",
    )
    selection = inspect_followup_campaign_selection(
        selection_content,
        committed_state_bytes,
        scientific_profile=scientific_profile,
    )

    attempts_root = _direct_directory(
        entries["attempts"],
        label="campaign attempt root",
    )
    expected_attempt_names = {
        f"{ordinal:02d}-attempt-{attempt}"
        for ordinal, selected in enumerate(selection.units)
        for attempt in (
            (1, 2) if selected["unit_attempt_ordinal"] == 2 else (1,)
        )
    }
    attempt_entries = {entry.name: entry for entry in attempts_root.iterdir()}
    if set(attempt_entries) != expected_attempt_names:
        raise FollowupCampaignEvidenceBundleError(
            "campaign attempt directory set changed"
        )
    attempts: list[FollowupFormalRunEvidence] = []
    for ordinal, selected in enumerate(selection.units):
        selected_attempt = selected["unit_attempt_ordinal"]
        assert type(selected_attempt) is int
        for attempt in ((1, 2) if selected_attempt == 2 else (1,)):
            attempt_root = _direct_directory(
                attempt_entries[f"{ordinal:02d}-attempt-{attempt}"],
                label=f"campaign attempt {ordinal}/{attempt}",
            )
            members = {entry.name: entry for entry in attempt_root.iterdir()}
            terminal_state = _direct_file_bytes(
                members.get("terminal-state.json", attempt_root / "missing"),
                label=f"campaign attempt {ordinal}/{attempt} terminal state",
            )
            parsed_terminal = inspect_followup_campaign_state(terminal_state)
            base_members = {
                "artifacts.json",
                "binding-state.json",
                "controller.json",
                "jobs.json",
                "reservation-state.json",
                "run-admission.json",
                "run.json",
                "terminal-state.json",
                "watch-armed-state.json",
                "watcher-receipt.json",
            }
            expected_members = set(base_members)
            if parsed_terminal.state == "unit-committed":
                expected_members.add("guard-receipt.json")
            elif parsed_terminal.state == "unit-provider-failed":
                expected_members.add("provider-failure.json")
            else:
                raise FollowupCampaignEvidenceBundleError(
                    "successful campaign contains a non-attempt terminal state"
                )
            if set(members) != expected_members:
                raise FollowupCampaignEvidenceBundleError(
                    "campaign attempt member set changed"
                )
            if attempt == selected_attempt and terminal_state != committed_state_bytes[ordinal]:
                raise FollowupCampaignEvidenceBundleError(
                    "selected attempt state differs from committed state"
                )
            reservation_bytes = _direct_file_bytes(
                members["reservation-state.json"],
                label=f"campaign attempt {ordinal}/{attempt} reservation",
            )
            binding_bytes = _direct_file_bytes(
                members["binding-state.json"],
                label=f"campaign attempt {ordinal}/{attempt} binding",
            )
            armed_bytes = _direct_file_bytes(
                members["watch-armed-state.json"],
                label=f"campaign attempt {ordinal}/{attempt} watch arm",
            )
            controller_bytes = _direct_file_bytes(
                members["controller.json"],
                label=f"campaign attempt {ordinal}/{attempt} controller",
            )
            controller = _parse_ascii_json(
                controller_bytes,
                label=f"campaign attempt {ordinal}/{attempt} controller",
            )
            if (
                type(controller) is not dict
                or _canonical_json_bytes(controller) != controller_bytes
                or controller.get("provider_run_id")
                != parsed_terminal.document["provider_run_id_or_null"]
                or controller.get("terminal_state_sha256")
                != parsed_terminal.sha256
            ):
                raise FollowupCampaignEvidenceBundleError(
                    "campaign attempt controller binding changed"
                )
            provider_run_id = parsed_terminal.document["provider_run_id_or_null"]
            campaign_id = parsed_terminal.document["campaign_id"]
            assert type(provider_run_id) is int
            assert type(campaign_id) is str
            armed = inspect_followup_campaign_run_admission(
                reservation_bytes,
                binding_bytes,
                armed_bytes,
                scientific_profile=scientific_profile,
                expected_campaign_id=campaign_id,
                expected_unit_ordinal=ordinal,
                expected_unit_attempt_ordinal=attempt,
                expected_provider_run_id=provider_run_id,
            )
            reservation_oid = controller.get("reservation_oid")
            watch_armed_oid = controller.get("watch_armed_oid")
            if type(reservation_oid) is not str or type(watch_armed_oid) is not str:
                raise FollowupCampaignEvidenceBundleError(
                    "campaign attempt CAS OIDs changed"
                )
            admission = build_followup_campaign_run_admission_receipt(
                armed,
                reservation_oid=reservation_oid,
                watch_armed_oid=watch_armed_oid,
            )
            admission_bytes = _direct_file_bytes(
                members["run-admission.json"],
                label=f"campaign attempt {ordinal}/{attempt} admission",
            )
            if (
                admission.document_bytes != admission_bytes
                or controller.get("campaign_run_admission_sha256")
                != admission.sha256
            ):
                raise FollowupCampaignEvidenceBundleError(
                    "campaign run admission receipt changed"
                )
            watcher_bytes = _direct_file_bytes(
                members["watcher-receipt.json"],
                label=f"campaign attempt {ordinal}/{attempt} watcher",
            )
            watcher = _parse_ascii_json(
                watcher_bytes,
                label=f"campaign attempt {ordinal}/{attempt} watcher",
            )
            run_bytes = _direct_file_bytes(
                members["run.json"],
                label=f"campaign attempt {ordinal}/{attempt} run",
            )
            jobs_bytes = _direct_file_bytes(
                members["jobs.json"],
                label=f"campaign attempt {ordinal}/{attempt} jobs",
            )
            artifacts_bytes = _direct_file_bytes(
                members["artifacts.json"],
                label=f"campaign attempt {ordinal}/{attempt} artifacts",
            )
            if (
                type(watcher) is not dict
                or _canonical_json_bytes(watcher) != watcher_bytes
                or hashlib.sha256(watcher_bytes).hexdigest()
                != parsed_terminal.document["watcher_receipt_sha256_or_null"]
                or watcher.get("run_api_sha256")
                != hashlib.sha256(run_bytes).hexdigest()
                or watcher.get("jobs_api_sha256")
                != hashlib.sha256(jobs_bytes).hexdigest()
                or watcher.get("artifacts_api_sha256")
                != hashlib.sha256(artifacts_bytes).hexdigest()
            ):
                raise FollowupCampaignEvidenceBundleError(
                    "campaign watcher evidence changed"
                )
            if parsed_terminal.state == "unit-committed":
                guard_receipt = _direct_file_bytes(
                    members["guard-receipt.json"],
                    label=f"campaign attempt {ordinal}/{attempt} guard receipt",
                )
                if watcher.get("guard_receipt_bytes_sha256") != hashlib.sha256(
                    guard_receipt
                ).hexdigest():
                    raise FollowupCampaignEvidenceBundleError(
                        "campaign guard receipt changed"
                    )
            else:
                failure_bytes = _direct_file_bytes(
                    members["provider-failure.json"],
                    label=f"campaign attempt {ordinal}/{attempt} provider failure",
                )
                if hashlib.sha256(failure_bytes).hexdigest() != parsed_terminal.document[
                    "provider_failure_evidence_sha256_or_null"
                ]:
                    raise FollowupCampaignEvidenceBundleError(
                        "campaign provider-failure evidence changed"
                    )
            attempts.append(
                FollowupFormalRunEvidence(
                    unit_ordinal=ordinal,
                    unit_attempt_ordinal=attempt,
                    run_json=run_bytes,
                    jobs_json=jobs_bytes,
                    terminal_campaign_state_bytes=terminal_state,
                )
            )
    timing = inspect_followup_formal_timing_campaign(
        tuple(attempts),
        campaign_selection=selection,
        scientific_profile=scientific_profile,
        expected_head_branch=expected_head_branch,
    )
    timing_bytes = _direct_file_bytes(
        entries["timing-ledger.json"],
        label="campaign timing ledger",
    )
    if timing.document_bytes != timing_bytes:
        raise FollowupCampaignEvidenceBundleError(
            "campaign timing ledger differs from provider evidence"
        )
    return FollowupCampaignEvidenceBundle(
        root=root,
        selection=selection,
        timing=timing,
        committed_state_bytes=committed_state_bytes,
        attempts=tuple(attempts),
    )
