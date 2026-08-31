#!/usr/bin/env python3
"""Rebuild one terminal run admission from provider commit and bundle bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_github_message import (
    canonical_json_from_github_commit_message,
)
from dynamic_cssc.followup_performance_terminal_binding import (
    FollowupTerminalBindingError,
    build_followup_terminal_run_admission,
    inspect_followup_terminal_claim,
    inspect_followup_terminal_watch_binding,
)


def _pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in rows:
        if key in value:
            raise FollowupTerminalBindingError("provider JSON has a duplicate key")
        value[key] = item
    return value


def _object(path: Path, *, label: str) -> dict[str, object]:
    content = path.read_bytes()
    if not content or len(content) > 1024 * 1024:
        raise FollowupTerminalBindingError(f"{label} bytes changed")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupTerminalBindingError(f"{label} is unreadable JSON") from error
    if type(value) is not dict:
        raise FollowupTerminalBindingError(f"{label} is not one object")
    return value


def _parent(document: dict[str, object], *, label: str) -> str:
    parents = document.get("parents")
    if (
        type(parents) is not list
        or len(parents) != 1
        or type(parents[0]) is not dict
        or type(parents[0].get("sha")) is not str
    ):
        raise FollowupTerminalBindingError(f"{label} parent changed")
    return parents[0]["sha"]


def _tree(document: dict[str, object], *, label: str) -> str:
    tree = document.get("tree")
    if type(tree) is not dict or type(tree.get("sha")) is not str:
        raise FollowupTerminalBindingError(f"{label} tree changed")
    return tree["sha"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref-json", required=True, type=Path)
    parser.add_argument("--claim-commit-json", required=True, type=Path)
    parser.add_argument("--binding-commit-json", required=True, type=Path)
    parser.add_argument("--campaign-transport", required=True, type=Path)
    parser.add_argument("--expected-claim-oid", required=True)
    parser.add_argument("--expected-campaign-id", required=True)
    parser.add_argument("--expected-s1", required=True)
    parser.add_argument("--expected-s2", required=True)
    parser.add_argument("--expected-compatibility", required=True)
    parser.add_argument("--expected-provider-run-id", required=True, type=int)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    ref = _object(arguments.ref_json, label="terminal ref")
    claim_commit = _object(arguments.claim_commit_json, label="terminal claim commit")
    binding_commit = _object(
        arguments.binding_commit_json,
        label="terminal binding commit",
    )
    target = ref.get("object")
    if (
        type(target) is not dict
        or target.get("type") != "commit"
        or target.get("sha") != binding_commit.get("sha")
        or binding_commit.get("sha") == arguments.expected_claim_oid
        or _parent(binding_commit, label="terminal binding")
        != arguments.expected_claim_oid
        or claim_commit.get("sha") != arguments.expected_claim_oid
        or _tree(binding_commit, label="terminal binding")
        != _tree(claim_commit, label="terminal claim")
    ):
        raise FollowupTerminalBindingError("terminal provider commit chain changed")
    claim_message = claim_commit.get("message")
    binding_message = binding_commit.get("message")
    if type(claim_message) is not str or type(binding_message) is not str:
        raise FollowupTerminalBindingError("terminal commit message changed")
    claim = inspect_followup_terminal_claim(
        canonical_json_from_github_commit_message(claim_message)
    )
    binding = inspect_followup_terminal_watch_binding(
        canonical_json_from_github_commit_message(binding_message)
    )
    if (
        _parent(claim_commit, label="terminal claim")
        != claim.document["final_progress_oid"]
        or
        claim.document["campaign_id"] != arguments.expected_campaign_id
        or claim.document["experiment_source_S1_sha"] != arguments.expected_s1
        or claim.document["evidence_freeze_S2_sha"] != arguments.expected_s2
        or claim.document["compatibility_receipt_sha256"]
        != arguments.expected_compatibility
        or binding.document["claim_oid"] != arguments.expected_claim_oid
        or binding.document["claim_sha256"] != claim.sha256
        or binding.document["provider_run_id"] != arguments.expected_provider_run_id
        or binding.document["evidence_freeze_S2_sha"] != arguments.expected_s2
    ):
        raise FollowupTerminalBindingError("terminal admission identity changed")
    transport = arguments.campaign_transport.read_bytes()
    if (
        not transport
        or len(transport) > 64 * 1024 * 1024
        or hashlib.sha256(transport).hexdigest()
        != claim.document["campaign_transport_sha256"]
    ):
        raise FollowupTerminalBindingError("terminal campaign transport changed")
    admission = build_followup_terminal_run_admission(
        claim,
        binding,
        binding_oid=binding_commit["sha"],
    )
    print(
        json.dumps(
            {
                "admission_receipt_sha256": admission.sha256,
                "binding_oid": binding_commit["sha"],
                "campaign_transport_sha256": claim.document[
                    "campaign_transport_sha256"
                ],
                "campaign_transport_expanded_bytes": claim.document[
                    "campaign_transport_expanded_bytes"
                ],
                "campaign_transport_member_count": claim.document[
                    "campaign_transport_member_count"
                ],
                "claim_oid": arguments.expected_claim_oid,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (FollowupTerminalBindingError, OSError, TypeError, ValueError) as error:
        print(f"follow-up terminal run admission failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
