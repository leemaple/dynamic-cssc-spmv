#!/usr/bin/env python3
"""Rebuild one S3 analysis admission from provider commit and bundle bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_analysis_binding import (
    FollowupAnalysisBindingError,
    build_followup_analysis_run_admission,
    inspect_followup_analysis_claim,
    inspect_followup_analysis_watch_binding,
)
from dynamic_cssc.followup_performance_github_message import (
    canonical_json_from_github_commit_message,
)


def _pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in rows:
        if key in value:
            raise FollowupAnalysisBindingError(
                "provider JSON has a duplicate key"
            )
        value[key] = item
    return value


def _object(path: Path, *, label: str) -> dict[str, object]:
    content = path.read_bytes()
    if not content or len(content) > 1024 * 1024:
        raise FollowupAnalysisBindingError(f"{label} bytes changed")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupAnalysisBindingError(
            f"{label} is unreadable JSON"
        ) from error
    if type(value) is not dict:
        raise FollowupAnalysisBindingError(f"{label} is not one object")
    return value


def _parent(document: dict[str, object], *, label: str) -> str:
    parents = document.get("parents")
    if (
        type(parents) is not list
        or len(parents) != 1
        or type(parents[0]) is not dict
        or type(parents[0].get("sha")) is not str
    ):
        raise FollowupAnalysisBindingError(f"{label} parent changed")
    return parents[0]["sha"]


def _tree(document: dict[str, object], *, label: str) -> str:
    tree = document.get("tree")
    if type(tree) is not dict or type(tree.get("sha")) is not str:
        raise FollowupAnalysisBindingError(f"{label} tree changed")
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
    parser.add_argument("--expected-s3", required=True)
    parser.add_argument("--expected-registration-compatibility", required=True)
    parser.add_argument("--expected-analysis-compatibility", required=True)
    parser.add_argument("--expected-provider-run-id", required=True, type=int)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    ref = _object(arguments.ref_json, label="analysis ref")
    claim_commit = _object(arguments.claim_commit_json, label="analysis claim commit")
    binding_commit = _object(
        arguments.binding_commit_json,
        label="analysis binding commit",
    )
    target = ref.get("object")
    if (
        type(target) is not dict
        or target.get("type") != "commit"
        or target.get("sha") != binding_commit.get("sha")
        or binding_commit.get("sha") == arguments.expected_claim_oid
        or _parent(binding_commit, label="analysis binding")
        != arguments.expected_claim_oid
        or claim_commit.get("sha") != arguments.expected_claim_oid
        or _tree(binding_commit, label="analysis binding")
        != _tree(claim_commit, label="analysis claim")
    ):
        raise FollowupAnalysisBindingError("analysis provider commit chain changed")
    claim_message = claim_commit.get("message")
    binding_message = binding_commit.get("message")
    if type(claim_message) is not str or type(binding_message) is not str:
        raise FollowupAnalysisBindingError("analysis commit message changed")
    claim = inspect_followup_analysis_claim(
        canonical_json_from_github_commit_message(claim_message)
    )
    binding = inspect_followup_analysis_watch_binding(
        canonical_json_from_github_commit_message(binding_message)
    )
    if (
        _parent(claim_commit, label="analysis claim")
        != claim.document["terminal_outcome_oid"]
        or claim.document["campaign_id"] != arguments.expected_campaign_id
        or claim.document["experiment_source_S1_sha"] != arguments.expected_s1
        or claim.document["evidence_freeze_S2_sha"] != arguments.expected_s2
        or claim.document["analysis_source_S3_sha"] != arguments.expected_s3
        or claim.document["registration_compatibility_receipt_sha256"]
        != arguments.expected_registration_compatibility
        or claim.document["analysis_compatibility_receipt_sha256"]
        != arguments.expected_analysis_compatibility
        or binding.document["claim_oid"] != arguments.expected_claim_oid
        or binding.document["claim_sha256"] != claim.sha256
        or binding.document["provider_run_id"]
        != arguments.expected_provider_run_id
        or binding.document["analysis_source_S3_sha"] != arguments.expected_s3
    ):
        raise FollowupAnalysisBindingError("analysis admission identity changed")
    transport = arguments.campaign_transport.read_bytes()
    if (
        not transport
        or len(transport) > 64 * 1024 * 1024
        or hashlib.sha256(transport).hexdigest()
        != claim.document["campaign_transport_sha256"]
    ):
        raise FollowupAnalysisBindingError("analysis campaign transport changed")
    admission = build_followup_analysis_run_admission(
        claim,
        binding,
        binding_oid=binding_commit["sha"],
    )
    terminal = claim.document["terminal_artifact"]
    aggregate = claim.document["aggregate_artifact"]
    assert type(terminal) is dict and type(aggregate) is dict
    output = {
        "admission_receipt_sha256": admission.sha256,
        "aggregate_artifact_id": aggregate["provider_artifact_id"],
        "aggregate_artifact_name": aggregate["artifact_name"],
        "aggregate_artifact_provider_digest": aggregate["provider_digest"],
        "aggregate_artifact_size_in_bytes": aggregate["size_in_bytes"],
        "analysis_runner_seconds_limit": claim.document[
            "analysis_runner_seconds_limit"
        ],
        "binding_oid": binding_commit["sha"],
        "campaign_transport_expanded_bytes": claim.document[
            "campaign_transport_expanded_bytes"
        ],
        "campaign_transport_member_count": claim.document[
            "campaign_transport_member_count"
        ],
        "campaign_transport_sha256": claim.document[
            "campaign_transport_sha256"
        ],
        "claim_oid": arguments.expected_claim_oid,
        "terminal_artifact_id": terminal["provider_artifact_id"],
        "terminal_artifact_name": terminal["artifact_name"],
        "terminal_artifact_provider_digest": terminal["provider_digest"],
        "terminal_artifact_size_in_bytes": terminal["size_in_bytes"],
        "terminal_provider_run_id": claim.document["terminal_provider_run_id"],
        "terminal_runner_seconds": claim.document["terminal_runner_seconds"],
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (
        FollowupAnalysisBindingError,
        OSError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ) as error:
        print(
            f"follow-up analysis run admission failed closed: {error}",
            file=os.sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
