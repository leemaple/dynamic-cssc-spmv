#!/usr/bin/env python3
"""Verify one provider CAS chain before a formal unit may observe its seed."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_campaign import (
    FOLLOWUP_FORMAL_PROGRESS_REF,
    FollowupCampaignError,
    build_followup_campaign_run_admission_receipt,
    inspect_followup_campaign_run_admission,
)
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PROVIDER_JSON_BYTES = 4 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--ref-json", required=True, type=Path)
    parser.add_argument("--reservation-commit-json", required=True, type=Path)
    parser.add_argument("--binding-commit-json", required=True, type=Path)
    parser.add_argument("--watch-commit-json", required=True, type=Path)
    parser.add_argument("--expected-reservation-oid", required=True)
    parser.add_argument("--expected-reservation-minutes", required=True, type=int)
    parser.add_argument("--expected-campaign-id", required=True)
    parser.add_argument("--expected-s1", required=True)
    parser.add_argument("--expected-s2", required=True)
    parser.add_argument("--expected-compatibility", required=True)
    parser.add_argument("--expected-unit-ordinal", required=True, type=int)
    parser.add_argument("--expected-unit-attempt-ordinal", required=True, type=int)
    parser.add_argument("--expected-job-token", required=True)
    parser.add_argument("--expected-provider-run-id", required=True, type=int)
    return parser


def _provider_json(path: Path, *, label: str) -> dict[str, object]:
    if not path.is_absolute():
        raise FollowupCampaignError(f"{label} path must be absolute")
    observed = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or not 0 < observed.st_size <= _MAX_PROVIDER_JSON_BYTES
    ):
        raise FollowupCampaignError(f"{label} is not one bounded owned file")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupCampaignError(f"{label} is not provider JSON") from error
    if type(value) is not dict:
        raise FollowupCampaignError(f"{label} is not one object")
    return value


def _commit(
    value: dict[str, object],
    *,
    expected_oid: str,
    expected_parent_oid: str,
    expected_tree_oid: str,
    label: str,
) -> bytes:
    parents = value.get("parents")
    tree = value.get("tree")
    message = value.get("message")
    if (
        value.get("sha") != expected_oid
        or type(parents) is not list
        or len(parents) != 1
        or type(parents[0]) is not dict
        or parents[0].get("sha") != expected_parent_oid
        or type(tree) is not dict
        or tree.get("sha") != expected_tree_oid
        or type(message) is not str
    ):
        raise FollowupCampaignError(f"{label} provider topology changed")
    try:
        return message.encode("ascii")
    except UnicodeEncodeError as error:
        raise FollowupCampaignError(f"{label} message is not ASCII") from error


def _git(repository_root: Path, *arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    return subprocess.run(
        ("git", "--no-replace-objects", *arguments),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _main(arguments: argparse.Namespace) -> int:
    root = arguments.repository_root.resolve(strict=True)
    for field in ("expected_s1", "expected_s2", "expected_reservation_oid"):
        if _LOWER_GIT_SHA.fullmatch(getattr(arguments, field)) is None:
            raise FollowupCampaignError(f"{field} is not a lowercase Git SHA-1")
    for field in ("expected_campaign_id", "expected_compatibility"):
        if _LOWER_SHA256.fullmatch(getattr(arguments, field)) is None:
            raise FollowupCampaignError(f"{field} is not a lowercase SHA-256")
    if arguments.expected_unit_attempt_ordinal not in {1, 2}:
        raise FollowupCampaignError("outer unit attempt is outside 1..2")
    if arguments.expected_provider_run_id <= 0:
        raise FollowupCampaignError("provider run ID is not positive")
    if _git(root, "rev-parse", "HEAD") != arguments.expected_s2 or _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    ):
        raise FollowupCampaignError("admission requires a clean exact-S2 checkout")
    tree_oid = _git(root, "rev-parse", "HEAD^{tree}")
    ref = _provider_json(arguments.ref_json, label="progress ref")
    target = ref.get("object")
    watch_oid = target.get("sha") if type(target) is dict else None
    if (
        ref.get("ref") != FOLLOWUP_FORMAL_PROGRESS_REF
        or type(target) is not dict
        or target.get("type") != "commit"
        or type(watch_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(watch_oid) is None
    ):
        raise FollowupCampaignError("progress ref identity changed")
    watch_commit = _provider_json(arguments.watch_commit_json, label="watch commit")
    binding_parents = watch_commit.get("parents")
    binding_oid = (
        binding_parents[0].get("sha")
        if type(binding_parents) is list
        and len(binding_parents) == 1
        and type(binding_parents[0]) is dict
        else None
    )
    if type(binding_oid) is not str or _LOWER_GIT_SHA.fullmatch(binding_oid) is None:
        raise FollowupCampaignError("watch commit parent changed")
    binding_commit = _provider_json(arguments.binding_commit_json, label="binding commit")
    reservation_parents = binding_commit.get("parents")
    reservation_oid = (
        reservation_parents[0].get("sha")
        if type(reservation_parents) is list
        and len(reservation_parents) == 1
        and type(reservation_parents[0]) is dict
        else None
    )
    if reservation_oid != arguments.expected_reservation_oid:
        raise FollowupCampaignError("run binding does not descend from the reservation")
    reservation_commit = _provider_json(
        arguments.reservation_commit_json,
        label="reservation commit",
    )
    reservation_parent_rows = reservation_commit.get("parents")
    reservation_parent = (
        reservation_parent_rows[0].get("sha")
        if type(reservation_parent_rows) is list
        and len(reservation_parent_rows) == 1
        and type(reservation_parent_rows[0]) is dict
        else None
    )
    if type(reservation_parent) is not str or _LOWER_GIT_SHA.fullmatch(
        reservation_parent
    ) is None:
        raise FollowupCampaignError("reservation parent changed")
    reservation_bytes = _commit(
        reservation_commit,
        expected_oid=arguments.expected_reservation_oid,
        expected_parent_oid=reservation_parent,
        expected_tree_oid=tree_oid,
        label="reservation commit",
    )
    binding_bytes = _commit(
        binding_commit,
        expected_oid=binding_oid,
        expected_parent_oid=arguments.expected_reservation_oid,
        expected_tree_oid=tree_oid,
        label="binding commit",
    )
    armed_bytes = _commit(
        watch_commit,
        expected_oid=watch_oid,
        expected_parent_oid=binding_oid,
        expected_tree_oid=tree_oid,
        label="watch commit",
    )
    scientific = materialize_followup_scientific_plan(root)
    specs = followup_formal_unit_specs(scientific.scientific_profile)
    if not 0 <= arguments.expected_unit_ordinal < len(specs):
        raise FollowupCampaignError("formal unit ordinal is outside 0..16")
    spec = specs[arguments.expected_unit_ordinal]
    if spec.job_token != arguments.expected_job_token:
        raise FollowupCampaignError("formal job token differs from the exact matrix")
    if spec.reservation_minutes != arguments.expected_reservation_minutes:
        raise FollowupCampaignError("formal reservation differs from the exact matrix")
    armed = inspect_followup_campaign_run_admission(
        reservation_bytes,
        binding_bytes,
        armed_bytes,
        scientific_profile=scientific.scientific_profile,
        expected_campaign_id=arguments.expected_campaign_id,
        expected_unit_ordinal=arguments.expected_unit_ordinal,
        expected_unit_attempt_ordinal=arguments.expected_unit_attempt_ordinal,
        expected_provider_run_id=arguments.expected_provider_run_id,
    )
    if (
        armed.document["experiment_source_S1_sha"] != arguments.expected_s1
        or armed.document["evidence_freeze_S2_sha"] != arguments.expected_s2
        or armed.document["compatibility_receipt_sha256"]
        != arguments.expected_compatibility
    ):
        raise FollowupCampaignError("campaign run admission lineage changed")
    receipt = build_followup_campaign_run_admission_receipt(
        armed,
        reservation_oid=arguments.expected_reservation_oid,
        watch_armed_oid=watch_oid,
    )
    print(
        json.dumps(
            {
                "admission_receipt_sha256": receipt.sha256,
                "reservation_minutes": spec.reservation_minutes,
                "unit_kind": spec.unit_kind,
                "watch_armed_oid": watch_oid,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError) as error:
        print(f"follow-up campaign run admission failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
