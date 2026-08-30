#!/usr/bin/env python3
"""Verify the external qualification watcher binding before any seed access."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_qualification_binding import (
    FollowupQualificationBindingError,
    build_followup_qualification_run_admission,
    inspect_followup_qualification_watch_binding,
)

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROGRESS_REF = (
    "refs/tags/dynamic-cssc-followup-performance-qualification-authority-v1"
)
_MAX_PROVIDER_JSON_BYTES = 4 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--ref-json", required=True, type=Path)
    parser.add_argument("--binding-commit-json", required=True, type=Path)
    parser.add_argument("--expected-claim-oid", required=True)
    parser.add_argument("--expected-s1", required=True)
    parser.add_argument("--expected-s2", required=True)
    parser.add_argument("--expected-compatibility", required=True)
    parser.add_argument("--expected-provider-run-id", required=True, type=int)
    return parser


def _provider_json(path: Path, *, label: str) -> dict[str, object]:
    if not path.is_absolute():
        raise FollowupQualificationBindingError(f"{label} path is not absolute")
    observed = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_nlink != 1
        or not 0 < observed.st_size <= _MAX_PROVIDER_JSON_BYTES
    ):
        raise FollowupQualificationBindingError(
            f"{label} is not one bounded owned file"
        )
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupQualificationBindingError(
            f"{label} is not provider JSON"
        ) from error
    if type(value) is not dict:
        raise FollowupQualificationBindingError(f"{label} is not one object")
    return value


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    return subprocess.run(
        ("git", "--no-replace-objects", *arguments),
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _main(arguments: argparse.Namespace) -> int:
    root = arguments.repository_root.resolve(strict=True)
    for field in ("expected_claim_oid", "expected_s1", "expected_s2"):
        if _LOWER_GIT_SHA.fullmatch(getattr(arguments, field)) is None:
            raise FollowupQualificationBindingError(
                f"{field} is not a lowercase Git SHA"
            )
    if (
        arguments.expected_claim_oid != arguments.expected_s2
        or _LOWER_SHA256.fullmatch(arguments.expected_compatibility) is None
        or arguments.expected_provider_run_id <= 0
    ):
        raise FollowupQualificationBindingError(
            "qualification admission input identity changed"
        )
    if _git(root, "rev-parse", "HEAD") != arguments.expected_s2 or _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    ):
        raise FollowupQualificationBindingError(
            "qualification admission requires a clean exact-S2 checkout"
        )
    tree_oid = _git(root, "rev-parse", "HEAD^{tree}")
    ref = _provider_json(arguments.ref_json, label="qualification progress ref")
    target = ref.get("object")
    binding_oid = target.get("sha") if type(target) is dict else None
    if (
        ref.get("ref") != _PROGRESS_REF
        or type(target) is not dict
        or target.get("type") != "commit"
        or type(binding_oid) is not str
        or _LOWER_GIT_SHA.fullmatch(binding_oid) is None
        or binding_oid == arguments.expected_claim_oid
    ):
        raise FollowupQualificationBindingError(
            "qualification progress ref is not watch-armed"
        )
    commit = _provider_json(
        arguments.binding_commit_json,
        label="qualification binding commit",
    )
    parents = commit.get("parents")
    tree = commit.get("tree")
    message = commit.get("message")
    if (
        commit.get("sha") != binding_oid
        or type(parents) is not list
        or len(parents) != 1
        or type(parents[0]) is not dict
        or parents[0].get("sha") != arguments.expected_claim_oid
        or type(tree) is not dict
        or tree.get("sha") != tree_oid
        or type(message) is not str
    ):
        raise FollowupQualificationBindingError(
            "qualification binding commit topology changed"
        )
    try:
        binding_bytes = message.encode("ascii")
    except UnicodeEncodeError as error:
        raise FollowupQualificationBindingError(
            "qualification binding commit message is not ASCII"
        ) from error
    binding = inspect_followup_qualification_watch_binding(binding_bytes)
    if (
        binding.document["claim_oid"] != arguments.expected_claim_oid
        or binding.document["experiment_source_S1_sha"] != arguments.expected_s1
        or binding.document["evidence_freeze_S2_sha"] != arguments.expected_s2
        or binding.document["compatibility_receipt_sha256"]
        != arguments.expected_compatibility
        or binding.document["provider_run_id"]
        != arguments.expected_provider_run_id
    ):
        raise FollowupQualificationBindingError(
            "qualification watch binding does not match this run"
        )
    admission = build_followup_qualification_run_admission(
        binding,
        binding_oid=binding_oid,
    )
    print(
        json.dumps(
            {
                "admission_receipt_sha256": admission.sha256,
                "binding_oid": binding_oid,
                "watcher_session_sha256": binding.document[
                    "watcher_session_sha256"
                ],
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
        print(
            f"follow-up qualification run admission failed closed: {error}",
            file=os.sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
