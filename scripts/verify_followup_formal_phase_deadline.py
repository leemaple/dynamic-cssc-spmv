#!/usr/bin/env python3
"""Read GitHub provider time and enforce one formal unit's shared deadline."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from dynamic_cssc.followup_performance_contract import materialize_followup_scientific_plan
from dynamic_cssc.followup_performance_formal_deadline import (
    FollowupFormalDeadlineError,
    inspect_followup_formal_phase_deadline,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.followup_performance_github_transport import GitHubCliTransport

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_MAX_JSON_BYTES = 8 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--expected-s2", required=True)
    parser.add_argument("--formal-unit-ordinal", required=True, type=int)
    parser.add_argument("--expected-job-token", required=True)
    parser.add_argument("--expected-reservation-minutes", required=True, type=int)
    parser.add_argument(
        "--phase",
        required=True,
        choices=("private-handoff", "guarded-final"),
    )
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--require-positive-remaining", action="store_true")
    return parser


def _main(arguments: argparse.Namespace) -> int:
    if _REPOSITORY.fullmatch(arguments.repository) is None:
        raise FollowupFormalDeadlineError("GitHub repository identity is invalid")
    if arguments.provider_run_id <= 0:
        raise FollowupFormalDeadlineError("provider run ID is not positive")
    root = arguments.repository_root.resolve(strict=True)
    scientific = materialize_followup_scientific_plan(root)
    specs = followup_formal_unit_specs(scientific.scientific_profile)
    if not 0 <= arguments.formal_unit_ordinal < len(specs):
        raise FollowupFormalDeadlineError("formal unit ordinal is outside 0..16")
    spec = specs[arguments.formal_unit_ordinal]
    if (
        arguments.expected_job_token != spec.job_token
        or arguments.expected_reservation_minutes != spec.reservation_minutes
    ):
        raise FollowupFormalDeadlineError("formal unit deadline input changed")
    transport = GitHubCliTransport(command_timeout_seconds=60)
    base = f"/repos/{arguments.repository}/actions/runs/{arguments.provider_run_id}"
    run = transport.request(
        method="GET",
        path=base,
        payload=None,
        expected_statuses=frozenset({200}),
        maximum_bytes=_MAX_JSON_BYTES,
    )
    jobs = transport.request(
        method="GET",
        path=f"{base}/jobs?per_page=100",
        payload=None,
        expected_statuses=frozenset({200}),
        maximum_bytes=_MAX_JSON_BYTES,
    )
    checkpoint = inspect_followup_formal_phase_deadline(
        run.body,
        jobs.body,
        provider_observed_at=jobs.provider_observed_at,
        expected_run_id=arguments.provider_run_id,
        expected_s2=arguments.expected_s2,
        spec=spec,
        phase=arguments.phase,
        checkpoint=arguments.checkpoint,
        require_positive_remaining=arguments.require_positive_remaining,
    )
    os.sys.stdout.buffer.write(checkpoint.document_bytes)
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up formal provider deadline failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
