#!/usr/bin/env python3
"""Read-only CLI for the Route A live GitHub qualification controller.

This Stage-2 seam deliberately consumes and abandons a successful ephemeral
capability.  Formal dispatch is added only together with the closed acquisition
workflow so no intermediate commit can turn a verification into publication
authority.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dynamic_cssc.route_a_controller import (
    GitHubActionsQualificationProvider,
    RouteAControllerError,
    RouteAQualificationRequest,
    abandon_route_a_qualification_capability,
    authorize_route_a_qualification,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--expected-s2", required=True)
    parser.add_argument("--expected-head-branch", default="main", choices=("main",))
    parser.add_argument("--run-attempt", type=int, default=1, choices=(1,))
    parser.add_argument("--verify-only", action="store_true", required=True)
    arguments = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if token is None:
        print("Route A live verification failed: GITHUB_TOKEN is absent", file=sys.stderr)
        return 2
    try:
        request = RouteAQualificationRequest(
            run_id=arguments.run_id,
            expected_s2_git_sha=arguments.expected_s2,
            expected_head_branch=arguments.expected_head_branch,
            expected_run_attempt=arguments.run_attempt,
        )
        provider = GitHubActionsQualificationProvider(
            repository_root=arguments.repository_root,
            repository_slug=arguments.repository,
            token=token,
        )
        capability = authorize_route_a_qualification(provider, request)
        abandon_route_a_qualification_capability(capability)
    except (OSError, RouteAControllerError, TypeError, ValueError) as error:
        print(f"Route A live verification failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "capability_abandoned": True,
                "formal_dispatch_performed": False,
                "qualification_verified": True,
                "run_id": arguments.run_id,
                "schema_version": "dynamic-cssc-route-a-live-controller-verify-only-v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
