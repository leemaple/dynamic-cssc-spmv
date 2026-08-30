#!/usr/bin/env python3
"""Render the deterministic follow-up S2 data-anchor proposal from exact S1."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dynamic_cssc.followup_performance_lineage import (
    FollowupLineageError,
    build_followup_registration_anchor,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--s1", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if not arguments.repository_root.is_absolute() or not arguments.output.is_absolute():
            raise FollowupLineageError("follow-up anchor paths must be absolute")
        if arguments.output.exists() or arguments.output.is_symlink():
            raise FollowupLineageError("follow-up anchor output must be absent")
        content = build_followup_registration_anchor(
            arguments.repository_root,
            s1=arguments.s1,
        )
        descriptor = os.open(
            arguments.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:  # pragma: no cover - os.write advances or raises
                    raise FollowupLineageError("follow-up anchor write stalled")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up source anchor failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
