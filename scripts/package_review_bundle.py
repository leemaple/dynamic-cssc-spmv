#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def run(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    return completed.stdout.strip() if completed.returncode == 0 else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--include", action="append", default=[])
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    commit = run(["git", "rev-parse", "HEAD"], root) or "uncommitted"
    short = commit[:12]
    bundle_name = f"review-pack-{args.stage}-{short}"
    staging = args.output_dir / bundle_name
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    core_paths = ["README.md", "config", "docs", "src", "tests", "cpp", ".github", "scripts", "pyproject.toml", "Makefile"]
    for relative in core_paths + args.include:
        source = root / relative
        if not source.exists():
            continue
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, destination)

    provenance = {
        "stage": args.stage,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": commit,
        "git_status": run(["git", "status", "--short"], root),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_sha": os.environ.get("GITHUB_SHA"),
        "github_ref": os.environ.get("GITHUB_REF"),
    }
    (staging / "PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8"
    )

    checksum_lines = []
    for path in sorted(staging.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            checksum_lines.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(staging)}"
            )
    (staging / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    archive_base = args.output_dir / bundle_name
    archive_path = Path(shutil.make_archive(str(archive_base), "zip", staging))
    archive_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (args.output_dir / f"{bundle_name}.zip.sha256").write_text(
        f"{archive_sha}  {archive_path.name}\n", encoding="utf-8"
    )
    print(archive_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
