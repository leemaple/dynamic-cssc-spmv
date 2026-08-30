#!/usr/bin/env python3
"""Select the terminal-admitted follow-up artifacts from one formal run."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from dynamic_cssc.followup_performance_analysis import FollowupAnalysisError
from dynamic_cssc.followup_performance_contract import (
    _canonical_json_bytes,
    _parse_ascii_json,
)

_SAFE_NAME = re.compile(r"followup-performance-v1-[a-z0-9-]+\Z")
_TERMINAL_PREFIX = "followup-performance-v1-formal-terminal-admission-"
_AGGREGATE_PREFIX = "followup-performance-v1-formal-aggregate-"


def _direct_children(root: Path) -> dict[str, Path]:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise FollowupAnalysisError("download root is not one absolute direct directory")
    children: dict[str, Path] = {}
    for child in root.iterdir():
        if (
            child.is_symlink()
            or not child.is_dir()
            or _SAFE_NAME.fullmatch(child.name) is None
            or child.name in children
        ):
            raise FollowupAnalysisError("download root contains an unsafe artifact")
        children[child.name] = child
    return children


def _only_prefix(children: dict[str, Path], prefix: str, *, label: str) -> Path:
    matches = [path for name, path in children.items() if name.startswith(prefix)]
    if len(matches) != 1:
        raise FollowupAnalysisError(f"download root lacks one exact {label}")
    return matches[0]


def _reject_links(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        if path.is_symlink():
            raise FollowupAnalysisError("downloaded artifact contains a symbolic link")


def _terminal_names(terminal: Path) -> tuple[str, ...]:
    try:
        content = (terminal / "inner-payload.json").read_bytes()
    except OSError as error:
        raise FollowupAnalysisError("terminal artifact is unreadable") from error
    document = _parse_ascii_json(content, label="terminal selection source")
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise FollowupAnalysisError("terminal selection source is not canonical")
    artifacts = document.get("artifacts")
    if type(artifacts) is not list or len(artifacts) != 17:
        raise FollowupAnalysisError("terminal artifact set is not seventeen units")
    names: list[str] = []
    for ordinal, record in enumerate(artifacts):
        if (
            type(record) is not dict
            or record.get("ordinal") != ordinal
            or type(record.get("artifact_name")) is not str
            or _SAFE_NAME.fullmatch(record["artifact_name"]) is None
        ):
            raise FollowupAnalysisError("terminal artifact record changed")
        names.append(record["artifact_name"])
    if len(set(names)) != 17:
        raise FollowupAnalysisError("terminal artifact names are not unique")
    return tuple(names)


def prepare_analysis_inputs(download_root: Path, output_directory: Path) -> dict[str, object]:
    children = _direct_children(download_root)
    terminal = _only_prefix(children, _TERMINAL_PREFIX, label="terminal artifact")
    aggregate = _only_prefix(children, _AGGREGATE_PREFIX, label="aggregate artifact")
    final_names = _terminal_names(terminal)
    try:
        final_paths = tuple(children[name] for name in final_names)
    except KeyError as error:
        raise FollowupAnalysisError("one terminal-admitted artifact was not downloaded") from error
    for root in (*final_paths, terminal, aggregate):
        _reject_links(root)
    if not output_directory.is_absolute() or output_directory.parent.is_symlink():
        raise FollowupAnalysisError("analysis input output path is unsafe")
    if output_directory.exists() or output_directory.is_symlink():
        raise FollowupAnalysisError("analysis input output already exists")
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}-",
            dir=output_directory.parent,
        )
    )
    try:
        finals = temporary / "finals"
        finals.mkdir()
        for source in final_paths:
            shutil.copytree(source, finals / source.name)
        shutil.copytree(terminal, temporary / "terminal")
        shutil.copytree(aggregate, temporary / "aggregate")
        receipt = {
            "aggregate_artifact_name": aggregate.name,
            "formal_artifact_names": list(final_names),
            "formal_artifact_count": 17,
            "selection_authority": False,
            "terminal_artifact_name": terminal.name,
        }
        (temporary / "selection.json").write_bytes(_canonical_json_bytes(receipt))
        os.replace(temporary, output_directory)
        return receipt
    except BaseException:
        if temporary.exists() and not temporary.is_symlink():
            shutil.rmtree(temporary, ignore_errors=True)
        if output_directory.exists() and not output_directory.is_symlink():
            shutil.rmtree(output_directory, ignore_errors=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--download-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        receipt = prepare_analysis_inputs(
            arguments.download_root,
            arguments.output_directory,
        )
    except (FollowupAnalysisError, OSError, TypeError, ValueError) as error:
        print(f"follow-up analysis input selection failed closed: {error}", file=os.sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
