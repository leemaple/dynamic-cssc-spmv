#!/usr/bin/env python3
"""Fixed one-shot post-review native campaign and independent reconstruction."""

import argparse
from pathlib import Path

from dynamic_cssc.r1_supplement import load_protocol, require_producer, run_group, run_trace
from dynamic_cssc.r1_supplement_analysis import collect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("preflight")
    for mode in ("group", "trace"):
        command = sub.add_parser(mode)
        command.add_argument("--group", required=True, type=int)
        command.add_argument("--executable", required=True, type=Path)
        command.add_argument("--output-dir", required=True, type=Path)
        if mode == "trace":
            command.add_argument("--repetition", required=True, type=int)
            command.add_argument(
                "--strategy", required=True, choices=("repack", "padding", "strong")
            )
    inspector = sub.add_parser("inspect")
    inspector.add_argument("--input-dir", required=True, type=Path)
    inspector.add_argument("--output-dir", required=True, type=Path)
    inspector.add_argument("--source", required=True)
    inspector.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if args.mode == "preflight":
        print(require_producer(load_protocol()))
    elif args.mode == "group":
        run_group(
            args.group,
            args.executable.resolve(),
            args.output_dir.resolve(),
            Path(__file__).resolve(),
        )
    elif args.mode == "trace":
        run_trace(
            args.group,
            args.repetition,
            args.strategy,
            args.executable.resolve(),
            args.output_dir.resolve(),
        )
    else:
        result = collect(args.input_dir, args.output_dir, args.source, args.run_id)
        print(result)
        return 0 if result["complete"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
