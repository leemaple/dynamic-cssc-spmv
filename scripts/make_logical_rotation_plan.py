#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("layout", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    layout_exists = args.layout.is_file()
    layout = json.loads(args.layout.read_text(encoding="utf-8")) if layout_exists else {}
    plans = []
    for probe in layout.get("probes", []):
        if probe.get("evaluation_succeeded"):
            plans.append(
                {
                    "logical_operation": f"direct-rotate-{probe['index']}",
                    "status": "measured-direct-api-only",
                    "steps": [{"op": "EvalRotate", "index": probe["index"]}],
                    "masks": 0,
                    "adds": 0,
                    "note": (
                        "This is a direct OpenFHE API permutation, not a synthesized "
                        "cross-row logical rotation."
                    ),
                }
            )
        else:
            plans.append(
                {
                    "logical_operation": f"direct-rotate-{probe['index']}",
                    "status": "unsupported-or-failed",
                    "steps": [],
                    "error": probe.get("error", ""),
                }
            )
    payload = {
        "status": (
            "partial-p0a-direct-plans" if layout_exists else "p0a-probe-did-not-produce-layout"
        ),
        "source": str(args.layout),
        "plans": plans,
        "guardrail": (
            "Cross-row moves must be explicitly synthesized and benchmarked; "
            "they are not inferred from a permutation alone."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if layout_exists else 1


if __name__ == "__main__":
    raise SystemExit(main())
