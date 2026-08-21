#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from dynamic_cssc.manifest import ManifestError, load_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        data = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"P-1 FAIL: {exc}")
        return 1
    print(
        "P-1 PASS: "
        f"mode={data['functional_mode']} "
        f"OpenFHE={data['openfhe']['version']}@{data['openfhe']['commit'][:12]} "
        f"t={data['openfhe']['plaintext_modulus']} "
        f"slots={data['packing']['total_slots']}/{data['packing']['effective_slots']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
