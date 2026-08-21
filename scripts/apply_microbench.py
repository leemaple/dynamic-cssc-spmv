#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-csv", required=True, type=Path)
    parser.add_argument("--microbench", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    micro = json.loads(args.microbench.read_text(encoding="utf-8"))
    operations = micro["operations"]
    unit = {name: details["median_ms"] for name, details in operations.items()}
    ciphertext_bytes = int(micro["ciphertext_bytes"])
    records = []
    with args.model_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            def integer(name: str) -> int:
                return int(float(row[name]))

            measured_time = (
                (integer("update_encryptions") + integer("blinding_encryptions"))
                * unit["encrypt"]
                + integer("cc_multiplications")
                * unit["eval_mult_with_relinearization"]
                + integer("rotations") * unit["eval_rotate"]
                + integer("additions") * unit["eval_add_ciphertext"]
                + integer("blinding_additions") * unit["eval_add_ciphertext"]
                + integer("plaintext_masks") * unit["eval_mult_plaintext_mask"]
                + integer("decryptions") * unit["decrypt"]
            )
            update_bytes = (
                integer("update_ciphertexts")
                + integer("compaction_ciphertexts")
                + integer("blinding_mask_ciphertexts")
            ) * ciphertext_bytes
            records.append(
                {
                    "strategy": row["strategy"],
                    "category": row["category"],
                    "source": "model-counts-times-measured-unit-costs",
                    "measured_unit_cost_time_ms": measured_time,
                    "estimated_update_bytes": update_bytes,
                    "ciphertext_bytes_measured": ciphertext_bytes,
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
