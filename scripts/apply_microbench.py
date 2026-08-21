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
    noise_budget_profile = micro["noise_budget_profile"]
    evidence_scope = micro["evidence_scope"]
    mixed_workload_claim_allowed = micro["mixed_workload_formal_parameter_claim_allowed"]
    if noise_budget_profile != "day2_mult_only":
        raise ValueError("microbench must use the day2_mult_only noise-budget profile")
    if evidence_scope != "isolated-unit-probe-only":
        raise ValueError("microbench evidence must remain isolated-unit-probe-only")
    if mixed_workload_claim_allowed is not False:
        raise ValueError("isolated microbench cannot support a mixed-workload parameter claim")
    operations = micro["operations"]
    unit = {name: details["median_ms"] for name, details in operations.items()}
    ciphertext_bytes = int(micro["ciphertext_bytes"])
    records = []
    with args.model_csv.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            def integer(name: str, record: dict[str, str] = row) -> int:
                return int(float(record[name]))

            update_time = integer("update_encryptions") * unit["encrypt"]
            query_time = (
                (integer("query_ciphertexts") + integer("blinding_encryptions"))
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
                integer("update_ciphertexts") + integer("compaction_ciphertexts")
            ) * ciphertext_bytes
            records.append(
                {
                    "strategy": row["strategy"],
                    "category": row["category"],
                    "source": "model-counts-times-isolated-measured-unit-costs",
                    "noise_budget_profile": noise_budget_profile,
                    "evidence_scope": evidence_scope,
                    "mixed_workload_formal_parameter_claim_allowed": (
                        mixed_workload_claim_allowed
                    ),
                    "complete_cost_claim_allowed": False,
                    "estimated_update_time_ms": update_time,
                    "estimated_query_time_ms": query_time,
                    "estimated_total_time_ms": update_time + query_time,
                    "estimated_update_bytes": update_bytes,
                    "estimated_query_upload_bytes": (
                        integer("query_ciphertexts") * ciphertext_bytes
                    ),
                    "estimated_mask_upload_bytes": (
                        integer("blinding_mask_ciphertexts") * ciphertext_bytes
                    ),
                    "estimated_result_download_bytes": (
                        integer("result_ciphertexts") * ciphertext_bytes
                    ),
                    "unpriced_counts": {
                        "client_merges": integer("client_merges"),
                        "mask_random_elements": integer("mask_random_elements"),
                        "mask_mapped_elements": integer("mask_mapped_elements"),
                        "client_reorder_elements": integer("client_reorder_elements"),
                        "metadata_units": integer("metadata_units"),
                    },
                    "ciphertext_bytes_measured": ciphertext_bytes,
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
