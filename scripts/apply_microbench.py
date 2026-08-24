#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

_COUNT_FIELDS = (
    "update_encryptions",
    "update_ciphertexts",
    "compaction_ciphertexts",
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
    "ci_patch_entries",
    "ci_full_sync_entries",
    "metadata_units",
)
_REQUIRED_MODEL_FIELDS = frozenset(("strategy", "category", *_COUNT_FIELDS))
_CANONICAL_NONNEGATIVE_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)")


def _model_count(raw_value: object, field: str) -> int:
    if type(raw_value) is not str or _CANONICAL_NONNEGATIVE_INTEGER.fullmatch(raw_value) is None:
        raise ValueError(f"{field} must be a canonical nonnegative integer")
    try:
        return int(raw_value)
    except ValueError as error:
        raise ValueError(f"{field} must be a canonical nonnegative integer") from error


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
    ciphertext_bytes = micro["ciphertext_bytes"]
    if type(ciphertext_bytes) is not int or ciphertext_bytes <= 0:
        raise ValueError("microbench ciphertext_bytes must be a positive strict integer")
    records = []
    with args.model_csv.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing_fields = sorted(_REQUIRED_MODEL_FIELDS - set(reader.fieldnames or ()))
        if missing_fields:
            raise ValueError(f"model CSV missing required fields: {', '.join(missing_fields)}")
        for row_number, row in enumerate(reader, start=2):
            counts = {
                name: _model_count(row[name], f"model CSV row {row_number} {name}")
                for name in _COUNT_FIELDS
            }

            def integer(name: str, record: dict[str, int] = counts) -> int:
                return record[name]

            if integer("update_encryptions") != (
                integer("update_ciphertexts") + integer("compaction_ciphertexts")
            ):
                raise ValueError(
                    "update_encryptions must equal update_ciphertexts + compaction_ciphertexts"
                )
            cc_multiplications = integer("cc_multiplications")
            relinearizations = integer("relinearizations")
            if cc_multiplications != relinearizations:
                raise ValueError("cc_multiplications must equal relinearizations")
            if integer("query_ciphertexts") != cc_multiplications:
                raise ValueError("query_ciphertexts must equal cc_multiplications")
            if integer("result_ciphertexts") != integer("decryptions"):
                raise ValueError("result_ciphertexts must equal decryptions")
            random_f1m_ciphertexts = integer("blinding_mask_ciphertexts")
            encrypted_zero_dummy_ciphertexts = integer("blinding_dummy_ciphertexts")
            blinding_encryptions = integer("blinding_encryptions")
            blinding_ciphertext_uploads = random_f1m_ciphertexts + encrypted_zero_dummy_ciphertexts
            if blinding_ciphertext_uploads != blinding_encryptions:
                raise ValueError(
                    "blinding_encryptions must equal blinding_mask_ciphertexts + "
                    "blinding_dummy_ciphertexts"
                )
            if integer("blinding_additions") != blinding_encryptions:
                raise ValueError("blinding_additions must equal blinding_encryptions")
            ci_patch_entries = integer("ci_patch_entries")
            ci_full_sync_entries = integer("ci_full_sync_entries")
            metadata_units = integer("metadata_units")
            if metadata_units != ci_patch_entries + ci_full_sync_entries:
                raise ValueError(
                    "metadata_units must equal ci_patch_entries + ci_full_sync_entries"
                )
            update_time = integer("update_encryptions") * unit["encrypt"]
            query_time = (
                (integer("query_ciphertexts") + blinding_encryptions) * unit["encrypt"]
                + cc_multiplications * unit["eval_mult_with_relinearization"]
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
                    "mixed_workload_formal_parameter_claim_allowed": (mixed_workload_claim_allowed),
                    "complete_cost_claim_allowed": False,
                    "estimated_update_time_ms": update_time,
                    "estimated_query_time_ms": query_time,
                    "estimated_total_time_ms": update_time + query_time,
                    "estimated_update_bytes": update_bytes,
                    "estimated_query_upload_bytes": (
                        integer("query_ciphertexts") * ciphertext_bytes
                    ),
                    "estimated_mask_upload_bytes": (blinding_ciphertext_uploads * ciphertext_bytes),
                    "estimated_result_download_bytes": (
                        integer("result_ciphertexts") * ciphertext_bytes
                    ),
                    "unpriced_counts": {
                        "ci_patch_entries": ci_patch_entries,
                        "ci_full_sync_entries": ci_full_sync_entries,
                        "client_merges": integer("client_merges"),
                        "mask_random_elements": integer("mask_random_elements"),
                        "mask_mapped_elements": integer("mask_mapped_elements"),
                        "client_reorder_elements": integer("client_reorder_elements"),
                        "metadata_units": metadata_units,
                    },
                    "ciphertext_bytes_measured": ciphertext_bytes,
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
