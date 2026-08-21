from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_apply_microbench_separates_query_update_and_unpriced_costs(tmp_path: Path) -> None:
    model_csv = tmp_path / "metrics.csv"
    fieldnames = [
        "strategy",
        "category",
        "update_encryptions",
        "update_ciphertexts",
        "compaction_ciphertexts",
        "query_ciphertexts",
        "result_ciphertexts",
        "cc_multiplications",
        "rotations",
        "additions",
        "plaintext_masks",
        "blinding_mask_ciphertexts",
        "blinding_encryptions",
        "blinding_additions",
        "decryptions",
        "client_merges",
        "mask_random_elements",
        "mask_mapped_elements",
        "client_reorder_elements",
        "metadata_units",
    ]
    values = {
        "strategy": "Mini-CSSC-Delta",
        "category": "reference",
        "update_encryptions": 2,
        "update_ciphertexts": 11,
        "compaction_ciphertexts": 12,
        "query_ciphertexts": 3,
        "result_ciphertexts": 14,
        "cc_multiplications": 5,
        "rotations": 6,
        "additions": 7,
        "plaintext_masks": 9,
        "blinding_mask_ciphertexts": 13,
        "blinding_encryptions": 4,
        "blinding_additions": 8,
        "decryptions": 10,
        "client_merges": 15,
        "mask_random_elements": 16,
        "mask_mapped_elements": 17,
        "client_reorder_elements": 18,
        "metadata_units": 19,
    }
    with model_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(values)

    microbench = tmp_path / "microbench.json"
    microbench.write_text(
        json.dumps(
            {
                "noise_budget_profile": "day2_mult_only",
                "evidence_scope": "isolated-unit-probe-only",
                "mixed_workload_formal_parameter_claim_allowed": False,
                "ciphertext_bytes": 100,
                "operations": {
                    "encrypt": {"median_ms": 2},
                    "eval_mult_with_relinearization": {"median_ms": 3},
                    "eval_rotate": {"median_ms": 5},
                    "eval_add_ciphertext": {"median_ms": 7},
                    "eval_mult_plaintext_mask": {"median_ms": 11},
                    "decrypt": {"median_ms": 13},
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "derived.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "apply_microbench.py"),
            "--model-csv",
            str(model_csv),
            "--microbench",
            str(microbench),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    [record] = json.loads(output.read_text(encoding="utf-8"))
    assert record["estimated_update_time_ms"] == 4
    assert record["estimated_query_time_ms"] == 393
    assert record["estimated_total_time_ms"] == 397
    assert record["estimated_update_bytes"] == 2300
    assert record["estimated_query_upload_bytes"] == 300
    assert record["estimated_mask_upload_bytes"] == 1300
    assert record["estimated_result_download_bytes"] == 1400
    assert record["unpriced_counts"] == {
        "client_merges": 15,
        "client_reorder_elements": 18,
        "mask_mapped_elements": 17,
        "mask_random_elements": 16,
        "metadata_units": 19,
    }
    assert record["complete_cost_claim_allowed"] is False
    assert record["noise_budget_profile"] == "day2_mult_only"
    assert record["evidence_scope"] == "isolated-unit-probe-only"
    assert record["mixed_workload_formal_parameter_claim_allowed"] is False
