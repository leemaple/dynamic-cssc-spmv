from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


MODEL_FIELDS = (
    "strategy",
    "category",
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


def _model_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "strategy": "Mini-CSSC-Delta",
        "category": "reference",
        "update_encryptions": 23,
        "update_ciphertexts": 11,
        "compaction_ciphertexts": 12,
        "query_ciphertexts": 5,
        "result_ciphertexts": 10,
        "cc_multiplications": 5,
        "relinearizations": 5,
        "rotations": 6,
        "additions": 7,
        "plaintext_masks": 9,
        "blinding_mask_ciphertexts": 1,
        "blinding_dummy_ciphertexts": 3,
        "blinding_encryptions": 4,
        "blinding_additions": 4,
        "decryptions": 10,
        "client_merges": 15,
        "mask_random_elements": 16,
        "mask_mapped_elements": 17,
        "client_reorder_elements": 18,
        "ci_patch_entries": 7,
        "ci_full_sync_entries": 12,
        "metadata_units": 19,
    }
    row.update(overrides)
    return row


def _run_apply(
    tmp_path: Path,
    *,
    row: dict[str, object] | None = None,
    omitted_fields: frozenset[str] = frozenset(),
    ciphertext_bytes: object = 100,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    values = _model_row() if row is None else row
    model_csv = tmp_path / "metrics.csv"
    fieldnames = [name for name in MODEL_FIELDS if name not in omitted_fields]
    with model_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({name: values[name] for name in fieldnames})

    microbench = tmp_path / "microbench.json"
    microbench.write_text(
        json.dumps(
            {
                "noise_budget_profile": "day2_mult_only",
                "evidence_scope": "isolated-unit-probe-only",
                "mixed_workload_formal_parameter_claim_allowed": False,
                "ciphertext_bytes": ciphertext_bytes,
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
    return completed, output


def test_apply_microbench_separates_query_update_and_unpriced_costs(tmp_path: Path) -> None:
    completed, output = _run_apply(tmp_path)

    assert completed.returncode == 0, completed.stderr
    [record] = json.loads(output.read_text(encoding="utf-8"))
    assert record["estimated_update_time_ms"] == 46
    assert record["estimated_query_time_ms"] == 369
    assert record["estimated_total_time_ms"] == 415
    assert record["estimated_update_bytes"] == 2300
    assert record["estimated_query_upload_bytes"] == 500
    assert record["estimated_mask_upload_bytes"] == 400
    assert record["estimated_result_download_bytes"] == 1000
    assert record["unpriced_counts"] == {
        "ci_full_sync_entries": 12,
        "ci_patch_entries": 7,
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


@pytest.mark.parametrize("reported_total", (3, 5))
def test_apply_microbench_fails_closed_when_blinding_upload_counts_do_not_reconcile(
    tmp_path: Path,
    reported_total: int,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(blinding_encryptions=reported_total),
    )

    assert completed.returncode != 0
    assert (
        "blinding_encryptions must equal blinding_mask_ciphertexts + "
        "blinding_dummy_ciphertexts" in completed.stderr
    )
    assert not output.exists()


@pytest.mark.parametrize("relinearizations", (4, 6))
def test_apply_microbench_fails_closed_when_composite_multiply_counts_do_not_reconcile(
    tmp_path: Path,
    relinearizations: int,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(relinearizations=relinearizations),
    )

    assert completed.returncode != 0
    assert "cc_multiplications must equal relinearizations" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("overrides", "message"),
    (
        (
            {"update_encryptions": 22},
            "update_encryptions must equal update_ciphertexts + compaction_ciphertexts",
        ),
        (
            {"query_ciphertexts": 4},
            "query_ciphertexts must equal cc_multiplications",
        ),
        (
            {"result_ciphertexts": 9},
            "result_ciphertexts must equal decryptions",
        ),
        (
            {"blinding_additions": 3},
            "blinding_additions must equal blinding_encryptions",
        ),
    ),
)
def test_apply_microbench_rejects_internally_inconsistent_day1_accounting(
    tmp_path: Path,
    overrides: dict[str, int],
    message: str,
) -> None:
    completed, output = _run_apply(tmp_path, row=_model_row(**overrides))

    assert completed.returncode != 0
    assert message in completed.stderr
    assert not output.exists()


def test_apply_microbench_rejects_legacy_metrics_missing_relinearizations(
    tmp_path: Path,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        omitted_fields=frozenset({"relinearizations"}),
    )

    assert completed.returncode != 0
    assert "model CSV missing required fields: relinearizations" in completed.stderr
    assert not output.exists()


def test_apply_microbench_prices_multiply_and_relinearization_as_one_composite(
    tmp_path: Path,
) -> None:
    zeroed_counts = {name: 0 for name in MODEL_FIELDS[2:]}
    zeroed_counts.update(query_ciphertexts=5, cc_multiplications=5, relinearizations=5)
    completed, output = _run_apply(tmp_path, row=_model_row(**zeroed_counts))

    assert completed.returncode == 0, completed.stderr
    [record] = json.loads(output.read_text(encoding="utf-8"))
    assert record["estimated_query_time_ms"] == 25
    assert record["estimated_total_time_ms"] == 25


@pytest.mark.parametrize("metadata_units", (18, 20))
def test_apply_microbench_fails_closed_when_metadata_counts_do_not_reconcile(
    tmp_path: Path,
    metadata_units: int,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(metadata_units=metadata_units),
    )

    assert completed.returncode != 0
    assert "metadata_units must equal ci_patch_entries + ci_full_sync_entries" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "missing_field",
    ("ci_patch_entries", "ci_full_sync_entries", "metadata_units"),
)
def test_apply_microbench_rejects_legacy_metrics_missing_metadata_breakdown(
    tmp_path: Path,
    missing_field: str,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        omitted_fields=frozenset({missing_field}),
    )

    assert completed.returncode != 0
    assert f"model CSV missing required fields: {missing_field}" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "missing_field",
    (
        "blinding_mask_ciphertexts",
        "blinding_dummy_ciphertexts",
        "blinding_encryptions",
    ),
)
def test_apply_microbench_rejects_legacy_metrics_missing_blinding_fields(
    tmp_path: Path,
    missing_field: str,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        omitted_fields=frozenset({missing_field}),
    )

    assert completed.returncode != 0
    assert f"model CSV missing required fields: {missing_field}" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("random_f1m", "encrypted_zero_dummy", "expected_query_ms", "expected_upload_bytes"),
    (
        (4, 0, 369, 400),
        (0, 4, 369, 400),
        (2, 3, 378, 500),
        (0, 0, 333, 0),
    ),
)
def test_apply_microbench_serializes_random_and_dummy_upload_combinations_consistently(
    tmp_path: Path,
    random_f1m: int,
    encrypted_zero_dummy: int,
    expected_query_ms: int,
    expected_upload_bytes: int,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(
            blinding_mask_ciphertexts=random_f1m,
            blinding_dummy_ciphertexts=encrypted_zero_dummy,
            blinding_encryptions=random_f1m + encrypted_zero_dummy,
            blinding_additions=random_f1m + encrypted_zero_dummy,
        ),
    )

    assert completed.returncode == 0, completed.stderr
    [record] = json.loads(output.read_text(encoding="utf-8"))
    assert record["estimated_query_time_ms"] == expected_query_ms
    assert record["estimated_mask_upload_bytes"] == expected_upload_bytes
    assert record["complete_cost_claim_allowed"] is False
    assert record["mixed_workload_formal_parameter_claim_allowed"] is False


@pytest.mark.parametrize(
    "noncanonical_count",
    ("", "1.0", "1e0", "+1", "01", " 1", "1 ", "True", "nan", "inf"),
)
def test_apply_microbench_rejects_noncanonical_count_types(
    tmp_path: Path,
    noncanonical_count: str,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(blinding_mask_ciphertexts=noncanonical_count),
    )

    assert completed.returncode != 0
    assert (
        "model CSV row 2 blinding_mask_ciphertexts must be a canonical "
        "nonnegative integer" in completed.stderr
    )
    assert not output.exists()


@pytest.mark.parametrize("count_field", MODEL_FIELDS[2:])
def test_apply_microbench_rejects_negative_model_counts(
    tmp_path: Path,
    count_field: str,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(**{count_field: -1}),
    )

    assert completed.returncode != 0
    assert (
        f"model CSV row 2 {count_field} must be a canonical nonnegative integer" in completed.stderr
    )
    assert not output.exists()


@pytest.mark.parametrize("invalid_ciphertext_bytes", (True, 100.0, "100", 0, -1))
def test_apply_microbench_requires_positive_strict_ciphertext_bytes(
    tmp_path: Path,
    invalid_ciphertext_bytes: object,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        ciphertext_bytes=invalid_ciphertext_bytes,
    )

    assert completed.returncode != 0
    assert "microbench ciphertext_bytes must be a positive strict integer" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "large_count",
    (2**53 + 1, 10**309),
    ids=("above-ieee754-exact-integer", "above-ieee754-finite-range"),
)
def test_apply_microbench_preserves_large_counts_through_json_serialization(
    tmp_path: Path,
    large_count: int,
) -> None:
    completed, output = _run_apply(
        tmp_path,
        row=_model_row(
            blinding_mask_ciphertexts=large_count,
            blinding_dummy_ciphertexts=0,
            blinding_encryptions=large_count,
            blinding_additions=large_count,
        ),
    )

    assert completed.returncode == 0, completed.stderr
    [record] = json.loads(output.read_text(encoding="utf-8"))
    assert record["estimated_query_time_ms"] == 333 + 9 * large_count
    assert record["estimated_mask_upload_bytes"] == 100 * large_count
    assert (
        record["estimated_mask_upload_bytes"] // record["ciphertext_bytes_measured"] == large_count
    )
