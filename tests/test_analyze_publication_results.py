from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY_ROOT / "scripts" / "analyze_publication_results.py"


def _run_cli(
    tmp_path: Path, content: bytes, claimed_digest: str
) -> subprocess.CompletedProcess[str]:
    input_path = tmp_path / "heldout.json"
    input_path.write_bytes(content)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        (
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--input-sha256",
            claimed_digest,
            "--output-dir",
            str(tmp_path / "analysis"),
        ),
        cwd=REPOSITORY_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_rejects_a_checksum_mismatch_before_parsing_or_writing(tmp_path: Path) -> None:
    result = _run_cli(tmp_path, b"not-json\n", "0" * 64)

    assert result.returncode != 0
    assert "SHA-256" in result.stderr
    assert not (tmp_path / "analysis").exists()


def test_cli_rejects_noncanonical_json_even_with_a_matching_checksum(tmp_path: Path) -> None:
    content = b"{}"
    result = _run_cli(tmp_path, content, hashlib.sha256(content).hexdigest())

    assert result.returncode != 0
    assert "canonical JSON" in result.stderr
    assert not (tmp_path / "analysis").exists()


def test_cli_cross_snapshot_path_is_explicitly_hold_without_caller_evidence_knobs(
    tmp_path: Path,
) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    help_result = subprocess.run(
        (sys.executable, str(SCRIPT), "--help"),
        cwd=REPOSITORY_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert help_result.returncode == 0
    assert "Cross-snapshot analysis is HOLD" in help_result.stdout

    input_path = tmp_path / "heldout.json"
    input_path.write_bytes(b"{}\n")
    result = subprocess.run(
        (
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_path),
            "--input-sha256",
            hashlib.sha256(b"{}\n").hexdigest(),
            "--output-dir",
            str(tmp_path / "analysis"),
            "--evidence-freeze-git-sha",
            "0" * 40,
        ),
        cwd=REPOSITORY_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "unrecognized arguments: --evidence-freeze-git-sha" in result.stderr
    assert not (tmp_path / "analysis").exists()


def test_cli_recomputes_the_closed_schema_instead_of_accepting_a_forged_verdict(
    tmp_path: Path,
) -> None:
    content = b'{"analysis_completed":true,"preregistered_finite_corpus_gate_passed":true}\n'
    result = _run_cli(tmp_path, content, hashlib.sha256(content).hexdigest())

    assert result.returncode != 0
    assert "keys must be exact" in result.stderr
    assert not (tmp_path / "analysis").exists()


def test_cli_rejects_an_unattested_or_dirty_analysis_source_before_nested_input(
    tmp_path: Path,
) -> None:
    payload = {
        "ablation_candidate_ids": None,
        "bandwidth_mbps": None,
        "calibration_classification_repetitions": None,
        "calibration_classification_seed": None,
        "calibration": None,
        "cell_bindings": None,
        "comparator_candidate_id": None,
        "dataset_ids": None,
        "experiment_source_git_sha": "0" * 40,
        "fixed_candidate_ids": None,
        "measurement_kind": None,
        "partition_resampling_repetitions": None,
        "partition_resampling_seed": None,
        "primary_confirmatory_family": None,
        "evaluated_freshness_seconds": None,
        "records": None,
        "reference_candidate_ids": None,
        "rho_values": None,
        "schema_version": None,
        "semantics": None,
        "trace_units": None,
    }
    content = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")

    result = _run_cli(tmp_path, content, hashlib.sha256(content).hexdigest())

    assert result.returncode != 0
    assert (
        "analysis behavior source" in result.stderr
        or "repository-owned clean analysis HEAD" in result.stderr
        or "stable clean HEAD" in result.stderr
        or "stable fully clean repository HEAD" in result.stderr
    )
    assert not (tmp_path / "analysis").exists()


def test_test_only_analysis_source_seam_rejects_external_process_callers() -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    completed = subprocess.run(
        (
            sys.executable,
            "-c",
            (
                "from dynamic_cssc.publication_statistics import "
                "_test_only_analysis_source; "
                "_test_only_analysis_source().__enter__()"
            ),
        ),
        cwd=REPOSITORY_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "unavailable to production callers" in completed.stderr
