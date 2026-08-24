from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_postrun as postrun
from dynamic_cssc.day2_calibration_authority import Day2CalibrationInspection
from dynamic_cssc.evidence_compatibility import EvidenceRole, repository_behavior_paths


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _behavior_inventory(source_sha: str) -> dict[str, object]:
    entries = [
        {
            "mode": "100644",
            "object_id": "2" * 40,
            "object_type": "blob",
            "path": path,
        }
        for path in repository_behavior_paths(EvidenceRole.DAY2)
    ]
    behavior_set = {
        "behavior_set_schema_version": "dynamic-cssc-day2-behavior-set-v3",
        "entries": entries,
        "role": "day2",
    }
    return {
        "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
        "role": "day2",
        "source_git_sha": source_sha,
        "behavior_set_schema_version": "dynamic-cssc-day2-behavior-set-v3",
        "behavior_set_sha256": _sha256(_canonical(behavior_set)),
        "entries": entries,
    }


def _inspection(inventory: dict[str, object]) -> Day2CalibrationInspection:
    return Day2CalibrationInspection(
        evidence_scope="isolated-14-primitive-fixed-host-calibration-only",
        source_git_sha="a" * 40,
        workflow_run_id=456,
        workflow_run_attempt=2,
        primitive_names=("primitive",),
        measurement_block_count=14,
        outer_archive_sha256="1" * 64,
        manifest_sha256="2" * 64,
        checksums_sha256="3" * 64,
        raw_measurement_blocks_sha256="4" * 64,
        operation_profile_set_sha256="5" * 64,
        rotation_key_plan_sha256="6" * 64,
        generated_key_inventory_sha256="7" * 64,
        runtime_isolation_receipt_sha256="8" * 64,
        contract_bindings_sha256="9" * 64,
        calibration_projection_sha256="b" * 64,
        artifact_behavior_inventory_sha256=_sha256(_canonical(inventory)),
        behavior_set_schema_version="dynamic-cssc-day2-behavior-set-v3",
        behavior_set_sha256=inventory["behavior_set_sha256"],
    )


def test_postrun_proposal_is_mechanical_atomic_and_non_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = _behavior_inventory("a" * 40)
    inspection = _inspection(inventory)
    metadata = {
        "schema_version": "dynamic-cssc-publication-day2-github-artifact-metadata-v2",
        "inner_archive_sha256": inspection.outer_archive_sha256,
    }
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_bytes(_canonical(metadata))
    monkeypatch.setattr(
        postrun,
        "inspect_day2_calibration_archive",
        lambda *_args, **_kwargs: inspection,
    )
    monkeypatch.setattr(postrun, "_artifact_behavior_inventory", lambda _path: inventory)
    output = tmp_path / "proposal"

    proposal = postrun.propose_repository_day2_calibration_post_run_anchor(
        tmp_path / "day2.zip",
        metadata_path,
        output,
    )

    assert proposal.output_dir == output.absolute()
    assert proposal.outer_archive_sha256 == inspection.outer_archive_sha256
    assert proposal.formal_authority_granted is False
    assert {path.name for path in output.iterdir()} == {
        "POSTRUN-MANIFEST.json",
        "SHA256SUMS",
        "day2-calibration-inspection.json",
        "day2-calibration-post-run-anchor-proposal.json",
        "day2-github-artifact-metadata.json",
    }
    anchor_set = json.loads(
        (output / "day2-calibration-post-run-anchor-proposal.json").read_bytes()
    )
    anchor = anchor_set["anchors"][0]
    assert anchor["outer_archive_sha256"] == inspection.outer_archive_sha256
    assert anchor["artifact_behavior_inventory"] == inventory
    assert anchor["runtime_isolation_receipt_sha256"] == (
        inspection.runtime_isolation_receipt_sha256
    )
    inspection_document = json.loads(
        (output / "day2-calibration-inspection.json").read_bytes()
    )
    assert inspection_document["formal_authority_granted"] is False
    assert "authority_granted" not in inspection_document


def test_postrun_proposal_rejects_noncanonical_metadata(tmp_path: Path) -> None:
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text('{"inner_archive_sha256": "' + "1" * 64 + '"}\n')

    with pytest.raises(postrun.Day2CalibrationPostRunError, match="not canonical"):
        postrun.propose_repository_day2_calibration_post_run_anchor(
            tmp_path / "day2.zip",
            metadata_path,
            tmp_path / "proposal",
        )


def test_postrun_proposal_never_replaces_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "proposal"
    output.mkdir()
    marker = output / "owned.txt"
    marker.write_text("owned\n", encoding="utf-8")

    with pytest.raises(postrun.Day2CalibrationPostRunError, match="must be absent"):
        postrun.propose_repository_day2_calibration_post_run_anchor(
            tmp_path / "day2.zip",
            tmp_path / "metadata.json",
            output,
        )
    assert marker.read_text(encoding="utf-8") == "owned\n"
