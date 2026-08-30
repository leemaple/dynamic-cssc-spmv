from __future__ import annotations

from pathlib import Path

import pytest

from dynamic_cssc.followup_performance_control_artifacts import (
    FollowupControlArtifactError,
    build_followup_control_receipt,
    inspect_followup_control_artifact,
    produce_followup_control_artifact,
)


@pytest.mark.parametrize(
    "kind",
    ("ci", "pre-s1", "independent-review", "source-anchor"),
)
def test_control_artifact_round_trip_binds_exact_s1_s2_and_run(
    tmp_path: Path,
    kind: str,
) -> None:
    receipt = build_followup_control_receipt(
        kind=kind,  # type: ignore[arg-type]
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=71,
        provider_run_attempt=1,
        details={"gate": "sentinel-pass", "scope": "non-authorizing-test"},
    )
    output = (tmp_path / "artifact").resolve()

    produced = produce_followup_control_artifact(
        receipt,
        output,
        kind=kind,  # type: ignore[arg-type]
    )
    inspected = inspect_followup_control_artifact(
        output,
        expected_kind=kind,  # type: ignore[arg-type]
        expected_receipt_bytes=receipt,
    )

    assert produced == inspected
    assert produced.artifact_name.startswith("followup-performance-v1-control-")
    assert produced.receipt["outcome"] == "success"
    assert produced.envelope.document["authority"] is False
    assert produced.envelope.document["experiment_source_S1_sha"] == "1" * 40
    assert produced.envelope.document["evidence_freeze_S2_sha"] == "2" * 40


def test_control_artifact_rejects_predecessor_schema_before_install(tmp_path: Path) -> None:
    predecessor = (
        b'{"authority":false,"schema_version":"dynamic-cssc-route-a-ci-v1",'
        b'"study_id":"dynamic-cssc-followup-performance-2026-08-30"}\n'
    )

    with pytest.raises(FollowupControlArtifactError):
        produce_followup_control_artifact(
            predecessor,
            (tmp_path / "artifact").resolve(),
            kind="ci",
        )


def test_control_artifact_rejects_extra_member(tmp_path: Path) -> None:
    receipt = build_followup_control_receipt(
        kind="ci",
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=71,
        provider_run_attempt=1,
        details={"gate": "sentinel-pass"},
    )
    output = (tmp_path / "artifact").resolve()
    produce_followup_control_artifact(receipt, output, kind="ci")
    (output / "predecessor-capability.json").write_text("{}\n", encoding="ascii")

    with pytest.raises(FollowupControlArtifactError, match="missing or extra"):
        inspect_followup_control_artifact(output, expected_kind="ci")
