from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest

from dynamic_cssc.followup_performance_aggregate import FollowupAggregateInspection
from dynamic_cssc.followup_performance_analysis import (
    FollowupAnalysisError,
    inspect_followup_analysis,
    produce_followup_analysis,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
)
from dynamic_cssc.followup_performance_lineage import FollowupCompatibilityReceipt


def _envelope() -> FollowupEvidenceEnvelope:
    content = _canonical_json_bytes({"aggregate": True})
    return FollowupEvidenceEnvelope(
        document={"authority": False},
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
        inner_bytes=b"sentinel\n",
    )


def _cell(shard: int, ordinal: int, *, projected: bool) -> dict[str, object]:
    document = {
        "counts": {"queries": ordinal + 1, "updates": 4, "windows": 2},
        "evaluation": {
            "mode": (
                "exact-query-linear-projection" if projected else "directly-measured"
            )
        },
        "identity": {
            "formal_seed_or_null": 95_000 + shard if shard < 6 else None,
            "object_sha256_or_null": None if shard < 6 else "a" * 64,
            "partition_or_null": None if shard < 6 else (shard - 6) // 2,
            "rho": "10" if projected else "1",
            "scale_or_null": "S" if shard < 6 else None,
            "semantics_or_null": None if shard < 6 else ("T1" if shard % 2 == 0 else "T2"),
            "source_kind": "synthetic" if shard < 6 else "snap-a2q",
            "strategy_candidate_id": "padding-reuse",
        },
        "measurements": {
            "peak_rss_kib": None if projected else 100,
            "producer_result_assembly_seconds": None if projected else "0.000000003",
            "producer_state_transition_seconds": None if projected else "0.000000002",
            "replay_seconds": None if projected else "0.000000004",
            "scratch_allocated_bytes": None if projected else 200,
        },
        "serialized_bytes": {"query": ordinal + 10, "update": ordinal + 20},
    }
    content = _canonical_json_bytes(document)
    return {"document": document, "sha256": hashlib.sha256(content).hexdigest()}


def _aggregate() -> FollowupAggregateInspection:
    simulator = []
    for shard in range(10):
        count = 10 if shard < 6 else 9
        simulator.append(
            {
                "cells": [
                    _cell(shard, ordinal, projected=ordinal == count - 1)
                    for ordinal in range(count)
                ],
                "formal_unit_ordinal": shard + 7,
            }
        )
    native = []
    for case in range(6):
        processes = [
            {
                "elapsed_ns": 5,
                "execution_process_role": "openfhe-warmup",
                "peak_resident_memory_bytes": 50,
                "peak_scratch_bytes": 60,
                "process_ordinal_or_null": 0,
            },
            *(
                {
                    "elapsed_ns": 100 + ordinal * 10 + case,
                    "execution_process_role": "openfhe-recorded",
                    "peak_resident_memory_bytes": 500 + ordinal,
                    "peak_scratch_bytes": 600 + ordinal,
                    "process_ordinal_or_null": ordinal,
                }
                for ordinal in range(3)
            ),
        ]
        native.append(
            {
                "case_binding_sha256": f"{case + 1:064x}",
                "formal_unit_ordinal": case + 1,
                "producer_observations": {
                    "producer_stage_ledger": {"processes": processes},
                    "recorded_packages": [
                        {
                            "process_ordinal": ordinal,
                            "serialized_package_bytes": 1_000 + ordinal * 100 + case,
                        }
                        for ordinal in range(3)
                    ],
                },
                "replay_receipts": [
                    {
                        "elapsed_ns": 200 + ordinal * 10 + case,
                        "peak_resident_memory_bytes": 700 + ordinal,
                        "peak_scratch_bytes": 800 + ordinal,
                    }
                    for ordinal in range(3)
                ],
                "scope": {
                    "formal_seed": 95_001,
                    "scale": "S" if case % 2 == 0 else "M",
                    "strategy_candidate_id": f"strategy-{case // 2}",
                },
            }
        )
    kinds = (
        "formal-acquisition",
        *("formal-native" for _ in range(6)),
        *("formal-synthetic" for _ in range(6)),
        *("formal-ordered-event" for _ in range(4)),
    )
    document = {
        "analysis_authority": False,
        "formal_artifacts": [
            {
                "artifact_name": f"formal-artifact-{ordinal}",
                "envelope_sha256": f"{ordinal + 100:064x}",
                "ordinal": ordinal,
                "unit_attempt_ordinal": 1,
                "unit_kind": kind,
            }
            for ordinal, kind in enumerate(kinds)
        ],
        "native_cases": native,
        "publication_evidence_admitted": True,
        "simulator_shards": simulator,
        "terminal_admission_artifact_name": "terminal-admission",
        "terminal_admission_envelope_sha256": "c" * 64,
    }
    content = _canonical_json_bytes(document)
    return FollowupAggregateInspection(
        artifact_name="aggregate",
        root=Path("/aggregate"),
        aggregate_sha256=hashlib.sha256(content).hexdigest(),
        unit_identity_sha256="b" * 64,
        envelope=_envelope(),
        document=document,
    )


def _compatibility() -> FollowupCompatibilityReceipt:
    content = _canonical_json_bytes(
        {
            "analysis_compatibility_verified": True,
            "analysis_execution_authorized": False,
            "analysis_source_S3_sha": "3" * 40,
            "analyzer_behavior_set_exact": True,
            "evidence_freeze_S2_sha": "2" * 40,
            "experiment_source_S1_sha": "1" * 40,
            "runtime_execution_isolation_verified": False,
        }
    )
    return FollowupCompatibilityReceipt(
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def test_analysis_reports_all_raw_native_repetitions_and_bounded_cells(
    tmp_path: Path,
) -> None:
    parent = (tmp_path / "output").resolve()
    parent.mkdir()
    output = parent / "analysis"
    aggregate = _aggregate()
    compatibility = _compatibility()

    produced = produce_followup_analysis(aggregate, compatibility, output)
    inspected = inspect_followup_analysis(
        output,
        aggregate=aggregate,
        compatibility=compatibility,
    )

    assert produced.artifact_name == inspected.artifact_name
    assert inspected.document["analysis_completed"] is True
    assert inspected.document["bounded_scale_only"] is True
    assert inspected.document["p_values"] is False
    assert len(inspected.document["simulator_cells"]) == 96
    assert len(inspected.document["native_raw_repetitions"]) == 36
    assert len(inspected.document["native_summaries"]) == 6
    assert inspected.document["native_summaries"][0]["producer_elapsed_ns_median"] == 110
    assert inspected.envelope.document["authority"] is False
    assert len((output / "simulator-cells.csv").read_text().splitlines()) == 97
    assert len((output / "native-repetitions.csv").read_text().splitlines()) == 37
    claim_rows = (output / "claim-to-artifact.csv").read_text().splitlines()
    assert len(claim_rows) == 45
    assert claim_rows[1].startswith("formal-artifact-7,FU-E1,")
    assert any(",FU-E4,bounded-descriptive-analysis," in row for row in claim_rows)


def test_analysis_rejects_derived_member_drift(tmp_path: Path) -> None:
    parent = (tmp_path / "output").resolve()
    parent.mkdir()
    output = parent / "analysis"
    aggregate = _aggregate()
    compatibility = _compatibility()
    produce_followup_analysis(aggregate, compatibility, output)

    target = output / "native-summary.csv"
    target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    target.write_bytes(b"changed\n")
    with pytest.raises(FollowupAnalysisError, match="member changed"):
        inspect_followup_analysis(
            output,
            aggregate=aggregate,
            compatibility=compatibility,
        )
