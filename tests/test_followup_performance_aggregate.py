from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_aggregate as aggregate_module
from dynamic_cssc.followup_performance_aggregate import (
    FollowupAggregateError,
    inspect_followup_aggregate,
    produce_followup_aggregate,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
)
from dynamic_cssc.followup_performance_terminal import (
    FollowupFormalArtifactRecord,
    FollowupFormalArtifactSet,
    FollowupTerminalAdmissionInspection,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage


class _FakeAcquisition:
    pass


class _FakeNative:
    pass


class _FakeSynthetic:
    pass


class _FakeOrdered:
    pass


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=303,
        provider_run_attempt=1,
    )


def _envelope(label: str) -> FollowupEvidenceEnvelope:
    content = _canonical_json_bytes({"label": label})
    return FollowupEvidenceEnvelope(
        document={"label": label},
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
        inner_bytes=b"sentinel\n",
    )


def _record(ordinal: int, kind: str) -> FollowupFormalArtifactRecord:
    return FollowupFormalArtifactRecord(
        ordinal=ordinal,
        unit_kind=kind,
        artifact_name=f"artifact-{ordinal}",
        unit_identity_sha256=f"{ordinal + 1:064x}",
        envelope_sha256=f"{ordinal + 101:064x}",
        inner_sha256=f"{ordinal + 201:064x}",
        scope={"ordinal": ordinal},
    )


def _receipt(label: str) -> bytes:
    return _canonical_json_bytes({"receipt": label})


def _cell(label: str) -> SimpleNamespace:
    document = {"cell": label}
    return SimpleNamespace(
        document=document,
        sha256=hashlib.sha256(_canonical_json_bytes(document)).hexdigest(),
    )


def _artifact_set(tmp_path: Path) -> FollowupFormalArtifactSet:
    acquisition = _FakeAcquisition()
    acquisition.guard_receipt = SimpleNamespace(document={"download": "guard"})
    acquisition.producer_receipt = SimpleNamespace(document={"download": "producer"})
    acquisition.transform = SimpleNamespace(raw_object_sha256="4" * 64)

    inspections: list[object] = [acquisition]
    records = [_record(0, "formal-acquisition")]
    for ordinal in range(1, 7):
        inner = tmp_path / f"native-{ordinal}"
        (inner / "replays").mkdir(parents=True)
        for replay in range(3):
            (inner / f"replays/recorded-{replay}.json").write_bytes(
                _receipt(f"native-{ordinal}-replay-{replay}")
            )
        inspection = _FakeNative()
        inspection.inner_directory = inner
        inspection.case = SimpleNamespace(case_binding_sha256=f"{ordinal + 301:064x}")
        inspection.inherited = SimpleNamespace(
            guard_receipt_bytes=_receipt(f"native-{ordinal}-guard")
        )
        inspection.producer_observations_bytes = _canonical_json_bytes(
            {"producer": ordinal}
        )
        inspections.append(inspection)
        records.append(_record(ordinal, "formal-native"))
    for offset in range(6):
        ordinal = 7 + offset
        inspection = _FakeSynthetic()
        inspection.inherited = SimpleNamespace(
            final_cells=tuple(_cell(f"synthetic-{offset}-{cell}") for cell in range(9)),
            rho10_cells=(_cell(f"synthetic-{offset}-rho10"),),
            replay_receipts=tuple(
                _receipt(f"synthetic-{offset}-replay-{cell}") for cell in range(10)
            ),
            guard_receipts=tuple(
                _receipt(f"synthetic-{offset}-guard-{cell}") for cell in range(10)
            ),
        )
        inspections.append(inspection)
        records.append(_record(ordinal, "formal-synthetic"))
    for offset in range(4):
        ordinal = 13 + offset
        inspection = _FakeOrdered()
        inspection.inherited = SimpleNamespace(
            final_cells=tuple(_cell(f"ordered-{offset}-{cell}") for cell in range(9)),
            replay_receipts=tuple(
                _receipt(f"ordered-{offset}-replay-{cell}") for cell in range(9)
            ),
            guard_receipts=tuple(
                _receipt(f"ordered-{offset}-guard-{cell}") for cell in range(9)
            ),
        )
        inspections.append(inspection)
        records.append(_record(ordinal, "formal-ordered-event"))
    document_bytes = _canonical_json_bytes([record.document() for record in records])
    return FollowupFormalArtifactSet(
        records=tuple(records),
        inspections=tuple(inspections),
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
    )


def _terminal(artifact_set: FollowupFormalArtifactSet) -> FollowupTerminalAdmissionInspection:
    return FollowupTerminalAdmissionInspection(
        artifact_name="terminal",
        root=Path("/terminal"),
        formal_artifact_set_sha256=artifact_set.sha256,
        formal_timing_ledger_sha256="5" * 64,
        unit_identity_sha256="6" * 64,
        envelope=_envelope("terminal"),
        document={
            "formal_campaign_provider_run_attempt": 1,
            "formal_campaign_provider_run_id": 303,
            "publication_evidence_admitted": True,
        },
    )


@pytest.fixture(autouse=True)
def exact_inspection_types(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aggregate_module, "FollowupAcquisitionInspection", _FakeAcquisition)
    monkeypatch.setattr(aggregate_module, "FollowupFormalNativeInspection", _FakeNative)
    monkeypatch.setattr(aggregate_module, "FollowupFormalSyntheticInspection", _FakeSynthetic)
    monkeypatch.setattr(aggregate_module, "FollowupFormalOrderedInspection", _FakeOrdered)


def test_aggregate_contains_all_admitted_raw_results_and_no_source_bytes(
    tmp_path: Path,
) -> None:
    artifact_set = _artifact_set(tmp_path)
    terminal = _terminal(artifact_set)
    parent = (tmp_path / "output").resolve()
    parent.mkdir()
    output = parent / "aggregate"

    produced = produce_followup_aggregate(
        artifact_set,
        terminal,
        output,
        lineage=_lineage(),
    )
    inspected = inspect_followup_aggregate(
        output,
        artifact_set=artifact_set,
        terminal=terminal,
        lineage=_lineage(),
    )

    assert produced.artifact_name == inspected.artifact_name
    assert inspected.document["publication_evidence_admitted"] is True
    assert inspected.document["analysis_authority"] is False
    assert inspected.document["acquisition"]["raw_source_bytes_included"] is False
    assert len(inspected.document["formal_artifacts"]) == 17
    assert inspected.document["formal_artifacts"][0]["artifact_name"] == "artifact-0"
    assert inspected.document["terminal_admission_artifact_name"] == "terminal"
    assert len(inspected.document["native_cases"]) == 6
    assert len(inspected.document["simulator_shards"]) == 10
    assert sum(
        len(shard["cells"]) for shard in inspected.document["simulator_shards"]
    ) == 96
    assert inspected.envelope.document["authority"] is False


def test_aggregate_rejects_terminal_or_payload_drift(tmp_path: Path) -> None:
    artifact_set = _artifact_set(tmp_path)
    terminal = _terminal(artifact_set)
    parent = (tmp_path / "output").resolve()
    parent.mkdir()
    output = parent / "aggregate"
    produce_followup_aggregate(
        artifact_set,
        terminal,
        output,
        lineage=_lineage(),
    )

    payload = output / "inner-payload.json"
    payload.chmod(stat.S_IRUSR | stat.S_IWUSR)
    payload.write_bytes(b"{}\n")
    with pytest.raises(FollowupAggregateError, match="checksums"):
        inspect_followup_aggregate(
            output,
            artifact_set=artifact_set,
            terminal=terminal,
            lineage=_lineage(),
        )
    terminal.document["publication_evidence_admitted"] = False
    with pytest.raises(FollowupAggregateError, match="terminal admission"):
        aggregate_module._aggregate_document(
            artifact_set,
            terminal,
            lineage=_lineage(),
        )
