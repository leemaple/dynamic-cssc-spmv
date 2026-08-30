from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.followup_performance_terminal as terminal_module
from dynamic_cssc.followup_performance_contract import (
    FollowupEvidenceEnvelope,
    _canonical_json_bytes,
)
from dynamic_cssc.followup_performance_formal_timing import FollowupFormalTimingLedger
from dynamic_cssc.followup_performance_terminal import (
    inspect_followup_formal_artifact_set,
    inspect_followup_terminal_admission,
    produce_followup_terminal_admission,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage

PLAN = b'{"terminal_sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="terminal-sentinel",
    qualification_seed=91_001,
    formal_seeds=(91_002, 91_003, 91_004),
    query_vector_seed=9_100_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=303,
        provider_run_attempt=1,
    )


def _timing() -> FollowupFormalTimingLedger:
    document = {
        "formal_campaign_provider_run_attempt": 1,
        "formal_campaign_provider_run_id": 303,
        "formal_unit_count": 17,
        "provider_retry_used": False,
    }
    content = _canonical_json_bytes(document)
    return FollowupFormalTimingLedger(
        document=document,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _envelope(kind: str, identity: str) -> FollowupEvidenceEnvelope:
    inner = hashlib.sha256(f"inner-{identity}".encode()).hexdigest()
    document = {
        "inner_sha256": inner,
        "unit_attempt_ordinal": 1,
        "unit_identity_sha256": identity,
        "unit_kind": kind,
    }
    content = f"{kind}:{identity}".encode()
    return FollowupEvidenceEnvelope(
        document=document,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
        inner_bytes=b"sentinel\n",
    )


def _inspection(root: Path, kind: str, identity_ordinal: int, **extra: object):
    identity = f"{identity_ordinal:064x}"
    return SimpleNamespace(
        artifact_name=root.name,
        root=root,
        unit_identity_sha256=identity,
        envelope=_envelope(kind, identity),
        **extra,
    )


@pytest.fixture
def terminal_mocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    root = (tmp_path / "inputs").resolve()
    root.mkdir()
    acquisition_root = root / "acquisition-final"
    native_names = {
        (strategy, scale): f"native-{ordinal}-{scale}"
        for ordinal, strategy in enumerate(ROUTE_A_STRATEGY_CANDIDATES)
        for scale in ("S", "M")
    }
    synthetic_names = {
        (scale, seed): f"synthetic-{scale}-{seed}"
        for scale in ("S", "M")
        for seed in PROFILE.formal_seeds
    }
    ordered_names = {
        (partition, semantics): f"ordered-{partition}-{semantics}"
        for partition in (0, 1)
        for semantics in ("T1", "T2")
    }
    all_names = (
        acquisition_root.name,
        *native_names.values(),
        *synthetic_names.values(),
        *ordered_names.values(),
    )
    for name in all_names:
        (root / name).mkdir()
    classified = {
        "formal-acquisition": {acquisition_root.name: acquisition_root},
        "formal-native": {name: root / name for name in native_names.values()},
        "formal-synthetic": {name: root / name for name in synthetic_names.values()},
        "formal-ordered-event": {name: root / name for name in ordered_names.values()},
    }
    monkeypatch.setattr(
        terminal_module,
        "_classify_children",
        lambda *_args, **_kwargs: classified,
    )
    traces = tuple(
        SimpleNamespace(
            partition=partition,
            semantics=semantics,
            accepted_trace_sha256=f"{40 + partition:064x}",
            mapping_sha256=f"{50 + partition:064x}",
            raw_object_sha256="6" * 64,
            event_trace_sha256=f"{60 + partition * 2 + (semantics == 'T2'):064x}",
        )
        for partition in (0, 1)
        for semantics in ("T1", "T2")
    )
    transform = SimpleNamespace(
        raw_object_sha256="6" * 64,
        partitions=(
            SimpleNamespace(
                accepted_trace_sha256="7" * 64,
                mapping_sha256="8" * 64,
            ),
            SimpleNamespace(
                accepted_trace_sha256="9" * 64,
                mapping_sha256="a" * 64,
            ),
        ),
    )
    monkeypatch.setattr(
        terminal_module,
        "inspect_followup_acquisition_artifact",
        lambda *_args, **_kwargs: _inspection(
            acquisition_root,
            "formal-acquisition",
            1,
            transform=transform,
            traces=traces,
        ),
    )
    monkeypatch.setattr(
        terminal_module,
        "expected_followup_formal_native_artifact_name",
        lambda **kwargs: native_names[
            (kwargs["strategy_candidate_id"], kwargs["scale"])
        ],
    )
    native_counter = iter(range(2, 8))
    monkeypatch.setattr(
        terminal_module,
        "inspect_followup_formal_native_artifact",
        lambda path, **kwargs: _inspection(
            path,
            "formal-native",
            next(native_counter),
            case=SimpleNamespace(
                case_binding_sha256=hashlib.sha256(
                    f"{kwargs['strategy_candidate_id']}:{kwargs['scale']}".encode()
                ).hexdigest()
            ),
        ),
    )

    def generate_trace(*, scale: str, formal_seed: int, **_kwargs: object):
        return SimpleNamespace(
            scale=scale,
            formal_seed=formal_seed,
            event_trace_sha256=hashlib.sha256(f"{scale}:{formal_seed}".encode()).hexdigest(),
        )

    monkeypatch.setattr(terminal_module, "generate_route_a_formal_trace", generate_trace)
    monkeypatch.setattr(
        terminal_module,
        "expected_followup_formal_synthetic_artifact_name",
        lambda **kwargs: synthetic_names[
            (kwargs["trace"].scale, kwargs["trace"].formal_seed)
        ],
    )
    synthetic_counter = iter(range(8, 14))
    monkeypatch.setattr(
        terminal_module,
        "inspect_followup_formal_synthetic_artifact",
        lambda path, **_kwargs: _inspection(
            path,
            "formal-synthetic",
            next(synthetic_counter),
            inherited=SimpleNamespace(shard_identity_sha256="b" * 64),
        ),
    )
    monkeypatch.setattr(
        terminal_module,
        "expected_followup_formal_ordered_artifact_name",
        lambda **kwargs: ordered_names[
            (kwargs["trace"].partition, kwargs["trace"].semantics)
        ],
    )
    ordered_counter = iter(range(14, 18))
    monkeypatch.setattr(
        terminal_module,
        "inspect_followup_formal_ordered_artifact",
        lambda path, **_kwargs: _inspection(
            path,
            "formal-ordered-event",
            next(ordered_counter),
            inherited=SimpleNamespace(shard_identity_sha256="c" * 64),
        ),
    )
    return root


def test_terminal_admits_exact_ordered_seventeen_object_set(
    tmp_path: Path,
    terminal_mocks: Path,
) -> None:
    artifact_set = inspect_followup_formal_artifact_set(
        terminal_mocks,
        repository_root=tmp_path.resolve(),
        lineage=_lineage(),
        scientific_profile=PROFILE,
        machine_plan_bytes=PLAN,
    )
    output_parent = (tmp_path / "output").resolve()
    output_parent.mkdir()
    output = output_parent / "terminal"
    produced = produce_followup_terminal_admission(
        artifact_set,
        output,
        lineage=_lineage(),
        timing_ledger=_timing(),
    )
    inspected = inspect_followup_terminal_admission(
        output,
        artifact_set=artifact_set,
        lineage=_lineage(),
        timing_ledger=_timing(),
    )

    assert len(artifact_set.records) == 17
    assert [record.unit_kind for record in artifact_set.records] == [
        "formal-acquisition",
        *(["formal-native"] * 6),
        *(["formal-synthetic"] * 6),
        *(["formal-ordered-event"] * 4),
    ]
    assert produced.artifact_name == inspected.artifact_name
    assert inspected.document["publication_evidence_admitted"] is True
    assert inspected.document["replacement_attempt_used"] is False
    assert inspected.envelope.document["authority"] is False
