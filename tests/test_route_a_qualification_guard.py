from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.route_a_qualification_guard as guard_module
from dynamic_cssc.route_a_qualification_guard import (
    RouteACombinedGuardError,
    inspect_route_a_combined_guard_artifact,
    produce_route_a_combined_guard,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_scientific_profile import (
    PREDECESSOR_ROUTE_A_PROFILE,
    RouteAScientificProfile,
)
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    route_a_synthetic_shard_identity,
)
from dynamic_cssc.route_a_workloads import generate_route_a_qualification_trace

ROOT = Path(__file__).resolve().parents[1]
PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()


@pytest.fixture
def lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=41,
        provider_run_attempt=1,
    )


def _wrapper(path: Path, members: dict[str, bytes]) -> tuple[str, int]:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest(), len(content)


def _provider_json(
    *,
    lineage: RouteASyntheticSuiteLineage,
    q2: tuple[str, int],
    q4: tuple[str, int],
    q2_name: str = "q2-simulator-guarded-receipt",
    q4_name: str = "q4-native-guarded-case-bundle",
) -> bytes:
    rows = []
    for identifier, name, (digest, size) in (
        (101, q2_name, q2),
        (103, q4_name, q4),
    ):
        rows.append(
            {
                "digest": f"sha256:{digest}",
                "expired": False,
                "id": identifier,
                "name": name,
                "size_in_bytes": size,
                "workflow_run": {
                    "head_sha": lineage.workflow_head_sha,
                    "id": lineage.provider_run_id,
                },
            }
        )
    return json.dumps({"artifacts": rows, "total_count": 2}).encode()


def _fake_case(
    trace: object,
    strategy: str,
    shard: str,
    *,
    nonempty_auxiliary_segment: bool = True,
) -> SimpleNamespace:
    structural = canonical_route_a_document(
        {
            "ciphertext_input_multiplicities_by_role": {"input": 2},
            "execution_kind": "strong" if "packed-coo" in strategy else "ordinary",
            "mechanism_coverage": {
                "actual_overlap_contributor_group": True,
                "f1m_random_mask_path": True,
                "nonempty_auxiliary_segment": nonempty_auxiliary_segment,
                "padding_or_tombstone_replacement": False,
            },
            "ordered_operation_types": ["EvalMult"],
            "result_ciphertext_count": 1,
            "schema_version": "dynamic-cssc-route-a-native-structural-vector-v1",
        }
    )
    case_binding = canonical_route_a_document(
        {
            "scale": trace.scale,
            "schema_version": "test-case-binding-v1",
            "shard": shard,
            "strategy": strategy,
        }
    )
    return SimpleNamespace(
        trace=trace,
        strategy_candidate_id=strategy,
        shard_identity_sha256=shard,
        structural_vector_bytes=structural,
        structural_vector_sha256=hashlib.sha256(structural).hexdigest(),
        case_binding_bytes=case_binding,
        case_binding_sha256=hashlib.sha256(case_binding).hexdigest(),
    )


def _patch_q5_inputs(
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    *,
    probe_nonempty_auxiliary_segment: bool = True,
    scientific_profile: RouteAScientificProfile = PREDECESSOR_ROUTE_A_PROFILE,
) -> tuple[SimpleNamespace, str]:
    if scientific_profile is PREDECESSOR_ROUTE_A_PROFILE:
        trace = generate_route_a_qualification_trace(
            scale="M",
            qualification_seed=scientific_profile.qualification_seed,
        )
        shard = route_a_synthetic_shard_identity(trace, lineage)
    else:
        trace = generate_route_a_qualification_trace(
            scale="M",
            qualification_seed=scientific_profile.qualification_seed,
            scientific_profile=scientific_profile,
        )
        shard = route_a_synthetic_shard_identity(
            trace,
            lineage,
            scientific_profile=scientific_profile,
        )
    expected_case = _fake_case(
        trace,
        "packed-coo-cloud-segmented-delta/segment-width=128",
        shard,
        nonempty_auxiliary_segment=probe_nonempty_auxiliary_segment,
    )

    def compile_case(
        trace: object,
        *,
        strategy_candidate_id: str,
        shard_identity_sha256: str,
        **_kwargs: object,
    ) -> SimpleNamespace:
        return _fake_case(
            trace,
            strategy_candidate_id,
            shard_identity_sha256,
            nonempty_auxiliary_segment=probe_nonempty_auxiliary_segment,
        )

    monkeypatch.setattr(guard_module, "compile_route_a_terminal_native_case", compile_case)
    monkeypatch.setattr(
        guard_module,
        "inspect_route_a_qualification_stage_artifact",
        lambda root, **_kwargs: SimpleNamespace(payload_path=root / "payload.bin"),
    )
    cell = SimpleNamespace(
        document={
            "identity": {
                "formal_seed_or_null": scientific_profile.qualification_seed,
                "rho": "1",
                "shard_identity_sha256": shard,
                "strategy_candidate_id": (
                    "packed-coo-cloud-segmented-delta/segment-width=128"
                ),
            }
        },
        sha256="4" * 64,
    )
    monkeypatch.setattr(
        guard_module,
        "inspect_route_a_synthetic_suite_replay",
        lambda *_args, **_kwargs: SimpleNamespace(
            final_cells=(cell,),
            guard_receipts=(b"guard",) * 9,
            shard_identity_sha256=shard,
        ),
    )
    native_guard = canonical_route_a_document(
        {
            "accepted": True,
            "mechanism_coverage": {
                "actual_overlap_contributor_group": True,
                "f1m_random_mask_path": True,
                "nonempty_auxiliary_segment": True,
                "padding_or_tombstone_replacement": False,
            },
        }
    )
    monkeypatch.setattr(
        guard_module,
        "inspect_route_a_native_qualification_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(
            case_binding_bytes=expected_case.case_binding_bytes,
            guard_receipt_bytes=native_guard,
            input_q3_manifest_sha256="5" * 64,
            structural_vector_bytes=expected_case.structural_vector_bytes,
        ),
    )
    return expected_case, shard


def test_q5_closes_provider_wrappers_functional_guard_and_six_formal_vectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q5").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    (repository / "config").mkdir()
    (repository / "config/route-a-publication-plan.json").write_bytes(PLAN_BYTES)
    q2_wrapper = (tmp_path / "q2.zip").resolve()
    q4_wrapper = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_wrapper, {"payload.bin": b"q2"})
    q4 = _wrapper(q4_wrapper, {"payload.bin": b"q4"})
    provider_path = (tmp_path / "artifacts.json").resolve()
    provider_path.write_bytes(_provider_json(lineage=lineage, q2=q2, q4=q4))
    _patch_q5_inputs(monkeypatch, lineage)

    inspection = produce_route_a_combined_guard(
        repository_root=repository,
        lineage=lineage,
        provider_artifacts_json_path=provider_path,
        q2_wrapper_path=q2_wrapper,
        q4_wrapper_path=q4_wrapper,
        scratch_parent=scratch,
        output_directory=output,
    )

    assert inspection.q2_provider.database_id == 101
    assert inspection.q4_provider.database_id == 103
    formal = json.loads(inspection.formal_structural_vectors_bytes)
    assert len(formal["cases"]) == 6
    assert formal["componentwise_relations_are_runtime_theorems"] is False
    combined_guard = json.loads(inspection.combined_guard_bytes)
    assert "completedAt" not in combined_guard
    assert "conclusion" not in combined_guard
    assert not tuple(scratch.iterdir())


def test_q5_rejects_provider_digest_that_differs_from_downloaded_wrapper(
    tmp_path: Path,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    q2_path = (tmp_path / "q2.zip").resolve()
    q4_path = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_path, {"a": b"q2"})
    q4 = _wrapper(q4_path, {"a": b"q4"})
    provider = json.loads(_provider_json(lineage=lineage, q2=q2, q4=q4))
    provider["artifacts"][0]["digest"] = "sha256:" + "f" * 64

    with pytest.raises(RouteACombinedGuardError, match="differs from wrapper"):
        guard_module._provider_bindings(  # noqa: SLF001
            json.dumps(provider).encode(),
            expected_head_sha=lineage.workflow_head_sha,
            expected_run_id=lineage.provider_run_id,
            wrapper_paths={
                "q2-simulator-guarded-receipt": q2_path,
                "q4-native-guarded-case-bundle": q4_path,
            },
        )


def test_q5_rejects_provider_artifact_from_another_run(
    tmp_path: Path,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    q2_path = (tmp_path / "q2.zip").resolve()
    q4_path = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_path, {"a": b"q2"})
    q4 = _wrapper(q4_path, {"a": b"q4"})
    provider = json.loads(_provider_json(lineage=lineage, q2=q2, q4=q4))
    provider["artifacts"][0]["workflow_run"]["id"] = lineage.provider_run_id + 1

    with pytest.raises(RouteACombinedGuardError, match="differs from wrapper"):
        guard_module._provider_bindings(  # noqa: SLF001
            json.dumps(provider).encode(),
            expected_head_sha=lineage.workflow_head_sha,
            expected_run_id=lineage.provider_run_id,
            wrapper_paths={
                "q2-simulator-guarded-receipt": q2_path,
                "q4-native-guarded-case-bundle": q4_path,
            },
        )


def test_q5_rejects_traversal_before_extracting_any_member(tmp_path: Path) -> None:
    wrapper = (tmp_path / "unsafe.zip").resolve()
    _wrapper(wrapper, {"../escape": b"unsafe"})
    output = (tmp_path / "extracted").resolve()

    with pytest.raises(RouteACombinedGuardError, match="unsafe path"):
        guard_module._extract_provider_wrapper(wrapper, output)  # noqa: SLF001

    assert not output.exists()
    assert not (tmp_path / "escape").exists()


def test_q5_mechanism_screen_rejects_a_formal_class_absent_from_probe() -> None:
    formal = canonical_route_a_document(
        {
            "cases": [
                {
                    "structural_vector": {
                        "mechanism_coverage": {
                            "actual_overlap_contributor_group": True,
                            "f1m_random_mask_path": True,
                            "nonempty_auxiliary_segment": True,
                            "padding_or_tombstone_replacement": False,
                        }
                    }
                }
            ],
            "schema_version": "dynamic-cssc-route-a-structural-comparability-set-v1",
        }
    )
    probe = canonical_route_a_document(
        {
            "case": {
                "structural_vector": {
                    "mechanism_coverage": {
                        "actual_overlap_contributor_group": True,
                        "f1m_random_mask_path": True,
                        "nonempty_auxiliary_segment": False,
                        "padding_or_tombstone_replacement": False,
                    }
                }
            },
            "schema_version": "dynamic-cssc-route-a-probe-structural-record-v1",
        }
    )

    missing = guard_module._mechanism_classes(formal) - guard_module._mechanism_classes(  # noqa: SLF001
        probe
    )

    assert missing == {"nonempty_auxiliary_segment"}


def test_q5_producer_rejects_a_formal_mechanism_absent_from_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q5").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    (repository / "config").mkdir()
    (repository / "config/route-a-publication-plan.json").write_bytes(PLAN_BYTES)
    q2_wrapper = (tmp_path / "q2.zip").resolve()
    q4_wrapper = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_wrapper, {"payload.bin": b"q2"})
    q4 = _wrapper(q4_wrapper, {"payload.bin": b"q4"})
    provider_path = (tmp_path / "artifacts.json").resolve()
    provider_path.write_bytes(_provider_json(lineage=lineage, q2=q2, q4=q4))
    _patch_q5_inputs(
        monkeypatch,
        lineage,
        probe_nonempty_auxiliary_segment=False,
    )
    formal = canonical_route_a_document(
        {
            "cases": [
                {
                    "structural_vector": {
                        "mechanism_coverage": {
                            "actual_overlap_contributor_group": True,
                            "f1m_random_mask_path": True,
                            "nonempty_auxiliary_segment": True,
                            "padding_or_tombstone_replacement": False,
                        },
                        "ordered_operation_types": ["EvalMult"],
                    }
                }
            ],
            "schema_version": (
                "dynamic-cssc-route-a-structural-comparability-set-v1"
            ),
        }
    )
    monkeypatch.setattr(guard_module, "_formal_structural_set", lambda _plan: formal)

    with pytest.raises(RouteACombinedGuardError, match="mechanism class is absent"):
        produce_route_a_combined_guard(
            repository_root=repository,
            lineage=lineage,
            provider_artifacts_json_path=provider_path,
            q2_wrapper_path=q2_wrapper,
            q4_wrapper_path=q4_wrapper,
            scratch_parent=scratch,
            output_directory=output,
        )

    assert not output.exists()
    assert not tuple(scratch.iterdir())


def test_q5_inspector_recomputes_formal_vectors_after_self_rehash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q5").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    (repository / "config").mkdir()
    (repository / "config/route-a-publication-plan.json").write_bytes(PLAN_BYTES)
    q2_path = (tmp_path / "q2.zip").resolve()
    q4_path = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_path, {"payload.bin": b"q2"})
    q4 = _wrapper(q4_path, {"payload.bin": b"q4"})
    provider_path = (tmp_path / "provider.json").resolve()
    provider_path.write_bytes(_provider_json(lineage=lineage, q2=q2, q4=q4))
    _patch_q5_inputs(monkeypatch, lineage)
    produced = produce_route_a_combined_guard(
        repository_root=repository,
        lineage=lineage,
        provider_artifacts_json_path=provider_path,
        q2_wrapper_path=q2_path,
        q4_wrapper_path=q4_path,
        scratch_parent=scratch,
        output_directory=output,
    )
    formal_path = output / "formal-structural-vectors.json"
    formal = json.loads(formal_path.read_bytes())
    formal["cases"][0]["scale"] = "M" if formal["cases"][0]["scale"] == "S" else "S"
    formal_path.chmod(0o600)
    formal_path.write_bytes(canonical_route_a_document(formal))
    members = guard_module._artifact_members(output, omit_control=True)  # noqa: SLF001
    manifest = guard_module._manifest(  # noqa: SLF001
        lineage=lineage,
        q2=produced.q2_provider,
        q4=produced.q4_provider,
        members=members,
    )
    for path, content in (
        (output / "manifest.json", manifest),
        (output / "checksums.sha256", guard_module._checksums(members, manifest)),  # noqa: SLF001
    ):
        path.chmod(0o600)
        path.write_bytes(content)

    with pytest.raises(RouteACombinedGuardError, match="retained record"):
        inspect_route_a_combined_guard_artifact(
            output,
            expected_lineage=lineage,
            machine_plan_bytes=PLAN_BYTES,
        )


def test_q5_followup_mode_closes_outer_wrappers_and_profile_specific_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q5").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    q2_name = "followup-performance-v1-qualification-q2-sentinel"
    q4_name = "followup-performance-v1-qualification-q4-sentinel"
    q2_wrapper = (tmp_path / "q2.zip").resolve()
    q4_wrapper = (tmp_path / "q4.zip").resolve()
    q2 = _wrapper(q2_wrapper, {"inner/payload.bin": b"q2"})
    q4 = _wrapper(q4_wrapper, {"inner/payload.bin": b"q4"})
    provider_path = (tmp_path / "artifacts.json").resolve()
    provider_path.write_bytes(
        _provider_json(
            lineage=lineage,
            q2=q2,
            q4=q4,
            q2_name=q2_name,
            q4_name=q4_name,
        )
    )
    profile = RouteAScientificProfile(
        profile_id="q5-followup-sentinel",
        qualification_seed=91_101,
        formal_seeds=(91_102, 91_103, 91_104),
        query_vector_seed=9_110_202,
        machine_plan_sha256=hashlib.sha256(PLAN_BYTES).hexdigest(),
    )
    _patch_q5_inputs(monkeypatch, lineage, scientific_profile=profile)
    observed_stages: list[str] = []

    def inspect_outer(root: Path, *, stage: str, **_kwargs: object) -> SimpleNamespace:
        observed_stages.append(stage)
        return SimpleNamespace(inner_directory=root / "inner")

    monkeypatch.setattr(
        "dynamic_cssc.followup_performance_artifacts.inspect_followup_qualification_artifact",
        inspect_outer,
    )

    inspection = produce_route_a_combined_guard(
        repository_root=repository,
        lineage=lineage,
        provider_artifacts_json_path=provider_path,
        q2_wrapper_path=q2_wrapper,
        q4_wrapper_path=q4_wrapper,
        scratch_parent=scratch,
        output_directory=output,
        scientific_profile=profile,
        machine_plan_bytes=PLAN_BYTES,
        q2_provider_name=q2_name,
        q4_provider_name=q4_name,
        followup_outer_wrappers=True,
    )

    assert observed_stages == ["q2", "q4"]
    assert inspection.q2_provider.name == q2_name
    assert inspection.q4_provider.name == q4_name
