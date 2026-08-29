from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.route_a_native_suite as suite_module
from dynamic_cssc.route_a_native_case import compile_route_a_terminal_native_case
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationError,
    inspect_route_a_native_qualification_artifact,
    produce_route_a_native_qualification_handoff,
    replay_and_guard_route_a_native_qualification,
)
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

ROOT = Path(__file__).resolve().parents[1]
PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
SHARD = "1" * 64
BUILD = "2" * 64


@pytest.fixture(scope="module")
def lineage() -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha="3" * 40,
        workflow_head_sha="4" * 40,
        compatibility_receipt_sha256="5" * 64,
        provider_run_id=17,
        provider_run_attempt=1,
    )


@pytest.fixture(scope="module")
def case():  # type: ignore[no-untyped-def]
    return compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id="periodic-repack/windows=1",
        shard_identity_sha256=SHARD,
        unit_attempt_ordinal=0,
        machine_plan_bytes=PLAN_BYTES,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _process_row(
    *,
    ordinal: int,
    lane_digit: str,
    warmup: bool = False,
    request_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "elapsed_ns": 1,
        "execution_process_role": "openfhe-warmup" if warmup else "openfhe-recorded",
        "lane_sha256": lane_digit * 64,
        "peak_resident_memory_bytes": 2,
        "peak_scratch_bytes": 3,
        "process_ordinal_or_null": ordinal,
        "request_sha256": request_sha256 or lane_digit * 64,
        "runner_build_identity_sha256": "b" * 64,
    }


def _guard_document(case: object, structural: bytes) -> dict[str, object]:
    packages = [str(ordinal) * 64 for ordinal in range(3)]
    return {
        "accepted": True,
        "authority_granted": False,
        "build_manifest_sha256": BUILD,
        "case_binding_sha256": hashlib.sha256(
            case.case_binding_bytes  # type: ignore[attr-defined]
        ).hexdigest(),
        "cloud_program_operation_inventory": {},
        "crypto_context_parameter_sha256": "c" * 64,
        "freshness_checks": {
            "evaluation_key_frame_roots_pairwise_distinct": True,
            "input_ciphertext_roots_pairwise_distinct": True,
            "producer_result_ciphertext_roots_pairwise_distinct": True,
            "public_key_roots_pairwise_distinct": True,
            "secret_key_roots_pairwise_distinct": True,
        },
        "lane_binding_sha256s": ["d" * 64, "e" * 64, "f" * 64],
        "mechanism_coverage": {
            "actual_overlap_contributor_group": True,
            "f1m_random_mask_path": True,
            "nonempty_auxiliary_segment": True,
            "padding_or_tombstone_replacement": False,
        },
        "native_resource_observations": [
            {
                "elapsed_ns": 1,
                "peak_resident_memory_bytes": 2,
                "peak_scratch_bytes": 3,
                "process_ordinal": ordinal,
            }
            for ordinal in range(3)
        ],
        "package_manifest_sha256s": packages,
        "process_ordinals": [0, 1, 2],
        "publication_evidence": False,
        "runner_build_identity_sha256": "b" * 64,
        "schema_version": "dynamic-cssc-route-a-native-three-replay-guard-v1",
        "structural_vector_sha256": hashlib.sha256(structural).hexdigest(),
    }


def _package(root: Path, case: object, ordinal: int) -> None:
    case_binding = case.case_binding_bytes  # type: ignore[attr-defined]
    structural = case.structural_vector_bytes  # type: ignore[attr-defined]
    lane = canonical_route_a_document(
        {
            "case_binding_sha256": hashlib.sha256(case_binding).hexdigest(),
            "execution_process_role": "openfhe-recorded",
            "process_ordinal": ordinal,
            "query_id": f"query-{ordinal}",
            "schema_version": "dynamic-cssc-route-a-native-package-lane-binding-v1",
            "shard_identity_sha256": SHARD,
            "strategy_candidate_id": "periodic-repack/windows=1",
            "unit_attempt_ordinal": 0,
        }
    )
    values = (
        ("authorization-receipt", "authorization-receipt", b"authorization"),
        ("canonical-request", "canonical-request", f"request-{ordinal}".encode()),
        ("case-binding", "case-binding", case_binding),
        ("consumed-ledger", "consumed-ledger", b"SQLite format 3\x00ledger"),
        ("crypto-context", "crypto-context", b"context"),
        ("direct-oracle", "direct-oracle", b"direct"),
        ("evaluation-key-frame", "evaluation-key-material", b"D1BKEY01frame"),
        ("lane-binding", "lane-binding", lane),
        ("preparation", "preparation", b"preparation"),
        ("producer-result", "producer-result", b"producer-result"),
        ("public-key", "public-key", f"public-{ordinal}".encode()),
        ("secret-key", "secret-key", f"secret-{ordinal}".encode()),
        ("structural-vector", "structural-vector", structural),
        ("typed-oracle", "typed-oracle", b"typed"),
        ("input-ciphertext", "input-0", f"input-{ordinal}".encode()),
        (
            "producer-result-ciphertext",
            "result-0",
            f"result-{ordinal}".encode(),
        ),
    )
    root.mkdir(parents=True)
    members = []
    for index, (role, subject, content) in enumerate(values):
        path = f"member-{index:06d}.bin"
        (root / path).write_bytes(content)
        members.append(
            {
                "byte_count": len(content),
                "relative_path": path,
                "role": role,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": subject,
            }
        )
    (root / "manifest.json").write_bytes(
        _canonical(
            {
                "build_manifest_sha256": BUILD,
                "case_binding_sha256": hashlib.sha256(case_binding).hexdigest(),
                "formal_authority_granted": False,
                "lane_binding_sha256": hashlib.sha256(lane).hexdigest(),
                "members": members,
                "publication_authority": False,
                "schema_version": "dynamic-cssc-route-a-native-package-manifest-v1",
            }
        )
    )


def _install_control_files(
    root: Path,
    *,
    stage: str,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    members = suite_module._tree_members(root, omit_control=True)  # noqa: SLF001
    manifest = suite_module._manifest(  # noqa: SLF001
        stage=stage,
        lineage=lineage,
        case=case,
        build_manifest_sha256=BUILD,
        input_q3_manifest_sha256=None if stage == "q3" else "a" * 64,
        members=members,
    )
    (root / "manifest.json").write_bytes(manifest)
    (root / "checksums.sha256").write_bytes(
        suite_module._checksums(members, manifest)  # noqa: SLF001
    )


def test_q3_inspector_closes_build_warmup_and_exact_three_packages(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    root = (tmp_path / "q3").resolve()
    root.mkdir()
    (root / "build-package.zip").write_bytes(b"build-package")
    (root / "lineage.json").write_bytes(lineage.document_bytes)
    (root / "case-binding.json").write_bytes(case.case_binding_bytes)  # type: ignore[attr-defined]
    (root / "structural-vector.json").write_bytes(  # type: ignore[attr-defined]
        case.structural_vector_bytes
    )
    process_rows = [
        _process_row(ordinal=0, lane_digit="1", warmup=True),
        _process_row(
            ordinal=0,
            lane_digit="2",
            request_sha256=hashlib.sha256(b"request-0").hexdigest(),
        ),
        _process_row(
            ordinal=1,
            lane_digit="3",
            request_sha256=hashlib.sha256(b"request-1").hexdigest(),
        ),
        _process_row(
            ordinal=2,
            lane_digit="4",
            request_sha256=hashlib.sha256(b"request-2").hexdigest(),
        ),
    ]
    (root / "warmup-receipt.json").write_bytes(
        canonical_route_a_document(
            {
                **process_rows[0],
                "authority_granted": False,
                "package_retained": False,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-warmup-receipt-v1",
            }
        )
    )
    (root / "stage-ledger.json").write_bytes(
        canonical_route_a_document(
            {
                "authority_granted": False,
                "elapsed_ns": 4,
                "processes": process_rows,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-stage-ledger-v1",
                "stage": "q3",
            }
        )
    )
    for ordinal in range(3):
        _package(root / f"packages/recorded-{ordinal}", case, ordinal)
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_build",
        lambda path: SimpleNamespace(manifest_sha256=BUILD, archive_path=path),
    )
    _install_control_files(root, stage="q3", lineage=lineage, case=case)

    inspection = inspect_route_a_native_qualification_artifact(
        root,
        expected_stage="q3",
        expected_lineage=lineage,
    )

    assert len(inspection.packages) == 3
    assert inspection.build_manifest_sha256 == BUILD
    assert inspection.input_q3_manifest_sha256 is None

    warmup_path = root / "warmup-receipt.json"
    truncated = json.loads(warmup_path.read_bytes())
    truncated.pop("request_sha256")
    warmup_path.write_bytes(canonical_route_a_document(truncated))
    _install_control_files(root, stage="q3", lineage=lineage, case=case)
    with pytest.raises(RouteANativeQualificationError, match="warm-up receipt"):
        inspect_route_a_native_qualification_artifact(
            root,
            expected_stage="q3",
            expected_lineage=lineage,
        )


def test_q3_inspector_rejects_self_rehashed_stage_ledger_request_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    root = (tmp_path / "q3-request-mismatch").resolve()
    root.mkdir()
    (root / "build-package.zip").write_bytes(b"build-package")
    (root / "lineage.json").write_bytes(lineage.document_bytes)
    (root / "case-binding.json").write_bytes(case.case_binding_bytes)  # type: ignore[attr-defined]
    (root / "structural-vector.json").write_bytes(  # type: ignore[attr-defined]
        case.structural_vector_bytes
    )
    process_rows = [
        _process_row(ordinal=0, lane_digit="1", warmup=True),
        _process_row(ordinal=0, lane_digit="2", request_sha256="6" * 64),
        _process_row(
            ordinal=1,
            lane_digit="3",
            request_sha256=hashlib.sha256(b"request-1").hexdigest(),
        ),
        _process_row(
            ordinal=2,
            lane_digit="4",
            request_sha256=hashlib.sha256(b"request-2").hexdigest(),
        ),
    ]
    (root / "warmup-receipt.json").write_bytes(
        canonical_route_a_document(
            {
                **process_rows[0],
                "authority_granted": False,
                "package_retained": False,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-warmup-receipt-v1",
            }
        )
    )
    (root / "stage-ledger.json").write_bytes(
        canonical_route_a_document(
            {
                "authority_granted": False,
                "elapsed_ns": 4,
                "processes": process_rows,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-stage-ledger-v1",
                "stage": "q3",
            }
        )
    )
    for ordinal in range(3):
        _package(root / f"packages/recorded-{ordinal}", case, ordinal)
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_build",
        lambda path: SimpleNamespace(manifest_sha256=BUILD, archive_path=path),
    )
    _install_control_files(root, stage="q3", lineage=lineage, case=case)

    with pytest.raises(RouteANativeQualificationError, match="warm-up receipt"):
        inspect_route_a_native_qualification_artifact(
            root,
            expected_stage="q3",
            expected_lineage=lineage,
        )


def test_q4_inspector_rejects_an_extra_self_rehashed_replay(
    tmp_path: Path,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    root = (tmp_path / "q4").resolve()
    root.mkdir()
    (root / "lineage.json").write_bytes(lineage.document_bytes)
    (root / "case-binding.json").write_bytes(case.case_binding_bytes)  # type: ignore[attr-defined]
    structural = case.structural_vector_bytes  # type: ignore[attr-defined]
    (root / "structural-vector.json").write_bytes(structural)
    package_digests = [str(ordinal) * 64 for ordinal in range(3)]
    (root / "native-guard.json").write_bytes(
        canonical_route_a_document(_guard_document(case, structural))
    )
    for ordinal in range(3):
        (root / "replays").mkdir(exist_ok=True)
        (root / f"replays/recorded-{ordinal}.json").write_bytes(
            canonical_route_a_document(
                {
                    "authority_granted": False,
                    "cloud_program_operation_inventory": {},
                    "elapsed_ns": 1,
                    "lane_sha256": str(ordinal + 6) * 64,
                    "lifecycle_operation_inventory": {},
                    "package_manifest_sha256": str(min(ordinal, 2)) * 64,
                    "peak_resident_memory_bytes": 2,
                    "peak_scratch_bytes": 3,
                    "preparation_sha256": "a" * 64,
                    "producer_request_sha256": str(ordinal) * 64,
                    "publication_evidence": False,
                    "reconstructed_output_sha256": "c" * 64,
                    "replay_request_sha256": str(ordinal) * 64,
                    "runner_build_identity_sha256": "b" * 64,
                    "schema_version": "dynamic-cssc-route-a-native-replay-receipt-v1",
                }
            )
        )
    (root / "stage-ledger.json").write_bytes(
        canonical_route_a_document(
            {
                "authority_granted": False,
                "elapsed_ns": 4,
                "package_manifest_sha256s": package_digests,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-stage-ledger-v1",
                "stage": "q4",
            }
        )
    )
    _install_control_files(root, stage="q4", lineage=lineage, case=case)

    inspection = inspect_route_a_native_qualification_artifact(
        root,
        expected_stage="q4",
        expected_lineage=lineage,
    )
    assert inspection.input_q3_manifest_sha256 == "a" * 64

    (root / "replays/recorded-3.json").write_bytes(
        canonical_route_a_document(
            {
                "authority_granted": False,
                "cloud_program_operation_inventory": {},
                "elapsed_ns": 1,
                "lane_sha256": "9" * 64,
                "lifecycle_operation_inventory": {},
                "package_manifest_sha256": "2" * 64,
                "peak_resident_memory_bytes": 2,
                "peak_scratch_bytes": 3,
                "preparation_sha256": "a" * 64,
                "producer_request_sha256": "9" * 64,
                "publication_evidence": False,
                "reconstructed_output_sha256": "c" * 64,
                "replay_request_sha256": "9" * 64,
                "runner_build_identity_sha256": "b" * 64,
                "schema_version": "dynamic-cssc-route-a-native-replay-receipt-v1",
            }
        )
    )
    _install_control_files(root, stage="q4", lineage=lineage, case=case)

    with pytest.raises(RouteANativeQualificationError, match="replay receipt set"):
        inspect_route_a_native_qualification_artifact(
            root,
            expected_stage="q4",
            expected_lineage=lineage,
        )


def test_q4_inspector_rejects_a_self_rehashed_request_mismatch(
    tmp_path: Path,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    root = (tmp_path / "q4-mismatched-request").resolve()
    root.mkdir()
    (root / "lineage.json").write_bytes(lineage.document_bytes)
    (root / "case-binding.json").write_bytes(case.case_binding_bytes)  # type: ignore[attr-defined]
    structural = case.structural_vector_bytes  # type: ignore[attr-defined]
    (root / "structural-vector.json").write_bytes(structural)
    package_digests = [str(ordinal) * 64 for ordinal in range(3)]
    (root / "native-guard.json").write_bytes(
        canonical_route_a_document(_guard_document(case, structural))
    )
    (root / "replays").mkdir()
    for ordinal in range(3):
        producer_request = str(ordinal) * 64
        replay_request = "e" * 64 if ordinal == 1 else producer_request
        (root / f"replays/recorded-{ordinal}.json").write_bytes(
            canonical_route_a_document(
                {
                    "authority_granted": False,
                    "cloud_program_operation_inventory": {},
                    "elapsed_ns": 1,
                    "lane_sha256": str(ordinal + 6) * 64,
                    "lifecycle_operation_inventory": {},
                    "package_manifest_sha256": str(ordinal) * 64,
                    "peak_resident_memory_bytes": 2,
                    "peak_scratch_bytes": 3,
                    "preparation_sha256": "a" * 64,
                    "producer_request_sha256": producer_request,
                    "publication_evidence": False,
                    "reconstructed_output_sha256": "c" * 64,
                    "replay_request_sha256": replay_request,
                    "runner_build_identity_sha256": "b" * 64,
                    "schema_version": "dynamic-cssc-route-a-native-replay-receipt-v1",
                }
            )
        )
    (root / "stage-ledger.json").write_bytes(
        canonical_route_a_document(
            {
                "authority_granted": False,
                "elapsed_ns": 4,
                "package_manifest_sha256s": package_digests,
                "publication_evidence": False,
                "schema_version": "dynamic-cssc-route-a-native-stage-ledger-v1",
                "stage": "q4",
            }
        )
    )
    _install_control_files(root, stage="q4", lineage=lineage, case=case)

    with pytest.raises(RouteANativeQualificationError, match="replay receipt binding"):
        inspect_route_a_native_qualification_artifact(
            root,
            expected_stage="q4",
            expected_lineage=lineage,
        )


def _fake_producer_execution(lane: object, retained: object | None) -> SimpleNamespace:
    return SimpleNamespace(
        lane=lane,
        runner_identity=SimpleNamespace(build_identity_sha256="b" * 64),
        process_observation=SimpleNamespace(
            elapsed_ns=1,
            peak_resident_memory_bytes=2,
            peak_scratch_bytes=3,
        ),
        verified_result=SimpleNamespace(request_sha256=lane.sha256),
        retained_package=retained,
    )


def _patch_q3_runtime(
    monkeypatch: pytest.MonkeyPatch,
    case: object,
    observed_ordinals: list[int | None],
    *,
    fail_at: int | None = None,
    retain_warmup: bool = False,
) -> None:
    monkeypatch.setattr(suite_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(suite_module, "_case", lambda *_args: case)

    def build(*_args: object, output_path: Path, **_kwargs: object) -> SimpleNamespace:
        output_path.write_bytes(b"build")
        return SimpleNamespace(manifest_sha256=BUILD)

    monkeypatch.setattr(suite_module, "produce_route_a_native_build", build)
    monkeypatch.setattr(
        suite_module,
        "prepare_route_a_native_invocation",
        lambda _case, lane, **_kwargs: lane,
    )
    monkeypatch.setattr(
        suite_module,
        "authorize_route_a_native_invocation",
        lambda lane, **_kwargs: lane,
    )

    def execute(lane: object, **kwargs: object) -> SimpleNamespace:
        ordinal = lane.process_ordinal_or_null  # type: ignore[attr-defined]
        observed_ordinals.append(ordinal)
        if fail_at == ordinal:
            raise RouteANativeQualificationError("injected producer failure")
        retained_directory = kwargs["retained_package_directory"]
        retained = None
        if retained_directory is not None:
            assert isinstance(retained_directory, Path)
            retained_directory.mkdir(parents=True)
            (retained_directory / "payload.bin").write_bytes(b"package")
            retained = SimpleNamespace()
        elif retain_warmup:
            retained = SimpleNamespace()
        return _fake_producer_execution(lane, retained)

    monkeypatch.setattr(suite_module, "execute_route_a_native_producer", execute)


def test_q3_orchestrates_warmup_then_three_recorded_lanes_and_cleans_private_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q3").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    observed: list[int | None] = []
    _patch_q3_runtime(monkeypatch, case, observed)
    result = SimpleNamespace(stage="q3")
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_qualification_artifact",
        lambda *_args, **_kwargs: result,
    )

    returned = produce_route_a_native_qualification_handoff(
        repository_root=repository,
        lineage=lineage,
        scratch_parent=scratch,
        output_directory=output,
    )

    assert returned is result
    assert observed == [0, 0, 1, 2]
    assert output.is_dir()
    assert not tuple(scratch.iterdir())


def test_q3_refuses_retained_warmup_and_removes_every_partial_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q3").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    _patch_q3_runtime(monkeypatch, case, [], retain_warmup=True)

    with pytest.raises(RouteANativeQualificationError, match="warm-up retention"):
        produce_route_a_native_qualification_handoff(
            repository_root=repository,
            lineage=lineage,
            scratch_parent=scratch,
            output_directory=output,
        )

    assert not output.exists()
    assert not tuple(output.parent.iterdir())
    assert not tuple(scratch.iterdir())


def test_q3_mid_sequence_failure_removes_output_and_private_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    output = (tmp_path / "out/q3").resolve()
    repository.mkdir()
    scratch.mkdir()
    output.parent.mkdir()
    observed: list[int | None] = []
    _patch_q3_runtime(monkeypatch, case, observed, fail_at=2)

    with pytest.raises(RouteANativeQualificationError, match="injected"):
        produce_route_a_native_qualification_handoff(
            repository_root=repository,
            lineage=lineage,
            scratch_parent=scratch,
            output_directory=output,
        )

    assert observed == [0, 0, 1, 2]
    assert not output.exists()
    assert not tuple(output.parent.iterdir())
    assert not tuple(scratch.iterdir())


def test_q4_rejects_wrong_expected_q3_address_before_case_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    q3_root = (tmp_path / "q3").resolve()
    output = (tmp_path / "out/q4").resolve()
    for directory in (repository, scratch, q3_root, output.parent):
        directory.mkdir()
    monkeypatch.setattr(suite_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_qualification_artifact",
        lambda *_args, **_kwargs: SimpleNamespace(manifest_sha256="1" * 64),
    )
    monkeypatch.setattr(
        suite_module,
        "_case",
        lambda *_args: pytest.fail("case compilation must follow the q3 address gate"),
    )

    with pytest.raises(RouteANativeQualificationError, match="stage-manifest address"):
        replay_and_guard_route_a_native_qualification(
            repository_root=repository,
            lineage=lineage,
            q3_artifact_directory=q3_root,
            scratch_parent=scratch,
            output_directory=output,
            expected_q3_manifest_sha256="2" * 64,
        )


def test_q4_rejects_case_mismatch_before_installing_or_probing_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    q3_root = (tmp_path / "q3").resolve()
    output = (tmp_path / "out/q4").resolve()
    for directory in (repository, scratch, q3_root, output.parent):
        directory.mkdir()
    monkeypatch.setattr(suite_module.platform, "system", lambda: "Linux")
    q3 = SimpleNamespace(
        manifest_sha256="1" * 64,
        case_binding_sha256="2" * 64,
        build_archive=q3_root / "build-package.zip",
    )
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_qualification_artifact",
        lambda *_args, **_kwargs: q3,
    )
    monkeypatch.setattr(suite_module, "_case", lambda *_args: case)
    monkeypatch.setattr(
        suite_module,
        "install_route_a_native_build",
        lambda *_args, **_kwargs: pytest.fail("build probes must follow the case gate"),
    )

    with pytest.raises(RouteANativeQualificationError, match="case binding"):
        replay_and_guard_route_a_native_qualification(
            repository_root=repository,
            lineage=lineage,
            q3_artifact_directory=q3_root,
            scratch_parent=scratch,
            output_directory=output,
            expected_q3_manifest_sha256="1" * 64,
        )


def _patch_q4_runtime(
    monkeypatch: pytest.MonkeyPatch,
    case: object,
    q3: object,
    final_result: object,
    observed_ordinals: list[int],
    *,
    fail_at: int | None = None,
) -> None:
    monkeypatch.setattr(suite_module.platform, "system", lambda: "Linux")
    inspections = iter((q3, final_result))
    monkeypatch.setattr(
        suite_module,
        "inspect_route_a_native_qualification_artifact",
        lambda *_args, **_kwargs: next(inspections),
    )
    monkeypatch.setattr(suite_module, "_case", lambda *_args: case)
    monkeypatch.setattr(
        suite_module,
        "install_route_a_native_build",
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                manifest_sha256=BUILD,
                runner_relative_path="build/cpp/openfhe_query_runner",
            ),
            SimpleNamespace(),
        ),
    )

    def execute(_case: object, lane: object, **_kwargs: object) -> SimpleNamespace:
        ordinal = lane.process_ordinal_or_null  # type: ignore[attr-defined]
        assert type(ordinal) is int
        observed_ordinals.append(ordinal)
        if ordinal == fail_at:
            raise RouteANativeQualificationError("injected replay failure")
        return SimpleNamespace(ordinal=ordinal)

    monkeypatch.setattr(suite_module, "execute_route_a_native_replay", execute)
    monkeypatch.setattr(
        suite_module,
        "_replay_receipt",
        lambda execution: canonical_route_a_document(
            {
                "ordinal": execution.ordinal,
                "schema_version": "test-replay-receipt",
            }
        ),
    )
    monkeypatch.setattr(
        suite_module,
        "guard_route_a_native_replays",
        lambda _case, executions: SimpleNamespace(
            receipt_bytes=canonical_route_a_document(
                {
                    "accepted": True,
                    "ordinals": [execution.ordinal for execution in executions],
                    "schema_version": "test-native-guard",
                }
            ),
            package_manifest_sha256s=("0" * 64, "1" * 64, "2" * 64),
        ),
    )


def test_q4_replays_exact_three_recorded_lanes_and_cleans_private_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    q3_root = (tmp_path / "q3").resolve()
    output = (tmp_path / "out/q4").resolve()
    for directory in (repository, scratch, q3_root, output.parent):
        directory.mkdir()
    build_archive = q3_root / "build-package.zip"
    build_archive.write_bytes(b"build")
    packages = []
    for ordinal in range(3):
        package_root = q3_root / f"package-{ordinal}"
        package_root.mkdir()
        packages.append(SimpleNamespace(package_root=package_root))
    q3 = SimpleNamespace(
        manifest_sha256="1" * 64,
        case_binding_sha256=case.case_binding_sha256,  # type: ignore[attr-defined]
        build_archive=build_archive,
        build_manifest_sha256=BUILD,
        packages=tuple(packages),
    )
    result = SimpleNamespace(stage="q4")
    observed: list[int] = []
    _patch_q4_runtime(monkeypatch, case, q3, result, observed)

    returned = replay_and_guard_route_a_native_qualification(
        repository_root=repository,
        lineage=lineage,
        q3_artifact_directory=q3_root,
        scratch_parent=scratch,
        output_directory=output,
        expected_q3_manifest_sha256="1" * 64,
    )

    assert returned is result
    assert observed == [0, 1, 2]
    assert output.is_dir()
    assert not tuple(scratch.iterdir())


def test_q4_mid_replay_failure_removes_output_and_private_scratch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lineage: RouteASyntheticSuiteLineage,
    case: object,
) -> None:
    repository = (tmp_path / "repo").resolve()
    scratch = (tmp_path / "scratch").resolve()
    q3_root = (tmp_path / "q3").resolve()
    output = (tmp_path / "out/q4").resolve()
    for directory in (repository, scratch, q3_root, output.parent):
        directory.mkdir()
    build_archive = q3_root / "build-package.zip"
    build_archive.write_bytes(b"build")
    q3 = SimpleNamespace(
        manifest_sha256="1" * 64,
        case_binding_sha256=case.case_binding_sha256,  # type: ignore[attr-defined]
        build_archive=build_archive,
        build_manifest_sha256=BUILD,
        packages=tuple(
            SimpleNamespace(package_root=q3_root / f"package-{ordinal}")
            for ordinal in range(3)
        ),
    )
    observed: list[int] = []
    _patch_q4_runtime(
        monkeypatch,
        case,
        q3,
        SimpleNamespace(stage="q4"),
        observed,
        fail_at=1,
    )

    with pytest.raises(RouteANativeQualificationError, match="injected replay"):
        replay_and_guard_route_a_native_qualification(
            repository_root=repository,
            lineage=lineage,
            q3_artifact_directory=q3_root,
            scratch_parent=scratch,
            output_directory=output,
            expected_q3_manifest_sha256="1" * 64,
        )

    assert observed == [0, 1]
    assert not output.exists()
    assert not tuple(output.parent.iterdir())
    assert not tuple(scratch.iterdir())
