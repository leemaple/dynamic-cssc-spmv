from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import stat
import zipfile
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.query_compiler as query_compiler_module
import dynamic_cssc.route_a_evaluation as evaluation_module
import dynamic_cssc.route_a_replay as replay_module
import dynamic_cssc.route_a_strategy as strategy_module
import dynamic_cssc.simulator as simulator_module
import dynamic_cssc.validation_scaling_study as study
from dynamic_cssc.route_a_results import canonical_route_a_document
from dynamic_cssc.validation_scaling_study import (
    produce_validation_scaling_seed_shard,
    replay_validation_scaling_seed_shard,
)
from scripts import run_validation_scaling_study as runner
from scripts import validate_validation_scaling_study as validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_BYTES = (REPOSITORY_ROOT / "config/validation-scaling-study.json").read_bytes()


def _empty_scratch(tmp_path: Path, name: str = "scratch") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def test_public_surface_has_exactly_two_operations() -> None:
    assert study.__all__ == (
        "produce_validation_scaling_seed_shard",
        "replay_validation_scaling_seed_shard",
    )


def test_public_operation_signatures_are_keyword_only_and_closed() -> None:
    producer = inspect.signature(produce_validation_scaling_seed_shard)
    replay = inspect.signature(replay_validation_scaling_seed_shard)
    assert tuple(producer.parameters) == ("plan_bytes", "seed_ordinal", "scratch_root")
    assert tuple(replay.parameters) == (
        "plan_bytes",
        "producer_package_bytes",
        "seed_ordinal",
        "scratch_root",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in (*producer.parameters.values(), *replay.parameters.values())
    )


@pytest.mark.parametrize("plan_bytes", [None, bytearray(PLAN_BYTES), "plan", True])
def test_public_operations_reject_nonbytes_plan_before_scratch_ownership(
    plan_bytes: object,
    tmp_path: Path,
) -> None:
    scratch = _empty_scratch(tmp_path)
    with pytest.raises(TypeError, match="plan_bytes must be exact bytes"):
        produce_validation_scaling_seed_shard(
            plan_bytes=plan_bytes,  # type: ignore[arg-type]
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert scratch.is_dir()


def test_public_operation_rejects_any_changed_plan_byte(tmp_path: Path) -> None:
    scratch = _empty_scratch(tmp_path)
    changed = PLAN_BYTES.replace(
        b'"formal_dispatch_count": 1',
        b'"formal_dispatch_count": 2',
    )
    assert changed != PLAN_BYTES
    with pytest.raises(ValueError, match="differ from the exact Stage-0 v2 plan"):
        produce_validation_scaling_seed_shard(
            plan_bytes=changed,
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert scratch.is_dir()


@pytest.mark.parametrize("ordinal", [True, False, 0, 4, -1, 1.0, "1", None])
def test_public_operation_rejects_nonregistered_ordinal_before_trace(
    ordinal: object,
    tmp_path: Path,
) -> None:
    scratch = _empty_scratch(tmp_path)
    with pytest.raises(ValueError, match="strict integer 1, 2, or 3"):
        produce_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            seed_ordinal=ordinal,  # type: ignore[arg-type]
            scratch_root=scratch,
        )
    assert scratch.is_dir()


def test_replay_rejects_nonbytes_and_empty_payload_before_scratch_ownership(
    tmp_path: Path,
) -> None:
    for ordinal, payload in enumerate((None, bytearray(b"zip"), "zip", b"")):
        scratch = _empty_scratch(tmp_path, f"scratch-{ordinal}")
        with pytest.raises((TypeError, ValueError)):
            replay_validation_scaling_seed_shard(
                plan_bytes=PLAN_BYTES,
                producer_package_bytes=payload,  # type: ignore[arg-type]
                seed_ordinal=1,
                scratch_root=scratch,
            )
        assert scratch.is_dir()


def test_replay_owns_and_destroys_scratch_after_malformed_payload(tmp_path: Path) -> None:
    scratch = _empty_scratch(tmp_path)
    with pytest.raises(ValueError, match="safe canonical ZIP"):
        replay_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            producer_package_bytes=b"not-a-zip",
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert not scratch.exists()


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o777])
def test_wrong_mode_scratch_is_rejected_without_ownership(
    mode: int,
    tmp_path: Path,
) -> None:
    scratch = _empty_scratch(tmp_path)
    scratch.chmod(mode)
    with pytest.raises(ValueError, match="direct empty mode-0700"):
        replay_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            producer_package_bytes=b"not-a-zip",
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert scratch.is_dir()


def test_nonempty_scratch_is_rejected_without_deleting_user_bytes(tmp_path: Path) -> None:
    scratch = _empty_scratch(tmp_path)
    retained = scratch / "user-owned.txt"
    retained.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="direct empty mode-0700"):
        replay_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            producer_package_bytes=b"not-a-zip",
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert retained.read_text(encoding="utf-8") == "keep"


def test_symlink_scratch_is_rejected_without_touching_target(tmp_path: Path) -> None:
    target = _empty_scratch(tmp_path, "target")
    scratch = tmp_path / "scratch-link"
    scratch.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="direct empty mode-0700"):
        replay_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            producer_package_bytes=b"not-a-zip",
            seed_ordinal=1,
            scratch_root=scratch,
        )
    assert target.is_dir()
    assert scratch.is_symlink()


@pytest.mark.parametrize(
    "scratch",
    [Path("relative-scratch"), "not-a-path", None],
)
def test_scratch_type_and_absolute_path_fail_before_trace(
    scratch: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_trace(*args: object, **kwargs: object) -> None:
        raise AssertionError("trace generation must remain unreachable")

    monkeypatch.setattr(study, "generate_route_a_formal_trace", forbidden_trace)
    with pytest.raises((TypeError, ValueError)):
        produce_validation_scaling_seed_shard(
            plan_bytes=PLAN_BYTES,
            seed_ordinal=1,
            scratch_root=scratch,  # type: ignore[arg-type]
        )


def test_sentinel_factory_rejects_every_registered_seed() -> None:
    formal_seeds, query_vector_seed = study._registered_scientific_values()
    registered = (
        study._unused_qualification_seed(formal_seeds, query_vector_seed),
        *formal_seeds,
        query_vector_seed,
    )
    for seed in registered:
        with pytest.raises(ValueError, match="disjoint from production"):
            study._make_validation_scaling_sentinel_domain(
                qualification_seed=seed,
                formal_seeds=(91_002, 91_003, 91_004),
                query_vector_seed=91_005,
                wall_clock_ns=lambda: 0,
                process_clock_ns=lambda: 0,
            )


def test_compile_counter_installs_one_wrapper_and_restores_both_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_compile(*args: object, **kwargs: object) -> str:
        calls.append((args, kwargs))
        return "compiled"

    monkeypatch.setattr(query_compiler_module, "compile_query", fake_compile)
    monkeypatch.setattr(simulator_module, "compile_query", fake_compile)
    with study._count_compile_queries() as counter:
        assert query_compiler_module.compile_query is simulator_module.compile_query
        assert query_compiler_module.compile_query("q", sentinel=True) == "compiled"
        assert simulator_module.compile_query("r") == "compiled"
    assert counter.count == 2
    assert calls == [(('q',), {'sentinel': True}), (('r',), {})]
    assert query_compiler_module.compile_query is fake_compile
    assert simulator_module.compile_query is fake_compile


def test_compile_counter_rejects_initially_divergent_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(query_compiler_module, "compile_query", lambda: None)
    monkeypatch.setattr(simulator_module, "compile_query", lambda: None)
    with (
        pytest.raises(ValueError, match="bindings differ before instrumentation"),
        study._count_compile_queries(),
    ):
        raise AssertionError("unreachable")


def test_compile_counter_detects_mutation_and_restores_both_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def original() -> None:
        return None

    def replacement() -> None:
        return None

    monkeypatch.setattr(query_compiler_module, "compile_query", original)
    monkeypatch.setattr(simulator_module, "compile_query", original)
    with pytest.raises(ValueError, match="binding mutated"), study._count_compile_queries():
        simulator_module.compile_query = replacement
    assert query_compiler_module.compile_query is original
    assert simulator_module.compile_query is original


def test_compile_counter_restores_both_bindings_when_measured_code_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def original() -> None:
        return None

    monkeypatch.setattr(query_compiler_module, "compile_query", original)
    monkeypatch.setattr(simulator_module, "compile_query", original)
    with (
        pytest.raises(RuntimeError, match="injected operation failure"),
        study._count_compile_queries(),
    ):
        raise RuntimeError("injected operation failure")
    assert query_compiler_module.compile_query is original
    assert simulator_module.compile_query is original


def test_semantic_projection_excludes_measurements() -> None:
    document = {field: {"sentinel": field} for field in study._SEMANTIC_FIELDS}
    document["measurements"] = {"operation_wall_nanoseconds": 123}
    projection = study._semantic_projection(document)
    assert b"measurements" not in projection
    assert b"123" not in projection


def test_canonical_payload_round_trip_and_reordered_archive_rejection() -> None:
    paths = study._producer_paths()
    members = {path: f"member:{path}\n".encode("ascii") for path in paths}
    payload = study._write_payload(paths, members)
    assert study._read_payload(payload, expected_paths=paths) == members

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in reversed(paths):
            info = zipfile.ZipInfo(path, date_time=study._ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, members[path])
    with pytest.raises(ValueError, match="reordered"):
        study._read_payload(buffer.getvalue(), expected_paths=paths)


def test_canonical_payload_rejects_nonregular_mode() -> None:
    paths = study._producer_paths()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for index, path in enumerate(paths):
            info = zipfile.ZipInfo(path, date_time=study._ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (
                (stat.S_IFLNK | 0o777) if index == 0 else (stat.S_IFREG | 0o644)
            ) << 16
            archive.writestr(info, b"member\n")
    with pytest.raises(ValueError, match="metadata changed"):
        study._read_payload(buffer.getvalue(), expected_paths=paths)


def test_canonical_payload_rejects_duplicate_member_and_archive_comment() -> None:
    paths = study._producer_paths()
    buffer = io.BytesIO()
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive,
    ):
        for path in (*paths[:-1], paths[-2]):
            archive.writestr(study._zip_info(path), b"member\n")
    with pytest.raises(ValueError, match="missing, extra, repeated, or reordered"):
        study._read_payload(buffer.getvalue(), expected_paths=paths)

    members = {path: f"member:{path}\n".encode("ascii") for path in paths}
    commented = io.BytesIO()
    with zipfile.ZipFile(commented, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in paths:
            archive.writestr(study._zip_info(path), members[path])
        archive.comment = b"not-authoritative-but-forbidden"
    with pytest.raises(ValueError, match="archive comment"):
        study._read_payload(commented.getvalue(), expected_paths=paths)


def _execution_receipt_bytes(
    *,
    payload: bytes,
    role: str = "producer",
    seed_ordinal: int = 1,
    run_id: int = 77,
    source_git_sha: str = "a" * 40,
) -> bytes:
    return canonical_route_a_document(
        {
            "schema_version": runner._RECEIPT_SCHEMA,
            "artifact_role": role,
            "seed_ordinal": seed_ordinal,
            "runner_os": "Linux",
            "runner_arch": "X64",
            "python_version": "3.12.13",
            "github_run_id": run_id,
            "github_run_attempt": 1,
            "github_job": f"{'producer' if role == 'producer' else 'replay'}-seed-{seed_ordinal}",
            "source_git_sha": source_git_sha,
            "operation_started_utc": "2026-09-01T00:00:01.000000Z",
            "package_finished_utc": "2026-09-01T00:00:02.000000Z",
            "seed_package_wall_nanoseconds": 1,
            "seed_package_process_nanoseconds": 1,
            "process_peak_rss_bytes_or_null": 1,
            "payload_filename": "payload.zip",
            "payload_byte_count": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
    )


def test_outer_provider_artifact_ignores_physical_order_but_rejects_links(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "artifact"
    directory.mkdir()
    payload = b"opaque producer payload"
    (directory / "payload.zip").write_bytes(payload)
    (directory / "execution-receipt.json").write_bytes(
        _execution_receipt_bytes(payload=payload)
    )
    assert runner._read_producer_artifact(
        directory,
        seed_ordinal=1,
        github_run_id=77,
        source_git_sha="a" * 40,
    ) == payload

    (directory / "payload.zip").unlink()
    target = tmp_path / "target.zip"
    target.write_bytes(payload)
    (directory / "payload.zip").symlink_to(target)
    with pytest.raises(ValueError, match="direct regular bytes"):
        runner._read_producer_artifact(
            directory,
            seed_ordinal=1,
            github_run_id=77,
            source_git_sha="a" * 40,
        )


def _provider_artifacts(run_id: int, source_git_sha: str) -> dict[str, object]:
    artifacts: list[dict[str, object]] = []
    for artifact_id, (role, ordinal) in enumerate(
        (
            (role, ordinal)
            for role in ("producer", "replay")
            for ordinal in (1, 2, 3)
        ),
        start=1,
    ):
        artifacts.append(
            {
                "id": artifact_id,
                "name": f"validation-scaling-{role}-seed-{ordinal}-v1",
                "size_in_bytes": 10,
                "digest": f"sha256:{artifact_id:064x}",
                "expired": False,
                "workflow_run": {
                    "id": run_id,
                    "head_branch": runner._SOURCE_TAG,
                    "head_sha": source_git_sha,
                },
            }
        )
    return {"total_count": 6, "artifacts": artifacts}


def test_provider_artifact_inventory_is_exact_and_strictly_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _provider_artifacts(77, "a" * 40)
    monkeypatch.setattr(runner, "_provider_json", lambda *args, **kwargs: response)
    observed = runner._artifact_metadata_from_provider(
        run_id=77,
        source_git_sha="a" * 40,
        token="sentinel",
    )
    assert tuple(observed) == tuple(
        f"validation-scaling-{role}-seed-{ordinal}-v1"
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    response["artifacts"][0]["id"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="metadata binding changed"):
        runner._artifact_metadata_from_provider(
            run_id=77,
            source_git_sha="a" * 40,
            token="sentinel",
        )


def test_formal_run_inventory_is_exact_and_strictly_typed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response: dict[str, object] = {
        "total_count": 1,
        "workflow_runs": [
            {
                "id": 77,
                "run_attempt": 1,
                "event": "workflow_dispatch",
                "head_branch": runner._SOURCE_TAG,
                "head_sha": "a" * 40,
            }
        ],
    }
    monkeypatch.setattr(runner, "_provider_json", lambda *args, **kwargs: response)
    runner._assert_single_run_inventory(
        run_id=77,
        source_git_sha="a" * 40,
        token="sentinel",
    )
    response["workflow_runs"][0]["run_attempt"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="exact current run"):
        runner._assert_single_run_inventory(
            run_id=77,
            source_git_sha="a" * 40,
            token="sentinel",
        )


def _provider_jobs() -> dict[str, object]:
    jobs: list[dict[str, object]] = []
    for database_id, name in enumerate(
        (
            f"{role}-seed-{ordinal}"
            for role in ("producer", "replay")
            for ordinal in (1, 2, 3)
        ),
        start=1,
    ):
        jobs.append(
            {
                "id": database_id,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-09-01T00:00:00Z",
                "completed_at": "2026-09-01T00:00:03Z",
            }
        )
    jobs.append(
        {
            "id": 7,
            "name": "aggregate",
            "status": "in_progress",
            "conclusion": None,
            "started_at": "2026-09-01T00:00:04Z",
            "completed_at": None,
        }
    )
    return {"total_count": 7, "jobs": jobs}


def test_provider_job_inventory_rejects_self_terminal_and_duplicate_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _provider_jobs()
    monkeypatch.setattr(runner, "_provider_json", lambda *args, **kwargs: response)
    assert len(runner._job_observations_from_provider(run_id=77, token="sentinel")) == 6

    response["jobs"][-1]["status"] = "completed"  # type: ignore[index]
    response["jobs"][-1]["conclusion"] = "success"  # type: ignore[index]
    response["jobs"][-1]["completed_at"] = "2026-09-01T00:00:05Z"  # type: ignore[index]
    with pytest.raises(ValueError, match="own terminal state"):
        runner._job_observations_from_provider(run_id=77, token="sentinel")

    response = _provider_jobs()
    response["jobs"][1]["id"] = 1  # type: ignore[index]
    monkeypatch.setattr(runner, "_provider_json", lambda *args, **kwargs: response)
    with pytest.raises(ValueError, match="successful terminal observation"):
        runner._job_observations_from_provider(run_id=77, token="sentinel")


def _seed_evidence_for_provider(
    *,
    role: str,
    ordinal: int,
    operation_started: str = "2026-09-01T00:00:01.000000Z",
    package_finished: str = "2026-09-01T00:00:02.000000Z",
) -> validator.SeedEvidence:
    provider_role = "producer" if role == "producer" else "replay"
    return validator.SeedEvidence(
        role=role,  # type: ignore[arg-type]
        seed_ordinal=ordinal,
        payload_bytes=b"payload",
        payload_sha256="a" * 64,
        receipt_bytes=b"receipt",
        receipt={
            "operation_started_utc": operation_started,
            "package_finished_utc": package_finished,
        },
        rows=(),
        row_bytes=(),
        semantic_bytes=(),
        cell_bytes=(),
        private_archive_bytes=(),
        binding_bytes=(),
        metadata=validator.ProviderArtifactMetadata(
            artifact_id=ordinal + (0 if role == "producer" else 3),
            name=f"validation-scaling-{provider_role}-seed-{ordinal}-v1",
            size_in_bytes=1,
            digest="sha256:" + "b" * 64,
        ),
    )


def _provider_observations() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "github_job_database_id": database_id,
            "github_job_name": f"{role}-seed-{ordinal}",
            "github_job_started_at": "2026-09-01T00:00:00Z",
            "github_job_completed_at": "2026-09-01T00:00:03Z",
            "github_job_conclusion": "success",
        }
        for database_id, (role, ordinal) in enumerate(
            (
                (role, ordinal)
                for role in ("producer", "replay")
                for ordinal in (1, 2, 3)
            ),
            start=1,
        )
    )


def test_provider_intervals_enclose_process_owned_receipt_intervals() -> None:
    seeds = tuple(
        _seed_evidence_for_provider(
            role="producer" if role == "producer" else "independent-replay",
            ordinal=ordinal,
        )
        for role in ("producer", "replay")
        for ordinal in (1, 2, 3)
    )
    observations = _provider_observations()
    assert validator._validate_provider_observations(observations, seeds) == observations

    outside = list(seeds)
    outside[0] = _seed_evidence_for_provider(
        role="producer",
        ordinal=1,
        operation_started="2026-08-31T23:59:59.000000Z",
    )
    with pytest.raises(ValueError, match="falls outside its provider job"):
        validator._validate_provider_observations(observations, tuple(outside))


def test_evidence_schema_is_closed_json_with_all_required_document_defs() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas/validation-scaling-evidence-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$defs"]["cellRow"]["additionalProperties"] is False
    assert schema["$defs"]["executionReceipt"]["additionalProperties"] is False
    assert schema["$defs"]["seedManifest"]["additionalProperties"] is False
    assert schema["$defs"]["aggregateManifest"]["additionalProperties"] is False
    assert len(schema["oneOf"]) == 12


def test_exact_ols_recovers_linear_model_without_floats() -> None:
    record = validator._ols_record(
        strategy="padding-reuse",
        role="producer",
        medians=(110, 202, 1124),
    )
    assert record["alpha_nanoseconds"] == {"numerator": 100, "denominator": 1}
    assert record["beta_nanoseconds_per_query"] == {
        "numerator": 2,
        "denominator": 1,
    }
    assert record["r_squared"] == {"numerator": 1, "denominator": 1}
    assert record["pass_threshold"] is None


def test_exact_ols_serializes_negative_intercept_as_reduced_rational() -> None:
    record = validator._ols_record(
        strategy="padding-reuse",
        role="independent-replay",
        medians=(25, 2601, 262144),
    )
    alpha = record["alpha_nanoseconds"]
    assert type(alpha) is dict
    assert alpha["numerator"] < 0
    assert Fraction(alpha["numerator"], alpha["denominator"]).denominator == alpha[
        "denominator"
    ]


def test_zero_sst_ols_emits_exact_one() -> None:
    record = validator._ols_record(
        strategy="padding-reuse",
        role="producer",
        medians=(123, 123, 123),
    )
    assert record["alpha_nanoseconds"] == {"numerator": 123, "denominator": 1}
    assert record["beta_nanoseconds_per_query"] == {
        "numerator": 0,
        "denominator": 1,
    }
    assert record["r_squared"] == {"numerator": 1, "denominator": 1}


def test_integer_summary_uses_stable_numeric_middle_value() -> None:
    assert validator._integer_summary([9, 1, 5]) == {
        "observations": [9, 1, 5],
        "minimum": 1,
        "median": 5,
        "maximum": 9,
    }


def test_human_rendering_uses_nine_place_half_even_only_after_fraction() -> None:
    assert validator._render_fraction(Fraction(1, 2), nanoseconds=True) == "0.000000000"
    assert validator._render_fraction(Fraction(3, 2), nanoseconds=True) == "0.000000002"
    assert validator._render_fraction(Fraction(1, 8), nanoseconds=False) == "0.125000000"


def test_private_engine_failure_destroys_the_owned_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    domain = study._make_validation_scaling_sentinel_domain(
        qualification_seed=91_001,
        formal_seeds=(91_002, 91_003, 91_004),
        query_vector_seed=91_005,
        wall_clock_ns=lambda: 0,
        process_clock_ns=lambda: 0,
    )
    scratch = _empty_scratch(tmp_path)

    def fail_before_trace(*args: object, **kwargs: object) -> bytes:
        raise RuntimeError("sentinel injected failure")

    monkeypatch.setattr(study, "_produce_payload", fail_before_trace)
    with pytest.raises(RuntimeError, match="sentinel injected failure"):
        study._run_owned(
            domain=domain,
            seed_ordinal=1,
            scratch_root=scratch,
            producer_payload_bytes=None,
        )
    assert not scratch.exists()


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true",
    reason="successful sentinel lifecycle is intentionally GitHub-Actions-only",
)
def test_private_sentinel_full_path_is_deterministic_closed_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class Tick:
        def __init__(self) -> None:
            self.value = 0

        def __call__(self) -> int:
            self.value += 1_000
            return self.value

    machine_plan = (REPOSITORY_ROOT / "config/route-a-publication-plan.json").read_bytes()

    def produce_once(name: str) -> tuple[bytes, study._ValidationScalingDomain]:
        tick = Tick()
        monkeypatch.setattr(evaluation_module.time, "perf_counter_ns", tick)
        monkeypatch.setattr(replay_module.time, "perf_counter_ns", tick)
        monkeypatch.setattr(strategy_module.time, "perf_counter_ns", tick)
        domain = study._make_validation_scaling_sentinel_domain(
            qualification_seed=91_001,
            formal_seeds=(91_002, 91_003, 91_004),
            query_vector_seed=91_005,
            wall_clock_ns=tick,
            process_clock_ns=tick,
        )
        scratch = _empty_scratch(tmp_path, name)
        payload = study._produce_payload(
            domain,
            domain.records[0],
            machine_plan,
            scratch,
        )
        assert tuple(scratch.iterdir()) == ()
        return payload, domain

    producer_a, domain_a = produce_once("producer-a")
    producer_b, _domain_b = produce_once("producer-b")
    assert producer_a == producer_b

    def replay_once(name: str) -> bytes:
        tick = Tick()
        monkeypatch.setattr(evaluation_module.time, "perf_counter_ns", tick)
        monkeypatch.setattr(replay_module.time, "perf_counter_ns", tick)
        monkeypatch.setattr(strategy_module.time, "perf_counter_ns", tick)
        domain = study._make_validation_scaling_sentinel_domain(
            qualification_seed=91_001,
            formal_seeds=(91_002, 91_003, 91_004),
            query_vector_seed=91_005,
            wall_clock_ns=tick,
            process_clock_ns=tick,
        )
        scratch = _empty_scratch(tmp_path, name)
        payload = study._replay_payload(
            domain,
            domain.records[0],
            machine_plan,
            producer_a,
            scratch,
        )
        assert tuple(scratch.iterdir()) == ()
        return payload

    replay_a = replay_once("replay-a")
    replay_b = replay_once("replay-b")
    assert replay_a == replay_b

    producer_members = study._read_payload(
        producer_a,
        expected_paths=study._producer_paths(),
    )
    replay_members = study._read_payload(
        replay_a,
        expected_paths=study._replay_paths(),
    )
    assert len(producer_members) == 28
    assert len(replay_members) == 46
    assert all(
        forbidden not in path
        for path in replay_members
        for forbidden in ("private", "preparation", "ledger", "producer-cell", "replay-cell")
    )
    trace = study.generate_route_a_formal_trace(
        scale="S",
        formal_seed=domain_a.records[0].formal_seed,
        scientific_profile=domain_a.profile,
    )
    producer_cells = study._decode_producer_payload(
        domain_a,
        domain_a.records[0],
        trace,
        producer_a,
    )
    assert len(producer_cells) == 9
    for cell_ordinal, producer in enumerate(producer_cells):
        producer_row = json.loads(producer.row_bytes)
        replay_row = json.loads(
            replay_members[f"cells/{cell_ordinal:02d}/timing-row.json"]
        )
        for row in (producer_row, replay_row):
            assert row["query_count"] <= row["compile_query_call_count"]
            assert row["compile_query_call_count"] <= 2 * row["query_count"]
        assert (
            producer.semantic_bytes
            == replay_members[f"cells/{cell_ordinal:02d}/semantic-projection.json"]
        )
