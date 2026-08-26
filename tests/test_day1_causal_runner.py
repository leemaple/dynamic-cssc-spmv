from __future__ import annotations

import argparse
import inspect
import json
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc import simulator as simulator_module
from dynamic_cssc.day1_registry import (
    Day1CandidateCatalog,
    Day1CandidateRegistrationError,
    RegistrationEvidence,
    _canonical_registered_candidates,
)
from dynamic_cssc.events import Event, NetUpdate, PublicationWindow
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.preflight import PreflightReport
from dynamic_cssc.selection import (
    FixedCandidate,
    build_fixed_candidates,
    parse_experiment_split,
    select_tuned_fixed_candidate,
    split_boundaries,
)
from dynamic_cssc.simulator import (
    RotationInventory,
    SimulationConfig,
    SimulationResult,
    SimulationTarget,
)
from scripts import run_day1_suite
from scripts.run_day1_suite import (
    CausalCellResult,
    _candidate_records,
    _evaluate_causal_cell,
    evaluate_causal_cell,
    run_suite,
)

ROOT = Path(__file__).resolve().parents[1]
_COMPACT_TEST_PLAN_VERSION = "test-only-compact-v1"


@pytest.fixture(autouse=True)
def _allow_compact_test_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        run_day1_suite._FROZEN_PLAN_LAYOUTS,  # noqa: SLF001
        _COMPACT_TEST_PLAN_VERSION,
        (2, 2, 2048, 128),
    )


def _small_experiment_plan() -> dict[str, object]:
    return {
        "plan_version": _COMPACT_TEST_PLAN_VERSION,
        "split": {"warmup": 0.1, "tuning": 0.3, "held_out": 0.6},
        "synthetic": {
            "rows": 2,
            "cols": 2,
            "initial_nnz_per_row": 1,
            "events": 10,
            "effective_slots": 2048,
            "partition_rows": 128,
            "layout_measurement_kind": "synthetic-proxy",
            "queries_per_update_grid": [1],
            "workloads": ["zipf"],
        },
        "reserved_slack_betas": [0, 0.05, 0.1, 0.2, 0.4],
        "periodic_repack_windows": [1, 4, 16, 64],
        "freshness_seconds": [1.0],
        "bandwidth_profiles_mbps": [100],
    }


def _small_publication_experiment_plan() -> dict[str, object]:
    return json.loads(
        (ROOT / "config" / "experiment_plan_publication.json").read_text(encoding="utf-8")
    )


def _registered_catalog() -> Day1CandidateCatalog:
    return Day1CandidateCatalog(
        candidates=_canonical_registered_candidates(),
        registration=RegistrationEvidence(
            schema_version="dynamic-cssc-day1-registration-evidence-v1",
            source_git_sha="1" * 40,
            run_id=1,
            correctness_artifact_sha256="2" * 64,
            accounting_evidence_sha256="3" * 64,
            policy_contract_sha256=(
                "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
            ),
        ),
    )


def _unavailable_catalog() -> Day1CandidateCatalog:
    raise Day1CandidateRegistrationError(
        "no repository-approved Day-1 composite registration anchor"
    )


def test_plan_0_2_freezes_the_synthetic_layout_proxy() -> None:
    plan = run_day1_suite.load_experiment_plan(ROOT / "config" / "experiment_plan.json")

    assert plan.plan_version == "0.2.0"
    assert plan.rows == 512
    assert plan.cols == 512
    assert plan.effective_slots == 2048
    assert plan.partition_rows == 128
    assert plan.layout_measurement_kind == "synthetic-proxy"


def test_plan_0_3_freezes_the_publication_layout_proxy() -> None:
    plan = run_day1_suite.parse_experiment_plan(_small_publication_experiment_plan())

    assert plan.plan_version == "0.3.0"
    assert plan.rows == 4096
    assert plan.cols == 8193
    assert plan.effective_slots == 4096
    assert plan.partition_rows == 4096
    assert plan.layout_measurement_kind == "synthetic-proxy"


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("plan_version", "0.1.0", "plan_version.*0.2.0"),
        ("rows", 511, "rows.*512.*0.2.0"),
        ("cols", 511, "cols.*512.*0.2.0"),
        ("effective_slots", 1024, "effective_slots.*2048"),
        ("partition_rows", 64, "partition_rows.*128"),
        ("layout_measurement_kind", "measured", "layout_measurement_kind.*synthetic-proxy"),
    ],
)
def test_plan_rejects_any_substitution_of_the_frozen_layout_proxy(
    field: str, replacement: object, message: str
) -> None:
    payload = json.loads(
        (ROOT / "config" / "experiment_plan.json").read_text(encoding="utf-8")
    )
    if field == "plan_version":
        payload[field] = replacement
    else:
        synthetic = payload["synthetic"]
        assert isinstance(synthetic, dict)
        synthetic[field] = replacement

    with pytest.raises(ValueError, match=message):
        run_day1_suite.parse_experiment_plan(payload)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("rows", 512, "rows.*4096.*0.3.0"),
        ("cols", 512, "cols.*8193.*0.3.0"),
        ("effective_slots", 2048, "effective_slots.*4096.*0.3.0"),
        ("partition_rows", 128, "partition_rows.*4096.*0.3.0"),
    ],
)
def test_publication_plan_rejects_exploratory_layout_substitution(
    field: str, replacement: int, message: str
) -> None:
    payload = _small_publication_experiment_plan()
    synthetic = payload["synthetic"]
    assert isinstance(synthetic, dict)
    synthetic[field] = replacement

    with pytest.raises(ValueError, match=message):
        run_day1_suite.parse_experiment_plan(payload)


@pytest.mark.parametrize("mutation", ["missing", "misspelled", "extra"])
def test_plan_boundary_rejects_noncanonical_synthetic_keys(tmp_path: Path, mutation: str) -> None:
    payload = _small_experiment_plan()
    synthetic = payload["synthetic"]
    assert isinstance(synthetic, dict)
    if mutation == "missing":
        del synthetic["workloads"]
    elif mutation == "misspelled":
        synthetic["rowz"] = synthetic.pop("rows")
    else:
        synthetic["updates"] = synthetic["events"]
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="synthetic keys"):
        run_day1_suite.load_experiment_plan(plan_path)


@pytest.mark.parametrize(
    ("argument_name", "override", "plan_field"),
    [
        ("rows", 3, "synthetic.rows"),
        ("nnz_per_row", True, "synthetic.initial_nnz_per_row"),
        ("effective_slots", 1024, "synthetic.effective_slots"),
        ("partition_rows", 64, "synthetic.partition_rows"),
    ],
)
def test_suite_rejects_cli_dimensions_that_disagree_with_the_plan(
    monkeypatch: pytest.MonkeyPatch,
    argument_name: str,
    override: int,
    plan_field: str,
) -> None:
    monkeypatch.setattr(run_day1_suite, "load_manifest", lambda _path: {})
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        ),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "load_experiment_plan",
        lambda _path: run_day1_suite.parse_experiment_plan(_small_experiment_plan()),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("generation must not start"),
    )
    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=Path("unused"),
        seed=7,
        workload="zipf",
        freshness_seconds="1",
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
        effective_slots=None,
        partition_rows=None,
    )
    setattr(args, argument_name, override)

    cli_flag = argument_name.replace("_", "-")
    with pytest.raises(ValueError, match=rf"--{cli_flag}.*{plan_field}"):
        run_suite(args)


@pytest.mark.parametrize(
    ("workload", "freshness_seconds", "message"),
    [
        ("not-in-plan", "1", "--workload.*must belong"),
        ("zipf", "2", "--freshness-seconds.*must belong"),
    ],
)
def test_shard_filters_must_belong_to_the_frozen_plan(
    monkeypatch: pytest.MonkeyPatch,
    workload: str,
    freshness_seconds: str,
    message: str,
) -> None:
    monkeypatch.setattr(run_day1_suite, "load_manifest", lambda _path: {})
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        ),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "load_experiment_plan",
        lambda _path: run_day1_suite.parse_experiment_plan(_small_experiment_plan()),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("generation must not start"),
    )
    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=Path("unused"),
        seed=7,
        workload=workload,
        freshness_seconds=freshness_seconds,
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
    )

    with pytest.raises(ValueError, match=message):
        run_suite(args)


def test_split_uses_exact_decimal_fractions_and_keeps_tuning_and_held_out_nonempty() -> None:
    split = parse_experiment_split({"warmup": "0.10", "tuning": "0.30", "held_out": "0.60"})

    assert split == (Fraction(1, 10), Fraction(3, 10), Fraction(3, 5))
    assert split_boundaries(10, split) == (1, 4)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (
            {"warmup": -0.1, "tuning": 0.5, "held_out": 0.6},
            "nonnegative",
        ),
        (
            {"warmup": 0.1, "tuning": 0.2, "held_out": 0.6},
            "sum to one",
        ),
        (
            {"warmup": False, "tuning": 0.4, "held_out": 0.6},
            "decimal fraction",
        ),
    ],
)
def test_split_rejects_invalid_fractions(values: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_experiment_split(values)


def test_candidate_grid_has_exactly_the_thirteen_fixed_policies() -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0.0, 0.05, 0.10, 0.20, 0.40],
        periodic_repack_windows=[1, 4, 16, 64],
    )

    assert [candidate.candidate_id for candidate in candidates] == [
        "padding-reuse",
        "mini-cssc-delta",
        "packed-coo-client-lane-delta/capacity=128",
        "strict-local-repack",
        "reserved-slack/beta=0",
        "reserved-slack/beta=0.05",
        "reserved-slack/beta=0.1",
        "reserved-slack/beta=0.2",
        "reserved-slack/beta=0.4",
        "periodic-repack/windows=1",
        "periodic-repack/windows=4",
        "periodic-repack/windows=16",
        "periodic-repack/windows=64",
    ]


@pytest.mark.parametrize(
    ("betas", "periods", "message"),
    [
        (
            [0, 0.05, 0.1, "0.10", 0.4],
            [1, 4, 16, 64],
            "frozen canonical grid",
        ),
        ([0, 0.05, 0.1, 0.2], [1, 4, 16, 64], "exactly five"),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 16], "exactly four"),
    ],
)
def test_candidate_grid_rejects_duplicates_or_changed_cardinality(
    betas: list[object], periods: list[int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        build_fixed_candidates(
            reserved_slack_betas=betas,
            periodic_repack_windows=periods,
        )


@pytest.mark.parametrize(
    ("betas", "periods"),
    [
        ([0, 0.05, 0.1, 0.3, 0.4], [1, 4, 16, 64]),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 8, 64]),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 16, 16]),
    ],
)
def test_candidate_grid_rejects_any_substitution_from_the_frozen_grid(
    betas: list[object], periods: list[int]
) -> None:
    with pytest.raises(ValueError, match="frozen canonical grid"):
        build_fixed_candidates(
            reserved_slack_betas=betas,
            periodic_repack_windows=periods,
        )


def test_tuning_selector_uses_only_finite_cost_then_canonical_id_for_ties() -> None:
    candidates = (
        FixedCandidate("z-policy", "PaddingReuse-CSSC"),
        FixedCandidate("a-policy", "Mini-CSSC-Delta"),
        FixedCandidate("nonfinite", "Strict-LocalRepack"),
    )
    metrics = {
        "z-policy": StrategyMetrics("PaddingReuse-CSSC", "reference"),
        "a-policy": StrategyMetrics("Mini-CSSC-Delta", "reference"),
        "nonfinite": StrategyMetrics(
            "Strict-LocalRepack", "reference", update_encryptions=float("inf")
        ),
    }

    selected = select_tuned_fixed_candidate(candidates, metrics, UnitCosts())

    assert selected.candidate_id == "a-policy"


def test_cell_enforces_reference_and_ablation_roles_across_one_causal_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = _registered_catalog()
    windows = [PublicationWindow(index, index, index + 1, (), 0, "fixture") for index in range(10)]
    call_trace: list[tuple[str, int, int]] = []

    def fake_simulate_targets(
        replay_windows: list[PublicationWindow],
        _initial: dict[tuple[int, int], int],
        targets: list[SimulationTarget],
        *,
        warmup_end: int,
        tuning_end: int,
    ) -> tuple[dict[str, SimulationResult], dict[str, SimulationResult]]:
        call_trace.append(("ordinary-causal", warmup_end, tuning_end))
        assert len(replay_windows) == 10
        target_ids = {target.run_id for target in targets}
        assert "packed-coo-cloud-segmented-delta/segment-width=128" not in target_ids
        assert "packed-coo-client-lane-delta/capacity=128" in target_ids
        assert len(targets) == 13

        def phase_results(*, tuning: bool) -> dict[str, SimulationResult]:
            results = {}
            for target in targets:
                score = 50
                if tuning and target.strategy == "ReservedSlack-CSSC":
                    score = 1 if target.config.reserved_slack_beta == 0.05 else 20
                if not tuning and target.strategy == "ReservedSlack-CSSC":
                    score = 7 if target.config.reserved_slack_beta == 0.05 else 20
                if not tuning and target.strategy == "PeriodicRepack":
                    score = 1 if target.config.periodic_repack_windows == 1 else 30
                if not tuning and target.strategy == "Packed-COO-Client-Lane-Delta":
                    score = 0
                results[target.run_id] = SimulationResult(
                    StrategyMetrics(
                        target.strategy,
                        "reference",
                        windows=(
                            tuning_end - warmup_end
                            if tuning
                            else len(replay_windows) - tuning_end
                        ),
                        update_encryptions=score,
                        update_ciphertexts=score,
                        rotations=1,
                        source="persistent-state-predicted",
                    ),
                    {0: score},
                    RotationInventory(((-1, 1),), (-1, 99)),
                )
            return results

        return phase_results(tuning=True), phase_results(tuning=False)

    def fake_simulate_strong(
        replay_windows: list[PublicationWindow],
        _initial: dict[tuple[int, int], int],
        config: SimulationConfig,
        *,
        warmup_end: int,
        tuning_end: int,
    ) -> tuple[SimulationResult, SimulationResult]:
        call_trace.append(("strong-causal", warmup_end, tuning_end))
        assert len(replay_windows) == 10
        assert config.packed_coo_segment_capacity == 128

        def phase_result(score: int, window_count: int) -> SimulationResult:
            return SimulationResult(
                StrategyMetrics(
                    "Packed-COO-Cloud-Segmented-Delta",
                    "reference",
                    windows=window_count,
                    update_encryptions=score,
                    update_ciphertexts=score,
                    rotations=2,
                    source="persistent-state-predicted",
                ),
                {0: score},
                RotationInventory(((-2, 2),), (-2, 101)),
            )

        return (
            phase_result(10, tuning_end - warmup_end),
            phase_result(2, len(replay_windows) - tuning_end),
        )

    real_select = select_tuned_fixed_candidate

    def observed_select(*args: object, **kwargs: object) -> FixedCandidate:
        call_trace.append(("freeze", -1, -1))
        return real_select(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_day1_suite, "select_tuned_fixed_candidate", observed_select)

    result = _evaluate_causal_cell(
        windows=windows,
        initial_state={},
        base_config=SimulationConfig(
            rows=1,
            cols=1,
            effective_slots=8,
            partition_rows=1,
            matrix_value_bound=7,
            max_row_nnz=1,
            reserved_slack_beta=0.1,
            periodic_repack_windows=4,
            packed_coo_segment_capacity=128,
        ),
        split=(Fraction(1, 10), Fraction(3, 10), Fraction(3, 5)),
        costs=UnitCosts(),
        catalog=catalog,
        simulate_targets_fn=fake_simulate_targets,
        simulate_strong_fn=fake_simulate_strong,
    )

    assert call_trace == [
        ("ordinary-causal", 1, 4),
        ("strong-causal", 1, 4),
        ("freeze", -1, -1),
    ]
    assert result.selected_candidate_id == "reserved-slack/beta=0.05"
    assert result.oracle_candidate_id == "periodic-repack/windows=1"
    assert set(result.tuning_results) == {
        candidate.candidate_id for candidate in catalog.selection_candidates
    }
    assert set(result.fixed_results) == {candidate.candidate_id for candidate in catalog.candidates}
    ablation = result.fixed_results["packed-coo-client-lane-delta/capacity=128"]
    assert ablation.metrics.category == "ablation"
    assert ablation.metrics.update_encryptions == 0
    assert ablation.rotation_inventory.required_indices == (-1, 99)
    strong = result.fixed_results["packed-coo-cloud-segmented-delta/segment-width=128"]
    assert strong.rotation_inventory.required_indices == (-2, 101)
    assert result.tuned_policy.strategy == "TunedFixedPolicy"
    assert result.tuned_policy.update_encryptions == 7
    assert result.offline_oracle.strategy == "BestFixed-Offline-Oracle"
    assert result.offline_oracle.update_encryptions == 1

    records = _candidate_records(result)
    assert len(records) == 16
    fixed_records = {
        record.candidate_id: record for record in records if record.record_kind == "fixed-candidate"
    }
    assert len(fixed_records) == 14
    assert fixed_records["packed-coo-client-lane-delta/capacity=128"].candidate_role == "ablation"
    for candidate_id, simulation in result.fixed_results.items():
        assert fixed_records[candidate_id].rotation_inventory == simulation.rotation_inventory
    aliases = {
        record.record_kind: record for record in records if record.record_kind != "fixed-candidate"
    }
    assert (
        aliases["tuned-fixed-policy"].rotation_inventory
        == fixed_records[result.selected_candidate_id].rotation_inventory
    )
    assert (
        aliases["diagnostic-oracle"].rotation_inventory
        == fixed_records[result.oracle_candidate_id].rotation_inventory
    )


def test_public_cell_interface_owns_repository_authority_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(evaluate_causal_cell).parameters) == (
        "windows",
        "initial_state",
        "base_config",
        "split",
        "costs",
    )
    monkeypatch.setattr(
        run_day1_suite,
        "simulate_targets_causal",
        lambda *_args, **_kwargs: pytest.fail("simulation must not run without registration"),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "simulate_strong_reference_causal",
        lambda *_args, **_kwargs: pytest.fail(
            "strong simulation must not run without registration"
        ),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "repository_day1_candidate_catalog",
        _unavailable_catalog,
    )

    with pytest.raises(Day1CandidateRegistrationError, match="composite registration anchor"):
        evaluate_causal_cell(
            windows=[
                PublicationWindow(index, index, index + 1, (), 0, "fixture") for index in range(3)
            ],
            initial_state={},
            base_config=SimulationConfig(
                rows=1,
                cols=1,
                effective_slots=128,
                partition_rows=1,
                matrix_value_bound=7,
                max_row_nnz=1,
                reserved_slack_beta=0.1,
                periodic_repack_windows=4,
                packed_coo_segment_capacity=128,
            ),
            split=(Fraction(0), Fraction(1, 3), Fraction(2, 3)),
            costs=UnitCosts(),
        )


def test_three_window_cell_runs_one_continuous_ordinary_and_strong_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows = [PublicationWindow(index, index, index + 1, (), 0, "fixture") for index in range(3)]
    init_count = 0
    advance_count = 0
    strong_init_count = 0
    strong_advance_count = 0
    real_initialize = simulator_module.initialize_strategy
    real_advance = simulator_module.advance_publication
    real_strong_initialize = simulator_module.initialize_strong_strategy
    real_strong_advance = simulator_module.advance_strong_publication

    def observed_initialize(*args: object, **kwargs: object):
        nonlocal init_count
        init_count += 1
        return real_initialize(*args, **kwargs)

    def observed_advance(*args: object, **kwargs: object):
        nonlocal advance_count
        advance_count += 1
        return real_advance(*args, **kwargs)

    def observed_strong_initialize(*args: object, **kwargs: object):
        nonlocal strong_init_count
        strong_init_count += 1
        return real_strong_initialize(*args, **kwargs)

    def observed_strong_advance(*args: object, **kwargs: object):
        nonlocal strong_advance_count
        strong_advance_count += 1
        return real_strong_advance(*args, **kwargs)

    monkeypatch.setattr(simulator_module, "initialize_strategy", observed_initialize)
    monkeypatch.setattr(simulator_module, "advance_publication", observed_advance)
    monkeypatch.setattr(
        simulator_module,
        "initialize_strong_strategy",
        observed_strong_initialize,
    )
    monkeypatch.setattr(
        simulator_module,
        "advance_strong_publication",
        observed_strong_advance,
    )

    _evaluate_causal_cell(
        windows=windows,
        initial_state={},
        base_config=SimulationConfig(
            rows=1,
            cols=1,
            effective_slots=128,
            partition_rows=1,
            matrix_value_bound=7,
            max_row_nnz=1,
            reserved_slack_beta=0.1,
            periodic_repack_windows=4,
            packed_coo_segment_capacity=128,
        ),
        split=(Fraction(0), Fraction(1, 3), Fraction(2, 3)),
        costs=UnitCosts(),
        catalog=_registered_catalog(),
        simulate_targets_fn=simulator_module.simulate_targets_causal,
        simulate_strong_fn=simulator_module.simulate_strong_reference_causal,
    )

    assert init_count == 13
    assert advance_count == 39
    assert strong_init_count == 1
    assert strong_advance_count == 3


@pytest.mark.parametrize("multiplier", [3, 10, 30, 100])
def test_integer_rho_scaling_is_exactly_equal_to_direct_causal_replay(
    multiplier: int,
) -> None:
    initial = {(0, 0): 1, (1, 0): 2}
    unit_windows = [
        PublicationWindow(
            index,
            index,
            index + 1,
            updates,
            1,
            "query",
        )
        for index, updates in enumerate(
            (
                (NetUpdate(0, 0, 1, 2),),
                (NetUpdate(0, 1, 0, 3),),
                (NetUpdate(1, 0, 2, 0),),
                (NetUpdate(0, 1, 3, 4),),
                (NetUpdate(1, 1, 0, 5),),
                (NetUpdate(1, 2, 0, 6),),
                (NetUpdate(1, 1, 5, 0),),
                (NetUpdate(0, 2, 0, 7),),
            )
        )
    ]
    scaled_windows = [replace(window, query_count=multiplier) for window in unit_windows]
    config = SimulationConfig(
        rows=2,
        cols=6,
        effective_slots=128,
        partition_rows=2,
        matrix_value_bound=7,
        max_row_nnz=6,
        reserved_slack_beta=0.1,
        periodic_repack_windows=4,
        packed_coo_segment_capacity=128,
    )
    arguments = {
        "initial_state": initial,
        "base_config": config,
        "split": (Fraction(1, 4), Fraction(1, 2), Fraction(1, 4)),
        "costs": UnitCosts(),
        "catalog": _registered_catalog(),
        "simulate_targets_fn": simulator_module.simulate_targets_causal,
        "simulate_strong_fn": simulator_module.simulate_strong_reference_causal,
    }

    unit = _evaluate_causal_cell(windows=unit_windows, **arguments)
    direct_scaled = _evaluate_causal_cell(windows=scaled_windows, **arguments)

    assert run_day1_suite._query_scaled_windows(  # noqa: SLF001
        unit_windows,
        scaled_windows,
        multiplier,
    )
    rescaled = run_day1_suite._rescale_causal_cell_queries(  # noqa: SLF001
        unit,
        multiplier,
        UnitCosts(),
    )
    assert rescaled == direct_scaled
    unit_span80 = run_day1_suite._candidate_span80(config.rows, unit)  # noqa: SLF001
    assert run_day1_suite._candidate_span80(  # noqa: SLF001
        config.rows,
        rescaled,
    ) == run_day1_suite._candidate_span80(  # noqa: SLF001
        config.rows,
        direct_scaled,
    ) == unit_span80


def test_integer_rho_scaling_rejects_a_spliced_selection_candidate_pool() -> None:
    metrics = StrategyMetrics("PaddingReuse-CSSC", "reference")
    result = CausalCellResult(
        warmup_end=1,
        tuning_end=2,
        tuning_results={"padding-reuse": SimulationResult(metrics, {})},
        fixed_results={"padding-reuse": SimulationResult(metrics, {})},
        selected_candidate_id="padding-reuse",
        tuned_policy=metrics,
        oracle_candidate_id="padding-reuse",
        offline_oracle=metrics,
        selection_candidates=(),
    )

    with pytest.raises(ValueError, match="selection candidates"):
        run_day1_suite._rescale_causal_cell_queries(result, 3, UnitCosts())  # noqa: SLF001


def test_suite_preflights_once_before_plan_and_materializes_each_cell_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    query_scaled_ratios = (1, 3, 10, 30, 100)
    plan_payload = _small_experiment_plan()
    synthetic = plan_payload["synthetic"]
    assert isinstance(synthetic, dict)
    synthetic["queries_per_update_grid"] = list(query_scaled_ratios)
    calls: list[str] = []
    generated = 0
    windowized = 0
    span80_calls = 0
    initial_parameters: list[tuple[tuple[object, ...], dict[str, object]]] = []
    event_parameters: list[dict[str, object]] = []
    freshness_values: list[float] = []
    cell_configs: list[SimulationConfig] = []
    written: list[tuple[Path, list[object], dict[str, object]]] = []
    audit_calls: list[dict[str, object]] = []

    def fake_manifest(_path: object) -> dict[str, object]:
        calls.append("manifest")
        return {
            "freshness": {
                "max_seconds": 10.0,
                "microbatch_max_updates": 10,
                "query_requires_latest": True,
            },
            "packing": {"effective_slots": 8},
            "integer_correctness": {"matrix_entry_abs_bound": 7},
            "matrix": {"max_nnz_per_row": 4},
        }

    def fake_preflight(_manifest: object) -> PreflightReport:
        calls.append("preflight")
        return PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        )

    def fake_plan(_path: object) -> run_day1_suite.ExperimentPlan:
        calls.append("plan")
        return run_day1_suite.parse_experiment_plan(plan_payload)

    def fake_initial(*args: object, **kwargs: object) -> dict[tuple[int, int], int]:
        calls.append("initial")
        initial_parameters.append((args, kwargs))
        return {(0, 0): 5}

    def fake_events(*_args: object, **kwargs: object) -> list[Event]:
        nonlocal generated
        generated += 1
        event_parameters.append(kwargs)
        return [Event.set(float(index), 0, 1, 1) for index in range(10)]

    def fake_windows(*_args: object, **kwargs: object):
        nonlocal windowized
        windowized += 1
        freshness_values.append(float(kwargs["max_seconds"]))
        query_count = query_scaled_ratios[windowized - 1]
        for index in range(10):
            updates = (NetUpdate(0, 0, 0, 1),) if index == 4 else ()
            yield PublicationWindow(index, index, index + 1, updates, query_count, "fixture")

    def fake_cell(**kwargs: object) -> CausalCellResult:
        cell_configs.append(kwargs["base_config"])  # type: ignore[arg-type]
        catalog = _registered_catalog()
        fixed = {}
        for index, candidate in enumerate(catalog.candidates):
            overflow_by_row = {}
            if index == 0:
                overflow_by_row = {0: 4}
            elif index == 1:
                overflow_by_row = {0: 1, 1: 1}
            fixed[candidate.candidate_id] = SimulationResult(
                StrategyMetrics(
                    candidate.strategy,
                    candidate.role,
                    source="persistent-state-predicted",
                ),
                overflow_by_row,
            )
        selected_id = catalog.selection_candidates[0].candidate_id
        return CausalCellResult(
            warmup_end=1,
            tuning_end=4,
            tuning_results={
                candidate.candidate_id: fixed[candidate.candidate_id]
                for candidate in catalog.selection_candidates
            },
            fixed_results=fixed,
            selected_candidate_id=selected_id,
            tuned_policy=StrategyMetrics(
                "TunedFixedPolicy",
                "tuned-fixed-policy",
                source="tuning-prefix-frozen",
            ),
            oracle_candidate_id=selected_id,
            offline_oracle=StrategyMetrics(
                "BestFixed-Offline-Oracle",
                "diagnostic-oracle",
                source="held-out-hindsight-diagnostic",
            ),
            selection_candidates=tuple(
                FixedCandidate(
                    candidate_id=candidate.candidate_id,
                    strategy=candidate.strategy,
                    reserved_slack_beta=candidate.reserved_slack_beta,
                    periodic_repack_windows=candidate.periodic_repack_windows,
                    packed_coo_segment_capacity=candidate.packed_coo_segment_capacity,
                )
                for candidate in catalog.selection_candidates
            ),
        )

    monkeypatch.setattr(run_day1_suite, "load_manifest", fake_manifest)
    monkeypatch.setattr(run_day1_suite, "run_day1_preflight", fake_preflight)
    monkeypatch.setattr(run_day1_suite, "load_experiment_plan", fake_plan, raising=False)
    monkeypatch.setattr(run_day1_suite, "generate_initial_matrix", fake_initial)
    monkeypatch.setattr(run_day1_suite, "generate_event_stream", fake_events)
    monkeypatch.setattr(run_day1_suite, "publication_windows", fake_windows)
    monkeypatch.setattr(run_day1_suite, "evaluate_causal_cell", fake_cell)
    real_candidate_span80 = run_day1_suite._candidate_span80  # noqa: SLF001

    def counted_candidate_span80(
        rows: int,
        result: CausalCellResult,
    ) -> dict[str, dict[int, float]]:
        nonlocal span80_calls
        span80_calls += 1
        return real_candidate_span80(rows, result)

    monkeypatch.setattr(run_day1_suite, "_candidate_span80", counted_candidate_span80)

    def fake_records(
        path: Path,
        items: list[object],
        _costs: object,
        metadata: dict[str, object],
        **audit: object,
    ) -> None:
        written.append((path, items, metadata))
        audit_calls.append(audit)

    def fake_report_output(*_args: object, **audit: object) -> None:
        audit_calls.append(audit)

    monkeypatch.setattr(run_day1_suite, "write_causal_records", fake_records, raising=False)
    monkeypatch.setattr(
        run_day1_suite,
        "write_causal_summary",
        fake_report_output,
        raising=False,
    )
    monkeypatch.setattr(run_day1_suite, "write_causal_plots", fake_report_output)

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text('{"fixture": true}\n', encoding="utf-8")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan_payload), encoding="utf-8")

    args = argparse.Namespace(
        manifest=str(manifest_path),
        experiment_plan=str(plan_path),
        output_dir=tmp_path / "out",
        seed=7,
        workload="zipf",
        freshness_seconds="1",
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
        effective_slots=None,
        partition_rows=None,
    )

    assert run_suite(args) == 0
    assert calls == ["manifest", "preflight", "plan", "initial"]
    assert generated == len(query_scaled_ratios)
    assert windowized == len(query_scaled_ratios)
    assert span80_calls == 1
    assert initial_parameters == [((2, 2, 1), {"seed": 7, "matrix_entry_abs_bound": 7})]
    assert event_parameters == [
        {
            "rows": 2,
            "cols": 2,
            "update_count": 10,
            "seed": 8,
            "query_every": 0,
            "matrix_entry_abs_bound": 7,
        }
    ] * len(query_scaled_ratios)
    assert freshness_values == [1.0] * len(query_scaled_ratios)
    assert len(cell_configs) == 1
    assert cell_configs[0].effective_slots == 2048
    assert cell_configs[0].partition_rows == 128
    assert len(written) == len(query_scaled_ratios)
    path, items, metadata = written[0]
    assert path.relative_to(args.output_dir).as_posix() == "zipf/freshness-n1d1s/rho-n1d1"
    expected_candidates = _registered_catalog().candidates
    assert [item.record_kind for item in items].count("fixed-candidate") == len(expected_candidates)
    assert [item.record_kind for item in items].count("tuned-fixed-policy") == 1
    assert [item.record_kind for item in items].count("diagnostic-oracle") == 1
    assert len(audit_calls) == 3 * len(query_scaled_ratios)
    for index, (_, _, cell_metadata) in enumerate(written):
        cell_audits = audit_calls[index * 3 : (index + 1) * 3]
        assert all(
            call["selected_candidate_id"] == cell_metadata["selected_candidate_id"]
            for call in cell_audits
        )
        assert all(
            call["oracle_candidate_id"] == cell_metadata["oracle_candidate_id"]
            for call in cell_audits
        )
    assert all(
        set(call["tuning_results"])
        == {candidate.candidate_id for candidate in _registered_catalog().selection_candidates}
        for call in audit_calls
    )  # type: ignore[arg-type]
    span80_by_candidate = metadata["span80_by_candidate"]
    assert isinstance(span80_by_candidate, dict)
    assert set(span80_by_candidate) == {candidate.candidate_id for candidate in expected_candidates}
    assert span80_by_candidate["padding-reuse"][1] == 0.5
    assert span80_by_candidate["mini-cssc-delta"][1] == 1.0
    assert all(call[2]["span80_by_candidate"] == span80_by_candidate for call in written)
    assert [
        call[2]["query_scaling_source_rho_fraction"] for call in written
    ] == [None, "1", "1", "1", "1"]
    assert len(
        {
            json.dumps(call[2]["span80_by_candidate"], sort_keys=True, allow_nan=False)
            for call in written
        }
    ) == 1
    assert metadata["effective_slots"] == 2048
    assert metadata["partition_rows"] == 128
    assert metadata["layout_measurement_kind"] == "synthetic-proxy"
    trace_header = json.loads((path / "event-window-trace.jsonl").read_text().splitlines()[0])
    assert trace_header["schema"] == "day1-event-window-trace-v2"
    assert trace_header["effective_slots"] == 2048
    assert trace_header["partition_rows"] == 128
    assert trace_header["layout_measurement_kind"] == "synthetic-proxy"
    assert trace_header["query_requires_latest"] is True
    assert not (args.output_dir / "SUITE_STATUS.json").exists()
    shard_status = json.loads((args.output_dir / "SHARD_STATUS.json").read_text(encoding="utf-8"))
    assert shard_status["suite_complete"] is False
    assert len(shard_status["cells"]) == len(query_scaled_ratios)
    assert shard_status["complete_reference_set"] is True
    assert shard_status["fixed_candidate_count"] == 14
    assert shard_status["reference_candidate_count"] == 13
    assert shard_status["ablation_candidate_count"] == 1
    assert shard_status["reference_candidate_ids"] == sorted(
        candidate.candidate_id for candidate in _registered_catalog().selection_candidates
    )
    assert shard_status["ablation_candidate_ids"] == ["packed-coo-client-lane-delta/capacity=128"]
    assert set(shard_status["cells"][0]) == {
        "cell_checksums_sha256",
        "event_window_trace_sha256",
        "relative_path",
        "rho_fraction",
        "rho_id",
    }
    assert shard_status["deferred_reference_baselines"] == []
    assert shard_status["security_claim_allowed"] is False
    assert shard_status["formal_performance_claim"] is False
    assert shard_status["deferred_unpriced_plan_dimensions"] == ["bandwidth_profiles_mbps"]
    assert shard_status["planned_bandwidth_profiles_mbps"] == [100.0]
    assert shard_status["effective_slots"] == 2048
    assert shard_status["partition_rows"] == 128
    assert shard_status["layout_measurement_kind"] == "synthetic-proxy"
    assert shard_status["candidate_ids"] == sorted(
        candidate.candidate_id for candidate in expected_candidates
    )


def test_suite_rejects_missing_plan_fields_before_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_day1_suite,
        "load_manifest",
        lambda _path: {
            "integer_correctness": {"matrix_entry_abs_bound": 7},
            "freshness": {"max_seconds": 1, "microbatch_max_updates": 1},
            "packing": {"effective_slots": 8},
            "matrix": {"max_nnz_per_row": 2},
        },
    )
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        ),
    )
    incomplete_plan = _small_experiment_plan()
    del incomplete_plan["reserved_slack_betas"]
    monkeypatch.setattr(
        run_day1_suite,
        "load_experiment_plan",
        lambda _path: run_day1_suite.parse_experiment_plan(incomplete_plan),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("generation must not start"),
    )
    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=Path("unused"),
        seed=7,
        workload="zipf",
        freshness_seconds="1",
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
    )

    with pytest.raises(ValueError, match="experiment plan keys"):
        run_suite(args)
