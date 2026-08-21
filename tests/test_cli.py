from __future__ import annotations

import json
from pathlib import Path

import pytest

from dynamic_cssc import cli
from dynamic_cssc.cli import build_parser
from dynamic_cssc.simulator import SimulationConfig


def test_smoke_cli_rejects_an_unknown_workload() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit) as error:
        parser.parse_args(
            [
                "smoke",
                "--output-dir",
                "unused",
                "--seed",
                "7",
                "--workload",
                "typo-workload",
            ]
        )

    assert error.value.code == 2


def test_smoke_cli_passes_the_persistent_config_and_labels_proxy_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        cli,
        "load_manifest",
        lambda _path: {
            "integer_correctness": {"matrix_entry_abs_bound": 9},
            "matrix": {"max_nnz_per_row": 3},
            "freshness": {
                "max_seconds": 1,
                "microbatch_max_updates": 4,
                "query_requires_latest": True,
            },
            "packing": {"effective_slots": 16},
        },
    )
    monkeypatch.setattr(cli, "generate_initial_matrix", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(cli, "generate_event_stream", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(cli, "publication_windows", lambda *_args, **_kwargs: iter(()))

    def fake_simulate_targets(_windows, _initial, targets, *, measure_from):
        captured["targets"] = targets
        captured["measure_from"] = measure_from
        return {}

    def fake_write_records(path, _metrics, _costs, metadata):
        path.mkdir(parents=True, exist_ok=True)
        captured["metadata"] = metadata

    monkeypatch.setattr(cli, "simulate_targets", fake_simulate_targets)
    monkeypatch.setattr(cli, "write_records", fake_write_records)
    monkeypatch.setattr(cli, "write_summary", lambda *_args: None)
    monkeypatch.setattr(cli, "write_plots", lambda *_args: None)
    monkeypatch.setattr(cli, "write_checksums", lambda *_args: None)
    output_dir = tmp_path / "smoke"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dynamic-cssc",
            "smoke",
            "--output-dir",
            str(output_dir),
            "--seed",
            "7",
            "--rows",
            "2",
            "--cols",
            "3",
            "--periodic-repack-period",
            "6",
            "--coo-segment-capacity",
            "8",
        ],
    )

    assert cli.main() == 0
    targets = captured["targets"]
    assert captured["measure_from"] == 0
    assert len(targets) == 6
    assert len({id(target.config) for target in targets}) == 1
    config = targets[0].config
    assert config.cols == 3
    assert config.matrix_value_bound == 9
    assert config.max_row_nnz == 3
    assert config.periodic_repack_windows == 6
    assert not hasattr(config, "periodic_repack_period")
    metadata = captured["metadata"]
    assert metadata["state_model"] == "persistent-strategy-snapshots"
    assert metadata["measurement_kind"] == "predicted-proxy"
    assert metadata["gate_eligible"] is False
    assert metadata["complete_cost_claim_allowed"] is False
    assert "status" not in metadata
    written_metadata = json.loads(
        (output_dir / "metadata.json").read_text(encoding="utf-8")
    )
    assert written_metadata["state_model"] == metadata["state_model"]
    assert written_metadata["measurement_kind"] == metadata["measurement_kind"]
    assert written_metadata["complete_cost_claim_allowed"] is False


def test_simulation_config_rejects_the_removed_period_alias() -> None:
    with pytest.raises(TypeError, match="periodic_repack_period"):
        SimulationConfig(
            rows=2,
            cols=3,
            effective_slots=4,
            partition_rows=2,
            matrix_value_bound=7,
            max_row_nnz=3,
            reserved_slack_beta=0.1,
            periodic_repack_windows=4,
            packed_coo_segment_capacity=4,
            periodic_repack_period=4,  # type: ignore[call-arg]
        )
