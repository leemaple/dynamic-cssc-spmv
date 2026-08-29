from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dynamic_cssc.route_a_postrun_admission import (
    RouteAPostrunAdmissionError,
    inspect_route_a_postrun_admission,
    produce_route_a_postrun_admission,
)

RUN_ID = 71
HEAD = "a" * 40
JOBS = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
ARTIFACTS = (
    "q1-simulator-pre-replay-handoff",
    "q2-simulator-guarded-receipt",
    "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4-native-guarded-case-bundle",
    "q5-combined-guard-bundle",
)


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path.resolve()


def _provider_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    run = {
        "conclusion": None,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": HEAD,
        "id": RUN_ID,
        "run_attempt": 1,
        "status": "in_progress",
    }
    bounds = (
        ("2026-08-29T00:00:00Z", "2026-08-29T00:05:00Z"),
        ("2026-08-29T00:05:00Z", "2026-08-29T00:10:00Z"),
        ("2026-08-29T00:10:00Z", "2026-08-29T00:12:00Z"),
        ("2026-08-29T00:12:00Z", "2026-08-29T00:14:00Z"),
        ("2026-08-29T00:14:00Z", "2026-08-29T00:15:00Z"),
        ("2026-08-29T00:15:01Z", None),
    )
    jobs = []
    for ordinal, (name, (started, completed)) in enumerate(
        zip(JOBS, bounds, strict=True),
        start=1,
    ):
        jobs.append(
            {
                "completed_at": completed,
                "conclusion": "success" if completed is not None else None,
                "id": 200 + ordinal,
                "name": name,
                "started_at": started,
                "status": "completed" if completed is not None else "in_progress",
            }
        )
    artifacts = [
        {
            "digest": "sha256:" + str(ordinal) * 64,
            "expired": False,
            "id": 300 + ordinal,
            "name": name,
            "size_in_bytes": 100 + ordinal,
            "workflow_run": {"head_sha": HEAD},
        }
        for ordinal, name in enumerate(ARTIFACTS, start=1)
    ]
    return (
        _write(tmp_path / "run.json", run),
        _write(tmp_path / "jobs.json", {"jobs": jobs, "total_count": len(jobs)}),
        _write(
            tmp_path / "artifacts.json",
            {"artifacts": artifacts, "total_count": len(artifacts)},
        ),
    )


def _produce(tmp_path: Path):  # type: ignore[no-untyped-def]
    run, jobs, artifacts = _provider_files(tmp_path)
    return produce_route_a_postrun_admission(
        run_json_path=run,
        jobs_json_path=jobs,
        artifacts_json_path=artifacts,
        expected_run_id=RUN_ID,
        expected_s2_git_sha=HEAD,
        expected_head_branch="main",
        expected_run_attempt=1,
        output_directory=(tmp_path / "q6").resolve(),
        observed_at=datetime(2026, 8, 29, 0, 15, 10, tzinfo=UTC),
    )


def test_q6_records_only_q1_through_q5_final_state_and_own_start(tmp_path: Path) -> None:
    inspection = _produce(tmp_path)

    assert inspection.record["qualification_computational_seconds"] == 900
    assert inspection.record["native_c_q_seconds"] == 300
    assert inspection.record["native_six_c_q_seconds"] == 1800
    assert inspection.record["q6"] == {
        "databaseId": 206,
        "name": "qualification-postrun-resource-admission",
        "startedAt": "2026-08-29T00:15:01Z",
    }
    assert "completedAt" not in inspection.record["q6"]
    assert "conclusion" not in inspection.record["q6"]
    assert inspect_route_a_postrun_admission(inspection.root).record_sha256 == (
        inspection.record_sha256
    )


def test_q6_rejects_its_own_premature_terminal_projection(tmp_path: Path) -> None:
    run, jobs_path, artifacts = _provider_files(tmp_path)
    jobs = json.loads(jobs_path.read_text())
    jobs["jobs"][-1]["status"] = "completed"
    jobs["jobs"][-1]["conclusion"] = "success"
    jobs["jobs"][-1]["completed_at"] = "2026-08-29T00:15:10Z"
    jobs_path.write_text(json.dumps(jobs))

    with pytest.raises(RouteAPostrunAdmissionError, match="live in-progress"):
        produce_route_a_postrun_admission(
            run_json_path=run,
            jobs_json_path=jobs_path,
            artifacts_json_path=artifacts,
            expected_run_id=RUN_ID,
            expected_s2_git_sha=HEAD,
            expected_head_branch="main",
            expected_run_attempt=1,
            output_directory=(tmp_path / "q6").resolve(),
            observed_at=datetime(2026, 8, 29, 0, 15, 10, tzinfo=UTC),
        )


def test_q6_rejects_missing_or_extra_prefix_provider_artifact(tmp_path: Path) -> None:
    run, jobs, artifacts_path = _provider_files(tmp_path)
    artifacts = json.loads(artifacts_path.read_text())
    artifacts["artifacts"].append(
        {
            "digest": "sha256:" + "f" * 64,
            "expired": False,
            "id": 999,
            "name": "unexpected",
            "size_in_bytes": 1,
            "workflow_run": {"head_sha": HEAD},
        }
    )
    artifacts["total_count"] += 1
    artifacts_path.write_text(json.dumps(artifacts))

    with pytest.raises(RouteAPostrunAdmissionError, match="artifact set"):
        produce_route_a_postrun_admission(
            run_json_path=run,
            jobs_json_path=jobs,
            artifacts_json_path=artifacts_path,
            expected_run_id=RUN_ID,
            expected_s2_git_sha=HEAD,
            expected_head_branch="main",
            expected_run_attempt=1,
            output_directory=(tmp_path / "q6").resolve(),
            observed_at=datetime(2026, 8, 29, 0, 15, 10, tzinfo=UTC),
        )


def test_q6_rejects_observation_after_frozen_q5_plus_ten_minute_deadline(
    tmp_path: Path,
) -> None:
    run, jobs, artifacts = _provider_files(tmp_path)
    with pytest.raises(RouteAPostrunAdmissionError, match="screen did not pass"):
        produce_route_a_postrun_admission(
            run_json_path=run,
            jobs_json_path=jobs,
            artifacts_json_path=artifacts,
            expected_run_id=RUN_ID,
            expected_s2_git_sha=HEAD,
            expected_head_branch="main",
            expected_run_attempt=1,
            output_directory=(tmp_path / "q6").resolve(),
            observed_at=datetime(2026, 8, 29, 0, 25, 1, tzinfo=UTC),
        )
