from __future__ import annotations

import bz2
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from inspect import signature
from pathlib import Path

import pytest

import dynamic_cssc.day1_registry as registry_module
import dynamic_cssc.publication_day1b as day1b_module
import dynamic_cssc.publication_statistics as statistics_module
from dynamic_cssc.day1_registry import Day1CandidateCatalog, RegistrationEvidence
from dynamic_cssc.publication_day1b import (
    DAY1B_UNIT_FRAGMENT_SCHEMA,
    DAY1B_UNIT_SCHEMA,
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
    PublicationDay1BCellMeasurements,
    PublicationDay1BHold,
    PublicationDay1BMeasurement,
    PublicationDay1BResourcePolicy,
    PublicationDay1BSerializedCategory,
    PublicationDay1BSerializedObject,
    _Day1BSourceAuthority,
    _Day1BTraceInput,
    _produce_publication_day1b_unit_for_test,
    _PublicationScheduleAdapter,
    produce_publication_day1b_unit,
)
from dynamic_cssc.publication_schedule import (
    ACCEPTED_EVENT_SCHEDULE_SCHEMA,
    AcceptedGroupPhaseRange,
    ExactPublicationWindow,
    ScheduledNetUpdate,
    _load_publication_trace_bundle_for_test,
)
from dynamic_cssc.publication_statistics import (
    CELL_BINDING_SCHEMA,
    FIXED_CANDIDATE_IDS,
    FRESHNESS_VALUES,
    HELDOUT_RECORD_SCHEMA,
    PRIMITIVE_NAMES,
    QUERY_VECTOR_SCHEMA,
    REFERENCE_CANDIDATE_IDS,
    RHO_VALUES,
    TRACE_UNIT_SCHEMA,
)
from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    PUBLICATION_TRACE_MANIFEST_SCHEMA,
    LicenseTermsObject,
    LocalSourceObject,
    _LocalTraceRequest,
    _prepare_publication_trace,
    _test_only_repository_snapshot,
)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _trace_v6_history_row(*, timestamp: datetime, user_id: int) -> str:
    fields = [""] * 78
    fields[0] = "simplewiki"
    fields[2] = "revision"
    fields[3] = "create"
    fields[4] = timestamp.strftime("%Y-%m-%d %H:%M:%S.0")
    fields[6] = str(user_id)
    fields[19] = "false"
    fields[20] = "false"
    fields[21] = "true"
    fields[28] = "2"
    fields[31] = "0"
    return "\t".join(fields) + "\n"


def _write_trace_v6_fixture(tmp_path: Path) -> Path:
    source_path = tmp_path / "history.tsv.bz2"
    start = datetime(2020, 1, 1, tzinfo=UTC)
    rows = "".join(
        _trace_v6_history_row(
            timestamp=start + timedelta(seconds=index),
            user_id=1 + index % 10,
        )
        for index in range(100)
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)

    terms_path = tmp_path / "mediawiki-history-readme.html"
    terms_path.write_text("<html>CC0 fixture terms</html>\n", encoding="utf-8")
    terms_bytes = terms_path.read_bytes()
    source_bytes = source_path.read_bytes()
    source_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    source = LocalSourceObject(
        role="history",
        path=source_path,
        source_url=source_url,
        final_url=source_url,
        http_status=200,
        media_type="application/octet-stream",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(source_bytes),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(source_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=(
            LicenseTermsObject(
                source_url=terms_url,
                final_url=terms_url,
                http_status=200,
                media_type="text/html",
                retrieval_utc="2026-08-23T00:00:00Z",
                http_etag=None,
                http_last_modified=None,
                section_anchor=None,
                path=terms_path,
                byte_count=len(terms_bytes),
                sha256=hashlib.sha256(terms_bytes).hexdigest(),
            ),
        ),
        attribution_text="Wikimedia Analytics MediaWiki History (CC0)",
    )
    bundle = _prepare_publication_trace(
        _LocalTraceRequest(
            dataset_id="simplewiki-2026-07",
            semantics="T1",
            source_partition=0,
            sources=(source,),
        ),
        config=replace(
            _PRODUCTION_CONFIG,
            rows=1,
            cols=10,
            target_accepted_events=70,
            minimum_logical_changes=70,
            minimum_complete_window_lower_bound=1,
            maximum_row_nonzeros=10,
        ),
        repository_snapshot=_test_only_repository_snapshot(),
    )
    trace_dir = tmp_path / "trace-v6"
    trace_dir.mkdir()
    artifacts = {
        "publication-trace-manifest.json": bundle.manifest_bytes,
        "publication-trace.jsonl": bundle.trace_jsonl_bytes,
        "publication-query-vector.json": bundle.query_vector_bytes,
    }
    for name, content in artifacts.items():
        (trace_dir / name).write_bytes(content)
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in artifacts.items()
    )
    (trace_dir / "checksums.sha256").write_text(checksums, encoding="ascii")
    return trace_dir


def _catalog() -> Day1CandidateCatalog:
    return Day1CandidateCatalog(
        candidates=registry_module._canonical_registered_candidates(),
        registration=RegistrationEvidence(
            schema_version="dynamic-cssc-day1-registration-evidence-v1",
            source_git_sha="1" * 40,
            run_id=123,
            correctness_artifact_sha256="2" * 64,
            accounting_evidence_sha256="3" * 64,
            policy_contract_sha256=(
                "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
            ),
        ),
    )


def _program(
    rho: Fraction,
    *,
    total: int = 1_000,
    t2_cardinality: bool = False,
) -> _PublicationScheduleAdapter:
    ranges = (
        AcceptedGroupPhaseRange("warmup", 0, total // 10),
        AcceptedGroupPhaseRange("tuning", total // 10, total * 4 // 10),
        AcceptedGroupPhaseRange("heldout", total * 4 // 10, total),
    )

    def group_set_count(ordinal: int) -> int:
        if not t2_cardinality:
            return 1
        if ordinal < total // 10:
            return 0
        if ordinal < total * 4 // 10:
            return 2
        return 1

    def schedule_bytes() -> object:
        yield _canonical_bytes(
            {
                "schema_version": ACCEPTED_EVENT_SCHEDULE_SCHEMA,
                "record_kind": "accepted-event-schedule-header",
                "accepted_group_count": total,
                "rho": {"numerator": rho.numerator, "denominator": rho.denominator},
            }
        )
        for ordinal in range(total):
            before = ordinal * rho.numerator // rho.denominator
            after = (ordinal + 1) * rho.numerator // rho.denominator
            yield _canonical_bytes(
                {
                    "schema_version": ACCEPTED_EVENT_SCHEDULE_SCHEMA,
                    "record_kind": "accepted-event-group",
                    "accepted_event_ordinal": ordinal,
                    "events": [
                        *({"kind": "set"} for _ in range(group_set_count(ordinal))),
                        {"kind": "tick"},
                        {
                            "kind": "query-run",
                            "first_query_ordinal": before,
                            "count": after - before,
                        },
                    ],
                }
            )

    digest = hashlib.sha256()
    for chunk in schedule_bytes():
        digest.update(chunk)

    def windows(_freshness: Fraction) -> object:
        for index, phase in enumerate(ranges):
            query_count = (phase.end * rho.numerator // rho.denominator) - (
                phase.start * rho.numerator // rho.denominator
            )
            set_count = sum(group_set_count(ordinal) for ordinal in range(phase.start, phase.end))
            yield ExactPublicationWindow(
                index=index,
                phase=phase.name,
                accepted_group_start=phase.start,
                accepted_group_end=phase.end,
                start_time=Fraction(phase.start, 128),
                end_time=Fraction(phase.end - 1, 128),
                set_count=set_count,
                updates=tuple(
                    ScheduledNetUpdate(row=0, col=ordinal, before=index, after=index + 1)
                    for ordinal in range(set_count)
                ),
                query_count=query_count,
                reason=f"phase-boundary:{phase.name}",
            )

    return _PublicationScheduleAdapter(
        schema_version=ACCEPTED_EVENT_SCHEDULE_SCHEMA,
        rho=rho,
        phase_ranges=ranges,
        accepted_group_count=total,
        total_set_count=sum(group_set_count(ordinal) for ordinal in range(total)),
        total_query_count=total * rho.numerator // rho.denominator,
        canonical_schedule_sha256=digest.hexdigest(),
        iter_canonical_bytes=schedule_bytes,
        stream_windows=windows,
    )


def _trace() -> _Day1BTraceInput:
    query_vector = {"schema_version": QUERY_VECTOR_SCHEMA, "values": [1, 0, -1]}
    query_vector_bytes = _canonical_bytes(query_vector)
    return _Day1BTraceInput(
        dataset_id="simplewiki-2026-07",
        dataset_release="mediawiki-history-2026-07-simplewiki-all-time",
        semantics="T1",
        source_partition=0,
        trace_source_git_sha="4" * 40,
        repository_provenance_sha256="5" * 64,
        trace_manifest_sha256="6" * 64,
        mapping_sha256="7" * 64,
        accepted_events_sha256="8" * 64,
        replay_receipt_sha256="9" * 64,
        source_bundle_sha256="a" * 64,
        acquisition_transaction_sha256=None,
        source_set_sha256=None,
        acquisition_network_authority_verified=False,
        accepted_group_count=1_000,
        query_vector=(1, 0, -1),
        query_vector_canonical_bytes=query_vector_bytes,
        query_vector_sha256=hashlib.sha256(query_vector_bytes).hexdigest(),
        compile_schedule=_program,
    )


def _source() -> _Day1BSourceAuthority:
    inventory = {
        "behavior_set_schema_version": "dynamic-cssc-day1b-behavior-set-v1",
        "behavior_set_sha256": "c" * 64,
        "entries": [],
        "role": "day1b",
        "schema_version": "dynamic-cssc-evidence-behavior-inventory-v1",
        "source_git_sha": "1" * 40,
    }
    return _Day1BSourceAuthority(
        git_sha="1" * 40,
        behavior_inventory=inventory,
        source_attestation="test-only-typed-day1b-source",
    )


def _resource_policy() -> PublicationDay1BResourcePolicy:
    return PublicationDay1BResourcePolicy(
        wall_clock_seconds_per_cell=600,
        resident_memory_bytes=2_000_000_000,
        scratch_bytes_per_cell=4_000_000_000,
        output_bytes_per_unit=8_000_000_000,
        cells_per_shard=18,
        max_concurrency=1,
        candidate_retry_count=0,
        infrastructure_preemption_whole_shard_rerun_limit=1,
        authority="test-only-outcome-blind-fixed-policy",
    )


def _measurement(seed: int) -> PublicationDay1BMeasurement:
    return PublicationDay1BMeasurement(
        outcome="complete",
        failure_reason=None,
        update_primitive_counts=tuple(seed + index for index in range(len(PRIMITIVE_NAMES))),
        query_primitive_counts=tuple(seed + 100 + index for index in range(len(PRIMITIVE_NAMES))),
        serialized_categories=tuple(
            PublicationDay1BSerializedCategory(
                category=category,
                objects=(
                    PublicationDay1BSerializedObject(
                        serialized_bytes=f"{seed}:{category}".encode("ascii"),
                        multiplicity=2,
                    ),
                ),
            )
            for category, _transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
        ),
    )


class _StreamingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[Fraction, Fraction, int]] = []

    def execute_cell(self, **kwargs: object) -> PublicationDay1BCellMeasurements:
        windows = kwargs["windows"]
        window_count = 0
        for _window in windows:
            window_count += 1
        self.calls.append((kwargs["freshness"], kwargs["rho"], window_count))
        return PublicationDay1BCellMeasurements(
            tuning_references=tuple(
                _measurement(index + 1) for index in range(len(REFERENCE_CANDIDATE_IDS))
            ),
            heldout_fixed=tuple(
                _measurement(index + 101) for index in range(len(FIXED_CANDIDATE_IDS))
            ),
            peak_resident_memory_bytes=250_000_000,
            peak_scratch_bytes=500_000_000,
        )


def test_repository_loader_consumes_trace_v6_acquisition_binding_and_preserves_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace_dir = _write_trace_v6_fixture(tmp_path)
    monkeypatch.setattr(
        day1b_module,
        "load_publication_trace_bundle",
        _load_publication_trace_bundle_for_test,
    )

    trace = day1b_module._load_repository_trace_input(trace_dir)
    manifest = json.loads((trace_dir / "publication-trace-manifest.json").read_bytes())
    acquisition_binding = manifest["acquisition_binding"]
    authority = acquisition_binding["authority"]

    assert manifest["schema_version"] == PUBLICATION_TRACE_MANIFEST_SCHEMA
    assert "acquisition_verification" not in manifest
    assert trace.source_bundle_sha256 == _sha(acquisition_binding)
    assert (
        trace.acquisition_transaction_sha256
        == (acquisition_binding["acquisition_transaction_sha256"])
    )
    assert trace.source_set_sha256 == acquisition_binding["source_set_sha256"]
    assert authority["state"] == "HOLD-test-only-local-source-fixture"
    assert authority["formal_authority_granted"] is False
    assert authority["acquisition_network_authority_verified"] is False
    assert trace.acquisition_network_authority_verified is False
    assert trace.trace_source_authority_verified is False


def test_public_producer_is_two_path_deep_seam_and_holds_before_writing(
    tmp_path: Path,
) -> None:
    assert tuple(signature(produce_publication_day1b_unit).parameters) == (
        "trace_bundle_dir",
        "output_dir",
    )
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    output_dir = tmp_path / "unit"

    with pytest.raises(PublicationDay1BHold, match="DAY1B.*Behavior Set|Behavior Set.*DAY1B"):
        produce_publication_day1b_unit(trace_dir, output_dir)

    assert not output_dir.exists()


def test_cli_exposes_only_the_two_public_paths_and_preserves_the_hold(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    output_dir = tmp_path / "unit"
    environment = {**os.environ, "PYTHONPATH": str(repository_root / "src")}

    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "run_publication_day1b.py"),
            "--trace-bundle-dir",
            str(trace_dir),
            "--output-dir",
            str(output_dir),
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "HOLD" in result.stderr
    assert result.stdout == ""
    assert not output_dir.exists()


def test_private_typed_core_writes_one_stats_composable_18_cell_486_record_unit(
    tmp_path: Path,
) -> None:
    executor = _StreamingExecutor()
    output_dir = tmp_path / "unit"

    bundle = _produce_publication_day1b_unit_for_test(
        trace=_trace(),
        output_dir=output_dir,
        source_authority=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=executor,
    )

    manifest = json.loads(bundle.manifest_path.read_bytes())
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
    schedule_lines = bundle.schedule_path.read_bytes().splitlines()
    ledger_lines = bundle.serialization_ledger_path.read_bytes().splitlines()
    trace_unit = fragment["trace_units"][0]
    cells = fragment["cell_bindings"]
    records = fragment["records"]

    assert manifest["schema_version"] == DAY1B_UNIT_SCHEMA
    assert fragment["schema_version"] == DAY1B_UNIT_FRAGMENT_SCHEMA
    assert trace_unit["schema_version"] == TRACE_UNIT_SCHEMA
    assert set(trace_unit) == statistics_module._TRACE_UNIT_KEYS
    assert len(cells) == 18
    assert len(records) == 486
    assert len(ledger_lines) == 486
    assert len(executor.calls) == 18
    assert all(window_count == 3 for _freshness, _rho, window_count in executor.calls)
    assert [cell["freshness_seconds"] for cell in cells] == [
        freshness for freshness in FRESHNESS_VALUES for _rho in RHO_VALUES
    ]
    assert [cell["rho"] for cell in cells] == list(RHO_VALUES) * len(FRESHNESS_VALUES)
    assert all(cell["schema_version"] == CELL_BINDING_SCHEMA for cell in cells)
    assert all(set(cell) == statistics_module._CELL_BINDING_KEYS for cell in cells)
    assert all(
        cell["event_schedule_schema_version"] == ACCEPTED_EVENT_SCHEDULE_SCHEMA for cell in cells
    )
    assert len({cell["query_vector_sha256"] for cell in cells}) == 1
    for cell, receipt in zip(cells, manifest["cell_execution_receipts"], strict=True):
        phase_receipts = {row["phase"]: row for row in receipt["phase_receipts"]}
        assert cell["tuning_update_count"] == phase_receipts["tuning"]["accepted_event_group_count"]
        assert cell["tuning_query_count"] == phase_receipts["tuning"]["realized_query_count"]
        assert (
            cell["heldout_update_count"] == phase_receipts["heldout"]["accepted_event_group_count"]
        )
        assert cell["heldout_query_count"] == phase_receipts["heldout"]["realized_query_count"]
    for rho in RHO_VALUES:
        matching = [cell for cell in cells if cell["rho"] == rho]
        assert len(matching) == 2
        assert len({cell["event_schedule_sha256"] for cell in matching}) == 1
    assert all(record["schema_version"] == HELDOUT_RECORD_SCHEMA for record in records)
    decoded_records = tuple(
        statistics_module._decode_record(record, index, PRIMITIVE_NAMES)
        for index, record in enumerate(records)
    )
    assert len(decoded_records) == 486
    assert [record["candidate_id"] for record in records[:27]] == [
        *REFERENCE_CANDIDATE_IDS,
        *FIXED_CANDIDATE_IDS,
    ]
    assert [record["phase"] for record in records[:27]] == [
        *("tuning-prefix" for _ in REFERENCE_CANDIDATE_IDS),
        *("held-out" for _ in FIXED_CANDIDATE_IDS),
    ]
    assert set(records[0]["update_primitive_counts"]) == set(PRIMITIVE_NAMES)
    assert manifest["cardinality"] == {
        "cell_binding_count": 18,
        "physical_record_count": 486,
        "schedule_program_count": 9,
        "serialization_ledger_count": 486,
    }
    assert manifest["experiment_source"]["behavior_inventory"] == (_source().behavior_inventory)
    assert manifest["resource_policy"]["candidate_retry_count"] == 0
    assert {
        receipt["peak_resident_memory_bytes"] for receipt in manifest["cell_execution_receipts"]
    } == {250_000_000}
    assert {receipt["peak_scratch_bytes"] for receipt in manifest["cell_execution_receipts"]} == {
        500_000_000
    }
    assert manifest["authority"]["publication_claim_allowed"] is False
    assert (
        len([line for line in schedule_lines if b'"rho":{"denominator":1,"numerator":100}' in line])
        == 1
    )
    assert not any(b'"kind":"query"' in line for line in schedule_lines)
    assert sum(b'"kind":"query-run"' in line for line in schedule_lines) == 9_000
    assert (
        bundle.heldout_fragment_sha256
        == hashlib.sha256(bundle.heldout_fragment_path.read_bytes()).hexdigest()
    )


def test_t2_realized_set_cardinality_is_separate_from_stats_update_denominator(
    tmp_path: Path,
) -> None:
    trace = replace(
        _trace(),
        semantics="T2",
        compile_schedule=lambda rho: _program(rho, t2_cardinality=True),
    )
    bundle = _produce_publication_day1b_unit_for_test(
        trace=trace,
        output_dir=tmp_path / "unit",
        source_authority=_source(),
        candidate_catalog=_catalog(),
        resource_policy=_resource_policy(),
        execution_adapter=_StreamingExecutor(),
    )
    manifest = json.loads(bundle.manifest_path.read_bytes())
    fragment = json.loads(bundle.heldout_fragment_path.read_bytes())
    receipts_by_cell = {
        receipt["cell_binding_sha256"]: receipt for receipt in manifest["cell_execution_receipts"]
    }
    records_by_cell: dict[str, list[dict[str, object]]] = {}
    for record in fragment["records"]:
        records_by_cell.setdefault(record["cell_binding_sha256"], []).append(record)

    for index, cell in enumerate(fragment["cell_bindings"]):
        receipt = receipts_by_cell[cell["cell_binding_sha256"]]
        phases = {row["phase"]: row for row in receipt["phase_receipts"]}
        _total, _warmup, tuning, heldout, _digest = (
            statistics_module._decode_accepted_event_group_ranges(cell, f"cell[{index}]")
        )
        expected = (
            tuning[1] - tuning[0],
            statistics_module._phase_query_count(tuning, cell["rho"]),
            heldout[1] - heldout[0],
            statistics_module._phase_query_count(heldout, cell["rho"]),
        )
        assert (
            cell["tuning_update_count"],
            cell["tuning_query_count"],
            cell["heldout_update_count"],
            cell["heldout_query_count"],
        ) == expected
        assert phases["tuning"]["realized_set_count"] == 600
        assert phases["tuning"]["accepted_event_group_count"] == 300
        assert phases["heldout"]["realized_set_count"] == 600
        assert phases["heldout"]["accepted_event_group_count"] == 600
        for record in records_by_cell[cell["cell_binding_sha256"]]:
            decoded = statistics_module._decode_record(record, 0, PRIMITIVE_NAMES)
            expected_record_counts = (
                expected[:2] if decoded.phase == "tuning-prefix" else expected[2:]
            )
            assert (decoded.update_count, decoded.query_count) == expected_record_counts


def test_private_core_rejects_a_query_vector_splice_before_output(tmp_path: Path) -> None:
    trace = replace(_trace(), query_vector=(1, 1, -1))
    output_dir = tmp_path / "unit"

    with pytest.raises(ValueError, match="query vector.*artifact"):
        _produce_publication_day1b_unit_for_test(
            trace=trace,
            output_dir=output_dir,
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=_StreamingExecutor(),
        )

    assert not output_dir.exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("peak_resident_memory_bytes", -1, "resident-memory observation"),
        ("peak_scratch_bytes", -1, "scratch-byte observation"),
        ("peak_resident_memory_bytes", 2_000_000_001, "resident-memory limit"),
        ("peak_scratch_bytes", 4_000_000_001, "scratch-byte limit"),
    ),
)
def test_private_core_rejects_invalid_or_over_limit_cell_resource_observations(
    tmp_path: Path,
    field: str,
    value: int,
    message: str,
) -> None:
    class InvalidResourceExecutor(_StreamingExecutor):
        def execute_cell(self, **kwargs: object) -> PublicationDay1BCellMeasurements:
            result = super().execute_cell(**kwargs)
            return replace(result, **{field: value})

    output_dir = tmp_path / "unit"
    with pytest.raises((ValueError, PublicationDay1BHold), match=message):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=InvalidResourceExecutor(),
        )

    assert not output_dir.exists()


def test_private_core_rejects_missing_cell_resource_observations(tmp_path: Path) -> None:
    class MissingResourceExecutor(_StreamingExecutor):
        def execute_cell(self, **kwargs: object) -> object:
            for _window in kwargs["windows"]:
                pass
            return object()

    output_dir = tmp_path / "unit"
    with pytest.raises(TypeError, match="exact Day1B cell measurements"):
        _produce_publication_day1b_unit_for_test(
            trace=_trace(),
            output_dir=output_dir,
            source_authority=_source(),
            candidate_catalog=_catalog(),
            resource_policy=_resource_policy(),
            execution_adapter=MissingResourceExecutor(),
        )

    assert not output_dir.exists()
