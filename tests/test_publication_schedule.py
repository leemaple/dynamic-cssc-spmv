from __future__ import annotations

import bz2
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.publication_schedule as schedule_module
from dynamic_cssc.publication_artifact_install import PublicationArtifactDirectory
from dynamic_cssc.publication_schedule import (
    _compile_accepted_group_program_for_test,
    _load_publication_trace_bundle_for_test,
    _stream_publication_windows_for_test,
    compile_accepted_group_program,
    load_publication_trace_bundle,
    stream_publication_windows,
)
from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    LicenseTermsObject,
    LocalSourceObject,
    _LocalTraceRequest,
    _prepare_publication_trace,
    _RepositorySnapshot,
    _test_only_repository_snapshot,
)


def _mediawiki_history_row(*, timestamp: datetime, user_id: int) -> str:
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


def _write_trace_bundle(
    tmp_path: Path,
    *,
    semantics: str = "T1",
    target_accepted_events: int = 70,
    cols: int = 10,
    repository_snapshot: _RepositorySnapshot | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source_path = tmp_path / f"{semantics}-history.tsv.bz2"
    start = datetime(2020, 1, 1, tzinfo=UTC)
    source_event_count = max(100, (target_accepted_events * 10 + 8) // 9)
    user_ids = [1 + index % 10 for index in range(source_event_count)]
    rows = "".join(
        _mediawiki_history_row(timestamp=start + timedelta(seconds=index), user_id=user_id)
        for index, user_id in enumerate(user_ids)
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)

    terms_path = tmp_path / "mediawiki-history-readme.html"
    terms_path.write_text("<html>CC0 fixture terms</html>\n", encoding="utf-8")
    terms_bytes = terms_path.read_bytes()
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    source_bytes = source_path.read_bytes()
    source_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
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
            semantics=semantics,
            source_partition=0,
            sources=(source,),
        ),
        config=replace(
            _PRODUCTION_CONFIG,
            rows=1,
            cols=cols,
            event_window_size=1 if semantics == "T2" else 32_768,
            target_accepted_events=target_accepted_events,
            minimum_logical_changes=target_accepted_events,
            minimum_complete_window_lower_bound=1,
            maximum_row_nonzeros=10,
        ),
        repository_snapshot=(
            _test_only_repository_snapshot() if repository_snapshot is None else repository_snapshot
        ),
    )
    trace_dir = tmp_path / f"{semantics}-trace"
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


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _refresh_checksums(trace_dir: Path) -> None:
    artifacts = {
        name: (trace_dir / name).read_bytes()
        for name in (
            "publication-trace-manifest.json",
            "publication-trace.jsonl",
            "publication-query-vector.json",
        )
    }
    checksums = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in artifacts.items()
    )
    (trace_dir / "checksums.sha256").write_text(checksums, encoding="ascii")


def _rewrite_trace_records(trace_dir: Path, records: list[dict[str, object]]) -> None:
    trace_bytes = b"".join(_canonical_json_bytes(record) for record in records)
    (trace_dir / "publication-trace.jsonl").write_bytes(trace_bytes)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["trace_jsonl_sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)


def test_private_loader_accepts_and_rehashes_one_closed_v7_v3_fixture(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path)

    trace = _load_publication_trace_bundle_for_test(trace_dir)

    assert (
        trace.dataset_id,
        trace.semantics,
        trace.source_partition,
        trace.accepted_group_count,
        trace.transition_count,
        trace.clock_denominator,
        trace.microbatch_max_updates,
    ) == ("simplewiki-2026-07", "T1", 0, 70, 70, 128, 64)
    assert trace.query_vector == (1, -1, 1, -1, -1, 0, 1, 0, -1, -1)
    assert (
        trace.manifest_sha256
        == hashlib.sha256((trace_dir / "publication-trace-manifest.json").read_bytes()).hexdigest()
    )
    assert (
        trace.trace_jsonl_sha256
        == hashlib.sha256((trace_dir / "publication-trace.jsonl").read_bytes()).hexdigest()
    )
    assert (
        trace.query_vector_sha256
        == hashlib.sha256((trace_dir / "publication-query-vector.json").read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("mutation", ("member", "root", "parent", "extra", "content"))
def test_descriptor_loader_rejects_tree_change_before_issuing_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    live_parent = tmp_path / "live-parent"
    trace_dir = _write_trace_bundle(live_parent)
    production_issued_before = set(schedule_module._ISSUED_PRODUCTION_TRACES)
    test_issued_before = set(schedule_module._ISSUED_TEST_TRACES)
    original_read = PublicationArtifactDirectory.read_regular
    mutated = False

    def mutate_after_snapshot(
        artifact: PublicationArtifactDirectory,
        relative_path: str,
    ) -> bytes:
        nonlocal mutated
        if not mutated:
            mutated = True
            if mutation == "member":
                manifest_path = trace_dir / "publication-trace-manifest.json"
                content = manifest_path.read_bytes()
                manifest_path.rename(tmp_path / "detached-manifest.json")
                manifest_path.write_bytes(content)
            elif mutation == "root":
                trace_dir.rename(live_parent / "detached-trace")
                trace_dir.mkdir()
            elif mutation == "parent":
                live_parent.rename(tmp_path / "detached-parent")
                live_parent.mkdir()
            elif mutation == "extra":
                (trace_dir / "late-extra.txt").write_bytes(b"not in the snapshot\n")
            else:
                manifest_path = trace_dir / "publication-trace-manifest.json"
                content = manifest_path.read_bytes()
                replacement = (b"X" if content[:1] != b"X" else b"Y") + content[1:]
                assert len(replacement) == len(content)
                manifest_path.write_bytes(replacement)
        return original_read(artifact, relative_path)

    monkeypatch.setattr(
        PublicationArtifactDirectory,
        "read_regular",
        mutate_after_snapshot,
    )

    with pytest.raises(ValueError, match="descriptor-bound"):
        _load_publication_trace_bundle_for_test(trace_dir)

    assert mutated is True
    assert set(schedule_module._ISSUED_PRODUCTION_TRACES) == production_issued_before
    assert set(schedule_module._ISSUED_TEST_TRACES) == test_issued_before


def test_descriptor_loader_rejects_four_member_same_inode_aba_before_issuance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    original_bytes = {
        name: (trace_dir / name).read_bytes() for name in schedule_module._BUNDLE_FILENAMES
    }
    original_identities = {
        name: (trace_dir / name).stat().st_ino for name in schedule_module._BUNDLE_FILENAMES
    }
    alternate_manifest = json.loads(original_bytes["publication-trace-manifest.json"])
    original_retrieval = alternate_manifest["acquisition_receipts"][0]["retrieval_utc"]
    alternate_manifest["acquisition_receipts"][0]["retrieval_utc"] = (
        "2025" if original_retrieval[:4] != "2025" else "2024"
    ) + original_retrieval[4:]
    alternate_manifest_bytes = _canonical_json_bytes(alternate_manifest)
    alternate_payloads = {
        "publication-trace-manifest.json": alternate_manifest_bytes,
        "publication-trace.jsonl": original_bytes["publication-trace.jsonl"],
        "publication-query-vector.json": original_bytes["publication-query-vector.json"],
    }
    alternate_checksums = "".join(
        f"{hashlib.sha256(value).hexdigest()}  {name}\n"
        for name, value in alternate_payloads.items()
    ).encode("ascii")
    alternate_bytes = {**alternate_payloads, "checksums.sha256": alternate_checksums}
    assert all(
        len(alternate_bytes[name]) == len(original_bytes[name])
        for name in schedule_module._BUNDLE_FILENAMES
    )
    production_issued_before = set(schedule_module._ISSUED_PRODUCTION_TRACES)
    test_issued_before = set(schedule_module._ISSUED_TEST_TRACES)
    original_read = PublicationArtifactDirectory.read_regular
    mutated = False
    successful_reads = 0

    def restore_original() -> None:
        for name, value in original_bytes.items():
            (trace_dir / name).write_bytes(value)
            assert (trace_dir / name).stat().st_ino == original_identities[name]

    def read_during_transient_splice(
        artifact: PublicationArtifactDirectory,
        relative_path: str,
    ) -> bytes:
        nonlocal mutated, successful_reads
        if not mutated:
            mutated = True
            for name, value in alternate_bytes.items():
                (trace_dir / name).write_bytes(value)
                assert (trace_dir / name).stat().st_ino == original_identities[name]
        try:
            value = original_read(artifact, relative_path)
        except BaseException:
            restore_original()
            raise
        successful_reads += 1
        if successful_reads == len(schedule_module._BUNDLE_FILENAMES):
            restore_original()
        return value

    monkeypatch.setattr(
        PublicationArtifactDirectory,
        "read_regular",
        read_during_transient_splice,
    )

    with pytest.raises(ValueError, match="descriptor-bound"):
        _load_publication_trace_bundle_for_test(trace_dir)

    assert mutated is True
    assert set(schedule_module._ISSUED_PRODUCTION_TRACES) == production_issued_before
    assert set(schedule_module._ISSUED_TEST_TRACES) == test_issued_before
    assert {
        name: (trace_dir / name).read_bytes() for name in schedule_module._BUNDLE_FILENAMES
    } == original_bytes


def test_loader_rejects_legacy_acquisition_transaction_v2_after_caller_rehash(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["acquisition_binding"]["acquisition_transaction_schema_version"] = (
        "dynamic-cssc-acquisition-transaction-v2"
    )
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="acquisition transaction schema is not frozen"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_rejects_extra_nested_manifest_fields_even_after_caller_rehash(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["normalization_contract"]["caller_extension"] = True
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="normalization_contract keys must be exactly"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_public_loader_rejects_test_provenance_and_nonproduction_dimensions(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)

    with pytest.raises(ValueError, match="hardened central acquisition provenance"):
        load_publication_trace_bundle(trace_dir)


def test_trace_producer_hardened_provenance_round_trips_through_loader(
    tmp_path: Path,
) -> None:
    snapshot = replace(
        _test_only_repository_snapshot(),
        source_git_sha="e" * 40,
        verification_mode="hardened-trace-role-git-object-worktree-v1",
    )
    trace_dir = _write_trace_bundle(tmp_path, repository_snapshot=snapshot)

    trace = _load_publication_trace_bundle_for_test(trace_dir)
    manifest = json.loads((trace_dir / "publication-trace-manifest.json").read_bytes())

    assert len(trace.manifest_sha256) == 64
    assert manifest["repository_provenance"]["verification_mode"] == (
        "hardened-trace-role-git-object-worktree-v1"
    )


def test_loader_rejects_legacy_weak_repository_verification_mode(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    provenance = manifest["repository_provenance"]
    provenance["verification_mode"] = "clean-head-git-blob-and-worktree-match-v1"
    provenance_core = {
        key: value for key, value in provenance.items() if key != "repository_provenance_sha256"
    }
    provenance["repository_provenance_sha256"] = hashlib.sha256(
        _canonical_json_bytes(provenance_core)
    ).hexdigest()
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="verification_mode is not recognized"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_rejects_rewritten_acquisition_attestation_after_caller_rehash(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["acquisition_binding"]["authority"]["claims_authorized"] = True
    manifest["acquisition_binding"]["authority"]["formal_authority_granted"] = True
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="authority must remain exact HOLD/false"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_rejects_legacy_caller_attested_acquisition_schema_after_rehash(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest.pop("acquisition_binding")
    manifest["acquisition_verification"] = {
        "acquisition_network_authority_verified": False,
        "final_url_caller_attested_without_redirect": True,
        "http_status_caller_attested_as_200": True,
        "http_metadata_source": "closed-local-source-manifest-attestation",
        "local_byte_count_verified": True,
        "local_sha256_verified": True,
        "media_type_caller_attested_and_allowlisted": True,
        "network_fetch_performed": False,
        "raw_objects_copied_to_output": False,
        "source_url_matches_frozen_source_url": True,
        "terms_page_local_byte_count_and_sha256_verified": True,
    }
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="acquisition_binding|trace manifest keys"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_rho_100_program_is_one_rle_record_per_group_with_exact_phase_boundaries(
    tmp_path: Path,
) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))

    program = _compile_accepted_group_program_for_test(trace, Fraction(100))
    groups = tuple(program)
    schedule_bytes = b"".join(program.iter_canonical_bytes())

    assert tuple((phase.name, phase.start, phase.end) for phase in program.phase_ranges) == (
        ("warmup", 0, 7),
        ("tuning", 7, 28),
        ("heldout", 28, 70),
    )
    assert (
        program.accepted_group_count,
        program.total_set_count,
        program.total_query_count,
        program.scheduled_event_count,
    ) == (70, 70, 7_000, 7_143)
    assert len(groups) == 70
    assert (
        groups[0].logical_time,
        groups[0].query_run.first_query_ordinal,
        groups[0].query_run.count,
        groups[-1].query_run.first_query_ordinal,
        groups[-1].query_run.count,
    ) == (Fraction(0, 128), 0, 100, 6_900, 100)
    assert groups[6].event_kinds == ("set", "tick", "query-run", "phase-boundary")
    assert groups[6].phase_close_after == "warmup"
    assert groups[27].phase_close_after == "tuning"
    assert groups[69].phase_close_after == "heldout"
    assert groups[7].phase_close_after is None
    assert schedule_bytes.count(b'"kind":"query-run"') == 70
    assert schedule_bytes.count(b'"kind":"phase-boundary"') == 3
    assert program.canonical_schedule_sha256 == hashlib.sha256(schedule_bytes).hexdigest()


def test_windows_keep_t2_groups_atomic_at_64_and_keep_state_across_phase_closes(
    tmp_path: Path,
) -> None:
    trace = _load_publication_trace_bundle_for_test(
        _write_trace_bundle(tmp_path, semantics="T2", target_accepted_events=340)
    )
    program = _compile_accepted_group_program_for_test(trace, Fraction(0))

    windows = tuple(_stream_publication_windows_for_test(program, Fraction(1_000)))

    assert len(windows) == 13
    assert (
        windows[0].phase,
        windows[0].accepted_group_start,
        windows[0].accepted_group_end,
        windows[0].set_count,
        windows[0].reason,
        windows[0].start_time,
        windows[0].end_time,
    ) == ("warmup", 0, 33, 65, "microbatch", Fraction(0), Fraction(32, 128))
    assert (
        windows[1].phase,
        windows[1].accepted_group_start,
        windows[1].accepted_group_end,
        windows[1].set_count,
        windows[1].reason,
    ) == ("warmup", 33, 34, 2, "phase-boundary:warmup")
    assert [window.phase for window in windows].count("tuning") == 4
    assert [window.phase for window in windows].count("heldout") == 7
    assert any(update.before == 1 and update.after == 0 for update in windows[2].updates)
    assert sum(window.set_count for window in windows) == 679
    assert all(window.accepted_group_start < window.accepted_group_end for window in windows)


def test_query_runs_feed_window_counts_without_expanding_rho_100_events(tmp_path: Path) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    program = _compile_accepted_group_program_for_test(trace, Fraction(100))

    windows = tuple(_stream_publication_windows_for_test(program, Fraction(1, 10)))

    assert len(windows) == 70
    assert sum(window.query_count for window in windows) == 7_000
    assert sum(window.set_count for window in windows) == 70
    assert {window.query_count for window in windows} == {100}
    assert all(window.accepted_group_end - window.accepted_group_start == 1 for window in windows)


def test_freshness_uses_exact_fraction_and_phase_closes_never_reset_state(
    tmp_path: Path,
) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    program = _compile_accepted_group_program_for_test(trace, Fraction(0))

    windows = tuple(_stream_publication_windows_for_test(program, Fraction(1, 10)))

    assert [window.phase for window in windows] == [
        "warmup",
        "tuning",
        "tuning",
        "heldout",
        "heldout",
        "heldout",
        "heldout",
    ]
    assert [window.reason for window in windows] == [
        "phase-boundary:warmup",
        "freshness",
        "phase-boundary:tuning",
        "freshness",
        "freshness",
        "freshness",
        "phase-boundary:heldout",
    ]
    assert (windows[1].accepted_group_start, windows[1].accepted_group_end) == (7, 20)
    assert windows[1].end_time == Fraction(99, 640)
    assert all(
        window.start_time.denominator <= 1_280 and window.end_time.denominator <= 1_280
        for window in windows
    )


def test_clipped_noop_group_emits_tick_and_query_run_but_no_set(tmp_path: Path) -> None:
    trace = _load_publication_trace_bundle_for_test(
        _write_trace_bundle(tmp_path, target_accepted_events=80)
    )

    program = _compile_accepted_group_program_for_test(trace, Fraction(0))
    groups = tuple(program)

    assert program.total_set_count == 70
    assert groups[70].event_kinds == ("tick", "query-run")
    assert groups[79].event_kinds == ("tick", "query-run", "phase-boundary")
    assert groups[79].phase_close_after == "heldout"


def test_exact_ratio_interfaces_reject_binary_floats(tmp_path: Path) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    with pytest.raises(ValueError, match="exact nonnegative Fraction"):
        _compile_accepted_group_program_for_test(trace, 0.1)  # type: ignore[arg-type]

    program = _compile_accepted_group_program_for_test(trace, Fraction(1, 10))
    with pytest.raises(ValueError, match="exact positive Fraction"):
        tuple(_stream_publication_windows_for_test(program, 0.1))  # type: ignore[arg-type]


def test_test_capabilities_cannot_cross_the_public_compile_or_window_seams(tmp_path: Path) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    with pytest.raises(TypeError, match="required loader capability"):
        compile_accepted_group_program(trace, Fraction(1))

    program = _compile_accepted_group_program_for_test(trace, Fraction(1))
    with pytest.raises(TypeError, match="required compiler capability"):
        tuple(stream_publication_windows(program, Fraction(1)))

    production_trace = replace(
        trace,
        _validation_token=schedule_module._PRODUCTION_TRACE_TOKEN,
    )
    schedule_module._ISSUED_PRODUCTION_TRACES[id(production_trace)] = production_trace
    try:
        with pytest.raises(TypeError, match="required loader capability"):
            _compile_accepted_group_program_for_test(production_trace, Fraction(1))
    finally:
        schedule_module._ISSUED_PRODUCTION_TRACES.pop(id(production_trace), None)


def test_loader_rejects_self_consistent_query_vector_replacement(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    vector_path = trace_dir / "publication-query-vector.json"
    vector = json.loads(vector_path.read_bytes())
    vector["values"][1] = 0
    vector_bytes = _canonical_json_bytes(vector)
    vector_path.write_bytes(vector_bytes)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["query_vector"]["query_vector_sha256"] = hashlib.sha256(vector_bytes).hexdigest()
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="frozen deterministic generator"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_rejects_self_consistent_noncanonical_transition_clock(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    trace_path = trace_dir / "publication-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_bytes().splitlines()]
    records[0]["logical_time_denominator"] = 127
    _rewrite_trace_records(trace_dir, records)

    with pytest.raises(ValueError, match="exact 128 Hz clock"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_rejects_extra_files_and_duplicate_json_keys(tmp_path: Path) -> None:
    extra_trace_dir = _write_trace_bundle(tmp_path / "extra")
    (extra_trace_dir / "caller-digest.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="trace bundle tree is closed"):
        _load_publication_trace_bundle_for_test(extra_trace_dir)

    duplicate_trace_dir = _write_trace_bundle(tmp_path / "duplicate")
    manifest_path = duplicate_trace_dir / "publication-trace-manifest.json"
    manifest_path.write_bytes(b'{"schema_version":"caller-v1",' + manifest_path.read_bytes()[1:])
    _refresh_checksums(duplicate_trace_dir)
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        _load_publication_trace_bundle_for_test(duplicate_trace_dir)


def test_t2_expiry_must_name_the_exact_fifo_admission_k_groups_earlier(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path, semantics="T2")
    trace_path = trace_dir / "publication-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_bytes().splitlines()]
    group_one = [record for record in records if record["accepted_event_ordinal"] == 1]
    expiry, admission = group_one
    expiry["subject_event"] = admission["subject_event"]
    _rewrite_trace_records(trace_dir, records)

    with pytest.raises(ValueError, match="expiry subject must equal the FIFO admission"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_public_interfaces_reject_nonfrozen_rho_and_freshness_before_capability_use(
    tmp_path: Path,
) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    with pytest.raises(ValueError, match="nine frozen rho values"):
        compile_accepted_group_program(trace, Fraction(2))

    program = _compile_accepted_group_program_for_test(trace, Fraction(1))
    with pytest.raises(ValueError, match="frozen publication freshness"):
        tuple(stream_publication_windows(program, Fraction(10)))


def test_loader_rejects_unknown_closed_count_categories_after_caller_rehash(
    tmp_path: Path,
) -> None:
    filter_trace_dir = _write_trace_bundle(tmp_path / "filter")
    filter_manifest_path = filter_trace_dir / "publication-trace-manifest.json"
    filter_manifest = json.loads(filter_manifest_path.read_bytes())
    filter_manifest["filter_counts"]["caller-extension"] = 0
    filter_manifest_path.write_bytes(_canonical_json_bytes(filter_manifest))
    _refresh_checksums(filter_trace_dir)

    with pytest.raises(ValueError, match="filter_counts contains non-frozen count keys"):
        _load_publication_trace_bundle_for_test(filter_trace_dir)

    receipt_trace_dir = _write_trace_bundle(tmp_path / "receipt")
    receipt_manifest_path = receipt_trace_dir / "publication-trace-manifest.json"
    receipt_manifest = json.loads(receipt_manifest_path.read_bytes())
    receipt_manifest["acquisition_receipts"][0]["rejected_event_counts"]["caller-extension"] = 0
    receipt_manifest_path.write_bytes(_canonical_json_bytes(receipt_manifest))
    _refresh_checksums(receipt_trace_dir)

    with pytest.raises(
        ValueError,
        match="rejected_event_counts contains non-frozen count keys",
    ):
        _load_publication_trace_bundle_for_test(receipt_trace_dir)


def test_loader_rejects_nonmonotonic_canonical_raw_event_ordinals(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    trace_path = trace_dir / "publication-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_bytes().splitlines()]
    records[1]["trigger_event"]["canonical_raw_event_ordinal"] = records[0]["trigger_event"][
        "canonical_raw_event_ordinal"
    ]
    records[1]["subject_event"]["canonical_raw_event_ordinal"] = records[0]["subject_event"][
        "canonical_raw_event_ordinal"
    ]
    _rewrite_trace_records(trace_dir, records)

    with pytest.raises(ValueError, match="canonical raw-event ordinals"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_loader_recomputes_capped_raw_counts_instead_of_trusting_before_after(
    tmp_path: Path,
) -> None:
    trace_dir = _write_trace_bundle(tmp_path)
    trace_path = trace_dir / "publication-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_bytes().splitlines()]
    first_coordinate = (records[0]["row_index"], records[0]["column_index"])
    coordinate_records = [
        record
        for record in records
        if (record["row_index"], record["column_index"]) == first_coordinate
    ]
    for occurrence, record in enumerate(coordinate_records):
        record["before"] = 0 if occurrence == 0 else min(7, occurrence + 1)
        record["after"] = min(7, occurrence + 2)
        record["operation"] = (
            "insert"
            if record["before"] == 0
            else "clipped-no-op"
            if record["before"] == record["after"]
            else "modify"
        )
    _rewrite_trace_records(trace_dir, records)
    manifest_path = trace_dir / "publication-trace-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["frozen_contract"]["minimum_logical_changes"] = 69
    manifest["trace"]["logical_changes"] = 69
    manifest["trace"]["clipped_noops"] = 1
    manifest["operation_counts"]["modify"] = 59
    manifest["operation_counts"]["clipped-no-op"] = 1
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    _refresh_checksums(trace_dir)

    with pytest.raises(ValueError, match="exact capped raw-count transform"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_reserved_empty_mapping_columns_can_never_appear_in_transitions(tmp_path: Path) -> None:
    trace_dir = _write_trace_bundle(tmp_path, target_accepted_events=80, cols=11)
    trace_path = trace_dir / "publication-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_bytes().splitlines()]
    records[-1]["column_index"] = 10
    records[-1]["before"] = 0
    records[-1]["after"] = 0
    records[-1]["operation"] = "clipped-no-op"
    _rewrite_trace_records(trace_dir, records)

    with pytest.raises(ValueError, match="reserved-empty columns"):
        _load_publication_trace_bundle_for_test(trace_dir)


def test_caller_cannot_copy_validation_tokens_into_new_self_authorized_objects(
    tmp_path: Path,
) -> None:
    trace = _load_publication_trace_bundle_for_test(_write_trace_bundle(tmp_path))
    copied_trace = replace(trace)
    with pytest.raises(TypeError, match="required loader capability"):
        _compile_accepted_group_program_for_test(copied_trace, Fraction(1))

    program = _compile_accepted_group_program_for_test(trace, Fraction(1))
    copied_program = replace(program)
    with pytest.raises(TypeError, match="required compiler capability"):
        tuple(_stream_publication_windows_for_test(copied_program, Fraction(1)))
