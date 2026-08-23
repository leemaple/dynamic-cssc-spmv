from __future__ import annotations

import bz2
import hashlib
import json
import os
import re
import tomllib
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.publication_acquisition import (
    _acquire_publication_sources,
    _TransportResponse,
)
from dynamic_cssc.publication_acquisition import (
    _test_only_repository_snapshot as _test_only_acquisition_snapshot,
)
from dynamic_cssc.publication_schedule import (
    _compile_accepted_group_program_for_test,
    _load_publication_trace_bundle_for_test,
)
from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    _require_path_outside_repository,
    _test_only_repository_snapshot,
)
from scripts import prepare_publication_traces


class _FakeAcquisitionTransport:
    def __init__(self, responses: dict[str, _TransportResponse]) -> None:
        self._responses = responses

    @contextmanager
    def open(self, url: str):  # type: ignore[no-untyped-def]
        yield self._responses[url]


def _closed_simplewiki_acquisition(tmp_path: Path, *, rows: str) -> Path:
    source_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    source_bytes = bz2.compress(rows.encode("utf-8"))
    terms_bytes = b"<html>CC0 fixture terms</html>\n"

    def response(url: str, content: bytes, media_type: str) -> _TransportResponse:
        return _TransportResponse(
            final_url=url,
            http_status=200,
            media_type=media_type,
            content_encoding=None,
            content_range=None,
            content_length=len(content),
            http_etag=None,
            http_last_modified=None,
            chunks=(content,),
        )

    output_dir = tmp_path / "simplewiki-acquisition"
    _acquire_publication_sources(
        "simplewiki-2026-07",
        output_dir,
        transport=_FakeAcquisitionTransport(
            {
                source_url: response(source_url, source_bytes, "application/octet-stream"),
                terms_url: response(terms_url, terms_bytes, "text/html"),
            }
        ),
        clock=lambda: datetime(2026, 8, 23, 1, 2, 3, tzinfo=UTC),
        repository_snapshot=_test_only_acquisition_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )
    return output_dir


def _rewrite_acquisition_downstream_digests(root: Path) -> None:
    source_set_bytes = (root / "source-set.json").read_bytes()
    transaction_path = root / "ACQUISITION-TRANSACTION.json"
    transaction = json.loads(transaction_path.read_bytes())
    transaction["source_set"]["sha256"] = hashlib.sha256(source_set_bytes).hexdigest()
    transaction_path.chmod(0o644)
    transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    checksums_path = root / "SHA256SUMS"
    checksums_path.chmod(0o644)
    checksums_path.write_text(
        "".join(
            f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n" for path in paths
        ),
        encoding="ascii",
    )


def test_publication_pyarrow_extra_is_exact_and_cp312_wheels_are_hash_locked() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((repository_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["optional-dependencies"]["publication"] == ["pyarrow==25.0.1"]

    lock_text = (repository_root / "requirements-publication.txt").read_text(encoding="utf-8")
    assert "--only-binary=:all:" in lock_text
    assert "declares no Requires-Dist entries" in lock_text
    assert lock_text.count("pyarrow==25.0.1") == 1
    assert set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock_text)) == {
        "df961f2e7ae9cf496459259d798652c70625f6c080650d6952f8c04053c58ee9",
        "cc4aa407fde9fc660be3939e49ea31f50f3e9fec17c0ec63159f7711edd3efc9",
        "4340f0ba6c1d2e13f21658de1d7c662ca2545018568d0030a1e9afca159d87e3",
        "5389cdf79447ed1515c9e31620e6e1e2302249564d603f2ad727d4f6d313e4c3",
        "d51592cb7561e87877c506113e7adbf1342ab579e6c21f0ef44b8ba41cb74c80",
        "6109c94d8b9f3b17a041daca16cacb2f651ad8f1ef70a4232c2c0f37a23da2a8",
    }


def test_publication_inputs_and_outputs_must_live_outside_the_source_checkout(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "publication-data" / "trace.jsonl"

    _require_path_outside_repository(outside, repository, field="trace output")
    with pytest.raises(ValueError, match="outside the source checkout"):
        _require_path_outside_repository(
            repository / "results" / "trace.jsonl",
            repository,
            field="trace output",
        )


def test_cli_accepts_only_an_acquisition_bundle_not_a_source_manifest(
    tmp_path: Path,
) -> None:
    accepted = prepare_publication_traces._parser().parse_args(
        [
            "--acquisition-bundle-dir",
            str(tmp_path / "acquisition"),
            "--dataset-id",
            "simplewiki-2026-07",
            "--semantics",
            "T1",
            "--source-partition",
            "0",
            "--output-dir",
            str(tmp_path / "trace"),
        ]
    )
    assert accepted.acquisition_bundle_dir == tmp_path / "acquisition"
    assert accepted.dataset_id == "simplewiki-2026-07"

    with pytest.raises(SystemExit):
        prepare_publication_traces._parser().parse_args(
            [
                "--source-manifest",
                str(tmp_path / "caller.json"),
                "--dataset-id",
                "simplewiki-2026-07",
                "--semantics",
                "T1",
                "--source-partition",
                "0",
                "--output-dir",
                str(tmp_path / "trace"),
            ]
        )

    with pytest.raises(SystemExit):
        prepare_publication_traces._parser().parse_args(
            [
                "--acquisition-bundle-dir",
                str(tmp_path / "acquisition"),
                "--dataset-id",
                "simplewiki-2026-07",
                "--semantics",
                "T1",
                "--source-partition",
                "0",
                "--output-dir",
                str(tmp_path / "trace"),
                "--formal-authority-granted",
                "true",
            ]
        )


def _mediawiki_history_row(*, timestamp: str, user_id: int, page_id: int) -> str:
    fields = [""] * 78
    fields[0] = "simplewiki"
    fields[2] = "revision"
    fields[3] = "create"
    fields[4] = timestamp
    fields[6] = str(user_id)
    fields[19] = "false"
    fields[20] = "false"
    fields[21] = "true"
    fields[28] = str(page_id)
    fields[31] = "0"
    return "\t".join(fields) + "\n"


def test_cli_consumes_the_closed_acquisition_transaction_and_emits_hold_binding(
    tmp_path: Path,
) -> None:
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:{second // 60:02d}:{second % 60:02d}.0",
            user_id=1 + second % 10,
            page_id=2,
        )
        for second in range(100)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    transaction_bytes = (acquisition_dir / "ACQUISITION-TRANSACTION.json").read_bytes()
    source_set_bytes = (acquisition_dir / "source-set.json").read_bytes()
    output_dir = tmp_path / "derived-from-transaction"
    config = replace(
        _PRODUCTION_CONFIG,
        rows=1,
        cols=10,
        target_accepted_events=70,
        minimum_logical_changes=70,
        microbatch_cap=64,
        minimum_complete_window_lower_bound=1,
        maximum_row_nonzeros=10,
    )

    result = prepare_publication_traces._run_cli(
        [
            "--acquisition-bundle-dir",
            str(acquisition_dir),
            "--dataset-id",
            "simplewiki-2026-07",
            "--semantics",
            "T1",
            "--source-partition",
            "0",
            "--output-dir",
            str(output_dir),
        ],
        config=config,
        repository_snapshot=_test_only_repository_snapshot(),
    )

    assert result == 0
    manifest = json.loads((output_dir / "publication-trace-manifest.json").read_bytes())
    assert manifest["schema_version"] == "dynamic-cssc-publication-trace-manifest-v6"
    binding = manifest["acquisition_binding"]
    assert (
        binding["acquisition_transaction_sha256"] == hashlib.sha256(transaction_bytes).hexdigest()
    )
    assert binding["source_set_sha256"] == hashlib.sha256(source_set_bytes).hexdigest()
    assert (
        binding["repository_provenance"]["behavior_inventory"]
        == json.loads(transaction_bytes)["repository_provenance"]["behavior_inventory"]
    )
    assert binding["authority"] == {
        "acquisition_network_authority_verified": False,
        "claims_authorized": False,
        "evidence_compatibility_verified": False,
        "formal_authority_granted": False,
        "post_run_anchor_verified": False,
        "state": "HOLD-test-only-fixture-no-post-run-anchor",
    }
    assert binding["verification"] == {
        "bundle_member_set_exact": True,
        "bundle_members_rehashed_no_follow": True,
        "embedded_central_inventory_verified": False,
        "network_fetch_recorded": True,
        "source_and_terms_objects_rehashed_no_follow": True,
        "transaction_chain_verified": True,
    }
    trace = _load_publication_trace_bundle_for_test(output_dir)
    assert (trace.dataset_id, trace.semantics, trace.accepted_group_count) == (
        "simplewiki-2026-07",
        "T1",
        70,
    )
    program = _compile_accepted_group_program_for_test(trace, Fraction(1, 100))
    assert (program.accepted_group_count, program.total_set_count) == (70, 70)


def test_cli_writes_only_canonical_derived_artifacts_from_verified_local_input(
    tmp_path: Path,
) -> None:
    rows = "".join(
        _mediawiki_history_row(timestamp=f"2020-01-01 00:00:{second:02d}.0", user_id=9, page_id=2)
        for second in range(10)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    source_path = next((acquisition_dir / "objects" / "data").iterdir())
    terms_path = next((acquisition_dir / "objects" / "terms").iterdir())
    source_bytes = source_path.read_bytes()
    terms_bytes = terms_path.read_bytes()
    output_dir = tmp_path / "derived"
    config = replace(
        _PRODUCTION_CONFIG,
        rows=1,
        cols=1,
        target_accepted_events=9,
        minimum_logical_changes=7,
        microbatch_cap=3,
        minimum_complete_window_lower_bound=2,
        maximum_row_nonzeros=1,
    )

    result = prepare_publication_traces._run_cli(
        [
            "--acquisition-bundle-dir",
            str(acquisition_dir),
            "--dataset-id",
            "simplewiki-2026-07",
            "--semantics",
            "T1",
            "--source-partition",
            "0",
            "--output-dir",
            str(output_dir),
        ],
        config=config,
        repository_snapshot=_test_only_repository_snapshot(),
    )

    assert result == 0
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "checksums.sha256",
        "publication-query-vector.json",
        "publication-trace-manifest.json",
        "publication-trace.jsonl",
    ]
    manifest_bytes = (output_dir / "publication-trace-manifest.json").read_bytes()
    trace_bytes = (output_dir / "publication-trace.jsonl").read_bytes()
    query_vector_bytes = (output_dir / "publication-query-vector.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert set(manifest) == {
        "schema_version",
        "protocol_version",
        "artifact_policy",
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "repository_provenance",
        "normalization_contract",
        "ordering",
        "logical_clock",
        "frozen_contract",
        "acquisition_binding",
        "acquisition_receipts",
        "schema_valid_raw_events",
        "mapping",
        "filter_counts",
        "accepted_raw_event_sha256",
        "source_event_type_counts",
        "operation_counts",
        "trace",
        "realized_bounds",
        "query_vector",
        "trace_jsonl_sha256",
        "eligibility",
    }
    assert manifest["schema_version"] == "dynamic-cssc-publication-trace-manifest-v6"
    assert manifest["artifact_policy"] == "derived-trace-and-download-by-source-only"
    assert manifest["acquisition_binding"]["authority"]["claims_authorized"] is False
    assert manifest["acquisition_binding"]["verification"]["transaction_chain_verified"] is True
    assert manifest["eligibility"]["eligible"] is True
    assert manifest["query_vector"] == {
        "filename": "publication-query-vector.json",
        "length": 1,
        "query_vector_sha256": hashlib.sha256(query_vector_bytes).hexdigest(),
        "schema_version": "dynamic-cssc-publication-query-vector-v1",
    }
    assert "local_path" not in manifest_bytes.decode("utf-8")
    [receipt] = manifest["acquisition_receipts"]
    assert set(receipt) == {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "source_git_sha",
        "behavior_source_blob_sha256",
        "repository_provenance_sha256",
        "role",
        "source_url",
        "final_url",
        "http_status",
        "media_type",
        "retrieval_utc",
        "byte_count",
        "http_etag",
        "http_last_modified",
        "local_sha256",
        "publisher_sha256",
        "license_terms_set_sha256",
        "license_terms_objects",
        "attribution_text",
        "redistribution_policy",
        "rejected_event_counts",
    }
    assert receipt["schema_version"] == "dynamic-cssc-acquisition-receipt-v6"
    assert receipt["source_git_sha"] == manifest["repository_provenance"]["source_git_sha"]
    assert (
        receipt["behavior_source_blob_sha256"]
        == manifest["repository_provenance"]["behavior_source_blob_sha256"]
    )
    assert (
        receipt["repository_provenance_sha256"]
        == manifest["repository_provenance"]["repository_provenance_sha256"]
    )
    assert receipt["rejected_event_counts"] == {}
    assert receipt["byte_count"] == len(source_bytes)
    assert receipt["local_sha256"] == hashlib.sha256(source_bytes).hexdigest()
    assert receipt["source_url"] == receipt["final_url"]
    assert receipt["http_status"] == 200
    assert receipt["media_type"] == "application/octet-stream"
    assert receipt["license_terms_objects"] == [
        {
            "source_url": "https://dumps.wikimedia.org/other/mediawiki_history/readme.html",
            "final_url": "https://dumps.wikimedia.org/other/mediawiki_history/readme.html",
            "http_status": 200,
            "media_type": "text/html",
            "retrieval_utc": "2026-08-23T01:02:03.000000Z",
            "http_etag": None,
            "http_last_modified": None,
            "section_anchor": None,
            "byte_count": len(terms_bytes),
            "sha256": hashlib.sha256(terms_bytes).hexdigest(),
        }
    ]
    assert len(receipt["license_terms_set_sha256"]) == 64
    assert len(trace_bytes.splitlines()) == 9
    first_transition = json.loads(trace_bytes.splitlines()[0])
    assert set(first_transition) == {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "repository_provenance_sha256",
        "accepted_event_ordinal",
        "transition_ordinal",
        "transition_cause",
        "trigger_event",
        "subject_event",
        "logical_time_numerator",
        "logical_time_denominator",
        "row_index",
        "column_index",
        "operation",
        "before",
        "after",
    }
    assert first_transition["schema_version"] == "dynamic-cssc-publication-transition-v3"
    assert set(first_transition["trigger_event"]) == {
        "canonical_raw_event_ordinal",
        "source_timestamp_utc",
        "source_file_ordinal",
        "within_file_ordinal",
        "source_event_type",
    }
    assert first_transition["subject_event"] == first_transition["trigger_event"]
    assert (
        first_transition["repository_provenance_sha256"]
        == manifest["repository_provenance"]["repository_provenance_sha256"]
    )
    assert (output_dir / "checksums.sha256").read_text(encoding="utf-8") == (
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  publication-trace-manifest.json\n"
        f"{hashlib.sha256(trace_bytes).hexdigest()}  publication-trace.jsonl\n"
        f"{hashlib.sha256(query_vector_bytes).hexdigest()}  publication-query-vector.json\n"
    )

    source_path.chmod(0o644)
    source_path.write_bytes(source_bytes + b"tampered")
    rejected_output = tmp_path / "tampered-derived"
    with pytest.raises(ValueError, match="SHA256SUMS|byte_count does not match"):
        prepare_publication_traces._run_cli(
            [
                "--acquisition-bundle-dir",
                str(acquisition_dir),
                "--dataset-id",
                "simplewiki-2026-07",
                "--semantics",
                "T1",
                "--source-partition",
                "0",
                "--output-dir",
                str(rejected_output),
            ],
            config=config,
            repository_snapshot=_test_only_repository_snapshot(),
        )
    assert not rejected_output.exists()


def _fixture_trace_cli_arguments(
    acquisition_dir: Path,
    output_dir: Path,
    *,
    dataset_id: str = "simplewiki-2026-07",
) -> list[str]:
    return [
        "--acquisition-bundle-dir",
        str(acquisition_dir),
        "--dataset-id",
        dataset_id,
        "--semantics",
        "T1",
        "--source-partition",
        "0",
        "--output-dir",
        str(output_dir),
    ]


@pytest.mark.parametrize(
    "splice",
    (
        "extra-member",
        "source-object",
        "terms-object",
        "source-set-role",
        "embedded-inventory",
        "self-minted-authority",
    ),
)
def test_cli_rejects_acquisition_splices_after_downstream_digest_recomputation(
    tmp_path: Path,
    splice: str,
) -> None:
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:00:{second:02d}.0",
            user_id=9,
            page_id=2,
        )
        for second in range(10)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    if splice == "extra-member":
        (acquisition_dir / "caller-added.json").write_text("{}\n", encoding="ascii")
    elif splice in {"source-object", "terms-object"}:
        kind = "data" if splice == "source-object" else "terms"
        path = next((acquisition_dir / "objects" / kind).iterdir())
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + b"caller-splice")
    elif splice == "source-set-role":
        path = acquisition_dir / "source-set.json"
        payload = json.loads(path.read_bytes())
        payload["objects"][0]["role"] = "caller-retargeted-role"
        path.chmod(0o644)
        path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
            encoding="ascii",
        )
    else:
        path = acquisition_dir / "ACQUISITION-TRANSACTION.json"
        payload = json.loads(path.read_bytes())
        if splice == "embedded-inventory":
            payload["repository_provenance"]["behavior_inventory"]["entries"][0]["object_id"] = (
                "a" * 40
            )
        else:
            payload["formal_authority_granted"] = True
            payload["acquisition_network_authority_verified"] = True
        path.chmod(0o644)
        path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
            encoding="ascii",
        )
    _rewrite_acquisition_downstream_digests(acquisition_dir)
    output_dir = tmp_path / "rejected-trace"

    with pytest.raises(ValueError):
        prepare_publication_traces._run_cli(
            _fixture_trace_cli_arguments(acquisition_dir, output_dir),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=_test_only_repository_snapshot(),
        )

    assert not output_dir.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("final_url", "https://example.invalid/redirected"),
        ("http_status", 206),
        ("media_type", "text/plain"),
        ("content_encoding", "gzip"),
        ("content_range", "bytes 0-1/2"),
        ("retrieval_utc", "not-a-utc-instant"),
    ),
)
def test_cli_rejects_rehashed_http_transaction_metadata_retargeting(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:00:{second:02d}.0",
            user_id=9,
            page_id=2,
        )
        for second in range(10)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    transaction_path = acquisition_dir / "ACQUISITION-TRANSACTION.json"
    transaction = json.loads(transaction_path.read_bytes())
    transaction["objects"][0][field] = value
    transaction_path.chmod(0o644)
    transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_acquisition_downstream_digests(acquisition_dir)
    output_dir = tmp_path / "retargeted-http-trace"

    with pytest.raises(ValueError):
        prepare_publication_traces._run_cli(
            _fixture_trace_cli_arguments(acquisition_dir, output_dir),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=_test_only_repository_snapshot(),
        )

    assert not output_dir.exists()


@pytest.mark.parametrize("attack", ("root-symlink", "member-symlink", "member-fifo"))
def test_cli_rejects_symlink_and_fifo_acquisition_paths(
    tmp_path: Path,
    attack: str,
) -> None:
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:00:{second:02d}.0",
            user_id=9,
            page_id=2,
        )
        for second in range(10)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    attacked_dir = acquisition_dir
    if attack == "root-symlink":
        attacked_dir = tmp_path / "acquisition-link"
        attacked_dir.symlink_to(acquisition_dir, target_is_directory=True)
    else:
        source_path = next((acquisition_dir / "objects" / "data").iterdir())
        source_path.unlink()
        if attack == "member-symlink":
            source_path.symlink_to(next((acquisition_dir / "objects" / "terms").iterdir()))
        else:
            os.mkfifo(source_path)
    output_dir = tmp_path / "rejected-special-file-trace"

    with pytest.raises(ValueError):
        prepare_publication_traces._run_cli(
            _fixture_trace_cli_arguments(attacked_dir, output_dir),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=_test_only_repository_snapshot(),
        )

    assert not output_dir.exists()


def test_cli_rejects_a_bundle_from_the_wrong_frozen_dataset_role_set(
    tmp_path: Path,
) -> None:
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:00:{second:02d}.0",
            user_id=9,
            page_id=2,
        )
        for second in range(10)
    )
    acquisition_dir = _closed_simplewiki_acquisition(tmp_path, rows=rows)
    output_dir = tmp_path / "wrong-dataset-trace"

    with pytest.raises(ValueError, match="dataset_id does not match"):
        prepare_publication_traces._run_cli(
            _fixture_trace_cli_arguments(
                acquisition_dir,
                output_dir,
                dataset_id="stack-overflow",
            ),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=_test_only_repository_snapshot(),
        )

    assert not output_dir.exists()
