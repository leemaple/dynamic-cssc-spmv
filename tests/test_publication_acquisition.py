from __future__ import annotations

import hashlib
import inspect
import json
import os
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dynamic_cssc.publication_acquisition import (
    AcquisitionError,
    _acquire_publication_sources,
    _test_only_repository_snapshot,
    _TransportResponse,
    _verify_acquisition_bundle,
    acquire_publication_sources,
)
from scripts import acquire_publication_sources as acquisition_cli


class _FakeTransport:
    def __init__(self, responses: dict[str, _TransportResponse]) -> None:
        self._responses = responses
        self.requested_urls: list[str] = []

    @contextmanager
    def open(self, url: str):  # type: ignore[no-untyped-def]
        self.requested_urls.append(url)
        yield self._responses[url]


def _response(url: str, content: bytes, media_type: str) -> _TransportResponse:
    return _TransportResponse(
        final_url=url,
        http_status=200,
        media_type=media_type,
        content_encoding=None,
        content_range=None,
        content_length=len(content),
        http_etag='"fixture-etag"',
        http_last_modified="Sun, 23 Aug 2026 00:00:00 GMT",
        chunks=(content,),
    )


def _stack_transport() -> _FakeTransport:
    a2q_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    c2q_url = "https://snap.stanford.edu/data/sx-stackoverflow-c2q.txt.gz"
    c2a_url = "https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz"
    urls = {
        a2q_url: (b"a2q\n", "application/x-gzip"),
        c2q_url: (b"c2q\n", "application/x-gzip"),
        c2a_url: (b"c2a\n", "application/x-gzip"),
        "https://stackoverflow.com/help/licensing": (b"licensing\n", "text/html"),
        "https://stackoverflow.com/legal/terms-of-service/public": (
            b"terms\n",
            "text/html; charset=UTF-8",
        ),
    }
    return _FakeTransport(
        {url: _response(url, content, media_type) for url, (content, media_type) in urls.items()}
    )


def _acquire_stack(tmp_path: Path):  # type: ignore[no-untyped-def]
    transport = _stack_transport()
    output_dir = tmp_path / "stack-overflow-acquisition"
    bundle = _acquire_publication_sources(
        "stack-overflow",
        output_dir,
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, 1, 2, 3, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )
    return bundle, transport


def _rewrite_sha256s(root: Path) -> None:
    transaction_path = root / "ACQUISITION-TRANSACTION.json"
    transaction = json.loads(transaction_path.read_text(encoding="ascii"))
    source_set_bytes = (root / "source-set.json").read_bytes()
    transaction["source_set"]["sha256"] = hashlib.sha256(source_set_bytes).hexdigest()
    transaction_path.chmod(0o644)
    transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    paths = sorted(
        str(path.relative_to(root))
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


def test_acquisition_writes_prepare_compatible_source_set_and_fail_closed_transaction(
    tmp_path: Path,
) -> None:
    bundle, transport = _acquire_stack(tmp_path)

    source_set = json.loads(bundle.source_set_path.read_text(encoding="utf-8"))
    transaction = json.loads(bundle.transaction_path.read_text(encoding="utf-8"))
    assert source_set["schema_version"] == "dynamic-cssc-local-source-set-v5"
    assert source_set["dataset_release"] == "snap-stackoverflow-temporal-network"
    assert [item["role"] for item in source_set["objects"]] == ["a2q", "c2q", "c2a"]
    assert [item["source_url"] for item in source_set["terms_objects"]] == [
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    ]
    assert source_set["terms_objects"][1]["media_type"] == "text/html; charset=utf-8"
    assert transaction["network_fetch_performed"] is True
    assert transaction["formal_authority_granted"] is False
    assert transaction["acquisition_network_authority_verified"] is False
    assert transaction["post_run_anchor_verified"] is False
    assert transaction["evidence_compatibility_verified"] is False
    assert transaction["http_request_policy"] == {
        "accept_encoding": "identity",
        "content_encoding": "identity-or-absent",
        "content_length_required": True,
        "content_range": "forbidden",
        "method": "GET",
        "redirect_policy": "reject-any-final-url-drift",
        "user_agent": "dynamic-cssc-publication-acquisition/1",
    }
    repository_provenance = transaction["repository_provenance"]
    assert repository_provenance["source_git_sha"] == "f" * 40
    behavior_inventory = repository_provenance["behavior_inventory"]
    assert behavior_inventory["schema_version"] == ("dynamic-cssc-evidence-behavior-inventory-v1")
    assert behavior_inventory["role"] == "acquisition"
    assert behavior_inventory["source_git_sha"] == "f" * 40
    assert behavior_inventory["behavior_set_schema_version"] == (
        "dynamic-cssc-acquisition-behavior-set-v1"
    )
    behavior_entries = behavior_inventory["entries"]
    assert [entry["path"] for entry in behavior_entries] == [
        "config/params_manifest.json",
        "docs/paper/publication-preregistration-draft.md",
        "docs/research/publication-dataset-citation-record.md",
        "docs/research/publication-venues-datasets-preregistration.md",
        "pyproject.toml",
        "requirements-publication.txt",
        "scripts/acquire_publication_sources.py",
        "scripts/prepare_publication_traces.py",
        "src/dynamic_cssc/__init__.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/publication_acquisition.py",
        "src/dynamic_cssc/publication_traces.py",
    ]
    assert {
        (entry["mode"], entry["object_type"], len(entry["object_id"])) for entry in behavior_entries
    } == {("100644", "blob", 40)}
    assert transaction["source_set"]["sha256"] == bundle.source_set_sha256
    assert len(set(transport.requested_urls)) == 5
    assert len(transport.requested_urls) == 5
    assert bundle.checksums_path.read_text(encoding="ascii").endswith("\n")


def test_rehashed_source_set_role_tamper_is_rejected(tmp_path: Path) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    source_set["objects"][0]["role"] = "forged-role"
    bundle.source_set_path.chmod(0o644)
    bundle.source_set_path.write_text(
        json.dumps(source_set, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    try:
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )
    except ValueError as error:
        assert "source-set" in str(error) or "source set" in str(error)
    else:  # pragma: no cover - documents the fail-closed expectation
        raise AssertionError("rehashed source-set role tamper was accepted")


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (
            lambda response: replace(response, final_url="https://example.invalid/redirected"),
            "redirect",
        ),
        (lambda response: replace(response, http_status=206), "status"),
        (lambda response: replace(response, media_type="text/plain"), "media type"),
        (
            lambda response: replace(
                response,
                content_length=response.content_length + 1,  # type: ignore[operator]
            ),
            "Content-Length",
        ),
        (lambda response: replace(response, content_encoding="gzip"), "Content-Encoding"),
        (
            lambda response: replace(response, content_range="bytes 0-3/8"),
            "Content-Range",
        ),
    ],
    ids=(
        "redirect",
        "wrong-status",
        "wrong-media",
        "truncated-stream",
        "content-encoding",
        "content-range",
    ),
)
def test_transport_attack_cleans_the_atomic_output(
    tmp_path: Path,
    mutation,  # type: ignore[no-untyped-def]
    error_match: str,
) -> None:
    transport = _stack_transport()
    attacked_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    transport._responses[attacked_url] = mutation(transport._responses[attacked_url])
    output_dir = tmp_path / "rejected-acquisition"

    with pytest.raises(AcquisitionError, match=error_match):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".rejected-acquisition.tmp-*")) == []


def test_missing_frozen_transport_response_is_atomic_and_fail_closed(tmp_path: Path) -> None:
    transport = _stack_transport()
    del transport._responses["https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz"]
    output_dir = tmp_path / "missing-role-acquisition"

    with pytest.raises(AcquisitionError, match="transport failed for frozen role c2a"):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".missing-role-acquisition.tmp-*")) == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda transaction: transaction["objects"].pop(),
        lambda transaction: transaction["objects"].append(
            {
                **transaction["objects"][0],
                "role": "extra-role",
                "local_path": "objects/data/extra-role.bin",
            }
        ),
        lambda transaction: transaction["objects"][1].update(
            {"local_path": transaction["objects"][0]["local_path"]}
        ),
    ],
    ids=("missing-role", "extra-role", "duplicate-target"),
)
def test_rehashed_transaction_cannot_change_the_exact_role_or_target_set(
    tmp_path: Path,
    mutation,  # type: ignore[no-untyped-def]
) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    mutation(transaction)
    transaction["object_count"] = len(transaction["objects"])
    bundle.transaction_path.chmod(0o644)
    bundle.transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    with pytest.raises(AcquisitionError, match="role set|role|target"):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )


def test_rehashed_transaction_cannot_mint_network_authority(tmp_path: Path) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    transaction["formal_authority_granted"] = True
    transaction["acquisition_network_authority_verified"] = True
    bundle.transaction_path.chmod(0o644)
    bundle.transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    with pytest.raises(AcquisitionError, match="closed repository-owned contract"):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )


def test_existing_and_symlink_output_paths_fail_before_transport_use(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    existing = tmp_path / "existing"
    existing.mkdir()
    symlink_target = tmp_path / "target"
    symlink_target.mkdir()
    symlink_output = tmp_path / "symlink-output"
    symlink_output.symlink_to(symlink_target, target_is_directory=True)
    fifo_output = tmp_path / "fifo-output"
    os.mkfifo(fifo_output)

    for output_dir in (existing, symlink_output, fifo_output):
        transport = _stack_transport()
        with pytest.raises(AcquisitionError, match="must not already exist"):
            _acquire_publication_sources(
                "stack-overflow",
                output_dir,
                transport=transport,
                clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
                repository_snapshot=_test_only_repository_snapshot(),
                repository_root=repository_root,
            )
        assert transport.requested_urls == []


def test_public_interface_does_not_accept_url_transport_header_clock_or_authority_injection(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(acquire_publication_sources).parameters) == (
        "dataset_id",
        "output_dir",
    )

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        acquire_publication_sources(  # type: ignore[call-arg]
            "stack-overflow",
            tmp_path / "never-created",
            source_url="https://example.invalid/forged",
        )

    assert not (tmp_path / "never-created").exists()


def test_simplewiki_uses_the_exact_versioned_object_and_cc0_terms_url(tmp_path: Path) -> None:
    data_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    transport = _FakeTransport(
        {
            data_url: _response(data_url, b"simplewiki-fixture\n", "application/octet-stream"),
            terms_url: _response(terms_url, b"cc0-terms\n", "text/html"),
        }
    )

    bundle = _acquire_publication_sources(
        "simplewiki-2026-07",
        tmp_path / "simplewiki-acquisition",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    assert source_set["dataset_release"] == "mediawiki-history-2026-07-simplewiki-all-time"
    assert source_set["objects"][0]["role"] == "history"
    assert source_set["objects"][0]["source_url"] == data_url
    assert source_set["objects"][0]["attribution_text"] == (
        "Wikimedia Analytics MediaWiki History (CC0)"
    )
    assert source_set["terms_objects"][0]["source_url"] == terms_url
    assert transport.requested_urls == [data_url, terms_url]


def test_nyc_acquisition_freezes_all_months_and_separates_overview_anchor(
    tmp_path: Path,
) -> None:
    monthly_urls = {
        (
            "https://d37ci6vzurychx.cloudfront.net/trip-data/"
            f"yellow_tripdata_2022-{month:02d}.parquet"
        ): (
            f"month-{month:02d}\n".encode("ascii"),
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        for month in range(1, 13)
    }
    zone_url = "https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv"
    terms_urls = {
        "https://opendata.cityofnewyork.us/faq/",
        "https://opendata.cityofnewyork.us/overview/",
        "https://cityofnewyork.github.io/opendatatsm/publicpolicies.html",
        "https://www.nyc.gov/main/terms-of-use",
    }
    responses = {
        url: _response(url, content, media_type)
        for url, (content, media_type) in monthly_urls.items()
    }
    responses[zone_url] = _response(zone_url, b"LocationID\n1\n", "text/csv")
    responses.update(
        {url: _response(url, f"terms:{url}\n".encode("ascii"), "text/html") for url in terms_urls}
    )
    transport = _FakeTransport(responses)

    bundle = _acquire_publication_sources(
        "nyc-tlc-yellow-2022",
        tmp_path / "nyc-acquisition",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    assert [item["role"] for item in source_set["objects"]] == [
        *(f"yellow-2022-{month:02d}" for month in range(1, 13)),
        "zone-lookup",
    ]
    assert {item["source_url"] for item in source_set["terms_objects"]} == terms_urls
    [overview] = [
        item
        for item in source_set["terms_objects"]
        if item["source_url"] == "https://opendata.cityofnewyork.us/overview/"
    ]
    assert overview["section_anchor"] == "termsofuse"
    assert "#" not in overview["source_url"]
    assert set(transport.requested_urls) == {*monthly_urls, zone_url, *terms_urls}
    assert len(transport.requested_urls) == 17


def test_cli_exposes_only_dataset_and_output_options(tmp_path: Path) -> None:
    calls: list[tuple[str, Path]] = []

    def fake_acquirer(dataset_id: str, output_dir: Path):  # type: ignore[no-untyped-def]
        calls.append((dataset_id, output_dir))
        return object()

    output_dir = tmp_path / "bundle"
    assert (
        acquisition_cli._run_cli(
            ["--dataset-id", "stack-overflow", "--output-dir", str(output_dir)],
            acquirer=fake_acquirer,  # type: ignore[arg-type]
        )
        == 0
    )
    assert calls == [("stack-overflow", output_dir)]

    with pytest.raises(SystemExit):
        acquisition_cli._run_cli(
            [
                "--dataset-id",
                "stack-overflow",
                "--output-dir",
                str(output_dir),
                "--source-url",
                "https://example.invalid/forged",
            ],
            acquirer=fake_acquirer,  # type: ignore[arg-type]
        )
