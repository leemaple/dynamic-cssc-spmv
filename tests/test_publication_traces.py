import bz2
import gzip
import hashlib
import inspect
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import fields, replace
from datetime import datetime
from pathlib import Path

import pytest

import dynamic_cssc.publication_traces as publication_traces
from dynamic_cssc.publication_traces import (
    _PRODUCTION_CONFIG,
    LicenseTermsObject,
    LocalSourceObject,
    PublicationTraceRequest,
    _LocalTraceRequest,
    _nyc_events,
    _nyc_local_datetime,
    _prepare_publication_trace,
    _read_canonical_raw_events,
    _stack_overflow_events,
    _validate_publication_parquet_runtime,
    prepare_publication_trace,
    read_canonical_raw_events,
    source_partition,
)


def test_public_trace_request_accepts_only_a_closed_acquisition_bundle() -> None:
    assert tuple(field.name for field in fields(PublicationTraceRequest)) == (
        "dataset_id",
        "semantics",
        "source_partition",
        "acquisition_bundle_dir",
    )
    assert tuple(inspect.signature(prepare_publication_trace).parameters) == ("request",)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        PublicationTraceRequest(  # type: ignore[call-arg]
            dataset_id="simplewiki-2026-07",
            semantics="T1",
            source_partition=0,
            sources=(),
        )


def test_local_source_fixture_seam_is_guarded_outside_pytest() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from dynamic_cssc.publication_traces import "
                "_LocalTraceRequest,_PRODUCTION_CONFIG,_prepare_publication_trace,"
                "_test_only_repository_snapshot;"
                "_prepare_publication_trace("
                "_LocalTraceRequest('simplewiki-2026-07','T1',0,()),"
                "config=_PRODUCTION_CONFIG,"
                "repository_snapshot=_test_only_repository_snapshot())"
            ),
        ],
        cwd=repository_root,
        env={"PYTHONPATH": "src"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "available only under pytest" in completed.stderr


def _mediawiki_history_row(
    *,
    timestamp: str,
    user_id: int | None,
    page_id: int,
    namespace: int = 0,
    permanent: bool = True,
) -> str:
    fields = [""] * 78
    fields[0] = "simplewiki"
    fields[2] = "revision"
    fields[3] = "create"
    fields[4] = timestamp
    fields[6] = "" if user_id is None else str(user_id)
    fields[19] = "false" if permanent else "true"
    fields[20] = "false"
    fields[21] = "true" if permanent else "false"
    fields[28] = str(page_id)
    fields[31] = str(namespace)
    return "\t".join(fields) + "\n"


def _fixture_terms(path: Path, dataset_id: str) -> tuple[LicenseTermsObject, ...]:
    content = path.read_bytes()
    return tuple(
        LicenseTermsObject(
            source_url=source_url,
            final_url=source_url,
            http_status=200,
            media_type="text/html",
            retrieval_utc="2026-08-23T00:00:00Z",
            http_etag=None,
            http_last_modified=None,
            section_anchor=publication_traces._LICENSE_TERMS_SECTION_ANCHORS[source_url],
            path=path,
            byte_count=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
        )
        for source_url in sorted(publication_traces._LICENSE_TERMS_URLS[dataset_id])
    )


def _initialize_trace_behavior_repository(
    repository: Path,
    *,
    content_prefix: str,
) -> dict[str, str]:
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "publication-test@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Publication Test"],
        cwd=repository,
        check=True,
    )
    expected_sha256: dict[str, str] = {}
    for relative_path in publication_traces._PUBLICATION_BEHAVIOR_PATHS:
        content = f"{content_prefix}:{relative_path}\n".encode()
        behavior_source = repository / relative_path
        behavior_source.parent.mkdir(parents=True, exist_ok=True)
        behavior_source.write_bytes(content)
        expected_sha256[relative_path] = hashlib.sha256(content).hexdigest()
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "trace behavior snapshot"], cwd=repository, check=True)
    return expected_sha256


def test_production_trace_rejects_acquisition_bundle_inside_source_checkout(
    tmp_path: Path,
) -> None:
    del tmp_path
    repository_bundle = Path(publication_traces.__file__).resolve().parents[2] / "raw-bundle"

    with pytest.raises(ValueError, match="acquisition bundle directory .* outside"):
        prepare_publication_trace(
            PublicationTraceRequest(
                dataset_id="simplewiki-2026-07",
                semantics="T1",
                source_partition=0,
                acquisition_bundle_dir=repository_bundle,
            )
        )


def test_source_partition_uses_the_frozen_release_identity_concatenation() -> None:
    assert (
        source_partition(
            "mediawiki-history-2026-07-simplewiki-all-time",
            "wiki:page:00000000000000000042",
        )
        == 4
    )


def test_publication_parquet_runtime_is_exactly_the_preregistered_identity() -> None:
    identity = _validate_publication_parquet_runtime(
        implementation_name="cpython",
        python_version=(3, 12, 13),
        pyarrow_version="25.0.1",
        platform_name="darwin",
        machine="arm64",
        platform_tag="macosx-11.0-arm64",
        timezone_tzif_sha256=("e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"),
    )
    assert identity == {
        "container_image_digest": None,
        "implementation_name": "cpython",
        "machine": "arm64",
        "platform_name": "darwin",
        "platform_tag": "macosx-11.0-arm64",
        "pyarrow_version": "25.0.1",
        "python_version": "3.12.13",
        "schema_version": "dynamic-cssc-publication-parser-runtime-v1",
        "timezone_key": "America/New_York",
        "timezone_tzif_sha256": (
            "e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"
        ),
    }

    frozen_tzif = "e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"
    for implementation_name, python_version, pyarrow_version, timezone_sha256 in (
        ("pypy", (3, 12, 13), "25.0.1", frozen_tzif),
        ("cpython", (3, 12, 12), "25.0.1", frozen_tzif),
        ("cpython", (3, 12, 13), "24.0.0", frozen_tzif),
        ("cpython", (3, 12, 13), "25.0.1", "0" * 64),
    ):
        with pytest.raises(RuntimeError, match="frozen NYC TLC parser runtime"):
            _validate_publication_parquet_runtime(
                implementation_name=implementation_name,
                python_version=python_version,
                pyarrow_version=pyarrow_version,
                platform_name="darwin",
                machine="arm64",
                platform_tag="macosx-11.0-arm64",
                timezone_tzif_sha256=timezone_sha256,
            )

    with pytest.raises(RuntimeError, match="frozen NYC TLC parser runtime"):
        _validate_publication_parquet_runtime(
            implementation_name="cpython",
            python_version=(3, 12, 13),
            pyarrow_version="25.0.1",
            platform_name="win32",
            machine="AMD64",
            platform_tag="win-amd64",
            timezone_tzif_sha256=frozen_tzif,
        )


def test_nyc_timezone_bytes_are_verified_before_the_parser_uses_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timezone_path = tmp_path / "America" / "New_York"
    timezone_path.parent.mkdir()
    timezone_path.write_bytes(b"frozen fixture TZif bytes")
    expected_sha256 = hashlib.sha256(timezone_path.read_bytes()).hexdigest()
    monkeypatch.setattr(publication_traces, "TZPATH", (str(tmp_path),))
    monkeypatch.setattr(publication_traces, "_NYC_TZIF_SHA256", expected_sha256)

    assert publication_traces._nyc_tzif_sha256() == expected_sha256

    timezone_path.write_bytes(b"drifted TZif bytes")
    with pytest.raises(RuntimeError, match="TZif identity"):
        publication_traces._nyc_tzif_sha256()


def test_repository_snapshot_binds_frozen_behavior_sources_and_rejects_dirty_head(
    tmp_path: Path,
) -> None:
    assert set(publication_traces._PUBLICATION_BEHAVIOR_PATHS) == {
        "config/params_manifest.json",
        "docs/paper/publication-preregistration-draft.md",
        "docs/research/publication-venues-datasets-preregistration.md",
        "pyproject.toml",
        "requirements-publication.txt",
        ".github/workflows/publication-structure-pilot.yml",
        "scripts/prepare_publication_traces.py",
        "scripts/run_publication_structure_pilot.py",
        "src/dynamic_cssc/__init__.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/publication_acquisition.py",
        "src/dynamic_cssc/publication_artifact_install.py",
        "src/dynamic_cssc/publication_structure_pilot.py",
        "src/dynamic_cssc/publication_traces.py",
    }
    repository = tmp_path / "repository"
    expected_sha256 = _initialize_trace_behavior_repository(
        repository,
        content_prefix="trusted",
    )

    snapshot = publication_traces._verify_clean_repository_snapshot(repository)

    assert snapshot.verification_mode == "hardened-trace-role-git-object-worktree-v1"
    assert snapshot.behavior_source_blob_sha256 == expected_sha256
    assert len(snapshot.source_git_sha) == 40
    assert tuple(
        inspect.signature(publication_traces._verify_clean_repository_snapshot).parameters
    ) == ("repository_root",)

    (repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="clean|stable"):
        publication_traces._verify_clean_repository_snapshot(repository)


def test_repository_snapshot_ignores_ambient_git_repository_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    redirected = tmp_path / "redirected"
    expected_sha256 = _initialize_trace_behavior_repository(
        repository,
        content_prefix="repository-head",
    )
    _initialize_trace_behavior_repository(
        redirected,
        content_prefix="redirected-head",
    )
    expected_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setenv("GIT_DIR", str(redirected / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(repository))

    snapshot = publication_traces._verify_clean_repository_snapshot(repository)

    assert snapshot.source_git_sha == expected_head
    assert snapshot.behavior_source_blob_sha256 == expected_sha256


def test_stack_overflow_adapter_normalizes_events_and_reports_rejections(tmp_path: Path) -> None:
    source_path = tmp_path / "sx-stackoverflow-a2q.txt.gz"
    with gzip.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write("# SRC DST UNIXTS\n1 2 123\n3 3 124\nbroken\n")
    source_bytes = source_path.read_bytes()
    source = LocalSourceObject(
        role="a2q",
        path=source_path,
        source_url="https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz",
        final_url="https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz",
        http_status=200,
        media_type="application/gzip",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(source_bytes),
        http_etag=None,
        http_last_modified="Mon, 23 Aug 2026 00:00:00 GMT",
        local_sha256=hashlib.sha256(source_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=_fixture_terms(source_path, "stack-overflow"),
        attribution_text="SNAP Stack Overflow temporal network",
    )

    with pytest.raises(ValueError, match="exact frozen source roles"):
        read_canonical_raw_events("stack-overflow", (source,))

    events, receipts = _stack_overflow_events((source,))

    assert len(events) == 1
    event = events[0]
    assert (
        event.timestamp_utc,
        event.source_file_ordinal,
        event.within_file_ordinal,
        event.canonical_source_id,
        event.canonical_target_id,
        event.source_event_type,
    ) == (
        "1970-01-01T00:02:03.000000Z",
        0,
        1,
        "stack-overflow:user:00000000000000000001",
        "stack-overflow:user:00000000000000000002",
        "a2q",
    )
    assert receipts[0].rejected_event_counts == {
        "malformed-record": 1,
        "self-loop": 1,
    }

    with pytest.raises(ValueError, match="publisher_sha256 does not match"):
        _stack_overflow_events((replace(source, publisher_sha256="0" * 64),))

    with pytest.raises(ValueError, match="unexpected HTTP redirect"):
        _stack_overflow_events((replace(source, final_url="https://redirect.invalid/source.gz"),))
    with pytest.raises(ValueError, match="strict integer 200"):
        _stack_overflow_events((replace(source, http_status=206),))
    with pytest.raises(ValueError, match="frozen type set"):
        _stack_overflow_events((replace(source, media_type=""),))
    tampered_terms = (
        replace(source.license_terms_objects[0], sha256="0" * 64),
        *source.license_terms_objects[1:],
    )
    with pytest.raises(ValueError, match="sha256 does not match"):
        _stack_overflow_events((replace(source, license_terms_objects=tampered_terms),))
    with pytest.raises(ValueError, match="frozen type set"):
        _stack_overflow_events(
            (
                replace(
                    source,
                    license_terms_objects=(
                        replace(source.license_terms_objects[0], media_type="text/plain"),
                        *source.license_terms_objects[1:],
                    ),
                ),
            )
        )
    with pytest.raises(ValueError, match="retrieval_utc"):
        _stack_overflow_events(
            (
                replace(
                    source,
                    license_terms_objects=(
                        replace(source.license_terms_objects[0], retrieval_utc="not-a-time"),
                        *source.license_terms_objects[1:],
                    ),
                ),
            )
        )
    with pytest.raises(ValueError, match="section anchor"):
        _stack_overflow_events(
            (
                replace(
                    source,
                    license_terms_objects=(
                        replace(source.license_terms_objects[0], section_anchor="retargeted"),
                        *source.license_terms_objects[1:],
                    ),
                ),
            )
        )
    with pytest.raises(ValueError, match="exact frozen official URL set"):
        _stack_overflow_events(
            (replace(source, license_terms_objects=source.license_terms_objects[:1]),)
        )

    with pytest.raises(
        ValueError,
        match=r"publication preparation requires the exact frozen source roles;.*c2a.*c2q",
    ):
        _prepare_publication_trace(
            _LocalTraceRequest(
                dataset_id="stack-overflow",
                semantics="T1",
                source_partition=0,
                sources=(source,),
            ),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=publication_traces._test_only_repository_snapshot(),
        )


def test_stack_overflow_adapter_uses_fixed_file_then_row_ties_not_input_order(
    tmp_path: Path,
) -> None:
    def stack_source(role: str, rows: str) -> LocalSourceObject:
        source_path = tmp_path / f"sx-stackoverflow-{role}.txt.gz"
        with gzip.open(source_path, "wt", encoding="utf-8", newline="") as handle:
            handle.write(rows)
        content = source_path.read_bytes()
        return LocalSourceObject(
            role=role,
            path=source_path,
            source_url=f"https://snap.stanford.edu/data/sx-stackoverflow-{role}.txt.gz",
            final_url=f"https://snap.stanford.edu/data/sx-stackoverflow-{role}.txt.gz",
            http_status=200,
            media_type="application/gzip",
            retrieval_utc="2026-08-23T00:00:00Z",
            byte_count=len(content),
            http_etag=None,
            http_last_modified=None,
            local_sha256=hashlib.sha256(content).hexdigest(),
            publisher_sha256=None,
            license_terms_objects=_fixture_terms(source_path, "stack-overflow"),
            attribution_text="SNAP Stack Overflow temporal network",
        )

    a2q = stack_source("a2q", "1 2 123\n3 4 123\n")
    c2q = stack_source("c2q", "5 6 123\n")

    events, _receipts = _stack_overflow_events((c2q, a2q))

    assert [
        (event.source_file_ordinal, event.within_file_ordinal, event.source_event_type)
        for event in events
    ] == [(0, 0, "a2q"), (0, 1, "a2q"), (1, 0, "c2q")]


def test_verified_source_snapshot_rejects_symlinks_and_survives_path_replacement(
    tmp_path: Path,
) -> None:
    trusted_path = tmp_path / "trusted-a2q.txt.gz"
    malicious_path = tmp_path / "malicious-a2q.txt.gz"
    with gzip.open(trusted_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write("1 2 123\n")
    with gzip.open(malicious_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write("90 91 123\n")
    terms_path = tmp_path / "stack-overflow-terms.html"
    terms_path.write_text("fixture terms\n", encoding="utf-8")
    trusted_bytes = trusted_path.read_bytes()
    source = LocalSourceObject(
        role="a2q",
        path=trusted_path,
        source_url="https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz",
        final_url="https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz",
        http_status=200,
        media_type="application/gzip",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(trusted_bytes),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(trusted_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=_fixture_terms(terms_path, "stack-overflow"),
        attribution_text="SNAP Stack Overflow temporal network",
    )

    symlink_path = tmp_path / "source-link.txt.gz"
    symlink_path.symlink_to(trusted_path)
    with pytest.raises(ValueError, match="symbolic link"):
        _stack_overflow_events((replace(source, path=symlink_path),))

    snapshot_paths: list[Path] = []

    def replace_source_after_snapshot(
        original_source: LocalSourceObject,
        snapshot_source: LocalSourceObject,
    ) -> None:
        snapshot_paths.append(snapshot_source.path)
        assert snapshot_source.path != original_source.path
        assert snapshot_source.path.stat().st_mode & 0o777 == 0o400
        original_source.path.unlink()
        original_source.path.symlink_to(malicious_path)

    events, receipts = _stack_overflow_events(
        (source,),
        _test_only_after_source_snapshot=replace_source_after_snapshot,
    )

    assert [event.canonical_source_id for event in events] == [
        "stack-overflow:user:00000000000000000001"
    ]
    assert receipts[0].local_sha256 == hashlib.sha256(trusted_bytes).hexdigest()
    assert len(snapshot_paths) == 1
    assert not snapshot_paths[0].exists()


@pytest.mark.parametrize("replacement_target", ("snapshot-directory", "snapshot-file"))
def test_verified_source_snapshot_preserves_a_racing_replacement_on_cleanup(
    tmp_path: Path,
    replacement_target: str,
) -> None:
    trusted_path = tmp_path / "trusted-source"
    trusted_path.write_bytes(b"trusted source bytes\n")
    terms_path = tmp_path / "terms.html"
    terms_path.write_text("fixture terms\n", encoding="utf-8")
    trusted_bytes = trusted_path.read_bytes()
    source_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    terms = _fixture_terms(terms_path, "stack-overflow")
    source = LocalSourceObject(
        role="a2q",
        path=trusted_path,
        source_url=source_url,
        final_url=source_url,
        http_status=200,
        media_type="application/gzip",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(trusted_bytes),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(trusted_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=terms,
        attribution_text="fixture",
    )
    replacement_marker: Path | None = None
    moved_owned_path: Path | None = None

    with (
        pytest.raises(RuntimeError, match="snapshot.*cleanup"),
        publication_traces._verified_source_snapshot(
            source,
            expected_url=source_url,
            expected_license_urls=frozenset(item.source_url for item in terms),
        ) as snapshot,
    ):
        snapshot_directory = snapshot.path.parent
        if replacement_target == "snapshot-directory":
            moved_owned_path = snapshot_directory.with_name(f"{snapshot_directory.name}-moved")
            snapshot_directory.rename(moved_owned_path)
            snapshot_directory.mkdir(mode=0o700)
            replacement_marker = snapshot_directory / "foreign-owner"
            replacement_marker.write_text("preserve\n", encoding="ascii")
        else:
            moved_owned_path = snapshot.path.with_name(f"{snapshot.path.name}-moved")
            snapshot.path.rename(moved_owned_path)
            replacement_marker = snapshot.path
            replacement_marker.write_text("preserve\n", encoding="ascii")

    assert replacement_marker is not None
    assert replacement_marker.read_text(encoding="ascii") == "preserve\n"
    assert moved_owned_path is not None and moved_owned_path.exists()


@pytest.mark.parametrize("replacement_target", ("snapshot-file", "snapshot-directory"))
def test_verified_source_snapshot_never_removes_a_delete_time_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_target: str,
) -> None:
    trusted_path = tmp_path / "trusted-source"
    trusted_path.write_bytes(b"trusted source bytes\n")
    terms_path = tmp_path / "terms.html"
    terms_path.write_text("fixture terms\n", encoding="utf-8")
    trusted_bytes = trusted_path.read_bytes()
    source_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    terms = _fixture_terms(terms_path, "stack-overflow")
    source = LocalSourceObject(
        role="a2q",
        path=trusted_path,
        source_url=source_url,
        final_url=source_url,
        http_status=200,
        media_type="application/gzip",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(trusted_bytes),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(trusted_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=terms,
        attribution_text="fixture",
    )
    snapshot_path: Path | None = None
    replacement_path: Path | None = None
    attacked = False
    original_unlink = os.unlink
    original_rmdir = os.rmdir

    def race_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal attacked, replacement_path
        name = os.fsdecode(path)
        if (
            replacement_target == "snapshot-file"
            and snapshot_path is not None
            and not attacked
            and "source-object" in name
        ):
            attacked = True
            if dir_fd is None:
                snapshot_path.rename(snapshot_path.with_name("source-object.owned"))
                replacement_path = snapshot_path
                replacement_path.write_text("replacement must survive\n", encoding="ascii")
            else:
                descriptor = os.open(
                    "source-object",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(b"replacement must survive\n")
                replacement_path = snapshot_path
        if dir_fd is None:
            original_unlink(path)
        else:
            original_unlink(path, dir_fd=dir_fd)

    def race_rmdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal attacked, replacement_path
        name = os.fsdecode(path)
        if (
            replacement_target == "snapshot-directory"
            and snapshot_path is not None
            and not attacked
            and snapshot_path.parent.name in name
        ):
            attacked = True
            snapshot_directory = snapshot_path.parent
            if dir_fd is None:
                snapshot_directory.rename(
                    snapshot_directory.with_name(f"{snapshot_directory.name}.owned")
                )
            replacement_path = snapshot_directory
            replacement_path.mkdir(mode=0o700)
        if dir_fd is None:
            original_rmdir(path)
        else:
            original_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", race_unlink)
    monkeypatch.setattr(os, "rmdir", race_rmdir)

    with (
        pytest.raises(RuntimeError, match="snapshot.*cleanup"),
        publication_traces._verified_source_snapshot(
            source,
            expected_url=source_url,
            expected_license_urls=frozenset(item.source_url for item in terms),
        ) as snapshot,
    ):
        snapshot_path = snapshot.path

    assert attacked
    assert replacement_path is not None
    if replacement_target == "snapshot-file":
        assert replacement_path.read_text(encoding="ascii") == "replacement must survive\n"
    else:
        assert replacement_path.is_dir()


def test_simplewiki_adapter_keeps_only_permanent_main_namespace_revisions(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "2026-07.simplewiki.all-time.tsv.bz2"
    rows = "".join(
        (
            _mediawiki_history_row(timestamp="2020-01-02 03:04:05.0", user_id=9, page_id=5),
            _mediawiki_history_row(
                timestamp="2020-01-02 03:04:06.0",
                user_id=9,
                page_id=6,
                namespace=1,
            ),
            _mediawiki_history_row(
                timestamp="2020-01-02 03:04:07.0",
                user_id=None,
                page_id=7,
                permanent=False,
            ),
        )
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)
    source_bytes = source_path.read_bytes()
    source = LocalSourceObject(
        role="history",
        path=source_path,
        source_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        final_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        http_status=200,
        media_type="application/octet-stream",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(source_bytes),
        http_etag='"fixture-etag"',
        http_last_modified=None,
        local_sha256=hashlib.sha256(source_bytes).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=_fixture_terms(source_path, "simplewiki-2026-07"),
        attribution_text="Wikimedia Analytics MediaWiki History (CC0)",
    )

    batch = read_canonical_raw_events("simplewiki-2026-07", (source,))

    assert len(batch.events) == 1
    event = batch.events[0]
    assert (
        event.timestamp_utc,
        event.canonical_source_id,
        event.canonical_target_id,
        event.source_event_type,
    ) == (
        "2020-01-02T03:04:05.000000Z",
        "wiki:page:00000000000000000005",
        "wiki:user:00000000000000000009",
        "revision-create",
    )
    assert batch.receipts[0].rejected_event_counts == {
        "non-main-namespace": 1,
        "non-permanent-contributor": 1,
    }

    header_path = tmp_path / "headerful-simplewiki.tsv.bz2"
    header_fields = [""] * 78
    header_fields[0] = "wiki_db"
    with bz2.open(header_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write("\t".join(header_fields) + "\n")
    header_bytes = header_path.read_bytes()
    with pytest.raises(ValueError, match="frozen headerless 78-column schema"):
        read_canonical_raw_events(
            "simplewiki-2026-07",
            (
                replace(
                    source,
                    path=header_path,
                    byte_count=len(header_bytes),
                    local_sha256=hashlib.sha256(header_bytes).hexdigest(),
                ),
            ),
        )


def test_nyc_adapter_time_expands_valid_zone_pairs_from_a_small_fixture(
    tmp_path: Path,
) -> None:
    zones_path = tmp_path / "taxi_zone_lookup.csv"
    zones_path.write_text("LocationID,Zone\n1,Alpha\n2,Beta\n", encoding="utf-8")
    trips_path = tmp_path / "yellow_tripdata_2022-01.fixture.csv"
    trips_path.write_text(
        "tpep_pickup_datetime,tpep_dropoff_datetime,PULocationID,DOLocationID\n"
        "2022-01-03 00:00:00,2022-01-03 00:16:00,1,2\n"
        "2022-01-03 00:20:00,2022-01-03 00:10:00,1,2\n"
        "2022-01-03 00:30:00,2022-01-03 00:40:00,99,2\n"
        "2022-03-13 02:30:00,2022-03-13 03:30:00,1,2\n"
        "2022-02-01 00:00:00,2022-02-01 00:10:00,1,2\n",
        encoding="utf-8",
    )

    def local_source(path: Path, *, role: str, source_url: str) -> LocalSourceObject:
        content = path.read_bytes()
        return LocalSourceObject(
            role=role,
            path=path,
            source_url=source_url,
            final_url=source_url,
            http_status=200,
            media_type=(
                "text/csv"
                if role == "zone-lookup"
                else "application/x-www-form-urlencoded; charset=utf-8"
            ),
            retrieval_utc="2026-08-23T00:00:00Z",
            byte_count=len(content),
            http_etag=None,
            http_last_modified=None,
            local_sha256=hashlib.sha256(content).hexdigest(),
            publisher_sha256=None,
            license_terms_objects=_fixture_terms(path, "nyc-tlc-yellow-2022"),
            attribution_text="NYC Taxi and Limousine Commission",
        )

    trip_source = local_source(
        trips_path,
        role="yellow-2022-01",
        source_url=(
            "https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-01.parquet"
        ),
    )
    zone_source = local_source(
        zones_path,
        role="zone-lookup",
        source_url="https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv",
    )
    with pytest.raises(ValueError, match="exact frozen source roles"):
        _read_canonical_raw_events(
            "nyc-tlc-yellow-2022",
            (trip_source, zone_source),
            config=replace(_PRODUCTION_CONFIG, allow_fixture_tlc_csv=True),
        )
    snapshot_paths: list[Path] = []

    def observe_sequential_snapshot(
        _original_source: LocalSourceObject,
        snapshot_source: LocalSourceObject,
    ) -> None:
        assert all(not previous.exists() for previous in snapshot_paths)
        snapshot_paths.append(snapshot_source.path)

    events, receipts = _nyc_events(
        (trip_source, zone_source),
        config=replace(_PRODUCTION_CONFIG, allow_fixture_tlc_csv=True),
        _test_only_after_source_snapshot=observe_sequential_snapshot,
    )

    assert len(events) == 1
    event = events[0]
    assert (
        event.timestamp_utc,
        event.canonical_source_id,
        event.canonical_target_id,
    ) == (
        "2022-01-03T05:00:00.000000Z",
        "nyc:pickup:zone:001:bin:000",
        "nyc:dropoff:zone:002:bin:001",
    )
    assert receipts[0].rejected_event_counts == {
        "dropoff-before-pickup": 1,
        "invalid-zone": 1,
        "nonexistent-local-time": 1,
        "pickup-outside-source-month": 1,
    }
    assert len(snapshot_paths) == 2
    assert all(not snapshot_path.exists() for snapshot_path in snapshot_paths)
    with pytest.raises(
        ValueError,
        match="publication preparation requires the exact frozen source roles",
    ):
        _prepare_publication_trace(
            _LocalTraceRequest(
                dataset_id="nyc-tlc-yellow-2022",
                semantics="T1",
                source_partition=0,
                sources=(trip_source, zone_source),
            ),
            config=_PRODUCTION_CONFIG,
            repository_snapshot=publication_traces._test_only_repository_snapshot(),
        )


def test_nyc_wall_clock_rejects_nonexistent_time_and_freezes_first_ambiguous_fold() -> None:
    with pytest.raises(ValueError, match="nonexistent America/New_York local time"):
        _nyc_local_datetime(datetime(2022, 3, 13, 2, 30))

    ambiguous = _nyc_local_datetime(datetime(2022, 11, 6, 1, 30))
    assert ambiguous.fold == 0
    assert ambiguous.utcoffset() is not None
    assert ambiguous.utcoffset().total_seconds() == -4 * 60 * 60


def test_t1_trace_uses_prefix_mapping_and_logs_clipped_noops(tmp_path: Path) -> None:
    source_path = tmp_path / "2026-07.simplewiki.all-time.tsv.bz2"
    rows = "".join(
        _mediawiki_history_row(timestamp=f"2020-01-01 00:00:{second:02d}.0", user_id=9, page_id=2)
        for second in range(10)
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)
    content = source_path.read_bytes()
    source = LocalSourceObject(
        role="history",
        path=source_path,
        source_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        final_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        http_status=200,
        media_type="application/octet-stream",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(content),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(content).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=_fixture_terms(source_path, "simplewiki-2026-07"),
        attribution_text="Wikimedia Analytics MediaWiki History (CC0)",
    )
    request = _LocalTraceRequest(
        dataset_id="simplewiki-2026-07",
        semantics="T1",
        source_partition=0,
        sources=(source,),
    )
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

    repository_snapshot = publication_traces._test_only_repository_snapshot()
    bundle = _prepare_publication_trace(
        request,
        config=config,
        repository_snapshot=repository_snapshot,
    )

    assert [record.operation for record in bundle.records] == [
        "insert",
        "modify",
        "modify",
        "modify",
        "modify",
        "modify",
        "modify",
        "clipped-no-op",
        "clipped-no-op",
    ]
    assert [(record.before, record.after) for record in bundle.records] == [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 5),
        (5, 6),
        (6, 7),
        (7, 7),
        (7, 7),
    ]
    assert bundle.manifest["mapping"]["row_ids"] == ["wiki:page:00000000000000000002"]
    assert bundle.manifest["mapping"]["column_ids"] == ["wiki:user:00000000000000000009"]
    assert (
        bundle.manifest["mapping"]["mapping_sha256"]
        == "80142710f3b2ba30b3d5da4ea398d3979a723afb99996e90d5df3419969dae7c"
    )
    query_vector = json.loads(bundle.query_vector_bytes)
    assert query_vector == {
        "coefficient_bound": 1,
        "dataset_id": "simplewiki-2026-07",
        "dataset_release": "mediawiki-history-2026-07-simplewiki-all-time",
        "generation": "shake256-per-coordinate-rejection-sampling",
        "length": 1,
        "mapping_sha256": bundle.manifest["mapping"]["mapping_sha256"],
        "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
        "schema_version": "dynamic-cssc-publication-query-vector-v1",
        "seed": 2026082302,
        "semantics": "T1",
        "source_partition": 0,
        "values": [1],
    }
    assert bundle.manifest["query_vector"] == {
        "filename": "publication-query-vector.json",
        "length": 1,
        "query_vector_sha256": hashlib.sha256(bundle.query_vector_bytes).hexdigest(),
        "schema_version": "dynamic-cssc-publication-query-vector-v1",
    }
    assert bundle.manifest["frozen_contract"]["query_vector_generation"] == {
        "coefficient_bound": 1,
        "forced_boundary_entries": {"0": 1},
        "generation": "shake256-per-coordinate-rejection-sampling",
        "length": 1,
        "evaluation_query_plaintext_public": True,
        "query_distribution_claim_allowed": False,
        "query_confidentiality_evidence_allowed": False,
        "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
        "schema_version": "dynamic-cssc-publication-query-vector-v1",
        "security_randomness_claim_allowed": False,
        "seed": 2026082302,
    }
    assert bundle.manifest["trace"] == {
        "accepted_raw_events": 9,
        "clipped_noops": 2,
        "complete_publication_window_lower_bound": 2,
        "logical_changes": 7,
        "target_reached": True,
        "transition_records": 9,
    }
    assert bundle.manifest["eligibility"] == {
        "eligible": True,
        "failure_reasons": [],
        "replacement_allowed": False,
    }
    assert bundle.manifest["operation_counts"] == {
        "insert": 1,
        "modify": 6,
        "delete": 0,
        "clipped-no-op": 2,
    }
    provenance = bundle.manifest["repository_provenance"]
    assert set(provenance) == {
        "schema_version",
        "source_git_sha",
        "behavior_source_blob_sha256",
        "verification_mode",
        "repository_provenance_sha256",
    }
    assert provenance["source_git_sha"] == "f" * 40
    assert set(provenance["behavior_source_blob_sha256"]) == set(
        publication_traces._PUBLICATION_BEHAVIOR_PATHS
    )
    assert {record.repository_provenance_sha256 for record in bundle.records} == {
        provenance["repository_provenance_sha256"]
    }
    assert len(bundle.manifest["accepted_raw_event_sha256"]) == 64

    padded = _prepare_publication_trace(
        request,
        config=replace(config, cols=2),
        repository_snapshot=repository_snapshot,
    )
    assert padded.manifest["mapping"]["column_ids"] == [
        "wiki:user:00000000000000000009",
        "reserved-empty-column:simplewiki-2026-07:partition-0:00000",
    ]
    assert padded.manifest["eligibility"] == {
        "eligible": False,
        "failure_reasons": ["reserved-column-padding-exceeds-10-percent:1/2"],
        "replacement_allowed": False,
    }


def test_t2_expires_before_admission_as_two_ordered_transitions(tmp_path: Path) -> None:
    source_path = tmp_path / "2026-07.simplewiki.all-time.tsv.bz2"
    user_ids = [9, 10, 9, 9, 10, 9, *([9] * 14)]
    rows = "".join(
        _mediawiki_history_row(
            timestamp=f"2020-01-01 00:00:{second:02d}.0",
            user_id=user_id,
            page_id=2,
        )
        for second, user_id in enumerate(user_ids)
    )
    with bz2.open(source_path, "wt", encoding="utf-8", newline="") as handle:
        handle.write(rows)
    content = source_path.read_bytes()
    source = LocalSourceObject(
        role="history",
        path=source_path,
        source_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        final_url=(
            "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
            "2026-07.simplewiki.all-time.tsv.bz2"
        ),
        http_status=200,
        media_type="application/octet-stream",
        retrieval_utc="2026-08-23T00:00:00Z",
        byte_count=len(content),
        http_etag=None,
        http_last_modified=None,
        local_sha256=hashlib.sha256(content).hexdigest(),
        publisher_sha256=None,
        license_terms_objects=_fixture_terms(source_path, "simplewiki-2026-07"),
        attribution_text="Wikimedia Analytics MediaWiki History (CC0)",
    )
    request = _LocalTraceRequest(
        dataset_id="simplewiki-2026-07",
        semantics="T2",
        source_partition=0,
        sources=(source,),
    )
    config = replace(
        _PRODUCTION_CONFIG,
        rows=1,
        cols=4,
        event_window_size=2,
        target_accepted_events=4,
        minimum_logical_changes=6,
        microbatch_cap=2,
        minimum_complete_window_lower_bound=2,
        maximum_row_nonzeros=2,
    )

    bundle = _prepare_publication_trace(
        request,
        config=config,
        repository_snapshot=publication_traces._test_only_repository_snapshot(),
    )
    query_vector = json.loads(bundle.query_vector_bytes)
    assert len(query_vector["values"]) == 4
    assert query_vector["values"][0] == 1
    assert query_vector["values"][-1] == -1
    assert set(query_vector["values"]) <= {-1, 0, 1}
    repeated_bundle = _prepare_publication_trace(
        request,
        config=config,
        repository_snapshot=publication_traces._test_only_repository_snapshot(),
    )
    assert repeated_bundle.query_vector_bytes == bundle.query_vector_bytes

    assert [
        (record.accepted_event_ordinal, record.transition_ordinal, record.transition_cause)
        for record in bundle.records
    ] == [
        (0, 1, "admission"),
        (1, 1, "admission"),
        (2, 0, "expiry"),
        (2, 1, "admission"),
        (3, 0, "expiry"),
        (3, 1, "admission"),
    ]
    assert [(record.operation, record.before, record.after) for record in bundle.records] == [
        ("insert", 0, 1),
        ("modify", 1, 2),
        ("modify", 2, 1),
        ("insert", 0, 1),
        ("delete", 1, 0),
        ("insert", 0, 1),
    ]
    first_expiry = bundle.records[2]
    first_admission = bundle.records[3]
    assert first_expiry.trigger_event == first_admission.trigger_event
    assert first_expiry.subject_event == bundle.records[0].subject_event
    assert first_expiry.trigger_event.canonical_raw_event_ordinal > (
        first_expiry.subject_event.canonical_raw_event_ordinal
    )
    assert first_expiry.trigger_event.within_file_ordinal > (
        first_expiry.subject_event.within_file_ordinal
    )
    assert first_expiry.trigger_event.source_timestamp_utc != (
        first_expiry.subject_event.source_timestamp_utc
    )
    assert first_admission.trigger_event == first_admission.subject_event
    assert bundle.manifest["trace"] == {
        "accepted_raw_events": 4,
        "clipped_noops": 0,
        "complete_publication_window_lower_bound": 2,
        "logical_changes": 6,
        "target_reached": True,
        "transition_records": 6,
    }
    assert bundle.manifest["frozen_contract"]["microbatch_cap_unit"] == (
        "emitted-logical-set-transitions"
    )
    assert bundle.manifest["frozen_contract"]["atomic_transition_group_policy"] == (
        "accepted-event-group-never-split"
    )
    assert bundle.manifest["frozen_contract"]["t2_expiry_event_provenance"] == (
        "trigger-event-is-incoming-raw-event;subject-event-is-expired-raw-event"
    )
    assert bundle.manifest["frozen_contract"]["maximum_transitions_per_microbatch_window"] == 3
    assert bundle.manifest["frozen_contract"]["query_arrival_schedule"] == {
        "accepted_event_ordinal_origin": 0,
        "clipped_noop_policy": "counts-in-denominator-emits-tick-no-set",
        "cumulative_query_rule": "floor(N*rho)",
        "grouping_key": "accepted_event_ordinal",
        "logical_tick_policy": "one-tick-after-every-complete-accepted-event-group",
        "query_placement": "after-complete-group",
        "rho_denominator_kind": "accepted-raw-event",
        "scheduled_event_order": "set-transitions-then-tick-then-queries",
        "schema_version": "dynamic-cssc-query-arrival-schedule-v1",
        "within_group_order": "transition_ordinal-ascending",
    }


def test_transform_sink_only_is_single_pass_and_equivalent_to_retained_records() -> None:
    dataset_id = "simplewiki-2026-07"
    dataset_release = publication_traces.frozen_dataset_release(dataset_id)
    source_id = next(
        f"stream-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"stream-source-{ordinal}") == 0
    )
    target_id = "stream-target"
    events = tuple(
        publication_traces.CanonicalRawEvent(
            schema_version=publication_traces.CANONICAL_RAW_EVENT_SCHEMA,
            timestamp_utc=f"2020-01-01T00:00:00.{ordinal:06d}Z",
            source_file_ordinal=0,
            within_file_ordinal=ordinal,
            canonical_source_id=source_id,
            canonical_target_id=target_id,
            source_event_type="fixture",
        )
        for ordinal in range(5)
    )
    batch = publication_traces.CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=dataset_release,
        events=(),
        receipts=(),
    )
    config = replace(_PRODUCTION_CONFIG, rows=1, cols=1, event_window_size=2)
    retained = publication_traces._transform_events(
        batch,
        ordered_events=enumerate(events),
        semantics="T2",
        source_partition_id=0,
        repository_provenance_sha256="0" * 64,
        row_index={source_id: 0},
        column_index={target_id: 0},
        config=config,
        accepted_event_limit=None,
    )
    streamed_records: list[publication_traces.PublicationTransition] = []

    def single_pass_events() -> object:
        for ordinal, event in enumerate(events):
            if ordinal:
                assert streamed_records, "sink must run before the next input event is requested"
            yield ordinal, event

    streamed = publication_traces._transform_events(
        batch,
        ordered_events=single_pass_events(),  # type: ignore[arg-type]
        semantics="T2",
        source_partition_id=0,
        repository_provenance_sha256="0" * 64,
        row_index={source_id: 0},
        column_index={target_id: 0},
        config=config,
        accepted_event_limit=None,
        record_sink=streamed_records.append,
        retain_records=False,
    )

    assert tuple(streamed_records) == retained.records
    assert streamed.records == ()
    assert streamed.filter_counts == retained.filter_counts
    assert streamed.accepted_raw_event_sha256 == retained.accepted_raw_event_sha256
    assert streamed.source_event_type_counts == retained.source_event_type_counts
    assert streamed.accepted_event_count == 5
    assert streamed.transition_record_count == 8
    assert streamed.operation_counts == retained.operation_counts
    assert streamed.maximum_transition_group_size_observed == 2
    assert streamed.event_window_peak_groups == 2


def test_transform_streaming_preserves_filter_accounting_after_target() -> None:
    dataset_id = "simplewiki-2026-07"
    dataset_release = publication_traces.frozen_dataset_release(dataset_id)
    selected_source = next(
        f"selected-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"selected-source-{ordinal}") == 0
    )
    unselected_source = next(
        f"unselected-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"unselected-source-{ordinal}") == 0
        and f"unselected-source-{ordinal}" != selected_source
    )
    other_partition_source = next(
        f"other-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"other-source-{ordinal}") == 1
    )
    pairs = (
        (selected_source, "selected-target"),
        (selected_source, "selected-target"),
        (other_partition_source, "selected-target"),
        (unselected_source, "selected-target"),
        (selected_source, "unselected-target"),
    )
    events = tuple(
        publication_traces.CanonicalRawEvent(
            schema_version=publication_traces.CANONICAL_RAW_EVENT_SCHEMA,
            timestamp_utc=f"2020-01-01T00:00:00.{ordinal:06d}Z",
            source_file_ordinal=0,
            within_file_ordinal=ordinal,
            canonical_source_id=source_id,
            canonical_target_id=target_id,
            source_event_type="fixture",
        )
        for ordinal, (source_id, target_id) in enumerate(pairs)
    )
    observed_ordinals: list[int] = []

    def observed_events() -> object:
        for ordinal, event in enumerate(events):
            observed_ordinals.append(ordinal)
            yield ordinal, event

    result = publication_traces._transform_events(
        publication_traces.CanonicalRawEventBatch(
            dataset_id=dataset_id,
            dataset_release=dataset_release,
            events=(),
            receipts=(),
        ),
        ordered_events=observed_events(),  # type: ignore[arg-type]
        semantics="T1",
        source_partition_id=0,
        repository_provenance_sha256="0" * 64,
        row_index={selected_source: 0},
        column_index={"selected-target": 0},
        config=replace(_PRODUCTION_CONFIG, rows=1, cols=1),
        accepted_event_limit=1,
        retain_records=False,
    )

    assert observed_ordinals == list(range(len(events)))
    assert result.filter_counts == {
        "after-target": 1,
        "other-source-partition": 1,
        "unselected-source": 1,
        "unselected-target": 1,
    }


def test_t2_transform_live_coordinate_state_is_bounded_by_the_event_window() -> None:
    dataset_id = "simplewiki-2026-07"
    dataset_release = publication_traces.frozen_dataset_release(dataset_id)
    source_id = next(
        f"window-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"window-source-{ordinal}") == 0
    )
    events = tuple(
        publication_traces.CanonicalRawEvent(
            schema_version=publication_traces.CANONICAL_RAW_EVENT_SCHEMA,
            timestamp_utc=f"2020-01-01T00:00:00.{ordinal:06d}Z",
            source_file_ordinal=0,
            within_file_ordinal=ordinal,
            canonical_source_id=source_id,
            canonical_target_id=f"target-{ordinal}",
            source_event_type="fixture",
        )
        for ordinal in range(20)
    )
    result = publication_traces._transform_events(
        publication_traces.CanonicalRawEventBatch(
            dataset_id=dataset_id,
            dataset_release=dataset_release,
            events=(),
            receipts=(),
        ),
        ordered_events=enumerate(events),
        semantics="T2",
        source_partition_id=0,
        repository_provenance_sha256="0" * 64,
        row_index={source_id: 0},
        column_index={event.canonical_target_id: ordinal for ordinal, event in enumerate(events)},
        config=replace(_PRODUCTION_CONFIG, rows=1, cols=20, event_window_size=2),
        accepted_event_limit=None,
        retain_records=False,
    )

    assert result.event_window_peak_groups == 2
    assert result.peak_live_coordinate_count == 2


def test_canonical_store_disk_mapping_is_exactly_equivalent_to_frozen_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset_id = "simplewiki-2026-07"
    dataset_release = publication_traces.frozen_dataset_release(dataset_id)
    partition_zero_sources = tuple(
        f"mapped-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"mapped-source-{ordinal}") == 0
    )[:3]
    other_source = next(
        f"other-source-{ordinal}"
        for ordinal in range(10_000)
        if source_partition(dataset_release, f"other-source-{ordinal}") == 1
    )
    partition_zero_sources = tuple(sorted(partition_zero_sources))
    prefix_pairs = (
        *((partition_zero_sources[1], "target-a") for _ in range(3)),
        *((partition_zero_sources[2], "target-b") for _ in range(3)),
        *((partition_zero_sources[0], "target-c") for _ in range(2)),
        *((other_source, "ignored-target") for _ in range(2)),
    )
    suffix_pairs = (
        (partition_zero_sources[0], "cutoff-lure"),
        *tuple((partition_zero_sources[0], f"suffix-{ordinal}") for ordinal in range(10)),
    )
    events = tuple(
        publication_traces.CanonicalRawEvent(
            schema_version=publication_traces.CANONICAL_RAW_EVENT_SCHEMA,
            timestamp_utc="2020-01-01T00:00:00.000000Z",
            source_file_ordinal=ordinal // 11,
            within_file_ordinal=ordinal % 11,
            canonical_source_id=source_id,
            canonical_target_id=target_id,
            source_event_type="fixture",
        )
        for ordinal, (source_id, target_id) in enumerate((*prefix_pairs, *suffix_pairs))
    )
    batch = publication_traces.CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=dataset_release,
        events=events,
        receipts=(),
    )
    config = replace(
        _PRODUCTION_CONFIG,
        rows=2,
        cols=3,
        mapping_prefix_numerator=1,
        mapping_prefix_denominator=2,
    )
    expected = publication_traces._mapping_for_partition(
        batch,
        total_event_count=21,
        prefix_events=lambda: iter(events[:10]),
        source_partition_id=0,
        config=config,
    )
    store = publication_traces._CanonicalEventStore(tmp_path / "events.sqlite3")
    try:
        for event in reversed(events):
            store.add(event)
        store.finalize()
        monkeypatch.setattr(
            publication_traces,
            "_mapping_for_partition",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("disk mapping must not call the Counter implementation")
            ),
        )

        observed = store.mapping_for_partition(
            batch,
            total_event_count=21,
            source_partition_id=0,
            config=config,
        )
    finally:
        store.close()

    assert observed == expected
    assert observed[0]["mapping_prefix_events"] == 10
    assert observed[0]["row_ids"] == list(partition_zero_sources[1:])
    assert observed[0]["column_ids"] == [
        "target-a",
        "target-b",
        "reserved-empty-column:simplewiki-2026-07:partition-0:00000",
    ]


def test_canonical_store_normalizes_sqlite_mapping_faults() -> None:
    dataset_id = "simplewiki-2026-07"
    store = publication_traces._CanonicalEventStore(Path(":memory:"))
    store.finalize()
    store.close()
    batch = publication_traces.CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=publication_traces.frozen_dataset_release(dataset_id),
        events=(),
        receipts=(),
    )

    with pytest.raises(RuntimeError, match="canonical mapping aggregation failed"):
        store.mapping_for_partition(
            batch,
            total_event_count=0,
            source_partition_id=0,
            config=replace(_PRODUCTION_CONFIG, rows=1, cols=1),
        )


def test_canonical_store_cleans_temporary_mapping_rows_after_column_sql_fault(
    tmp_path: Path,
) -> None:
    dataset_id = "simplewiki-2026-07"
    dataset_release = publication_traces.frozen_dataset_release(dataset_id)
    event = publication_traces.CanonicalRawEvent(
        schema_version=publication_traces.CANONICAL_RAW_EVENT_SCHEMA,
        timestamp_utc="2020-01-01T00:00:00.000000Z",
        source_file_ordinal=0,
        within_file_ordinal=0,
        canonical_source_id="source",
        canonical_target_id="target",
        source_event_type="fixture",
    )
    batch = publication_traces.CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=dataset_release,
        events=(),
        receipts=(),
    )
    store = publication_traces._CanonicalEventStore(tmp_path / "events.sqlite3")
    store.add(event)
    store.finalize()
    real_connection = store._connection

    class FailColumnAggregation:
        def execute(self, sql: str, parameters: object = ()) -> object:
            if "SELECT prefix.canonical_target_id" in sql:
                raise sqlite3.OperationalError("injected column aggregation fault")
            return real_connection.execute(sql, parameters)  # type: ignore[arg-type]

        def __getattr__(self, name: str) -> object:
            return getattr(real_connection, name)

    store._connection = FailColumnAggregation()  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="canonical mapping aggregation failed"):
            store.mapping_for_partition(
                batch,
                total_event_count=1,
                source_partition_id=0,
                config=replace(
                    _PRODUCTION_CONFIG,
                    rows=1,
                    cols=1,
                    mapping_prefix_numerator=1,
                    mapping_prefix_denominator=2,
                ),
            )
        assert (
            real_connection.execute(
                "SELECT name FROM sqlite_temp_master "
                "WHERE type = 'table' AND name = 'selected_mapping_rows'"
            ).fetchone()
            is None
        )
    finally:
        store._connection = real_connection
        store.close()


def test_production_interface_exposes_no_caller_controlled_protocol_knobs() -> None:
    assert tuple(inspect.signature(prepare_publication_trace).parameters) == ("request",)
    assert (
        _PRODUCTION_CONFIG.rows,
        _PRODUCTION_CONFIG.cols,
        _PRODUCTION_CONFIG.mapping_prefix_numerator,
        _PRODUCTION_CONFIG.mapping_prefix_denominator,
        _PRODUCTION_CONFIG.source_partitions,
        _PRODUCTION_CONFIG.coefficient_cap,
        _PRODUCTION_CONFIG.event_window_size,
        _PRODUCTION_CONFIG.accepted_events_per_second,
        _PRODUCTION_CONFIG.target_accepted_events,
        _PRODUCTION_CONFIG.minimum_logical_changes,
        _PRODUCTION_CONFIG.microbatch_cap,
        _PRODUCTION_CONFIG.minimum_complete_window_lower_bound,
        _PRODUCTION_CONFIG.maximum_row_nonzeros,
    ) == (4096, 8193, 1, 10, 5, 7, 32768, 128, 131072, 65536, 64, 1000, 4096)


def test_query_vector_generator_matches_the_frozen_known_answer() -> None:
    payload = publication_traces._publication_query_vector_payload(
        dataset_id="fixture-dataset",
        dataset_release="fixture-release-v1",
        semantics="T2",
        source_partition=3,
        mapping_sha256="ab" * 32,
        length=8,
    )

    assert payload["values"] == [1, -1, -1, 0, 0, 1, 1, -1]
    assert (
        hashlib.sha256(publication_traces._canonical_json_bytes(payload)).hexdigest()
        == "1f158b52f8f0dc250ea0e8ad9e1804f525f0385c135c0e70528a22a8e54ec14f"
    )
