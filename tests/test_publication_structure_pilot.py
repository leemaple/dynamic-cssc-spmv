import builtins
import csv
import hashlib
import inspect
import json
import os
import stat
import zlib
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import dynamic_cssc.publication_structure_pilot as publication_structure_pilot
from dynamic_cssc.publication_structure_pilot import (
    PublicationStructurePilotError,
    PublicationStructurePilotHold,
    _test_only_produce_publication_structure_pilot,
    produce_publication_structure_pilot,
)
from dynamic_cssc.publication_traces import (
    CANONICAL_RAW_EVENT_SCHEMA,
    CanonicalRawEvent,
    CanonicalRawEventBatch,
    _TraceConfig,
    frozen_dataset_release,
    source_partition,
)

_DATASET_IDS = (
    "stack-overflow",
    "simplewiki-2026-07",
    "nyc-tlc-yellow-2022",
)

_SCRATCH_ENVIRONMENT = (
    "PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT",
    "TMPDIR",
    "SQLITE_TMPDIR",
)


@pytest.fixture(autouse=True)
def _production_scratch_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    root = tmp_path / "production-scratch"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    for name in _SCRATCH_ENVIRONMENT:
        monkeypatch.setenv(name, str(root))
    monkeypatch.setattr(publication_structure_pilot.tempfile, "tempdir", str(root))
    return root


def _verified_binding(seed: int) -> dict[str, object]:
    return {
        "acquisition_transaction_sha256": f"{seed:x}" * 64,
        "source_set_sha256": f"{seed + 1:x}" * 64,
        "repository_provenance": {
            "behavior_inventory": {"behavior_set_sha256": f"{seed + 2:x}" * 64}
        },
    }


def test_public_structure_pilot_interface_accepts_only_two_external_paths(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(produce_publication_structure_pilot).parameters) == (
        "acquisition_bundle_root",
        "output_dir",
    )

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        produce_publication_structure_pilot(  # type: ignore[call-arg]
            tmp_path / "acquisitions",
            tmp_path / "output",
            semantics="T1",
        )


def test_production_unavailable_inputs_hold_before_creating_any_output(
    tmp_path: Path,
) -> None:
    acquisition_root = tmp_path / "missing-acquisitions"
    output_dir = tmp_path / "pilot-output"

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(tmp_path.glob(".pilot-output.*")) == []


def test_production_requires_the_exact_three_dataset_bundle_directories_before_write(
    tmp_path: Path,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS[:-1]:
        (acquisition_root / dataset_id).mkdir()
    (acquisition_root / "caller-added").mkdir()
    output_dir = tmp_path / "pilot-output"

    with pytest.raises(PublicationStructurePilotHold, match="exact three.*bundle directories"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(tmp_path.glob(".pilot-output.*")) == []


@pytest.mark.parametrize(
    "invalid_scratch",
    (
        "missing-env",
        "relative",
        "missing-directory",
        "symlink",
        "non-private",
        "nonempty",
        "inside-acquisition",
        "contains-output",
        "default-tmp",
        "tmpdir-mismatch",
        "sqlite-tmpdir-mismatch",
    ),
)
def test_public_scratch_root_prerequisites_hold_before_source_verification_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _production_scratch_root: Path,
    invalid_scratch: str,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    root = _production_scratch_root

    if invalid_scratch == "missing-env":
        monkeypatch.delenv("PUBLICATION_STRUCTURE_PILOT_SCRATCH_ROOT")
    elif invalid_scratch == "relative":
        for name in _SCRATCH_ENVIRONMENT:
            monkeypatch.setenv(name, "relative-scratch")
    elif invalid_scratch == "missing-directory":
        root = tmp_path / "missing-scratch"
        for name in _SCRATCH_ENVIRONMENT:
            monkeypatch.setenv(name, str(root))
        monkeypatch.setattr(publication_structure_pilot.tempfile, "tempdir", str(root))
    elif invalid_scratch == "symlink":
        target = tmp_path / "scratch-target"
        target.mkdir(mode=0o700)
        target.chmod(0o700)
        root = tmp_path / "scratch-link"
        root.symlink_to(target, target_is_directory=True)
        for name in _SCRATCH_ENVIRONMENT:
            monkeypatch.setenv(name, str(root))
        monkeypatch.setattr(publication_structure_pilot.tempfile, "tempdir", str(root))
    elif invalid_scratch == "non-private":
        root.chmod(0o755)
    elif invalid_scratch == "nonempty":
        (root / "caller-owned").write_text("preserve\n", encoding="ascii")
    elif invalid_scratch == "inside-acquisition":
        root = acquisition_root / _DATASET_IDS[0] / "scratch"
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        for name in _SCRATCH_ENVIRONMENT:
            monkeypatch.setenv(name, str(root))
        monkeypatch.setattr(publication_structure_pilot.tempfile, "tempdir", str(root))
    elif invalid_scratch == "contains-output":
        output_dir = root / "pilot-output"
    elif invalid_scratch == "default-tmp":
        root = Path("/tmp")
        for name in _SCRATCH_ENVIRONMENT:
            monkeypatch.setenv(name, str(root))
        monkeypatch.setattr(publication_structure_pilot.tempfile, "tempdir", str(root))
    elif invalid_scratch == "tmpdir-mismatch":
        monkeypatch.setenv("TMPDIR", str(tmp_path))
    else:
        monkeypatch.setenv("SQLITE_TMPDIR", str(tmp_path))

    def must_not_verify(_repository_root: Path) -> object:
        raise AssertionError("scratch prerequisites must precede source verification")

    def must_not_open_sqlite(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scratch prerequisites must precede SQLite work")

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        must_not_verify,
    )
    monkeypatch.setattr(
        publication_structure_pilot.sqlite3,
        "connect",
        must_not_open_sqlite,
    )

    with pytest.raises(PublicationStructurePilotHold, match="scratch"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(output_dir.parent.glob(f".{output_dir.name}.*")) == []


def test_public_scratch_workspace_replacement_is_preserved_and_holds_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _production_scratch_root: Path,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    source_snapshot = object()
    replacement_marker: Path | None = None
    moved_workspace: Path | None = None

    def replace_workspace(
        _dataset_inputs: object,
        *,
        config: object,
        scratch: object,
        scratch_workspace: Path,
    ) -> dict[str, object]:
        del config, scratch
        nonlocal moved_workspace, replacement_marker
        moved_workspace = scratch_workspace.with_name(f"{scratch_workspace.name}-moved")
        scratch_workspace.rename(moved_workspace)
        scratch_workspace.mkdir(mode=0o700)
        replacement_marker = scratch_workspace / "foreign-owner"
        replacement_marker.write_text("preserve\n", encoding="ascii")
        return {}

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_report_from_inputs",
        replace_workspace,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert replacement_marker is not None
    assert replacement_marker.read_text(encoding="ascii") == "preserve\n"
    assert moved_workspace is not None and moved_workspace.is_dir()
    assert not output_dir.exists()
    assert list(output_dir.parent.glob(f".{output_dir.name}.*")) == []


def test_public_scratch_lock_cleanup_identity_change_holds_before_output_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _production_scratch_root: Path,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    source_snapshot = object()
    attacked = False
    moved_owned_lock: Path | None = None
    replacement_lock: Path | None = None
    original_claim = publication_structure_pilot._claim_owned_entry

    def replace_scratch_lock_before_cleanup(
        path: Path,
        identity: tuple[int, int],
        *,
        directory: bool,
        field: str,
    ) -> tuple[int, str, int]:
        nonlocal attacked, moved_owned_lock, replacement_lock
        if path.name == publication_structure_pilot._SCRATCH_LOCK_FILENAME and not attacked:
            attacked = True
            moved_owned_lock = path.with_name(f"{path.name}.owned")
            path.rename(moved_owned_lock)
            replacement_lock = path
            replacement_lock.write_text("replacement must survive\n", encoding="ascii")
        return original_claim(
            path,
            identity,
            directory=directory,
            field=field,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_report_from_inputs",
        lambda *_args, **_kwargs: {"resource": {}},
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_claim_owned_entry",
        replace_scratch_lock_before_cleanup,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert attacked
    assert not output_dir.exists()
    assert replacement_lock is not None
    assert replacement_lock.read_text(encoding="ascii") == "replacement must survive\n"
    assert moved_owned_lock is not None and moved_owned_lock.is_file()


@pytest.mark.parametrize("replacement_target", ("dataset-directory", "canonical-store"))
def test_public_dataset_scratch_replacement_is_preserved_and_holds_before_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_target: str,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    store_paths: list[Path] = []
    replacement_marker: Path | None = None
    moved_owned_path: Path | None = None
    attacked = False
    original_store_init = publication_structure_pilot._CanonicalEventStore.__init__

    def observe_store_path(store: object, path: Path) -> None:
        store_paths.append(path)
        original_store_init(store, path)  # type: ignore[arg-type]

    def load_input(
        dataset_id: str,
        _bundle_dir: Path,
        _repository_root: Path,
        _acquisition_snapshot: object,
    ) -> object:
        batch = batches[dataset_id]
        binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 1)

        def scan(event_sink: object) -> CanonicalRawEventBatch:
            assert callable(event_sink)
            for event in batch.events:
                event_sink(event)
            return replace(batch, events=())

        def revalidate() -> object:
            nonlocal attacked, moved_owned_path, replacement_marker
            if dataset_id == _DATASET_IDS[0] and not attacked:
                attacked = True
                store_path = store_paths[-1]
                if replacement_target == "dataset-directory":
                    owned_path = store_path.parent
                    moved_owned_path = owned_path.with_name(f"{owned_path.name}-moved")
                    owned_path.rename(moved_owned_path)
                    owned_path.mkdir(mode=0o700)
                    replacement_marker = owned_path / "foreign-owner"
                    replacement_marker.write_text("preserve\n", encoding="ascii")
                else:
                    moved_owned_path = store_path.with_name(f"{store_path.name}.moved")
                    store_path.rename(moved_owned_path)
                    replacement_marker = store_path
                    replacement_marker.write_text("preserve\n", encoding="ascii")
            return binding

        return publication_structure_pilot._PilotDatasetInput(
            dataset_id=dataset_id,
            scan=scan,
            verified_binding=binding,
            revalidate_binding=revalidate,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: object(),
    )
    acquisition_snapshot = object()
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: acquisition_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        load_input,
    )
    monkeypatch.setattr(
        publication_structure_pilot._CanonicalEventStore,
        "__init__",
        observe_store_path,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert replacement_marker is not None
    assert replacement_marker.read_text(encoding="ascii") == "preserve\n"
    assert moved_owned_path is not None and moved_owned_path.exists()
    assert not output_dir.exists()
    assert list(output_dir.parent.glob(f".{output_dir.name}.*")) == []


def test_public_store_cleanup_never_unlinks_a_replacement_created_at_delete_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    store_paths: list[Path] = []
    attacked = False
    replacement_path: Path | None = None
    original_store_init = publication_structure_pilot._CanonicalEventStore.__init__
    original_unlink = os.unlink

    def observe_store_path(store: object, path: Path) -> None:
        store_paths.append(path)
        original_store_init(store, path)  # type: ignore[arg-type]

    def race_store_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal attacked, replacement_path
        name = os.fsdecode(path)
        if not attacked and "dataset-0.sqlite3" in name and store_paths:
            attacked = True
            store_path = store_paths[0]
            if dir_fd is None:
                store_path.rename(store_path.with_name(f"{store_path.name}.owned"))
            replacement_path = store_path
            replacement_path.write_text("replacement must survive\n", encoding="ascii")
        if dir_fd is None:
            original_unlink(path)
        else:
            original_unlink(path, dir_fd=dir_fd)

    acquisition_snapshot = object()

    def load_input(
        dataset_id: str,
        _bundle_dir: Path,
        _repository_root: Path,
        observed_snapshot: object,
    ) -> object:
        assert observed_snapshot is acquisition_snapshot
        batch = batches[dataset_id]
        binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 1)

        def scan(event_sink: object) -> CanonicalRawEventBatch:
            assert callable(event_sink)
            for event in batch.events:
                event_sink(event)
            return replace(batch, events=())

        return publication_structure_pilot._PilotDatasetInput(
            dataset_id=dataset_id,
            scan=scan,
            verified_binding=binding,
            revalidate_binding=lambda: binding,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: object(),
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: acquisition_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        load_input,
    )
    monkeypatch.setattr(
        publication_structure_pilot._CanonicalEventStore,
        "__init__",
        observe_store_path,
    )
    monkeypatch.setattr(os, "unlink", race_store_unlink)

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert attacked
    assert replacement_path is not None
    assert replacement_path.read_text(encoding="ascii") == "replacement must survive\n"
    assert not output_dir.exists()


@pytest.mark.parametrize("target_level", ("outer-workspace", "nested-dataset-directory"))
def test_owned_scratch_directory_cleanup_never_removes_a_delete_time_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_level: str,
) -> None:
    root = tmp_path / "private-root"
    root.mkdir(mode=0o700)
    target: Path | None = None
    replacement: Path | None = None
    attacked = False
    original_rmdir = os.rmdir

    def race_directory_removal(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal attacked, replacement
        name = os.fsdecode(path)
        if target is not None and not attacked and target.name in name:
            attacked = True
            if dir_fd is None:
                target.rename(target.with_name(f"{target.name}.owned"))
            replacement = target
            replacement.mkdir(mode=0o700)
        if dir_fd is None:
            original_rmdir(path)
        else:
            original_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "rmdir", race_directory_removal)

    with (
        pytest.raises(PublicationStructurePilotError, match="cleanup|identity"),
        publication_structure_pilot._owned_empty_directory(
            root,
            prefix="outer-workspace-",
            field="scratch workspace",
        ) as outer,
    ):
        if target_level == "outer-workspace":
            target = outer
        else:
            with publication_structure_pilot._owned_empty_directory(
                outer,
                prefix="nested-dataset-directory-",
                field="dataset scratch directory",
            ) as nested:
                target = nested

    assert attacked
    assert replacement is not None and replacement.is_dir()


def test_unsupported_sqlite_runtime_holds_before_source_verification_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    monkeypatch.setattr(
        publication_structure_pilot.sqlite3,
        "sqlite_version_info",
        (3, 34, 1),
    )

    def must_not_verify(_repository_root: Path) -> object:
        raise AssertionError("SQLite must be gated before source verification")

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        must_not_verify,
    )

    with pytest.raises(PublicationStructurePilotHold, match="SQLite"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(tmp_path.glob(".pilot-output.*")) == []


@pytest.mark.parametrize(
    "compile_options",
    (
        (),
        (("TEMP_STORE=0",),),
        (("TEMP_STORE=2",),),
        (("TEMP_STORE=3",),),
        (("TEMP_STORE=1",), ("TEMP_STORE=2",)),
    ),
)
def test_sqlite_compile_time_temp_store_policy_is_closed(
    monkeypatch: pytest.MonkeyPatch,
    compile_options: tuple[tuple[str], ...],
) -> None:
    class Result:
        def __init__(
            self,
            rows: tuple[tuple[object, ...], ...] = (),
            *,
            one: tuple[object, ...] | None = None,
        ) -> None:
            self._rows = rows
            self._one = one

        def __iter__(self) -> object:
            return iter(self._rows)

        def fetchone(self) -> tuple[object, ...] | None:
            return self._one

    class Connection:
        def execute(self, statement: str) -> Result:
            if statement == "PRAGMA temp_store=FILE":
                return Result()
            if statement == "PRAGMA temp_store":
                return Result(one=(1,))
            if statement == "PRAGMA compile_options":
                return Result(compile_options)
            raise AssertionError(f"unexpected SQLite statement: {statement}")

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        publication_structure_pilot.sqlite3,
        "connect",
        lambda _database: Connection(),
    )

    with pytest.raises(PublicationStructurePilotError, match="TEMP_STORE"):
        publication_structure_pilot._require_sqlite_runtime()


@pytest.mark.parametrize(
    "relationship",
    ("equal", "output-inside-input", "output-contains-input", "symlink-resolves-inside"),
)
def test_public_input_and_output_trees_must_be_canonically_disjoint_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relationship: str,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    if relationship == "equal":
        output_dir = acquisition_root
    elif relationship == "output-inside-input":
        output_dir = acquisition_root / _DATASET_IDS[0] / "pilot-output"
    elif relationship == "output-contains-input":
        output_dir = tmp_path
    else:
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(acquisition_root / _DATASET_IDS[0], target_is_directory=True)
        output_dir = linked_parent / "pilot-output"

    def must_not_verify(_repository_root: Path) -> object:
        raise AssertionError("overlap must fail before source verification")

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        must_not_verify,
    )

    with pytest.raises(PublicationStructurePilotError, match="disjoint"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert list(acquisition_root.rglob("structure-pilot-report.json")) == []
    assert list(acquisition_root.rglob("checksums.sha256")) == []
    assert list(tmp_path.glob(".*.structure-pilot-*")) == []


def _source_ids_for_partitions(dataset_release: str) -> tuple[str, ...]:
    identities: list[str] = []
    for partition in range(5):
        matches: list[str] = []
        candidate = 0
        while len(matches) < 2:
            identity = f"source-{partition}-{candidate:04d}"
            if source_partition(dataset_release, identity) == partition:
                matches.append(identity)
            candidate += 1
        identities.extend(matches)
    return tuple(identities)


def _synthetic_batch(
    dataset_id: str,
    *,
    suffix_marker: str = "a",
    prefix_events_per_partition: int = 2,
) -> CanonicalRawEventBatch:
    dataset_release = frozen_dataset_release(dataset_id)
    prefix_sources = _source_ids_for_partitions(dataset_release)
    events: list[CanonicalRawEvent] = []
    for partition in range(5):
        for repetition in range(prefix_events_per_partition):
            index = len(events)
            events.append(
                CanonicalRawEvent(
                    schema_version=CANONICAL_RAW_EVENT_SCHEMA,
                    timestamp_utc=f"2020-01-01T00:00:00.{index:06d}Z",
                    source_file_ordinal=0,
                    within_file_ordinal=index,
                    canonical_source_id=prefix_sources[partition * 2 + repetition % 2],
                    canonical_target_id=f"target-{partition}-{repetition % 2}",
                    source_event_type="fixture",
                )
            )
    prefix_count = len(events)
    events.extend(
        CanonicalRawEvent(
            schema_version=CANONICAL_RAW_EVENT_SCHEMA,
            timestamp_utc=f"2020-01-01T00:00:01.{index:06d}Z",
            source_file_ordinal=0,
            within_file_ordinal=index + prefix_count,
            canonical_source_id=f"suffix-{suffix_marker}-{index:04d}",
            canonical_target_id=f"suffix-target-{suffix_marker}-{index:04d}",
            source_event_type="fixture",
        )
        for index in range(prefix_count * 9)
    )
    return CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=dataset_release,
        events=tuple(events),
        receipts=(),
    )


def _synthetic_config() -> _TraceConfig:
    return _TraceConfig(
        rows=2,
        cols=2,
        mapping_prefix_numerator=1,
        mapping_prefix_denominator=10,
        source_partitions=5,
        coefficient_cap=7,
        event_window_size=1,
        accepted_events_per_second=1,
        target_accepted_events=2,
        minimum_logical_changes=1,
        microbatch_cap=1,
        minimum_complete_window_lower_bound=1,
        maximum_row_nonzeros=2,
    )


def _streaming_input_from_batch(
    batch: CanonicalRawEventBatch,
) -> object:
    binding = _verified_binding(_DATASET_IDS.index(batch.dataset_id) + 1)

    def scan(event_sink: object) -> CanonicalRawEventBatch:
        assert callable(event_sink)
        for event in batch.events:
            event_sink(event)
        return replace(batch, events=())

    return publication_structure_pilot._PilotDatasetInput(
        dataset_id=batch.dataset_id,
        scan=scan,
        verified_binding=binding,
        revalidate_binding=lambda: binding,
    )


def test_private_synthetic_pilot_atomically_emits_the_fixed_thirty_cell_coverage(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "pilot-output"
    bundle = _test_only_produce_publication_structure_pilot(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        output_dir,
        config=_synthetic_config(),
    )

    assert bundle.output_dir == output_dir
    assert {path.name for path in output_dir.iterdir()} == {
        "structure-pilot-report.json",
        "checksums.sha256",
    }
    report = json.loads(bundle.report_path.read_bytes())
    assert report["artifact_policy"] == "pre-freeze-pilot-only-permanently-non-admissible"
    assert report["coverage"] == {
        "completed_cell_count": 30,
        "dataset_ids": list(_DATASET_IDS),
        "expected_cell_count": 30,
        "expected_dataset_scan_count": 3,
        "observed_cell_count": 30,
        "observed_dataset_scan_count": 3,
        "semantics": ["T1", "T2"],
        "source_partitions": [0, 1, 2, 3, 4],
    }
    assert {
        (cell["dataset_id"], cell["semantics"], cell["source_partition"])
        for cell in report["cells"]
    } == {
        (dataset_id, semantics, partition)
        for dataset_id in _DATASET_IDS
        for semantics in ("T1", "T2")
        for partition in range(5)
    }
    assert {cell["cardinality"]["accepted_prefix_group_count"] for cell in report["cells"]} == {2}
    assert {
        cell["cardinality"]["transition_record_count"]
        for cell in report["cells"]
        if cell["semantics"] == "T1"
    } == {2}
    assert {
        cell["cardinality"]["transition_record_count"]
        for cell in report["cells"]
        if cell["semantics"] == "T2"
    } == {3}
    assert {
        cell["structure"]["peak_live_coordinate_count"]
        for cell in report["cells"]
        if cell["semantics"] == "T1"
    } == {2}
    assert {
        cell["structure"]["peak_live_coordinate_count"]
        for cell in report["cells"]
        if cell["semantics"] == "T2"
    } == {1}


def test_pilot_consumes_every_mapped_group_in_the_prefix_without_the_formal_trace_cap(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "all-prefix-groups"
    _test_only_produce_publication_structure_pilot(
        {
            dataset_id: _synthetic_batch(dataset_id, prefix_events_per_partition=3)
            for dataset_id in _DATASET_IDS
        },
        output_dir,
        config=_synthetic_config(),
    )

    report = json.loads((output_dir / "structure-pilot-report.json").read_bytes())
    assert {cell["cardinality"]["accepted_prefix_group_count"] for cell in report["cells"]} == {3}
    assert all(
        cell["cardinality"]["filtered_unselected_target_count"] == 0 for cell in report["cells"]
    )


def test_cell_reopens_the_prefix_iterator_and_uses_sink_only_transform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = _synthetic_batch(_DATASET_IDS[0])
    prefix = batch.events[: len(batch.events) // 10]
    iterator_open_count = 0
    original_transform = publication_structure_pilot._transform_events

    def prefix_events() -> object:
        nonlocal iterator_open_count
        iterator_open_count += 1
        return iter(prefix)

    def require_sink_only(*args: object, **kwargs: object) -> object:
        assert kwargs["retain_records"] is False
        assert callable(kwargs["record_sink"])
        result = original_transform(*args, **kwargs)
        assert result.records == ()
        return result

    monkeypatch.setattr(publication_structure_pilot, "_transform_events", require_sink_only)
    event_store = publication_structure_pilot._CanonicalEventStore(
        tmp_path / "canonical-events.sqlite3"
    )
    try:
        for event in batch.events:
            event_store.add(event)
        event_store.finalize()
        cell = publication_structure_pilot._cell_report(
            replace(batch, events=()),
            event_store=event_store,
            prefix_events=prefix_events,  # type: ignore[arg-type]
            total_event_count=len(batch.events),
            semantics="T2",
            source_partition_id=0,
            config=_synthetic_config(),
        )
    finally:
        event_store.close()

    assert cell["health"]["completion_state"] == "complete"
    assert cell["cardinality"]["accepted_prefix_group_count"] == 2
    assert cell["cardinality"]["transition_record_count"] == 3
    assert iterator_open_count == 2


def test_pilot_mapping_uses_the_disk_store_not_the_unbounded_counter_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_counter_mapping(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("pilot must use the canonical store mapping seam")

    monkeypatch.setattr(
        publication_structure_pilot,
        "_mapping_for_partition",
        forbidden_counter_mapping,
        raising=False,
    )

    report = publication_structure_pilot._report_from_batches(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        config=_synthetic_config(),
    )

    assert report["coverage"]["completed_cell_count"] == 30


def test_forbidden_outcome_vocabulary_fails_before_installing_the_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(publication_structure_pilot.platform, "machine", lambda: "CANDIDATE-host")
    output_dir = tmp_path / "forbidden-report"

    with pytest.raises(PublicationStructurePilotError, match="forbidden outcome field"):
        _test_only_produce_publication_structure_pilot(
            {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
            output_dir,
            config=_synthetic_config(),
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".forbidden-report.*")) == []

    nested_output = tmp_path / "forbidden-key"
    with pytest.raises(PublicationStructurePilotError, match="forbidden outcome field"):
        publication_structure_pilot._install_report(
            {"safe": [{"Winning-RHO": 1}]},
            nested_output,
        )
    assert not nested_output.exists()
    assert list(tmp_path.glob(".forbidden-key.*")) == []


def _outcome_blind_projection(report: dict[str, object]) -> dict[str, object]:
    return {
        "prefix_rule": report["prefix_rule"],
        "coverage": report["coverage"],
        "dataset_scans": [
            {
                "dataset_id": scan["dataset_id"],
                "dataset_release": scan["dataset_release"],
                "cardinality": scan["cardinality"],
                "health": scan["health"],
                "error": scan["error"],
            }
            for scan in report["dataset_scans"]  # type: ignore[union-attr]
        ],
        "cells": [
            {
                key: cell[key]
                for key in (
                    "dataset_id",
                    "dataset_release",
                    "semantics",
                    "source_partition",
                    "structure",
                    "cardinality",
                    "health",
                    "error",
                    "serialization_completeness",
                )
            }
            for cell in report["cells"]  # type: ignore[union-attr]
        ],
    }


def test_changing_only_the_post_prefix_suffix_cannot_change_any_structural_result(
    tmp_path: Path,
) -> None:
    reports: list[dict[str, object]] = []
    for marker in ("all-zero-shape", "adversarial-different-shape"):
        output_dir = tmp_path / marker
        _test_only_produce_publication_structure_pilot(
            {
                dataset_id: _synthetic_batch(dataset_id, suffix_marker=marker)
                for dataset_id in _DATASET_IDS
            },
            output_dir,
            config=_synthetic_config(),
        )
        reports.append(json.loads((output_dir / "structure-pilot-report.json").read_bytes()))

    assert _outcome_blind_projection(reports[0]) == _outcome_blind_projection(reports[1])


def test_report_has_closed_key_sets_canonical_bytes_and_one_exact_checksum(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "closed-report"
    _test_only_produce_publication_structure_pilot(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        output_dir,
        config=_synthetic_config(),
    )

    report_bytes = (output_dir / "structure-pilot-report.json").read_bytes()
    report = json.loads(report_bytes)
    assert set(report) == {
        "schema_version",
        "artifact_policy",
        "prefix_rule",
        "coverage",
        "health",
        "resource",
        "dataset_scans",
        "cells",
    }
    assert set(report["prefix_rule"]) == {
        "basis",
        "numerator",
        "denominator",
        "count_rule",
        "structure_scope",
    }
    assert set(report["coverage"]) == {
        "dataset_ids",
        "semantics",
        "source_partitions",
        "expected_dataset_scan_count",
        "observed_dataset_scan_count",
        "expected_cell_count",
        "observed_cell_count",
        "completed_cell_count",
    }
    assert set(report["health"]) == {
        "python_implementation",
        "python_version",
        "platform_system",
        "machine",
        "sqlite_library_version",
        "sqlite_temp_store_policy",
        "required_runtime_ok",
        "all_dataset_scans_completed",
        "all_cells_completed",
    }
    assert report["health"]["sqlite_library_version"] == (
        publication_structure_pilot.sqlite3.sqlite_version
    )
    assert report["health"]["sqlite_temp_store_policy"] == "FILE"
    assert set(report["resource"]) == {
        "worker_concurrency",
        "analysis_wall_clock_ns",
        "process_high_water_rss_bytes_before_report_install",
        "maximum_canonical_store_bytes_after_index",
        "total_prefix_transition_serialized_bytes",
        "scratch_root_policy",
        "scratch_root_identity_sha256",
    }
    assert set(report["dataset_scans"][0]) == {
        "dataset_id",
        "dataset_release",
        "input_identity",
        "cardinality",
        "health",
        "resource",
        "error",
    }
    assert set(report["dataset_scans"][0]["cardinality"]) == {
        "schema_valid_event_count",
        "mapping_prefix_event_count",
        "parser_rejected_event_count",
    }
    assert set(report["dataset_scans"][0]["health"]) == {
        "completion_state",
        "runtime_healthy",
    }
    assert set(report["dataset_scans"][0]["resource"]) == {
        "verification_parser_index_wall_clock_ns",
        "process_high_water_rss_bytes_at_scan_completion",
        "canonical_store_bytes_after_index",
    }
    assert set(report["dataset_scans"][0]["input_identity"]) == {
        "acquisition_transaction_sha256",
        "source_set_sha256",
        "acquisition_behavior_set_sha256",
        "verified_input_binding_sha256",
    }
    assert set(report["dataset_scans"][0]["error"]) == {"stage", "scan_error_code"}
    assert set(report["cells"][0]) == {
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "structure",
        "cardinality",
        "health",
        "resource",
        "error",
        "serialization_completeness",
    }
    assert set(report["cells"][0]["structure"]) == {
        "selected_row_count",
        "observed_column_count",
        "reserved_empty_column_count",
        "peak_row_nonzeros",
        "peak_live_coordinate_count",
        "maximum_transition_group_size_observed",
        "t2_window_peak_groups",
    }
    assert set(report["cells"][0]["cardinality"]) == {
        "source_partition_prefix_event_count",
        "accepted_prefix_group_count",
        "transition_record_count",
        "logical_change_count",
        "insert_count",
        "modify_count",
        "delete_count",
        "clipped_noop_count",
        "filtered_other_partition_count",
        "filtered_unselected_source_count",
        "filtered_unselected_target_count",
    }
    assert set(report["cells"][0]["health"]) == {
        "completion_state",
        "prefix_mapping_eligible",
        "runtime_healthy",
        "eligibility_codes",
    }
    assert set(report["cells"][0]["resource"]) == {
        "wall_clock_ns",
        "process_high_water_rss_bytes_at_cell_completion",
        "prefix_transition_serialized_bytes",
    }
    assert set(report["cells"][0]["error"]) == {"stage", "code"}
    assert set(report["cells"][0]["serialization_completeness"]) == {
        "expected_record_count",
        "serialized_record_count",
        "decoded_record_count",
        "canonical_roundtrip_record_count",
        "complete",
    }
    assert report["resource"]["maximum_canonical_store_bytes_after_index"] == max(
        scan["resource"]["canonical_store_bytes_after_index"] for scan in report["dataset_scans"]
    )
    assert report["resource"]["total_prefix_transition_serialized_bytes"] == sum(
        cell["resource"]["prefix_transition_serialized_bytes"] for cell in report["cells"]
    )
    assert b"peak_scratch_bytes" not in report_bytes
    assert b"serialized_output_bytes" not in report_bytes
    assert b'"total_wall_clock_ns"' not in report_bytes
    assert b'"process_high_water_rss_bytes"' not in report_bytes
    assert report_bytes == (
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    assert (output_dir / "checksums.sha256").read_bytes() == (
        f"{report_sha256}  structure-pilot-report.json\n".encode("ascii")
    )
    assert {stat.S_IMODE(path.stat().st_mode) for path in output_dir.iterdir()} == {0o644}


def test_suffix_sentinels_never_reach_mapping_transform_or_serialization(
    tmp_path: Path,
) -> None:
    batches: dict[str, CanonicalRawEventBatch] = {}
    for dataset_id in _DATASET_IDS:
        original = _synthetic_batch(dataset_id)
        batches[dataset_id] = replace(
            original,
            events=tuple(
                event
                if index < 10
                else replace(event, canonical_source_id="", canonical_target_id="")
                for index, event in enumerate(original.events)
            ),
        )

    output_dir = tmp_path / "sentinel-prefix"
    _test_only_produce_publication_structure_pilot(
        batches,
        output_dir,
        config=_synthetic_config(),
    )

    report = json.loads((output_dir / "structure-pilot-report.json").read_bytes())
    assert report["coverage"]["completed_cell_count"] == 30
    assert {cell["cardinality"]["accepted_prefix_group_count"] for cell in report["cells"]} == {2}


def test_pilot_does_not_import_schedule_day1b_or_selection_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = {
        "dynamic_cssc.publication_schedule",
        "dynamic_cssc.publication_day1b",
        "dynamic_cssc.day1_registry",
        "dynamic_cssc.selection",
    }
    real_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name in blocked:
            raise AssertionError(f"forbidden pilot import: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    output_dir = tmp_path / "no-outcome-modules"
    _test_only_produce_publication_structure_pilot(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        output_dir,
        config=_synthetic_config(),
    )

    assert (output_dir / "structure-pilot-report.json").is_file()


@pytest.mark.parametrize(
    ("injected_name", "failure_type", "expected_stage", "expected_code"),
    (
        ("_mapping_for_cell", RuntimeError, "mapping", "mapping-failed"),
        ("_transform_events", RuntimeError, "transform", "transform-failed"),
        ("_transition_payload", TypeError, "serialization", "serialization-failed"),
    ),
)
def test_cell_failures_retain_exact_coverage_and_use_only_closed_error_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    injected_name: str,
    failure_type: type[Exception],
    expected_stage: str,
    expected_code: str,
) -> None:
    original = getattr(publication_structure_pilot, injected_name)
    injected = False

    def fail_first_call(*args: object, **kwargs: object) -> object:
        nonlocal injected
        if not injected:
            injected = True
            raise failure_type("private diagnostic text must not enter the report")
        return original(*args, **kwargs)

    monkeypatch.setattr(publication_structure_pilot, injected_name, fail_first_call)
    output_dir = tmp_path / expected_stage
    _test_only_produce_publication_structure_pilot(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        output_dir,
        config=_synthetic_config(),
    )

    report = json.loads((output_dir / "structure-pilot-report.json").read_bytes())
    assert report["coverage"]["observed_cell_count"] == 30
    assert report["coverage"]["completed_cell_count"] == 29
    failures = [cell for cell in report["cells"] if cell["error"]["code"] is not None]
    assert len(failures) == 1
    assert failures[0]["error"] == {"stage": expected_stage, "code": expected_code}
    assert failures[0]["health"] == {
        "completion_state": "failed",
        "prefix_mapping_eligible": None,
        "runtime_healthy": False,
        "eligibility_codes": [],
    }
    assert "private diagnostic" not in (output_dir / "structure-pilot-report.json").read_text()


@pytest.mark.parametrize(
    ("failing_iterator_open", "expected_stage", "expected_code"),
    (
        (1, "mapping", "mapping-failed"),
        (2, "transform", "transform-failed"),
    ),
)
def test_sqlite_cursor_faults_use_closed_cell_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_iterator_open: int,
    expected_stage: str,
    expected_code: str,
) -> None:
    original = publication_structure_pilot._CanonicalEventStore.ordered_events
    iterator_open_count = 0
    injected = False

    def ordered_events(store: object, **kwargs: object) -> object:
        nonlocal injected
        nonlocal iterator_open_count
        iterator_open_count += 1
        if not injected and iterator_open_count == failing_iterator_open:
            injected = True

            def fail_on_iteration() -> object:
                raise publication_structure_pilot.sqlite3.OperationalError(
                    "private cursor details must never enter the report"
                )
                yield  # pragma: no cover

            return fail_on_iteration()
        return original(store, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        publication_structure_pilot._CanonicalEventStore,
        "ordered_events",
        ordered_events,
    )
    output_dir = tmp_path / f"cursor-{expected_stage}"

    _test_only_produce_publication_structure_pilot(
        {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
        output_dir,
        config=_synthetic_config(),
    )

    report_text = (output_dir / "structure-pilot-report.json").read_text(encoding="ascii")
    report = json.loads(report_text)
    failures = [cell for cell in report["cells"] if cell["error"]["code"] is not None]
    assert report["coverage"]["completed_cell_count"] == 29
    assert [cell["error"] for cell in failures] == [
        {"stage": expected_stage, "code": expected_code}
    ]
    assert "private cursor details" not in report_text


def test_output_is_no_replace_for_existing_symlink_and_concurrent_claims(
    tmp_path: Path,
) -> None:
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    config = _synthetic_config()

    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "caller-owned"
    marker.write_text("preserve\n", encoding="ascii")
    with pytest.raises(PublicationStructurePilotError, match="new path"):
        _test_only_produce_publication_structure_pilot(batches, existing, config=config)
    assert marker.read_text(encoding="ascii") == "preserve\n"

    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "symlink-output"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(PublicationStructurePilotError, match="new path"):
        _test_only_produce_publication_structure_pilot(batches, symlink, config=config)
    assert list(target.iterdir()) == []

    claimed = tmp_path / "claimed"
    lock = tmp_path / ".claimed.structure-pilot.lock"
    lock.write_text("other-owner\n", encoding="ascii")
    with pytest.raises(PublicationStructurePilotError, match="already claiming"):
        _test_only_produce_publication_structure_pilot(batches, claimed, config=config)
    assert not claimed.exists()
    assert lock.read_text(encoding="ascii") == "other-owner\n"
    assert list(tmp_path.glob(".claimed.structure-pilot-*")) == []


def test_atomic_install_preserves_a_racing_empty_directory_and_replacement_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "raced-output"
    lock_path = tmp_path / ".raced-output.structure-pilot.lock"
    no_replace = publication_structure_pilot._rename_entry_no_replace

    def create_racing_destination(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        if destination_name == output_dir.name:
            os.mkdir(destination_name, dir_fd=destination_parent_fd)
            lock_path.unlink()
            lock_path.write_text("racing-owner\n", encoding="ascii")
        no_replace(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        create_racing_destination,
    )

    with pytest.raises(PublicationStructurePilotError, match="claimed concurrently"):
        _test_only_produce_publication_structure_pilot(
            {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
            output_dir,
            config=_synthetic_config(),
        )

    assert output_dir.is_dir()
    assert list(output_dir.iterdir()) == []
    assert lock_path.read_text(encoding="ascii") == "racing-owner\n"
    assert list(tmp_path.glob(".raced-output.structure-pilot-*")) == []


def test_atomic_install_refuses_a_replaced_staging_directory_without_installing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "replaced-staging-output"
    original_install = publication_structure_pilot._install_owned_staging
    moved_owned_staging: Path | None = None
    replacement_staging: Path | None = None

    def replace_staging_before_install(
        staging: object,
        destination: Path,
    ) -> None:
        nonlocal moved_owned_staging, replacement_staging
        source = staging.path  # type: ignore[attr-defined]
        moved_owned_staging = source.with_name(f"{source.name}-owned")
        source.rename(moved_owned_staging)
        source.mkdir(mode=0o700)
        replacement_staging = source
        (source / "structure-pilot-report.json").write_text(
            '{"forged":"preserve"}\n',
            encoding="ascii",
        )
        (source / "checksums.sha256").write_text(
            "0" * 64 + "  structure-pilot-report.json\n",
            encoding="ascii",
        )
        original_install(staging, destination)  # type: ignore[arg-type]

    monkeypatch.setattr(
        publication_structure_pilot,
        "_install_owned_staging",
        replace_staging_before_install,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        _test_only_produce_publication_structure_pilot(
            {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS},
            output_dir,
            config=_synthetic_config(),
        )

    assert not output_dir.exists()
    assert replacement_staging is not None
    assert (replacement_staging / "structure-pilot-report.json").read_text(
        encoding="ascii"
    ) == '{"forged":"preserve"}\n'
    assert moved_owned_staging is not None
    assert (moved_owned_staging / "structure-pilot-report.json").is_file()


def test_staging_replacement_after_owner_claim_is_quarantined_off_the_output_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "post-claim-replacement-output"
    attacked = False
    owned_staging_path: Path | None = None
    blocker_path: Path | None = None
    original_rename = publication_structure_pilot._rename_entry_no_replace

    def replace_claimed_staging(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        nonlocal attacked, blocker_path, owned_staging_path
        if not attacked and destination_name == output_dir.name:
            attacked = True
            owned_name = f"{source_name}.owned"
            os.rename(
                source_name,
                owned_name,
                src_dir_fd=source_parent_fd,
                dst_dir_fd=source_parent_fd,
            )
            owned_staging_path = tmp_path / owned_name
            os.mkdir(source_name, 0o700, dir_fd=source_parent_fd)
            forged_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent_fd,
            )
            try:
                for name, content in (
                    ("structure-pilot-report.json", b'{"forged":"preserve"}\n'),
                    ("checksums.sha256", b"forged checksum must survive\n"),
                ):
                    descriptor = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=forged_fd,
                    )
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(content)
            finally:
                os.close(forged_fd)
            original_rename(
                source_parent_fd,
                source_name,
                destination_parent_fd,
                destination_name,
                destination=destination,
            )
            os.mkdir(source_name, 0o700, dir_fd=source_parent_fd)
            blocker_path = tmp_path / source_name
            return
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        replace_claimed_staging,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()
    assert owned_staging_path is not None
    assert (owned_staging_path / "structure-pilot-report.json").is_file()
    assert blocker_path is not None and blocker_path.is_dir()
    forged_reports = tuple(
        path
        for path in tmp_path.rglob("structure-pilot-report.json")
        if path.read_bytes() == b'{"forged":"preserve"}\n'
    )
    assert len(forged_reports) == 1


def test_staging_member_content_rewrite_after_claim_never_reaches_formal_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "rewritten-member-output"
    attacked = False
    original_rename = publication_structure_pilot._rename_entry_no_replace

    def rewrite_report_before_install(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        nonlocal attacked
        if not attacked and destination_name == output_dir.name:
            attacked = True
            staging_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent_fd,
            )
            try:
                report_fd = os.open(
                    "structure-pilot-report.json",
                    os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
                    dir_fd=staging_fd,
                )
                with os.fdopen(report_fd, "wb") as handle:
                    handle.write(b'{"forged":"same-inode"}\n')
            finally:
                os.close(staging_fd)
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        rewrite_report_before_install,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()
    rejected_reports = tuple(
        path
        for path in tmp_path.rglob("structure-pilot-report.json")
        if path.read_bytes() == b'{"forged":"same-inode"}\n'
    )
    assert len(rejected_reports) == 1


def test_byte_identical_staging_member_inode_replacement_never_installs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "replaced-member-inode-output"
    attacked = False
    original_rename = publication_structure_pilot._rename_entry_no_replace

    def replace_report_inode_before_install(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        nonlocal attacked
        if not attacked and destination_name == output_dir.name:
            attacked = True
            staging_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent_fd,
            )
            try:
                os.rename(
                    "structure-pilot-report.json",
                    "structure-pilot-report.json.owned",
                    src_dir_fd=staging_fd,
                    dst_dir_fd=staging_fd,
                )
                owned_fd = os.open(
                    "structure-pilot-report.json.owned",
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=staging_fd,
                )
                try:
                    content = os.read(owned_fd, 4096)
                finally:
                    os.close(owned_fd)
                replacement_fd = os.open(
                    "structure-pilot-report.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o644,
                    dir_fd=staging_fd,
                )
                with os.fdopen(replacement_fd, "wb") as handle:
                    handle.write(content)
            finally:
                os.close(staging_fd)
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        replace_report_inode_before_install,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()


def test_unexpected_staging_member_is_preserved_off_the_formal_output_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "unexpected-member-output"
    attacked = False
    original_rename = publication_structure_pilot._rename_entry_no_replace

    def add_foreign_member_before_install(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        nonlocal attacked
        if not attacked and destination_name == output_dir.name:
            attacked = True
            staging_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent_fd,
            )
            try:
                foreign_fd = os.open(
                    "foreign-member",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=staging_fd,
                )
                with os.fdopen(foreign_fd, "wb") as handle:
                    handle.write(b"preserve foreign member\n")
            finally:
                os.close(staging_fd)
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        add_foreign_member_before_install,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()
    foreign_members = tuple(tmp_path.rglob("foreign-member"))
    assert len(foreign_members) == 1
    assert foreign_members[0].read_bytes() == b"preserve foreign member\n"


def test_staging_member_mode_drift_never_installs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "member-mode-drift-output"
    attacked = False
    original_rename = publication_structure_pilot._rename_entry_no_replace

    def change_report_mode_before_install(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        nonlocal attacked
        if not attacked and destination_name == output_dir.name:
            attacked = True
            staging_fd = os.open(
                source_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_parent_fd,
            )
            try:
                report_fd = os.open(
                    "structure-pilot-report.json",
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=staging_fd,
                )
                try:
                    os.fchmod(report_fd, 0o600)
                finally:
                    os.close(report_fd)
            finally:
                os.close(staging_fd)
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        change_report_mode_before_install,
    )

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()


def test_failed_install_cleanup_never_unlinks_a_staging_file_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "failed-install-output"
    attacked = False
    original_unlink = os.unlink

    original_rename = publication_structure_pilot._rename_entry_no_replace

    def fail_install(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
        *,
        destination: Path,
    ) -> None:
        if destination_name == output_dir.name:
            raise OSError(5, "synthetic installation failure")
        original_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
            destination=destination,
        )

    def race_staging_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal attacked
        name = os.fsdecode(path)
        if not attacked and "structure-pilot-report.json" in name:
            attacked = True
            assert dir_fd is not None
            with suppress(FileNotFoundError):
                os.rename(
                    "structure-pilot-report.json",
                    "structure-pilot-report.json.owned",
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
            descriptor = os.open(
                "structure-pilot-report.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(b"replacement must survive\n")
        if dir_fd is None:
            original_unlink(path)
        else:
            original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(
        publication_structure_pilot,
        "_rename_entry_no_replace",
        fail_install,
    )
    monkeypatch.setattr(os, "unlink", race_staging_unlink)

    with pytest.raises(OSError, match="synthetic installation failure"):
        publication_structure_pilot._install_report({"safe": "value"}, output_dir)

    assert attacked
    assert not output_dir.exists()
    replacements = tuple(tmp_path.rglob("structure-pilot-report.json"))
    assert len(replacements) == 1
    assert replacements[0].read_text(encoding="ascii") == "replacement must survive\n"


def test_public_two_path_seam_verifies_three_bundles_and_rechecks_source_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _production_scratch_root: Path,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    acquisition_snapshot = object()
    source_checks: list[object] = []
    bundle_loads: list[tuple[str, Path]] = []
    store_paths: list[Path] = []
    original_store_init = publication_structure_pilot._CanonicalEventStore.__init__

    def observe_store_path(store: object, path: Path) -> None:
        store_paths.append(path)
        original_store_init(store, path)  # type: ignore[arg-type]

    def verify_source(_repository_root: Path) -> object:
        source_checks.append(source_snapshot)
        return source_snapshot

    def load_input(
        dataset_id: str,
        bundle_dir: Path,
        _repository_root: Path,
        observed_acquisition_snapshot: object,
    ) -> object:
        assert observed_acquisition_snapshot is acquisition_snapshot
        bundle_loads.append((dataset_id, bundle_dir))
        return _streaming_input_from_batch(batches[dataset_id])

    monkeypatch.setattr(publication_structure_pilot, "_verify_production_source", verify_source)
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: acquisition_snapshot,
    )
    monkeypatch.setattr(publication_structure_pilot, "_load_verified_production_input", load_input)
    monkeypatch.setattr(
        publication_structure_pilot._CanonicalEventStore,
        "__init__",
        observe_store_path,
    )
    output_dir = tmp_path / "production-pilot"

    bundle = produce_publication_structure_pilot(acquisition_root, output_dir)

    assert bundle.report_path.is_file()
    assert source_checks == [source_snapshot, source_snapshot]
    assert bundle_loads == [
        (dataset_id, acquisition_root / dataset_id) for dataset_id in _DATASET_IDS
    ]
    report = json.loads(bundle.report_path.read_bytes())
    assert report["coverage"]["completed_cell_count"] == 30
    assert len(store_paths) == 3
    assert len({path.parent for path in store_paths}) == 1
    assert all(_production_scratch_root in path.parents for path in store_paths)
    scratch_stat = _production_scratch_root.lstat()
    expected_scratch_identity = hashlib.sha256(
        b"dynamic-cssc-publication-structure-pilot-scratch-root-v1\0"
        + os.fsencode(_production_scratch_root.resolve())
        + b"\0"
        + scratch_stat.st_dev.to_bytes(16, "big", signed=False)
        + scratch_stat.st_ino.to_bytes(16, "big", signed=False)
    ).hexdigest()
    assert report["resource"]["scratch_root_policy"] == (
        "workflow-fixed-external-private-empty-exclusive-v1"
    )
    assert report["resource"]["scratch_root_identity_sha256"] == expected_scratch_identity
    assert list(_production_scratch_root.iterdir()) == []


def test_public_production_parser_streams_each_dataset_into_the_canonical_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    parser_calls: list[str] = []
    source_snapshot = object()

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def verified_input(request: object, **_kwargs: object) -> object:
        return SimpleNamespace(
            request=SimpleNamespace(sources=()),
            binding={
                "acquisition_transaction_sha256": "1" * 64,
                "source_set_sha256": "2" * 64,
                "repository_provenance": {"behavior_inventory": {"behavior_set_sha256": "3" * 64}},
            },
        )

    def stream_parser(
        dataset_id: str,
        _sources: object,
        *,
        config: object,
        event_sink: object = None,
    ) -> CanonicalRawEventBatch:
        del config
        assert callable(event_sink)
        parser_calls.append(dataset_id)
        for event in batches[dataset_id].events:
            event_sink(event)
        return replace(batches[dataset_id], events=())

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verified_acquisition_input",
        verified_input,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_read_canonical_raw_events",
        stream_parser,
    )
    output_dir = tmp_path / "streamed-output"

    bundle = produce_publication_structure_pilot(acquisition_root, output_dir)

    assert bundle.report_path.is_file()
    assert parser_calls == list(_DATASET_IDS)


def test_report_binds_verified_acquisition_identities_and_changes_on_retarget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    retarget_offset = 0
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def verified_input(request: object, **_kwargs: object) -> object:
        dataset_id = request.dataset_id  # type: ignore[attr-defined]
        return SimpleNamespace(
            request=SimpleNamespace(sources=()),
            binding=_verified_binding(_DATASET_IDS.index(dataset_id) + 1 + retarget_offset),
        )

    def stream_parser(
        dataset_id: str,
        _sources: object,
        *,
        config: object,
        event_sink: object,
    ) -> CanonicalRawEventBatch:
        del config
        assert callable(event_sink)
        for event in batches[dataset_id].events:
            event_sink(event)
        return replace(batches[dataset_id], events=())

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verified_acquisition_input",
        verified_input,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_read_canonical_raw_events",
        stream_parser,
    )
    identities: list[list[dict[str, str]]] = []
    for ordinal in range(2):
        output_dir = tmp_path / f"binding-{ordinal}"
        bundle = produce_publication_structure_pilot(acquisition_root, output_dir)
        report = json.loads(bundle.report_path.read_bytes())
        identities.append([scan["input_identity"] for scan in report["dataset_scans"]])
        retarget_offset = 3

    assert identities[0][0]["acquisition_transaction_sha256"] == "1" * 64
    assert identities[0][0]["source_set_sha256"] == "2" * 64
    assert identities[0][0]["acquisition_behavior_set_sha256"] == "3" * 64
    assert len({identity["verified_input_binding_sha256"] for identity in identities[0]}) == 3
    assert identities[0] != identities[1]


@pytest.mark.parametrize(
    ("failure_point", "failure_stage", "scan_error_code", "blocked_code"),
    (
        ("parser", "parser", "parser-failed", "parser-scan-blocked"),
        (
            "canonical-constructor",
            "canonical-scan",
            "canonical-scan-failed",
            "canonical-scan-blocked",
        ),
        (
            "canonical-write",
            "canonical-scan",
            "canonical-scan-failed",
            "canonical-scan-blocked",
        ),
        (
            "canonical-finalize",
            "canonical-scan",
            "canonical-scan-failed",
            "canonical-scan-blocked",
        ),
    ),
)
def test_expected_dataset_scan_failure_retains_thirty_cells_with_closed_blocked_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    failure_stage: str,
    scan_error_code: str,
    blocked_code: str,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def verified_input(request: object, **_kwargs: object) -> object:
        dataset_id = request.dataset_id  # type: ignore[attr-defined]
        return SimpleNamespace(
            request=SimpleNamespace(sources=()),
            binding=_verified_binding(_DATASET_IDS.index(dataset_id) + 1),
        )

    def stream_parser(
        dataset_id: str,
        _sources: object,
        *,
        config: object,
        event_sink: object,
    ) -> CanonicalRawEventBatch:
        del config
        if failure_point == "parser" and dataset_id == _DATASET_IDS[0]:
            raise ValueError("private parser details must never enter the report")
        assert callable(event_sink)
        for event in batches[dataset_id].events:
            event_sink(event)
        return replace(batches[dataset_id], events=())

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verified_acquisition_input",
        verified_input,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_read_canonical_raw_events",
        stream_parser,
    )
    if failure_point == "canonical-constructor":
        real_store_type = publication_structure_pilot._CanonicalEventStore
        injected = False

        def fail_first_constructor(path: Path) -> object:
            nonlocal injected
            if not injected:
                injected = True
                raise publication_structure_pilot.sqlite3.OperationalError(
                    "private constructor details must never enter the report"
                )
            return real_store_type(path)

        monkeypatch.setattr(
            publication_structure_pilot,
            "_CanonicalEventStore",
            fail_first_constructor,
        )
    elif failure_point == "canonical-write":
        original_add = publication_structure_pilot._CanonicalEventStore.add
        injected = False

        def fail_first_add(store: object, event: object) -> None:
            nonlocal injected
            if not injected:
                injected = True
                raise publication_structure_pilot.sqlite3.OperationalError(
                    "private write details must never enter the report"
                )
            original_add(store, event)  # type: ignore[arg-type]

        monkeypatch.setattr(
            publication_structure_pilot._CanonicalEventStore,
            "add",
            fail_first_add,
        )
    elif failure_point == "canonical-finalize":
        original_finalize = publication_structure_pilot._CanonicalEventStore.finalize
        injected = False

        def fail_first_finalize(store: object) -> None:
            nonlocal injected
            if not injected:
                injected = True
                raise OSError("private store details must never enter the report")
            original_finalize(store)  # type: ignore[arg-type]

        monkeypatch.setattr(
            publication_structure_pilot._CanonicalEventStore,
            "finalize",
            fail_first_finalize,
        )
    output_dir = tmp_path / failure_point

    bundle = produce_publication_structure_pilot(acquisition_root, output_dir)

    report_text = bundle.report_path.read_text(encoding="ascii")
    report = json.loads(report_text)
    assert report["coverage"]["observed_cell_count"] == 30
    assert report["coverage"]["completed_cell_count"] == 20
    assert report["health"]["required_runtime_ok"] is True
    assert report["health"]["all_dataset_scans_completed"] is False
    assert report["health"]["all_cells_completed"] is False
    failed_scan = report["dataset_scans"][0]
    assert failed_scan["health"] == {"completion_state": "failed", "runtime_healthy": False}
    assert failed_scan["error"] == {
        "stage": failure_stage,
        "scan_error_code": scan_error_code,
    }
    blocked = [cell for cell in report["cells"] if cell["health"]["completion_state"] == "blocked"]
    assert len(blocked) == 10
    assert {cell["error"]["code"] for cell in blocked} == {blocked_code}
    assert {cell["error"]["stage"] for cell in blocked} == {"dataset-scan"}
    assert "private parser details" not in report_text
    assert "private constructor details" not in report_text
    assert "private write details" not in report_text
    assert "private store details" not in report_text


@pytest.mark.parametrize(
    "parser_error",
    (
        EOFError("private truncated-compressed-stream details"),
        csv.Error("private csv-format details"),
        zlib.error("private gzip-deflate details"),
    ),
)
def test_expected_parser_format_exception_is_closed_and_blocks_only_its_ten_cells(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parser_error: Exception,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def parser_input(dataset_id: str, *_args: object) -> object:
        batch = batches[dataset_id]
        binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 1)

        def scan(event_sink: object) -> CanonicalRawEventBatch:
            if dataset_id == _DATASET_IDS[0]:
                raise parser_error
            assert callable(event_sink)
            for event in batch.events:
                event_sink(event)
            return replace(batch, events=())

        return publication_structure_pilot._PilotDatasetInput(
            dataset_id=dataset_id,
            scan=scan,
            verified_binding=binding,
            revalidate_binding=lambda: binding,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        parser_input,
    )
    output_dir = tmp_path / "closed-parser-format-failure"

    bundle = produce_publication_structure_pilot(acquisition_root, output_dir)

    report_text = bundle.report_path.read_text(encoding="ascii")
    report = json.loads(report_text)
    assert report["coverage"]["completed_cell_count"] == 20
    assert report["dataset_scans"][0]["error"] == {
        "stage": "parser",
        "scan_error_code": "parser-failed",
    }
    blocked = [cell for cell in report["cells"] if cell["health"]["completion_state"] == "blocked"]
    assert len(blocked) == 10
    assert {(cell["error"]["stage"], cell["error"]["code"]) for cell in blocked} == {
        ("dataset-scan", "parser-scan-blocked")
    }
    assert str(parser_error) not in report_text


@pytest.mark.parametrize("parser_fails", (False, True))
def test_verified_acquisition_binding_drift_holds_before_any_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    parser_fails: bool,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def drifting_input(dataset_id: str, *_args: object) -> object:
        batch = batches[dataset_id]
        initial_binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 1)
        changed_binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 4)

        def scan(event_sink: object) -> CanonicalRawEventBatch:
            if parser_fails:
                raise ValueError("private parser failure before binding revalidation")
            assert callable(event_sink)
            for event in batch.events:
                event_sink(event)
            return replace(batch, events=())

        return publication_structure_pilot._PilotDatasetInput(
            dataset_id=dataset_id,
            scan=scan,
            verified_binding=initial_binding,
            revalidate_binding=lambda: changed_binding,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        drifting_input,
    )
    output_dir = tmp_path / f"binding-drift-output-{parser_fails}"

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(tmp_path.glob(f".{output_dir.name}.*")) == []


def test_final_binding_sweep_holds_when_an_earlier_bundle_drifts_during_a_later_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    source_snapshot = object()
    first_binding_drifted = False
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: source_snapshot,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )

    def drifting_input(dataset_id: str, *_args: object) -> object:
        batch = batches[dataset_id]
        initial_binding = _verified_binding(_DATASET_IDS.index(dataset_id) + 1)

        def scan(event_sink: object) -> CanonicalRawEventBatch:
            nonlocal first_binding_drifted
            assert callable(event_sink)
            for event in batch.events:
                event_sink(event)
            if dataset_id == _DATASET_IDS[-1]:
                first_binding_drifted = True
            return replace(batch, events=())

        def revalidate() -> dict[str, object]:
            if dataset_id == _DATASET_IDS[0] and first_binding_drifted:
                return _verified_binding(4)
            return initial_binding

        return publication_structure_pilot._PilotDatasetInput(
            dataset_id=dataset_id,
            scan=scan,
            verified_binding=initial_binding,
            revalidate_binding=revalidate,
        )

    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        drifting_input,
    )
    output_dir = tmp_path / "cross-dataset-binding-drift-output"

    with pytest.raises(PublicationStructurePilotHold, match="HOLD"):
        produce_publication_structure_pilot(acquisition_root, output_dir)

    assert not output_dir.exists()
    assert list(tmp_path.glob(f".{output_dir.name}.*")) == []


def test_public_source_drift_or_dirty_source_holds_before_any_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    batches = {dataset_id: _synthetic_batch(dataset_id) for dataset_id in _DATASET_IDS}
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_load_verified_production_input",
        lambda dataset_id, *_args: _streaming_input_from_batch(batches[dataset_id]),
    )
    snapshots = iter((object(), object()))
    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        lambda _repository_root: next(snapshots),
    )
    drift_output = tmp_path / "drift-output"

    with pytest.raises(PublicationStructurePilotHold, match="attestation changed"):
        produce_publication_structure_pilot(acquisition_root, drift_output)

    assert not drift_output.exists()
    assert list(tmp_path.glob(".drift-output.*")) == []

    def dirty_source(_repository_root: Path) -> object:
        raise RuntimeError("dirty worktree")

    monkeypatch.setattr(
        publication_structure_pilot,
        "_verify_production_source",
        dirty_source,
    )
    dirty_output = tmp_path / "dirty-output"
    with pytest.raises(PublicationStructurePilotHold, match="prerequisites"):
        produce_publication_structure_pilot(acquisition_root, dirty_output)

    assert not dirty_output.exists()
    assert list(tmp_path.glob(".dirty-output.*")) == []


def test_top_level_resource_checkpoint_follows_final_source_revalidation_and_scratch_teardown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    _production_scratch_root: Path,
) -> None:
    acquisition_root = tmp_path / "acquisitions"
    acquisition_root.mkdir()
    for dataset_id in _DATASET_IDS:
        (acquisition_root / dataset_id).mkdir()
    output_dir = tmp_path / "pilot-output"
    source_snapshot = object()
    source_verification_count = 0
    observed_rss = 101

    def verify_source(_repository_root: Path) -> object:
        nonlocal observed_rss, source_verification_count
        source_verification_count += 1
        if source_verification_count == 2:
            observed_rss = 909
        return source_snapshot

    def report_without_final_checkpoint(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "resource": {
                "analysis_wall_clock_ns": -1,
                "process_high_water_rss_bytes_before_report_install": 101,
            }
        }

    def observe_peak_rss() -> int:
        assert source_verification_count == 2
        assert list(_production_scratch_root.iterdir()) == []
        return observed_rss

    clock = iter((1_000, 1_900))
    monkeypatch.setattr(publication_structure_pilot, "_verify_production_source", verify_source)
    monkeypatch.setattr(
        publication_structure_pilot,
        "_production_acquisition_snapshot",
        lambda _repository_root: object(),
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_report_from_inputs",
        report_without_final_checkpoint,
    )
    monkeypatch.setattr(
        publication_structure_pilot,
        "_peak_resident_memory_bytes",
        observe_peak_rss,
    )
    monkeypatch.setattr(
        publication_structure_pilot.time,
        "monotonic_ns",
        lambda: next(clock),
    )

    bundle = produce_publication_structure_pilot(acquisition_root, output_dir)

    report = json.loads(bundle.report_path.read_bytes())
    assert report["resource"] == {
        "analysis_wall_clock_ns": 900,
        "process_high_water_rss_bytes_before_report_install": 909,
    }
