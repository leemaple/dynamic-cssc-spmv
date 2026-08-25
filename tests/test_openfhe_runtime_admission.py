from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from dynamic_cssc.openfhe_runtime_admission import (
    AdmittedExecutableFile,
    OpenFHERuntimeAdmissionError,
    admit_linux_runtime_mapping_continuity,
    capture_linux_process_mapping_snapshot,
)


def _file(path: Path, content: bytes) -> AdmittedExecutableFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o755)
    observed = path.stat(follow_symlinks=False)
    return AdmittedExecutableFile(
        path=str(path),
        device=observed.st_dev,
        inode=observed.st_ino,
        mode=stat.S_IMODE(observed.st_mode),
        byte_count=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        binary_format="elf-v1",
        binary_id=hashlib.sha256(b"binary-id:" + content).hexdigest()[:40],
    )


def _stat_bytes(pid: int, start_time: int) -> bytes:
    fields_three_through_twenty_two = ["S", *(["0"] * 18), str(start_time)]
    return f"{pid} (openfhe runner) {' '.join(fields_three_through_twenty_two)}\n".encode()


def _map_row(
    item: AdmittedExecutableFile,
    address: int,
    *,
    permissions: str = "r-xp",
    inode: int | None = None,
) -> str:
    return (
        f"{address:08x}-{address + 4096:08x} {permissions} 00000000 "
        f"{os.major(item.device):02x}:{os.minor(item.device):02x} "
        f"{item.inode if inode is None else inode} {item.path}\n"
    )


def _write_proc(
    proc_root: Path,
    *,
    pid: int,
    start_time: int,
    maps: str,
) -> None:
    process = proc_root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    (process / "stat").write_bytes(_stat_bytes(pid, start_time))
    (process / "maps").write_text(maps, encoding="utf-8")


def test_ready_done_mapping_admission_allows_only_raw_nonexecuting_changes(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    runner = _file(root / "bin/openfhe_query_runner", b"runner")
    library = _file(root / "lib/libOPENFHEpke.so.1", b"library")
    admitted = tuple(sorted((runner, library), key=lambda item: item.path))
    proc_root = root / "proc"
    pid = 4172
    executable_maps = (
        _map_row(runner, 0x100000)
        + _map_row(library, 0x200000)
        + "7fff0000-7fff1000 r-xp 00000000 00:00 0 [vdso]\n"
    )
    _write_proc(
        proc_root,
        pid=pid,
        start_time=998877,
        maps=executable_maps,
    )
    ready = capture_linux_process_mapping_snapshot(
        pid=pid,
        stage="READY",
        admitted_executable_files=admitted,
        proc_root=proc_root,
    )

    _write_proc(
        proc_root,
        pid=pid,
        start_time=998877,
        maps=(
            executable_maps
            + "30000000-30001000 rw-p 00000000 00:00 0 [heap]\n"
        ),
    )
    done = capture_linux_process_mapping_snapshot(
        pid=pid,
        stage="DONE",
        admitted_executable_files=admitted,
        proc_root=proc_root,
    )
    admission = admit_linux_runtime_mapping_continuity(ready, done)

    assert ready.raw_maps_sha256 != done.raw_maps_sha256
    assert ready.executable_mapping_set_sha256 == done.executable_mapping_set_sha256
    assert admission.to_document()["runtime_state_continuity_verified"] is True
    assert admission.to_document()["formal_authority_granted"] is False
    assert admission.to_document()["publication_authority"] is False


def test_mapping_snapshot_rejects_extra_or_retargeted_executable_files(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    runner = _file(root / "bin/openfhe_query_runner", b"runner")
    library = _file(root / "lib/libOPENFHEpke.so.1", b"library")
    extra = _file(root / "lib/libinjected.so", b"injected")
    admitted = tuple(sorted((runner, library), key=lambda item: item.path))
    proc_root = root / "proc"
    pid = 4173
    _write_proc(
        proc_root,
        pid=pid,
        start_time=112233,
        maps=(
            _map_row(runner, 0x100000)
            + _map_row(library, 0x200000)
            + _map_row(extra, 0x300000)
        ),
    )
    with pytest.raises(OpenFHERuntimeAdmissionError, match="file set differs"):
        capture_linux_process_mapping_snapshot(
            pid=pid,
            stage="READY",
            admitted_executable_files=admitted,
            proc_root=proc_root,
        )

    _write_proc(
        proc_root,
        pid=pid,
        start_time=112233,
        maps=(
            _map_row(runner, 0x100000, inode=runner.inode + 1)
            + _map_row(library, 0x200000)
        ),
    )
    with pytest.raises(OpenFHERuntimeAdmissionError, match="pre-launch inode"):
        capture_linux_process_mapping_snapshot(
            pid=pid,
            stage="READY",
            admitted_executable_files=admitted,
            proc_root=proc_root,
        )

    _write_proc(
        proc_root,
        pid=pid,
        start_time=112233,
        maps=_map_row(runner, 0x100000) + _map_row(library, 0x200000),
    )
    Path(runner.path).write_bytes(b"tamper")
    with pytest.raises(OpenFHERuntimeAdmissionError, match="bytes changed"):
        capture_linux_process_mapping_snapshot(
            pid=pid,
            stage="READY",
            admitted_executable_files=admitted,
            proc_root=proc_root,
        )

    Path(runner.path).write_bytes(b"runner")
    Path(runner.path).chmod(0o700)
    with pytest.raises(OpenFHERuntimeAdmissionError, match="metadata differs"):
        capture_linux_process_mapping_snapshot(
            pid=pid,
            stage="READY",
            admitted_executable_files=admitted,
            proc_root=proc_root,
        )


def test_mapping_admission_rejects_pid_reuse_and_unapproved_kernel_code(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    runner = _file(root / "bin/openfhe_query_runner", b"runner")
    admitted = (runner,)
    proc_root = root / "proc"
    pid = 4174
    _write_proc(
        proc_root,
        pid=pid,
        start_time=445566,
        maps=_map_row(runner, 0x100000),
    )
    ready = capture_linux_process_mapping_snapshot(
        pid=pid,
        stage="READY",
        admitted_executable_files=admitted,
        proc_root=proc_root,
    )
    _write_proc(
        proc_root,
        pid=pid,
        start_time=778899,
        maps=_map_row(runner, 0x100000),
    )
    done = capture_linux_process_mapping_snapshot(
        pid=pid,
        stage="DONE",
        admitted_executable_files=admitted,
        proc_root=proc_root,
    )
    with pytest.raises(OpenFHERuntimeAdmissionError, match="not continuous"):
        admit_linux_runtime_mapping_continuity(ready, done)

    _write_proc(
        proc_root,
        pid=pid,
        start_time=445566,
        maps=(
            _map_row(runner, 0x100000)
            + "7fff0000-7fff1000 r-xp 00000000 00:00 0 [jit-cache]\n"
        ),
    )
    with pytest.raises(OpenFHERuntimeAdmissionError, match="kernel executable"):
        capture_linux_process_mapping_snapshot(
            pid=pid,
            stage="DONE",
            admitted_executable_files=admitted,
            proc_root=proc_root,
        )
