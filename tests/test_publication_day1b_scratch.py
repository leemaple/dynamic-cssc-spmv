from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import stat
from dataclasses import replace
from pathlib import Path

import pytest

import dynamic_cssc.publication_day1b_scratch as scratch_module
from dynamic_cssc.publication_day1b_scratch import (
    DAY1B_ANONYMOUS_SCRATCH_CREATION_RECEIPT_SCHEMA,
    DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES,
    Day1BAnonymousScratchCreationError,
    Day1BAnonymousScratchCreationReceipt,
    Day1BAnonymousScratchMemberIdentity,
    open_linux_day1b_anonymous_scratch,
)

_LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="production anonymous scratch uses Linux openat and /proc/self/fd",
)


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _synthetic_receipt() -> Day1BAnonymousScratchCreationReceipt:
    return Day1BAnonymousScratchCreationReceipt(
        launcher_parent_path="/controller-owned/day1b-scratch",
        parent_device=41,
        parent_inode=51,
        parent_mode=0o700,
        parent_owner_uid=61,
        filesystem_id=71,
        ephemeral_root_name_sha256="a" * 64,
        ephemeral_root_device=41,
        ephemeral_root_inode=81,
        ephemeral_root_mode=0o700,
        ephemeral_root_owner_uid=61,
        members=(
            Day1BAnonymousScratchMemberIdentity(
                role="binding-index.sqlite3",
                device=41,
                inode=91,
                mode=0o600,
                owner_uid=61,
            ),
            Day1BAnonymousScratchMemberIdentity(
                role="object-receipts.jsonl",
                device=41,
                inode=92,
                mode=0o600,
                owner_uid=61,
            ),
        ),
        sqlite_connection_identity_verified=True,
        all_member_names_unlinked=True,
        ephemeral_root_removed=True,
    )


def test_anonymous_scratch_creation_receipt_is_closed_and_non_authorizing() -> None:
    receipt = _synthetic_receipt()
    document = receipt.to_document()
    digest = document.pop("receipt_sha256")

    assert document["schema_version"] == (
        DAY1B_ANONYMOUS_SCRATCH_CREATION_RECEIPT_SCHEMA
    )
    assert document["status"] == "verified-linux-anonymous-scratch-creation-only"
    assert document["directory_resolution"] == "linux-openat-proc-self-fd-v1"
    assert [item["role"] for item in document["members"]] == list(
        DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES
    )
    assert document["formal_authority_granted"] is False
    assert document["production_execution_admissible"] is False
    assert document["publication_authority"] is False
    assert digest == hashlib.sha256(_canonical_bytes(document)).hexdigest()


def test_anonymous_scratch_creation_receipt_rejects_semantic_mutation() -> None:
    receipt = _synthetic_receipt()

    with pytest.raises(Day1BAnonymousScratchCreationError, match="malformed"):
        replace(receipt, all_member_names_unlinked=False)
    with pytest.raises(Day1BAnonymousScratchCreationError, match="malformed"):
        replace(receipt, members=tuple(reversed(receipt.members)))
    with pytest.raises(Day1BAnonymousScratchCreationError, match="malformed"):
        replace(receipt.members[0], mode=0o644)


def test_anonymous_scratch_creation_fails_closed_off_linux(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(scratch_module.platform, "system", lambda: "Darwin")

    with pytest.raises(Day1BAnonymousScratchCreationError, match="requires Linux"):
        open_linux_day1b_anonymous_scratch(tmp_path)


@_LINUX_ONLY
def test_linux_anonymous_scratch_is_unlinked_before_handles_are_returned(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "launcher-owned"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)

    opened = open_linux_day1b_anonymous_scratch(parent)
    members, connection, receipt = opened.transfer()
    try:
        assert not tuple(parent.iterdir())
        assert receipt.launcher_parent_path == str(parent)
        assert receipt.all_member_names_unlinked is True
        assert receipt.ephemeral_root_removed is True
        assert receipt.sqlite_connection_identity_verified is True
        assert tuple(item.role for item in receipt.members) == (
            DAY1B_ANONYMOUS_SCRATCH_MEMBER_NAMES
        )
        for (role, file, identity), recorded in zip(
            members,
            receipt.members,
            strict=True,
        ):
            observed = os.fstat(file.fileno())
            assert role == recorded.role
            assert identity == (recorded.device, recorded.inode)
            assert observed.st_nlink == 0
            assert stat.S_IMODE(observed.st_mode) == 0o600

        assert connection.execute("PRAGMA journal_mode=OFF").fetchone() == ("off",)
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("CREATE TABLE witness(value INTEGER NOT NULL)")
        connection.execute("INSERT INTO witness VALUES (7)")
        connection.commit()
        assert connection.execute("SELECT value FROM witness").fetchall() == [(7,)]
        members[1][1].write(b'{"object":"witness"}\n')
        members[1][1].flush()
        assert all(os.fstat(item[1].fileno()).st_size > 0 for item in members)
        assert not tuple(parent.iterdir())
    finally:
        connection.close()
        for _role, file, _identity in members:
            file.close()


@_LINUX_ONLY
def test_linux_anonymous_scratch_rejects_nonempty_nonprivate_and_symlink_parents(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "launcher-owned"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o755)
    with pytest.raises(Day1BAnonymousScratchCreationError, match="owner-only"):
        open_linux_day1b_anonymous_scratch(parent)

    os.chmod(parent, 0o700)
    foreign = parent / "foreign"
    foreign.write_bytes(b"")
    with pytest.raises(Day1BAnonymousScratchCreationError, match="owner-only"):
        open_linux_day1b_anonymous_scratch(parent)
    foreign.unlink()

    alias = tmp_path / "launcher-alias"
    alias.symlink_to(parent, target_is_directory=True)
    with pytest.raises(Day1BAnonymousScratchCreationError, match="symlink component"):
        open_linux_day1b_anonymous_scratch(alias)
    assert not tuple(parent.iterdir())


@_LINUX_ONLY
def test_linux_anonymous_scratch_cleans_exact_members_after_sqlite_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "launcher-owned"
    parent.mkdir(mode=0o700)
    os.chmod(parent, 0o700)

    def fail_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("injected SQLite failure")

    monkeypatch.setattr(scratch_module.sqlite3, "connect", fail_connect)
    with pytest.raises(Day1BAnonymousScratchCreationError, match="failed closed"):
        open_linux_day1b_anonymous_scratch(parent)
    assert not tuple(parent.iterdir())
