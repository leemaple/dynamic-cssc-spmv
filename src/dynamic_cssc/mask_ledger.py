from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol, TypeAlias

MaskBinding: TypeAlias = tuple[str, str, str, str, str]


class DuplicateMaskBindingError(RuntimeError):
    """Raised when a one-time mask binding was already consumed."""


class MaskBindingLedger(Protocol):
    """Persistent atomic reservation boundary for one-time mask bindings."""

    def reserve_all(self, bindings: Iterable[MaskBinding]) -> None:
        """Atomically reserve every binding, or reserve none if one is a duplicate."""


class SQLiteMaskBindingLedger:
    """Crash-persistent SQLite implementation of the mask binding ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) == ":memory:":
            raise ValueError("mask binding ledger must be persistent")
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mask_binding_reservations (
                    query_id TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    output_plan_digest TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    output_block_id TEXT NOT NULL,
                    PRIMARY KEY (
                        query_id,
                        version_id,
                        output_plan_digest,
                        component_id,
                        output_block_id
                    )
                ) WITHOUT ROWID
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def reserve_all(self, bindings: Iterable[MaskBinding]) -> None:
        requested = tuple(bindings)
        if not requested:
            return
        if len(set(requested)) != len(requested):
            raise DuplicateMaskBindingError("reservation request repeats a mask binding")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.executemany(
                    """
                    INSERT INTO mask_binding_reservations (
                        query_id,
                        version_id,
                        output_plan_digest,
                        component_id,
                        output_block_id
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    requested,
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateMaskBindingError("mask binding was already consumed") from error
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
