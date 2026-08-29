from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, TypeAlias

MaskBinding: TypeAlias = tuple[str, str, str, str, str]
PreparedF1MKind: TypeAlias = Literal["random-zero-sum", "encrypted-zero-dummy"]


class DuplicateMaskBindingError(RuntimeError):
    """Raised when a one-time mask binding was already consumed."""


class PreparedF1MCommitmentError(RuntimeError):
    """Raised when prepared F1-M operands do not match persistent ledger state."""


class ConsumedPreparedF1MCommitmentError(PreparedF1MCommitmentError):
    """Raised when a prepared F1-M commitment batch was already executed."""


@dataclass(frozen=True, slots=True)
class PreparedF1MCommitment:
    query_id: str
    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    kind: PreparedF1MKind
    values: tuple[int, ...]

    @property
    def binding(self) -> MaskBinding:
        return (
            self.query_id,
            self.version_id,
            self.output_plan_digest,
            self.component_id,
            self.output_block_id,
        )


class MaskBindingLedger(Protocol):
    """Persistent atomic reservation boundary for one-time mask bindings."""

    def reserve_all(self, bindings: Iterable[MaskBinding]) -> None:
        """Atomically reserve every binding, or reserve none if one is a duplicate."""


class PreparedF1MCommitmentLedger(MaskBindingLedger, Protocol):
    """Trusted persistence boundary from preparation through one execution."""

    def commit_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> str:
        """Persist a ledger-issued batch token and exact operand commitments."""

    def verify_and_consume_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        commitment_token: str,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> None:
        """Atomically verify the exact committed operands and consume the batch once."""

    def verify_consumed_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        commitment_token: str,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> None:
        """Read-only verification of one already consumed exact batch."""


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_commitments(
    commitments: Iterable[PreparedF1MCommitment],
    *,
    query_id: str,
    version_id: str,
    output_plan_digest: str,
    private_plan_digest: str,
    execution_binding_digest: str,
    modulus: int,
) -> tuple[PreparedF1MCommitment, ...]:
    if (
        not _valid_id(query_id)
        or not _valid_id(version_id)
        or not _valid_sha256(output_plan_digest)
        or not _valid_sha256(private_plan_digest)
        or not _valid_sha256(execution_binding_digest)
        or not _is_strict_int(modulus)
        or modulus < 2
    ):
        raise PreparedF1MCommitmentError("prepared F1-M commitment batch binding is invalid")
    requested = tuple(commitments)
    share_ids: set[tuple[str, str]] = set()
    for commitment in requested:
        if (
            not isinstance(commitment, PreparedF1MCommitment)
            or commitment.query_id != query_id
            or commitment.version_id != version_id
            or commitment.output_plan_digest != output_plan_digest
            or not _valid_id(commitment.component_id)
            or not _valid_id(commitment.output_block_id)
            or commitment.kind not in ("random-zero-sum", "encrypted-zero-dummy")
            or not isinstance(commitment.values, tuple)
            or not commitment.values
            or any(
                not _is_strict_int(value) or not 0 <= value < modulus for value in commitment.values
            )
        ):
            raise PreparedF1MCommitmentError("prepared F1-M commitment is invalid")
        share_id = (commitment.component_id, commitment.output_block_id)
        if share_id in share_ids:
            raise PreparedF1MCommitmentError(
                "prepared F1-M commitment batch repeats an output share"
            )
        share_ids.add(share_id)
        if commitment.kind == "encrypted-zero-dummy" and any(commitment.values):
            raise PreparedF1MCommitmentError("prepared F1-M dummy commitment must be exactly zero")
    return requested


def _values_digest(commitment: PreparedF1MCommitment, *, modulus: int) -> str:
    encoded = json.dumps(
        {
            "binding": list(commitment.binding),
            "format": "dynamic-cssc-prepared-f1m-commitment-v1",
            "kind": commitment.kind,
            "modulus": modulus,
            "values": list(commitment.values),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class SQLiteMaskBindingLedger:
    """Crash-persistent SQLite implementation of the mask binding ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._read_only = False
        if str(path) == ":memory:":
            raise ValueError("mask binding ledger must be persistent")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prepared_f1m_batches (
                    commitment_token TEXT NOT NULL PRIMARY KEY,
                    query_id TEXT NOT NULL,
                    version_id TEXT NOT NULL,
                    output_plan_digest TEXT NOT NULL,
                    private_plan_digest TEXT NOT NULL,
                    execution_binding_digest TEXT NOT NULL,
                    modulus TEXT NOT NULL,
                    consumed INTEGER NOT NULL CHECK (consumed IN (0, 1)),
                    UNIQUE (query_id, version_id, output_plan_digest)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS prepared_f1m_commitments (
                    commitment_token TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    output_block_id TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (
                        kind IN ('random-zero-sum', 'encrypted-zero-dummy')
                    ),
                    value_count INTEGER NOT NULL CHECK (value_count > 0),
                    values_digest TEXT NOT NULL,
                    PRIMARY KEY (commitment_token, component_id, output_block_id),
                    FOREIGN KEY (commitment_token)
                        REFERENCES prepared_f1m_batches (commitment_token)
                ) WITHOUT ROWID
                """
            )
            batch_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(prepared_f1m_batches)")
            }
            if "private_plan_digest" not in batch_columns:
                connection.execute(
                    """
                    ALTER TABLE prepared_f1m_batches
                    ADD COLUMN private_plan_digest TEXT
                    """
                )
            if "execution_binding_digest" not in batch_columns:
                connection.execute(
                    """
                    ALTER TABLE prepared_f1m_batches
                    ADD COLUMN execution_binding_digest TEXT
                    """
                )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @classmethod
    def open_existing_read_only(cls, path: str | Path) -> SQLiteMaskBindingLedger:
        """Open an exact existing ledger without creating or mutating any bytes."""

        ledger_path = Path(path)
        try:
            ledger_path.lstat()
        except OSError as error:
            raise PreparedF1MCommitmentError(
                "read-only prepared F1-M ledger is unavailable"
            ) from error
        if not ledger_path.is_file() or ledger_path.is_symlink():
            raise PreparedF1MCommitmentError(
                "read-only prepared F1-M ledger must be one regular file"
            )
        ledger = object.__new__(cls)
        ledger.path = ledger_path
        ledger._read_only = True
        connection = ledger._connect()
        try:
            required_tables = {
                "mask_binding_reservations",
                "prepared_f1m_batches",
                "prepared_f1m_commitments",
            }
            observed_tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                )
            }
            if observed_tables != required_tables:
                raise PreparedF1MCommitmentError(
                    "read-only prepared F1-M ledger schema is not closed"
                )
            if tuple(connection.execute("PRAGMA foreign_key_check").fetchall()):
                raise PreparedF1MCommitmentError(
                    "read-only prepared F1-M ledger has a foreign-key violation"
                )
        finally:
            connection.close()
        return ledger

    def _require_writable(self) -> None:
        if self._read_only:
            raise RuntimeError("prepared F1-M ledger is read-only")

    def _connect(self) -> sqlite3.Connection:
        if self._read_only:
            connection = sqlite3.connect(
                f"{self.path.resolve().as_uri()}?mode=ro&immutable=1",
                timeout=30.0,
                uri=True,
            )
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def reserve_all(self, bindings: Iterable[MaskBinding]) -> None:
        self._require_writable()
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

    def commit_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> str:
        self._require_writable()
        requested = _validate_commitments(
            commitments,
            query_id=query_id,
            version_id=version_id,
            output_plan_digest=output_plan_digest,
            private_plan_digest=private_plan_digest,
            execution_binding_digest=execution_binding_digest,
            modulus=modulus,
        )
        commitment_token = secrets.token_hex(32)
        if not _valid_sha256(commitment_token):  # pragma: no cover - stdlib contract
            raise PreparedF1MCommitmentError(
                "ledger failed to issue a prepared F1-M commitment token"
            )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for commitment in requested:
                if commitment.kind != "random-zero-sum":
                    continue
                reservation = connection.execute(
                    """
                    SELECT 1
                    FROM mask_binding_reservations
                    WHERE query_id = ?
                      AND version_id = ?
                      AND output_plan_digest = ?
                      AND component_id = ?
                      AND output_block_id = ?
                    """,
                    commitment.binding,
                ).fetchone()
                if reservation is None:
                    raise PreparedF1MCommitmentError(
                        "random prepared F1-M commitment lacks a prior reservation"
                    )
            try:
                connection.execute(
                    """
                    INSERT INTO prepared_f1m_batches (
                        commitment_token,
                        query_id,
                        version_id,
                        output_plan_digest,
                        private_plan_digest,
                        execution_binding_digest,
                        modulus,
                        consumed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        commitment_token,
                        query_id,
                        version_id,
                        output_plan_digest,
                        private_plan_digest,
                        execution_binding_digest,
                        str(modulus),
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO prepared_f1m_commitments (
                        commitment_token,
                        component_id,
                        output_block_id,
                        kind,
                        value_count,
                        values_digest
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            commitment_token,
                            commitment.component_id,
                            commitment.output_block_id,
                            commitment.kind,
                            len(commitment.values),
                            _values_digest(commitment, modulus=modulus),
                        )
                        for commitment in requested
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise DuplicateMaskBindingError(
                    "prepared F1-M query binding was already committed"
                ) from error
            connection.commit()
            return commitment_token
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def verify_and_consume_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        commitment_token: str,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> None:
        self._require_writable()
        requested = _validate_commitments(
            commitments,
            query_id=query_id,
            version_id=version_id,
            output_plan_digest=output_plan_digest,
            private_plan_digest=private_plan_digest,
            execution_binding_digest=execution_binding_digest,
            modulus=modulus,
        )
        if not _valid_sha256(commitment_token):
            raise PreparedF1MCommitmentError("prepared F1-M commitment token is invalid")
        expected_rows = tuple(
            sorted(
                (
                    commitment.component_id,
                    commitment.output_block_id,
                    commitment.kind,
                    len(commitment.values),
                    _values_digest(commitment, modulus=modulus),
                )
                for commitment in requested
            )
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            batch = connection.execute(
                """
                SELECT
                    query_id,
                    version_id,
                    output_plan_digest,
                    private_plan_digest,
                    execution_binding_digest,
                    modulus,
                    consumed
                FROM prepared_f1m_batches
                WHERE commitment_token = ?
                """,
                (commitment_token,),
            ).fetchone()
            if (
                batch is None
                or tuple(batch[:3])
                != (
                    query_id,
                    version_id,
                    output_plan_digest,
                )
                or batch[5] != str(modulus)
            ):
                raise PreparedF1MCommitmentError(
                    "prepared F1-M commitment does not match its ledger batch"
                )
            if batch[3] != private_plan_digest:
                raise PreparedF1MCommitmentError(
                    "prepared F1-M commitment private plan does not match the ledger"
                )
            if batch[4] != execution_binding_digest:
                raise PreparedF1MCommitmentError(
                    "prepared F1-M commitment execution binding does not match the ledger"
                )
            if batch[6] != 0:
                raise ConsumedPreparedF1MCommitmentError(
                    "prepared F1-M commitment batch was already consumed"
                )
            stored_rows = tuple(
                connection.execute(
                    """
                    SELECT component_id, output_block_id, kind, value_count, values_digest
                    FROM prepared_f1m_commitments
                    WHERE commitment_token = ?
                    ORDER BY component_id, output_block_id
                    """,
                    (commitment_token,),
                ).fetchall()
            )
            if stored_rows != expected_rows:
                raise PreparedF1MCommitmentError(
                    "prepared F1-M commitment values do not match the ledger"
                )
            cursor = connection.execute(
                """
                UPDATE prepared_f1m_batches
                SET consumed = 1
                WHERE commitment_token = ? AND consumed = 0
                """,
                (commitment_token,),
            )
            if cursor.rowcount != 1:  # pragma: no cover - guarded in the same transaction
                raise ConsumedPreparedF1MCommitmentError(
                    "prepared F1-M commitment batch was already consumed"
                )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def verify_consumed_prepared_f1m(
        self,
        commitments: Iterable[PreparedF1MCommitment],
        *,
        commitment_token: str,
        query_id: str,
        version_id: str,
        output_plan_digest: str,
        private_plan_digest: str,
        execution_binding_digest: str,
        modulus: int,
    ) -> None:
        """Verify an exact consumed batch without changing the ledger."""

        requested = _validate_commitments(
            commitments,
            query_id=query_id,
            version_id=version_id,
            output_plan_digest=output_plan_digest,
            private_plan_digest=private_plan_digest,
            execution_binding_digest=execution_binding_digest,
            modulus=modulus,
        )
        if not _valid_sha256(commitment_token):
            raise PreparedF1MCommitmentError("prepared F1-M commitment token is invalid")
        expected_rows = tuple(
            sorted(
                (
                    commitment.component_id,
                    commitment.output_block_id,
                    commitment.kind,
                    len(commitment.values),
                    _values_digest(commitment, modulus=modulus),
                )
                for commitment in requested
            )
        )
        connection = self._connect()
        try:
            batch = connection.execute(
                """
                SELECT
                    query_id,
                    version_id,
                    output_plan_digest,
                    private_plan_digest,
                    execution_binding_digest,
                    modulus,
                    consumed
                FROM prepared_f1m_batches
                WHERE commitment_token = ?
                """,
                (commitment_token,),
            ).fetchone()
            if batch != (
                query_id,
                version_id,
                output_plan_digest,
                private_plan_digest,
                execution_binding_digest,
                str(modulus),
                1,
            ):
                raise PreparedF1MCommitmentError(
                    "prepared F1-M replay batch is absent, unconsumed, or mismatched"
                )
            stored_rows = tuple(
                connection.execute(
                    """
                    SELECT component_id, output_block_id, kind, value_count, values_digest
                    FROM prepared_f1m_commitments
                    WHERE commitment_token = ?
                    ORDER BY component_id, output_block_id
                    """,
                    (commitment_token,),
                ).fetchall()
            )
            if stored_rows != expected_rows:
                raise PreparedF1MCommitmentError(
                    "prepared F1-M replay operands differ from the consumed ledger"
                )
        finally:
            connection.close()

    def verify_closed_consumed_prepared_f1m_ledger(
        self,
        *,
        commitment_tokens: tuple[str, ...],
        reservation_bindings: tuple[MaskBinding, ...],
    ) -> None:
        """Reject missing, extra, duplicate, or unconsumed rows in a replay ledger."""

        if (
            type(commitment_tokens) is not tuple
            or any(not _valid_sha256(token) for token in commitment_tokens)
            or len(set(commitment_tokens)) != len(commitment_tokens)
            or type(reservation_bindings) is not tuple
            or len(set(reservation_bindings)) != len(reservation_bindings)
        ):
            raise PreparedF1MCommitmentError(
                "closed prepared F1-M replay ledger expectation is invalid"
            )
        for binding in reservation_bindings:
            if (
                type(binding) is not tuple
                or len(binding) != 5
                or not _valid_id(binding[0])
                or not _valid_id(binding[1])
                or not _valid_sha256(binding[2])
                or not _valid_id(binding[3])
                or not _valid_id(binding[4])
            ):
                raise PreparedF1MCommitmentError(
                    "closed prepared F1-M replay reservation is invalid"
                )
        connection = self._connect()
        try:
            observed_batches = tuple(
                connection.execute(
                    """
                    SELECT commitment_token
                    FROM prepared_f1m_batches
                    WHERE consumed = 1
                    ORDER BY commitment_token
                    """
                ).fetchall()
            )
            all_batch_count = connection.execute(
                "SELECT COUNT(*) FROM prepared_f1m_batches"
            ).fetchone()
            observed_reservations = tuple(
                connection.execute(
                    """
                    SELECT
                        query_id,
                        version_id,
                        output_plan_digest,
                        component_id,
                        output_block_id
                    FROM mask_binding_reservations
                    ORDER BY
                        query_id,
                        version_id,
                        output_plan_digest,
                        component_id,
                        output_block_id
                    """
                ).fetchall()
            )
            observed_commitment_tokens = tuple(
                row[0]
                for row in connection.execute(
                    """
                    SELECT DISTINCT commitment_token
                    FROM prepared_f1m_commitments
                    ORDER BY commitment_token
                    """
                ).fetchall()
            )
            foreign_key_violations = tuple(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            if (
                observed_batches != tuple((token,) for token in sorted(commitment_tokens))
                or all_batch_count != (len(commitment_tokens),)
                or observed_reservations != tuple(sorted(reservation_bindings))
                # Subset is intentional: a legitimate consumed batch may have zero
                # commitment rows, but every stored row must belong to an expected batch.
                or any(
                    token not in commitment_tokens for token in observed_commitment_tokens
                )
                or foreign_key_violations
            ):
                raise PreparedF1MCommitmentError(
                    "prepared F1-M replay ledger is missing, extra, duplicated, unconsumed, "
                    "or has invalid commitment rows"
                )
        finally:
            connection.close()
