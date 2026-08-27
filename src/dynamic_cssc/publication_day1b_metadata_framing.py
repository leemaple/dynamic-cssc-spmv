"""Canonical fixed-width Day 1B protocol-metadata serialization.

The publication communication ledger prices protocol objects, not JSON
descriptions of them.  These records therefore use exact big-endian binary
layouts whose byte lengths do not depend on identifier spelling or integer
rendering.  CI patch and full-sync entries intentionally share one size class;
their only layout difference is the fixed-position ``entry_kind`` byte.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Final

from dynamic_cssc.publication_day1b_aggregate_bounds import (
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
)

DAY1B_METADATA_FRAMING_SCHEMA: Final = "dynamic-cssc-publication-day1b-metadata-framing-v1"
DAY1B_METADATA_SIZE_CLASS_SCHEMA: Final = "dynamic-cssc-publication-day1b-metadata-size-class-v2"
DAY1B_METADATA_MAGIC: Final = b"D1BMETA1"
DAY1B_METADATA_BINARY_SCHEMA_VERSION: Final = 1

DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES: Final = 64
DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES: Final = 144
DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES: Final = 136

_COLUMN_INDEX_CATEGORY = "update-column-index-synchronization"
_UPDATE_VERSION_CATEGORY = "update-version-plan-metadata"
_QUERY_VERSION_CATEGORY = "query-version-plan-metadata"
DAY1B_FIXED_WIDTH_METADATA_CATEGORIES: Final = (
    _COLUMN_INDEX_CATEGORY,
    _UPDATE_VERSION_CATEGORY,
    _QUERY_VERSION_CATEGORY,
)
_EXPECTED_METADATA_TAXONOMY = (
    (_COLUMN_INDEX_CATEGORY, "update"),
    (_UPDATE_VERSION_CATEGORY, "update"),
    (_QUERY_VERSION_CATEGORY, "query"),
)
if (
    tuple(
        item
        for item in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
        if item[0] in DAY1B_FIXED_WIDTH_METADATA_CATEGORIES
    )
    != _EXPECTED_METADATA_TAXONOMY
):
    raise AssertionError("Day 1B fixed-width metadata taxonomy drifted")

_COLUMN_INDEX_RECORD_KIND = 1
_UPDATE_VERSION_RECORD_KIND = 2
_QUERY_VERSION_RECORD_KIND = 3
_ENTRY_KIND_TO_CODE = {"patch": 1, "full-sync": 2}
_CODE_TO_ENTRY_KIND = {code: kind for kind, code in _ENTRY_KIND_TO_CODE.items()}
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_COLUMN_INDEX_STRUCT = struct.Struct(">8sBBHIQQIIIIqB7s")
_UPDATE_VERSION_STRUCT = struct.Struct(">8sBBHIQQQQ32s32s32s")
_QUERY_VERSION_STRUCT = struct.Struct(">8sBBHIQQQ32s32s32s")

if _COLUMN_INDEX_STRUCT.size != DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES:
    raise AssertionError("Day 1B column-index metadata layout drifted")
if _UPDATE_VERSION_STRUCT.size != DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES:
    raise AssertionError("Day 1B update-version metadata layout drifted")
if _QUERY_VERSION_STRUCT.size != DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES:
    raise AssertionError("Day 1B query-version metadata layout drifted")


class Day1BMetadataFramingError(ValueError):
    """Raised when one metadata object is not its exact binary framing."""


def _strict_unsigned(value: object, bits: int, field: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise Day1BMetadataFramingError(f"{field} must be one exact unsigned {bits}-bit integer")
    return value


def _strict_signed_64(value: object, field: str) -> int:
    if type(value) is not int or not -(1 << 63) <= value < 1 << 63:
        raise Day1BMetadataFramingError(f"{field} must be one exact signed 64-bit integer")
    return value


def _digest_bytes(value: object, field: str) -> bytes:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BMetadataFramingError(f"{field} must be an exact lowercase SHA-256")
    return bytes.fromhex(value)


def _header(record_kind: int, byte_count: int) -> tuple[bytes, int, int, int, int]:
    return (
        DAY1B_METADATA_MAGIC,
        record_kind,
        0,
        DAY1B_METADATA_BINARY_SCHEMA_VERSION,
        byte_count,
    )


def _validate_header(
    *,
    magic: object,
    record_kind: object,
    flags: object,
    schema_version: object,
    byte_count: object,
    expected_record_kind: int,
    expected_byte_count: int,
) -> None:
    if magic != DAY1B_METADATA_MAGIC:
        raise Day1BMetadataFramingError("Day 1B metadata magic changed")
    if record_kind != expected_record_kind:
        raise Day1BMetadataFramingError("Day 1B metadata record kind changed")
    if flags != 0:
        raise Day1BMetadataFramingError("Day 1B metadata flags must be zero")
    if schema_version != DAY1B_METADATA_BINARY_SCHEMA_VERSION:
        raise Day1BMetadataFramingError("Day 1B metadata binary schema changed")
    if byte_count != expected_byte_count:
        raise Day1BMetadataFramingError("Day 1B metadata byte-count header changed")


def _exact_bytes(value: object, expected_length: int) -> bytes:
    if type(value) is not bytes or len(value) != expected_length:
        raise Day1BMetadataFramingError(
            f"Day 1B metadata payload must contain exactly {expected_length} bytes"
        )
    return value


@dataclass(frozen=True, slots=True)
class Day1BColumnIndexSynchronizationEntry:
    """One 64-byte patch or full-sync ColumnIndex synchronization entry."""

    version_ordinal: int
    window_index: int
    component_ordinal: int
    storage_object_ordinal: int
    lane_ordinal: int
    logical_row: int
    global_column_index: int
    entry_kind: str

    def __post_init__(self) -> None:
        _strict_unsigned(self.version_ordinal, 64, "version ordinal")
        _strict_unsigned(self.window_index, 64, "window index")
        _strict_unsigned(self.component_ordinal, 32, "component ordinal")
        _strict_unsigned(self.storage_object_ordinal, 32, "storage object ordinal")
        _strict_unsigned(self.lane_ordinal, 32, "lane ordinal")
        _strict_unsigned(self.logical_row, 32, "logical row")
        _strict_signed_64(self.global_column_index, "global column index")
        if self.entry_kind not in _ENTRY_KIND_TO_CODE:
            raise Day1BMetadataFramingError("column-index entry kind must be patch or full-sync")

    def to_bytes(self) -> bytes:
        return _COLUMN_INDEX_STRUCT.pack(
            *_header(
                _COLUMN_INDEX_RECORD_KIND,
                DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES,
            ),
            self.version_ordinal,
            self.window_index,
            self.component_ordinal,
            self.storage_object_ordinal,
            self.lane_ordinal,
            self.logical_row,
            self.global_column_index,
            _ENTRY_KIND_TO_CODE[self.entry_kind],
            b"\0" * 7,
        )

    @classmethod
    def from_bytes(cls, value: object) -> Day1BColumnIndexSynchronizationEntry:
        fields = _COLUMN_INDEX_STRUCT.unpack(
            _exact_bytes(value, DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES)
        )
        _validate_header(
            magic=fields[0],
            record_kind=fields[1],
            flags=fields[2],
            schema_version=fields[3],
            byte_count=fields[4],
            expected_record_kind=_COLUMN_INDEX_RECORD_KIND,
            expected_byte_count=DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES,
        )
        if fields[-1] != b"\0" * 7:
            raise Day1BMetadataFramingError("column-index metadata reserved bytes must be zero")
        entry_kind = _CODE_TO_ENTRY_KIND.get(fields[-2])
        if entry_kind is None:
            raise Day1BMetadataFramingError("column-index entry kind code changed")
        return cls(
            version_ordinal=fields[5],
            window_index=fields[6],
            component_ordinal=fields[7],
            storage_object_ordinal=fields[8],
            lane_ordinal=fields[9],
            logical_row=fields[10],
            global_column_index=fields[11],
            entry_kind=entry_kind,
        )


@dataclass(frozen=True, slots=True)
class Day1BUpdateVersionPlanMetadata:
    """One 144-byte publication record for an actual version transition."""

    window_index: int
    version_ordinal: int
    accepted_group_start: int
    accepted_group_end: int
    logical_state_sha256: str
    output_plan_sha256: str
    execution_binding_sha256: str

    def __post_init__(self) -> None:
        _strict_unsigned(self.window_index, 64, "window index")
        _strict_unsigned(self.version_ordinal, 64, "version ordinal")
        start = _strict_unsigned(
            self.accepted_group_start,
            64,
            "accepted-group start",
        )
        end = _strict_unsigned(self.accepted_group_end, 64, "accepted-group end")
        if end <= start:
            raise Day1BMetadataFramingError("update-version accepted-group range must be nonempty")
        _digest_bytes(self.logical_state_sha256, "logical-state digest")
        _digest_bytes(self.output_plan_sha256, "output-plan digest")
        _digest_bytes(self.execution_binding_sha256, "execution-binding digest")

    def to_bytes(self) -> bytes:
        return _UPDATE_VERSION_STRUCT.pack(
            *_header(
                _UPDATE_VERSION_RECORD_KIND,
                DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES,
            ),
            self.window_index,
            self.version_ordinal,
            self.accepted_group_start,
            self.accepted_group_end,
            _digest_bytes(self.logical_state_sha256, "logical-state digest"),
            _digest_bytes(self.output_plan_sha256, "output-plan digest"),
            _digest_bytes(
                self.execution_binding_sha256,
                "execution-binding digest",
            ),
        )

    @classmethod
    def from_bytes(cls, value: object) -> Day1BUpdateVersionPlanMetadata:
        fields = _UPDATE_VERSION_STRUCT.unpack(
            _exact_bytes(value, DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES)
        )
        _validate_header(
            magic=fields[0],
            record_kind=fields[1],
            flags=fields[2],
            schema_version=fields[3],
            byte_count=fields[4],
            expected_record_kind=_UPDATE_VERSION_RECORD_KIND,
            expected_byte_count=DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES,
        )
        return cls(
            window_index=fields[5],
            version_ordinal=fields[6],
            accepted_group_start=fields[7],
            accepted_group_end=fields[8],
            logical_state_sha256=fields[9].hex(),
            output_plan_sha256=fields[10].hex(),
            execution_binding_sha256=fields[11].hex(),
        )


@dataclass(frozen=True, slots=True)
class Day1BQueryVersionPlanMetadata:
    """One 136-byte version/plan binding for one logical query."""

    window_index: int
    global_query_ordinal: int
    version_ordinal: int
    query_vector_sha256: str
    output_plan_sha256: str
    execution_binding_sha256: str

    def __post_init__(self) -> None:
        _strict_unsigned(self.window_index, 64, "window index")
        _strict_unsigned(self.global_query_ordinal, 64, "global query ordinal")
        _strict_unsigned(self.version_ordinal, 64, "version ordinal")
        _digest_bytes(self.query_vector_sha256, "query-vector digest")
        _digest_bytes(self.output_plan_sha256, "output-plan digest")
        _digest_bytes(self.execution_binding_sha256, "execution-binding digest")

    def to_bytes(self) -> bytes:
        return _QUERY_VERSION_STRUCT.pack(
            *_header(
                _QUERY_VERSION_RECORD_KIND,
                DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES,
            ),
            self.window_index,
            self.global_query_ordinal,
            self.version_ordinal,
            _digest_bytes(self.query_vector_sha256, "query-vector digest"),
            _digest_bytes(self.output_plan_sha256, "output-plan digest"),
            _digest_bytes(
                self.execution_binding_sha256,
                "execution-binding digest",
            ),
        )

    @classmethod
    def from_bytes(cls, value: object) -> Day1BQueryVersionPlanMetadata:
        fields = _QUERY_VERSION_STRUCT.unpack(
            _exact_bytes(value, DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES)
        )
        _validate_header(
            magic=fields[0],
            record_kind=fields[1],
            flags=fields[2],
            schema_version=fields[3],
            byte_count=fields[4],
            expected_record_kind=_QUERY_VERSION_RECORD_KIND,
            expected_byte_count=DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES,
        )
        return cls(
            window_index=fields[5],
            global_query_ordinal=fields[6],
            version_ordinal=fields[7],
            query_vector_sha256=fields[8].hex(),
            output_plan_sha256=fields[9].hex(),
            execution_binding_sha256=fields[10].hex(),
        )


def day1b_metadata_size_class_document(category: str) -> dict[str, object]:
    """Return the canonical size-class descriptor for one metadata category."""

    facts = {
        _COLUMN_INDEX_CATEGORY: (
            "update",
            "column-index-synchronization",
            _COLUMN_INDEX_RECORD_KIND,
            DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES,
        ),
        _UPDATE_VERSION_CATEGORY: (
            "update",
            "update-version-plan",
            _UPDATE_VERSION_RECORD_KIND,
            DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES,
        ),
        _QUERY_VERSION_CATEGORY: (
            "query",
            "query-version-plan",
            _QUERY_VERSION_RECORD_KIND,
            DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES,
        ),
    }
    if type(category) is not str or category not in facts:
        raise Day1BMetadataFramingError(
            "metadata size class requires one frozen Day 1B metadata category"
        )
    transaction, record_kind, record_kind_code, byte_count = facts[category]
    return {
        "binary_framing_schema": DAY1B_METADATA_FRAMING_SCHEMA,
        "category": category,
        "record_kind": record_kind,
        "record_kind_code": record_kind_code,
        "schema_version": DAY1B_METADATA_SIZE_CLASS_SCHEMA,
        "serialized_byte_count": byte_count,
        "transaction": transaction,
    }


def day1b_metadata_size_class_sha256(category: str) -> str:
    document = day1b_metadata_size_class_document(category)
    rendered = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256((rendered + "\n").encode("ascii")).hexdigest()


__all__ = (
    "DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES",
    "DAY1B_FIXED_WIDTH_METADATA_CATEGORIES",
    "DAY1B_METADATA_BINARY_SCHEMA_VERSION",
    "DAY1B_METADATA_FRAMING_SCHEMA",
    "DAY1B_METADATA_MAGIC",
    "DAY1B_METADATA_SIZE_CLASS_SCHEMA",
    "DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES",
    "DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES",
    "Day1BColumnIndexSynchronizationEntry",
    "Day1BMetadataFramingError",
    "Day1BQueryVersionPlanMetadata",
    "Day1BUpdateVersionPlanMetadata",
    "day1b_metadata_size_class_document",
    "day1b_metadata_size_class_sha256",
)
