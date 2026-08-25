from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.publication_day1b_metadata_framing import (
    DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES,
    DAY1B_METADATA_BINARY_SCHEMA_VERSION,
    DAY1B_METADATA_MAGIC,
    DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES,
    DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES,
    Day1BColumnIndexSynchronizationEntry,
    Day1BMetadataFramingError,
    Day1BQueryVersionPlanMetadata,
    Day1BUpdateVersionPlanMetadata,
    day1b_metadata_size_class_document,
    day1b_metadata_size_class_sha256,
)


def _column_index(
    entry_kind: str = "patch",
) -> Day1BColumnIndexSynchronizationEntry:
    return Day1BColumnIndexSynchronizationEntry(
        version_ordinal=7,
        window_index=11,
        component_ordinal=13,
        storage_object_ordinal=17,
        lane_ordinal=19,
        logical_row=23,
        global_column_index=29,
        entry_kind=entry_kind,
    )


def _update_version() -> Day1BUpdateVersionPlanMetadata:
    return Day1BUpdateVersionPlanMetadata(
        window_index=11,
        version_ordinal=7,
        accepted_group_start=100,
        accepted_group_end=200,
        logical_state_sha256="a" * 64,
        output_plan_sha256="b" * 64,
        execution_binding_sha256="c" * 64,
    )


def _query_version() -> Day1BQueryVersionPlanMetadata:
    return Day1BQueryVersionPlanMetadata(
        window_index=11,
        global_query_ordinal=31,
        version_ordinal=7,
        query_vector_sha256="d" * 64,
        output_plan_sha256="b" * 64,
        execution_binding_sha256="c" * 64,
    )


@pytest.mark.parametrize(
    ("record", "expected_length", "record_kind"),
    (
        (_column_index(), DAY1B_COLUMN_INDEX_SYNCHRONIZATION_BYTES, 1),
        (_update_version(), DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES, 2),
        (_query_version(), DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES, 3),
    ),
)
def test_metadata_records_round_trip_with_exact_header_and_length(
    record: object,
    expected_length: int,
    record_kind: int,
) -> None:
    payload = record.to_bytes()

    assert len(payload) == expected_length
    assert payload[:8] == DAY1B_METADATA_MAGIC
    assert payload[8] == record_kind
    assert payload[9] == 0
    assert int.from_bytes(payload[10:12], "big") == DAY1B_METADATA_BINARY_SCHEMA_VERSION
    assert int.from_bytes(payload[12:16], "big") == expected_length
    assert type(record).from_bytes(payload) == record
    assert type(record).from_bytes(payload).to_bytes() == payload


def test_patch_and_full_sync_share_one_64_byte_size_class() -> None:
    patch = _column_index("patch").to_bytes()
    full_sync = _column_index("full-sync").to_bytes()

    assert len(patch) == len(full_sync) == 64
    assert patch[:56] == full_sync[:56]
    assert patch[56] == 1
    assert full_sync[56] == 2
    assert patch[57:] == full_sync[57:] == b"\0" * 7
    size_class = day1b_metadata_size_class_document("update-column-index-synchronization")
    assert size_class["serialized_byte_count"] == len(patch) == len(full_sync)
    assert "entry_kind" not in size_class


def test_metadata_categories_have_three_distinct_size_classes() -> None:
    categories = (
        "update-column-index-synchronization",
        "update-version-plan-metadata",
        "query-version-plan-metadata",
    )
    documents = tuple(day1b_metadata_size_class_document(item) for item in categories)

    assert tuple(item["serialized_byte_count"] for item in documents) == (64, 144, 136)
    assert tuple(item["record_kind_code"] for item in documents) == (1, 2, 3)
    assert all(
        set(item)
        == {
            "binary_framing_schema",
            "category",
            "record_kind",
            "record_kind_code",
            "schema_version",
            "serialized_byte_count",
        }
        for item in documents
    )
    assert len({day1b_metadata_size_class_sha256(item) for item in categories}) == 3


@pytest.mark.parametrize("cut", (0, 1, 63, 64))
def test_column_index_parser_rejects_truncated_or_extended_payload(cut: int) -> None:
    payload = _column_index().to_bytes()
    changed = payload[:cut] if cut < len(payload) else payload + b"\0"

    with pytest.raises(Day1BMetadataFramingError, match="exactly 64 bytes"):
        Day1BColumnIndexSynchronizationEntry.from_bytes(changed)


@pytest.mark.parametrize(
    ("offset", "replacement", "message"),
    (
        (0, b"X", "magic"),
        (8, b"\x02", "record kind"),
        (9, b"\x01", "flags"),
        (11, b"\x02", "binary schema"),
        (15, b"?", "byte-count header"),
        (57, b"\x01", "reserved bytes"),
    ),
)
def test_column_index_parser_rejects_header_and_reserved_tampering(
    offset: int,
    replacement: bytes,
    message: str,
) -> None:
    payload = bytearray(_column_index().to_bytes())
    payload[offset : offset + 1] = replacement

    with pytest.raises(Day1BMetadataFramingError, match=message):
        Day1BColumnIndexSynchronizationEntry.from_bytes(bytes(payload))


def test_column_index_parser_rejects_unknown_entry_kind_code() -> None:
    payload = bytearray(_column_index().to_bytes())
    payload[56] = 3

    with pytest.raises(Day1BMetadataFramingError, match="entry kind code"):
        Day1BColumnIndexSynchronizationEntry.from_bytes(bytes(payload))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("window_index", True, "unsigned 64-bit"),
        ("component_ordinal", 1 << 32, "unsigned 32-bit"),
        ("global_column_index", 1 << 63, "signed 64-bit"),
        ("entry_kind", "snapshot", "patch or full-sync"),
    ),
)
def test_column_index_constructor_rejects_noncanonical_fields(
    field: str,
    value: object,
    message: str,
) -> None:
    with pytest.raises(Day1BMetadataFramingError, match=message):
        replace(_column_index(), **{field: value})


def test_update_version_requires_actual_nonempty_window_range() -> None:
    with pytest.raises(Day1BMetadataFramingError, match="range must be nonempty"):
        replace(_update_version(), accepted_group_end=100)


@pytest.mark.parametrize(
    ("record", "field"),
    (
        (_update_version(), "logical_state_sha256"),
        (_query_version(), "query_vector_sha256"),
    ),
)
def test_metadata_records_reject_noncanonical_digests(record: object, field: str) -> None:
    with pytest.raises(Day1BMetadataFramingError, match="lowercase SHA-256"):
        replace(record, **{field: "A" * 64})


@pytest.mark.parametrize(
    ("record", "parser", "expected_length"),
    (
        (
            _update_version(),
            Day1BUpdateVersionPlanMetadata.from_bytes,
            DAY1B_UPDATE_VERSION_PLAN_METADATA_BYTES,
        ),
        (
            _query_version(),
            Day1BQueryVersionPlanMetadata.from_bytes,
            DAY1B_QUERY_VERSION_PLAN_METADATA_BYTES,
        ),
    ),
)
def test_version_metadata_parser_rejects_wrong_kind_and_trailing_bytes(
    record: object,
    parser: object,
    expected_length: int,
) -> None:
    payload = bytearray(record.to_bytes())
    payload[8] = 1
    with pytest.raises(Day1BMetadataFramingError, match="record kind"):
        parser(bytes(payload))

    with pytest.raises(
        Day1BMetadataFramingError,
        match=f"exactly {expected_length} bytes",
    ):
        parser(record.to_bytes() + b"\0")


def test_metadata_size_class_rejects_unfrozen_category_and_non_string() -> None:
    with pytest.raises(Day1BMetadataFramingError, match="frozen Day 1B"):
        day1b_metadata_size_class_document("query-result-ciphertexts")
    with pytest.raises(Day1BMetadataFramingError, match="frozen Day 1B"):
        day1b_metadata_size_class_document([])  # type: ignore[arg-type]
