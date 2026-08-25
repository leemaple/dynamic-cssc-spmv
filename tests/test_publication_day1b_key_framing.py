from __future__ import annotations

import hashlib

import pytest

from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
    DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES,
    DAY1B_COMBINED_EVALUATION_KEY_MAGIC,
    Day1BCombinedEvaluationKeyFrame,
    Day1BCombinedEvaluationKeyFrameStreamValidator,
    Day1BCombinedEvaluationKeyFramingError,
    day1b_combined_evaluation_key_size_class_document,
    day1b_combined_evaluation_key_size_class_sha256,
)

_ROTATION = b"rotation-key-inventory\x00payload"
_EVAL_MULT = b"eval-mult-key-set\x00payload"


def _frame() -> Day1BCombinedEvaluationKeyFrame:
    return Day1BCombinedEvaluationKeyFrame(
        rotation_key_inventory=_ROTATION,
        eval_mult_keys=_EVAL_MULT,
    )


def _open(payload: bytes) -> Day1BCombinedEvaluationKeyFrame:
    return Day1BCombinedEvaluationKeyFrame.from_bytes(
        payload,
        expected_rotation_key_inventory_bytes=len(_ROTATION),
        expected_eval_mult_key_bytes=len(_EVAL_MULT),
    )


def _size_class() -> dict[str, object]:
    return day1b_combined_evaluation_key_size_class_document(
        day2_outer_archive_sha256="a" * 64,
        serialized_object_size_profile_sha256="b" * 64,
        serialized_rotation_key_inventory_bytes=len(_ROTATION),
        serialized_eval_mult_key_bytes=len(_EVAL_MULT),
    )


def test_combined_key_frame_round_trip_has_exact_layout() -> None:
    frame = _frame()
    payload = frame.to_bytes()

    assert payload[:8] == DAY1B_COMBINED_EVALUATION_KEY_MAGIC
    assert int.from_bytes(payload[8:16], "big") == len(_ROTATION)
    assert payload[16:48] == hashlib.sha256(_ROTATION).digest()
    assert int.from_bytes(payload[48:56], "big") == len(_EVAL_MULT)
    assert payload[56:88] == hashlib.sha256(_EVAL_MULT).digest()
    assert payload[88 : 88 + len(_ROTATION)] == _ROTATION
    assert payload[88 + len(_ROTATION) :] == _EVAL_MULT
    assert len(payload) == (
        DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES + len(_ROTATION) + len(_EVAL_MULT)
    )
    assert _open(payload) == frame
    assert _open(payload).to_bytes() == payload


def test_combined_frame_contains_only_the_two_frozen_segments() -> None:
    payload = _frame().to_bytes()

    assert payload[DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES:] == (_ROTATION + _EVAL_MULT)
    assert b"crypto-context" not in payload
    assert b"public-key" not in payload
    assert b"dynamic-cssc-openfhe-key-bundle-v1" not in payload


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("rotation_key_inventory", b""),
        ("eval_mult_keys", b""),
        ("rotation_key_inventory", bytearray(b"rotation")),
        ("eval_mult_keys", memoryview(b"mult")),
    ),
)
def test_combined_frame_rejects_empty_or_nonexact_segments(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "rotation_key_inventory": _ROTATION,
        "eval_mult_keys": _EVAL_MULT,
    }
    values[field] = value

    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="nonempty bytes payload",
    ):
        Day1BCombinedEvaluationKeyFrame(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("magic", "magic changed"),
        ("rotation-length", "segment length differs"),
        ("eval-length", "segment length differs"),
        ("rotation-digest", "rotation segment digest"),
        ("eval-digest", "eval-mult segment digest"),
        ("missing", "missing or trailing"),
        ("trailing", "missing or trailing"),
    ),
)
def test_combined_frame_parser_fails_closed_on_tampering(
    mutation: str,
    message: str,
) -> None:
    payload = bytearray(_frame().to_bytes())
    if mutation == "magic":
        payload[0] ^= 1
    elif mutation == "rotation-length":
        payload[15] += 1
    elif mutation == "eval-length":
        payload[55] += 1
    elif mutation == "rotation-digest":
        payload[16] ^= 1
    elif mutation == "eval-digest":
        payload[56] ^= 1
    elif mutation == "missing":
        payload.pop()
    else:
        payload.append(0)

    with pytest.raises(Day1BCombinedEvaluationKeyFramingError, match=message):
        _open(bytes(payload))


def test_combined_frame_parser_requires_exact_day2_lengths_and_bytes_type() -> None:
    payload = _frame().to_bytes()

    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="segment length differs",
    ):
        Day1BCombinedEvaluationKeyFrame.from_bytes(
            payload,
            expected_rotation_key_inventory_bytes=len(_ROTATION) + 1,
            expected_eval_mult_key_bytes=len(_EVAL_MULT),
        )
    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="payload must be exact bytes",
    ):
        Day1BCombinedEvaluationKeyFrame.from_bytes(
            bytearray(payload),
            expected_rotation_key_inventory_bytes=len(_ROTATION),
            expected_eval_mult_key_bytes=len(_EVAL_MULT),
        )
    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="positive uint64",
    ):
        Day1BCombinedEvaluationKeyFrame.from_bytes(
            payload,
            expected_rotation_key_inventory_bytes=True,
            expected_eval_mult_key_bytes=len(_EVAL_MULT),
        )


def test_combined_frame_stream_validator_accepts_arbitrary_chunk_boundaries() -> None:
    payload = _frame().to_bytes()
    validator = Day1BCombinedEvaluationKeyFrameStreamValidator(
        expected_rotation_key_inventory_bytes=len(_ROTATION),
        expected_eval_mult_key_bytes=len(_EVAL_MULT),
    )
    position = 0
    chunk_sizes = (1, 7, 33, 2, 49, 5, 11)
    chunk_index = 0
    while position < len(payload):
        end = min(len(payload), position + chunk_sizes[chunk_index % len(chunk_sizes)])
        validator.accept(memoryview(payload)[position:end])
        position = end
        chunk_index += 1

    validator.finish()


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("header", "magic changed"),
        ("rotation", "rotation segment digest changed"),
        ("eval-mult", "eval-mult segment digest changed"),
        ("missing", "missing segment bytes"),
        ("trailing", "trailing bytes"),
    ),
)
def test_combined_frame_stream_validator_fails_closed(
    mutation: str,
    message: str,
) -> None:
    payload = bytearray(_frame().to_bytes())
    if mutation == "header":
        payload[0] ^= 1
    elif mutation == "rotation":
        payload[88] ^= 1
    elif mutation == "eval-mult":
        payload[88 + len(_ROTATION)] ^= 1
    elif mutation == "missing":
        payload.pop()
    else:
        payload.append(0)
    validator = Day1BCombinedEvaluationKeyFrameStreamValidator(
        expected_rotation_key_inventory_bytes=len(_ROTATION),
        expected_eval_mult_key_bytes=len(_EVAL_MULT),
    )

    with pytest.raises(Day1BCombinedEvaluationKeyFramingError, match=message):
        validator.accept(bytes(payload))
        validator.finish()


def test_old_context_and_public_key_bundle_is_not_a_formal_key_frame() -> None:
    old_bundle = (
        b"dynamic-cssc-openfhe-key-bundle-v1\x00"
        b"\x00\x0ecrypto-context"
        b"\x00\x00\x00\x00\x00\x00\x00\x07context"
        b"\x00\x0apublic-key"
    ).ljust(88 + len(_ROTATION) + len(_EVAL_MULT), b"\x00")

    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="magic changed",
    ):
        _open(old_bundle)


def test_combined_key_size_class_binds_day2_roots_lengths_and_taxonomy() -> None:
    document = _size_class()

    assert document == {
        "binary_framing_schema": DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
        "category": DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
        "day2_outer_archive_sha256": "a" * 64,
        "eval_mult_key_segment_bytes": len(_EVAL_MULT),
        "frame_header_bytes": DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES,
        "rotation_key_inventory_segment_bytes": len(_ROTATION),
        "schema_version": ("dynamic-cssc-publication-day1b-combined-evaluation-key-size-class-v1"),
        "segment_order": ["rotation-key-inventory", "eval-mult-keys"],
        "serialized_byte_count": (
            DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES + len(_ROTATION) + len(_EVAL_MULT)
        ),
        "serialized_object_size_profile_sha256": "b" * 64,
        "transaction": "one-time",
    }
    digest = day1b_combined_evaluation_key_size_class_sha256(
        day2_outer_archive_sha256="a" * 64,
        serialized_object_size_profile_sha256="b" * 64,
        serialized_rotation_key_inventory_bytes=len(_ROTATION),
        serialized_eval_mult_key_bytes=len(_EVAL_MULT),
    )
    changed_profile_digest = day1b_combined_evaluation_key_size_class_sha256(
        day2_outer_archive_sha256="a" * 64,
        serialized_object_size_profile_sha256="c" * 64,
        serialized_rotation_key_inventory_bytes=len(_ROTATION),
        serialized_eval_mult_key_bytes=len(_EVAL_MULT),
    )
    assert len(digest) == 64
    assert digest != changed_profile_digest


def test_equal_length_key_pairs_share_size_class_but_not_frame_identity() -> None:
    first = _frame().to_bytes()
    second = Day1BCombinedEvaluationKeyFrame(
        rotation_key_inventory=b"R" * len(_ROTATION),
        eval_mult_keys=b"M" * len(_EVAL_MULT),
    ).to_bytes()

    assert len(first) == len(second) == _size_class()["serialized_byte_count"]
    assert first != second
    assert hashlib.sha256(first).digest() != hashlib.sha256(second).digest()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("day2_outer_archive_sha256", "A" * 64, "lowercase SHA-256"),
        ("serialized_object_size_profile_sha256", "b" * 63, "lowercase SHA-256"),
        ("serialized_rotation_key_inventory_bytes", 0, "positive uint64"),
        ("serialized_eval_mult_key_bytes", True, "positive uint64"),
        ("serialized_eval_mult_key_bytes", 1 << 64, "positive uint64"),
    ),
)
def test_combined_key_size_class_rejects_noncanonical_authority(
    field: str,
    value: object,
    message: str,
) -> None:
    values: dict[str, object] = {
        "day2_outer_archive_sha256": "a" * 64,
        "serialized_object_size_profile_sha256": "b" * 64,
        "serialized_rotation_key_inventory_bytes": len(_ROTATION),
        "serialized_eval_mult_key_bytes": len(_EVAL_MULT),
    }
    values[field] = value

    with pytest.raises(Day1BCombinedEvaluationKeyFramingError, match=message):
        day1b_combined_evaluation_key_size_class_document(  # type: ignore[arg-type]
            **values
        )


def test_combined_key_size_class_rejects_uint64_total_overflow() -> None:
    with pytest.raises(
        Day1BCombinedEvaluationKeyFramingError,
        match="size class exceeds uint64",
    ):
        day1b_combined_evaluation_key_size_class_document(
            day2_outer_archive_sha256="a" * 64,
            serialized_object_size_profile_sha256="b" * 64,
            serialized_rotation_key_inventory_bytes=(1 << 64) - 1,
            serialized_eval_mult_key_bytes=1,
        )
