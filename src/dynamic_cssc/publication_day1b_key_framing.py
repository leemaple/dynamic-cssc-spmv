"""Canonical Day 1B rotation-plus-eval-mult key framing.

The publication taxonomy has one one-time evaluation-key category, while the
Day 2 authority measures two serialized OpenFHE payloads separately: the full
rotation-key inventory and the evaluation-multiplication key set.  This module
places exactly those two payloads behind one small framing interface.  Crypto
contexts, public keys, labels, and optional third segments are deliberately not
part of the frame.
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

DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-combined-evaluation-key-framing-v1"
)
DAY1B_COMBINED_EVALUATION_KEY_SIZE_CLASS_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-combined-evaluation-key-size-class-v1"
)
DAY1B_COMBINED_EVALUATION_KEY_MAGIC: Final = b"D1BKEY01"
DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES: Final = 88
DAY1B_COMBINED_EVALUATION_KEY_CATEGORY: Final = "one-time-evaluation-key-material"

_TRANSACTION = "one-time"
_ROTATION_SEGMENT = "rotation-key-inventory"
_EVAL_MULT_SEGMENT = "eval-mult-keys"
_UINT64_MAX = (1 << 64) - 1
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEADER = struct.Struct(">8sQ32sQ32s")

if _HEADER.size != DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES:
    raise AssertionError("Day 1B combined evaluation-key header layout drifted")
if tuple(
    item
    for item in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    if item[0] == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY
) != ((DAY1B_COMBINED_EVALUATION_KEY_CATEGORY, _TRANSACTION),):
    raise AssertionError("Day 1B combined evaluation-key taxonomy drifted")


class Day1BCombinedEvaluationKeyFramingError(ValueError):
    """Raised when one key frame or size class is not canonical."""


def _strict_segment(value: object, field: str) -> bytes:
    if type(value) is not bytes or not value or len(value) > _UINT64_MAX:
        raise Day1BCombinedEvaluationKeyFramingError(
            f"{field} must be one nonempty bytes payload with uint64 length"
        )
    return value


def _strict_segment_bytes(value: object, field: str) -> int:
    if type(value) is not int or not 0 < value <= _UINT64_MAX:
        raise Day1BCombinedEvaluationKeyFramingError(
            f"{field} must be one exact positive uint64 byte count"
        )
    return value


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BCombinedEvaluationKeyFramingError(f"{field} must be an exact lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class Day1BCombinedEvaluationKeyFrame:
    """The exact rotation-inventory and eval-mult payload pair."""

    rotation_key_inventory: bytes
    eval_mult_keys: bytes

    def __post_init__(self) -> None:
        _strict_segment(
            self.rotation_key_inventory,
            "rotation-key inventory segment",
        )
        _strict_segment(self.eval_mult_keys, "eval-mult key segment")
        if (
            DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES
            + len(self.rotation_key_inventory)
            + len(self.eval_mult_keys)
            > _UINT64_MAX
        ):
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key frame exceeds uint64 length"
            )

    def to_bytes(self) -> bytes:
        rotation_digest = hashlib.sha256(self.rotation_key_inventory).digest()
        eval_mult_digest = hashlib.sha256(self.eval_mult_keys).digest()
        return b"".join(
            (
                _HEADER.pack(
                    DAY1B_COMBINED_EVALUATION_KEY_MAGIC,
                    len(self.rotation_key_inventory),
                    rotation_digest,
                    len(self.eval_mult_keys),
                    eval_mult_digest,
                ),
                self.rotation_key_inventory,
                self.eval_mult_keys,
            )
        )

    @classmethod
    def from_bytes(
        cls,
        value: object,
        *,
        expected_rotation_key_inventory_bytes: int,
        expected_eval_mult_key_bytes: int,
    ) -> Day1BCombinedEvaluationKeyFrame:
        """Open one frame only under exact Day 2 segment lengths."""

        rotation_bytes = _strict_segment_bytes(
            expected_rotation_key_inventory_bytes,
            "expected rotation-key inventory bytes",
        )
        eval_mult_bytes = _strict_segment_bytes(
            expected_eval_mult_key_bytes,
            "expected eval-mult key bytes",
        )
        if (
            DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES + rotation_bytes + eval_mult_bytes
            > _UINT64_MAX
        ):
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key expected length exceeds uint64"
            )
        if type(value) is not bytes:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key payload must be exact bytes"
            )
        if len(value) < _HEADER.size:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key payload is shorter than its exact header"
            )
        fields = _HEADER.unpack(value[: _HEADER.size])
        if fields[0] != DAY1B_COMBINED_EVALUATION_KEY_MAGIC:
            raise Day1BCombinedEvaluationKeyFramingError("combined evaluation-key magic changed")
        if fields[1] != rotation_bytes or fields[3] != eval_mult_bytes:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key segment length differs from Day 2 authority"
            )
        expected_total = _HEADER.size + rotation_bytes + eval_mult_bytes
        if len(value) != expected_total:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key payload has missing or trailing bytes"
            )
        rotation_end = _HEADER.size + rotation_bytes
        rotation_payload = value[_HEADER.size : rotation_end]
        eval_mult_payload = value[rotation_end:]
        if hashlib.sha256(rotation_payload).digest() != fields[2]:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key rotation segment digest changed"
            )
        if hashlib.sha256(eval_mult_payload).digest() != fields[4]:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key eval-mult segment digest changed"
            )
        result = cls(
            rotation_key_inventory=rotation_payload,
            eval_mult_keys=eval_mult_payload,
        )
        if result.to_bytes() != value:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key frame is not its exact typed projection"
            )
        return result


@dataclass(frozen=True, slots=True)
class Day1BCombinedEvaluationKeyFrameStreamReceipt:
    rotation_key_inventory_bytes: int
    rotation_key_inventory_sha256: str
    eval_mult_key_bytes: int
    eval_mult_key_sha256: str


class Day1BCombinedEvaluationKeyFrameStreamValidator:
    """Validate one combined key frame without retaining its binary payload."""

    __slots__ = (
        "_eval_mult_digest",
        "_eval_mult_hasher",
        "_eval_mult_remaining",
        "_expected_eval_mult_bytes",
        "_expected_rotation_bytes",
        "_expected_total_bytes",
        "_header",
        "_rotation_digest",
        "_rotation_hasher",
        "_rotation_remaining",
        "_total_bytes",
    )

    def __init__(
        self,
        *,
        expected_rotation_key_inventory_bytes: int,
        expected_eval_mult_key_bytes: int,
    ) -> None:
        self._expected_rotation_bytes = _strict_segment_bytes(
            expected_rotation_key_inventory_bytes,
            "expected rotation-key inventory bytes",
        )
        self._expected_eval_mult_bytes = _strict_segment_bytes(
            expected_eval_mult_key_bytes,
            "expected eval-mult key bytes",
        )
        self._expected_total_bytes = (
            DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES
            + self._expected_rotation_bytes
            + self._expected_eval_mult_bytes
        )
        if self._expected_total_bytes > _UINT64_MAX:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key expected length exceeds uint64"
            )
        self._rotation_remaining = self._expected_rotation_bytes
        self._eval_mult_remaining = self._expected_eval_mult_bytes
        self._total_bytes = 0
        self._header = bytearray()
        self._rotation_digest: bytes | None = None
        self._eval_mult_digest: bytes | None = None
        self._rotation_hasher = hashlib.sha256()
        self._eval_mult_hasher = hashlib.sha256()

    def accept(self, value: bytes | memoryview) -> None:
        """Consume the next nonempty contiguous frame fragment."""

        if type(value) is bytes:
            fragment = memoryview(value)
        elif type(value) is memoryview:
            fragment = value
        else:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream fragment must be exact bytes"
            )
        if not fragment:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream fragment must be nonempty"
            )
        position = 0
        self._total_bytes += len(fragment)
        if self._total_bytes > self._expected_total_bytes:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream has trailing bytes"
            )

        if len(self._header) < _HEADER.size:
            take = min(_HEADER.size - len(self._header), len(fragment))
            self._header.extend(fragment[:take])
            position += take
            if len(self._header) == _HEADER.size:
                fields = _HEADER.unpack(bytes(self._header))
                if fields[0] != DAY1B_COMBINED_EVALUATION_KEY_MAGIC:
                    raise Day1BCombinedEvaluationKeyFramingError(
                        "combined evaluation-key magic changed"
                    )
                if (
                    fields[1] != self._expected_rotation_bytes
                    or fields[3] != self._expected_eval_mult_bytes
                ):
                    raise Day1BCombinedEvaluationKeyFramingError(
                        "combined evaluation-key segment length differs from Day 2 authority"
                    )
                self._rotation_digest = fields[2]
                self._eval_mult_digest = fields[4]

        if position < len(fragment) and self._rotation_remaining:
            take = min(self._rotation_remaining, len(fragment) - position)
            self._rotation_hasher.update(fragment[position : position + take])
            self._rotation_remaining -= take
            position += take
        if position < len(fragment) and self._eval_mult_remaining:
            take = min(self._eval_mult_remaining, len(fragment) - position)
            self._eval_mult_hasher.update(fragment[position : position + take])
            self._eval_mult_remaining -= take
            position += take
        if position != len(fragment):
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream has trailing bytes"
            )

    def finish(self) -> Day1BCombinedEvaluationKeyFrameStreamReceipt:
        """Require the exact header, lengths, and segment digests."""

        if len(self._header) != _HEADER.size:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream is shorter than its exact header"
            )
        if self._rotation_remaining or self._eval_mult_remaining:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key stream has missing segment bytes"
            )
        assert self._rotation_digest is not None and self._eval_mult_digest is not None
        if self._rotation_hasher.digest() != self._rotation_digest:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key rotation segment digest changed"
            )
        if self._eval_mult_hasher.digest() != self._eval_mult_digest:
            raise Day1BCombinedEvaluationKeyFramingError(
                "combined evaluation-key eval-mult segment digest changed"
            )
        return Day1BCombinedEvaluationKeyFrameStreamReceipt(
            rotation_key_inventory_bytes=self._expected_rotation_bytes,
            rotation_key_inventory_sha256=self._rotation_hasher.hexdigest(),
            eval_mult_key_bytes=self._expected_eval_mult_bytes,
            eval_mult_key_sha256=self._eval_mult_hasher.hexdigest(),
        )


def day1b_combined_evaluation_key_size_class_document(
    *,
    day2_outer_archive_sha256: str,
    serialized_object_size_profile_sha256: str,
    serialized_rotation_key_inventory_bytes: int,
    serialized_eval_mult_key_bytes: int,
) -> dict[str, object]:
    """Bind the combined frame length to one exact Day 2 size authority."""

    archive_sha256 = _require_sha256(
        day2_outer_archive_sha256,
        "Day 2 outer archive digest",
    )
    profile_sha256 = _require_sha256(
        serialized_object_size_profile_sha256,
        "serialized-object size-profile digest",
    )
    rotation_bytes = _strict_segment_bytes(
        serialized_rotation_key_inventory_bytes,
        "serialized rotation-key inventory bytes",
    )
    eval_mult_bytes = _strict_segment_bytes(
        serialized_eval_mult_key_bytes,
        "serialized eval-mult key bytes",
    )
    serialized_byte_count = (
        DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES + rotation_bytes + eval_mult_bytes
    )
    if serialized_byte_count > _UINT64_MAX:
        raise Day1BCombinedEvaluationKeyFramingError(
            "combined evaluation-key size class exceeds uint64 length"
        )
    return {
        "binary_framing_schema": DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA,
        "category": DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
        "day2_outer_archive_sha256": archive_sha256,
        "eval_mult_key_segment_bytes": eval_mult_bytes,
        "frame_header_bytes": DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES,
        "rotation_key_inventory_segment_bytes": rotation_bytes,
        "schema_version": DAY1B_COMBINED_EVALUATION_KEY_SIZE_CLASS_SCHEMA,
        "segment_order": [_ROTATION_SEGMENT, _EVAL_MULT_SEGMENT],
        "serialized_byte_count": serialized_byte_count,
        "serialized_object_size_profile_sha256": profile_sha256,
        "transaction": _TRANSACTION,
    }


def day1b_combined_evaluation_key_size_class_sha256(
    *,
    day2_outer_archive_sha256: str,
    serialized_object_size_profile_sha256: str,
    serialized_rotation_key_inventory_bytes: int,
    serialized_eval_mult_key_bytes: int,
) -> str:
    document = day1b_combined_evaluation_key_size_class_document(
        day2_outer_archive_sha256=day2_outer_archive_sha256,
        serialized_object_size_profile_sha256=(serialized_object_size_profile_sha256),
        serialized_rotation_key_inventory_bytes=(serialized_rotation_key_inventory_bytes),
        serialized_eval_mult_key_bytes=serialized_eval_mult_key_bytes,
    )
    rendered = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256((rendered + "\n").encode("ascii")).hexdigest()


__all__ = (
    "DAY1B_COMBINED_EVALUATION_KEY_CATEGORY",
    "DAY1B_COMBINED_EVALUATION_KEY_FRAMING_SCHEMA",
    "DAY1B_COMBINED_EVALUATION_KEY_HEADER_BYTES",
    "DAY1B_COMBINED_EVALUATION_KEY_MAGIC",
    "DAY1B_COMBINED_EVALUATION_KEY_SIZE_CLASS_SCHEMA",
    "Day1BCombinedEvaluationKeyFrame",
    "Day1BCombinedEvaluationKeyFrameStreamReceipt",
    "Day1BCombinedEvaluationKeyFrameStreamValidator",
    "Day1BCombinedEvaluationKeyFramingError",
    "day1b_combined_evaluation_key_size_class_document",
    "day1b_combined_evaluation_key_size_class_sha256",
)
