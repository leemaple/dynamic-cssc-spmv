"""Canonical formal-watcher receipt inspection.

The GitHub adapter produces these receipts, the campaign controller binds them
to one live outcome, and the timing inspector later replays them from retained
evidence.  Keeping the byte grammar here prevents those three callers from
accepting different cancellation or terminal projections.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from dynamic_cssc.followup_performance_campaign import (
    FOLLOWUP_PROVIDER_FAILURE_CLASSES,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    _canonical_json_bytes,
    _parse_ascii_json,
)

__all__ = (
    "FollowupFormalWatcherReceipt",
    "FollowupFormalWatcherReceiptError",
    "inspect_followup_formal_watcher_receipt",
)

_SCHEMA = "dynamic-cssc-followup-performance-watcher-receipt-v3"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARTIFACT_NAME = re.compile(
    r"followup-performance-v1-[a-z0-9][a-z0-9._-]{0,254}\Z"
)
_PROVIDER_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_COMMON_FIELDS = frozenset(
    {
        "artifacts_api_sha256",
        "authority",
        "campaign_id",
        "cancellation_ledger",
        "decision",
        "formal_unit_ordinal",
        "jobs_api_sha256",
        "provider_run_id",
        "publication_evidence_admitted",
        "run_api_sha256",
        "schema_version",
        "unit_attempt_ordinal",
        "watcher_session_sha256",
    }
)
_SUCCESS_FIELDS = _COMMON_FIELDS | {
    "artifact_id",
    "artifact_name",
    "artifact_provider_digest",
    "critical_path_seconds",
    "guard_receipt_bytes_sha256",
    "reservation_minutes",
    "unit_output_envelope_sha256",
}
_TERMINAL_FIELDS = _COMMON_FIELDS | {
    "no_go_reason_or_null",
    "provider_failure_class_or_null",
    "provider_failure_evidence_sha256_or_null",
}
_CANCELLATION_FIELDS = frozenset(
    {
        "ack_to_watch_decision_seconds",
        "cancel_request_utc",
        "controller_detection_utc",
        "final_conclusion",
        "provider_api_ack_utc",
        "provider_terminal_updated_utc",
        "request_to_ack_seconds",
        "threshold_utc",
        "watch_decided_utc",
    }
)
_NO_GO_REASONS = frozenset({"budget-exhausted", "scientific-or-guard-failure"})


class FollowupFormalWatcherReceiptError(FollowupContractError):
    """One formal watcher receipt is malformed or semantically inconsistent."""


@dataclass(frozen=True, slots=True)
class FollowupFormalWatcherReceipt:
    document: dict[str, object]
    document_bytes: bytes
    sha256: str
    cancellation_ledger: dict[str, object] | None


def _sha256(value: object, *, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise FollowupFormalWatcherReceiptError(f"{field} is not SHA-256")
    return value


def _positive_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise FollowupFormalWatcherReceiptError(f"{field} is not positive")
    return value


def _nonnegative_integer(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise FollowupFormalWatcherReceiptError(f"{field} is not nonnegative")
    return value


def _provider_timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or _PROVIDER_TIMESTAMP.fullmatch(value) is None:
        raise FollowupFormalWatcherReceiptError(
            f"{field} is not provider UTC seconds"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:  # pragma: no cover - regex narrows the syntax
        raise FollowupFormalWatcherReceiptError(
            f"{field} is not a real provider timestamp"
        ) from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise FollowupFormalWatcherReceiptError(
            f"{field} is not canonical provider UTC"
        )
    return parsed


def _controller_timestamp(value: object, *, field: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise FollowupFormalWatcherReceiptError(f"{field} is not controller UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise FollowupFormalWatcherReceiptError(
            f"{field} is not controller UTC"
        ) from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise FollowupFormalWatcherReceiptError(
            f"{field} is not canonical controller UTC"
        )
    return parsed


def _cancellation_ledger(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != _CANCELLATION_FIELDS:
        raise FollowupFormalWatcherReceiptError(
            "formal cancellation ledger field set changed"
        )
    threshold = value["threshold_utc"]
    threshold_timestamp: datetime | None = None
    if threshold is not None:
        threshold_timestamp = _provider_timestamp(
            threshold,
            field="cancellation.threshold_utc",
        )
    detection = _controller_timestamp(
        value["controller_detection_utc"],
        field="cancellation.controller_detection_utc",
    )
    requested = _controller_timestamp(
        value["cancel_request_utc"],
        field="cancellation.cancel_request_utc",
    )
    acknowledged = _controller_timestamp(
        value["provider_api_ack_utc"],
        field="cancellation.provider_api_ack_utc",
    )
    decided = _controller_timestamp(
        value["watch_decided_utc"],
        field="cancellation.watch_decided_utc",
    )
    if not detection <= requested <= acknowledged <= decided:
        raise FollowupFormalWatcherReceiptError(
            "formal cancellation controller clock moved backwards"
        )
    request_to_ack = _nonnegative_integer(
        value["request_to_ack_seconds"],
        field="cancellation.request_to_ack_seconds",
    )
    ack_to_decision = _nonnegative_integer(
        value["ack_to_watch_decision_seconds"],
        field="cancellation.ack_to_watch_decision_seconds",
    )
    if (
        request_to_ack != math.ceil((acknowledged - requested).total_seconds())
        or ack_to_decision != math.ceil((decided - acknowledged).total_seconds())
    ):
        raise FollowupFormalWatcherReceiptError(
            "formal cancellation elapsed arithmetic changed"
        )
    terminal_timestamp = _provider_timestamp(
        value["provider_terminal_updated_utc"],
        field="cancellation.provider_terminal_updated_utc",
    )
    if (
        threshold_timestamp is not None
        and terminal_timestamp < threshold_timestamp
    ):
        raise FollowupFormalWatcherReceiptError(
            "formal cancellation provider terminal update precedes its threshold"
        )
    if type(value["final_conclusion"]) is not str or not value["final_conclusion"]:
        raise FollowupFormalWatcherReceiptError(
            "formal cancellation final conclusion is absent"
        )
    return dict(value)


def inspect_followup_formal_watcher_receipt(
    content: bytes,
) -> FollowupFormalWatcherReceipt:
    """Inspect exact canonical bytes and close every self-contained invariant."""

    try:
        value = _parse_ascii_json(content, label="formal watcher receipt")
    except FollowupContractError as error:
        raise FollowupFormalWatcherReceiptError(
            "formal watcher receipt is not readable JSON"
        ) from error
    if type(value) is not dict or _canonical_json_bytes(value) != content:
        raise FollowupFormalWatcherReceiptError(
            "formal watcher receipt is not one canonical object"
        )
    decision = value.get("decision")
    expected_fields = _SUCCESS_FIELDS if decision == "success" else _TERMINAL_FIELDS
    if set(value) != expected_fields:
        raise FollowupFormalWatcherReceiptError(
            "formal watcher receipt field set changed"
        )
    if (
        value.get("schema_version") != _SCHEMA
        or value.get("authority") is not False
        or value.get("publication_evidence_admitted") is not False
        or decision not in {"success", "provider-failure", "no-go"}
    ):
        raise FollowupFormalWatcherReceiptError(
            "formal watcher receipt authority or decision changed"
        )
    for field in (
        "artifacts_api_sha256",
        "campaign_id",
        "jobs_api_sha256",
        "run_api_sha256",
        "watcher_session_sha256",
    ):
        _sha256(value[field], field=field)
    ordinal = value["formal_unit_ordinal"]
    if type(ordinal) is not int or not 0 <= ordinal < 17:
        raise FollowupFormalWatcherReceiptError(
            "formal watcher unit ordinal is outside 0..16"
        )
    if value["unit_attempt_ordinal"] not in {1, 2}:
        raise FollowupFormalWatcherReceiptError(
            "formal watcher attempt ordinal changed"
        )
    _positive_integer(value["provider_run_id"], field="provider_run_id")
    cancellation = _cancellation_ledger(value["cancellation_ledger"])

    if decision == "success":
        if cancellation is not None:
            raise FollowupFormalWatcherReceiptError(
                "successful formal watcher carries cancellation"
            )
        _positive_integer(value["artifact_id"], field="artifact_id")
        artifact_name = value["artifact_name"]
        if type(artifact_name) is not str or _ARTIFACT_NAME.fullmatch(artifact_name) is None:
            raise FollowupFormalWatcherReceiptError("artifact_name changed")
        provider_digest = value["artifact_provider_digest"]
        if (
            type(provider_digest) is not str
            or _PROVIDER_DIGEST.fullmatch(provider_digest) is None
        ):
            raise FollowupFormalWatcherReceiptError(
                "artifact_provider_digest changed"
            )
        reservation = _positive_integer(
            value["reservation_minutes"], field="reservation_minutes"
        )
        critical = _nonnegative_integer(
            value["critical_path_seconds"], field="critical_path_seconds"
        )
        if reservation > 60 or critical > reservation * 60:
            raise FollowupFormalWatcherReceiptError(
                "successful formal watcher exceeded its reservation"
            )
        _sha256(
            value["guard_receipt_bytes_sha256"],
            field="guard_receipt_bytes_sha256",
        )
        _sha256(
            value["unit_output_envelope_sha256"],
            field="unit_output_envelope_sha256",
        )
    elif decision == "provider-failure":
        if (
            cancellation is not None
            or value["provider_failure_class_or_null"]
            not in FOLLOWUP_PROVIDER_FAILURE_CLASSES
            or value["no_go_reason_or_null"] is not None
        ):
            raise FollowupFormalWatcherReceiptError(
                "provider-failure watcher classification or cancellation changed"
            )
        _sha256(
            value["provider_failure_evidence_sha256_or_null"],
            field="provider_failure_evidence_sha256_or_null",
        )
    else:
        if (
            value["provider_failure_class_or_null"] is not None
            or value["provider_failure_evidence_sha256_or_null"] is not None
            or value["no_go_reason_or_null"] not in _NO_GO_REASONS
            or (
                (value["no_go_reason_or_null"] == "budget-exhausted")
                != (cancellation is not None)
            )
        ):
            raise FollowupFormalWatcherReceiptError(
                "NO-GO watcher reason or cancellation changed"
            )

    return FollowupFormalWatcherReceipt(
        document=value,
        document_bytes=content,
        sha256=hashlib.sha256(content).hexdigest(),
        cancellation_ledger=cancellation,
    )
