from __future__ import annotations

import json

import pytest

from dynamic_cssc.followup_performance_qualification_binding import (
    FollowupQualificationBindingError,
    build_followup_qualification_run_admission,
    build_followup_qualification_watch_binding,
    inspect_followup_qualification_watch_binding,
)


def _binding():  # type: ignore[no-untyped-def]
    return build_followup_qualification_watch_binding(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=7001,
        watcher_session_sha256="4" * 64,
        workflow_ref=(
            "owner/repository/.github/workflows/"
            "followup-performance-qualification.yml@refs/heads/main"
        ),
    )


def test_qualification_binding_and_admission_are_exact_and_reproducible() -> None:
    binding = _binding()
    reinspected = inspect_followup_qualification_watch_binding(
        binding.document_bytes
    )
    admission = build_followup_qualification_run_admission(
        binding,
        binding_oid="5" * 40,
    )
    repeated = build_followup_qualification_run_admission(
        reinspected,
        binding_oid="5" * 40,
    )

    assert reinspected == binding
    assert repeated == admission
    assert admission.document["provider_run_id"] == 7001
    assert admission.document["watcher_session_sha256"] == "4" * 64


def test_qualification_binding_rejects_noncanonical_duplicate_or_unwatched_state() -> None:
    binding = _binding()
    with pytest.raises(FollowupQualificationBindingError, match="canonical"):
        inspect_followup_qualification_watch_binding(
            json.dumps(binding.document, indent=2).encode("ascii")
        )
    duplicate = binding.document_bytes.replace(
        b'{"authority":false,',
        b'{"authority":false,"authority":false,',
        1,
    )
    with pytest.raises(FollowupQualificationBindingError, match="duplicate"):
        inspect_followup_qualification_watch_binding(duplicate)
    changed = dict(binding.document)
    changed["state"] = "run-bound"
    with pytest.raises(FollowupQualificationBindingError, match="projection"):
        inspect_followup_qualification_watch_binding(
            json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n"
        )
