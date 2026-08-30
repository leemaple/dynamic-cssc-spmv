from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import scripts.verify_followup_qualification_run_admission as admission_script
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


def test_qualification_admission_script_rebuilds_the_provider_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binding = _binding()
    binding_oid = "5" * 40
    tree_oid = "6" * 40
    ref_path = tmp_path / "ref.json"
    commit_path = tmp_path / "binding.json"
    ref_path.write_text(
        json.dumps(
            {
                "object": {"sha": binding_oid, "type": "commit"},
                "ref": (
                    "refs/tags/"
                    "dynamic-cssc-followup-performance-qualification-authority-v1"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    commit_path.write_text(
        json.dumps(
            {
                "message": binding.document_bytes.decode("ascii"),
                "parents": [{"sha": "2" * 40}],
                "sha": binding_oid,
                "tree": {"sha": tree_oid},
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    def fake_git(_root: Path, *arguments: str) -> str:
        if arguments == ("rev-parse", "HEAD"):
            return "2" * 40
        if arguments == ("status", "--porcelain=v1", "--untracked-files=no"):
            return ""
        if arguments == ("rev-parse", "HEAD^{tree}"):
            return tree_oid
        raise AssertionError(arguments)

    monkeypatch.setattr(admission_script, "_git", fake_git)
    arguments = argparse.Namespace(
        repository_root=tmp_path,
        ref_json=ref_path.resolve(),
        binding_commit_json=commit_path.resolve(),
        expected_claim_oid="2" * 40,
        expected_s1="1" * 40,
        expected_s2="2" * 40,
        expected_compatibility="3" * 64,
        expected_provider_run_id=7001,
    )

    assert admission_script._main(arguments) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["binding_oid"] == binding_oid
    assert output["watcher_session_sha256"] == "4" * 64

    ref_path.write_text(
        json.dumps(
            {
                "object": {"sha": "2" * 40, "type": "commit"},
                "ref": (
                    "refs/tags/"
                    "dynamic-cssc-followup-performance-qualification-authority-v1"
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    with pytest.raises(FollowupQualificationBindingError, match="not watch-armed"):
        admission_script._main(arguments)
