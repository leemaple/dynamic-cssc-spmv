from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, replace
from decimal import Decimal
from inspect import signature
from pathlib import Path
from typing import get_args

import pytest

import dynamic_cssc.day1_registry as registry_module
from dynamic_cssc.day1_registry import (
    CandidateRole,
    Day1CandidateCatalog,
    Day1CandidateRegistrationError,
    RegisteredCandidate,
    RegistrationEvidence,
    repository_day1_candidate_catalog,
)
from dynamic_cssc.evidence_compatibility import (
    DAY1_REGISTRATION_ANCHOR_PATH,
    STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
    EvidenceRole,
    capture_behavior_inventory,
    repository_behavior_paths,
)
from dynamic_cssc.strong_reference_receipt import (
    StrongReferenceCapability,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _synthetic_catalog_repository(
    tmp_path: Path,
    *,
    registration_mutation: str | None = None,
    commit_anchor: bool = True,
    install_anchor: bool = True,
    include_historical_strong_source: bool = True,
) -> tuple[Path, str]:
    repository = tmp_path / (
        f"catalog-{registration_mutation or 'valid'}-{commit_anchor}-{install_anchor}-"
        f"{include_historical_strong_source}"
    )
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "catalog-test@example.invalid")
    _git(repository, "config", "user.name", "Catalog Test")
    (repository / ".gitignore").write_text("*.pyc\n__pycache__/\n", encoding="utf-8")
    for relative_path in repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION):
        source = REPOSITORY_ROOT / relative_path
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    strong_anchor = repository / STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH
    strong_anchor.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        REPOSITORY_ROOT / STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
        strong_anchor,
    )
    registration_anchor = repository / DAY1_REGISTRATION_ANCHOR_PATH
    registration_anchor.parent.mkdir(parents=True, exist_ok=True)
    registration_anchor.write_bytes(
        b'{"anchors":[],"schema_version":"dynamic-cssc-day1-registration-anchor-set-v1"}\n'
    )
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "registration experiment")
    experiment_sha = _git(repository, "rev-parse", "HEAD")
    if include_historical_strong_source:
        _git(
            repository,
            "fetch",
            "-q",
            str(REPOSITORY_ROOT),
            "fcb00e0d7f111f3ab5003c111b124df83ae11813:refs/remotes/evidence/strong",
        )
    if not install_anchor:
        return repository, experiment_sha
    inventory = capture_behavior_inventory(
        EvidenceRole.DAY1_REGISTRATION,
        source_git_sha=experiment_sha,
        repository_root=repository,
    )
    registration = {
        "accounting_evidence_sha256": "3" * 64,
        "correctness_artifact_sha256": (
            "c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe"
        ),
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
        "run_id": 123,
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": experiment_sha,
    }
    if registration_mutation == "policy":
        registration["policy_contract_sha256"] = "0" * 64
    elif registration_mutation == "schema":
        registration["schema_version"] = "dynamic-cssc-day1-registration-evidence-v2"
    elif registration_mutation == "correctness":
        registration["correctness_artifact_sha256"] = "0" * 64
    record = {
        "artifact_behavior_inventory": inventory,
        "artifact_sha256": hashlib.sha256(_canonical(registration)).hexdigest(),
        "experiment_source_git_sha": experiment_sha,
        "registration_evidence": registration,
        "role": "day1-registration",
        "schema_version": "dynamic-cssc-day1-registration-anchor-v1",
    }
    registration_anchor.write_bytes(
        _canonical(
            {
                "anchors": [record],
                "schema_version": "dynamic-cssc-day1-registration-anchor-set-v1",
            }
        )
    )
    if commit_anchor:
        _git(repository, "add", "--all")
        _git(repository, "commit", "-qm", "install registration evidence")
        _git(repository, "commit", "--allow-empty", "-qm", "analysis snapshot")
    return repository, experiment_sha


def _run_synthetic_catalog(
    repository: Path,
    *,
    inject_inline_anchor: bool = False,
) -> subprocess.CompletedProcess[str]:
    program = f"""
import json
import sys
sys.path.insert(0, {str(repository / "src")!r})
try:
    import dynamic_cssc.day1_registry as registry_module
    from dynamic_cssc.strong_reference_receipt import repository_strong_reference_capability
    if {inject_inline_anchor!r}:
        registry_module._REPOSITORY_REGISTRATION_ANCHORS = (object(),)
    catalog = registry_module.repository_day1_candidate_catalog()
    correctness = repository_strong_reference_capability()
except Exception as error:
    print(f"{{type(error).__name__}}: {{error}}", file=sys.stderr)
    raise SystemExit(2)
print(json.dumps({{
    "candidate_count": len(catalog.candidates),
    "registration_source": catalog.registration.source_git_sha,
    "correctness_source": correctness.source_git_sha,
    "correctness_authority": correctness.formal_authority_granted,
}}, sort_keys=True))
"""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        (sys.executable, "-c", program),
        cwd=repository.parent,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_repository_catalog_is_zero_argument_and_fails_when_composite_anchor_is_absent(
    tmp_path: Path,
) -> None:
    assert tuple(signature(repository_day1_candidate_catalog).parameters) == ()
    assert not hasattr(registry_module, "_REPOSITORY_REGISTRATION_ANCHORS")
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        install_anchor=False,
    )

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert "no repository-approved Day-1 composite registration anchor" in completed.stderr


def test_public_catalog_reads_even_an_empty_anchor_only_from_git_100644(
    tmp_path: Path,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        install_anchor=False,
    )
    anchor = repository / DAY1_REGISTRATION_ANCHOR_PATH
    anchor.chmod(0o755)
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "make empty registration anchor executable")

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert "100644" in completed.stderr


def test_inline_registration_anchor_monkeypatch_cannot_admit_the_catalog(
    tmp_path: Path,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        install_anchor=False,
    )

    completed = _run_synthetic_catalog(repository, inject_inline_anchor=True)

    assert completed.returncode != 0
    assert "no repository-approved" in completed.stderr


def test_public_catalog_accepts_independent_registration_and_historical_correctness_s1(
    tmp_path: Path,
) -> None:
    repository, experiment_sha = _synthetic_catalog_repository(tmp_path)

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "candidate_count": 14,
        "correctness_authority": False,
        "correctness_source": "fcb00e0d7f111f3ab5003c111b124df83ae11813",
        "registration_source": experiment_sha,
    }
    assert result["registration_source"] != result["correctness_source"]


def test_public_catalog_rejects_a_descriptor_without_reachable_historical_source(
    tmp_path: Path,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        include_historical_strong_source=False,
    )

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert "historical strong source commit" in completed.stderr


def test_self_written_uncommitted_registration_json_never_admits_a_catalog(
    tmp_path: Path,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        commit_anchor=False,
    )

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert "clean repository HEAD" in completed.stderr


@pytest.mark.parametrize("mutation", ("policy", "schema", "correctness"))
def test_public_catalog_rejects_self_consistent_domain_identity_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        registration_mutation=mutation,
    )

    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert any(
        expected in completed.stderr
        for expected in (
            "frozen strong policy",
            "schema version is not approved",
            "does not bind the historical correctness artifact",
        )
    )


def test_correctness_receipt_or_forged_projection_alone_cannot_register_a_catalog(
    tmp_path: Path,
) -> None:
    repository, _experiment_sha = _synthetic_catalog_repository(
        tmp_path,
        install_anchor=False,
    )
    completed = _run_synthetic_catalog(repository)

    assert completed.returncode != 0
    assert "correctness evidence alone" in completed.stderr
    with pytest.raises(TypeError):
        repository_day1_candidate_catalog(object())  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        repository_day1_candidate_catalog(StrongReferenceCapability)  # type: ignore[call-arg]
    for injected in (
        {"capability": object()},
        {"receipt": {}},
        {"trust_anchor": object()},
        {"catalog_factory": object()},
        {"enabled": True},
    ):
        with pytest.raises(TypeError):
            repository_day1_candidate_catalog(**injected)  # type: ignore[call-arg]


def test_registration_evidence_is_an_immutable_descriptive_projection() -> None:
    evidence = RegistrationEvidence(
        schema_version="dynamic-cssc-day1-registration-evidence-v1",
        source_git_sha="1" * 40,
        run_id=123,
        correctness_artifact_sha256="2" * 64,
        accounting_evidence_sha256="3" * 64,
        policy_contract_sha256="4" * 64,
    )

    assert tuple(field.name for field in fields(evidence)) == (
        "schema_version",
        "source_git_sha",
        "run_id",
        "correctness_artifact_sha256",
        "accounting_evidence_sha256",
        "policy_contract_sha256",
    )
    assert not hasattr(evidence, "__dict__")
    with pytest.raises(FrozenInstanceError):
        evidence.run_id = 124  # type: ignore[misc]


def test_closed_composite_parser_projects_an_exact_anchored_bundle() -> None:
    payload = {
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": "1" * 40,
        "run_id": 123,
        "correctness_artifact_sha256": "2" * 64,
        "accounting_evidence_sha256": "3" * 64,
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
    }
    assert registry_module._parse_registration_evidence(payload) == RegistrationEvidence(**payload)


def test_closed_composite_parser_does_not_treat_object_key_order_as_evidence() -> None:
    ordered_items = (
        ("schema_version", "dynamic-cssc-day1-registration-evidence-v1"),
        ("source_git_sha", "1" * 40),
        ("run_id", 123),
        ("correctness_artifact_sha256", "2" * 64),
        ("accounting_evidence_sha256", "3" * 64),
        (
            "policy_contract_sha256",
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b",
        ),
    )
    payload = dict(reversed(ordered_items))
    assert registry_module._parse_registration_evidence(payload).run_id == 123


def test_registered_candidate_is_an_immutable_role_aware_value() -> None:
    candidate = RegisteredCandidate(
        candidate_id="reserved-slack/beta=0.05",
        strategy="ReservedSlack-CSSC",
        role="reference",
        reserved_slack_beta=Decimal("0.05"),
    )

    assert get_args(CandidateRole) == ("reference", "ablation")
    assert tuple(field.name for field in fields(candidate)) == (
        "candidate_id",
        "strategy",
        "role",
        "reserved_slack_beta",
        "periodic_repack_windows",
        "packed_coo_segment_capacity",
    )
    assert not hasattr(candidate, "__dict__")
    with pytest.raises(FrozenInstanceError):
        candidate.role = "ablation"  # type: ignore[misc]


@pytest.mark.parametrize("invalid_role", ("selector", "Reference", True))
def test_registered_candidate_rejects_roles_outside_the_closed_taxonomy(
    invalid_role: object,
) -> None:
    with pytest.raises(ValueError, match="role"):
        RegisteredCandidate(
            candidate_id="padding-reuse",
            strategy="PaddingReuse-CSSC",
            role=invalid_role,  # type: ignore[arg-type]
        )


def test_registered_candidate_rejects_unknown_strategy_identity() -> None:
    with pytest.raises(ValueError, match="strategy"):
        RegisteredCandidate(
            candidate_id="invented",
            strategy="Invented-Hybrid",  # type: ignore[arg-type]
            role="reference",
        )


def test_composite_parser_rejects_a_self_consistent_but_noncanonical_policy_hash() -> None:
    payload = {
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": "1" * 40,
        "run_id": 123,
        "correctness_artifact_sha256": "2" * 64,
        "accounting_evidence_sha256": "3" * 64,
        "policy_contract_sha256": "4" * 64,
    }
    with pytest.raises(Day1CandidateRegistrationError, match="frozen strong policy"):
        registry_module._parse_registration_evidence(payload)


@pytest.mark.parametrize(
    ("field", "retargeted"),
    (
        ("schema_version", "dynamic-cssc-day1-registration-evidence-v2"),
        ("source_git_sha", "HEAD"),
        ("run_id", 0),
        ("correctness_artifact_sha256", "A" * 64),
        ("accounting_evidence_sha256", "b" * 63),
        ("policy_contract_sha256", "c" * 64),
    ),
)
def test_composite_parser_rejects_every_identity_retarget(
    field: str,
    retargeted: object,
) -> None:
    anchored = {
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": "1" * 40,
        "run_id": 123,
        "correctness_artifact_sha256": "2" * 64,
        "accounting_evidence_sha256": "3" * 64,
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
    }
    payload = dict(anchored)
    payload[field] = retargeted

    with pytest.raises(Day1CandidateRegistrationError):
        registry_module._parse_registration_evidence(payload)


@pytest.mark.parametrize("mutation", ("missing", "unknown"))
def test_composite_parser_rejects_open_registration_objects(mutation: str) -> None:
    anchored = {
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": "1" * 40,
        "run_id": 123,
        "correctness_artifact_sha256": "2" * 64,
        "accounting_evidence_sha256": "3" * 64,
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
    }
    payload = dict(anchored)
    if mutation == "missing":
        payload.pop("accounting_evidence_sha256")
    else:
        payload["accounting_schema_trusted"] = True

    with pytest.raises(Day1CandidateRegistrationError, match="closed schema"):
        registry_module._parse_registration_evidence(payload)


def test_pure_catalog_builder_emits_role_aware_canonical_day1_roster() -> None:
    frozen_policy = {
        "schema_version": "dynamic-cssc-day1-strong-policy-contract-v1",
        "candidate_id": "packed-coo-cloud-segmented-delta/segment-width=128",
        "strategy": "Packed-COO-Cloud-Segmented-Delta",
        "segment_width": 128,
        "fold": "never",
        "compaction": "none",
        "base_reserved_slack_beta": "0",
    }
    policy_contract_sha256 = hashlib.sha256(
        json.dumps(
            frozen_policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    assert policy_contract_sha256 == (
        "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
    )
    registration = RegistrationEvidence(
        schema_version="dynamic-cssc-day1-registration-evidence-v1",
        source_git_sha="1" * 40,
        run_id=123,
        correctness_artifact_sha256="2" * 64,
        accounting_evidence_sha256="3" * 64,
        policy_contract_sha256=policy_contract_sha256,
    )

    catalog = registry_module._build_day1_candidate_catalog(registration)

    assert isinstance(catalog, Day1CandidateCatalog)
    assert catalog.registration == registration
    assert len(catalog.candidates) == 14
    assert len(catalog.selection_candidates) == 13
    assert len(catalog.ablation_candidates) == 1
    assert all(candidate.role == "reference" for candidate in catalog.selection_candidates)
    assert tuple(candidate.candidate_id for candidate in catalog.candidates) == (
        "padding-reuse",
        "mini-cssc-delta",
        "packed-coo-client-lane-delta/capacity=128",
        "strict-local-repack",
        "reserved-slack/beta=0",
        "reserved-slack/beta=0.05",
        "reserved-slack/beta=0.1",
        "reserved-slack/beta=0.2",
        "reserved-slack/beta=0.4",
        "periodic-repack/windows=1",
        "periodic-repack/windows=4",
        "periodic-repack/windows=16",
        "periodic-repack/windows=64",
        "packed-coo-cloud-segmented-delta/segment-width=128",
    )
    assert len({candidate.candidate_id for candidate in catalog.candidates}) == 14

    client_lane = catalog.ablation_candidates[0]
    assert client_lane.candidate_id == "packed-coo-client-lane-delta/capacity=128"
    assert client_lane.strategy == "Packed-COO-Client-Lane-Delta"
    assert client_lane.packed_coo_segment_capacity == 128

    strong = next(
        candidate
        for candidate in catalog.selection_candidates
        if candidate.strategy == "Packed-COO-Cloud-Segmented-Delta"
    )
    assert strong.candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128"
    assert strong.role == "reference"
    assert strong.reserved_slack_beta == Decimal("0")
    assert strong.periodic_repack_windows is None
    assert strong.packed_coo_segment_capacity is None

    with pytest.raises(FrozenInstanceError):
        catalog.candidates = ()  # type: ignore[misc]


def test_catalog_value_rejects_relabeling_the_client_lane_as_selectable() -> None:
    registration = RegistrationEvidence(
        schema_version="dynamic-cssc-day1-registration-evidence-v1",
        source_git_sha="1" * 40,
        run_id=123,
        correctness_artifact_sha256="2" * 64,
        accounting_evidence_sha256="3" * 64,
        policy_contract_sha256=("a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"),
    )
    catalog = registry_module._build_day1_candidate_catalog(registration)
    relabeled = tuple(
        replace(candidate, role="reference") if candidate.role == "ablation" else candidate
        for candidate in catalog.candidates
    )

    with pytest.raises(ValueError, match="canonical Day-1 roster"):
        Day1CandidateCatalog(candidates=relabeled, registration=registration)
