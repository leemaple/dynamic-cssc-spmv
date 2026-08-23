"""Closed descriptive evidence for future Day-1 composite registration review.

The public producer intentionally has one path-only input and currently stops on a
policy HOLD. A registration run identifier may not come from caller arguments,
process environment, or the historical correctness receipt. The private fixed-run
seam exercises the complete archive transaction until repository-owned provenance
is frozen.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass, fields
from decimal import Decimal
from pathlib import Path

_REGISTRATION_SCHEMA = "dynamic-cssc-day1-registration-evidence-v1"
_ACCOUNTING_SCHEMA = "dynamic-cssc-day1-registration-accounting-evidence-v1"
_STRONG_IDENTITY_SCHEMA = "dynamic-cssc-day1-strong-correctness-identity-v1"
_WORKFLOW_PROVENANCE_SCHEMA = "dynamic-cssc-day1-registration-run-provenance-v1"
_MANIFEST_SCHEMA = "dynamic-cssc-day1-registration-evidence-archive-v1"
_ANCHOR_PROJECTION_SCHEMA = "dynamic-cssc-day1-registration-anchor-review-projection-v1"
_AUTHORITY_STATE = "descriptive-review-input-only"
_HISTORICAL_STRONG_ARTIFACT_SHA256 = (
    "c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe"
)
_PRIVATE_TEST_RUN_ID = 456789
_PRIVATE_TEST_RUN_AUTHORITY = "private-fixed-test-fixture-non-production"
_STRONG_SOURCE_HOLD = "HOLD-until-zero-argument-hardened-strong-source-attestation-is-frozen"
_DEDICATED_WORKFLOW_PATH = ".github/workflows/day1-registration-evidence.yml"
_DESCRIPTIVE_DAY1_WORKFLOW_PATH = ".github/workflows/day1-cost-model.yml"
_REQUIRED_PRODUCER_BEHAVIOR_PATHS = frozenset(
    {
        "scripts/produce_day1_registration_evidence.py",
        "src/dynamic_cssc/day1_registration_evidence.py",
        "tests/test_day1_registration_evidence.py",
    }
)
_VALIDATION_SOURCE_PATHS = (
    "src/dynamic_cssc/day1_registry.py",
    "src/dynamic_cssc/metrics.py",
    "src/dynamic_cssc/report.py",
    "src/dynamic_cssc/simulator.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "tests/test_day1_registry.py",
    "tests/test_query_accounting.py",
    "tests/test_report.py",
    "tests/test_strong_day1_simulator.py",
)
_PAYLOAD_FILENAMES = (
    "accounting-evidence.json",
    "artifact-behavior-inventory.json",
    "registration-evidence.json",
    "strong-correctness-identity.json",
    "workflow-provenance.json",
)
_MANIFEST_FILENAME = "day1-registration-evidence-manifest.json"
_CHECKSUMS_FILENAME = "SHA256SUMS"
_JSON_FILENAMES = (*_PAYLOAD_FILENAMES, _MANIFEST_FILENAME)
_ARCHIVE_FILENAMES = frozenset((*_JSON_FILENAMES, _CHECKSUMS_FILENAME))
_MAX_MEMBER_BYTES = 8 * 1024 * 1024
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class Day1RegistrationEvidenceError(ValueError):
    """A registration archive or its repository inputs failed closed."""


class Day1RegistrationEvidenceHold(RuntimeError):
    """Required repository-owned registration production policy is not frozen."""


@dataclass(frozen=True, slots=True)
class Day1RegistrationEvidenceArchive:
    """Paths and digests of one installed, non-authoritative archive."""

    output_dir: Path
    manifest_sha256: str
    registration_evidence_sha256: str
    checksums_sha256: str
    formal_authority_granted: bool = False


@dataclass(frozen=True, slots=True)
class Day1RegistrationEvidenceInspection:
    """Descriptive inspection result; this value can never admit a catalog."""

    archive_dir: Path
    manifest_sha256: str
    registration_evidence_sha256: str
    source_git_sha: str
    source_tree_git_sha: str
    run_id: int
    formal_authority_granted: bool = False
    catalog_authority_minted: bool = False
    repository_anchor_installed: bool = False


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json_bytes(payload: object) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day1RegistrationEvidenceError(
            "registration evidence is not canonical JSON"
        ) from error
    return (encoded + "\n").encode("ascii")


def _require_exact_keys(
    value: object,
    expected: frozenset[str],
    field: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise Day1RegistrationEvidenceError(f"{field} must be an exact object")
    if set(value) != expected:
        raise Day1RegistrationEvidenceError(f"{field} keys must match the closed schema")
    return value


def _require_lower_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1RegistrationEvidenceError(f"{field} must be a lowercase SHA-256")
    return value


def _require_lower_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise Day1RegistrationEvidenceError(f"{field} must be a full lowercase 40-digit Git SHA")
    return value


def _require_false(value: object, field: str) -> None:
    if type(value) is not bool or value is not False:
        raise Day1RegistrationEvidenceError(f"{field} must be exact false")


def _decimal_string(value: Decimal | None) -> str | None:
    if value is None:
        return None
    normalized = format(value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return "0" if normalized in {"", "-0"} else normalized


def _candidate_document(candidate: object) -> dict[str, object]:
    return {
        "candidate_id": candidate.candidate_id,
        "packed_coo_segment_capacity": candidate.packed_coo_segment_capacity,
        "periodic_repack_windows": candidate.periodic_repack_windows,
        "reserved_slack_beta": _decimal_string(candidate.reserved_slack_beta),
        "role": candidate.role,
        "strategy": candidate.strategy,
    }


def _canonical_roster_document() -> dict[str, object]:
    from dynamic_cssc import day1_registry

    candidates = day1_registry._canonical_registered_candidates()
    if type(candidates) is not tuple or len(candidates) != 14:
        raise Day1RegistrationEvidenceError(
            "repository canonical Day-1 roster must contain exactly 14 candidates"
        )
    documents = [_candidate_document(candidate) for candidate in candidates]
    fixed_ids = [candidate.candidate_id for candidate in candidates]
    reference_ids = [
        candidate.candidate_id for candidate in candidates if candidate.role == "reference"
    ]
    ablation_ids = [
        candidate.candidate_id for candidate in candidates if candidate.role == "ablation"
    ]
    if (
        len(fixed_ids) != len(set(fixed_ids))
        or len(reference_ids) != 13
        or len(ablation_ids) != 1
        or set(reference_ids).intersection(ablation_ids)
        or set(fixed_ids) != set(reference_ids).union(ablation_ids)
    ):
        raise Day1RegistrationEvidenceError(
            "repository canonical Day-1 roles must be an exact 13/1 partition"
        )
    return {
        "ablation_candidate_count": 1,
        "ablation_candidate_ids": ablation_ids,
        "candidate_documents": documents,
        "derived_aliases_are_physical_candidates": False,
        "diagnostic_oracle_is_registered_candidate": False,
        "fixed_candidate_count": 14,
        "fixed_candidate_ids": fixed_ids,
        "reference_candidate_count": 13,
        "reference_candidate_ids": reference_ids,
        "roles_partition_the_fixed_roster": True,
        "schema_version": "dynamic-cssc-day1-fixed-candidate-roster-v1",
    }


def _report_contract_document() -> dict[str, object]:
    from dynamic_cssc import metrics, report

    return {
        "accounting_invariants": list(report._ACCOUNTING_INVARIANTS),
        "causal_artifact_filenames": list(report.CAUSAL_ARTIFACT_FILENAMES),
        "causal_schema": report.CAUSAL_SCHEMA,
        "completion_proof_schema": report.CAUSAL_COMPLETION_PROOF_SCHEMA,
        "measurement_kind": report.CAUSAL_MEASUREMENT_KIND,
        "report_validator_symbol": "dynamic_cssc.report.validate_causal_payload",
        "schema_version": "dynamic-cssc-day1-accounting-report-contract-v1",
        "state_model": report.CAUSAL_STATE_MODEL,
        "strategy_metrics_fields": [field.name for field in fields(metrics.StrategyMetrics)],
        "unit_cost_fields": [field.name for field in fields(metrics.UnitCosts)],
        "unit_costs": asdict(metrics.UnitCosts()),
    }


def _strong_policy_document() -> tuple[dict[str, object], str]:
    from dynamic_cssc import day1_registry

    contract = dict(day1_registry._STRONG_POLICY_CONTRACT)
    digest = _sha256(
        json.dumps(
            contract,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )
    if digest != day1_registry._STRONG_POLICY_CONTRACT_SHA256:
        raise Day1RegistrationEvidenceError(
            "repository strong policy contract digest is internally inconsistent"
        )
    return contract, digest


def _strong_projection_document() -> dict[str, object]:
    from dynamic_cssc.strong_reference_receipt import (
        StrongReferenceCapability,
        repository_strong_reference_capability,
    )

    capability = repository_strong_reference_capability()
    if type(capability) is not StrongReferenceCapability:
        raise Day1RegistrationEvidenceError(
            "repository strong correctness seam returned an unexpected type"
        )
    projection = {
        field.name: getattr(capability, field.name) for field in fields(StrongReferenceCapability)
    }
    false_claims = (
        "formal_authority_granted",
        "gate_eligible",
        "candidate_registered",
        "candidate_registration_allowed",
        "complete_reference_set",
        "complete_cost_claim_allowed",
        "formal_parameter_claim_allowed",
        "end_to_end_correctness_claim_allowed",
        "security_claim_allowed",
        "formal_correctness_claim",
        "formal_security_claim",
        "formal_performance_claim",
        "mixed_workload_parameter_claim",
    )
    if projection.get("authority_state") != "historical-descriptive-only" or any(
        projection.get(field) is not False for field in false_claims
    ):
        raise Day1RegistrationEvidenceError(
            "historical strong correctness identity must remain descriptive and claims-false"
        )
    if projection.get("artifact_sha256") != _HISTORICAL_STRONG_ARTIFACT_SHA256:
        raise Day1RegistrationEvidenceError(
            "repository historical strong artifact identity changed"
        )
    return projection


def _validate_embedded_strong_projection(value: object) -> dict[str, object]:
    """Validate the closed historical descriptor without consulting mutable HEAD."""

    from dynamic_cssc import strong_reference_receipt

    expected_fields = frozenset(
        field.name for field in fields(strong_reference_receipt.StrongReferenceCapability)
    )
    projection = _require_exact_keys(value, expected_fields, "strong correctness projection")
    if (
        projection["authority_state"] != "historical-descriptive-only"
        or projection["schema_version"] != strong_reference_receipt.RECEIPT_SCHEMA_VERSION
        or projection["evidence_scope"] != strong_reference_receipt.WHOLE_QUERY_EVIDENCE_SCOPE
        or projection["openfhe_version"] != strong_reference_receipt.PINNED_OPENFHE_VERSION
        or projection["openfhe_commit"] != strong_reference_receipt.PINNED_OPENFHE_COMMIT
        or projection["segment_width"] != strong_reference_receipt.FROZEN_SEGMENT_WIDTH
        or projection["builder_grammar_authorized"] is not True
    ):
        raise Day1RegistrationEvidenceError("strong correctness projection identity is invalid")
    false_claims = (
        "formal_authority_granted",
        "gate_eligible",
        "candidate_registered",
        "candidate_registration_allowed",
        "complete_reference_set",
        "complete_cost_claim_allowed",
        "formal_parameter_claim_allowed",
        "end_to_end_correctness_claim_allowed",
        "security_claim_allowed",
        "formal_correctness_claim",
        "formal_security_claim",
        "formal_performance_claim",
        "mixed_workload_parameter_claim",
    )
    for field in false_claims:
        _require_false(projection[field], f"strong correctness projection {field}")
    _require_lower_git_sha(projection["source_git_sha"], "strong correctness source Git SHA")
    for field in expected_fields:
        if field.endswith("sha256"):
            _require_lower_sha256(projection[field], f"strong correctness {field}")
    if projection["artifact_sha256"] != _HISTORICAL_STRONG_ARTIFACT_SHA256:
        raise Day1RegistrationEvidenceError("embedded historical strong artifact identity changed")
    for field in ("witness_run_id", "property_contract_run_id"):
        if type(projection[field]) is not int or projection[field] <= 0:
            raise Day1RegistrationEvidenceError(
                f"strong correctness {field} must be a positive integer"
            )
    return projection


def _validation_bindings(
    inventory: dict[str, object],
    source_sha256: dict[str, str],
) -> list[dict[str, str]]:
    raw_entries = inventory.get("entries")
    if type(raw_entries) is not list:
        raise Day1RegistrationEvidenceError("Behavior inventory entries are malformed")
    entries = {
        entry.get("path"): entry
        for entry in raw_entries
        if type(entry) is dict and type(entry.get("path")) is str
    }
    if set(_VALIDATION_SOURCE_PATHS) - set(entries):
        raise Day1RegistrationEvidenceError(
            "DAY1_REGISTRATION Behavior Set lacks accounting validation sources"
        )
    bindings: list[dict[str, str]] = []
    for path in _VALIDATION_SOURCE_PATHS:
        entry = entries[path]
        digest = source_sha256.get(path)
        _require_lower_sha256(digest, f"Behavior source SHA-256 for {path}")
        bindings.append(
            {
                "mode": str(entry["mode"]),
                "object_id": str(entry["object_id"]),
                "object_type": str(entry["object_type"]),
                "path": path,
                "sha256": digest,
            }
        )
    return bindings


def _isolated_repository_facts_document() -> dict[str, object]:
    """Collect all repository facts inside the fresh isolated worker process."""

    from dynamic_cssc import evidence_compatibility
    from dynamic_cssc.evidence_compatibility import EvidenceRole

    repository_root = Path(__file__).resolve().parents[2]
    behavior_paths = frozenset(
        evidence_compatibility.repository_behavior_paths(EvidenceRole.DAY1_REGISTRATION)
    )
    if not behavior_paths >= _REQUIRED_PRODUCER_BEHAVIOR_PATHS:
        raise Day1RegistrationEvidenceHold(
            "HOLD: the central DAY1_REGISTRATION Behavior Set lacks the producer paths"
        )
    try:
        first_attestation = evidence_compatibility.verify_current_role_source(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
        inventory = evidence_compatibility.capture_behavior_inventory(
            EvidenceRole.DAY1_REGISTRATION,
            source_git_sha=first_attestation.git_sha,
            repository_root=repository_root,
        )
    except evidence_compatibility.EvidenceCompatibilityError as error:
        raise Day1RegistrationEvidenceError(
            f"DAY1_REGISTRATION S1 source attestation failed: {error}"
        ) from error
    if (
        inventory.get("source_git_sha") != first_attestation.git_sha
        or inventory.get("behavior_set_sha256") != first_attestation.behavior_set_sha256
        or inventory.get("behavior_set_schema_version")
        != first_attestation.behavior_set_schema_version
    ):
        raise Day1RegistrationEvidenceError(
            "captured Behavior inventory does not match the S1 source attestation"
        )
    source_sha256 = dict(first_attestation.behavior_source_blob_sha256)
    if set(source_sha256) != behavior_paths:
        raise Day1RegistrationEvidenceError(
            "S1 worktree SHA-256 inventory does not equal the central Behavior Set"
        )

    tree_sha = (
        evidence_compatibility._git(
            repository_root,
            "rev-parse",
            "--verify",
            f"{first_attestation.git_sha}^{{tree}}",
        )
        .decode("ascii")
        .strip()
    )
    _require_lower_git_sha(tree_sha, "S1 Git tree")
    roster = _canonical_roster_document()
    report_contract = _report_contract_document()
    policy_contract, policy_digest = _strong_policy_document()
    strong_projection = _strong_projection_document()
    bindings = _validation_bindings(inventory, source_sha256)

    try:
        final_attestation = evidence_compatibility.verify_current_role_source(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
    except evidence_compatibility.EvidenceCompatibilityError as error:
        raise Day1RegistrationEvidenceError(
            f"DAY1_REGISTRATION S1 changed during collection: {error}"
        ) from error
    if final_attestation != first_attestation:
        raise Day1RegistrationEvidenceError(
            "DAY1_REGISTRATION S1 attestation changed during collection"
        )
    if _strong_projection_document() != strong_projection:
        raise Day1RegistrationEvidenceError(
            "historical strong correctness identity changed during collection"
        )
    return {
        "artifact_behavior_inventory": inventory,
        "candidate_roster": roster,
        "experiment_source_git_sha": first_attestation.git_sha,
        "experiment_source_tree_git_sha": tree_sha,
        "report_contract": report_contract,
        "schema_version": "dynamic-cssc-day1-registration-repository-facts-v1",
        "strong_policy_contract": policy_contract,
        "strong_policy_contract_sha256": policy_digest,
        "strong_projection": strong_projection,
        "strong_source_attestation": {
            "authority_state": _STRONG_SOURCE_HOLD,
            "schema_version": "dynamic-cssc-strong-source-attestation-status-v1",
            "verified": False,
        },
        "validation_source_bindings": bindings,
    }


def _collect_repository_facts_in_isolated_interpreter() -> dict[str, object]:
    """Reload facts from clean repository bytes, excluding inline monkeypatches."""

    repository_root = Path(__file__).resolve().parents[2]
    source_dir = repository_root / "src"
    program = f"""
import sys
sys.path.insert(0, {str(source_dir)!r})
from dynamic_cssc.day1_registration_evidence import (
    Day1RegistrationEvidenceHold,
    _canonical_json_bytes,
    _isolated_repository_facts_document,
)
try:
    document = _isolated_repository_facts_document()
except Day1RegistrationEvidenceHold as error:
    print(f\"HOLD:{{error}}\", file=sys.stderr)
    raise SystemExit(3)
except Exception as error:
    print(f\"ERROR:{{type(error).__name__}}: {{error}}\", file=sys.stderr)
    raise SystemExit(4)
sys.stdout.buffer.write(_canonical_json_bytes(document))
"""
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("PYTHON") or name.startswith("GIT_"):
            environment.pop(name)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = subprocess.run(
            (sys.executable, "-I", "-S", "-B", "-c", program),
            cwd=repository_root.parent,
            env=environment,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise Day1RegistrationEvidenceError(
            "cannot launch the isolated repository-facts verifier"
        ) from error
    detail = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode == 3 and detail.startswith("HOLD:"):
        raise Day1RegistrationEvidenceHold(detail.removeprefix("HOLD:"))
    if completed.returncode != 0:
        raise Day1RegistrationEvidenceError(
            f"isolated repository-facts verification failed: {detail or 'worker failed'}"
        )
    return _decode_canonical_json(completed.stdout, "isolated repository facts")


def _verify_production_strong_source_in_isolated_interpreter() -> None:
    """Require the repository's zero-argument hardened historical-source seam."""

    repository_root = Path(__file__).resolve().parents[2]
    source_dir = repository_root / "src"
    program = f"""
import sys
sys.path.insert(0, {str(source_dir)!r})
from dynamic_cssc.evidence_compatibility import HistoricalStrongSourceAttestation
from dynamic_cssc.strong_reference_receipt import (
    repository_historical_strong_source_attestation,
)
attestation = repository_historical_strong_source_attestation()
if type(attestation) is not HistoricalStrongSourceAttestation:
    raise TypeError('historical strong source attestation has the wrong type')
if attestation.formal_authority_granted is not False:
    raise ValueError('historical strong source attestation must remain claims-false')
"""
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("PYTHON") or name.startswith("GIT_"):
            environment.pop(name)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        (sys.executable, "-I", "-S", "-B", "-c", program),
        cwd=repository_root.parent,
        env=environment,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise Day1RegistrationEvidenceHold(
            "HOLD: hardened zero-argument historical strong source attestation failed: "
            f"{detail or 'isolated verifier failed'}"
        )


def _archive_documents(
    facts: dict[str, object],
    *,
    run_id: int,
    run_identity_authority_state: str,
) -> dict[str, bytes]:
    if type(run_id) is not int or run_id <= 0:
        raise Day1RegistrationEvidenceError("registration run_id must be a positive integer")
    source_sha = _require_lower_git_sha(
        facts.get("experiment_source_git_sha"),
        "repository facts source Git SHA",
    )
    source_tree = _require_lower_git_sha(
        facts.get("experiment_source_tree_git_sha"),
        "repository facts source tree Git SHA",
    )
    inventory = facts.get("artifact_behavior_inventory")
    if type(inventory) is not dict:
        raise Day1RegistrationEvidenceError("repository facts Behavior inventory is malformed")
    inventory_bytes = _canonical_json_bytes(inventory)
    inventory_sha256 = _sha256(inventory_bytes)

    strong_projection = facts.get("strong_projection")
    if type(strong_projection) is not dict:
        raise Day1RegistrationEvidenceError("repository strong projection is malformed")
    strong_source_attestation = facts.get("strong_source_attestation")
    if type(strong_source_attestation) is not dict:
        raise Day1RegistrationEvidenceError("strong source attestation status is malformed")
    strong_identity = {
        "authority_state": _AUTHORITY_STATE,
        "formal_authority_granted": False,
        "projection": strong_projection,
        "schema_version": _STRONG_IDENTITY_SCHEMA,
        "source_attestation": strong_source_attestation,
    }
    strong_bytes = _canonical_json_bytes(strong_identity)

    workflow = {
        "dedicated_registration_workflow_path": _DEDICATED_WORKFLOW_PATH,
        "descriptive_day1_workflow_path": _DESCRIPTIVE_DAY1_WORKFLOW_PATH,
        "experiment_source_git_sha": source_sha,
        "experiment_source_tree_git_sha": source_tree,
        "formal_authority_granted": False,
        "production_eligible": False,
        "provider_receipt_verified": False,
        "run_id": run_id,
        "run_identity_authority_state": run_identity_authority_state,
        "schema_version": _WORKFLOW_PROVENANCE_SCHEMA,
    }
    workflow_bytes = _canonical_json_bytes(workflow)

    accounting = {
        "artifact_behavior_inventory_sha256": inventory_sha256,
        "authority": {
            "candidate_registration_allowed": False,
            "catalog_authority_minted": False,
            "complete_cost_claim_allowed": False,
            "formal_authority_granted": False,
            "formal_performance_claim": False,
        },
        "candidate_roster": facts["candidate_roster"],
        "experiment_source_git_sha": source_sha,
        "experiment_source_tree_git_sha": source_tree,
        "report_contract": facts["report_contract"],
        "schema_version": _ACCOUNTING_SCHEMA,
        "strong_policy_contract": facts["strong_policy_contract"],
        "strong_policy_contract_sha256": facts["strong_policy_contract_sha256"],
        "validation_source_bindings": facts["validation_source_bindings"],
        "workflow_provenance_sha256": _sha256(workflow_bytes),
    }
    accounting_bytes = _canonical_json_bytes(accounting)
    correctness_sha = _require_lower_sha256(
        strong_projection.get("artifact_sha256"),
        "historical correctness artifact SHA-256",
    )
    policy_sha = _require_lower_sha256(
        facts.get("strong_policy_contract_sha256"),
        "strong policy contract SHA-256",
    )
    registration = {
        "accounting_evidence_sha256": _sha256(accounting_bytes),
        "correctness_artifact_sha256": correctness_sha,
        "policy_contract_sha256": policy_sha,
        "run_id": run_id,
        "schema_version": _REGISTRATION_SCHEMA,
        "source_git_sha": source_sha,
    }
    registration_bytes = _canonical_json_bytes(registration)

    payloads = {
        "accounting-evidence.json": accounting_bytes,
        "artifact-behavior-inventory.json": inventory_bytes,
        "registration-evidence.json": registration_bytes,
        "strong-correctness-identity.json": strong_bytes,
        "workflow-provenance.json": workflow_bytes,
    }
    file_records = [
        {"bytes": len(payloads[name]), "path": name, "sha256": _sha256(payloads[name])}
        for name in _PAYLOAD_FILENAMES
    ]
    authority = {
        "candidate_registration_allowed": False,
        "catalog_authority_minted": False,
        "complete_reference_set": False,
        "formal_authority_granted": False,
        "repository_anchor_installed": False,
        "review_required_before_s2_anchor": True,
    }
    anchor_projection = {
        "formal_authority_granted": False,
        "production_run_identity_verified": False,
        "repository_anchor_installed": False,
        "required_fields": {
            "artifact_behavior_inventory": inventory,
            "artifact_sha256": _sha256(registration_bytes),
            "experiment_source_git_sha": source_sha,
            "registration_evidence": registration,
            "role": "day1-registration",
            "schema_version": "dynamic-cssc-day1-registration-anchor-v1",
        },
        "review_required": True,
        "schema_version": _ANCHOR_PROJECTION_SCHEMA,
    }
    manifest = {
        "artifact_behavior_inventory_sha256": inventory_sha256,
        "authority": authority,
        "experiment_source_git_sha": source_sha,
        "experiment_source_tree_git_sha": source_tree,
        "files": file_records,
        "future_repository_anchor_projection": anchor_projection,
        "registration_evidence_sha256": _sha256(registration_bytes),
        "schema_version": _MANIFEST_SCHEMA,
    }
    manifest_bytes = _canonical_json_bytes(manifest)
    documents = {**payloads, _MANIFEST_FILENAME: manifest_bytes}
    documents[_CHECKSUMS_FILENAME] = "".join(
        f"{_sha256(documents[name])}  {name}\n" for name in sorted(_JSON_FILENAMES)
    ).encode("ascii")
    return documents


def _validated_output_path(output_dir: Path, repository_root: Path) -> Path:
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    if output_dir.exists() or output_dir.is_symlink():
        raise Day1RegistrationEvidenceError("output_dir must be a new path")
    if output_dir.name in {"", ".", ".."}:
        raise Day1RegistrationEvidenceError("output_dir must name one new directory")
    try:
        parent = output_dir.parent.resolve(strict=True)
    except OSError as error:
        raise Day1RegistrationEvidenceError(
            "output_dir parent must be an existing directory"
        ) from error
    try:
        parent_mode = parent.lstat().st_mode
    except OSError as error:
        raise Day1RegistrationEvidenceError("output_dir parent is unavailable") from error
    if not stat.S_ISDIR(parent_mode) or stat.S_ISLNK(parent_mode):
        raise Day1RegistrationEvidenceError("output_dir parent must be a no-follow directory")
    resolved = parent / output_dir.name
    repository_root = repository_root.resolve(strict=True)
    try:
        resolved.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise Day1RegistrationEvidenceError("output_dir must be external to the source repository")
    if resolved.exists() or resolved.is_symlink():
        raise Day1RegistrationEvidenceError("output_dir must be a new path")
    return resolved


def _write_file(path: Path, content: bytes) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise Day1RegistrationEvidenceError("archive writing requires O_NOFOLLOW support")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise Day1RegistrationEvidenceError(f"cannot create archive member {path.name}") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with suppress(OSError):
            path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _install_archive(
    output_dir: Path,
    repository_root: Path,
    documents: dict[str, bytes],
) -> Day1RegistrationEvidenceArchive:
    output_dir = _validated_output_path(output_dir, repository_root)
    if set(documents) != _ARCHIVE_FILENAMES:
        raise Day1RegistrationEvidenceError("internal archive member set is not closed")
    parent = output_dir.parent
    lock_path = parent / f".{output_dir.name}.day1-registration.lock"
    stage_path: Path | None = None
    lock_descriptor: int | None = None
    try:
        lock_descriptor = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        stage_path = Path(
            tempfile.mkdtemp(
                prefix=f".{output_dir.name}.day1-registration-stage-",
                dir=parent,
            )
        )
        for name in sorted(documents):
            _write_file(stage_path / name, documents[name])
        _fsync_directory(stage_path)
        inspect_day1_registration_evidence_archive(stage_path)
        if output_dir.exists() or output_dir.is_symlink():
            raise Day1RegistrationEvidenceError("output_dir appeared during production")
        os.rename(stage_path, output_dir)
        stage_path = None
        _fsync_directory(parent)
        inspection = inspect_day1_registration_evidence_archive(output_dir)
        return Day1RegistrationEvidenceArchive(
            output_dir=output_dir,
            manifest_sha256=inspection.manifest_sha256,
            registration_evidence_sha256=inspection.registration_evidence_sha256,
            checksums_sha256=_sha256(documents[_CHECKSUMS_FILENAME]),
        )
    except FileExistsError as error:
        raise Day1RegistrationEvidenceError(
            "another registration evidence transaction owns the output path"
        ) from error
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        if stage_path is not None:
            shutil.rmtree(stage_path, ignore_errors=True)
        with suppress(OSError):
            lock_path.unlink(missing_ok=True)


def _decode_canonical_json(content: bytes, field: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise Day1RegistrationEvidenceError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        document = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Day1RegistrationEvidenceError(f"{field} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day1RegistrationEvidenceError(f"{field} is not canonical ASCII JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise Day1RegistrationEvidenceError(f"{field} is not canonical JSON")
    return document


def _read_archive_members(archive_dir: Path) -> dict[str, bytes]:
    if not isinstance(archive_dir, Path):
        raise TypeError("archive_dir must be a pathlib.Path")
    try:
        directory_mode = archive_dir.lstat().st_mode
    except OSError as error:
        raise Day1RegistrationEvidenceError("archive_dir is unavailable") from error
    if stat.S_ISLNK(directory_mode) or not stat.S_ISDIR(directory_mode):
        raise Day1RegistrationEvidenceError("archive_dir must be a no-follow directory")
    names: set[str] = set()
    with os.scandir(archive_dir) as entries:
        for entry in entries:
            if entry.name in names:
                raise Day1RegistrationEvidenceError("archive contains duplicate members")
            names.add(entry.name)
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise Day1RegistrationEvidenceError(
                    f"archive member must be a no-follow regular file: {entry.name}"
                )
    if names != _ARCHIVE_FILENAMES:
        raise Day1RegistrationEvidenceError(
            "archive member names must exactly match the closed schema"
        )
    if not hasattr(os, "O_NOFOLLOW"):
        raise Day1RegistrationEvidenceError("archive inspection requires O_NOFOLLOW support")
    members: dict[str, bytes] = {}
    for name in sorted(names):
        path = archive_dir / name
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
            )
        except OSError as error:
            raise Day1RegistrationEvidenceError(
                f"archive member cannot be opened securely: {name}"
            ) from error
        with os.fdopen(descriptor, "rb") as handle:
            mode = os.fstat(handle.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise Day1RegistrationEvidenceError(
                    f"archive member changed type while reading: {name}"
                )
            content = handle.read(_MAX_MEMBER_BYTES + 1)
        if len(content) > _MAX_MEMBER_BYTES:
            raise Day1RegistrationEvidenceError(f"archive member is too large: {name}")
        members[name] = content
    return members


def _validate_inventory(
    inventory: dict[str, object],
    source_sha: str,
) -> dict[str, dict[str, str]]:
    _require_exact_keys(
        inventory,
        frozenset(
            {
                "behavior_set_schema_version",
                "behavior_set_sha256",
                "entries",
                "role",
                "schema_version",
                "source_git_sha",
            }
        ),
        "artifact Behavior inventory",
    )
    if (
        inventory["schema_version"] != "dynamic-cssc-evidence-behavior-inventory-v1"
        or inventory["behavior_set_schema_version"]
        != "dynamic-cssc-day1-registration-behavior-set-v1"
        or inventory["role"] != "day1-registration"
        or inventory["source_git_sha"] != source_sha
    ):
        raise Day1RegistrationEvidenceError("artifact Behavior inventory identity is invalid")
    raw_entries = inventory["entries"]
    if type(raw_entries) is not list or not raw_entries:
        raise Day1RegistrationEvidenceError("artifact Behavior inventory entries are invalid")
    by_path: dict[str, dict[str, str]] = {}
    for index, raw_entry in enumerate(raw_entries):
        entry = _require_exact_keys(
            raw_entry,
            frozenset({"mode", "object_id", "object_type", "path"}),
            f"artifact Behavior inventory entry {index}",
        )
        path = entry["path"]
        if (
            type(path) is not str
            or not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or entry["mode"] not in {"100644", "100755"}
            or entry["object_type"] != "blob"
        ):
            raise Day1RegistrationEvidenceError("artifact Behavior inventory entry is invalid")
        _require_lower_git_sha(entry["object_id"], f"Behavior entry object_id for {path}")
        if path in by_path:
            raise Day1RegistrationEvidenceError("artifact Behavior inventory paths repeat")
        by_path[path] = {key: str(value) for key, value in entry.items()}
    if not set(by_path) >= _REQUIRED_PRODUCER_BEHAVIOR_PATHS:
        raise Day1RegistrationEvidenceError(
            "artifact Behavior inventory omits registration producer sources"
        )
    behavior_set = {
        "behavior_set_schema_version": inventory["behavior_set_schema_version"],
        "entries": raw_entries,
        "role": inventory["role"],
    }
    if inventory["behavior_set_sha256"] != _sha256(_canonical_json_bytes(behavior_set)):
        raise Day1RegistrationEvidenceError("artifact Behavior Set digest is invalid")
    return by_path


def _validate_manifest(
    members: dict[str, bytes],
    manifest: dict[str, object],
) -> tuple[str, str]:
    _require_exact_keys(
        manifest,
        frozenset(
            {
                "artifact_behavior_inventory_sha256",
                "authority",
                "experiment_source_git_sha",
                "experiment_source_tree_git_sha",
                "files",
                "future_repository_anchor_projection",
                "registration_evidence_sha256",
                "schema_version",
            }
        ),
        "archive manifest",
    )
    if manifest["schema_version"] != _MANIFEST_SCHEMA:
        raise Day1RegistrationEvidenceError("archive manifest schema is not frozen")
    source_sha = _require_lower_git_sha(
        manifest["experiment_source_git_sha"], "manifest experiment source"
    )
    source_tree = _require_lower_git_sha(
        manifest["experiment_source_tree_git_sha"], "manifest experiment source tree"
    )
    raw_files = manifest["files"]
    if type(raw_files) is not list or len(raw_files) != len(_PAYLOAD_FILENAMES):
        raise Day1RegistrationEvidenceError("manifest files must cover every payload member")
    for index, (raw_file, name) in enumerate(zip(raw_files, _PAYLOAD_FILENAMES, strict=True)):
        file_record = _require_exact_keys(
            raw_file,
            frozenset({"bytes", "path", "sha256"}),
            f"manifest file record {index}",
        )
        if (
            file_record["path"] != name
            or type(file_record["bytes"]) is not int
            or file_record["bytes"] != len(members[name])
            or file_record["sha256"] != _sha256(members[name])
        ):
            raise Day1RegistrationEvidenceError("manifest member binding is invalid")
    authority = _require_exact_keys(
        manifest["authority"],
        frozenset(
            {
                "candidate_registration_allowed",
                "catalog_authority_minted",
                "complete_reference_set",
                "formal_authority_granted",
                "repository_anchor_installed",
                "review_required_before_s2_anchor",
            }
        ),
        "manifest authority",
    )
    for field in (
        "candidate_registration_allowed",
        "catalog_authority_minted",
        "complete_reference_set",
        "formal_authority_granted",
        "repository_anchor_installed",
    ):
        _require_false(authority[field], f"manifest authority {field}")
    if authority["review_required_before_s2_anchor"] is not True:
        raise Day1RegistrationEvidenceError("manifest must require independent S2 review")
    return source_sha, source_tree


def _validate_workflow_and_strong(
    members: dict[str, bytes],
    payloads: dict[str, dict[str, object]],
    *,
    source_sha: str,
    source_tree: str,
) -> tuple[dict[str, object], int]:
    workflow = payloads["workflow-provenance.json"]
    _require_exact_keys(
        workflow,
        frozenset(
            {
                "dedicated_registration_workflow_path",
                "descriptive_day1_workflow_path",
                "experiment_source_git_sha",
                "experiment_source_tree_git_sha",
                "formal_authority_granted",
                "production_eligible",
                "provider_receipt_verified",
                "run_id",
                "run_identity_authority_state",
                "schema_version",
            }
        ),
        "workflow provenance",
    )
    if (
        workflow["schema_version"] != _WORKFLOW_PROVENANCE_SCHEMA
        or workflow["dedicated_registration_workflow_path"] != _DEDICATED_WORKFLOW_PATH
        or workflow["descriptive_day1_workflow_path"] != _DESCRIPTIVE_DAY1_WORKFLOW_PATH
        or workflow["experiment_source_git_sha"] != source_sha
        or workflow["experiment_source_tree_git_sha"] != source_tree
        or workflow["run_identity_authority_state"] != _PRIVATE_TEST_RUN_AUTHORITY
        or type(workflow["run_id"]) is not int
        or workflow["run_id"] != _PRIVATE_TEST_RUN_ID
    ):
        raise Day1RegistrationEvidenceError("workflow provenance is not the fixed test fixture")
    for field in (
        "formal_authority_granted",
        "production_eligible",
        "provider_receipt_verified",
    ):
        _require_false(workflow[field], f"workflow provenance {field}")

    strong = payloads["strong-correctness-identity.json"]
    _require_exact_keys(
        strong,
        frozenset(
            {
                "authority_state",
                "formal_authority_granted",
                "projection",
                "schema_version",
                "source_attestation",
            }
        ),
        "strong correctness identity",
    )
    if (
        strong["schema_version"] != _STRONG_IDENTITY_SCHEMA
        or strong["authority_state"] != _AUTHORITY_STATE
    ):
        raise Day1RegistrationEvidenceError("strong correctness wrapper identity is invalid")
    _require_false(strong["formal_authority_granted"], "strong formal authority")
    projection = _validate_embedded_strong_projection(strong["projection"])
    source_attestation = _require_exact_keys(
        strong["source_attestation"],
        frozenset({"authority_state", "schema_version", "verified"}),
        "strong source attestation",
    )
    if (
        source_attestation["authority_state"] != _STRONG_SOURCE_HOLD
        or source_attestation["schema_version"]
        != "dynamic-cssc-strong-source-attestation-status-v1"
    ):
        raise Day1RegistrationEvidenceError("strong source attestation HOLD is invalid")
    _require_false(source_attestation["verified"], "strong source attestation verified")
    return projection, workflow["run_id"]


def _validate_accounting(
    members: dict[str, bytes],
    payloads: dict[str, dict[str, object]],
    inventory_by_path: dict[str, dict[str, str]],
    *,
    source_sha: str,
    source_tree: str,
) -> str:
    accounting = payloads["accounting-evidence.json"]
    _require_exact_keys(
        accounting,
        frozenset(
            {
                "artifact_behavior_inventory_sha256",
                "authority",
                "candidate_roster",
                "experiment_source_git_sha",
                "experiment_source_tree_git_sha",
                "report_contract",
                "schema_version",
                "strong_policy_contract",
                "strong_policy_contract_sha256",
                "validation_source_bindings",
                "workflow_provenance_sha256",
            }
        ),
        "accounting evidence",
    )
    if (
        accounting["schema_version"] != _ACCOUNTING_SCHEMA
        or accounting["artifact_behavior_inventory_sha256"]
        != _sha256(members["artifact-behavior-inventory.json"])
        or accounting["experiment_source_git_sha"] != source_sha
        or accounting["experiment_source_tree_git_sha"] != source_tree
        or accounting["workflow_provenance_sha256"] != _sha256(members["workflow-provenance.json"])
        or accounting["candidate_roster"] != _canonical_roster_document()
        or accounting["report_contract"] != _report_contract_document()
    ):
        raise Day1RegistrationEvidenceError("accounting evidence bindings are invalid")
    policy, policy_sha = _strong_policy_document()
    if (
        accounting["strong_policy_contract"] != policy
        or accounting["strong_policy_contract_sha256"] != policy_sha
    ):
        raise Day1RegistrationEvidenceError("accounting strong policy binding is invalid")
    authority = _require_exact_keys(
        accounting["authority"],
        frozenset(
            {
                "candidate_registration_allowed",
                "catalog_authority_minted",
                "complete_cost_claim_allowed",
                "formal_authority_granted",
                "formal_performance_claim",
            }
        ),
        "accounting authority",
    )
    for field, value in authority.items():
        _require_false(value, f"accounting authority {field}")
    raw_bindings = accounting["validation_source_bindings"]
    if type(raw_bindings) is not list or len(raw_bindings) != len(_VALIDATION_SOURCE_PATHS):
        raise Day1RegistrationEvidenceError("validation source bindings are incomplete")
    for index, (raw_binding, path) in enumerate(
        zip(raw_bindings, _VALIDATION_SOURCE_PATHS, strict=True)
    ):
        binding = _require_exact_keys(
            raw_binding,
            frozenset({"mode", "object_id", "object_type", "path", "sha256"}),
            f"validation source binding {index}",
        )
        inventory_entry = inventory_by_path.get(path)
        if (
            binding["path"] != path
            or inventory_entry is None
            or any(
                binding[field] != inventory_entry[field]
                for field in ("mode", "object_id", "object_type")
            )
        ):
            raise Day1RegistrationEvidenceError("validation source binding changed identity")
        _require_lower_sha256(binding["sha256"], f"validation source SHA-256 for {path}")
    return policy_sha


def _validate_registration_and_projection(
    members: dict[str, bytes],
    payloads: dict[str, dict[str, object]],
    *,
    source_sha: str,
    run_id: int,
    correctness_sha: object,
    policy_sha: str,
) -> str:
    registration = payloads["registration-evidence.json"]
    _require_exact_keys(
        registration,
        frozenset(
            {
                "accounting_evidence_sha256",
                "correctness_artifact_sha256",
                "policy_contract_sha256",
                "run_id",
                "schema_version",
                "source_git_sha",
            }
        ),
        "registration evidence",
    )
    if (
        registration["schema_version"] != _REGISTRATION_SCHEMA
        or registration["source_git_sha"] != source_sha
        or registration["run_id"] != run_id
        or registration["accounting_evidence_sha256"]
        != _sha256(members["accounting-evidence.json"])
        or registration["correctness_artifact_sha256"] != correctness_sha
        or registration["policy_contract_sha256"] != policy_sha
    ):
        raise Day1RegistrationEvidenceError("registration evidence bindings are invalid")
    registration_sha = _sha256(members["registration-evidence.json"])
    manifest = payloads[_MANIFEST_FILENAME]
    if manifest["registration_evidence_sha256"] != registration_sha:
        raise Day1RegistrationEvidenceError("manifest registration digest is invalid")
    projection = _require_exact_keys(
        manifest["future_repository_anchor_projection"],
        frozenset(
            {
                "formal_authority_granted",
                "production_run_identity_verified",
                "repository_anchor_installed",
                "required_fields",
                "review_required",
                "schema_version",
            }
        ),
        "future anchor projection",
    )
    if (
        projection["schema_version"] != _ANCHOR_PROJECTION_SCHEMA
        or projection["review_required"] is not True
    ):
        raise Day1RegistrationEvidenceError("future anchor projection identity is invalid")
    for field in (
        "formal_authority_granted",
        "production_run_identity_verified",
        "repository_anchor_installed",
    ):
        _require_false(projection[field], f"future anchor projection {field}")
    required_fields = _require_exact_keys(
        projection["required_fields"],
        frozenset(
            {
                "artifact_behavior_inventory",
                "artifact_sha256",
                "experiment_source_git_sha",
                "registration_evidence",
                "role",
                "schema_version",
            }
        ),
        "future anchor required fields",
    )
    if required_fields != {
        "artifact_behavior_inventory": payloads["artifact-behavior-inventory.json"],
        "artifact_sha256": registration_sha,
        "experiment_source_git_sha": source_sha,
        "registration_evidence": registration,
        "role": "day1-registration",
        "schema_version": "dynamic-cssc-day1-registration-anchor-v1",
    }:
        raise Day1RegistrationEvidenceError("future anchor field projection is invalid")
    return registration_sha


def inspect_day1_registration_evidence_archive(
    archive_dir: Path,
) -> Day1RegistrationEvidenceInspection:
    """Inspect a closed archive descriptively; never grant candidate authority."""

    members = _read_archive_members(archive_dir)
    expected_checksums = "".join(
        f"{_sha256(members[name])}  {name}\n" for name in sorted(_JSON_FILENAMES)
    ).encode("ascii")
    if members[_CHECKSUMS_FILENAME] != expected_checksums:
        raise Day1RegistrationEvidenceError("SHA256SUMS is not the exact canonical checksum set")
    payloads = {name: _decode_canonical_json(members[name], name) for name in _JSON_FILENAMES}
    manifest = payloads[_MANIFEST_FILENAME]
    source_sha, source_tree = _validate_manifest(members, manifest)
    inventory = payloads["artifact-behavior-inventory.json"]
    inventory_by_path = _validate_inventory(inventory, source_sha)
    if manifest["artifact_behavior_inventory_sha256"] != _sha256(
        members["artifact-behavior-inventory.json"]
    ):
        raise Day1RegistrationEvidenceError("manifest Behavior inventory digest is invalid")
    strong_projection, run_id = _validate_workflow_and_strong(
        members,
        payloads,
        source_sha=source_sha,
        source_tree=source_tree,
    )
    policy_sha = _validate_accounting(
        members,
        payloads,
        inventory_by_path,
        source_sha=source_sha,
        source_tree=source_tree,
    )
    registration_sha = _validate_registration_and_projection(
        members,
        payloads,
        source_sha=source_sha,
        run_id=run_id,
        correctness_sha=strong_projection["artifact_sha256"],
        policy_sha=policy_sha,
    )
    return Day1RegistrationEvidenceInspection(
        archive_dir=archive_dir.resolve(),
        manifest_sha256=_sha256(members[_MANIFEST_FILENAME]),
        registration_evidence_sha256=registration_sha,
        source_git_sha=source_sha,
        source_tree_git_sha=source_tree,
        run_id=run_id,
    )


def produce_day1_registration_evidence_archive(
    output_dir: Path,
) -> Day1RegistrationEvidenceArchive:
    """Verify S1 facts, then HOLD until trustworthy production provenance exists."""

    repository_root = Path(__file__).resolve().parents[2]
    _validated_output_path(output_dir, repository_root)
    _collect_repository_facts_in_isolated_interpreter()
    try:
        _verify_production_strong_source_in_isolated_interpreter()
    except Day1RegistrationEvidenceHold as error:
        raise Day1RegistrationEvidenceHold(
            "HOLD: hardened strong source attestation and repository-owned registration "
            f"run identity are not frozen; no archive was written ({error})"
        ) from error
    raise Day1RegistrationEvidenceHold(
        "HOLD: hardened strong source attestation and repository-owned registration "
        "run identity are not frozen; no archive was written"
    )


def _produce_day1_registration_evidence_archive_for_test(
    output_dir: Path,
) -> Day1RegistrationEvidenceArchive:
    """Exercise the full transaction with one fixed, visibly non-production run id."""

    repository_root = Path(__file__).resolve().parents[2]
    _validated_output_path(output_dir, repository_root)
    facts = _collect_repository_facts_in_isolated_interpreter()
    documents = _archive_documents(
        facts,
        run_id=_PRIVATE_TEST_RUN_ID,
        run_identity_authority_state=_PRIVATE_TEST_RUN_AUTHORITY,
    )
    return _install_archive(output_dir, repository_root, documents)


__all__ = (
    "Day1RegistrationEvidenceArchive",
    "Day1RegistrationEvidenceError",
    "Day1RegistrationEvidenceHold",
    "Day1RegistrationEvidenceInspection",
    "inspect_day1_registration_evidence_archive",
    "produce_day1_registration_evidence_archive",
)
