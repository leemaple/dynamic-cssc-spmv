"""Fail-closed Git-object compatibility for publication evidence snapshots.

The module owns every Behavior Set and changed-path allowlist.  Producers may
capture the inventory for a named evidence role, but neither producers nor
consumers can substitute paths or mint a compatibility decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

EVIDENCE_COMPATIBILITY_ANCHOR_PATH = "config/evidence-compatibility-anchors.json"
STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH = "config/strong-reference-evidence-anchors.json"
DAY1_REGISTRATION_ANCHOR_PATH = "config/day1-registration-anchors.json"
_DAY2_POST_RUN_ANCHOR_PATH = "config/day2-calibration-anchors.json"
_DAY2_PROFILE_ANCHOR_PATH = "config/day2-calibration-profile-anchors.json"
BEHAVIOR_INVENTORY_SCHEMA = "dynamic-cssc-evidence-behavior-inventory-v1"
RUNTIME_EXECUTION_ISOLATION_RECEIPT_SCHEMA = "dynamic-cssc-runtime-execution-isolation-receipt-v1"
RUNTIME_EXECUTION_ISOLATION_HOLD = (
    "HOLD-until-fresh-checkout-isolated-interpreter-import-origin-wheel-lock-runtime-receipt-v1"
)
RUNTIME_EXECUTION_ISOLATION_REQUIRED_CHECKS = (
    "fresh-detached-checkout",
    "user-site-and-caller-pythonpath-disabled",
    "isolated-bytecode-cache-no-pth-sitecustomize",
    "exact-cpython-3.12.13",
    "hash-locked-wheel-set",
    "exact-import-origins-and-byte-hashes",
    "exact-analysis-invocation",
    "source-attestation-before-decode",
    "source-attestation-after-analysis",
    "source-attestation-after-render-and-atomic-install",
)


class EvidenceRole(StrEnum):
    """Repository-owned execution roles with distinct Behavior Sets."""

    ACQUISITION = "acquisition"
    TRACE = "trace"
    DAY1B = "day1b"
    DAY2 = "day2"
    ANALYZER = "analyzer"
    STRONG_CORRECTNESS = "strong-correctness"
    DAY1_REGISTRATION = "day1-registration"


class EvidenceCompatibilityError(ValueError):
    """A snapshot, artifact inventory, or repository anchor failed closed."""


class EvidenceCompatibilityHold(EvidenceCompatibilityError):
    """The repository has not implemented or frozen the requested evidence role."""


@dataclass(frozen=True, slots=True)
class AnalysisSourceAttestation:
    """Clean analyzer Git identity; runtime isolation remains a separate HOLD."""

    git_sha: str
    behavior_set_schema_version: str
    behavior_set_sha256: str
    attestation: str = "repository-clean-head"
    runtime_execution_isolation_authority_state: str = RUNTIME_EXECUTION_ISOLATION_HOLD
    runtime_execution_isolation_verified: bool = False


@dataclass(frozen=True, slots=True)
class RoleSourceAttestation:
    """Hardened clean-HEAD attestation for one repository-owned evidence role."""

    role: EvidenceRole
    git_sha: str
    behavior_set_schema_version: str
    behavior_set_sha256: str
    behavior_source_blob_sha256: Mapping[str, str]
    attestation: str = "repository-clean-head"
    runtime_execution_isolation_authority_state: str = RUNTIME_EXECUTION_ISOLATION_HOLD
    runtime_execution_isolation_verified: bool = False


@dataclass(frozen=True, slots=True)
class RepositoryDataBlob:
    """One current clean-HEAD, no-follow, repository-owned evidence data blob."""

    role: EvidenceRole
    git_sha: str
    path: str
    mode: str
    object_id: str
    sha256: str
    content: bytes


@dataclass(frozen=True, slots=True)
class HistoricalStrongSourceAttestation:
    """Descriptive Git-object identity of the historical strong witness source."""

    source_git_sha: str
    behavior_set_schema_version: str
    behavior_set_sha256: str
    behavior_source_blob_sha256: Mapping[str, str]
    reachable_ref_names: tuple[str, ...]
    formal_authority_granted: bool = False


@dataclass(frozen=True, slots=True)
class RepositoryAnchorHistoryAttestation:
    """Descriptive result of repository-owned S1/S2/S3 history verification."""

    role: EvidenceRole
    experiment_source_git_sha: str
    evidence_freeze_git_sha: str
    analysis_source_git_sha: str
    artifact_sha256: str
    receipt_sha256: str
    _anchor_document: bytes
    day1a_authority_receipt_sha256: str | None = None
    day1a_evidence_anchor_git_sha: str | None = None
    day2_profile_installation_git_sha: str | None = None
    compatibility_verified: bool = True
    runtime_execution_isolation_verified: bool = False
    formal_authority_granted: bool = False

    @property
    def artifact_behavior_inventory(self) -> dict[str, object]:
        return self._document_field("artifact_behavior_inventory")

    @property
    def registration_evidence(self) -> dict[str, object]:
        return self._document_field("registration_evidence")

    def _document_field(self, field: str) -> dict[str, object]:
        document = json.loads(self._anchor_document.decode("ascii"))
        value = document[field]
        if type(value) is not dict:  # pragma: no cover - validated before construction
            raise RuntimeError("invalid repository anchor attestation")
        return value


_ACQUISITION_BEHAVIOR_PATHS = (
    "config/params_manifest.json",
    "docs/paper/publication-preregistration-draft.md",
    "docs/research/publication-dataset-citation-record.md",
    "docs/research/publication-venues-datasets-preregistration.md",
    "pyproject.toml",
    "requirements-acquisition.txt",
    "scripts/acquire_publication_sources.py",
    "scripts/prepare_publication_traces.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/publication_acquisition.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_traces.py",
)

_TRACE_BEHAVIOR_PATHS = (
    ".github/workflows/publication-structure-pilot.yml",
    "config/params_manifest.json",
    "docs/paper/publication-preregistration-draft.md",
    "docs/research/publication-venues-datasets-preregistration.md",
    "pyproject.toml",
    "requirements-publication.txt",
    "scripts/prepare_publication_traces.py",
    "scripts/run_publication_structure_pilot.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/publication_acquisition.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_structure_pilot.py",
    "src/dynamic_cssc/publication_traces.py",
)

_ANALYZER_BEHAVIOR_PATHS = (
    "config/publication-runtime-policy.json",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "requirements-publication.txt",
    "scripts/analyze_publication_results.py",
    "scripts/run_publication_analysis_isolated.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/day2_calibration_authority.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/publication_runtime.py",
    "src/dynamic_cssc/publication_schedule.py",
    "src/dynamic_cssc/publication_statistics.py",
    "src/dynamic_cssc/publication_traces.py",
)

_DAY2_BEHAVIOR_PATHS = (
    ".github/workflows/day2-publication-calibration.yml",
    "config/experiment_plan_publication.json",
    "config/params_manifest.json",
    "cpp/CMakeLists.txt",
    "cpp/include/args.hpp",
    "cpp/microbench.cpp",
    "docs/decisions/0013-anchor-day2-serialized-size-profile.md",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "scripts/apply_microbench.py",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
    "scripts/capture_day2_github_metadata.py",
    "scripts/package_review_bundle.py",
    "scripts/propose_day2_calibration_post_run_anchor.py",
    "scripts/run_day2_calibration_isolated.py",
    "scripts/validate_manifest.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cli.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/day1a_export.py",
    "src/dynamic_cssc/day2_calibration_authority.py",
    "src/dynamic_cssc/day2_calibration_github.py",
    "src/dynamic_cssc/day2_calibration_postrun.py",
    "src/dynamic_cssc/day2_calibration_profile.py",
    "src/dynamic_cssc/day2_calibration_producer.py",
    "src/dynamic_cssc/day2_calibration_runtime.py",
    "src/dynamic_cssc/day1_registry.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/metrics.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_primitive_accounting.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/report.py",
    "src/dynamic_cssc/selection.py",
    "src/dynamic_cssc/simulator.py",
    "src/dynamic_cssc/span80.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "src/dynamic_cssc/workloads.py",
)

_STRONG_CORRECTNESS_BEHAVIOR_PATHS = (
    ".github/workflows/strong-whole-query-witness.yml",
    "config/params_manifest.json",
    "config/params_manifest.schema.json",
    "cpp/CMakeLists.txt",
    "cpp/include/args.hpp",
    "cpp/strong_whole_query_witness.cpp",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
    "scripts/make_strong_whole_query_witness_binding.py",
    "scripts/property_contract.py",
    "scripts/property_contract_spec.py",
    "scripts/validate_manifest.py",
    "scripts/validate_property_contract.py",
    "scripts/validate_strong_whole_query_witness.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "src/dynamic_cssc/strong_whole_query_witness.py",
    "tests/test_strong_property_contract.py",
)

_HISTORICAL_STRONG_CORRECTNESS_BEHAVIOR_PATHS = (
    ".github/workflows/strong-whole-query-witness.yml",
    "config/params_manifest.json",
    "config/params_manifest.schema.json",
    "cpp/CMakeLists.txt",
    "cpp/include/args.hpp",
    "cpp/strong_whole_query_witness.cpp",
    "pyproject.toml",
    "requirements-ci.txt",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
    "scripts/make_strong_whole_query_witness_binding.py",
    "scripts/property_contract.py",
    "scripts/property_contract_spec.py",
    "scripts/validate_manifest.py",
    "scripts/validate_property_contract.py",
    "scripts/validate_strong_whole_query_witness.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_whole_query_witness.py",
    "tests/test_strong_property_contract.py",
)
_HISTORICAL_STRONG_BEHAVIOR_SCHEMA = "dynamic-cssc-historical-strong-correctness-behavior-set-v1"

_DAY1_REGISTRATION_BEHAVIOR_PATHS = (
    ".github/workflows/day1-cost-model.yml",
    ".github/workflows/day1a-publication-cost-model.yml",
    ".github/workflows/day1-registration-evidence.yml",
    "config/experiment_plan.json",
    "config/experiment_plan_publication.json",
    "config/params_manifest.json",
    "config/params_manifest.schema.json",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "scripts/aggregate_day1_shards.py",
    "scripts/package_review_bundle.py",
    "scripts/produce_day1_registration_evidence.py",
    "scripts/replay_day1_shard.py",
    "scripts/run_day1_suite.py",
    "scripts/validate_manifest.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/day1a_export.py",
    "src/dynamic_cssc/day1_registration_evidence.py",
    "src/dynamic_cssc/day1_registry.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/metrics.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/preflight.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_traces.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/report.py",
    "src/dynamic_cssc/selection.py",
    "src/dynamic_cssc/simulator.py",
    "src/dynamic_cssc/span80.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "src/dynamic_cssc/workloads.py",
    "tests/test_day1a_publication_workflow_contract.py",
    "tests/test_day1_causal_runner.py",
    "tests/test_day1_runner.py",
    "tests/test_day1_registration_evidence.py",
    "tests/test_day1_registry.py",
    "tests/test_day1_shard_aggregation.py",
    "tests/test_day1_workflow_contract.py",
    "tests/test_query_accounting.py",
    "tests/test_report.py",
    "tests/test_simulator.py",
    "tests/test_strong_day1_simulator.py",
    "tests/test_strategy_state.py",
    "tests/test_strong_strategy_state.py",
)

# This is deliberately a PRE-S1 exact reviewed v9 schema-source inventory bound
# by the first resource amendment.  Keep it immutable so later source can
# reconstruct that historical inventory without treating the current path set
# as retroactive.
_DAY1B_RESOURCE_AMENDMENT_SCHEMA_SOURCE_BEHAVIOR_PATHS = (
    ".github/workflows/publication-day1b-preparatory.yml",
    "config/params_manifest.json",
    "config/params_manifest.schema.json",
    "config/publication-day1b-resource-policy.json",
    "cpp/CMakeLists.txt",
    "cpp/include/args.hpp",
    "cpp/openfhe_query_runner.cpp",
    "docs/decisions/0003-f1m-hidden-rowmap.md",
    "docs/decisions/0005-output-plan-overlap-blinding.md",
    "docs/decisions/0006-persistent-strategy-snapshots.md",
    "docs/decisions/0007-anonymous-fixed-segment-primitive.md",
    "docs/decisions/0008-strong-whole-query-execution-bundle.md",
    "docs/decisions/0009-fail-closed-role-aware-day1-catalog.md",
    "docs/decisions/0010-separate-experiment-and-evidence-freeze-snapshots.md",
    "docs/decisions/0011-post-registration-day2-profile-anchor.md",
    "docs/decisions/0012-window-weighted-day1b-accounting.md",
    "docs/paper/publication-preregistration-draft.md",
    "pyproject.toml",
    "requirements-ci.txt",
    "requirements-publication.txt",
    "scripts/bootstrap_openfhe.sh",
    "scripts/build_cpp.sh",
    "scripts/run_openfhe_query_smoke.py",
    "scripts/run_publication_day1b.py",
    "scripts/validate_manifest.py",
    "src/dynamic_cssc/__init__.py",
    "src/dynamic_cssc/cloud_execution_plan.py",
    "src/dynamic_cssc/cssc.py",
    "src/dynamic_cssc/day2_calibration_authority.py",
    "src/dynamic_cssc/day1_registry.py",
    "src/dynamic_cssc/evidence_compatibility.py",
    "src/dynamic_cssc/events.py",
    "src/dynamic_cssc/manifest.py",
    "src/dynamic_cssc/mask_ledger.py",
    "src/dynamic_cssc/metrics.py",
    "src/dynamic_cssc/openfhe_query_runner.py",
    "src/dynamic_cssc/openfhe_query_runtime.py",
    "src/dynamic_cssc/ordinary_query_lifecycle.py",
    "src/dynamic_cssc/output_plan.py",
    "src/dynamic_cssc/plaintext_oracle.py",
    "src/dynamic_cssc/publication_artifact_install.py",
    "src/dynamic_cssc/publication_day1b.py",
    "src/dynamic_cssc/publication_day1b_accounting.py",
    "src/dynamic_cssc/publication_day1b_worker_protocol.py",
    "src/dynamic_cssc/publication_primitive_accounting.py",
    "src/dynamic_cssc/publication_schedule.py",
    "src/dynamic_cssc/publication_statistics.py",
    "src/dynamic_cssc/publication_traces.py",
    "src/dynamic_cssc/query_compiler.py",
    "src/dynamic_cssc/selection.py",
    "src/dynamic_cssc/simulator.py",
    "src/dynamic_cssc/strategy_state.py",
    "src/dynamic_cssc/strong_execution.py",
    "src/dynamic_cssc/strong_packed_coo.py",
    "src/dynamic_cssc/strong_reference_receipt.py",
    "tests/test_evidence_compatibility.py",
    "tests/test_openfhe_query_runner.py",
    "tests/test_openfhe_query_runtime.py",
    "tests/test_ordinary_query_lifecycle.py",
    "tests/test_publication_day1b.py",
    "tests/test_publication_day1b_accounting.py",
    "tests/test_publication_day1b_worker_protocol.py",
    "tests/test_publication_day1b_workflow_contract.py",
    "tests/test_publication_primitive_accounting.py",
    "tests/test_query_accounting.py",
    "tests/test_strong_day1_simulator.py",
)

# This remains a PRE-S1 preparatory source inventory.  It now freezes the
# reviewed non-authorizing resource amendment and its review receipt, but it
# still cannot authorize dispatch or substitute for the production
# worker/runtime, profile, or anchors.
_DAY1B_PREPARATORY_BEHAVIOR_PATHS = (
    *_DAY1B_RESOURCE_AMENDMENT_SCHEMA_SOURCE_BEHAVIOR_PATHS,
    "config/publication-day1b-resource-amendment.json",
    "docs/decisions/0013-anchor-day2-serialized-size-profile.md",
    "docs/reviews/day1b-resource-amendment-review-2026-08-25.md",
    "src/dynamic_cssc/day2_openfhe_key_plan.py",
    "src/dynamic_cssc/openfhe_runtime_admission.py",
    "src/dynamic_cssc/publication_day1b_aggregate_bounds.py",
    "src/dynamic_cssc/publication_day1b_expected_counts.py",
    "src/dynamic_cssc/publication_day1b_f1m_aggregation.py",
    "src/dynamic_cssc/publication_day1b_key_framing.py",
    "src/dynamic_cssc/publication_day1b_layout_execution.py",
    "src/dynamic_cssc/publication_day1b_replay_execution.py",
    "src/dynamic_cssc/publication_day1b_metadata_framing.py",
    "src/dynamic_cssc/publication_day1b_openfhe_execution.py",
    "src/dynamic_cssc/publication_day1b_scratch.py",
    "tests/test_publication_day1b_aggregate_bounds.py",
    "tests/test_publication_day1b_expected_counts.py",
    "tests/test_publication_day1b_f1m_aggregation.py",
    "tests/test_publication_day1b_key_framing.py",
    "tests/test_publication_day1b_layout_execution.py",
    "tests/test_publication_day1b_replay_execution.py",
    "tests/test_publication_day1b_metadata_framing.py",
    "tests/test_publication_day1b_openfhe_execution.py",
    "tests/test_publication_day1b_scratch.py",
    "tests/test_day2_openfhe_key_plan.py",
    "tests/test_openfhe_runtime_admission.py",
    "tests/test_strong_execution_bundle.py",
    "tests/test_strong_strategy_state.py",
)

_ROLE_BEHAVIOR_PATHS: dict[EvidenceRole, tuple[str, ...] | None] = {
    EvidenceRole.ACQUISITION: _ACQUISITION_BEHAVIOR_PATHS,
    EvidenceRole.TRACE: _TRACE_BEHAVIOR_PATHS,
    EvidenceRole.DAY1B: _DAY1B_PREPARATORY_BEHAVIOR_PATHS,
    EvidenceRole.DAY2: _DAY2_BEHAVIOR_PATHS,
    EvidenceRole.ANALYZER: _ANALYZER_BEHAVIOR_PATHS,
    EvidenceRole.STRONG_CORRECTNESS: _STRONG_CORRECTNESS_BEHAVIOR_PATHS,
    EvidenceRole.DAY1_REGISTRATION: _DAY1_REGISTRATION_BEHAVIOR_PATHS,
}

_ROLE_BEHAVIOR_SCHEMAS = {
    EvidenceRole.ACQUISITION: "dynamic-cssc-acquisition-behavior-set-v2",
    EvidenceRole.TRACE: "dynamic-cssc-trace-behavior-set-v2",
    EvidenceRole.DAY1B: "dynamic-cssc-day1b-preparatory-behavior-set-v31",
    EvidenceRole.DAY2: "dynamic-cssc-day2-behavior-set-v6",
    EvidenceRole.ANALYZER: "dynamic-cssc-publication-analyzer-behavior-set-v2",
    EvidenceRole.STRONG_CORRECTNESS: "dynamic-cssc-strong-correctness-behavior-set-v1",
    EvidenceRole.DAY1_REGISTRATION: "dynamic-cssc-day1-registration-behavior-set-v4",
}

_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_ROLE_EVIDENCE_ONLY_PATHS = {
    **{
        role: (EVIDENCE_COMPATIBILITY_ANCHOR_PATH,)
        for role in EvidenceRole
        if role is not EvidenceRole.DAY2
    },
    EvidenceRole.DAY2: (
        _DAY2_POST_RUN_ANCHOR_PATH,
        _DAY2_PROFILE_ANCHOR_PATH,
        EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
    ),
    EvidenceRole.STRONG_CORRECTNESS: (STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,),
    EvidenceRole.DAY1_REGISTRATION: (DAY1_REGISTRATION_ANCHOR_PATH,),
}
_REPOSITORY_DATA_ONLY_ANCHOR_PATHS = (
    _DAY2_POST_RUN_ANCHOR_PATH,
    _DAY2_PROFILE_ANCHOR_PATH,
    EVIDENCE_COMPATIBILITY_ANCHOR_PATH,
)
_ROLE_ANALYSIS_ONLY_PATHS = {
    # Artifact roles may observe later monotonic evidence-data additions. The
    # Analyzer has no post-run compatibility phase at all: its exact S3 and
    # isolated same-run admission are the authority boundary.
    role: (() if role is EvidenceRole.ANALYZER else _REPOSITORY_DATA_ONLY_ANCHOR_PATHS)
    for role in EvidenceRole
}

_DAY1_REGISTRATION_POST_FREEZE_DATA_PATHS = _REPOSITORY_DATA_ONLY_ANCHOR_PATHS


@dataclass(frozen=True, slots=True)
class _ReceiptBinding:
    document: bytes


class EvidenceCompatibilityReceipt:
    """Descriptive output minted after verification; never an authority input."""

    __slots__ = ("_binding",)

    def __new__(cls) -> EvidenceCompatibilityReceipt:
        raise TypeError(
            "EvidenceCompatibilityReceipt can only be minted by repository verification"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("EvidenceCompatibilityReceipt is read-only")

    def __bool__(self) -> bool:
        raise TypeError("compatibility receipts are not caller-supplied booleans")

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(self._binding.document).hexdigest()

    @property
    def role(self) -> EvidenceRole:
        return EvidenceRole(self.to_document()["role"])

    @property
    def experiment_source_git_sha(self) -> str:
        return str(self.to_document()["experiment_source"]["git_sha"])

    @property
    def evidence_freeze_git_sha(self) -> str:
        return str(self.to_document()["evidence_freeze_source"]["git_sha"])

    @property
    def analysis_source_git_sha(self) -> str:
        return str(self.to_document()["analysis_source"]["git_sha"])

    @property
    def runtime_execution_isolation_verified(self) -> bool:
        return False

    @property
    def runtime_execution_isolation_state(self) -> str:
        return RUNTIME_EXECUTION_ISOLATION_HOLD

    def to_document(self) -> dict[str, object]:
        """Return a detached canonical receipt document."""

        document = json.loads(self._binding.document.decode("ascii"))
        if type(document) is not dict:  # pragma: no cover - guarded at minting
            raise RuntimeError("invalid repository-minted compatibility receipt")
        return document


def _mint_receipt(document: dict[str, object]) -> EvidenceCompatibilityReceipt:
    receipt = object.__new__(EvidenceCompatibilityReceipt)
    object.__setattr__(receipt, "_binding", _ReceiptBinding(_canonical_json_bytes(document)))
    return receipt


@dataclass(frozen=True, slots=True)
class _RuntimeAdmissionBinding:
    audit_document: bytes
    repository_root: Path
    output_directory: Path


class RuntimeAdmissionCapability:
    """Ephemeral in-process runtime authority; its audit projection is not replayable."""

    __slots__ = ("_binding",)

    def __new__(cls) -> RuntimeAdmissionCapability:
        raise TypeError(
            "RuntimeAdmissionCapability can only be minted by central runtime admission"
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("RuntimeAdmissionCapability is read-only")

    def __bool__(self) -> bool:
        raise TypeError("runtime admission capabilities are not caller-supplied booleans")

    @property
    def runtime_execution_isolation_verified(self) -> bool:
        _require_runtime_admission_capability(self)
        return True

    @property
    def formal_authority_granted(self) -> bool:
        _require_runtime_admission_capability(self)
        return False

    @property
    def analysis_source_git_sha(self) -> str:
        return str(self.to_audit_document()["analysis_source_git_sha"])

    @property
    def receipt_sha256(self) -> str:
        binding = _require_runtime_admission_capability(self)
        return hashlib.sha256(binding.audit_document).hexdigest()

    def to_audit_document(self) -> dict[str, object]:
        """Return non-authoritative audit metadata without a replayable success bit."""

        binding = _require_runtime_admission_capability(self)
        document = json.loads(binding.audit_document.decode("ascii"))
        if type(document) is not dict:  # pragma: no cover - minting invariant
            raise RuntimeError("invalid runtime admission audit document")
        return document


_RUNTIME_ADMISSION_LOCK = threading.Lock()
_LIVE_RUNTIME_ADMISSIONS: dict[
    int, tuple[RuntimeAdmissionCapability, _RuntimeAdmissionBinding]
] = {}


def _require_runtime_admission_capability(
    capability: object,
) -> _RuntimeAdmissionBinding:
    if type(capability) is not RuntimeAdmissionCapability:
        raise EvidenceCompatibilityError(
            "runtime authority requires an exact central admission capability"
        )
    with _RUNTIME_ADMISSION_LOCK:
        active = _LIVE_RUNTIME_ADMISSIONS.get(id(capability))
    binding = getattr(capability, "_binding", None)
    if active is None or active[0] is not capability or active[1] is not binding:
        raise EvidenceCompatibilityError(
            "runtime admission capability was not minted by central verification"
        )
    return binding


def _canonical_json_bytes(payload: object) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise EvidenceCompatibilityError(
            "evidence compatibility payload is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _require_role(role: object) -> EvidenceRole:
    if type(role) is not EvidenceRole:
        raise EvidenceCompatibilityError("evidence role must be an exact EvidenceRole")
    return role


def _behavior_paths(role: EvidenceRole) -> tuple[str, ...]:
    paths = _ROLE_BEHAVIOR_PATHS[role]
    if paths is None:
        raise EvidenceCompatibilityHold(
            "HOLD: no repository-owned publication Day1B producer Behavior Set exists"
        )
    if not paths:
        raise EvidenceCompatibilityHold(
            f"HOLD: the repository-owned {role.value} Behavior Set is not frozen"
        )
    return paths


def _git(repository_root: Path, *arguments: str) -> bytes:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    try:
        completed = subprocess.run(
            ("git", "--no-replace-objects", "-C", str(repository_root), *arguments),
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as error:
        raise EvidenceCompatibilityError("cannot execute the repository-owned Git check") from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
        raise EvidenceCompatibilityError(
            f"evidence compatibility Git check failed: {detail or 'Git command failed'}"
        )
    return completed.stdout


def _repository(repository_root: Path) -> Path:
    if not isinstance(repository_root, Path) or not repository_root.is_dir():
        raise EvidenceCompatibilityError("repository_root must be an existing directory")
    repository_root = repository_root.resolve()
    reported = Path(
        _git(repository_root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    ).resolve()
    if reported != repository_root:
        raise EvidenceCompatibilityError("repository_root must be the exact Git top level")
    if (
        _git(repository_root, "rev-parse", "--is-shallow-repository").decode("ascii").strip()
        != "false"
    ):
        raise EvidenceCompatibilityError("shallow repositories cannot prove full ancestry")
    if _git(repository_root, "rev-parse", "--show-object-format").decode("ascii").strip() != (
        "sha1"
    ):
        raise EvidenceCompatibilityError(
            "evidence compatibility currently requires exact 40-digit SHA-1 Git objects"
        )
    replacement_refs = _git(
        repository_root,
        "for-each-ref",
        "--format=%(refname)",
        "refs/replace/",
    )
    if replacement_refs:
        raise EvidenceCompatibilityError("Git replacement refs are forbidden")
    return repository_root


def _exact_commit(repository_root: Path, value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise EvidenceCompatibilityError(f"{field} must be an exact lowercase 40-digit Git SHA")
    resolved = _git(repository_root, "rev-parse", "--verify", f"{value}^{{commit}}")
    resolved_text = resolved.decode("ascii").strip()
    if resolved_text != value:
        raise EvidenceCompatibilityError(f"{field} must resolve to that exact commit")
    return value


def _tree_entries(
    repository_root: Path,
    source_git_sha: str,
    paths: tuple[str, ...],
) -> list[dict[str, str]]:
    output = _git(
        repository_root,
        "ls-tree",
        "-z",
        "--full-tree",
        source_git_sha,
        "--",
        *paths,
    )
    entries: dict[str, dict[str, str]] = {}
    for raw_entry in output.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        parts = metadata.split(b" ")
        if separator != b"\t" or len(parts) != 3:
            raise EvidenceCompatibilityError("Git returned a malformed Behavior Set entry")
        try:
            mode, object_type, object_id = (part.decode("ascii") for part in parts)
            relative_path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceCompatibilityError("Behavior Set paths must be UTF-8") from error
        if relative_path in entries:
            raise EvidenceCompatibilityError("Git returned duplicate Behavior Set entries")
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise EvidenceCompatibilityError(
                f"Behavior Set entry must be a regular Git blob: {relative_path}"
            )
        entries[relative_path] = {
            "mode": mode,
            "object_id": object_id,
            "object_type": object_type,
            "path": relative_path,
        }
    if set(entries) != set(paths):
        raise EvidenceCompatibilityError(
            "repository Behavior Set is incomplete; "
            f"missing={sorted(set(paths) - set(entries))}, "
            f"extra={sorted(set(entries) - set(paths))}"
        )
    return [entries[path] for path in paths]


def _full_tree(
    repository_root: Path,
    source_git_sha: str,
) -> dict[str, tuple[str, str, str]]:
    output = _git(
        repository_root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        source_git_sha,
    )
    entries: dict[str, tuple[str, str, str]] = {}
    for raw_entry in output.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        parts = metadata.split(b" ")
        if separator != b"\t" or len(parts) != 3:
            raise EvidenceCompatibilityError("Git returned a malformed tree entry")
        try:
            mode, object_type, object_id = (part.decode("ascii") for part in parts)
            relative_path = raw_path.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceCompatibilityError("repository tree paths must be UTF-8") from error
        if relative_path in entries:
            raise EvidenceCompatibilityError("Git returned duplicate repository tree entries")
        entries[relative_path] = (mode, object_type, object_id)
    return entries


def _changed_paths(
    before: dict[str, tuple[str, str, str]],
    after: dict[str, tuple[str, str, str]],
) -> tuple[str, ...]:
    return tuple(
        path for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)
    )


def _require_changed_data_blobs(
    paths: tuple[str, ...],
    target_tree: dict[str, tuple[str, str, str]],
    transition: str,
) -> None:
    for path in paths:
        entry = target_tree.get(path)
        if entry is None or entry[:2] != ("100644", "blob"):
            raise EvidenceCompatibilityError(
                f"{transition} changed anchor must end as a Git 100644 data blob: {path}"
            )


def _decode_canonical_json(content: bytes, field: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise EvidenceCompatibilityError(f"{field} contains a duplicate JSON key")
            document[key] = value
        return document

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                EvidenceCompatibilityError(f"{field} contains non-finite JSON: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceCompatibilityError(f"{field} is not canonical UTF-8 JSON") from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise EvidenceCompatibilityError(f"{field} is not canonical JSON")
    return document


def _anchor_set_at(
    repository_root: Path,
    source_git_sha: str,
) -> tuple[dict[str, object], ...]:
    entry = _tree_entries(
        repository_root,
        source_git_sha,
        (EVIDENCE_COMPATIBILITY_ANCHOR_PATH,),
    )[0]
    if entry["mode"] != "100644":
        raise EvidenceCompatibilityError(
            "evidence compatibility anchor set must be a non-executable Git 100644 blob"
        )
    content = _git(repository_root, "cat-file", "blob", entry["object_id"])
    document = _decode_canonical_json(
        content,
        f"{EVIDENCE_COMPATIBILITY_ANCHOR_PATH}@{source_git_sha}",
    )
    if set(document) != {"anchors", "schema_version"}:
        raise EvidenceCompatibilityError("evidence compatibility anchor-set keys must be exact")
    if document["schema_version"] != "dynamic-cssc-evidence-compatibility-anchor-set-v1":
        raise EvidenceCompatibilityError("evidence compatibility anchor-set schema is not frozen")
    raw_anchors = document["anchors"]
    if type(raw_anchors) is not list:
        raise EvidenceCompatibilityError("evidence compatibility anchors must be an array")
    anchors: list[dict[str, object]] = []
    expected_keys = {
        "artifact_sha256",
        "behavior_set_schema_version",
        "behavior_set_sha256",
        "experiment_source_git_sha",
        "role",
        "schema_version",
    }
    for index, raw_anchor in enumerate(raw_anchors):
        if type(raw_anchor) is not dict or set(raw_anchor) != expected_keys:
            raise EvidenceCompatibilityError(
                f"evidence compatibility anchor {index} keys must be exact"
            )
        if raw_anchor["schema_version"] != "dynamic-cssc-evidence-compatibility-anchor-v1":
            raise EvidenceCompatibilityError(
                f"evidence compatibility anchor {index} schema is not frozen"
            )
        try:
            anchor_role = EvidenceRole(raw_anchor["role"])
        except (TypeError, ValueError) as error:
            raise EvidenceCompatibilityError(
                f"evidence compatibility anchor {index} role is not frozen"
            ) from error
        if raw_anchor["behavior_set_schema_version"] != _ROLE_BEHAVIOR_SCHEMAS[anchor_role]:
            raise EvidenceCompatibilityError(
                f"evidence compatibility anchor {index} Behavior Set schema mismatch"
            )
        if (
            type(raw_anchor["experiment_source_git_sha"]) is not str
            or _LOWER_GIT_SHA.fullmatch(raw_anchor["experiment_source_git_sha"]) is None
        ):
            raise EvidenceCompatibilityError(
                f"evidence compatibility anchor {index} source SHA is malformed"
            )
        for field in ("artifact_sha256", "behavior_set_sha256"):
            if (
                type(raw_anchor[field]) is not str
                or _LOWER_SHA256.fullmatch(raw_anchor[field]) is None
            ):
                raise EvidenceCompatibilityError(
                    f"evidence compatibility anchor {index} {field} is malformed"
                )
        anchors.append(raw_anchor)
    canonical_order = sorted(
        anchors,
        key=lambda anchor: (
            str(anchor["role"]),
            str(anchor["experiment_source_git_sha"]),
            str(anchor["artifact_sha256"]),
        ),
    )
    if anchors != canonical_order or len(
        {
            (
                anchor["role"],
                anchor["experiment_source_git_sha"],
                anchor["artifact_sha256"],
            )
            for anchor in anchors
        }
    ) != len(anchors):
        raise EvidenceCompatibilityError(
            "evidence compatibility anchors must be unique and canonically ordered"
        )
    return tuple(anchors)


def _compatibility_anchor_records_at(
    repository_root: Path,
    source_git_sha: str,
    tree: dict[str, tuple[str, str, str]],
) -> tuple[bytes, ...]:
    if EVIDENCE_COMPATIBILITY_ANCHOR_PATH not in tree:
        return ()
    return tuple(
        _canonical_json_bytes(anchor) for anchor in _anchor_set_at(repository_root, source_git_sha)
    )


def _singleton_data_anchor_records_at(
    repository_root: Path,
    source_git_sha: str,
    tree: dict[str, tuple[str, str, str]],
    *,
    relative_path: str,
    label: str,
    schema_version: str | tuple[str, ...],
) -> tuple[bytes, ...]:
    entry = tree.get(relative_path)
    if entry is None:
        return ()
    mode, object_type, object_id = entry
    if mode != "100644" or object_type != "blob":
        raise EvidenceCompatibilityError(
            f"{label} anchor set must be a non-executable Git 100644 data blob"
        )
    content = _git(repository_root, "cat-file", "blob", object_id)
    document = _decode_canonical_json(
        content,
        f"{relative_path}@{source_git_sha}",
    )
    if set(document) != {"anchors", "schema_version"}:
        raise EvidenceCompatibilityError(f"{label} anchor-set keys must be exact")
    allowed_schema_versions = (
        (schema_version,) if type(schema_version) is str else schema_version
    )
    if (
        not allowed_schema_versions
        or any(type(value) is not str or not value for value in allowed_schema_versions)
        or document["schema_version"] not in allowed_schema_versions
    ):
        raise EvidenceCompatibilityError(f"{label} anchor-set schema is not frozen")
    anchors = document["anchors"]
    if type(anchors) is not list or len(anchors) > 1:
        raise EvidenceCompatibilityError(
            f"{label} anchor set must contain zero or one binding"
        )
    if any(type(anchor) is not dict for anchor in anchors):
        raise EvidenceCompatibilityError(f"{label} binding must be a JSON object")
    return tuple(_canonical_json_bytes(anchor) for anchor in anchors)


def _day2_post_run_anchor_records_at(
    repository_root: Path,
    source_git_sha: str,
    tree: dict[str, tuple[str, str, str]],
) -> tuple[bytes, ...]:
    records = _singleton_data_anchor_records_at(
        repository_root,
        source_git_sha,
        tree,
        relative_path=_DAY2_POST_RUN_ANCHOR_PATH,
        label="Day2 post-run",
        schema_version=(
            "dynamic-cssc-day2-calibration-post-run-anchor-set-v4",
            "dynamic-cssc-day2-calibration-post-run-anchor-set-v6",
        ),
    )
    if _DAY2_POST_RUN_ANCHOR_PATH not in tree:
        return records
    content = _git(
        repository_root,
        "cat-file",
        "blob",
        tree[_DAY2_POST_RUN_ANCHOR_PATH][2],
    )
    document = _decode_canonical_json(
        content,
        f"{_DAY2_POST_RUN_ANCHOR_PATH}@{source_git_sha}",
    )
    if (
        records
        and document["schema_version"]
        == "dynamic-cssc-day2-calibration-post-run-anchor-set-v4"
    ):
        raise EvidenceCompatibilityError(
            "legacy Day2 post-run anchor set may only be empty"
        )
    return records


def _day2_profile_anchor_records_at(
    repository_root: Path,
    source_git_sha: str,
    tree: dict[str, tuple[str, str, str]],
) -> tuple[bytes, ...]:
    records = _singleton_data_anchor_records_at(
        repository_root,
        source_git_sha,
        tree,
        relative_path=_DAY2_PROFILE_ANCHOR_PATH,
        label="Day2 profile",
        schema_version="dynamic-cssc-day2-calibration-profile-anchor-set-v3",
    )
    if _DAY2_PROFILE_ANCHOR_PATH not in tree:
        return records
    content = _git(
        repository_root,
        "cat-file",
        "blob",
        tree[_DAY2_PROFILE_ANCHOR_PATH][2],
    )
    from dynamic_cssc.day2_calibration_authority import (
        Day2CalibrationAuthorityError,
        validate_day2_calibration_profile_anchor_document,
    )

    try:
        validate_day2_calibration_profile_anchor_document(content)
    except Day2CalibrationAuthorityError as error:
        raise EvidenceCompatibilityError(
            f"Day2 profile anchor binding is malformed: {error}"
        ) from error
    return records


def _day1_registration_anchors_at(
    repository_root: Path,
    source_git_sha: str,
    *,
    require_file: bool,
) -> tuple[dict[str, object], ...]:
    tree = _full_tree(repository_root, source_git_sha)
    entry = tree.get(DAY1_REGISTRATION_ANCHOR_PATH)
    if entry is None:
        if require_file:
            raise EvidenceCompatibilityError(
                "Day1 registration anchor set must exist at the experiment snapshot"
            )
        return ()
    mode, object_type, object_id = entry
    if mode != "100644" or object_type != "blob":
        raise EvidenceCompatibilityError(
            "Day1 registration anchor set must be a non-executable Git data blob"
        )
    content = _git(repository_root, "cat-file", "blob", object_id)
    document = _decode_canonical_json(
        content,
        f"{DAY1_REGISTRATION_ANCHOR_PATH}@{source_git_sha}",
    )
    if set(document) != {"anchors", "schema_version"}:
        raise EvidenceCompatibilityError("Day1 registration anchor-set keys must be exact")
    if document["schema_version"] != "dynamic-cssc-day1-registration-anchor-set-v1":
        raise EvidenceCompatibilityError("Day1 registration anchor-set schema is not frozen")
    raw_anchors = document["anchors"]
    if type(raw_anchors) is not list or len(raw_anchors) > 1:
        raise EvidenceCompatibilityError(
            "Day1 registration anchor set permits at most one canonical record"
        )
    if not raw_anchors:
        return ()
    raw_anchor = raw_anchors[0]
    expected_keys = {
        "artifact_behavior_inventory",
        "artifact_sha256",
        "experiment_source_git_sha",
        "registration_evidence",
        "role",
        "schema_version",
    }
    if type(raw_anchor) is not dict or set(raw_anchor) != expected_keys:
        raise EvidenceCompatibilityError("Day1 registration anchor keys must be exact")
    if (
        raw_anchor["schema_version"] != "dynamic-cssc-day1-registration-anchor-v1"
        or raw_anchor["role"] != EvidenceRole.DAY1_REGISTRATION.value
    ):
        raise EvidenceCompatibilityError("Day1 registration anchor identity is not frozen")
    experiment_sha = raw_anchor["experiment_source_git_sha"]
    artifact_sha256 = raw_anchor["artifact_sha256"]
    if type(experiment_sha) is not str or _LOWER_GIT_SHA.fullmatch(experiment_sha) is None:
        raise EvidenceCompatibilityError(
            "Day1 registration experiment source must be an exact Git SHA"
        )
    if type(artifact_sha256) is not str or _LOWER_SHA256.fullmatch(artifact_sha256) is None:
        raise EvidenceCompatibilityError(
            "Day1 registration artifact digest must be a lowercase SHA-256"
        )
    registration = raw_anchor["registration_evidence"]
    inventory = raw_anchor["artifact_behavior_inventory"]
    if type(registration) is not dict or type(inventory) is not dict:
        raise EvidenceCompatibilityError(
            "Day1 registration artifact and Behavior inventory must be objects"
        )
    if registration.get("source_git_sha") != experiment_sha:
        raise EvidenceCompatibilityError(
            "Day1 registration artifact source does not match its experiment snapshot"
        )
    if hashlib.sha256(_canonical_json_bytes(registration)).hexdigest() != artifact_sha256:
        raise EvidenceCompatibilityError(
            "Day1 registration artifact digest does not match its canonical bytes"
        )
    return (raw_anchor,)


def _required_post_run_anchor(
    repository_root: Path,
    *,
    role: EvidenceRole,
    experiment_source_git_sha: str,
    evidence_freeze_git_sha: str,
    analysis_source_git_sha: str,
    artifact_sha256: str,
    behavior_set_sha256: str,
) -> dict[str, object]:
    expected = {
        "artifact_sha256": artifact_sha256,
        "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
        "behavior_set_sha256": behavior_set_sha256,
        "experiment_source_git_sha": experiment_source_git_sha,
        "role": role.value,
        "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
    }
    experiment_anchors = _anchor_set_at(repository_root, experiment_source_git_sha)
    evidence_anchors = _anchor_set_at(repository_root, evidence_freeze_git_sha)
    analysis_anchors = _anchor_set_at(repository_root, analysis_source_git_sha)
    if expected in experiment_anchors:
        raise EvidenceCompatibilityError("artifact anchor must be installed after the experiment")
    if evidence_anchors.count(expected) != 1:
        raise EvidenceCompatibilityError(
            "exact post-run artifact anchor is absent from the evidence-freeze snapshot"
        )
    if analysis_anchors.count(expected) != 1:
        raise EvidenceCompatibilityError(
            "exact post-run artifact anchor is absent from the analysis snapshot"
        )
    experiment_records = {_canonical_json_bytes(anchor) for anchor in experiment_anchors}
    evidence_records = {_canonical_json_bytes(anchor) for anchor in evidence_anchors}
    analysis_records = {_canonical_json_bytes(anchor) for anchor in analysis_anchors}
    if not experiment_records <= evidence_records:
        raise EvidenceCompatibilityError(
            "evidence-freeze anchor set may not remove an existing repository anchor"
        )
    if not evidence_records <= analysis_records:
        raise EvidenceCompatibilityError(
            "analysis snapshot may not remove or retarget an evidence-freeze anchor"
        )
    expected_record = _canonical_json_bytes(expected)
    _verify_data_anchor_history(
        repository_root,
        start_git_sha=experiment_source_git_sha,
        end_git_sha=evidence_freeze_git_sha,
        allowed_paths=_REPOSITORY_DATA_ONLY_ANCHOR_PATHS,
        history_label="experiment-to-evidence history",
    )
    _verify_data_anchor_history(
        repository_root,
        start_git_sha=evidence_freeze_git_sha,
        end_git_sha=analysis_source_git_sha,
        allowed_paths=_REPOSITORY_DATA_ONLY_ANCHOR_PATHS,
        history_label="post-freeze anchor history",
        required_compatibility_record=expected_record,
    )
    return expected


def _head_is_stably_clean(repository_root: Path, source_git_sha: str) -> None:
    status_arguments = ("status", "--porcelain=v1", "-z", "--untracked-files=all")
    if _git(repository_root, *status_arguments):
        raise EvidenceCompatibilityError(
            "role source must be the stable fully clean repository HEAD"
        )
    observed_head = (
        _git(
            repository_root,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        )
        .decode("ascii")
        .strip()
    )
    if observed_head != source_git_sha:
        raise EvidenceCompatibilityError("role source Git SHA must equal current clean HEAD")
    for entry in _git(repository_root, "ls-files", "-v", "-z").split(b"\0"):
        if entry and not entry.startswith(b"H "):
            raise EvidenceCompatibilityError(
                "role source forbids assume-unchanged or skip-worktree index flags"
            )


def _verify_role_worktree(
    repository_root: Path,
    inventory: dict[str, object],
) -> Mapping[str, str]:
    raw_entries = inventory["entries"]
    if type(raw_entries) is not list:
        raise EvidenceCompatibilityError("role Behavior Set entries are malformed")
    sha256_by_path: dict[str, str] = {}
    for raw_entry in raw_entries:
        if type(raw_entry) is not dict:
            raise EvidenceCompatibilityError("role Behavior Set entry is malformed")
        relative_path = raw_entry["path"]
        expected_mode = raw_entry["mode"]
        expected_object_id = raw_entry["object_id"]
        if type(relative_path) is not str:
            raise EvidenceCompatibilityError("role Behavior Set path is malformed")
        path = repository_root / relative_path
        try:
            observed_mode = path.lstat().st_mode
        except OSError as error:
            raise EvidenceCompatibilityError(
                f"role behavior file is not readable: {relative_path}"
            ) from error
        if stat.S_ISLNK(observed_mode) or not stat.S_ISREG(observed_mode):
            raise EvidenceCompatibilityError(
                f"role behavior file must be a no-follow regular file: {relative_path}"
            )
        if not hasattr(os, "O_NOFOLLOW"):
            raise EvidenceCompatibilityError(
                "role worktree verification requires O_NOFOLLOW support"
            )
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
            )
        except OSError as error:
            raise EvidenceCompatibilityError(
                f"role behavior file cannot be opened securely: {relative_path}"
            ) from error
        with os.fdopen(descriptor, "rb") as handle:
            descriptor_mode = os.fstat(descriptor).st_mode
            if not stat.S_ISREG(descriptor_mode):
                raise EvidenceCompatibilityError(
                    f"role behavior file changed type while reading: {relative_path}"
                )
            content = handle.read()
        digest = hashlib.sha1(usedforsecurity=False)
        digest.update(f"blob {len(content)}\0".encode("ascii"))
        digest.update(content)
        executable = bool(descriptor_mode & 0o111)
        if digest.hexdigest() != expected_object_id or executable != (expected_mode == "100755"):
            raise EvidenceCompatibilityError(
                f"role behavior file differs from current HEAD: {relative_path}"
            )
        sha256_by_path[relative_path] = hashlib.sha256(content).hexdigest()
    return MappingProxyType(dict(sorted(sha256_by_path.items())))


def _is_ancestor(repository_root: Path, ancestor: str, descendant: str) -> bool:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    try:
        completed = subprocess.run(
            (
                "git",
                "--no-replace-objects",
                "-C",
                str(repository_root),
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ),
            check=False,
            capture_output=True,
            env=environment,
        )
    except OSError as error:
        raise EvidenceCompatibilityError("cannot execute the Git ancestry check") from error
    if completed.returncode not in {0, 1}:
        detail = (completed.stderr or completed.stdout).decode("utf-8", "replace").strip()
        raise EvidenceCompatibilityError(
            f"Git ancestry check failed: {detail or 'Git command failed'}"
        )
    return completed.returncode == 0


def _revision_list(repository_root: Path, *arguments: str) -> tuple[str, ...]:
    output = _git(repository_root, "rev-list", *arguments).decode("ascii").splitlines()
    commits = tuple(commit for commit in output if commit)
    if any(_LOWER_GIT_SHA.fullmatch(commit) is None for commit in commits):
        raise EvidenceCompatibilityError("Git returned a malformed commit history")
    return commits


@dataclass(frozen=True, slots=True)
class _DataAnchorSnapshot:
    tree: dict[str, tuple[str, str, str]]
    compatibility_records: frozenset[bytes]
    day2_post_run_records: frozenset[bytes]
    day2_profile_records: frozenset[bytes]


def _commit_parents(repository_root: Path, source_git_sha: str) -> tuple[str, ...]:
    fields = (
        _git(repository_root, "rev-list", "--parents", "-n", "1", source_git_sha)
        .decode("ascii")
        .split()
    )
    if (
        not fields
        or fields[0] != source_git_sha
        or any(_LOWER_GIT_SHA.fullmatch(value) is None for value in fields)
    ):
        raise EvidenceCompatibilityError("Git returned malformed commit parentage")
    return tuple(fields[1:])


def _verify_data_anchor_history(
    repository_root: Path,
    *,
    start_git_sha: str,
    end_git_sha: str,
    allowed_paths: tuple[str, ...],
    history_label: str,
    required_compatibility_record: bytes | None = None,
) -> str | None:
    cache: dict[str, _DataAnchorSnapshot] = {}

    def snapshot(commit: str) -> _DataAnchorSnapshot:
        observed = cache.get(commit)
        if observed is not None:
            return observed
        tree = _full_tree(repository_root, commit)
        observed = _DataAnchorSnapshot(
            tree=tree,
            compatibility_records=frozenset(
                _compatibility_anchor_records_at(repository_root, commit, tree)
            ),
            day2_post_run_records=frozenset(
                _day2_post_run_anchor_records_at(repository_root, commit, tree)
            ),
            day2_profile_records=frozenset(
                _day2_profile_anchor_records_at(repository_root, commit, tree)
            ),
        )
        cache[commit] = observed
        return observed

    commits = (
        start_git_sha,
        *_revision_list(
            repository_root,
            "--reverse",
            "--topo-order",
            "--ancestry-path",
            f"{start_git_sha}..{end_git_sha}",
        ),
    )
    if commits[-1] != end_git_sha:
        raise EvidenceCompatibilityError(f"{history_label} does not reach its end snapshot")
    allowed = set(allowed_paths)
    start = snapshot(start_git_sha)
    profile_addition_commits: set[str] = set()
    if (
        required_compatibility_record is not None
        and required_compatibility_record not in start.compatibility_records
    ):
        raise EvidenceCompatibilityError(
            f"{history_label} may not remove or retarget the exact post-run anchor"
        )
    for commit in commits[1:]:
        current = snapshot(commit)
        if (
            required_compatibility_record is not None
            and required_compatibility_record not in current.compatibility_records
        ):
            raise EvidenceCompatibilityError(
                f"{history_label} may not remove or retarget the exact post-run anchor"
            )
        internal_parents = tuple(
            parent
            for parent in _commit_parents(repository_root, commit)
            if parent == start_git_sha
            or (
                _is_ancestor(repository_root, start_git_sha, parent)
                and _is_ancestor(repository_root, parent, end_git_sha)
            )
        )
        if not internal_parents:
            raise EvidenceCompatibilityError(
                f"{history_label} contains a commit without an internal ancestry edge"
            )
        for parent in internal_parents:
            previous = snapshot(parent)
            changed_paths = _changed_paths(previous.tree, current.tree)
            unexpected = tuple(path for path in changed_paths if path not in allowed)
            if unexpected:
                raise EvidenceCompatibilityError(
                    f"{history_label} contains unapproved history drift: " + ", ".join(unexpected)
                )
            if not previous.compatibility_records <= current.compatibility_records:
                raise EvidenceCompatibilityError(
                    f"{history_label} may not remove or retarget compatibility anchors"
                )
            if not previous.day2_post_run_records <= current.day2_post_run_records:
                raise EvidenceCompatibilityError(
                    f"{history_label} rejects Day2 post-run remove or retarget of a binding"
                )
            if not previous.day2_profile_records <= current.day2_profile_records:
                raise EvidenceCompatibilityError(
                    f"{history_label} rejects Day2 profile remove or retarget of a binding"
                )
            if not previous.day2_profile_records and current.day2_profile_records:
                profile_addition_commits.add(commit)
            if (
                not previous.day2_profile_records
                and current.day2_profile_records
                and current.day2_post_run_records
            ):
                raise EvidenceCompatibilityError(
                    f"{history_label} requires the Day2 profile before any post-run binding"
                )
            _require_changed_data_blobs(changed_paths, current.tree, history_label)

    profile_installation_git_sha: str | None = None
    if not start.day2_profile_records:
        first_appearances = tuple(
            commit
            for commit in profile_addition_commits
            if not any(
                other != commit and _is_ancestor(repository_root, other, commit)
                for other in profile_addition_commits
            )
        )
        if len(first_appearances) > 1:
            raise EvidenceCompatibilityError(
                f"{history_label} requires one unique first Day2 profile installation"
            )
        if first_appearances:
            first = first_appearances[0]
            profile_installation_git_sha = first
            first_snapshot = snapshot(first)
            if first_snapshot.day2_post_run_records:
                raise EvidenceCompatibilityError(
                    f"{history_label} requires the Day2 profile before any post-run binding"
                )
            internal_parents = tuple(
                parent
                for parent in _commit_parents(repository_root, first)
                if parent == start_git_sha
                or (
                    _is_ancestor(repository_root, start_git_sha, parent)
                    and _is_ancestor(repository_root, parent, end_git_sha)
                )
            )
            if any(
                _changed_paths(snapshot(parent).tree, first_snapshot.tree)
                != (_DAY2_PROFILE_ANCHOR_PATH,)
                for parent in internal_parents
            ):
                raise EvidenceCompatibilityError(
                    f"{history_label} Day2 profile installation must change only its data path"
                )
    return profile_installation_git_sha


def _unique_first_compatibility_record_installation(
    repository_root: Path,
    *,
    start_git_sha: str,
    end_git_sha: str,
    required_record: bytes,
) -> str:
    cache: dict[str, frozenset[bytes]] = {}

    def records(commit: str) -> frozenset[bytes]:
        observed = cache.get(commit)
        if observed is None:
            tree = _full_tree(repository_root, commit)
            observed = frozenset(
                _compatibility_anchor_records_at(repository_root, commit, tree)
            )
            cache[commit] = observed
        return observed

    if required_record in records(start_git_sha):
        raise EvidenceCompatibilityError(
            "selected Day1A compatibility anchor must be installed after registration S2"
        )
    commits = (
        start_git_sha,
        *_revision_list(
            repository_root,
            "--reverse",
            "--topo-order",
            "--ancestry-path",
            f"{start_git_sha}..{end_git_sha}",
        ),
    )
    if commits[-1] != end_git_sha or required_record not in records(end_git_sha):
        raise EvidenceCompatibilityError(
            "selected Day1A compatibility anchor is absent before profile installation"
        )
    addition_commits: set[str] = set()
    for commit in commits[1:]:
        if required_record not in records(commit):
            continue
        internal_parents = tuple(
            parent
            for parent in _commit_parents(repository_root, commit)
            if parent == start_git_sha
            or (
                _is_ancestor(repository_root, start_git_sha, parent)
                and _is_ancestor(repository_root, parent, end_git_sha)
            )
        )
        if internal_parents and all(
            required_record not in records(parent) for parent in internal_parents
        ):
            addition_commits.add(commit)
    if len(addition_commits) != 1:
        raise EvidenceCompatibilityError(
            "selected Day1A compatibility anchor must have one unique first installation"
        )
    return next(iter(addition_commits))


def _require_day1a_anchor_before_profile(
    repository_root: Path,
    *,
    evidence_freeze_git_sha: str,
    profile_installation_git_sha: str,
    analysis_source_git_sha: str,
    behavior_set_sha256: str,
) -> tuple[str, str]:
    profile_tree = _full_tree(repository_root, profile_installation_git_sha)
    profile_records = _day2_profile_anchor_records_at(
        repository_root,
        profile_installation_git_sha,
        profile_tree,
    )
    if len(profile_records) != 1:
        raise EvidenceCompatibilityError(
            "Day2 profile installation must contain exactly one validated binding"
        )
    profile_binding = _decode_canonical_json(
        profile_records[0],
        "Day2 profile binding",
    )
    receipt_sha256 = profile_binding.get("day1a_authority_receipt_sha256")
    if type(receipt_sha256) is not str or _LOWER_SHA256.fullmatch(receipt_sha256) is None:
        raise EvidenceCompatibilityError(
            "Day2 profile binding has no exact Day1A authority receipt digest"
        )
    expected = {
        "artifact_sha256": receipt_sha256,
        "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[
            EvidenceRole.DAY1_REGISTRATION
        ],
        "behavior_set_sha256": behavior_set_sha256,
        "experiment_source_git_sha": evidence_freeze_git_sha,
        "role": EvidenceRole.DAY1_REGISTRATION.value,
        "schema_version": "dynamic-cssc-evidence-compatibility-anchor-v1",
    }
    expected_record = _canonical_json_bytes(expected)
    for label, commit in (
        ("profile installation", profile_installation_git_sha),
        ("current analysis", analysis_source_git_sha),
    ):
        selected_records = tuple(
            anchor
            for anchor in _anchor_set_at(repository_root, commit)
            if anchor["role"] == EvidenceRole.DAY1_REGISTRATION.value
        )
        if selected_records != (expected,):
            raise EvidenceCompatibilityError(
                f"{label} must retain exactly the selected Day1A compatibility anchor"
            )
    anchor_git_sha = _unique_first_compatibility_record_installation(
        repository_root,
        start_git_sha=evidence_freeze_git_sha,
        end_git_sha=profile_installation_git_sha,
        required_record=expected_record,
    )
    return receipt_sha256, anchor_git_sha


def _same_behavior_inventory(
    before: dict[str, object],
    after: dict[str, object],
) -> bool:
    fields = (
        "behavior_set_schema_version",
        "behavior_set_sha256",
        "entries",
        "role",
        "schema_version",
    )
    return all(
        _canonical_json_bytes(before[field]) == _canonical_json_bytes(after[field])
        for field in fields
    )


def _behavior_set_digest(inventory: dict[str, object]) -> str:
    digest = inventory.get("behavior_set_sha256")
    if type(digest) is not str or _LOWER_SHA256.fullmatch(digest) is None:
        raise EvidenceCompatibilityError("repository Behavior Set digest is malformed")
    return digest


def _changed_allowlist_digest(role: EvidenceRole) -> str:
    payload = {
        "analysis_only_paths": list(_ROLE_ANALYSIS_ONLY_PATHS[role]),
        "evidence_only_paths": list(_REPOSITORY_DATA_ONLY_ANCHOR_PATHS),
        "role": role.value,
        "schema_version": "dynamic-cssc-evidence-changed-path-allowlist-v1",
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def capture_behavior_inventory(
    role: EvidenceRole,
    *,
    source_git_sha: str,
    repository_root: Path,
) -> dict[str, object]:
    """Capture the repository-owned exact Git entries for one evidence role."""

    role = _require_role(role)
    repository_root = _repository(repository_root)
    source_git_sha = _exact_commit(
        repository_root,
        source_git_sha,
        "source_git_sha",
    )
    entries = _tree_entries(repository_root, source_git_sha, _behavior_paths(role))
    behavior_set = {
        "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
        "entries": entries,
        "role": role.value,
    }
    return {
        "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
        "behavior_set_sha256": hashlib.sha256(_canonical_json_bytes(behavior_set)).hexdigest(),
        "entries": entries,
        "role": role.value,
        "schema_version": BEHAVIOR_INVENTORY_SCHEMA,
        "source_git_sha": source_git_sha,
    }


def verify_day1b_resource_amendment_schema_source(
    *,
    source_git_sha: object,
    current_git_sha: object,
    expected_inventory_sha256: object,
    repository_root: Path,
) -> dict[str, object]:
    """Reconstruct and verify the immutable v9 resource-schema source.

    The current DAY1B inventory necessarily contains the later amendment and
    review blobs.  Reusing it for the earlier schema source would make that
    source self-referential, so this seam owns the sole historical v9 path set
    and requires it to be an ancestor of the clean current source.
    """

    repository_root = _repository(repository_root)
    source_git_sha = _exact_commit(
        repository_root,
        source_git_sha,
        "Day1B resource-amendment schema source",
    )
    current_git_sha = _exact_commit(
        repository_root,
        current_git_sha,
        "current Day1B resource-amendment source",
    )
    if not _is_ancestor(repository_root, source_git_sha, current_git_sha):
        raise EvidenceCompatibilityError(
            "Day1B resource-amendment schema source is not an ancestor of current source"
        )
    if (
        type(expected_inventory_sha256) is not str
        or _LOWER_SHA256.fullmatch(expected_inventory_sha256) is None
    ):
        raise EvidenceCompatibilityError(
            "Day1B resource-amendment schema-source inventory digest is malformed"
        )

    entries = _tree_entries(
        repository_root,
        source_git_sha,
        _DAY1B_RESOURCE_AMENDMENT_SCHEMA_SOURCE_BEHAVIOR_PATHS,
    )
    schema_version = "dynamic-cssc-day1b-preparatory-behavior-set-v9"
    behavior_set = {
        "behavior_set_schema_version": schema_version,
        "entries": entries,
        "role": EvidenceRole.DAY1B.value,
    }
    inventory = {
        "behavior_set_schema_version": schema_version,
        "behavior_set_sha256": hashlib.sha256(
            _canonical_json_bytes(behavior_set)
        ).hexdigest(),
        "entries": entries,
        "role": EvidenceRole.DAY1B.value,
        "schema_version": BEHAVIOR_INVENTORY_SCHEMA,
        "source_git_sha": source_git_sha,
    }
    if hashlib.sha256(_canonical_json_bytes(inventory)).hexdigest() != (
        expected_inventory_sha256
    ):
        raise EvidenceCompatibilityError(
            "Day1B resource-amendment schema-source inventory digest changed"
        )
    return inventory


def verify_current_role_source(
    role: EvidenceRole,
    repository_root: Path,
) -> RoleSourceAttestation:
    """Verify one current role source through the hardened Git/worktree seam."""

    role = _require_role(role)
    _behavior_paths(role)
    repository_root = _repository(repository_root)
    head_sha = (
        _git(
            repository_root,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        )
        .decode("ascii")
        .strip()
    )
    head_sha = _exact_commit(repository_root, head_sha, f"{role.value} source HEAD")
    _head_is_stably_clean(repository_root, head_sha)
    inventory = capture_behavior_inventory(
        role,
        source_git_sha=head_sha,
        repository_root=repository_root,
    )
    first_blob_sha256 = _verify_role_worktree(repository_root, inventory)
    _head_is_stably_clean(repository_root, head_sha)
    second_blob_sha256 = _verify_role_worktree(repository_root, inventory)
    if first_blob_sha256 != second_blob_sha256:
        raise EvidenceCompatibilityError(
            f"{role.value} behavior source changed during clean-HEAD verification"
        )
    return RoleSourceAttestation(
        role=role,
        git_sha=head_sha,
        behavior_set_schema_version=_ROLE_BEHAVIOR_SCHEMAS[role],
        behavior_set_sha256=_behavior_set_digest(inventory),
        behavior_source_blob_sha256=first_blob_sha256,
    )


def verify_current_analysis_source(repository_root: Path) -> AnalysisSourceAttestation:
    """Verify the one current analyzer source through the hardened role seam."""

    attestation = verify_current_role_source(EvidenceRole.ANALYZER, repository_root)
    return AnalysisSourceAttestation(
        git_sha=attestation.git_sha,
        behavior_set_schema_version=attestation.behavior_set_schema_version,
        behavior_set_sha256=attestation.behavior_set_sha256,
    )


def repository_behavior_paths(role: EvidenceRole) -> tuple[str, ...]:
    """Return the immutable repository-owned path inventory for one role."""

    return _behavior_paths(_require_role(role))


def read_current_role_evidence_data(
    role: EvidenceRole,
    repository_root: Path,
) -> tuple[RepositoryDataBlob, ...]:
    """Read the exact role-owned evidence-only data from current clean Git HEAD."""

    role = _require_role(role)
    repository_root = _repository(repository_root)
    head_sha = (
        _git(repository_root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    )
    head_sha = _exact_commit(repository_root, head_sha, f"{role.value} evidence-data HEAD")
    _head_is_stably_clean(repository_root, head_sha)
    paths = _ROLE_EVIDENCE_ONLY_PATHS[role]
    entries = _tree_entries(repository_root, head_sha, paths)
    if any(entry["mode"] != "100644" for entry in entries):
        raise EvidenceCompatibilityError(
            f"{role.value} evidence data must be exact Git 100644 blobs"
        )
    worktree_sha256 = _verify_role_worktree(
        repository_root,
        {"entries": entries},
    )
    blobs: list[RepositoryDataBlob] = []
    for entry in entries:
        content = _git(repository_root, "cat-file", "blob", entry["object_id"])
        digest = hashlib.sha256(content).hexdigest()
        if worktree_sha256[entry["path"]] != digest:
            raise EvidenceCompatibilityError(
                f"{role.value} evidence data differs between Git and worktree"
            )
        blobs.append(
            RepositoryDataBlob(
                role=role,
                git_sha=head_sha,
                path=entry["path"],
                mode=entry["mode"],
                object_id=entry["object_id"],
                sha256=digest,
                content=content,
            )
        )
    _head_is_stably_clean(repository_root, head_sha)
    second_sha256 = _verify_role_worktree(repository_root, {"entries": entries})
    if second_sha256 != worktree_sha256:
        raise EvidenceCompatibilityError(
            f"{role.value} evidence data changed while it was being read"
        )
    return tuple(blobs)


def _verify_historical_strong_source(
    repository_root: Path,
    *,
    source_git_sha: object,
    expected_behavior_set_schema_version: object,
    expected_behavior_set_sha256: object,
) -> HistoricalStrongSourceAttestation:
    """Verify repository-anchored historical strong source without caller authority."""

    repository_root = _repository(repository_root)
    source_git_sha = _exact_commit(
        repository_root,
        source_git_sha,
        "historical strong source_git_sha",
    )
    if expected_behavior_set_schema_version != _HISTORICAL_STRONG_BEHAVIOR_SCHEMA:
        raise EvidenceCompatibilityError(
            "historical strong Behavior Set schema is not repository-approved"
        )
    if (
        type(expected_behavior_set_sha256) is not str
        or _LOWER_SHA256.fullmatch(expected_behavior_set_sha256) is None
    ):
        raise EvidenceCompatibilityError("historical strong Behavior Set digest is malformed")
    reachable_refs = tuple(
        sorted(
            ref
            for ref in _git(
                repository_root,
                "for-each-ref",
                f"--contains={source_git_sha}",
                "--format=%(refname)",
            )
            .decode("utf-8")
            .splitlines()
            if ref
        )
    )
    if not reachable_refs:
        raise EvidenceCompatibilityError(
            "historical strong source commit is not reachable from a repository ref"
        )
    entries = _tree_entries(
        repository_root,
        source_git_sha,
        _HISTORICAL_STRONG_CORRECTNESS_BEHAVIOR_PATHS,
    )
    behavior_document = {
        "behavior_set_schema_version": _HISTORICAL_STRONG_BEHAVIOR_SCHEMA,
        "entries": entries,
        "role": EvidenceRole.STRONG_CORRECTNESS.value,
    }
    behavior_set_sha256 = hashlib.sha256(_canonical_json_bytes(behavior_document)).hexdigest()
    if behavior_set_sha256 != expected_behavior_set_sha256:
        raise EvidenceCompatibilityError(
            "historical strong Git Behavior Set differs from its repository data anchor"
        )
    sha256_by_path: dict[str, str] = {}
    for entry in entries:
        content = _git(repository_root, "cat-file", "blob", entry["object_id"])
        digest = hashlib.sha1(usedforsecurity=False)
        digest.update(f"blob {len(content)}\0".encode("ascii"))
        digest.update(content)
        if digest.hexdigest() != entry["object_id"]:
            raise EvidenceCompatibilityError(
                "historical strong Git blob bytes differ from their object identity"
            )
        sha256_by_path[entry["path"]] = hashlib.sha256(content).hexdigest()
    second_refs = tuple(
        sorted(
            ref
            for ref in _git(
                repository_root,
                "for-each-ref",
                f"--contains={source_git_sha}",
                "--format=%(refname)",
            )
            .decode("utf-8")
            .splitlines()
            if ref
        )
    )
    second_entries = _tree_entries(
        repository_root,
        source_git_sha,
        _HISTORICAL_STRONG_CORRECTNESS_BEHAVIOR_PATHS,
    )
    if second_refs != reachable_refs or second_entries != entries:
        raise EvidenceCompatibilityError("historical strong Git source changed during attestation")
    return HistoricalStrongSourceAttestation(
        source_git_sha=source_git_sha,
        behavior_set_schema_version=_HISTORICAL_STRONG_BEHAVIOR_SCHEMA,
        behavior_set_sha256=behavior_set_sha256,
        behavior_source_blob_sha256=MappingProxyType(dict(sorted(sha256_by_path.items()))),
        reachable_ref_names=reachable_refs,
    )


def admit_isolated_publication_run(
    runtime_receipt: object,
) -> RuntimeAdmissionCapability:
    """Fully reverify one live isolated run and mint ephemeral runtime authority.

    The installed inner receipt remains descriptive.  This seam accepts no
    repository path, source identity, policy, environment, digest, Boolean, or
    disk receipt; the isolated runner's live result is consumed exactly once.
    """

    from dynamic_cssc import publication_runtime

    verified = publication_runtime._verify_and_consume_runtime_receipt(runtime_receipt)
    first_attestation = verify_current_role_source(
        EvidenceRole.ANALYZER,
        verified.repository_root,
    )
    if first_attestation.git_sha != verified.source_git_sha:
        raise EvidenceCompatibilityError(
            "runtime admission source differs from current central Analyzer S3"
        )
    inventory = capture_behavior_inventory(
        EvidenceRole.ANALYZER,
        source_git_sha=first_attestation.git_sha,
        repository_root=verified.repository_root,
    )
    raw_entries = inventory["entries"]
    if type(raw_entries) is not list:  # pragma: no cover - capture invariant
        raise AssertionError("central Analyzer inventory entries are malformed")
    runtime_entries = [
        {
            "git_mode": entry["mode"],
            "object_id": entry["object_id"],
            "path": entry["path"],
            "sha256": first_attestation.behavior_source_blob_sha256[entry["path"]],
        }
        for entry in raw_entries
    ]
    if verified.source_attestation["entries"] != runtime_entries:
        raise EvidenceCompatibilityError(
            "runtime source inventory differs from the central Analyzer Behavior Set"
        )
    audit_document: dict[str, object] = {
        "analysis_source_git_sha": first_attestation.git_sha,
        "analyzer_behavior_set_sha256": first_attestation.behavior_set_sha256,
        "authority_scope": "ephemeral-in-process-runtime-admission-only",
        "formal_authority_granted": False,
        "installed_artifact_set_sha256": verified.installed_artifact_set_sha256,
        "replayable_from_audit_document": False,
        "runtime_receipt_sha256": verified.receipt_sha256,
        "schema_version": "dynamic-cssc-runtime-final-admission-audit-v1",
    }
    if (
        verify_current_role_source(
            EvidenceRole.ANALYZER,
            verified.repository_root,
        )
        != first_attestation
    ):
        raise EvidenceCompatibilityError("Analyzer source changed during central runtime admission")
    capability = object.__new__(RuntimeAdmissionCapability)
    binding = _RuntimeAdmissionBinding(
        _canonical_json_bytes(audit_document),
        verified.repository_root,
        verified.output_directory,
    )
    object.__setattr__(capability, "_binding", binding)
    with _RUNTIME_ADMISSION_LOCK:
        _LIVE_RUNTIME_ADMISSIONS[id(capability)] = (capability, binding)
    return capability


def verify_repository_anchor_history(
    role: EvidenceRole,
    repository_root: Path,
) -> RepositoryAnchorHistoryAttestation:
    """Locate and verify the unique repository-owned S2 without caller input."""

    role = _require_role(role)
    if role is EvidenceRole.STRONG_CORRECTNESS:
        raise EvidenceCompatibilityHold(
            "HOLD: the historical strong-correctness anchor is descriptive only"
        )
    if role is not EvidenceRole.DAY1_REGISTRATION:
        raise EvidenceCompatibilityError(
            "repository anchor-history verification is not defined for this evidence role"
        )
    repository_root = _repository(repository_root)
    analysis_attestation = verify_current_role_source(role, repository_root)
    analysis_sha = analysis_attestation.git_sha
    current_anchors = _day1_registration_anchors_at(
        repository_root,
        analysis_sha,
        require_file=True,
    )
    if not current_anchors:
        raise EvidenceCompatibilityHold(
            "HOLD: no repository-approved Day1 composite registration anchor is installed"
        )
    anchor = current_anchors[0]
    anchor_bytes = _canonical_json_bytes(anchor)
    experiment_sha = _exact_commit(
        repository_root,
        anchor["experiment_source_git_sha"],
        "Day1 registration experiment_source_git_sha",
    )
    if not _is_ancestor(repository_root, experiment_sha, analysis_sha):
        raise EvidenceCompatibilityError(
            "Day1 registration experiment source is not an ancestor of current analysis"
        )
    if _day1_registration_anchors_at(
        repository_root,
        experiment_sha,
        require_file=True,
    ):
        raise EvidenceCompatibilityError(
            "Day1 registration anchor must be absent from the experiment snapshot"
        )
    for commit in _revision_list(repository_root, experiment_sha):
        if _day1_registration_anchors_at(
            repository_root,
            commit,
            require_file=False,
        ):
            raise EvidenceCompatibilityError(
                "Day1 registration anchor history replays evidence present before S1"
            )

    between = _revision_list(
        repository_root,
        "--reverse",
        "--topo-order",
        f"{experiment_sha}..{analysis_sha}",
    )
    present_commits: list[str] = []
    for commit in between:
        observed = _day1_registration_anchors_at(
            repository_root,
            commit,
            require_file=False,
        )
        if not observed:
            continue
        if len(observed) != 1 or _canonical_json_bytes(observed[0]) != anchor_bytes:
            raise EvidenceCompatibilityError(
                "Day1 registration history contains an extra or retargeted anchor"
            )
        present_commits.append(commit)
    first_appearance = [
        commit
        for commit in present_commits
        if not any(
            other != commit and _is_ancestor(repository_root, other, commit)
            for other in present_commits
        )
    ]
    if len(first_appearance) != 1:
        raise EvidenceCompatibilityError(
            "Day1 registration anchor must have one unique first evidence-freeze commit"
        )
    evidence_freeze_sha = first_appearance[0]
    for snapshot_label, snapshot_sha in (
        ("registration S1", experiment_sha),
        ("registration S2", evidence_freeze_sha),
    ):
        snapshot_tree = _full_tree(repository_root, snapshot_sha)
        if _day2_profile_anchor_records_at(repository_root, snapshot_sha, snapshot_tree):
            raise EvidenceCompatibilityError(
                f"Day2 profile binding must be absent from {snapshot_label}"
            )
    retained_commits = (
        evidence_freeze_sha,
        *_revision_list(
            repository_root,
            "--ancestry-path",
            f"{evidence_freeze_sha}..{analysis_sha}",
        ),
    )
    for commit in retained_commits:
        observed = _day1_registration_anchors_at(
            repository_root,
            commit,
            require_file=True,
        )
        if len(observed) != 1 or _canonical_json_bytes(observed[0]) != anchor_bytes:
            raise EvidenceCompatibilityError(
                "Day1 registration anchor was removed, replayed, or retargeted after S2"
            )
    _verify_data_anchor_history(
        repository_root,
        start_git_sha=experiment_sha,
        end_git_sha=evidence_freeze_sha,
        allowed_paths=(DAY1_REGISTRATION_ANCHOR_PATH,),
        history_label="Day1 S1-to-S2 history",
    )

    expected_inventory = capture_behavior_inventory(
        role,
        source_git_sha=experiment_sha,
        repository_root=repository_root,
    )
    artifact_inventory = anchor["artifact_behavior_inventory"]
    if type(artifact_inventory) is not dict or _canonical_json_bytes(
        artifact_inventory
    ) != _canonical_json_bytes(expected_inventory):
        raise EvidenceCompatibilityError(
            "Day1 registration artifact inventory does not equal the repository Behavior Set"
        )
    evidence_inventory = capture_behavior_inventory(
        role,
        source_git_sha=evidence_freeze_sha,
        repository_root=repository_root,
    )
    analysis_inventory = capture_behavior_inventory(
        role,
        source_git_sha=analysis_sha,
        repository_root=repository_root,
    )
    if not _same_behavior_inventory(expected_inventory, evidence_inventory) or not (
        _same_behavior_inventory(expected_inventory, analysis_inventory)
    ):
        raise EvidenceCompatibilityError("Day1 registration Behavior Set changed across S1/S2/S3")

    experiment_tree = _full_tree(repository_root, experiment_sha)
    evidence_tree = _full_tree(repository_root, evidence_freeze_sha)
    analysis_tree = _full_tree(repository_root, analysis_sha)
    experiment_changes = _changed_paths(experiment_tree, evidence_tree)
    analysis_changes = _changed_paths(evidence_tree, analysis_tree)
    if experiment_changes != (DAY1_REGISTRATION_ANCHOR_PATH,):
        raise EvidenceCompatibilityError(
            "Day1 S1-to-S2 tree must change only the exact registration data anchor"
        )
    unexpected_analysis_changes = tuple(
        path for path in analysis_changes if path not in _DAY1_REGISTRATION_POST_FREEZE_DATA_PATHS
    )
    if unexpected_analysis_changes:
        raise EvidenceCompatibilityError(
            "Day1 S2-to-S3 tree contains unapproved post-registration drift: "
            + ", ".join(unexpected_analysis_changes)
        )
    for path in analysis_changes:
        entry = analysis_tree.get(path)
        if entry is None or entry[:2] != ("100644", "blob"):
            raise EvidenceCompatibilityError(
                f"Day1 post-freeze cross-role anchor must be a Git 100644 data blob: {path}"
            )
    profile_installation_git_sha = _verify_data_anchor_history(
        repository_root,
        start_git_sha=evidence_freeze_sha,
        end_git_sha=analysis_sha,
        allowed_paths=_DAY1_REGISTRATION_POST_FREEZE_DATA_PATHS,
        history_label="Day1 post-freeze history",
    )
    day1a_authority_receipt_sha256: str | None = None
    day1a_evidence_anchor_git_sha: str | None = None
    if profile_installation_git_sha is not None:
        (
            day1a_authority_receipt_sha256,
            day1a_evidence_anchor_git_sha,
        ) = _require_day1a_anchor_before_profile(
            repository_root,
            evidence_freeze_git_sha=evidence_freeze_sha,
            profile_installation_git_sha=profile_installation_git_sha,
            analysis_source_git_sha=analysis_sha,
            behavior_set_sha256=_behavior_set_digest(expected_inventory),
        )
    if verify_current_role_source(role, repository_root) != analysis_attestation:
        raise EvidenceCompatibilityError(
            "Day1 registration source changed while verifying repository history"
        )
    receipt_document = {
        "analysis_source_git_sha": analysis_sha,
        "artifact_sha256": anchor["artifact_sha256"],
        "behavior_set_sha256": expected_inventory["behavior_set_sha256"],
        "day1a_authority_receipt_sha256": day1a_authority_receipt_sha256,
        "day1a_evidence_anchor_git_sha": day1a_evidence_anchor_git_sha,
        "day2_profile_installation_git_sha": profile_installation_git_sha,
        "evidence_freeze_git_sha": evidence_freeze_sha,
        "experiment_source_git_sha": experiment_sha,
        "role": role.value,
        "schema_version": "dynamic-cssc-repository-anchor-history-receipt-v2",
    }
    return RepositoryAnchorHistoryAttestation(
        role=role,
        experiment_source_git_sha=experiment_sha,
        evidence_freeze_git_sha=evidence_freeze_sha,
        analysis_source_git_sha=analysis_sha,
        artifact_sha256=str(anchor["artifact_sha256"]),
        receipt_sha256=hashlib.sha256(_canonical_json_bytes(receipt_document)).hexdigest(),
        _anchor_document=anchor_bytes,
        day1a_authority_receipt_sha256=day1a_authority_receipt_sha256,
        day1a_evidence_anchor_git_sha=day1a_evidence_anchor_git_sha,
        day2_profile_installation_git_sha=profile_installation_git_sha,
    )


def verify_evidence_compatibility(
    *,
    role: EvidenceRole,
    experiment_source_git_sha: str,
    evidence_freeze_git_sha: str,
    analysis_source_git_sha: str,
    artifact_sha256: str,
    artifact_behavior_inventory: object,
    repository_root: Path,
) -> EvidenceCompatibilityReceipt:
    """Verify one artifact and its S1/S2/S3 Git-object compatibility chain."""

    role = _require_role(role)
    if role in {EvidenceRole.STRONG_CORRECTNESS, EvidenceRole.DAY1_REGISTRATION}:
        raise EvidenceCompatibilityError(
            "repository-owned strong/registration roles forbid caller-supplied S2; "
            "use verify_repository_anchor_history"
        )
    _behavior_paths(role)
    repository_root = _repository(repository_root)
    experiment_source_git_sha = _exact_commit(
        repository_root,
        experiment_source_git_sha,
        "experiment_source_git_sha",
    )
    if type(artifact_sha256) is not str or _LOWER_SHA256.fullmatch(artifact_sha256) is None:
        raise EvidenceCompatibilityError("artifact_sha256 must be a lowercase SHA-256 digest")
    expected_inventory = capture_behavior_inventory(
        role,
        source_git_sha=experiment_source_git_sha,
        repository_root=repository_root,
    )
    if type(artifact_behavior_inventory) is not dict or _canonical_json_bytes(
        artifact_behavior_inventory
    ) != _canonical_json_bytes(expected_inventory):
        raise EvidenceCompatibilityError(
            "artifact behavior inventory must exactly equal the repository-owned Behavior Set"
        )
    evidence_freeze_git_sha = _exact_commit(
        repository_root,
        evidence_freeze_git_sha,
        "evidence_freeze_git_sha",
    )
    analysis_source_git_sha = _exact_commit(
        repository_root,
        analysis_source_git_sha,
        "analysis_source_git_sha",
    )
    analysis_attestation = verify_current_analysis_source(repository_root)
    if analysis_attestation.git_sha != analysis_source_git_sha:
        raise EvidenceCompatibilityError("analysis_source_git_sha must equal current clean HEAD")
    if not _is_ancestor(
        repository_root,
        experiment_source_git_sha,
        evidence_freeze_git_sha,
    ):
        raise EvidenceCompatibilityError(
            "experiment source must be an ancestor of the evidence-freeze source"
        )
    if not _is_ancestor(
        repository_root,
        evidence_freeze_git_sha,
        analysis_source_git_sha,
    ):
        raise EvidenceCompatibilityError(
            "evidence-freeze source must be an ancestor of current analysis source"
        )

    evidence_inventory = capture_behavior_inventory(
        role,
        source_git_sha=evidence_freeze_git_sha,
        repository_root=repository_root,
    )
    analysis_role_inventory = capture_behavior_inventory(
        role,
        source_git_sha=analysis_source_git_sha,
        repository_root=repository_root,
    )
    experiment_digest = _behavior_set_digest(expected_inventory)
    if (
        _behavior_set_digest(evidence_inventory) != experiment_digest
        or _behavior_set_digest(analysis_role_inventory) != experiment_digest
    ):
        raise EvidenceCompatibilityError(
            "role-specific Behavior Set changed across experiment/evidence/analysis snapshots"
        )
    if (
        role is EvidenceRole.ANALYZER
        and len(
            {
                experiment_source_git_sha,
                evidence_freeze_git_sha,
                analysis_source_git_sha,
            }
        )
        != 1
    ):
        raise EvidenceCompatibilityError(
            "ANALYZER role permits identity-snapshot verification only; "
            "non-identity post-run compatibility would be self-referential"
        )
    experiment_tree = _full_tree(repository_root, experiment_source_git_sha)
    evidence_tree = _full_tree(repository_root, evidence_freeze_git_sha)
    analysis_tree = _full_tree(repository_root, analysis_source_git_sha)
    if role is EvidenceRole.DAY2 and len(
        _day2_profile_anchor_records_at(
            repository_root,
            experiment_source_git_sha,
            experiment_tree,
        )
    ) != 1:
        raise EvidenceCompatibilityError(
            "Day2 profile binding must already exist at the experiment source"
        )
    experiment_to_evidence_changed_paths = _changed_paths(experiment_tree, evidence_tree)
    evidence_to_analysis_changed_paths = _changed_paths(evidence_tree, analysis_tree)
    evidence_only_paths = set(_REPOSITORY_DATA_ONLY_ANCHOR_PATHS)
    analysis_only_paths = set(_ROLE_ANALYSIS_ONLY_PATHS[role])
    unexpected_evidence_changes = sorted(
        set(experiment_to_evidence_changed_paths) - evidence_only_paths
    )
    if unexpected_evidence_changes:
        raise EvidenceCompatibilityError(
            "experiment-to-evidence tree contains behavior or extra drift; "
            f"changed={unexpected_evidence_changes}"
        )
    _require_changed_data_blobs(
        experiment_to_evidence_changed_paths,
        evidence_tree,
        "experiment-to-evidence",
    )
    unexpected_analysis_changes = sorted(
        set(evidence_to_analysis_changed_paths) - analysis_only_paths
    )
    if unexpected_analysis_changes:
        raise EvidenceCompatibilityError(
            "evidence-to-analysis tree contains behavior or extra drift; "
            f"changed={unexpected_analysis_changes}"
        )
    _require_changed_data_blobs(
        evidence_to_analysis_changed_paths,
        analysis_tree,
        "evidence-to-analysis",
    )
    snapshot_identity_shortcut = (
        experiment_source_git_sha == evidence_freeze_git_sha == analysis_source_git_sha
    )
    post_run_anchor: dict[str, object] | None = None
    if not snapshot_identity_shortcut:
        post_run_anchor = _required_post_run_anchor(
            repository_root,
            role=role,
            experiment_source_git_sha=experiment_source_git_sha,
            evidence_freeze_git_sha=evidence_freeze_git_sha,
            analysis_source_git_sha=analysis_source_git_sha,
            artifact_sha256=artifact_sha256,
            behavior_set_sha256=experiment_digest,
        )
    allowlist_digest = _changed_allowlist_digest(role)
    evidence_only_allowlist_sha256 = hashlib.sha256(
        _canonical_json_bytes(list(_REPOSITORY_DATA_ONLY_ANCHOR_PATHS))
    ).hexdigest()
    analysis_only_allowlist_sha256 = hashlib.sha256(
        _canonical_json_bytes(list(_ROLE_ANALYSIS_ONLY_PATHS[role]))
    ).hexdigest()
    document: dict[str, object] = {
        "analysis_only_allowlist_sha256": analysis_only_allowlist_sha256,
        "analysis_only_changed_paths": list(evidence_to_analysis_changed_paths),
        "analysis_source": {
            "analysis_behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[EvidenceRole.ANALYZER],
            "analysis_behavior_set_sha256": analysis_attestation.behavior_set_sha256,
            "experiment_role_behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
            "experiment_role_behavior_set_sha256": experiment_digest,
            "git_sha": analysis_source_git_sha,
        },
        "artifact_behavior_inventory_exact": True,
        "artifact_behavior_inventory_sha256": hashlib.sha256(
            _canonical_json_bytes(expected_inventory)
        ).hexdigest(),
        "artifact_sha256": artifact_sha256,
        "changed_path_allowlist_sha256": allowlist_digest,
        "compatibility_verified": post_run_anchor is not None,
        "evidence_only_allowlist_sha256": evidence_only_allowlist_sha256,
        "evidence_freeze_source": {
            "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
            "behavior_set_sha256": _behavior_set_digest(evidence_inventory),
            "git_sha": evidence_freeze_git_sha,
        },
        "evidence_only_changed_paths": list(experiment_to_evidence_changed_paths),
        "evidence_to_analysis_changed_paths": list(evidence_to_analysis_changed_paths),
        "experiment_to_evidence_changed_paths": list(experiment_to_evidence_changed_paths),
        "experiment_source": {
            "behavior_set_schema_version": _ROLE_BEHAVIOR_SCHEMAS[role],
            "behavior_set_sha256": experiment_digest,
            "git_sha": experiment_source_git_sha,
        },
        "formal_authority_granted": False,
        "git_replace_refs_absent": True,
        "post_run_anchor_sha256": (
            None
            if post_run_anchor is None
            else hashlib.sha256(_canonical_json_bytes(post_run_anchor)).hexdigest()
        ),
        "post_run_anchor_verified": post_run_anchor is not None,
        "role": role.value,
        # Wave1 deliberately cannot upgrade this.  A future receipt schema may
        # set it true only after verifying a fresh checkout, isolated interpreter,
        # import origins/blob hashes, locked wheels, and the exact runtime.
        "runtime_execution_isolation_authority_state": RUNTIME_EXECUTION_ISOLATION_HOLD,
        "runtime_execution_isolation_required_checks": list(
            RUNTIME_EXECUTION_ISOLATION_REQUIRED_CHECKS
        ),
        "runtime_execution_isolation_receipt_schema_version": (
            RUNTIME_EXECUTION_ISOLATION_RECEIPT_SCHEMA
        ),
        "runtime_execution_isolation_verified": False,
        "schema_version": "dynamic-cssc-evidence-compatibility-receipt-v1",
        "snapshot_compatibility_verified": True,
        "snapshot_identity_shortcut": snapshot_identity_shortcut,
    }
    if verify_current_analysis_source(repository_root) != analysis_attestation:
        raise EvidenceCompatibilityError(
            "analysis source changed while minting the compatibility receipt"
        )
    return _mint_receipt(document)


__all__ = (
    "BEHAVIOR_INVENTORY_SCHEMA",
    "DAY1_REGISTRATION_ANCHOR_PATH",
    "EVIDENCE_COMPATIBILITY_ANCHOR_PATH",
    "STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH",
    "AnalysisSourceAttestation",
    "EvidenceCompatibilityError",
    "EvidenceCompatibilityHold",
    "EvidenceCompatibilityReceipt",
    "EvidenceRole",
    "HistoricalStrongSourceAttestation",
    "RUNTIME_EXECUTION_ISOLATION_HOLD",
    "RUNTIME_EXECUTION_ISOLATION_RECEIPT_SCHEMA",
    "RUNTIME_EXECUTION_ISOLATION_REQUIRED_CHECKS",
    "RepositoryAnchorHistoryAttestation",
    "RepositoryDataBlob",
    "RoleSourceAttestation",
    "RuntimeAdmissionCapability",
    "admit_isolated_publication_run",
    "capture_behavior_inventory",
    "repository_behavior_paths",
    "read_current_role_evidence_data",
    "verify_current_analysis_source",
    "verify_current_role_source",
    "verify_day1b_resource_amendment_schema_source",
    "verify_evidence_compatibility",
    "verify_repository_anchor_history",
)
