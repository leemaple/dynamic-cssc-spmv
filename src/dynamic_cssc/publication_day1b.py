"""Fail-closed production of one publication Day1B paired analysis unit.

The production interface is intentionally two paths deep. Candidate identities, source
authority, resource limits, exact scheduling, and protocol-object serialization stay behind
that interface. The repository has not frozen all of those authorities yet, so production
currently stops before creating output. A typed private seam exercises the complete unit
builder without weakening that production HOLD.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Protocol

from dynamic_cssc import publication_statistics as publication_statistics_module
from dynamic_cssc.day1_registry import (
    Day1CandidateCatalog,
    Day1CandidateRegistrationError,
    RegisteredCandidate,
    RegistrationEvidence,
    repository_day1_candidate_catalog,
)
from dynamic_cssc.day2_calibration_authority import (
    Day2CalibrationAuthorityError,
    repository_day2_calibration_authority,
)
from dynamic_cssc.evidence_compatibility import (
    EvidenceCompatibilityError,
    EvidenceRole,
    RoleSourceAttestation,
    capture_behavior_inventory,
    verify_current_role_source,
    verify_day1b_resource_amendment_schema_source,
    verify_repository_anchor_history,
)
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactDirectory,
    install_verified_directory,
    quarantine_owned_directory,
)
from dynamic_cssc.publication_day1b_accounting import (
    PUBLICATION_DAY1B_ACCOUNTING_DOMAIN,
    Day1BAccountingDomain,
    PublicationDay1BAccounting,
    replay_publication_day1b_candidate_cell,
)
from dynamic_cssc.publication_day1b_aggregate_bounds import (
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
)
from dynamic_cssc.publication_day1b_expected_counts import (
    Day1BControllerExpectedCounts,
    derive_day1b_controller_expected_counts,
    require_formal_day1b_combined_evaluation_key_size_class,
    require_formal_day1b_f1m_worker_zero,
    require_formal_day1b_fixed_width_metadata_size_classes,
)
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    DAY1B_F1M_ACCOUNTING_BASIS,
    DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA,
    Day1BF1MChargedSizeClass,
    Day1BF1MCompletePhaseAudit,
    Day1BF1MCompleteScheduleAudit,
    Day1BF1MController,
    Day1BF1MControllerContext,
    Day1BF1MControllerSummary,
    Day1BF1MPhaseBoundary,
    canonical_day1b_f1m_charged_size_class_set_sha256,
    derive_day1b_f1m_charged_size_classes,
)
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    Day1BSerializedObjectSizeAuthority as _Day1BSerializedObjectSizeAuthority,
)
from dynamic_cssc.publication_day1b_key_framing import (
    DAY1B_COMBINED_EVALUATION_KEY_CATEGORY,
    day1b_combined_evaluation_key_size_class_sha256,
)
from dynamic_cssc.publication_day1b_metadata_framing import (
    DAY1B_FIXED_WIDTH_METADATA_CATEGORIES,
    day1b_metadata_size_class_document,
    day1b_metadata_size_class_sha256,
)
from dynamic_cssc.publication_day1b_worker_protocol import (
    DAY1B_WORKER_EXECUTION_BASIS,
    DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA,
    DAY1B_WORKER_RECEIPT_SCHEMA,
    DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
    Day1BClaimedWorkerEvidence,
    Day1BWorkerCandidateSpec,
    Day1BWorkerCellReceipt,
    Day1BWorkerInvocationCapability,
    Day1BWorkerPhaseAudit,
    Day1BWorkerPhaseRange,
    Day1BWorkerPhaseReceipt,
    Day1BWorkerProtocolContract,
    Day1BWorkerProtocolError,
    Day1BWorkerResourceLimits,
    Day1BWorkerSerializedCategoryReceipt,
    abandon_day1b_worker_invocation,
    canonical_day1b_worker_window_audit_bytes,
    claim_day1b_worker_evidence,
    consume_day1b_worker_frames,
)
from dynamic_cssc.publication_schedule import (
    ACCEPTED_EVENT_SCHEDULE_SCHEMA,
    AcceptedGroupPhaseRange,
    AcceptedGroupProgram,
    ExactPublicationWindow,
    ValidatedPublicationTrace,
    _compile_accepted_group_program_for_test,
    _load_publication_trace_bundle_for_test,
    _stream_publication_windows_for_test,
    compile_accepted_group_program,
    load_publication_trace_bundle,
    stream_publication_windows,
)
from dynamic_cssc.publication_statistics import (
    ABLATION_CANDIDATE_ID,
    CELL_BINDING_SCHEMA,
    DATASET_IDS,
    FIXED_CANDIDATE_IDS,
    FRESHNESS_VALUES,
    HELDOUT_RECORD_SCHEMA,
    PRIMITIVE_NAMES,
    QUERY_VECTOR_SCHEMA,
    REFERENCE_CANDIDATE_IDS,
    RHO_VALUES,
    SEMANTICS,
    TRACE_UNIT_SCHEMA,
    canonical_json_bytes,
)
from dynamic_cssc.publication_traces import (
    ACQUISITION_TRACE_BINDING_SCHEMA,
    PUBLICATION_SOURCE_PARTITION_COUNT,
    PUBLICATION_TRACE_MANIFEST_SCHEMA,
)

DAY1B_UNIT_SCHEMA = "dynamic-cssc-publication-day1b-unit-v4"
DAY1B_UNIT_FRAGMENT_SCHEMA = "dynamic-cssc-publication-day1b-unit-fragment-v1"
_TEST_DAY1B_UNIT_SCHEMA = "dynamic-cssc-publication-day1b-unit-private-test-fixture-v4"
_TEST_DAY1B_UNIT_FRAGMENT_SCHEMA = (
    "dynamic-cssc-publication-day1b-unit-fragment-private-test-fixture-v1"
)
DAY1B_SERIALIZATION_LEDGER_SCHEMA = (
    "dynamic-cssc-publication-day1b-serialized-protocol-object-ledger-v5"
)
DAY1B_SERIALIZED_OBJECT_SIZE_AUTHORITY_SCHEMA = (
    "dynamic-cssc-publication-day1b-serialized-object-size-authority-v1"
)
DAY1B_RESOURCE_POLICY_SCHEMA = "dynamic-cssc-publication-day1b-resource-policy-v1"
DAY1B_PENDING_RESOURCE_POLICY_SCHEMA = "dynamic-cssc-publication-day1b-resource-policy-pending-v1"
DAY1B_RESOURCE_AMENDMENT_SCHEMA = "dynamic-cssc-publication-day1b-resource-amendment-v1"
DAY1B_REPLAY_RECEIPT_SCHEMA = "dynamic-cssc-publication-day1b-trace-replay-receipt-v1"
DAY1B_ARTIFACT_VARIANT_SCHEMA = "dynamic-cssc-publication-day1b-artifact-variant-v1"

_DAY1B_PENDING_RESOURCE_POLICY_PATH = "config/publication-day1b-resource-policy.json"
_DAY1B_RESOURCE_AMENDMENT_PATH = "config/publication-day1b-resource-amendment.json"
_DAY1B_RESOURCE_AMENDMENT_REVIEW_PATH = "docs/reviews/day1b-resource-amendment-review-2026-08-25.md"
_DAY1B_PENDING_RESOURCE_POLICY_BYTES_MAXIMUM = 32_768
_DAY1B_RESOURCE_AMENDMENT_BYTES_MAXIMUM = 32_768
_DAY1B_RESOURCE_AMENDMENT_REVIEW_BYTES_MAXIMUM = 64 * 1024
_PENDING_RESOURCE_POLICY_KEYS = frozenset(
    {
        "amendment_identity",
        "authority",
        "limits",
        "measurement_methods",
        "pilot_evidence",
        "protocol_invariants",
        "schema_version",
        "state",
        "worker_runtime_identity",
    }
)
_PENDING_PROTOCOL_INVARIANT_KEYS = frozenset(
    {
        "candidate_retry_count",
        "selective_candidate_retry_allowed",
    }
)
_PENDING_AMENDMENT_IDENTITY_KEYS = frozenset(
    {
        "resource_policy_amendment_git_sha",
        "resource_policy_amendment_id",
        "resource_policy_amendment_sha256",
    }
)
_PENDING_AUTHORITY_KEYS = frozenset(
    {
        "artifact_publication_authorized",
        "claims_authorized",
        "common_ordinary_query_preparation_verified",
        "controller_scratch_isolation_verified",
        "day1_registration_anchor_verified",
        "dispatch_authorized",
        "formal_authority_granted",
        "full_openfhe_runner_verified",
        "outcome_blind_structure_pilot_reviewed",
        "resource_policy_frozen",
        "trace_post_run_anchor_verified",
        "workflow_dispatch_authorized",
    }
)
_PENDING_LIMIT_KEYS = frozenset(
    {
        "cells_per_shard",
        "controller_registered_scratch_bytes_checkpoint_maximum",
        "infrastructure_preemption_whole_shard_rerun_limit",
        "job_cost_budget_usd_maximum",
        "job_wall_clock_seconds_maximum",
        "max_concurrency",
        "output_bytes_per_unit",
        "resident_memory_bytes_per_candidate_cell",
        "scratch_bytes_per_candidate_cell",
        "serialized_object_bytes_maximum",
        "serialized_object_receipt_count_maximum",
        "serialized_object_receipt_spool_bytes_maximum",
        "serialized_payload_bytes_per_cell_maximum",
        "shard_cost_budget_usd_maximum",
        "shard_wall_clock_seconds_maximum",
        "wall_clock_seconds_per_candidate_cell",
        "worker_frame_count_maximum",
    }
)
_PENDING_MEASUREMENT_METHOD_KEYS = frozenset(
    {
        "controlled_scratch_high_water_measurement_method",
        "controlled_scratch_root_policy",
        "controller_scratch_observation_method",
        "infrastructure_preemption_classification_method",
        "output_byte_observation_method",
        "resident_memory_observation_method",
        "scratch_observation_method",
        "wall_clock_observation_method",
    }
)
_PENDING_PILOT_EVIDENCE_KEYS = frozenset(
    {
        "review_receipt_sha256",
        "structure_pilot_checksums_sha256",
        "structure_pilot_report_sha256",
        "structure_pilot_source_git_sha",
    }
)
_PENDING_WORKER_RUNTIME_IDENTITY_KEYS = frozenset(
    {
        "common_ordinary_private_plan_schema_version",
        "common_ordinary_query_preparation_schema_version",
        "compiler_flags",
        "compiler_identity",
        "controller_scratch_capability_schema_version",
        "cpu_affinity_policy",
        "full_openfhe_runner_path",
        "full_openfhe_runner_sha256",
        "full_openfhe_runtime_receipt_schema_version",
        "host_identity",
        "openfhe_build_identity_sha256",
        "openfhe_version",
        "operating_system_identity",
        "worker_adapter_schema_version",
        "worker_build_receipt_sha256",
    }
)
_RESOURCE_AMENDMENT_KEYS = frozenset(
    {
        "amendment_identity",
        "limits",
        "measurement_methods",
        "pilot_evidence",
        "protocol_invariants",
        "schema_source",
        "schema_version",
        "state",
    }
)
_RESOURCE_AMENDMENT_IDENTITY_KEYS = frozenset(
    {
        "resource_policy_amendment_id",
        "resource_policy_amendment_payload_sha256",
    }
)
_RESOURCE_AMENDMENT_SCHEMA_SOURCE_KEYS = frozenset(
    {
        "behavior_inventory_sha256",
        "git_sha",
    }
)
_RESOURCE_AMENDMENT_STATE = "RESOURCE-VALUES-FROZEN"
_RESOURCE_AMENDMENT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_RESOURCE_AMENDMENT_METHOD_TOKEN = re.compile(r"[a-z0-9][a-z0-9._:+/-]{0,127}\Z")
_CANONICAL_POSITIVE_DECIMAL = re.compile(r"(?:0\.[0-9]*[1-9]|[1-9][0-9]*(?:\.[0-9]*[1-9])?)\Z")

_PRODUCTION_TRACE_PROJECTION_TOKEN = object()
_TEST_TRACE_PROJECTION_TOKEN = object()
_PRODUCTION_ARTIFACT_VARIANT_TOKEN = object()
_TEST_ARTIFACT_VARIANT_TOKEN = object()
_TEST_DAY1B_ACCOUNTING_DOMAIN = Day1BAccountingDomain(
    rows=128,
    cols=512,
    effective_slots=128,
    partition_rows=128,
    matrix_value_bound=7,
    max_row_nnz=512,
    strong_segment_width=128,
)
_PRODUCTION_ARTIFACT_VARIANT = MappingProxyType(
    {
        "schema_version": DAY1B_ARTIFACT_VARIANT_SCHEMA,
        "kind": "production",
        "producer_entrypoint": "scripts/run_publication_day1b.py",
        "claims_authorized": False,
    }
)
_TEST_ARTIFACT_VARIANT = MappingProxyType(
    {
        "schema_version": DAY1B_ARTIFACT_VARIANT_SCHEMA,
        "kind": "private-test-fixture",
        "fixture_seam": "pytest-only-private-day1b-unit-producer",
        "claims_authorized": False,
    }
)
_TRACE_ACQUISITION_HOLD_STATES = frozenset(
    {
        "HOLD-no-repository-post-run-anchor",
        "HOLD-test-only-fixture-no-post-run-anchor",
        "HOLD-test-only-local-source-fixture",
    }
)

_MANIFEST_FILENAME = "publication-day1b-unit-manifest.json"
_FRAGMENT_FILENAME = "publication-heldout-fragment.json"
_SCHEDULE_FILENAME = "accepted-event-schedules.jsonl"
_LEDGER_FILENAME = "serialized-object-ledgers.jsonl"
_OBJECT_RECEIPT_FILENAME = "serialized-object-receipts.jsonl"
_CHECKSUM_FILENAME = "SHA256SUMS"
_ARTIFACT_FILENAMES = (
    _MANIFEST_FILENAME,
    _FRAGMENT_FILENAME,
    _SCHEDULE_FILENAME,
    _LEDGER_FILENAME,
    _OBJECT_RECEIPT_FILENAME,
    _CHECKSUM_FILENAME,
)
_CHECKSUM_TARGETS = _ARTIFACT_FILENAMES[:-1]
_DAY1B_MANIFEST_BYTES_MAXIMUM = 16 * 1024 * 1024
_DAY1B_FRAGMENT_BYTES_MAXIMUM = 16 * 1024 * 1024
_DAY1B_CHECKSUM_BYTES_MAXIMUM = 4 * 1024
_DAY1B_ARTIFACT_BYTES_HARD_MAXIMUM = 8_000_000_000
_DAY1B_SCHEDULE_LINE_BYTES_MAXIMUM = 64 * 1024
_DAY1B_LEDGER_LINE_BYTES_MAXIMUM = 1024 * 1024
_DAY1B_OBJECT_RECEIPT_LINE_BYTES_MAXIMUM = 64 * 1024
_DAY1B_WORKER_RECEIPT_CANONICAL_BYTES_MAXIMUM = 64 * 1024
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = frozenset({"complete", "failed", "timeout", "infeasible", "missing", "ineligible"})
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "artifact_policy",
        "artifact_variant",
        "unit_identity",
        "experiment_source",
        "trace_source",
        "acquisition_binding",
        "query_vector",
        "candidate_catalog",
        "serialized_object_size_authority",
        "resource_policy",
        "invocation",
        "cardinality",
        "cell_execution_receipts",
        "authority",
        "schedule_index",
        "members",
        "heldout_input_member_sha256",
    }
)
_FRAGMENT_KEYS = frozenset(
    {"schema_version", "experiment_source_git_sha", "trace_units", "cell_bindings", "records"}
)
_MEMBER_KEYS = frozenset(
    {_FRAGMENT_FILENAME, _SCHEDULE_FILENAME, _LEDGER_FILENAME, _OBJECT_RECEIPT_FILENAME}
)
_SCHEDULE_INDEX_KEYS = frozenset(
    {
        "rho",
        "schema_version",
        "canonical_schedule_sha256",
        "jsonl_line_count",
        "byte_count",
        "query_events_materialized",
    }
)
_LEDGER_KEYS = frozenset(
    {
        "schema_version",
        "cell_binding_sha256",
        "phase",
        "candidate_id",
        "controller_accounting_sha256",
        "controller_expected_counts_sha256",
        "byte_derivation",
        "ciphertext_count_used_as_byte_proxy",
        "raw_serialized_protocol_bytes_retained",
        "worker_object_receipt_spool_sha256",
        "f1m_controller_context_sha256",
        "f1m_route_coverage_sha256",
        "f1m_charged_size_class_set_sha256",
        "categories",
        "update_serialized_bytes",
        "query_serialized_bytes",
        "controller_charged_query_bytes",
        "query_serialized_bytes_including_controller_charge",
        "one_time_serialized_bytes_excluded_from_primary_C",
    }
)
_CATEGORY_LEDGER_KEYS = frozenset(
    {
        "category",
        "charge_authority",
        "charged_byte_count",
        "controller_charged_byte_count",
        "controller_charged_size_class",
        "controller_expected_combined_evaluation_key_size_class_sha256",
        "controller_expected_fixed_width_size_class_sha256",
        "controller_expected_logical_protocol_object_count",
        "controller_expected_serialized_byte_count",
        "controller_expected_worker_streamed_protocol_object_count",
        "object_receipt_spool_line_count",
        "object_receipt_spool_start_line",
        "object_receipt_stream_sha256",
        "protocol_object_count",
        "serialization_equivalence_class_count",
        "transaction",
    }
)
_F1M_CHARGED_SIZE_CLASS_KEYS = frozenset(
    {
        "accounting_basis",
        "category",
        "charged_byte_count",
        "ciphertext_bytes",
        "day2_outer_archive_sha256",
        "f1m_kind",
        "materialized_cryptographic_object_count",
        "multiplicity",
        "phase",
        "schema_version",
        "serialized_size_profile_key",
        "serialized_object_size_profile_sha256",
    }
)
_OBJECT_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "candidate_id",
        "category",
        "worker_input_binding_sha256",
        "object",
        "phase",
        "spool_line_ordinal",
        "transaction",
    }
)
_OBJECT_KEYS = frozenset(
    {
        "charged_byte_count",
        "f1m_size_class",
        "multiplicity",
        "serialization_equivalence_class_ordinal",
        "serialized_byte_count",
        "serialized_sha256",
    }
)
_EXPERIMENT_SOURCE_KEYS = frozenset({"git_sha", "source_attestation", "behavior_inventory"})
_TRACE_SOURCE_KEYS = frozenset(
    {
        "trace_manifest_schema_version",
        "git_sha",
        "trace_behavior_source_blob_sha256",
        "trace_behavior_source_inventory_sha256",
        "repository_provenance_sha256",
        "trace_manifest_sha256",
        "trace_central_behavior_inventory_present",
        "trace_source_authority_verified",
        "authority_state",
    }
)
_ACQUISITION_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "acquisition_transaction_sha256",
        "source_set_sha256",
        "source_bundle_sha256",
        "acquisition_behavior_set_sha256",
        "acquisition_behavior_inventory_sha256",
        "acquisition_authority_state",
        "central_behavior_inventory_present",
        "acquisition_network_authority_verified",
    }
)
_AUTHORITY_KEYS = frozenset(
    {
        "state",
        "local_integrity_verified",
        "schedule_v2_verified",
        "serialized_protocol_object_bytes_verified",
        "derived_aliases_materialized",
        "day1b_behavior_source_verified",
        "trace_source_authority_verified",
        "acquisition_network_authority_verified",
        "runtime_execution_isolation_verified",
        "publication_claim_allowed",
    }
)
_UNIT_IDENTITY_KEYS = frozenset({"dataset_id", "dataset_release", "semantics", "source_partition"})
_QUERY_VECTOR_BINDING_KEYS = frozenset({"schema_version", "sha256", "reuse_scope"})
_CANDIDATE_CATALOG_KEYS = frozenset(
    {
        "registration",
        "registration_sha256",
        "fixed_candidate_ids",
        "reference_candidate_ids",
        "ablation_candidate_ids",
        "candidate_policies",
    }
)
_CANDIDATE_POLICY_KEYS = frozenset(
    {
        "candidate_id",
        "candidate_policy_digest",
        "candidate_role",
        "packed_coo_segment_capacity",
        "periodic_repack_windows",
        "reserved_slack_beta",
        "strategy",
    }
)
_SERIALIZED_OBJECT_SIZE_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "day2_experiment_source_git_sha",
        "day2_outer_archive_sha256",
        "serialized_object_size_profile_sha256",
        "ciphertext_bytes",
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
        "serialized_rotation_key_inventory_bytes",
        "serialized_eval_mult_key_bytes",
    }
)
_INVOCATION_KEYS = frozenset(
    {
        "entrypoint",
        "public_interface",
        "caller_options_allowed",
        "shard_scope",
        "selective_candidate_retry_allowed",
    }
)
_REGISTRATION_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "run_id",
        "correctness_artifact_sha256",
        "accounting_evidence_sha256",
        "policy_contract_sha256",
    }
)
_RESOURCE_POLICY_KEYS = frozenset(
    {
        "schema_version",
        "wall_clock_seconds_per_candidate_cell",
        "resident_memory_bytes_per_candidate_cell",
        "scratch_bytes_per_candidate_cell",
        "serialized_object_bytes_maximum",
        "serialized_object_receipt_count_maximum",
        "serialized_object_receipt_spool_bytes_maximum",
        "serialized_payload_bytes_per_cell_maximum",
        "worker_frame_count_maximum",
        "controller_registered_scratch_bytes_checkpoint_maximum",
        "output_bytes_per_unit",
        "cells_per_shard",
        "max_concurrency",
        "candidate_retry_count",
        "infrastructure_preemption_whole_shard_rerun_limit",
        "authority",
        "resource_policy_sha256",
    }
)
_CELL_EXECUTION_RECEIPT_KEYS = frozenset(
    {
        "cell_binding_sha256",
        "freshness_seconds",
        "rho",
        "phase_receipts",
        "candidate_cell_receipts",
        "candidate_cell_receipt_count",
        "physical_record_count",
        "candidate_retry_count",
        "peak_resident_memory_bytes",
        "peak_scratch_bytes",
    }
)
_WORKER_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "candidate",
        "controller_schedule_phase_audits",
        "controller_expected_f1m_size_class_count",
        "controller_expected_f1m_size_class_set_sha256",
        "controller_expected_f1m_phase_size_class_counts",
        "controller_expected_f1m_phase_query_counts",
        "controller_expected_f1m_phase_dummy_route_counts",
        "controller_expected_f1m_phase_random_route_counts",
        "controller_f1m_cardinality_derivation_root_sha256",
        "controller_expected_serialized_equivalence_class_count",
        "controller_registered_scratch_bytes_checkpoint_maximum",
        "controller_observed_registered_scratch_peak_bytes",
        "anonymous_scratch_creation_isolation_verified",
        "f1m_controller_context_sha256",
        "f1m_route_coverage_sha256",
        "f1m_charged_size_class_set_sha256",
        "input_binding_document",
        "input_binding_sha256",
        "object_receipt_byte_count",
        "object_receipt_line_count",
        "object_receipt_spool_sha256",
        "raw_protocol_object_bytes_retained",
        "controller_f1m_window_batch_stream_sha256",
        "pre_dispatch_context_sha256",
        "production_execution_admissible",
        "runtime_state_continuity_verified",
        "worker_declared_phase_audits_match_controller_schedule_audits",
        "worker_observed_f1m_materialized_binding_count",
        "worker_observed_f1m_size_class_count",
        "weighted_query_range_coverage_verified",
        "worker_candidate_cell_receipt_sha256",
    }
)
_CELL_PHASE_RECEIPT_KEYS = frozenset(
    {
        "phase",
        "accepted_event_group_range",
        "accepted_event_group_count",
        "realized_publication_window_count",
        "realized_set_count",
        "realized_query_count",
        "consumed_window_audit_stream_sha256",
    }
)
_WORKER_PHASE_AUDIT_KEYS = frozenset(
    {
        "phase",
        "accepted_group_start",
        "accepted_group_end",
        "realized_window_count",
        "realized_set_count",
        "realized_query_count",
        "consumed_window_audit_stream_sha256",
    }
)
_WORKER_CANDIDATE_KEYS = frozenset(
    {
        "candidate_id",
        "candidate_role",
        "candidate_retry_count",
        "receipt_origin",
        "terminal_outcome",
        "terminal_failure_code",
        "controller_observed_elapsed_ns",
        "controller_observed_peak_resident_memory_bytes",
        "controller_observed_peak_scratch_bytes",
        "phases",
        "worker_declared_state_reset_count",
    }
)
_F1M_SIZE_CLASS_KEYS = frozenset(
    {
        "schema_version",
        "version_id",
        "output_plan_digest",
        "component_id",
        "output_block_id",
        "f1m_kind",
        "private_plan_digest",
        "execution_binding_digest",
    }
)


class PublicationDay1BHold(RuntimeError):
    """A required pre-dispatch publication authority is not frozen."""


@dataclass(frozen=True, slots=True)
class _PendingDay1BResourcePolicy:
    """Closed descriptive identity of a policy that cannot authorize execution."""

    state: str
    canonical_sha256: str


def _decode_pending_day1b_resource_policy(content: bytes) -> _PendingDay1BResourcePolicy:
    """Decode only the empirical-null, authority-false pre-S1 placeholder."""

    if (
        type(content) is not bytes
        or not content
        or len(content) > (_DAY1B_PENDING_RESOURCE_POLICY_BYTES_MAXIMUM)
    ):
        raise ValueError("pending Day1B resource policy bytes are outside the closed bound")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("pending Day1B resource policy contains a duplicate key")
            document[key] = value
        return document

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"pending Day1B resource policy contains {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pending Day1B resource policy is not canonical UTF-8 JSON") from error
    if (
        type(document) is not dict
        or set(document) != _PENDING_RESOURCE_POLICY_KEYS
        or canonical_json_bytes(document) != content
    ):
        raise ValueError("pending Day1B resource policy top-level document is not exact")

    nested_contracts = (
        ("amendment_identity", _PENDING_AMENDMENT_IDENTITY_KEYS, None),
        ("authority", _PENDING_AUTHORITY_KEYS, False),
        ("limits", _PENDING_LIMIT_KEYS, None),
        ("measurement_methods", _PENDING_MEASUREMENT_METHOD_KEYS, None),
        ("pilot_evidence", _PENDING_PILOT_EVIDENCE_KEYS, None),
        ("worker_runtime_identity", _PENDING_WORKER_RUNTIME_IDENTITY_KEYS, None),
    )
    for field, expected_keys, expected_value in nested_contracts:
        nested = document[field]
        if (
            type(nested) is not dict
            or set(nested) != expected_keys
            or any(value is not expected_value for value in nested.values())
        ):
            raise ValueError(
                f"pending Day1B resource policy {field} must retain its exact placeholder state"
            )
    protocol_invariants = document["protocol_invariants"]
    if (
        type(protocol_invariants) is not dict
        or set(protocol_invariants) != _PENDING_PROTOCOL_INVARIANT_KEYS
        or type(protocol_invariants["candidate_retry_count"]) is not int
        or protocol_invariants["candidate_retry_count"] != 0
        or protocol_invariants["selective_candidate_retry_allowed"] is not False
    ):
        raise ValueError(
            "pending Day1B resource policy must retain the preregistered no-retry "
            "protocol invariant"
        )
    if (
        document["schema_version"] != DAY1B_PENDING_RESOURCE_POLICY_SCHEMA
        or document["state"] != "PENDING-FREEZE"
    ):
        raise ValueError("pending Day1B resource policy cannot be promoted or retargeted")
    return _PendingDay1BResourcePolicy(
        state="PENDING-FREEZE",
        canonical_sha256=hashlib.sha256(content).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class PublicationDay1BResourcePolicy:
    """One outcome-blind resource envelope fixed before a unit is dispatched."""

    wall_clock_seconds_per_candidate_cell: int
    resident_memory_bytes_per_candidate_cell: int
    scratch_bytes_per_candidate_cell: int
    serialized_object_bytes_maximum: int
    serialized_object_receipt_count_maximum: int
    serialized_object_receipt_spool_bytes_maximum: int
    serialized_payload_bytes_per_cell_maximum: int
    worker_frame_count_maximum: int
    controller_registered_scratch_bytes_checkpoint_maximum: int
    output_bytes_per_unit: int
    cells_per_shard: int
    max_concurrency: int
    candidate_retry_count: int
    infrastructure_preemption_whole_shard_rerun_limit: int
    authority: str

    def __post_init__(self) -> None:
        for field in (
            "wall_clock_seconds_per_candidate_cell",
            "resident_memory_bytes_per_candidate_cell",
            "scratch_bytes_per_candidate_cell",
            "serialized_object_bytes_maximum",
            "serialized_object_receipt_count_maximum",
            "serialized_object_receipt_spool_bytes_maximum",
            "serialized_payload_bytes_per_cell_maximum",
            "worker_frame_count_maximum",
            "controller_registered_scratch_bytes_checkpoint_maximum",
            "output_bytes_per_unit",
            "cells_per_shard",
            "max_concurrency",
            "candidate_retry_count",
            "infrastructure_preemption_whole_shard_rerun_limit",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"resource_policy.{field} must be a strict nonnegative integer")
        if (
            min(
                self.wall_clock_seconds_per_candidate_cell,
                self.resident_memory_bytes_per_candidate_cell,
                self.scratch_bytes_per_candidate_cell,
                self.serialized_object_bytes_maximum,
                self.serialized_object_receipt_count_maximum,
                self.serialized_object_receipt_spool_bytes_maximum,
                self.serialized_payload_bytes_per_cell_maximum,
                self.worker_frame_count_maximum,
                self.controller_registered_scratch_bytes_checkpoint_maximum,
                self.output_bytes_per_unit,
            )
            <= 0
        ):
            raise ValueError("resource-policy wall/RAM/scratch/output limits must be positive")
        if self.cells_per_shard != 18 or self.max_concurrency != 1:
            raise ValueError("Day1B resource policy requires exactly 18 cells and concurrency one")
        if self.candidate_retry_count != 0:
            raise ValueError("Day1B candidate selective retries must be exactly zero")
        if self.infrastructure_preemption_whole_shard_rerun_limit not in {0, 1}:
            raise ValueError("whole-shard infrastructure-preemption reruns must be zero or one")
        if type(self.authority) is not str or not self.authority:
            raise ValueError("resource_policy.authority must be a nonempty string")

    def to_document(self) -> dict[str, object]:
        document = {"schema_version": DAY1B_RESOURCE_POLICY_SCHEMA, **asdict(self)}
        document["resource_policy_sha256"] = _digest(document)
        return document

    def to_worker_limits(self) -> Day1BWorkerResourceLimits:
        return Day1BWorkerResourceLimits(
            wall_clock_ns_per_candidate_cell=(
                self.wall_clock_seconds_per_candidate_cell * 1_000_000_000
            ),
            resident_memory_bytes_per_candidate_cell=(
                self.resident_memory_bytes_per_candidate_cell
            ),
            scratch_bytes_per_candidate_cell=self.scratch_bytes_per_candidate_cell,
            serialized_object_bytes_maximum=self.serialized_object_bytes_maximum,
            serialized_object_receipt_count_maximum=(self.serialized_object_receipt_count_maximum),
            serialized_object_receipt_spool_bytes_maximum=(
                self.serialized_object_receipt_spool_bytes_maximum
            ),
            serialized_payload_bytes_per_cell_maximum=(
                self.serialized_payload_bytes_per_cell_maximum
            ),
            worker_frame_count_maximum=self.worker_frame_count_maximum,
            controller_registered_scratch_bytes_checkpoint_maximum=(
                self.controller_registered_scratch_bytes_checkpoint_maximum
            ),
        )


@dataclass(frozen=True, slots=True)
class _Day1BResourceAmendment:
    """One decoded resource-only amendment; never a dispatch capability."""

    state: str
    amendment_id: str
    amendment_payload_sha256: str
    canonical_sha256: str
    schema_source_git_sha: str
    schema_source_behavior_inventory_sha256: str
    structure_pilot_source_git_sha: str
    structure_pilot_report_sha256: str
    structure_pilot_checksums_sha256: str
    review_receipt_sha256: str
    measurement_methods: tuple[tuple[str, str], ...]
    shard_wall_clock_seconds_maximum: int
    job_wall_clock_seconds_maximum: int
    shard_cost_budget_usd_maximum: str
    job_cost_budget_usd_maximum: str
    resource_policy: PublicationDay1BResourcePolicy


@dataclass(frozen=True, slots=True)
class _PublicationScheduleAdapter:
    """Internal schedule seam with production and small typed-test adapters."""

    schema_version: str
    rho: Fraction
    phase_ranges: tuple[AcceptedGroupPhaseRange, ...]
    accepted_group_count: int
    total_set_count: int
    total_query_count: int
    canonical_schedule_sha256: str
    iter_canonical_bytes: Callable[[], Iterator[bytes]]
    stream_windows: Callable[[Fraction], Iterator[ExactPublicationWindow]]


@dataclass(frozen=True, slots=True)
class _Day1BTraceInput:
    """Already validated trace facts consumed by the private unit builder."""

    dataset_id: str
    dataset_release: str
    semantics: str
    source_partition: int
    trace_source_git_sha: str
    trace_behavior_source_blob_sha256: tuple[tuple[str, str], ...]
    trace_behavior_source_inventory_sha256: str
    repository_provenance_sha256: str
    trace_manifest_sha256: str
    mapping_sha256: str
    accepted_events_sha256: str
    replay_receipt_sha256: str
    source_bundle_sha256: str
    acquisition_transaction_sha256: str | None
    source_set_sha256: str | None
    acquisition_behavior_set_sha256: str | None
    acquisition_behavior_inventory_sha256: str | None
    acquisition_authority_state: str | None
    acquisition_network_authority_verified: bool
    accepted_group_count: int
    query_vector: tuple[int, ...]
    query_vector_canonical_bytes: bytes
    query_vector_sha256: str
    compile_schedule: Callable[[Fraction], _PublicationScheduleAdapter]
    trace_source_authority_verified: bool = False


@dataclass(frozen=True, slots=True)
class _Day1BPreparatorySourceAttestation:
    git_sha: str
    behavior_inventory: Mapping[str, object]
    source_attestation: str


@dataclass(frozen=True, slots=True)
class _Day1BF1MExecutionLineage:
    """Repository-admitted anchors and worker identities unavailable from a trace."""

    day1_registration_anchor_sha256: str
    trace_post_run_anchor_sha256: str
    worker_build_identity_sha256: str
    worker_runtime_identity_sha256: str

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            _require_sha256(getattr(self, field), f"Day1B F1-M lineage {field}")


@dataclass(frozen=True, slots=True)
class _Day1BControllerReplay:
    """The two controller-owned preimages produced by one deterministic replay."""

    f1m_summary: Day1BF1MControllerSummary
    expected_counts: Day1BControllerExpectedCounts

    def __post_init__(self) -> None:
        if type(self.f1m_summary) is not Day1BF1MControllerSummary:
            raise TypeError("controller replay requires one exact F1-M summary")
        if type(self.expected_counts) is not Day1BControllerExpectedCounts:
            raise TypeError("controller replay requires one exact expected-count preimage")
        if (
            self.expected_counts.accounting_sha256
            != self.f1m_summary.context.accounting_sha256
        ):
            raise Day1BWorkerProtocolError(
                "controller replay summary and expected counts bind different accounting"
            )


class _Day1BExecutionAdapter(Protocol):
    """Launch exactly one canonical candidate×cell worker invocation.

    The adapter owns every minted invocation capability until an exact
    :class:`_Day1BWorkerLaunch` returns. It must abandon that capability on every
    pre-return exception; after return, ownership transfers to the core.
    """

    def execute_candidate_cell(
        self,
        *,
        windows: Iterator[ExactPublicationWindow],
        contract_seed: _Day1BWorkerContractSeed,
    ) -> _Day1BWorkerLaunch: ...


@dataclass(frozen=True, slots=True)
class _Day1BWorkerLaunch:
    """Controller output for one candidate×cell; never a caller-minted receipt."""

    contract: Day1BWorkerProtocolContract
    frame_chunks: Iterable[bytes]
    invocation_capability: Day1BWorkerInvocationCapability

    def __post_init__(self) -> None:
        if type(self.contract) is not Day1BWorkerProtocolContract:
            raise TypeError("worker launch requires one exact bound contract")
        if type(self.invocation_capability) is not Day1BWorkerInvocationCapability:
            raise TypeError("worker launch requires one exact invocation capability")
        try:
            iter(self.frame_chunks)
        except TypeError as error:
            raise TypeError("worker launch frame chunks must be iterable") from error


@dataclass(frozen=True, slots=True)
class PublicationDay1BUnitBundle:
    """Paths and independently recomputed member identities of one installed unit."""

    output_dir: Path
    manifest_path: Path
    heldout_fragment_path: Path
    schedule_path: Path
    serialization_ledger_path: Path
    serialized_object_receipt_path: Path
    checksums_path: Path
    manifest_sha256: str
    heldout_fragment_sha256: str
    schedule_sha256: str
    serialization_ledger_sha256: str
    serialized_object_receipt_sha256: str
    checksums_sha256: str


@dataclass(frozen=True, slots=True)
class _CellAudit:
    phase_audits: tuple[Day1BWorkerPhaseAudit, ...]

    @property
    def phase_receipts(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "phase": audit.phase,
                "accepted_event_group_range": [
                    audit.accepted_group_start,
                    audit.accepted_group_end,
                ],
                "accepted_event_group_count": (
                    audit.accepted_group_end - audit.accepted_group_start
                ),
                "realized_publication_window_count": audit.realized_window_count,
                "realized_set_count": audit.realized_set_count,
                "realized_query_count": audit.realized_query_count,
                "consumed_window_audit_stream_sha256": (audit.consumed_window_audit_stream_sha256),
            }
            for audit in self.phase_audits
        )


class _AuditedWindowStream:
    """Audit a one-pass schedule stream without retaining Publication Windows."""

    __slots__ = (
        "_expected_index",
        "_exhausted",
        "_iterator",
        "_phase_hashers",
        "_phase_ranges",
        "_phase_stats",
        "_rho",
    )

    def __init__(
        self,
        windows: Iterator[ExactPublicationWindow],
        phase_ranges: tuple[AcceptedGroupPhaseRange, ...],
        rho: Fraction,
    ) -> None:
        self._iterator = iter(windows)
        self._phase_ranges = {phase.name: phase for phase in phase_ranges}
        self._phase_stats = {
            phase.name: {"window_count": 0, "set_count": 0, "query_count": 0}
            for phase in phase_ranges
        }
        self._phase_hashers = {phase.name: hashlib.sha256() for phase in phase_ranges}
        self._rho = rho
        self._expected_index = 0
        self._exhausted = False

    def __iter__(self) -> _AuditedWindowStream:
        return self

    def __next__(self) -> ExactPublicationWindow:
        try:
            window = next(self._iterator)
        except StopIteration:
            self._exhausted = True
            raise
        if type(window) is not ExactPublicationWindow:
            raise ValueError("execution adapter windows must be exact publication windows")
        if window.index != self._expected_index:
            raise ValueError("publication-window indexes must be contiguous from zero")
        self._expected_index += 1
        phase = self._phase_ranges.get(window.phase)
        if phase is None:
            raise ValueError("publication window has an unknown accepted-group phase")
        if not (
            phase.start <= window.accepted_group_start < window.accepted_group_end <= phase.end
        ):
            raise ValueError("publication window accepted ordinals escape their phase range")
        if type(window.set_count) is not int or window.set_count < 0:
            raise ValueError("publication-window SET count must be nonnegative")
        if type(window.query_count) is not int or window.query_count < 0:
            raise ValueError("publication-window QUERY count must be nonnegative")
        stats = self._phase_stats[window.phase]
        stats["window_count"] += 1
        stats["set_count"] += window.set_count
        stats["query_count"] += window.query_count
        self._phase_hashers[window.phase].update(
            canonical_day1b_worker_window_audit_bytes(
                index=window.index,
                phase=window.phase,
                accepted_group_start=window.accepted_group_start,
                accepted_group_end=window.accepted_group_end,
                start_time=window.start_time,
                end_time=window.end_time,
                set_count=window.set_count,
                updates=tuple(
                    (update.row, update.col, update.before, update.after)
                    for update in window.updates
                ),
                query_count=window.query_count,
                reason=window.reason,
            )
        )
        return window

    def finish(self) -> _CellAudit:
        if not self._exhausted:
            try:
                next(self)
            except StopIteration:
                pass
            else:
                raise ValueError("execution adapter did not consume the complete window stream")
        receipts: list[Day1BWorkerPhaseAudit] = []
        for phase_name in ("warmup", "tuning", "heldout"):
            phase = self._phase_ranges[phase_name]
            stats = self._phase_stats[phase_name]
            expected_query_count = _phase_query_count((phase.start, phase.end), self._rho)
            if stats["query_count"] != expected_query_count:
                raise ValueError("realized phase QUERY count does not match the exact RLE schedule")
            receipts.append(
                Day1BWorkerPhaseAudit(
                    phase=phase_name,
                    accepted_group_start=phase.start,
                    accepted_group_end=phase.end,
                    realized_window_count=stats["window_count"],
                    realized_set_count=stats["set_count"],
                    realized_query_count=stats["query_count"],
                    consumed_window_audit_stream_sha256=(
                        self._phase_hashers[phase_name].hexdigest()
                    ),
                )
            )
        return _CellAudit(tuple(receipts))


def _digest(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase 40-digit Git SHA")
    return value


def _decode_day1b_resource_amendment(content: bytes) -> _Day1BResourceAmendment:
    """Decode one canonical resource-only amendment without granting authority."""

    if (
        type(content) is not bytes
        or not content
        or len(content) > _DAY1B_RESOURCE_AMENDMENT_BYTES_MAXIMUM
    ):
        raise ValueError("Day1B resource amendment bytes are outside the closed bound")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Day1B resource amendment contains a duplicate key")
            result[key] = value
        return result

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"Day1B resource amendment contains {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Day1B resource amendment is not canonical UTF-8 JSON") from error
    if (
        type(document) is not dict
        or set(document) != _RESOURCE_AMENDMENT_KEYS
        or canonical_json_bytes(document) != content
    ):
        raise ValueError("Day1B resource amendment top-level document is not exact")

    def exact_nested(field: str, keys: frozenset[str]) -> dict[str, object]:
        value = document[field]
        if type(value) is not dict or set(value) != keys:
            raise ValueError(f"Day1B resource amendment {field} is not exact")
        return value

    identity = exact_nested("amendment_identity", _RESOURCE_AMENDMENT_IDENTITY_KEYS)
    limits = exact_nested("limits", _PENDING_LIMIT_KEYS)
    methods = exact_nested("measurement_methods", _PENDING_MEASUREMENT_METHOD_KEYS)
    pilot = exact_nested("pilot_evidence", _PENDING_PILOT_EVIDENCE_KEYS)
    protocol = exact_nested("protocol_invariants", _PENDING_PROTOCOL_INVARIANT_KEYS)
    schema_source = exact_nested("schema_source", _RESOURCE_AMENDMENT_SCHEMA_SOURCE_KEYS)

    if (
        document["schema_version"] != DAY1B_RESOURCE_AMENDMENT_SCHEMA
        or document["state"] != _RESOURCE_AMENDMENT_STATE
    ):
        raise ValueError(
            "Day1B resource amendment must freeze resource values without authorizing dispatch"
        )
    amendment_id = identity["resource_policy_amendment_id"]
    if type(amendment_id) is not str or _RESOURCE_AMENDMENT_ID.fullmatch(amendment_id) is None:
        raise ValueError("Day1B resource amendment ID is not one canonical token")
    amendment_payload_sha256 = _require_sha256(
        identity["resource_policy_amendment_payload_sha256"],
        "Day1B resource amendment payload digest",
    )
    schema_source_git_sha = _require_git_sha(
        schema_source["git_sha"], "Day1B resource amendment schema-source Git SHA"
    )
    schema_source_inventory_sha256 = _require_sha256(
        schema_source["behavior_inventory_sha256"],
        "Day1B resource amendment schema-source Behavior inventory digest",
    )

    positive_integer_limit_fields = _PENDING_LIMIT_KEYS - {
        "infrastructure_preemption_whole_shard_rerun_limit",
        "job_cost_budget_usd_maximum",
        "shard_cost_budget_usd_maximum",
    }
    for field in positive_integer_limit_fields:
        value = limits[field]
        if type(value) is not int or value <= 0:
            raise ValueError(
                f"Day1B resource amendment limits.{field} must be a strict positive integer"
            )
    if limits["cells_per_shard"] != 18 or limits["max_concurrency"] != 1:
        raise ValueError("Day1B resource amendment requires exactly 18 cells and concurrency one")
    preemption_rerun_limit = limits["infrastructure_preemption_whole_shard_rerun_limit"]
    if type(preemption_rerun_limit) is not int or preemption_rerun_limit not in {0, 1}:
        raise ValueError(
            "Day1B resource amendment whole-shard preemption reruns must be zero or one"
        )
    if limits["output_bytes_per_unit"] > _DAY1B_ARTIFACT_BYTES_HARD_MAXIMUM:
        raise ValueError("Day1B resource amendment output limit exceeds the hard ceiling")
    if (
        limits["shard_wall_clock_seconds_maximum"] < limits["wall_clock_seconds_per_candidate_cell"]
        or limits["job_wall_clock_seconds_maximum"] < limits["shard_wall_clock_seconds_maximum"]
    ):
        raise ValueError("Day1B resource amendment wall-clock budgets are not nested")

    canonical_costs: dict[str, str] = {}
    for field in ("shard_cost_budget_usd_maximum", "job_cost_budget_usd_maximum"):
        value = limits[field]
        if type(value) is not str or _CANONICAL_POSITIVE_DECIMAL.fullmatch(value) is None:
            raise ValueError(
                f"Day1B resource amendment limits.{field} must be one canonical "
                "positive decimal string"
            )
        canonical_costs[field] = value
    if Fraction(canonical_costs["job_cost_budget_usd_maximum"]) < Fraction(
        canonical_costs["shard_cost_budget_usd_maximum"]
    ):
        raise ValueError("Day1B resource amendment cost budgets are not nested")

    canonical_methods: list[tuple[str, str]] = []
    for field in sorted(_PENDING_MEASUREMENT_METHOD_KEYS):
        value = methods[field]
        if type(value) is not str or _RESOURCE_AMENDMENT_METHOD_TOKEN.fullmatch(value) is None:
            raise ValueError(
                f"Day1B resource amendment measurement_methods.{field} "
                "must be one canonical method token"
            )
        canonical_methods.append((field, value))

    structure_pilot_source_git_sha = _require_git_sha(
        pilot["structure_pilot_source_git_sha"],
        "Day1B resource amendment structure-pilot source Git SHA",
    )
    structure_pilot_report_sha256 = _require_sha256(
        pilot["structure_pilot_report_sha256"],
        "Day1B resource amendment structure-pilot report digest",
    )
    structure_pilot_checksums_sha256 = _require_sha256(
        pilot["structure_pilot_checksums_sha256"],
        "Day1B resource amendment structure-pilot checksums digest",
    )
    review_receipt_sha256 = _require_sha256(
        pilot["review_receipt_sha256"],
        "Day1B resource amendment outcome-blind review-receipt digest",
    )
    if (
        type(protocol["candidate_retry_count"]) is not int
        or protocol["candidate_retry_count"] != 0
        or protocol["selective_candidate_retry_allowed"] is not False
    ):
        raise ValueError(
            "Day1B resource amendment must retain the preregistered no-selective-retry rule"
        )

    digest_preimage = {
        **document,
        "amendment_identity": {
            "resource_policy_amendment_id": amendment_id,
        },
    }
    if _digest(digest_preimage) != amendment_payload_sha256:
        raise ValueError("Day1B resource amendment payload digest is not self-binding")

    resource_policy = PublicationDay1BResourcePolicy(
        wall_clock_seconds_per_candidate_cell=limits["wall_clock_seconds_per_candidate_cell"],
        resident_memory_bytes_per_candidate_cell=limits["resident_memory_bytes_per_candidate_cell"],
        scratch_bytes_per_candidate_cell=limits["scratch_bytes_per_candidate_cell"],
        serialized_object_bytes_maximum=limits["serialized_object_bytes_maximum"],
        serialized_object_receipt_count_maximum=limits["serialized_object_receipt_count_maximum"],
        serialized_object_receipt_spool_bytes_maximum=limits[
            "serialized_object_receipt_spool_bytes_maximum"
        ],
        serialized_payload_bytes_per_cell_maximum=limits[
            "serialized_payload_bytes_per_cell_maximum"
        ],
        worker_frame_count_maximum=limits["worker_frame_count_maximum"],
        controller_registered_scratch_bytes_checkpoint_maximum=limits[
            "controller_registered_scratch_bytes_checkpoint_maximum"
        ],
        output_bytes_per_unit=limits["output_bytes_per_unit"],
        cells_per_shard=limits["cells_per_shard"],
        max_concurrency=limits["max_concurrency"],
        candidate_retry_count=protocol["candidate_retry_count"],
        infrastructure_preemption_whole_shard_rerun_limit=preemption_rerun_limit,
        authority=(f"non-authorizing-resource-amendment-binding:{amendment_payload_sha256}"),
    )
    return _Day1BResourceAmendment(
        state=_RESOURCE_AMENDMENT_STATE,
        amendment_id=amendment_id,
        amendment_payload_sha256=amendment_payload_sha256,
        canonical_sha256=hashlib.sha256(content).hexdigest(),
        schema_source_git_sha=schema_source_git_sha,
        schema_source_behavior_inventory_sha256=schema_source_inventory_sha256,
        structure_pilot_source_git_sha=structure_pilot_source_git_sha,
        structure_pilot_report_sha256=structure_pilot_report_sha256,
        structure_pilot_checksums_sha256=structure_pilot_checksums_sha256,
        review_receipt_sha256=review_receipt_sha256,
        measurement_methods=tuple(canonical_methods),
        shard_wall_clock_seconds_maximum=limits["shard_wall_clock_seconds_maximum"],
        job_wall_clock_seconds_maximum=limits["job_wall_clock_seconds_maximum"],
        shard_cost_budget_usd_maximum=canonical_costs["shard_cost_budget_usd_maximum"],
        job_cost_budget_usd_maximum=canonical_costs["job_cost_budget_usd_maximum"],
        resource_policy=resource_policy,
    )


def _fraction_text(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    denominator = value.denominator
    terminating = denominator
    while terminating % 2 == 0:
        terminating //= 2
    while terminating % 5 == 0:
        terminating //= 5
    if terminating != 1:
        return f"{value.numerator}/{value.denominator}"
    whole, remainder = divmod(value.numerator, value.denominator)
    digits: list[str] = []
    while remainder:
        remainder *= 10
        digit, remainder = divmod(remainder, value.denominator)
        digits.append(str(digit))
    return str(whole) if not digits else f"{whole}.{''.join(digits)}"


def _phase_query_count(accepted_range: tuple[int, int], rho: Fraction) -> int:
    start, end = accepted_range
    return (end * rho.numerator // rho.denominator) - (start * rho.numerator // rho.denominator)


def _validate_preparatory_source_attestation(
    source: _Day1BPreparatorySourceAttestation,
) -> None:
    if type(source) is not _Day1BPreparatorySourceAttestation:
        raise TypeError("source_attestation must be an exact typed preparatory attestation")
    _require_git_sha(source.git_sha, "experiment source Git SHA")
    if type(source.behavior_inventory) is not dict:
        raise ValueError("experiment source behavior inventory must be an exact object")
    inventory = source.behavior_inventory
    if (
        inventory.get("role") != EvidenceRole.DAY1B.value
        or inventory.get("source_git_sha") != source.git_sha
        or inventory.get("behavior_set_schema_version")
        != "dynamic-cssc-day1b-preparatory-behavior-set-v24"
    ):
        raise ValueError(
            "preparatory source inventory must bind the DAY1B role, schema, and exact S1"
        )
    _require_sha256(inventory.get("behavior_set_sha256"), "Behavior Set digest")
    if type(source.source_attestation) is not str or not source.source_attestation:
        raise ValueError("preparatory source attestation must be a nonempty string")


def _validate_trace(trace: _Day1BTraceInput) -> None:
    if type(trace) is not _Day1BTraceInput:
        raise TypeError("trace must be an exact typed Day1B trace input")
    if trace.dataset_id not in DATASET_IDS or trace.semantics not in SEMANTICS:
        raise ValueError("Day1B trace must name one frozen primary dataset and semantics")
    if type(trace.source_partition) is not int or trace.source_partition not in range(
        PUBLICATION_SOURCE_PARTITION_COUNT
    ):
        raise ValueError("Day1B source partition is outside the frozen domain")
    _require_git_sha(trace.trace_source_git_sha, "trace source Git SHA")
    for field in (
        "repository_provenance_sha256",
        "trace_behavior_source_inventory_sha256",
        "trace_manifest_sha256",
        "mapping_sha256",
        "accepted_events_sha256",
        "replay_receipt_sha256",
        "source_bundle_sha256",
        "query_vector_sha256",
    ):
        _require_sha256(getattr(trace, field), f"trace.{field}")
    if (
        type(trace.trace_behavior_source_blob_sha256) is not tuple
        or not trace.trace_behavior_source_blob_sha256
        or tuple(sorted(trace.trace_behavior_source_blob_sha256))
        != trace.trace_behavior_source_blob_sha256
    ):
        raise ValueError("trace behavior-source mapping must be one nonempty canonical tuple")
    behavior_sources: dict[str, str] = {}
    for path, digest in trace.trace_behavior_source_blob_sha256:
        if type(path) is not str or not path or path in behavior_sources:
            raise ValueError("trace behavior-source paths must be unique nonempty strings")
        behavior_sources[path] = _require_sha256(digest, f"trace behavior source {path!r}")
    if _digest(behavior_sources) != trace.trace_behavior_source_inventory_sha256:
        raise ValueError("trace behavior-source mapping digest does not bind its exact mapping")
    for field in (
        "acquisition_transaction_sha256",
        "source_set_sha256",
        "acquisition_behavior_set_sha256",
        "acquisition_behavior_inventory_sha256",
    ):
        value = getattr(trace, field)
        if value is not None:
            _require_sha256(value, f"trace.{field}")
    acquisition_binding_facts = (
        trace.acquisition_transaction_sha256,
        trace.source_set_sha256,
        trace.acquisition_behavior_set_sha256,
        trace.acquisition_behavior_inventory_sha256,
        trace.acquisition_authority_state,
    )
    if any(value is None for value in acquisition_binding_facts) and not all(
        value is None for value in acquisition_binding_facts
    ):
        raise ValueError("trace acquisition binding projection must be complete or absent")
    if (
        trace.acquisition_authority_state is not None
        and trace.acquisition_authority_state not in _TRACE_ACQUISITION_HOLD_STATES
    ):
        raise ValueError("trace acquisition authority state must remain an exact frozen HOLD")
    if trace.acquisition_network_authority_verified is not False:
        raise ValueError("trace acquisition network authority must remain exact false")
    if trace.trace_source_authority_verified is not False:
        raise ValueError("trace source authority must remain exact false before central admission")
    if type(trace.accepted_group_count) is not int or trace.accepted_group_count < 10:
        raise ValueError("Day1B trace must contain at least ten accepted-event groups")
    if type(trace.query_vector) is not tuple or not trace.query_vector:
        raise ValueError("Day1B trace query vector must be one nonempty immutable vector")
    if any(type(value) is not int or value not in {-1, 0, 1} for value in trace.query_vector):
        raise ValueError("Day1B trace query vector must contain exact ternary integers")
    if type(trace.query_vector_canonical_bytes) is not bytes:
        raise ValueError("Day1B trace query vector must retain exact canonical bytes")
    if hashlib.sha256(trace.query_vector_canonical_bytes).hexdigest() != (
        trace.query_vector_sha256
    ):
        raise ValueError("Day1B trace query-vector bytes do not match their bound digest")
    try:
        query_vector_payload = json.loads(trace.query_vector_canonical_bytes.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Day1B trace query vector must be canonical ASCII JSON") from error
    if (
        type(query_vector_payload) is not dict
        or canonical_json_bytes(query_vector_payload) != trace.query_vector_canonical_bytes
        or query_vector_payload.get("schema_version") != QUERY_VECTOR_SCHEMA
        or query_vector_payload.get("values") != list(trace.query_vector)
    ):
        raise ValueError("Day1B trace query vector does not match its canonical artifact binding")


def _artifact_variant_contract(
    token: object,
    *,
    trace: _Day1BTraceInput,
    source: _Day1BPreparatorySourceAttestation,
) -> tuple[Mapping[str, object], str, str]:
    """Select one closed artifact variant and reject crossed provenance facts."""

    artifact_variant, unit_schema, fragment_schema = _artifact_variant_schema_contract(token)
    if token is _PRODUCTION_ARTIFACT_VARIANT_TOKEN:
        required_acquisition_facts = (
            trace.acquisition_transaction_sha256,
            trace.source_set_sha256,
            trace.acquisition_behavior_set_sha256,
            trace.acquisition_behavior_inventory_sha256,
        )
        if (
            source.source_attestation != "repository-clean-head"
            or any(value is None for value in required_acquisition_facts)
            or trace.acquisition_authority_state != "HOLD-no-repository-post-run-anchor"
        ):
            raise ValueError(
                "production artifact variant requires clean source and complete HOLD provenance"
            )
    else:
        fixture_only_facts = (
            trace.acquisition_transaction_sha256,
            trace.source_set_sha256,
            trace.acquisition_behavior_set_sha256,
            trace.acquisition_behavior_inventory_sha256,
            trace.acquisition_authority_state,
        )
        if source.source_attestation != "test-only-typed-day1b-source" or any(
            value is not None for value in fixture_only_facts
        ):
            raise ValueError(
                "fixture artifact variant rejects production source or acquisition provenance"
            )
    return artifact_variant, unit_schema, fragment_schema


def _artifact_variant_schema_contract(
    token: object,
) -> tuple[Mapping[str, object], str, str]:
    """Resolve the closed schema pair without accepting a caller-authored discriminator."""

    if token is _PRODUCTION_ARTIFACT_VARIANT_TOKEN:
        return _PRODUCTION_ARTIFACT_VARIANT, DAY1B_UNIT_SCHEMA, DAY1B_UNIT_FRAGMENT_SCHEMA
    if token is _TEST_ARTIFACT_VARIANT_TOKEN:
        return (
            _TEST_ARTIFACT_VARIANT,
            _TEST_DAY1B_UNIT_SCHEMA,
            _TEST_DAY1B_UNIT_FRAGMENT_SCHEMA,
        )
    raise TypeError("Day1B artifact variant requires one exact producer capability")


def _validate_catalog(catalog: Day1CandidateCatalog) -> tuple[RegisteredCandidate, ...]:
    if type(catalog) is not Day1CandidateCatalog:
        raise TypeError("candidate catalog must be an exact repository catalog")
    by_id = {candidate.candidate_id: candidate for candidate in catalog.candidates}
    if tuple(by_id) != FIXED_CANDIDATE_IDS or len(by_id) != len(FIXED_CANDIDATE_IDS):
        raise ValueError("candidate catalog must equal the analyzer's exact fixed roster order")
    if tuple(candidate.candidate_id for candidate in catalog.selection_candidates) != (
        REFERENCE_CANDIDATE_IDS
    ):
        raise ValueError("candidate catalog must equal the analyzer's 13-reference order")
    if tuple(candidate.candidate_id for candidate in catalog.ablation_candidates) != (
        ABLATION_CANDIDATE_ID,
    ):
        raise ValueError("candidate catalog must contain the exact one ablation")
    return catalog.candidates


def _expected_phase_ranges(total: int) -> tuple[AcceptedGroupPhaseRange, ...]:
    return (
        AcceptedGroupPhaseRange("warmup", 0, total // 10),
        AcceptedGroupPhaseRange("tuning", total // 10, total * 4 // 10),
        AcceptedGroupPhaseRange("heldout", total * 4 // 10, total),
    )


def _validate_program(
    program: _PublicationScheduleAdapter,
    *,
    trace: _Day1BTraceInput,
    rho: Fraction,
) -> None:
    if type(program) is not _PublicationScheduleAdapter:
        raise TypeError("schedule compiler must return an exact typed adapter")
    if program.schema_version != ACCEPTED_EVENT_SCHEDULE_SCHEMA:
        raise ValueError("Day1B rejects a non-v2 accepted-event schedule")
    if program.rho != rho or program.accepted_group_count != trace.accepted_group_count:
        raise ValueError("schedule adapter retargeted rho or accepted-event cardinality")
    if program.phase_ranges != _expected_phase_ranges(trace.accepted_group_count):
        raise ValueError("schedule adapter must preserve the exact 10/30/60 ordinal ranges")
    if type(program.total_set_count) is not int or program.total_set_count < 0:
        raise ValueError("schedule total SET count must be nonnegative")
    expected_queries = trace.accepted_group_count * rho.numerator // rho.denominator
    if program.total_query_count != expected_queries:
        raise ValueError("schedule total QUERY count does not match exact rational rho")
    _require_sha256(program.canonical_schedule_sha256, "canonical schedule digest")
    if not callable(program.iter_canonical_bytes) or not callable(program.stream_windows):
        raise TypeError("schedule adapter must provide streaming schedule/window callables")


def _trace_unit_document(
    trace: _Day1BTraceInput,
    source: _Day1BPreparatorySourceAttestation,
) -> dict[str, object]:
    ranges = _expected_phase_ranges(trace.accepted_group_count)
    range_fields: dict[str, object] = {
        "accepted_raw_events_total": trace.accepted_group_count,
        "warmup_accepted_event_group_range": [ranges[0].start, ranges[0].end],
        "tuning_accepted_event_group_range": [ranges[1].start, ranges[1].end],
        "heldout_accepted_event_group_range": [ranges[2].start, ranges[2].end],
    }
    range_fields["accepted_event_group_ranges_sha256"] = _digest(range_fields)
    document: dict[str, object] = {
        "schema_version": TRACE_UNIT_SCHEMA,
        "experiment_source_git_sha": source.git_sha,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "trace_manifest_sha256": trace.trace_manifest_sha256,
        "mapping_sha256": trace.mapping_sha256,
        "accepted_events_sha256": trace.accepted_events_sha256,
        **range_fields,
        "replay_receipt_sha256": trace.replay_receipt_sha256,
        "source_bundle_sha256": trace.source_bundle_sha256,
    }
    document["trace_binding_sha256"] = _digest(document)
    return document


def _cell_document(
    trace_unit: Mapping[str, object],
    trace: _Day1BTraceInput,
    source: _Day1BPreparatorySourceAttestation,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    audit: _CellAudit,
) -> dict[str, object]:
    rho_text = _fraction_text(program.rho)
    freshness_text = _fraction_text(freshness)
    phase_receipts = {str(receipt["phase"]): receipt for receipt in audit.phase_receipts}
    if set(phase_receipts) != {"warmup", "tuning", "heldout"}:
        raise ValueError("cell audit must contain the exact warmup/tuning/heldout phases")
    document: dict[str, object] = {
        "schema_version": CELL_BINDING_SCHEMA,
        "experiment_source_git_sha": source.git_sha,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "freshness_seconds": freshness_text,
        "rho": rho_text,
        "trace_manifest_sha256": trace_unit["trace_manifest_sha256"],
        "mapping_sha256": trace_unit["mapping_sha256"],
        "accepted_events_sha256": trace_unit["accepted_events_sha256"],
        "accepted_raw_events_total": trace_unit["accepted_raw_events_total"],
        "warmup_accepted_event_group_range": trace_unit["warmup_accepted_event_group_range"],
        "tuning_accepted_event_group_range": trace_unit["tuning_accepted_event_group_range"],
        "heldout_accepted_event_group_range": trace_unit["heldout_accepted_event_group_range"],
        "accepted_event_group_ranges_sha256": trace_unit["accepted_event_group_ranges_sha256"],
        "replay_receipt_sha256": trace_unit["replay_receipt_sha256"],
        "source_bundle_sha256": trace_unit["source_bundle_sha256"],
        "trace_binding_sha256": trace_unit["trace_binding_sha256"],
        "tuning_update_count": phase_receipts["tuning"]["accepted_event_group_count"],
        "tuning_query_count": phase_receipts["tuning"]["realized_query_count"],
        "heldout_update_count": phase_receipts["heldout"]["accepted_event_group_count"],
        "heldout_query_count": phase_receipts["heldout"]["realized_query_count"],
        "event_schedule_schema_version": program.schema_version,
        "event_schedule_sha256": program.canonical_schedule_sha256,
        "query_vector_schema_version": QUERY_VECTOR_SCHEMA,
        "query_vector_sha256": trace.query_vector_sha256,
    }
    if (
        min(
            document["tuning_update_count"],
            document["tuning_query_count"],
            document["heldout_update_count"],
            document["heldout_query_count"],
        )
        <= 0
    ):
        raise ValueError("every Day1B tuning/held-out phase needs positive update/query counts")
    document["cell_binding_sha256"] = _digest(document)
    return document


def _primitive_count_document(value: tuple[int, ...] | None, field: str) -> dict[str, int]:
    if type(value) is not tuple or len(value) != len(PRIMITIVE_NAMES):
        raise ValueError(f"{field} must be the exact 14-primitive positional vector")
    if any(type(count) is not int or count < 0 for count in value):
        raise ValueError(f"{field} counts must be strict nonnegative integers")
    return dict(zip(PRIMITIVE_NAMES, value, strict=True))


def _controller_f1m_charge_index(
    summary: Day1BF1MControllerSummary,
) -> dict[tuple[str, str], Day1BF1MChargedSizeClass]:
    """Validate and index the controller-only Day 2 anchored F1-M charges."""

    if type(summary) is not Day1BF1MControllerSummary:
        raise TypeError("F1-M controller summary type is not exact")
    category_specs = {
        "query-f1m-random-mask-ciphertexts": (
            "random-zero-sum",
            "f1m_random_zero_sum_ciphertext_bytes",
            summary.phase_random_route_counts,
        ),
        "query-f1m-encrypted-zero-dummy-ciphertexts": (
            "encrypted-zero-dummy",
            "f1m_encrypted_zero_dummy_ciphertext_bytes",
            summary.phase_dummy_route_counts,
        ),
    }
    phase_indices = {"warmup": 0, "tuning-prefix": 1, "held-out": 2}
    expected_order = tuple(
        (phase, category) for phase in summary.retained_phases for category in category_specs
    )
    rank = {key: index for index, key in enumerate(expected_order)}
    index: dict[tuple[str, str], Day1BF1MChargedSizeClass] = {}
    observed_ranks: list[int] = []
    for item in summary.charged_size_classes:
        if type(item) is not Day1BF1MChargedSizeClass:
            raise TypeError("F1-M charged size-class type is not exact")
        key = (item.phase, item.category)
        if key not in rank or key in index:
            raise ValueError("F1-M controller charge identity is duplicated or out of scope")
        kind, size_field, counts = category_specs[item.category]
        expected_multiplicity = counts[phase_indices[item.phase]]
        expected_ciphertext_bytes = getattr(summary.size_authority, size_field)
        if (
            item.f1m_kind != kind
            or item.multiplicity != expected_multiplicity
            or item.ciphertext_bytes != expected_ciphertext_bytes
            or item.serialized_object_size_profile_sha256
            != summary.size_authority.serialized_object_size_profile_sha256
            or item.day2_outer_archive_sha256 != summary.size_authority.day2_outer_archive_sha256
        ):
            raise ValueError("F1-M controller charge contradicts its route or Day 2 authority")
        observed_ranks.append(rank[key])
        index[key] = item
    if observed_ranks != sorted(observed_ranks):
        raise ValueError("F1-M controller charges are not in canonical phase/category order")
    for phase, category in expected_order:
        _kind, _size_field, counts = category_specs[category]
        expected_multiplicity = counts[phase_indices[phase]]
        if ((phase, category) in index) != (expected_multiplicity > 0):
            raise ValueError("F1-M controller charge presence contradicts its route count")
    return index


def _serialized_ledger(
    categories: tuple[Day1BWorkerSerializedCategoryReceipt, ...] | None,
    *,
    phase: str,
    candidate_id: str,
    cell_binding_sha256: str,
    worker_object_receipt_spool_sha256: str,
    f1m_controller_summary: Day1BF1MControllerSummary,
    controller_expected_counts: Day1BControllerExpectedCounts,
) -> tuple[dict[str, object], int, int]:
    if type(categories) is not tuple:
        raise ValueError("complete outcomes require the exact serialized-object category ledger")
    expected_categories = tuple(
        category for category, _transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    )
    if tuple(category.category for category in categories) != expected_categories:
        raise ValueError("serialized-object categories must be exact, complete, and canonical")
    _require_sha256(
        worker_object_receipt_spool_sha256,
        "worker object-receipt spool digest",
    )
    controller_charges = _controller_f1m_charge_index(f1m_controller_summary)
    if (
        type(controller_expected_counts) is not Day1BControllerExpectedCounts
        or controller_expected_counts.candidate_id != candidate_id
        or controller_expected_counts.accounting_sha256
        != f1m_controller_summary.context.accounting_sha256
    ):
        raise ValueError("serialized ledger changed its controller count authority")
    require_formal_day1b_fixed_width_metadata_size_classes(
        controller_expected_counts
    )
    require_formal_day1b_combined_evaluation_key_size_class(
        controller_expected_counts
    )
    if phase not in f1m_controller_summary.retained_phases:
        raise ValueError("serialized ledger phase is absent from the F1-M controller summary")
    expected_phase = controller_expected_counts.phase_counts(phase)
    rows: list[dict[str, object]] = []
    totals = {"update": 0, "query": 0, "one-time": 0}
    controller_charged_query_bytes = 0
    for category_index, (category, (expected_name, transaction)) in enumerate(
        zip(
        categories,
        SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
        strict=True,
        )
    ):
        if (
            type(category) is not Day1BWorkerSerializedCategoryReceipt
            or category.category != expected_name
            or category.transaction != transaction
        ):
            raise ValueError("serialized-object category order changed")
        totals[transaction] += category.charged_byte_count
        row = category.to_document()
        logical_count = expected_phase.logical_protocol_object_counts[category_index]
        worker_count = expected_phase.worker_streamed_protocol_object_counts[
            category_index
        ]
        if category.protocol_object_count != worker_count:
            raise ValueError(
                "serialized ledger worker multiplicity differs from controller expectation"
            )
        row.update(
            {
                "controller_expected_logical_protocol_object_count": logical_count,
                "controller_expected_worker_streamed_protocol_object_count": worker_count,
            }
        )
        metadata_size_class = controller_expected_counts.metadata_size_class(
            expected_name
        )
        combined_key_size_class = (
            controller_expected_counts.combined_evaluation_key_size_class_for(
                expected_name
            )
        )
        if metadata_size_class is None and combined_key_size_class is None:
            row.update(
                {
                    "controller_expected_combined_evaluation_key_size_class_sha256": None,
                    "controller_expected_fixed_width_size_class_sha256": None,
                    "controller_expected_serialized_byte_count": None,
                }
            )
        else:
            expected_size_class = (
                metadata_size_class
                if metadata_size_class is not None
                else combined_key_size_class
            )
            assert expected_size_class is not None
            expected_class_count = int(worker_count > 0)
            if (
                category.charged_byte_count
                != worker_count * expected_size_class.serialized_byte_count
                or category.serialization_equivalence_class_count
                != expected_class_count
                or category.object_receipt_spool_line_count
                != expected_class_count
            ):
                raise ValueError(
                    "serialized receipt differs from its controller size class"
                )
            row.update(
                {
                    "controller_expected_fixed_width_size_class_sha256": (
                        None
                        if metadata_size_class is None
                        else metadata_size_class.metadata_size_class_sha256
                    ),
                    "controller_expected_combined_evaluation_key_size_class_sha256": (
                        None
                        if combined_key_size_class is None
                        else combined_key_size_class.combined_evaluation_key_size_class_sha256
                    ),
                    "controller_expected_serialized_byte_count": (
                        expected_size_class.serialized_byte_count
                    ),
                }
            )
        if expected_name in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES:
            if (
                category.charged_byte_count != 0
                or category.serialization_equivalence_class_count != 0
                or category.protocol_object_count != 0
                or category.object_receipt_spool_line_count != 0
            ):
                raise ValueError("bridge F1-M rows must not claim worker-spooled charge or objects")
            controller_class = controller_charges.get((phase, expected_name))
            controller_charge = (
                0 if controller_class is None else controller_class.charged_byte_count
            )
            controller_multiplicity = (
                0 if controller_class is None else controller_class.multiplicity
            )
            if controller_multiplicity != logical_count:
                raise ValueError(
                    "F1-M controller charge multiplicity differs from expected counts"
                )
            row.update(
                {
                    "charge_authority": "controller-anchored-day2-size-class",
                    "controller_charged_byte_count": controller_charge,
                    "controller_charged_size_class": (
                        None if controller_class is None else controller_class.to_document()
                    ),
                }
            )
            controller_charged_query_bytes += controller_charge
        else:
            row.update(
                {
                    "charge_authority": "worker-streamed-spool",
                    "controller_charged_byte_count": 0,
                    "controller_charged_size_class": None,
                }
            )
        rows.append(row)
    inclusive_query_bytes = totals["query"] + controller_charged_query_bytes
    ledger: dict[str, object] = {
        "schema_version": DAY1B_SERIALIZATION_LEDGER_SCHEMA,
        "cell_binding_sha256": cell_binding_sha256,
        "phase": phase,
        "candidate_id": candidate_id,
        "controller_accounting_sha256": controller_expected_counts.accounting_sha256,
        "controller_expected_counts_sha256": (
            controller_expected_counts.expected_counts_sha256
        ),
        "byte_derivation": ("worker-streamed-spool-plus-controller-anchored-day2-size-class-v1"),
        "ciphertext_count_used_as_byte_proxy": False,
        "raw_serialized_protocol_bytes_retained": False,
        "worker_object_receipt_spool_sha256": (worker_object_receipt_spool_sha256),
        "f1m_controller_context_sha256": (f1m_controller_summary.context.context_sha256),
        "f1m_route_coverage_sha256": f1m_controller_summary.route_coverage_sha256,
        "f1m_charged_size_class_set_sha256": (f1m_controller_summary.charged_size_class_set_sha256),
        "categories": rows,
        "update_serialized_bytes": totals["update"],
        "query_serialized_bytes": totals["query"],
        "controller_charged_query_bytes": controller_charged_query_bytes,
        "query_serialized_bytes_including_controller_charge": inclusive_query_bytes,
        "one_time_serialized_bytes_excluded_from_primary_C": totals["one-time"],
    }
    return ledger, totals["update"], inclusive_query_bytes


def _physical_record_and_ledger(
    measurement: Day1BWorkerPhaseReceipt,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
    phase: str,
    candidate_id: str,
    candidate_role: str,
    selection_source: str,
    worker_object_receipt_spool_sha256: str,
    f1m_controller_summary: Day1BF1MControllerSummary,
    controller_expected_counts: Day1BControllerExpectedCounts,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(measurement) is not Day1BWorkerPhaseReceipt:
        raise TypeError("execution adapter measurements must use the exact typed result")
    if (
        type(controller_expected_counts) is not Day1BControllerExpectedCounts
        or controller_expected_counts.candidate_id != candidate_id
        or controller_expected_counts.accounting_sha256
        != f1m_controller_summary.context.accounting_sha256
    ):
        raise ValueError("physical record changed its controller count authority")
    _require_sha256(
        worker_object_receipt_spool_sha256,
        "worker object-receipt spool digest",
    )
    if measurement.outcome not in _OUTCOMES:
        raise ValueError("measurement outcome is outside the closed taxonomy")
    counts = (
        (cell["tuning_update_count"], cell["tuning_query_count"])
        if phase == "tuning-prefix"
        else (cell["heldout_update_count"], cell["heldout_query_count"])
    )
    if measurement.outcome == "complete":
        if measurement.failure_code is not None:
            raise ValueError("complete outcomes must not carry a failure reason")
        update_counts = _primitive_count_document(
            measurement.update_primitive_counts,
            "update_primitive_counts",
        )
        query_counts = _primitive_count_document(
            measurement.query_primitive_counts,
            "query_primitive_counts",
        )
        ledger, update_bytes, query_bytes = _serialized_ledger(
            measurement.serialized_categories,
            phase=phase,
            candidate_id=candidate_id,
            cell_binding_sha256=str(cell["cell_binding_sha256"]),
            worker_object_receipt_spool_sha256=(worker_object_receipt_spool_sha256),
            f1m_controller_summary=f1m_controller_summary,
            controller_expected_counts=controller_expected_counts,
        )
    else:
        if type(measurement.failure_code) is not str or not measurement.failure_code.strip():
            raise ValueError("incomplete outcomes require a nonempty failure reason")
        if any(
            value is not None
            for value in (
                measurement.update_primitive_counts,
                measurement.query_primitive_counts,
                measurement.serialized_categories,
            )
        ):
            raise ValueError("incomplete outcomes must discard all partial quantities")
        update_counts = None
        query_counts = None
        update_bytes = None
        query_bytes = None
        ledger = {
            "schema_version": DAY1B_SERIALIZATION_LEDGER_SCHEMA,
            "cell_binding_sha256": cell["cell_binding_sha256"],
            "phase": phase,
            "candidate_id": candidate_id,
            "controller_accounting_sha256": (
                controller_expected_counts.accounting_sha256
            ),
            "controller_expected_counts_sha256": (
                controller_expected_counts.expected_counts_sha256
            ),
            "byte_derivation": None,
            "ciphertext_count_used_as_byte_proxy": False,
            "raw_serialized_protocol_bytes_retained": False,
            "worker_object_receipt_spool_sha256": (worker_object_receipt_spool_sha256),
            "f1m_controller_context_sha256": (f1m_controller_summary.context.context_sha256),
            "f1m_route_coverage_sha256": f1m_controller_summary.route_coverage_sha256,
            "f1m_charged_size_class_set_sha256": (
                f1m_controller_summary.charged_size_class_set_sha256
            ),
            "categories": None,
            "update_serialized_bytes": None,
            "query_serialized_bytes": None,
            "controller_charged_query_bytes": None,
            "query_serialized_bytes_including_controller_charge": None,
            "one_time_serialized_bytes_excluded_from_primary_C": None,
        }
    record: dict[str, object] = {
        "schema_version": HELDOUT_RECORD_SCHEMA,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "freshness_seconds": cell["freshness_seconds"],
        "rho": cell["rho"],
        "phase": phase,
        "record_kind": "fixed-candidate",
        "candidate_id": candidate_id,
        "candidate_role": candidate_role,
        "selection_source": selection_source,
        "cell_binding_sha256": cell["cell_binding_sha256"],
        "outcome": measurement.outcome,
        "failure_reason": measurement.failure_code,
        "update_count": counts[0],
        "query_count": counts[1],
        "update_primitive_counts": update_counts,
        "query_primitive_counts": query_counts,
        "update_serialized_bytes": update_bytes,
        "query_serialized_bytes": query_bytes,
    }
    ledger["physical_record_sha256"] = _digest(record)
    ledger["serialization_ledger_sha256"] = _digest(ledger)
    return record, ledger


def _records_for_candidate_cell(
    result: Day1BWorkerCellReceipt,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
    f1m_controller_summary: Day1BF1MControllerSummary,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if type(result) is not Day1BWorkerCellReceipt:
        raise TypeError("decoder must return exact candidate-cell evidence")
    candidate = result.candidate
    if candidate.candidate_id not in FIXED_CANDIDATE_IDS:
        raise ValueError("candidate-cell receipt identity changed")
    is_ablation = candidate.candidate_id == ABLATION_CANDIDATE_ID
    expected_role = "ablation" if is_ablation else "reference"
    if candidate.candidate_role != expected_role:
        raise ValueError("candidate-cell receipt role changed")
    expected_retained_phases = (
        ("tuning-prefix", "held-out") if expected_role == "reference" else ("held-out",)
    )
    if type(f1m_controller_summary) is not Day1BF1MControllerSummary:
        raise TypeError("candidate cell requires one exact F1-M controller summary")
    context = f1m_controller_summary.context
    controller_expected_counts = result.input_binding.controller_expected_counts
    if (
        context.candidate_id != candidate.candidate_id
        or context.candidate_role != expected_role
        or context.cell_binding_sha256 != cell["cell_binding_sha256"]
        or context.dataset_id != trace.dataset_id
        or context.dataset_release != trace.dataset_release
        or context.semantics != trace.semantics
        or context.source_partition != trace.source_partition
        or context.freshness != cell["freshness_seconds"]
        or context.rho != cell["rho"]
        or context.event_schedule_sha256 != cell["event_schedule_sha256"]
        or context.query_vector_sha256 != cell["query_vector_sha256"]
        or f1m_controller_summary.retained_phases != expected_retained_phases
        or controller_expected_counts.candidate_id != candidate.candidate_id
        or controller_expected_counts.accounting_sha256 != context.accounting_sha256
        or tuple(phase.phase for phase in controller_expected_counts.phases)
        != expected_retained_phases
    ):
        raise ValueError("candidate receipt and F1-M controller summary do not bind one cell")
    if (
        result.f1m_controller_context_sha256 != context.context_sha256
        or result.f1m_route_coverage_sha256 != f1m_controller_summary.route_coverage_sha256
        or result.f1m_charged_size_class_set_sha256
        != f1m_controller_summary.charged_size_class_set_sha256
    ):
        raise ValueError("candidate receipt changed its F1-M controller roots")
    _controller_f1m_charge_index(f1m_controller_summary)
    if candidate.terminal_outcome is None:
        if tuple(phase.phase for phase in candidate.phases) != (
            "warmup",
            "tuning-prefix",
            "held-out",
        ):
            raise ValueError("candidate-cell receipt phase coverage changed")
        phase_measurements = {phase.phase: phase for phase in candidate.phases}
        retained_phases = (
            result.candidate.phases[1:]
            if expected_role == "reference"
            else result.candidate.phases[2:]
        )
        for retained_index, retained_phase in enumerate(retained_phases):
            if not retained_phase.retained_measurement:
                raise ValueError("candidate retained phase role changed")
            if retained_phase.outcome != "complete":
                continue
            if type(retained_phase.serialized_categories) is not tuple:
                raise ValueError("complete retained phase lost its serialized inventory")
            one_time = next(
                (
                    category
                    for category in retained_phase.serialized_categories
                    if category.category == "one-time-evaluation-key-material"
                ),
                None,
            )
            if one_time is None:
                raise ValueError("candidate retained phase lost its one-time category")
            expected_count = int(retained_index == 0)
            if (
                one_time.serialization_equivalence_class_count != expected_count
                or one_time.protocol_object_count != expected_count
                or (one_time.charged_byte_count > 0) != bool(expected_count)
            ):
                raise ValueError(
                    "one-time evaluation-key inventory must occur exactly once in the "
                    "first retained phase"
                )
    else:
        if (
            candidate.phases
            or candidate.terminal_outcome not in _OUTCOMES - {"complete", "ineligible"}
            or type(candidate.terminal_failure_code) is not str
            or not candidate.terminal_failure_code
            or candidate.receipt_origin != "controller-terminal-null-projection"
        ):
            raise ValueError("candidate-cell terminal receipt is not one closed null projection")
        phase_measurements = {
            phase: Day1BWorkerPhaseReceipt(
                phase=phase,
                retained_measurement=True,
                outcome=candidate.terminal_outcome,
                failure_code=candidate.terminal_failure_code,
                update_primitive_counts=None,
                query_primitive_counts=None,
                serialized_categories=None,
                worker_declared_phase_audit=None,
            )
            for phase in (
                ("tuning-prefix", "held-out") if expected_role == "reference" else ("held-out",)
            )
        }
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    if expected_role == "reference":
        record, ledger = _physical_record_and_ledger(
            phase_measurements["tuning-prefix"],
            trace=trace,
            cell=cell,
            phase="tuning-prefix",
            candidate_id=candidate.candidate_id,
            candidate_role="reference",
            selection_source="fixed-reference-tuning-prefix",
            worker_object_receipt_spool_sha256=(result.object_receipt_spool_sha256),
            f1m_controller_summary=f1m_controller_summary,
            controller_expected_counts=controller_expected_counts,
        )
        records.append(record)
        ledgers.append(ledger)
    record, ledger = _physical_record_and_ledger(
        phase_measurements["held-out"],
        trace=trace,
        cell=cell,
        phase="held-out",
        candidate_id=candidate.candidate_id,
        candidate_role=expected_role,
        selection_source=("fixed-ablation-held-out" if is_ablation else "fixed-reference-held-out"),
        worker_object_receipt_spool_sha256=(result.object_receipt_spool_sha256),
        f1m_controller_summary=f1m_controller_summary,
        controller_expected_counts=controller_expected_counts,
    )
    records.append(record)
    ledgers.append(ledger)
    if all(record["outcome"] == "complete" for record in records):
        charged_documents = [
            row["controller_charged_size_class"]
            for ledger in ledgers
            for row in ledger["categories"]
            if row["controller_charged_size_class"] is not None
        ]
        charged_classes = tuple(
            Day1BF1MChargedSizeClass.from_document(document) for document in charged_documents
        )
        replayed_root = canonical_day1b_f1m_charged_size_class_set_sha256(charged_classes)
        if replayed_root != f1m_controller_summary.charged_size_class_set_sha256:
            raise ValueError("retained ledgers do not replay the controller F1-M charge set")
    return records, ledgers


class _UnitObjectReceiptArchive:
    """Disk-backed unit spool for weighted serialized-object receipts."""

    def __init__(self) -> None:
        self._file: BinaryIO = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
        self._hasher = hashlib.sha256()
        self.line_count = 0
        self.byte_count = 0
        self._sealed = False

    def accept_candidate_receipt(self, receipt: Day1BWorkerCellReceipt) -> None:
        if self._sealed or type(receipt) is not Day1BWorkerCellReceipt:
            raise ValueError("unit archive requires one exact unsealed candidate receipt")
        if receipt.worker_observed_f1m_materialized_binding_count != 0:
            raise ValueError("weighted Day1B receipt claims materialized F1-M bindings")
        _require_sha256(
            receipt.controller_f1m_window_batch_stream_sha256,
            "candidate-cell F1-M window-batch stream",
        )
        if receipt.weighted_query_range_coverage_verified is not True:
            raise ValueError("candidate-cell weighted query-range coverage is unverified")

    def write(self, line: bytes) -> int:
        if self._sealed or type(line) is not bytes or not line.endswith(b"\n"):
            raise ValueError("unit object-receipt archive only accepts canonical JSON lines")
        try:
            document = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("worker object receipt line is not canonical ASCII JSON") from error
        if type(document) is not dict or canonical_json_bytes(document) != line:
            raise ValueError("worker object receipt line is not canonical closed JSON")
        category = document.get("category")
        serialized_object = document.get("object")
        if type(category) is not str or type(serialized_object) is not dict:
            raise ValueError("worker object receipt line lost category/object identity")
        f1m_size_class = serialized_object.get("f1m_size_class")
        if category in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES:
            size_class = _exact_object(
                f1m_size_class,
                _F1M_SIZE_CLASS_KEYS,
                "unit F1-M object receipt size class",
            )
            if size_class["schema_version"] != DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA:
                raise ValueError("F1-M object receipt size-class schema changed")
            expected_kind = (
                "random-zero-sum"
                if category == "query-f1m-random-mask-ciphertexts"
                else "encrypted-zero-dummy"
            )
            if size_class["f1m_kind"] != expected_kind:
                raise ValueError("F1-M object receipt size-class kind changed")
            for field in ("version_id", "component_id", "output_block_id"):
                if type(size_class[field]) is not str or not size_class[field]:
                    raise ValueError(f"F1-M size class {field} is empty")
            for field in (
                "output_plan_digest",
                "private_plan_digest",
                "execution_binding_digest",
            ):
                _require_sha256(size_class[field], f"F1-M size class {field}")
        elif f1m_size_class is not None:
            raise ValueError("non-F1-M object receipt carries an F1-M size class")
        written = self._file.write(line)
        if written != len(line):
            raise OSError("unit object-receipt archive write was incomplete")
        self._hasher.update(line)
        self.line_count += 1
        self.byte_count += len(line)
        return written

    def seal(self) -> tuple[str, int, int]:
        self._file.flush()
        self._sealed = True
        return self._hasher.hexdigest(), self.line_count, self.byte_count

    def copy_to(self, destination: BinaryIO) -> tuple[str, int, int]:
        if not self._sealed:
            raise RuntimeError("unit object-receipt archive is not sealed")
        self._file.seek(0)
        hasher = hashlib.sha256()
        line_count = 0
        byte_count = 0
        while line := self._file.readline():
            written = destination.write(line)
            if written != len(line):
                raise OSError("installed object-receipt archive write was incomplete")
            hasher.update(line)
            line_count += 1
            byte_count += len(line)
        observed = (hasher.hexdigest(), line_count, byte_count)
        expected = (self._hasher.hexdigest(), self.line_count, self.byte_count)
        if observed != expected:
            raise RuntimeError("unit object-receipt archive changed after sealing")
        return observed

    def close(self) -> None:
        self._file.close()


def _append_candidate_object_receipts(
    evidence: Day1BClaimedWorkerEvidence,
    archive: _UnitObjectReceiptArchive,
) -> None:
    """Revalidate one sealed invocation spool, then append its canonical lines."""

    with tempfile.TemporaryFile(mode="w+b") as candidate_copy:
        copied_sha256 = evidence.copy_object_receipts_to(candidate_copy)
        if copied_sha256 != evidence.receipt.object_receipt_spool_sha256:
            raise Day1BWorkerProtocolError(
                "candidate object-receipt copy differs from its sealed digest"
            )
        candidate_copy.seek(0)
        copied_line_count = 0
        while line := candidate_copy.readline():
            archive.write(line)
            copied_line_count += 1
        if copied_line_count != evidence.object_receipt_line_count:
            raise Day1BWorkerProtocolError(
                "candidate object-receipt copy differs from its sealed line count"
            )


@dataclass(frozen=True, slots=True)
class _Day1BArtifactVerification:
    """Path-free semantic identity returned by the descriptor-held verifier."""

    artifact_variant_kind: str
    manifest_sha256: str
    heldout_fragment_sha256: str
    schedule_sha256: str
    serialization_ledger_sha256: str
    serialized_object_receipt_sha256: str
    checksums_sha256: str
    cardinality: tuple[int, int, int, int]
    semantic_fingerprint: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class _LedgerCategoryExpectation:
    start_line: int
    line_count: int
    stream_sha256: str
    charged_byte_count: int
    protocol_object_count: int
    equivalence_class_count: int


class _RollingObjectFacts:
    __slots__ = (
        "byte_count",
        "charged_byte_count",
        "first_spool_ordinal",
        "hasher",
        "line_count",
        "multiplicity",
    )

    def __init__(self) -> None:
        self.hasher = hashlib.sha256()
        self.line_count = 0
        self.byte_count = 0
        self.charged_byte_count = 0
        self.multiplicity = 0
        self.first_spool_ordinal: int | None = None

    def add(
        self,
        line: bytes,
        *,
        charged_byte_count: int,
        multiplicity: int,
        spool_ordinal: int,
    ) -> None:
        if self.first_spool_ordinal is None:
            self.first_spool_ordinal = spool_ordinal
        self.hasher.update(line)
        self.line_count += 1
        self.byte_count += len(line)
        self.charged_byte_count += charged_byte_count
        self.multiplicity += multiplicity

    @property
    def sha256(self) -> str:
        return self.hasher.hexdigest()


def _exact_object(value: object, keys: frozenset[str], field: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"{field} must be one closed object with exact keys")
    return value


def _strict_nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a strict nonnegative integer")
    return value


def _canonical_object_bytes(raw: bytes, keys: frozenset[str], field: str) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} must be canonical ASCII JSON") from error
    value = _exact_object(value, keys, field)
    if canonical_json_bytes(value) != raw:
        raise ValueError(f"{field} must use exact canonical JSON encoding")
    return value


def _variant_matches(
    value: object,
    expected: Mapping[str, object],
    field: str,
) -> None:
    if type(value) is not dict or value != dict(expected) or set(value) != set(expected):
        raise ValueError(f"{field} does not match the selected closed artifact variant")


def _verify_day1b_unit_view(
    view: PublicationArtifactDirectory,
    *,
    artifact_variant_token: object,
) -> _Day1BArtifactVerification:
    """Verify one exact six-member unit without reopening any member pathname."""

    if type(view) is not PublicationArtifactDirectory:
        raise TypeError("Day1B artifact verification requires an exact descriptor view")
    artifact_variant, unit_schema, fragment_schema = _artifact_variant_schema_contract(
        artifact_variant_token
    )
    if view.entries() != tuple(sorted(_ARTIFACT_FILENAMES)):
        raise ValueError("Day1B artifact directory must contain exactly six regular members")
    member_sizes = {name: view.regular_size(name) for name in _ARTIFACT_FILENAMES}
    if member_sizes[_MANIFEST_FILENAME] > _DAY1B_MANIFEST_BYTES_MAXIMUM:
        raise ValueError("Day1B manifest exceeds its repository-fixed read bound")
    if member_sizes[_CHECKSUM_FILENAME] > _DAY1B_CHECKSUM_BYTES_MAXIMUM:
        raise ValueError("Day1B checksum inventory exceeds its repository-fixed read bound")
    manifest_raw = view.read_regular(_MANIFEST_FILENAME)
    checksum_raw = view.read_regular(_CHECKSUM_FILENAME)
    manifest = _canonical_object_bytes(manifest_raw, _MANIFEST_KEYS, "manifest")
    checksum_lines = checksum_raw.splitlines(keepends=True)
    if (
        len(checksum_lines) != len(_CHECKSUM_TARGETS)
        or not checksum_raw.endswith(b"\n")
        or any(not line.endswith(b"\n") for line in checksum_lines)
    ):
        raise ValueError("Day1B SHA256SUMS must contain exactly five member lines")
    checksum_digests: dict[str, str] = {}
    for line, expected_name in zip(checksum_lines, _CHECKSUM_TARGETS, strict=True):
        try:
            digest_text, name_text = line.decode("ascii").removesuffix("\n").split("  ", 1)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("Day1B SHA256SUMS is not canonical ASCII") from error
        if name_text != expected_name:
            raise ValueError("Day1B SHA256SUMS member order changed")
        checksum_digests[expected_name] = _require_sha256(
            digest_text, f"SHA256SUMS {expected_name}"
        )
    if checksum_digests[_MANIFEST_FILENAME] != hashlib.sha256(manifest_raw).hexdigest():
        raise ValueError("Day1B SHA256SUMS does not bind its manifest")

    early_resource_policy = _exact_object(
        manifest["resource_policy"], _RESOURCE_POLICY_KEYS, "manifest.resource_policy"
    )
    early_resource_digest = _require_sha256(
        early_resource_policy["resource_policy_sha256"], "manifest resource-policy digest"
    )
    if early_resource_digest != _digest(
        {
            key: value
            for key, value in early_resource_policy.items()
            if key != "resource_policy_sha256"
        }
    ):
        raise ValueError("Day1B resource-policy digest is not self-binding")
    output_limit = _strict_nonnegative_int(
        early_resource_policy["output_bytes_per_unit"],
        "resource-policy output byte limit",
    )
    if output_limit <= 0 or output_limit > _DAY1B_ARTIFACT_BYTES_HARD_MAXIMUM:
        raise ValueError("Day1B resource-policy output limit exceeds the repository hard ceiling")
    if sum(member_sizes.values()) > output_limit:
        raise ValueError("Day1B artifact exceeds its exact resource-policy output limit")

    members = _exact_object(manifest["members"], _MEMBER_KEYS, "manifest.members")
    for member_name in _MEMBER_KEYS:
        member_keys = {"sha256", "byte_count"}
        if member_name == _OBJECT_RECEIPT_FILENAME:
            member_keys.add("jsonl_line_count")
        member = _exact_object(
            members[member_name],
            frozenset(member_keys),
            f"manifest.members.{member_name}",
        )
        if (
            _require_sha256(member["sha256"], f"manifest.members.{member_name}.sha256")
            != checksum_digests[member_name]
            or _strict_nonnegative_int(
                member["byte_count"], f"manifest.members.{member_name}.byte_count"
            )
            != member_sizes[member_name]
        ):
            raise ValueError(f"manifest member facts do not bind {member_name}")
    if member_sizes[_FRAGMENT_FILENAME] > _DAY1B_FRAGMENT_BYTES_MAXIMUM:
        raise ValueError("Day1B fragment exceeds its repository-fixed read bound")
    fragment_raw = view.read_regular(_FRAGMENT_FILENAME)
    if hashlib.sha256(fragment_raw).hexdigest() != checksum_digests[_FRAGMENT_FILENAME]:
        raise ValueError("Day1B SHA256SUMS does not bind its fragment")
    fragment = _canonical_object_bytes(fragment_raw, _FRAGMENT_KEYS, "fragment")
    digests = {
        **checksum_digests,
        _CHECKSUM_FILENAME: hashlib.sha256(checksum_raw).hexdigest(),
    }
    if manifest["schema_version"] != unit_schema or fragment["schema_version"] != fragment_schema:
        raise ValueError("Day1B manifest and fragment schemas cross artifact variants")
    _variant_matches(manifest["artifact_variant"], artifact_variant, "manifest.artifact_variant")
    if manifest["artifact_policy"] != ("derived-publication-evidence-no-raw-source-redistribution"):
        raise ValueError("Day1B artifact policy changed")

    unit_identity = _exact_object(
        manifest["unit_identity"], _UNIT_IDENTITY_KEYS, "manifest.unit_identity"
    )
    if (
        unit_identity["dataset_id"] not in DATASET_IDS
        or unit_identity["semantics"] not in SEMANTICS
        or type(unit_identity["dataset_release"]) is not str
        or not unit_identity["dataset_release"]
        or type(unit_identity["source_partition"]) is not int
        or unit_identity["source_partition"] not in range(PUBLICATION_SOURCE_PARTITION_COUNT)
    ):
        raise ValueError("Day1B unit identity is outside the frozen analysis domain")
    unit_identity_sha256 = _digest(unit_identity)

    experiment_source = _exact_object(
        manifest["experiment_source"], _EXPERIMENT_SOURCE_KEYS, "manifest.experiment_source"
    )
    experiment_git_sha = _require_git_sha(
        experiment_source["git_sha"], "manifest.experiment_source.git_sha"
    )
    behavior_inventory = experiment_source["behavior_inventory"]
    if type(behavior_inventory) is not dict:
        raise ValueError("manifest experiment Behavior inventory must be one exact object")
    if (
        behavior_inventory.get("role") != EvidenceRole.DAY1B.value
        or behavior_inventory.get("source_git_sha") != experiment_git_sha
    ):
        raise ValueError("manifest experiment Behavior inventory retargets role or source")
    publication_behavior_inventory_sha256 = _require_sha256(
        behavior_inventory.get("behavior_set_sha256"),
        "manifest experiment Behavior Set digest",
    )
    publication_behavior_set_schema_version = behavior_inventory.get(
        "behavior_set_schema_version"
    )
    if (
        type(publication_behavior_set_schema_version) is not str
        or not publication_behavior_set_schema_version
    ):
        raise ValueError("manifest experiment Behavior Set schema is unavailable")

    size_authority = _parse_serialized_object_size_authority_document(
        manifest["serialized_object_size_authority"]
    )
    if size_authority.source_git_sha != experiment_git_sha:
        raise ValueError("Day1B unit size authority retargets the experiment source")

    trace_source = _exact_object(
        manifest["trace_source"], _TRACE_SOURCE_KEYS, "manifest.trace_source"
    )
    if trace_source["trace_manifest_schema_version"] != PUBLICATION_TRACE_MANIFEST_SCHEMA:
        raise ValueError("manifest trace source is not the exact v7 trace schema")
    _require_git_sha(trace_source["git_sha"], "manifest.trace_source.git_sha")
    trace_behavior_sources = trace_source["trace_behavior_source_blob_sha256"]
    if type(trace_behavior_sources) is not dict or not trace_behavior_sources:
        raise ValueError("manifest trace behavior-source mapping must be nonempty")
    for path, digest in trace_behavior_sources.items():
        if type(path) is not str or not path:
            raise ValueError("manifest trace behavior-source path must be nonempty")
        _require_sha256(digest, f"manifest trace behavior source {path!r}")
    if (
        _digest(trace_behavior_sources) != trace_source["trace_behavior_source_inventory_sha256"]
        or trace_source["trace_central_behavior_inventory_present"] is not False
        or trace_source["trace_source_authority_verified"] is not False
        or trace_source["authority_state"] != "HOLD-no-central-TRACE-post-run-anchor"
    ):
        raise ValueError("manifest trace provenance overstates its frozen HOLD boundary")
    _require_sha256(
        trace_source["repository_provenance_sha256"],
        "manifest trace repository provenance digest",
    )
    _require_sha256(trace_source["trace_manifest_sha256"], "manifest trace digest")

    query_vector = _exact_object(
        manifest["query_vector"], _QUERY_VECTOR_BINDING_KEYS, "manifest.query_vector"
    )
    if (
        query_vector["schema_version"] != QUERY_VECTOR_SCHEMA
        or query_vector["reuse_scope"] != "one-paired-unit-all-18-cells-and-all-physical-candidates"
    ):
        raise ValueError("Day1B query-vector binding semantics changed")
    _require_sha256(query_vector["sha256"], "manifest query-vector digest")

    candidate_catalog = _exact_object(
        manifest["candidate_catalog"],
        _CANDIDATE_CATALOG_KEYS,
        "manifest.candidate_catalog",
    )
    registration = _exact_object(
        candidate_catalog["registration"], _REGISTRATION_KEYS, "candidate registration"
    )
    if _digest(registration) != candidate_catalog["registration_sha256"]:
        raise ValueError("Day1B candidate registration digest is not self-binding")
    if registration["schema_version"] != "dynamic-cssc-day1-registration-evidence-v1":
        raise ValueError("Day1B candidate registration schema changed")
    _require_git_sha(registration["source_git_sha"], "candidate registration source Git SHA")
    for field in (
        "correctness_artifact_sha256",
        "accounting_evidence_sha256",
        "policy_contract_sha256",
    ):
        _require_sha256(registration[field], f"candidate registration {field}")
    if type(registration["run_id"]) is not int or registration["run_id"] <= 0:
        raise ValueError("candidate registration run ID must be a strict positive integer")
    if (
        candidate_catalog["fixed_candidate_ids"] != list(FIXED_CANDIDATE_IDS)
        or candidate_catalog["reference_candidate_ids"] != list(REFERENCE_CANDIDATE_IDS)
        or candidate_catalog["ablation_candidate_ids"] != [ABLATION_CANDIDATE_ID]
    ):
        raise ValueError("Day1B candidate catalog changed its frozen roster")
    try:
        registered_candidates = _parse_candidate_policy_documents(
            candidate_catalog["candidate_policies"]
        )
        opened_candidate_catalog = Day1CandidateCatalog(
            candidates=registered_candidates,
            registration=RegistrationEvidence(**registration),
        )
    except (Day1CandidateRegistrationError, TypeError, ValueError) as error:
        raise ValueError("Day1B candidate policies do not open the canonical roster") from error
    expected_candidate_specs = {
        candidate.candidate_id: _candidate_worker_spec(candidate)
        for candidate in opened_candidate_catalog.candidates
    }

    resource_policy = early_resource_policy
    if (
        resource_policy.get("schema_version") != DAY1B_RESOURCE_POLICY_SCHEMA
        or resource_policy.get("candidate_retry_count") != 0
        or resource_policy.get("cells_per_shard") != 18
        or resource_policy.get("max_concurrency") != 1
    ):
        raise ValueError("Day1B resource-policy closed invariants changed")
    candidate_catalog_sha256 = _digest(candidate_catalog)
    expected_worker_resource_limits = Day1BWorkerResourceLimits(
        wall_clock_ns_per_candidate_cell=(
            _strict_nonnegative_int(
                resource_policy["wall_clock_seconds_per_candidate_cell"],
                "resource-policy candidate wall clock",
            )
            * 1_000_000_000
        ),
        resident_memory_bytes_per_candidate_cell=_strict_nonnegative_int(
            resource_policy["resident_memory_bytes_per_candidate_cell"],
            "resource-policy candidate resident memory",
        ),
        scratch_bytes_per_candidate_cell=_strict_nonnegative_int(
            resource_policy["scratch_bytes_per_candidate_cell"],
            "resource-policy candidate scratch",
        ),
        serialized_object_bytes_maximum=_strict_nonnegative_int(
            resource_policy["serialized_object_bytes_maximum"],
            "resource-policy serialized-object bytes",
        ),
        serialized_object_receipt_count_maximum=_strict_nonnegative_int(
            resource_policy["serialized_object_receipt_count_maximum"],
            "resource-policy object-receipt count",
        ),
        serialized_object_receipt_spool_bytes_maximum=_strict_nonnegative_int(
            resource_policy["serialized_object_receipt_spool_bytes_maximum"],
            "resource-policy object-receipt spool bytes",
        ),
        serialized_payload_bytes_per_cell_maximum=_strict_nonnegative_int(
            resource_policy["serialized_payload_bytes_per_cell_maximum"],
            "resource-policy worker serialized payload bytes",
        ),
        worker_frame_count_maximum=_strict_nonnegative_int(
            resource_policy["worker_frame_count_maximum"],
            "resource-policy worker frame count",
        ),
        controller_registered_scratch_bytes_checkpoint_maximum=(
            _strict_nonnegative_int(
                resource_policy["controller_registered_scratch_bytes_checkpoint_maximum"],
                "resource-policy controller registered scratch",
            )
        ),
    )

    invocation = _exact_object(manifest["invocation"], _INVOCATION_KEYS, "manifest.invocation")
    if invocation != {
        "entrypoint": "scripts/run_publication_day1b.py",
        "public_interface": (
            "produce_publication_day1b_unit(trace_bundle_dir:Path,output_dir:Path)"
        ),
        "caller_options_allowed": False,
        "shard_scope": "exactly-one-paired-unit-18-cells",
        "selective_candidate_retry_allowed": False,
    }:
        raise ValueError("Day1B invocation contract changed")

    acquisition = _exact_object(
        manifest["acquisition_binding"],
        _ACQUISITION_BINDING_KEYS,
        "manifest.acquisition_binding",
    )
    if acquisition["schema_version"] != ACQUISITION_TRACE_BINDING_SCHEMA:
        raise ValueError("manifest acquisition binding is not the exact v2 schema")
    _require_sha256(acquisition["source_bundle_sha256"], "acquisition source bundle digest")
    authority = _exact_object(manifest["authority"], _AUTHORITY_KEYS, "manifest.authority")
    if authority["state"] != "HOLD-pre-S1-no-central-TRACE-anchor-no-runtime-admission" or any(
        value is not False for key, value in authority.items() if key != "state"
    ):
        raise ValueError("Day1B artifact authority must remain the exact all-false HOLD")

    if artifact_variant_token is _PRODUCTION_ARTIFACT_VARIANT_TOKEN:
        if experiment_source["source_attestation"] != "repository-clean-head":
            raise ValueError("production artifact source attestation changed")
        for field in (
            "acquisition_transaction_sha256",
            "source_set_sha256",
            "acquisition_behavior_set_sha256",
            "acquisition_behavior_inventory_sha256",
        ):
            _require_sha256(acquisition[field], f"production {field}")
        if (
            acquisition["acquisition_authority_state"] != "HOLD-no-repository-post-run-anchor"
            or acquisition["central_behavior_inventory_present"] is not True
            or acquisition["acquisition_network_authority_verified"] is not False
        ):
            raise ValueError("production acquisition binding changed its exact HOLD facts")
    else:
        if experiment_source["source_attestation"] != "test-only-typed-day1b-source":
            raise ValueError("fixture artifact source attestation changed")
        if (
            any(
                acquisition[field] is not None
                for field in (
                    "acquisition_transaction_sha256",
                    "source_set_sha256",
                    "acquisition_behavior_set_sha256",
                    "acquisition_behavior_inventory_sha256",
                    "acquisition_authority_state",
                )
            )
            or acquisition["central_behavior_inventory_present"] is not False
        ):
            raise ValueError("fixture artifact carries production acquisition provenance")
        if acquisition["acquisition_network_authority_verified"] is not False:
            raise ValueError("fixture artifact acquisition authority must remain false")

    if manifest["heldout_input_member_sha256"] != digests[_FRAGMENT_FILENAME]:
        raise ValueError("heldout input digest does not bind the fragment member")

    cardinality = _exact_object(
        manifest["cardinality"],
        frozenset(
            {
                "cell_binding_count",
                "candidate_cell_receipt_count",
                "physical_record_count",
                "schedule_program_count",
                "serialization_ledger_count",
            }
        ),
        "manifest.cardinality",
    )
    expected_cardinality = {
        "cell_binding_count": 18,
        "candidate_cell_receipt_count": 252,
        "physical_record_count": 486,
        "schedule_program_count": 9,
        "serialization_ledger_count": 486,
    }
    if cardinality != expected_cardinality:
        raise ValueError("Day1B manifest cardinality must be exactly 18/252/486/9/486")

    trace_units = fragment["trace_units"]
    cells = fragment["cell_bindings"]
    records = fragment["records"]
    if (
        type(trace_units) is not list
        or len(trace_units) != 1
        or type(cells) is not list
        or len(cells) != 18
        or type(records) is not list
        or len(records) != 486
    ):
        raise ValueError("Day1B fragment must contain exactly 1/18/486 trace/cell/record facts")
    trace_unit = _exact_object(
        trace_units[0],
        publication_statistics_module._TRACE_UNIT_KEYS,
        "fragment.trace_units[0]",
    )
    if trace_unit["schema_version"] != TRACE_UNIT_SCHEMA:
        raise ValueError("Day1B trace-unit schema changed")
    publication_statistics_module._decode_accepted_event_group_ranges(
        trace_unit,
        "fragment.trace_units[0]",
    )
    for field in (
        "trace_manifest_sha256",
        "mapping_sha256",
        "accepted_events_sha256",
        "replay_receipt_sha256",
        "source_bundle_sha256",
    ):
        _require_sha256(trace_unit[field], f"fragment.trace_units[0].{field}")
    trace_binding = _require_sha256(trace_unit["trace_binding_sha256"], "trace binding")
    if trace_binding != _digest(
        {key: value for key, value in trace_unit.items() if key != "trace_binding_sha256"}
    ):
        raise ValueError("Day1B trace-unit digest does not bind its exact document")
    if (
        fragment["experiment_source_git_sha"] != trace_unit["experiment_source_git_sha"]
        or fragment["experiment_source_git_sha"] != experiment_git_sha
        or trace_source["trace_manifest_sha256"] != trace_unit["trace_manifest_sha256"]
        or acquisition["source_bundle_sha256"] != trace_unit["source_bundle_sha256"]
    ):
        raise ValueError("Day1B fragment and trace unit splice experiment source revisions")
    if any(
        trace_unit[field] != unit_identity[field]
        for field in ("dataset_id", "semantics", "source_partition")
    ):
        raise ValueError("Day1B unit identity retargets its trace binding")
    if trace_unit["experiment_source_git_sha"] != experiment_git_sha:
        raise ValueError("Day1B trace binding retargets its experiment source")

    cell_by_digest: dict[str, dict[str, object]] = {}
    expected_cell_keys = tuple(
        (freshness, rho) for freshness in FRESHNESS_VALUES for rho in RHO_VALUES
    )
    for index, (cell_value, expected_key) in enumerate(zip(cells, expected_cell_keys, strict=True)):
        cell = _exact_object(
            cell_value,
            publication_statistics_module._CELL_BINDING_KEYS,
            f"fragment.cell_bindings[{index}]",
        )
        if cell["schema_version"] != CELL_BINDING_SCHEMA:
            raise ValueError("Day1B cell-binding schema changed")
        if (cell["freshness_seconds"], cell["rho"]) != expected_key:
            raise ValueError("Day1B cell bindings are not in canonical freshness/rho order")
        for field in ("dataset_id", "semantics", "source_partition"):
            if cell[field] != trace_unit[field]:
                raise ValueError("Day1B cell binding retargets its trace unit")
        for field in (
            "trace_manifest_sha256",
            "mapping_sha256",
            "accepted_events_sha256",
            "accepted_raw_events_total",
            "warmup_accepted_event_group_range",
            "tuning_accepted_event_group_range",
            "heldout_accepted_event_group_range",
            "accepted_event_group_ranges_sha256",
            "replay_receipt_sha256",
            "source_bundle_sha256",
            "trace_binding_sha256",
        ):
            if cell[field] != trace_unit[field]:
                raise ValueError("Day1B cell binding splices trace provenance")
        if (
            cell["experiment_source_git_sha"] != experiment_git_sha
            or cell["query_vector_schema_version"] != QUERY_VECTOR_SCHEMA
            or cell["query_vector_sha256"] != query_vector["sha256"]
            or cell["event_schedule_schema_version"] != ACCEPTED_EVENT_SCHEDULE_SCHEMA
        ):
            raise ValueError("Day1B cell binding retargets source/query/schedule schema")
        tuning_range = cell["tuning_accepted_event_group_range"]
        heldout_range = cell["heldout_accepted_event_group_range"]
        if (
            cell["tuning_update_count"] != tuning_range[1] - tuning_range[0]
            or cell["heldout_update_count"] != heldout_range[1] - heldout_range[0]
            or cell["tuning_query_count"]
            != _phase_query_count((tuning_range[0], tuning_range[1]), Fraction(cell["rho"]))
            or cell["heldout_query_count"]
            != _phase_query_count((heldout_range[0], heldout_range[1]), Fraction(cell["rho"]))
        ):
            raise ValueError("Day1B cell update/query cardinality changed")
        cell_digest = _require_sha256(cell["cell_binding_sha256"], "cell binding digest")
        if cell_digest != _digest(
            {key: value for key, value in cell.items() if key != "cell_binding_sha256"}
        ):
            raise ValueError("Day1B cell-binding digest does not bind its exact document")
        if cell_digest in cell_by_digest:
            raise ValueError("Day1B cell binding digest is duplicated")
        cell_by_digest[cell_digest] = cell

    expected_record_candidates = (*REFERENCE_CANDIDATE_IDS, *FIXED_CANDIDATE_IDS)
    for index, record in enumerate(records):
        publication_statistics_module._decode_record(record, index, PRIMITIVE_NAMES)
        cell = cells[index // 27]
        if (
            record["cell_binding_sha256"] != cell["cell_binding_sha256"]
            or record["candidate_id"] != expected_record_candidates[index % 27]
            or record["phase"]
            != ("tuning-prefix" if index % 27 < len(REFERENCE_CANDIDATE_IDS) else "held-out")
        ):
            raise ValueError("Day1B physical records are not in canonical per-cell order")
        expected_counts = (
            (cell["tuning_update_count"], cell["tuning_query_count"])
            if record["phase"] == "tuning-prefix"
            else (cell["heldout_update_count"], cell["heldout_query_count"])
        )
        if (record["update_count"], record["query_count"]) != expected_counts:
            raise ValueError("Day1B physical record cardinality disagrees with its cell")
    record_by_candidate_phase = {
        (
            str(record["cell_binding_sha256"]),
            str(record["candidate_id"]),
            str(record["phase"]),
        ): record
        for record in records
    }
    if len(record_by_candidate_phase) != len(records):
        raise ValueError("Day1B physical record candidate-phase identity is duplicated")

    execution_receipts = manifest["cell_execution_receipts"]
    if type(execution_receipts) is not list or len(execution_receipts) != 18:
        raise ValueError("Day1B manifest must contain exactly 18 cell execution receipts")
    candidate_receipt_count = 0
    worker_receipts: dict[tuple[str, str], dict[str, object]] = {}
    worker_contracts: dict[tuple[str, str], Day1BWorkerProtocolContract] = {}
    worker_receipts_by_binding: dict[str, tuple[str, dict[str, object]]] = {}
    worker_contracts_by_binding: dict[str, Day1BWorkerProtocolContract] = {}
    unit_f1m_lineage: tuple[str, str, str, str] | None = None
    for index, receipt in enumerate(execution_receipts):
        receipt = _exact_object(
            receipt,
            _CELL_EXECUTION_RECEIPT_KEYS,
            f"manifest.cell_execution_receipts[{index}]",
        )
        candidates = receipt.get("candidate_cell_receipts")
        if (
            receipt.get("cell_binding_sha256") != cells[index]["cell_binding_sha256"]
            or type(candidates) is not list
            or len(candidates) != 14
            or receipt.get("candidate_cell_receipt_count") != 14
            or receipt.get("physical_record_count") != 27
        ):
            raise ValueError("Day1B cell execution receipt cardinality or binding changed")
        if (
            receipt["freshness_seconds"] != cells[index]["freshness_seconds"]
            or receipt["rho"] != cells[index]["rho"]
            or receipt["candidate_retry_count"] != 0
        ):
            raise ValueError("Day1B cell execution receipt retargets its cell or retry policy")
        phase_receipts = receipt["phase_receipts"]
        if type(phase_receipts) is not list or len(phase_receipts) != 3:
            raise ValueError("Day1B cell receipt lost warmup/tuning/heldout audit coverage")
        phase_by_name: dict[str, dict[str, object]] = {}
        for phase_index, phase_name in enumerate(("warmup", "tuning", "heldout")):
            phase = _exact_object(
                phase_receipts[phase_index],
                _CELL_PHASE_RECEIPT_KEYS,
                f"cell receipt[{index}].phase_receipts[{phase_index}]",
            )
            if phase["phase"] != phase_name:
                raise ValueError("Day1B cell phase receipts are not canonically ordered")
            accepted_range = phase["accepted_event_group_range"]
            if (
                type(accepted_range) is not list
                or len(accepted_range) != 2
                or any(type(value) is not int for value in accepted_range)
                or phase["accepted_event_group_count"] != accepted_range[1] - accepted_range[0]
            ):
                raise ValueError("Day1B cell phase receipt range/count changed")
            _require_sha256(
                phase["consumed_window_audit_stream_sha256"],
                "cell phase window-audit digest",
            )
            phase_by_name[phase_name] = phase
        if (
            phase_by_name["tuning"]["accepted_event_group_count"]
            != cells[index]["tuning_update_count"]
            or phase_by_name["tuning"]["realized_query_count"] != cells[index]["tuning_query_count"]
            or phase_by_name["heldout"]["accepted_event_group_count"]
            != cells[index]["heldout_update_count"]
            or phase_by_name["heldout"]["realized_query_count"]
            != cells[index]["heldout_query_count"]
        ):
            raise ValueError("Day1B cell phase receipt disagrees with its cell binding")
        for candidate_index, (candidate_value, candidate_id) in enumerate(
            zip(candidates, FIXED_CANDIDATE_IDS, strict=True)
        ):
            candidate_receipt = _exact_object(
                candidate_value,
                _WORKER_RECEIPT_KEYS,
                f"cell receipt[{index}].candidate[{candidate_index}]",
            )
            if (
                len(canonical_json_bytes(candidate_receipt))
                > _DAY1B_WORKER_RECEIPT_CANONICAL_BYTES_MAXIMUM
            ):
                raise ValueError("Day1B worker receipt exceeds its canonical byte bound")
            if candidate_receipt["schema_version"] != DAY1B_WORKER_RECEIPT_SCHEMA:
                raise ValueError("Day1B worker receipt schema changed")
            for field in (
                "f1m_controller_context_sha256",
                "f1m_route_coverage_sha256",
                "f1m_charged_size_class_set_sha256",
            ):
                _require_sha256(
                    candidate_receipt[field],
                    f"worker receipt {field}",
                )
            worker_digest = _require_sha256(
                candidate_receipt["worker_candidate_cell_receipt_sha256"],
                "worker candidate-cell receipt digest",
            )
            if worker_digest != _digest(
                {
                    key: value
                    for key, value in candidate_receipt.items()
                    if key != "worker_candidate_cell_receipt_sha256"
                }
            ):
                raise ValueError("Day1B worker receipt digest is not self-binding")
            candidate = _exact_object(
                candidate_receipt["candidate"],
                _WORKER_CANDIDATE_KEYS,
                f"cell receipt[{index}].candidate[{candidate_index}].candidate",
            )
            if (
                candidate["candidate_id"] != candidate_id
                or candidate["candidate_role"]
                != ("ablation" if candidate_id == ABLATION_CANDIDATE_ID else "reference")
                or candidate["candidate_retry_count"] != 0
            ):
                raise ValueError("Day1B worker receipts are not in canonical candidate order")
            if candidate["receipt_origin"] == "worker-complete-transcript":
                if (
                    candidate["worker_declared_state_reset_count"] != 0
                    or candidate["terminal_outcome"] is not None
                    or candidate["terminal_failure_code"] is not None
                    or type(candidate["phases"]) is not list
                    or len(candidate["phases"]) != 3
                ):
                    raise ValueError("Day1B complete worker receipt changed its closed projection")
            elif candidate["receipt_origin"] == "controller-terminal-null-projection":
                if (
                    candidate["worker_declared_state_reset_count"] is not None
                    or candidate["terminal_outcome"]
                    not in {"failed", "timeout", "infeasible", "missing"}
                    or type(candidate["terminal_failure_code"]) is not str
                    or not candidate["terminal_failure_code"]
                    or candidate["phases"] != []
                ):
                    raise ValueError("Day1B terminal receipt changed its closed null projection")
            else:
                raise ValueError("Day1B worker receipt origin is outside the closed taxonomy")
            input_binding = _require_sha256(
                candidate_receipt["input_binding_sha256"],
                "worker input binding digest",
            )
            try:
                input_contract = Day1BWorkerProtocolContract.from_input_binding_document(
                    candidate_receipt["input_binding_document"]
                )
            except (Day1BWorkerProtocolError, TypeError, ValueError) as error:
                raise ValueError(
                    "Day1B worker receipt does not carry one open exact input binding"
                ) from error
            require_formal_day1b_f1m_worker_zero(
                input_contract.controller_expected_counts
            )
            require_formal_day1b_fixed_width_metadata_size_classes(
                input_contract.controller_expected_counts
            )
            require_formal_day1b_combined_evaluation_key_size_class(
                input_contract.controller_expected_counts
            )
            if candidate["receipt_origin"] == "worker-complete-transcript":
                phase_documents = {
                    phase.get("phase"): phase
                    for phase in candidate["phases"]
                    if type(phase) is dict
                }
                if len(phase_documents) != len(candidate["phases"]):
                    raise ValueError("Day1B worker phase identities are not exact and unique")
                for expected_phase in input_contract.controller_expected_counts.phases:
                    phase_document = phase_documents.get(expected_phase.phase)
                    if type(phase_document) is not dict:
                        raise ValueError(
                            "Day1B worker phase does not open controller expected counts"
                        )
                    if phase_document.get("outcome") == "failed":
                        if (
                            phase_document.get("failure_code")
                            != "candidate-execution-failed"
                            or phase_document.get("retained_measurement") is not True
                            or phase_document.get("update_primitive_counts") is not None
                            or phase_document.get("query_primitive_counts") is not None
                            or phase_document.get("serialized_categories") is not None
                        ):
                            raise ValueError(
                                "Day1B failed worker phase carries measurement quantities"
                            )
                        continue
                    if (
                        phase_document.get("outcome") != "complete"
                        or phase_document.get("retained_measurement") is not True
                        or phase_document.get("update_primitive_counts")
                        != list(expected_phase.update_primitive_counts)
                        or phase_document.get("query_primitive_counts")
                        != list(expected_phase.query_primitive_counts)
                    ):
                        raise ValueError(
                            "Day1B worker phase does not open controller expected primitive counts"
                        )
                    serialized_categories = phase_document.get("serialized_categories")
                    if type(serialized_categories) is not list or len(
                        serialized_categories
                    ) != len(input_contract.serialized_categories):
                        raise ValueError(
                            "Day1B worker phase does not open controller expected categories"
                        )
                    for category_index, (
                        category_document,
                        (expected_category, expected_transaction),
                    ) in enumerate(
                        zip(
                            serialized_categories,
                            input_contract.serialized_categories,
                            strict=True,
                        )
                    ):
                        if (
                            type(category_document) is not dict
                            or category_document.get("category") != expected_category
                            or category_document.get("transaction") != expected_transaction
                            or category_document.get("protocol_object_count")
                            != expected_phase.worker_streamed_protocol_object_counts[
                                category_index
                            ]
                        ):
                            raise ValueError(
                                "Day1B worker phase does not open controller "
                                "expected multiplicities"
                            )
                    physical_record = record_by_candidate_phase[
                        (
                            str(receipt["cell_binding_sha256"]),
                            candidate_id,
                            expected_phase.phase,
                        )
                    ]
                    for field, expected_vector in (
                        (
                            "update_primitive_counts",
                            expected_phase.update_primitive_counts,
                        ),
                        (
                            "query_primitive_counts",
                            expected_phase.query_primitive_counts,
                        ),
                    ):
                        record_vector = physical_record[field]
                        if type(record_vector) is not dict or tuple(
                            record_vector.get(name) for name in PRIMITIVE_NAMES
                        ) != tuple(expected_vector):
                            raise ValueError(
                                "Day1B controller expected primitive counts differ from "
                                "the physical record"
                            )
            expected_phase_ranges = tuple(
                Day1BWorkerPhaseRange(
                    phase=phase_name,
                    accepted_group_start=phase_by_name[phase_name]["accepted_event_group_range"][0],
                    accepted_group_end=phase_by_name[phase_name]["accepted_event_group_range"][1],
                )
                for phase_name in ("warmup", "tuning", "heldout")
            )
            expected_invocation_id = _digest(
                {
                    "candidate_id": candidate_id,
                    "cell_binding_sha256": receipt["cell_binding_sha256"],
                    "schema_version": (
                        "dynamic-cssc-publication-day1b-candidate-cell-invocation-v1"
                    ),
                }
            )
            if (
                input_contract.input_binding_sha256 != input_binding
                or input_contract.invocation_id != expected_invocation_id
                or input_contract.trace_manifest_sha256 != trace_unit["trace_manifest_sha256"]
                or input_contract.event_schedule_sha256 != cells[index]["event_schedule_sha256"]
                or input_contract.query_vector_sha256 != query_vector["sha256"]
                or input_contract.candidate_catalog_sha256 != candidate_catalog_sha256
                or input_contract.resource_policy_sha256 != early_resource_digest
                or input_contract.freshness != receipt["freshness_seconds"]
                or input_contract.rho != receipt["rho"]
                or input_contract.candidate.candidate_id != candidate_id
                or input_contract.candidate.candidate_role != candidate["candidate_role"]
                or input_contract.phase_ranges != expected_phase_ranges
                or input_contract.primitive_names != PRIMITIVE_NAMES
                or input_contract.serialized_categories != SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
                or input_contract.f1m_size_class_categories
                != DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
                or input_contract.resource_limits != expected_worker_resource_limits
                or input_contract.f1m_controller_context_sha256
                != candidate_receipt["f1m_controller_context_sha256"]
                or input_contract.f1m_route_coverage_sha256
                != candidate_receipt["f1m_route_coverage_sha256"]
                or input_contract.f1m_charged_size_class_set_sha256
                != candidate_receipt["f1m_charged_size_class_set_sha256"]
                or input_contract.expected_f1m_size_class_set_sha256
                != candidate_receipt["controller_expected_f1m_size_class_set_sha256"]
                or input_contract.expected_f1m_size_class_count
                != candidate_receipt["controller_expected_f1m_size_class_count"]
                or input_contract.expected_serialized_equivalence_class_count
                != candidate_receipt["controller_expected_serialized_equivalence_class_count"]
                or input_contract.expected_f1m_cardinality_derivation_root_sha256
                != candidate_receipt["controller_f1m_cardinality_derivation_root_sha256"]
            ):
                raise ValueError(
                    "Day1B worker input binding retargets its manifest, cell, or receipt"
                )
            expected_candidate_spec = expected_candidate_specs[candidate_id]
            if (
                input_contract.candidate != expected_candidate_spec
                or input_contract.day2_outer_archive_sha256
                != size_authority.day2_outer_archive_sha256
                or input_contract.serialized_object_size_profile_sha256
                != size_authority.serialized_object_size_profile_sha256
                or input_contract.ciphertext_bytes != size_authority.ciphertext_bytes
                or input_contract.f1m_random_zero_sum_ciphertext_bytes
                != size_authority.f1m_random_zero_sum_ciphertext_bytes
                or input_contract.f1m_encrypted_zero_dummy_ciphertext_bytes
                != size_authority.f1m_encrypted_zero_dummy_ciphertext_bytes
                or input_contract.serialized_rotation_key_inventory_bytes
                != size_authority.serialized_rotation_key_inventory_bytes
                or input_contract.serialized_eval_mult_key_bytes
                != size_authority.serialized_eval_mult_key_bytes
            ):
                raise ValueError(
                    "Day1B worker input binding diverges from unit policy or Day 2 authority"
                )

            phase_aliases = (
                ("warmup", "warmup"),
                ("tuning", "tuning-prefix"),
                ("heldout", "held-out"),
            )
            expected_context_boundaries = tuple(
                Day1BF1MPhaseBoundary(
                    context_phase,
                    phase_by_name[receipt_phase]["accepted_event_group_range"][0],
                    phase_by_name[receipt_phase]["accepted_event_group_range"][1],
                )
                for receipt_phase, context_phase in phase_aliases
            )
            expected_complete_schedule_audit = Day1BF1MCompleteScheduleAudit(
                tuple(
                    Day1BF1MCompletePhaseAudit(
                        phase=context_phase,
                        accepted_group_start=(
                            phase_by_name[receipt_phase]["accepted_event_group_range"][0]
                        ),
                        accepted_group_end=(
                            phase_by_name[receipt_phase]["accepted_event_group_range"][1]
                        ),
                        realized_window_count=(
                            phase_by_name[receipt_phase][
                                "realized_publication_window_count"
                            ]
                        ),
                        realized_set_count=phase_by_name[receipt_phase]["realized_set_count"],
                        realized_query_count=(
                            phase_by_name[receipt_phase]["realized_query_count"]
                        ),
                        consumed_window_audit_stream_sha256=(
                            phase_by_name[receipt_phase][
                                "consumed_window_audit_stream_sha256"
                            ]
                        ),
                    )
                    for receipt_phase, context_phase in phase_aliases
                )
            )
            context = input_contract.f1m_controller_context
            expected_context_facts: tuple[tuple[str, object], ...] = (
                ("publication_source_git_sha", experiment_git_sha),
                ("trace_source_git_sha", trace_source["git_sha"]),
                (
                    "publication_behavior_set_schema_version",
                    publication_behavior_set_schema_version,
                ),
                (
                    "publication_behavior_inventory_sha256",
                    publication_behavior_inventory_sha256,
                ),
                ("terminal_registration_sha256", candidate_catalog["registration_sha256"]),
                ("acquisition_bundle_sha256", trace_unit["source_bundle_sha256"]),
                ("trace_manifest_sha256", trace_unit["trace_manifest_sha256"]),
                ("candidate_catalog_sha256", candidate_catalog_sha256),
                ("resource_policy_sha256", early_resource_digest),
                ("dataset_id", unit_identity["dataset_id"]),
                ("dataset_release", unit_identity["dataset_release"]),
                ("semantics", unit_identity["semantics"]),
                ("source_partition", unit_identity["source_partition"]),
                ("unit_identity_sha256", unit_identity_sha256),
                ("cell_binding_sha256", receipt["cell_binding_sha256"]),
                ("cell_ordinal", index),
                ("freshness", receipt["freshness_seconds"]),
                ("rho", receipt["rho"]),
                ("candidate_id", expected_candidate_spec.candidate_id),
                ("candidate_role", expected_candidate_spec.candidate_role),
                (
                    "candidate_policy_sha256",
                    expected_candidate_spec.candidate_policy_digest,
                ),
                ("retained_phases", expected_candidate_spec.retained_phases),
                ("phase_boundaries", expected_context_boundaries),
                ("event_schedule_sha256", cells[index]["event_schedule_sha256"]),
                ("query_vector_sha256", query_vector["sha256"]),
                ("accepted_group_count", trace_unit["accepted_raw_events_total"]),
                (
                    "complete_window_count",
                    expected_complete_schedule_audit.complete_window_count,
                ),
                (
                    "total_query_count",
                    sum(expected_complete_schedule_audit.phase_query_counts),
                ),
                (
                    "phase_window_counts",
                    expected_complete_schedule_audit.phase_window_counts,
                ),
                (
                    "phase_query_counts",
                    expected_complete_schedule_audit.phase_query_counts,
                ),
                (
                    "complete_phase_audit_root_sha256",
                    expected_complete_schedule_audit.complete_phase_audit_root_sha256,
                ),
            )
            if any(
                getattr(context, field) != expected
                for field, expected in expected_context_facts
            ):
                raise ValueError(
                    "Day1B opened F1-M controller context retargets unit or cell facts"
                )
            observed_lineage = (
                context.day1_registration_anchor_sha256,
                context.trace_post_run_anchor_sha256,
                context.worker_build_identity_sha256,
                context.worker_runtime_identity_sha256,
            )
            if unit_f1m_lineage is None:
                unit_f1m_lineage = observed_lineage
            elif observed_lineage != unit_f1m_lineage:
                raise ValueError("Day1B F1-M lineage changes within one paired unit")

            route_coverage = input_contract.f1m_route_coverage
            expected_charged_classes = derive_day1b_f1m_charged_size_classes(
                retained_phases=expected_candidate_spec.retained_phases,
                phase_random_route_counts=route_coverage.phase_random_route_counts,
                phase_dummy_route_counts=route_coverage.phase_dummy_route_counts,
                size_authority=size_authority,
            )
            expected_charged_root = canonical_day1b_f1m_charged_size_class_set_sha256(
                expected_charged_classes
            )
            if (
                expected_charged_root != input_contract.f1m_charged_size_class_set_sha256
                or expected_charged_root
                != candidate_receipt["f1m_charged_size_class_set_sha256"]
            ):
                raise ValueError(
                    "Day1B opened F1-M route coverage does not derive its charge-set root"
                )
            worker_audits = candidate_receipt["controller_schedule_phase_audits"]
            if type(worker_audits) is not list or len(worker_audits) != 3:
                raise ValueError("Day1B worker receipt lost controller phase audits")
            for audit_index, phase_name in enumerate(("warmup", "tuning", "heldout")):
                audit = _exact_object(
                    worker_audits[audit_index],
                    _WORKER_PHASE_AUDIT_KEYS,
                    f"worker receipt[{index},{candidate_index}].audit[{audit_index}]",
                )
                phase = phase_by_name[phase_name]
                if (
                    audit["phase"] != phase_name
                    or [audit["accepted_group_start"], audit["accepted_group_end"]]
                    != phase["accepted_event_group_range"]
                    or audit["realized_window_count"] != phase["realized_publication_window_count"]
                    or audit["realized_set_count"] != phase["realized_set_count"]
                    or audit["realized_query_count"] != phase["realized_query_count"]
                    or audit["consumed_window_audit_stream_sha256"]
                    != phase["consumed_window_audit_stream_sha256"]
                ):
                    raise ValueError("Day1B worker controller audit splices its cell schedule")
            for field in (
                "anonymous_scratch_creation_isolation_verified",
                "production_execution_admissible",
                "runtime_state_continuity_verified",
            ):
                if candidate_receipt[field] is not False:
                    raise ValueError("Day1B worker receipt overstates fixture/runtime authority")
            if candidate_receipt["weighted_query_range_coverage_verified"] is not True:
                raise ValueError("Day1B weighted query-range coverage is unverified")
            _require_sha256(
                candidate_receipt["controller_f1m_window_batch_stream_sha256"],
                "worker F1-M window-batch stream",
            )
            if (
                _strict_nonnegative_int(
                    candidate_receipt["worker_observed_f1m_materialized_binding_count"],
                    "worker materialized F1-M binding count",
                )
                != 0
            ):
                raise ValueError("weighted Day1B receipt claims materialized F1-M bindings")
            expected_size_classes = _strict_nonnegative_int(
                candidate_receipt["controller_expected_f1m_size_class_count"],
                "controller expected F1-M size-class count",
            )
            observed_size_classes = _strict_nonnegative_int(
                candidate_receipt["worker_observed_f1m_size_class_count"],
                "worker observed F1-M size-class count",
            )
            if candidate["receipt_origin"] == "worker-complete-transcript":
                if observed_size_classes != expected_size_classes:
                    raise ValueError(
                        "complete worker receipt does not cover every expected F1-M size class"
                    )
            elif observed_size_classes != 0:
                raise ValueError(
                    "controller-terminal worker receipt carries observed F1-M size classes"
                )
            registered_scratch_cap = _strict_nonnegative_int(
                candidate_receipt["controller_registered_scratch_bytes_checkpoint_maximum"],
                "worker controller-registered scratch cap",
            )
            registered_scratch_peak = _strict_nonnegative_int(
                candidate_receipt["controller_observed_registered_scratch_peak_bytes"],
                "worker controller-registered scratch peak",
            )
            if (
                registered_scratch_cap <= 0
                or registered_scratch_peak <= 0
                or registered_scratch_peak > registered_scratch_cap
            ):
                raise ValueError(
                    "Day1B worker controller-registered scratch peak exceeds its closed cap"
                )
            key = (str(receipt["cell_binding_sha256"]), candidate_id)
            if key in worker_receipts:
                raise ValueError("Day1B worker receipt identity is duplicated")
            if input_binding in worker_receipts_by_binding:
                raise ValueError("Day1B worker input binding is reused across candidate cells")
            worker_receipts[key] = candidate_receipt
            worker_contracts[key] = input_contract
            worker_receipts_by_binding[input_binding] = (candidate_id, candidate_receipt)
            worker_contracts_by_binding[input_binding] = input_contract
        candidate_receipt_count += len(candidates)
    if candidate_receipt_count != 252:
        raise ValueError("Day1B artifact must contain exactly 252 candidate-cell receipts")

    schedule_index = manifest["schedule_index"]
    if type(schedule_index) is not list or len(schedule_index) != 9:
        raise ValueError("Day1B manifest must index exactly nine schedules")
    schedule_specs: list[tuple[str, int, int, str, Fraction]] = []
    expected_schedule_lines = 0
    for index, (entry_value, rho) in enumerate(zip(schedule_index, RHO_VALUES, strict=True)):
        entry = _exact_object(entry_value, _SCHEDULE_INDEX_KEYS, f"schedule_index[{index}]")
        line_count = _strict_nonnegative_int(entry["jsonl_line_count"], "schedule line count")
        byte_count = _strict_nonnegative_int(entry["byte_count"], "schedule byte count")
        if (
            entry["rho"] != rho
            or entry["schema_version"] != ACCEPTED_EVENT_SCHEDULE_SCHEMA
            or entry["query_events_materialized"] is not False
            or line_count != trace_unit["accepted_raw_events_total"] + 1
        ):
            raise ValueError("Day1B schedule index changed its frozen semantics")
        digest = _require_sha256(entry["canonical_schedule_sha256"], "schedule digest")
        schedule_specs.append((rho, line_count, byte_count, digest, Fraction(rho)))
        expected_schedule_lines += line_count

    schedule_segment = 0
    schedule_line_in_segment = 0
    schedule_segment_hasher = hashlib.sha256()
    schedule_segment_bytes = 0
    schedule_query_ordinal = 0
    schedule_digest_by_rho: dict[str, str] = {}

    def consume_schedule_line(
        _global_index: int,
        line: bytes,
        row: dict[str, object],
    ) -> None:
        nonlocal schedule_segment
        nonlocal schedule_line_in_segment
        nonlocal schedule_segment_hasher
        nonlocal schedule_segment_bytes
        nonlocal schedule_query_ordinal
        if schedule_segment >= len(schedule_specs):
            raise ValueError("Day1B schedule member contains unindexed trailing records")
        rho, line_count, byte_count, expected_digest, ratio = schedule_specs[schedule_segment]
        schedule_segment_hasher.update(line)
        schedule_segment_bytes += len(line)
        if schedule_line_in_segment == 0:
            if (
                row.get("schema_version") != ACCEPTED_EVENT_SCHEDULE_SCHEMA
                or row.get("record_kind") != "accepted-event-schedule-header"
                or row.get("accepted_group_count") != trace_unit["accepted_raw_events_total"]
                or type(row.get("rho")) is not dict
            ):
                raise ValueError("Day1B schedule header changed its frozen identity")
            observed_ratio = row["rho"]
            if (
                set(observed_ratio) != {"numerator", "denominator"}
                or type(observed_ratio["numerator"]) is not int
                or type(observed_ratio["denominator"]) is not int
                or observed_ratio["denominator"] <= 0
                or Fraction(observed_ratio["numerator"], observed_ratio["denominator"]) != ratio
            ):
                raise ValueError("Day1B schedule header rho changed")
        else:
            ordinal = schedule_line_in_segment - 1
            if (
                row.get("schema_version") != ACCEPTED_EVENT_SCHEDULE_SCHEMA
                or row.get("record_kind") != "accepted-event-group"
                or row.get("accepted_event_ordinal") != ordinal
                or type(row.get("events")) is not list
            ):
                raise ValueError("Day1B schedule group order or schema changed")
            query_runs = [
                event
                for event in row["events"]
                if type(event) is dict and event.get("kind") == "query-run"
            ]
            if len(query_runs) != 1:
                raise ValueError("Day1B schedule group must contain one exact QUERY-RUN")
            query_run = query_runs[0]
            if (
                set(query_run) != {"kind", "first_query_ordinal", "count"}
                or query_run["first_query_ordinal"] != schedule_query_ordinal
                or type(query_run["count"]) is not int
                or query_run["count"] < 0
            ):
                raise ValueError("Day1B QUERY-RUN encoding changed")
            schedule_query_ordinal += query_run["count"]
        schedule_line_in_segment += 1
        if schedule_line_in_segment == line_count:
            expected_queries = (
                trace_unit["accepted_raw_events_total"] * ratio.numerator // (ratio.denominator)
            )
            if (
                schedule_segment_bytes != byte_count
                or schedule_segment_hasher.hexdigest() != expected_digest
                or schedule_query_ordinal != expected_queries
            ):
                raise ValueError("Day1B schedule index does not bind its exact JSONL segment")
            schedule_digest_by_rho[rho] = expected_digest
            schedule_segment += 1
            schedule_line_in_segment = 0
            schedule_segment_hasher = hashlib.sha256()
            schedule_segment_bytes = 0
            schedule_query_ordinal = 0

    schedule_stream = view.consume_canonical_jsonl(
        _SCHEDULE_FILENAME,
        maximum_file_bytes=min(
            output_limit,
            expected_schedule_lines * _DAY1B_SCHEDULE_LINE_BYTES_MAXIMUM,
        ),
        maximum_line_bytes=_DAY1B_SCHEDULE_LINE_BYTES_MAXIMUM,
        consumer=consume_schedule_line,
    )
    if (
        schedule_segment != len(schedule_specs)
        or schedule_line_in_segment != 0
        or schedule_stream.line_count != expected_schedule_lines
        or schedule_stream.byte_count != member_sizes[_SCHEDULE_FILENAME]
        or schedule_stream.sha256 != checksum_digests[_SCHEDULE_FILENAME]
    ):
        raise ValueError("Day1B schedule member is not its exact indexed stream")
    for cell in cells:
        if cell["event_schedule_sha256"] != schedule_digest_by_rho[cell["rho"]]:
            raise ValueError("Day1B cell binding splices a foreign schedule digest")

    object_member = members[_OBJECT_RECEIPT_FILENAME]
    expected_object_lines = _strict_nonnegative_int(
        object_member["jsonl_line_count"], "object-receipt member line count"
    )
    spool_facts = {binding: _RollingObjectFacts() for binding in worker_receipts_by_binding}
    category_facts: dict[tuple[str, str, str], _RollingObjectFacts] = {}

    def consume_object_line(index: int, line: bytes, row: dict[str, object]) -> None:
        _exact_object(row, _OBJECT_RECEIPT_KEYS, f"object receipts[{index}]")
        if row["schema_version"] != "dynamic-cssc-publication-day1b-object-receipt-v1":
            raise ValueError("Day1B object-receipt schema changed")
        serialized_object = _exact_object(
            row["object"], _OBJECT_KEYS, f"object receipts[{index}].object"
        )
        if (
            row["candidate_id"] not in FIXED_CANDIDATE_IDS
            or row["phase"] not in {"tuning-prefix", "held-out"}
            or (row["category"], row["transaction"]) not in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
        ):
            raise ValueError("Day1B object receipt retargets candidate, phase, or category")
        input_binding = _require_sha256(
            row["worker_input_binding_sha256"], "object worker input binding"
        )
        try:
            expected_candidate_id, _worker_receipt = worker_receipts_by_binding[input_binding]
        except KeyError as error:
            raise ValueError("Day1B object receipt names an unknown worker binding") from error
        spool = spool_facts[input_binding]
        spool_ordinal = _strict_nonnegative_int(row["spool_line_ordinal"], "object spool ordinal")
        if row["candidate_id"] != expected_candidate_id or spool_ordinal != spool.line_count:
            raise ValueError("Day1B object receipt order is not exactly worker-bound")
        serialized_size = _strict_nonnegative_int(
            serialized_object["serialized_byte_count"], "serialized object byte count"
        )
        multiplicity = _strict_nonnegative_int(
            serialized_object["multiplicity"], "serialized object multiplicity"
        )
        charged = _strict_nonnegative_int(
            serialized_object["charged_byte_count"], "serialized object charged bytes"
        )
        if multiplicity <= 0 or serialized_size <= 0 or charged != multiplicity * serialized_size:
            raise ValueError("Day1B object receipt charged-byte arithmetic changed")
        _require_sha256(serialized_object["serialized_sha256"], "serialized object digest")
        if row["category"] in DAY1B_FIXED_WIDTH_METADATA_CATEGORIES:
            size_class = day1b_metadata_size_class_document(str(row["category"]))
            if (
                size_class["transaction"] != row["transaction"]
                or size_class["serialized_byte_count"] != serialized_size
            ):
                raise ValueError(
                    "Day1B metadata object receipt changed its fixed-width size class"
                )
        if row["category"] == DAY1B_COMBINED_EVALUATION_KEY_CATEGORY:
            key_size_class = worker_contracts_by_binding[
                input_binding
            ].controller_expected_counts.combined_evaluation_key_size_class
            if (
                key_size_class is None
                or key_size_class.transaction != row["transaction"]
                or key_size_class.serialized_byte_count != serialized_size
            ):
                raise ValueError(
                    "Day1B combined evaluation-key receipt changed its controller size class"
                )
        f1m_size_class = serialized_object["f1m_size_class"]
        if row["category"] in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES:
            size_class = _exact_object(
                f1m_size_class,
                _F1M_SIZE_CLASS_KEYS,
                f"object receipts[{index}].object.f1m_size_class",
            )
            if size_class["f1m_kind"] != (
                "random-zero-sum"
                if row["category"] == "query-f1m-random-mask-ciphertexts"
                else "encrypted-zero-dummy"
            ):
                raise ValueError("Day1B F1-M size-class kind contradicts its category")
            if size_class["schema_version"] != DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA:
                raise ValueError("Day1B F1-M size-class schema changed")
            for field in ("version_id", "component_id", "output_block_id"):
                if type(size_class[field]) is not str or not size_class[field]:
                    raise ValueError(f"Day1B F1-M size class {field} is empty")
            for field in (
                "output_plan_digest",
                "private_plan_digest",
                "execution_binding_digest",
            ):
                _require_sha256(size_class[field], f"F1-M size class {field}")
        elif f1m_size_class is not None:
            raise ValueError("non-F1-M object receipt carries an F1-M size class")
        spool.add(
            line,
            charged_byte_count=charged,
            multiplicity=multiplicity,
            spool_ordinal=spool_ordinal,
        )
        category_key = (input_binding, str(row["phase"]), str(row["category"]))
        category_facts.setdefault(category_key, _RollingObjectFacts()).add(
            line,
            charged_byte_count=charged,
            multiplicity=multiplicity,
            spool_ordinal=spool_ordinal,
        )

    object_stream = view.consume_canonical_jsonl(
        _OBJECT_RECEIPT_FILENAME,
        maximum_file_bytes=min(
            output_limit,
            max(1, expected_object_lines) * _DAY1B_OBJECT_RECEIPT_LINE_BYTES_MAXIMUM,
        ),
        maximum_line_bytes=_DAY1B_OBJECT_RECEIPT_LINE_BYTES_MAXIMUM,
        consumer=consume_object_line,
    )
    if (
        object_stream.line_count != expected_object_lines
        or object_stream.byte_count != member_sizes[_OBJECT_RECEIPT_FILENAME]
        or object_stream.sha256 != checksum_digests[_OBJECT_RECEIPT_FILENAME]
    ):
        raise ValueError("Day1B object-receipt member changed its exact stream facts")
    for binding, (candidate_id, worker_receipt) in worker_receipts_by_binding.items():
        observed = spool_facts[binding]
        if (
            observed.line_count
            != _strict_nonnegative_int(
                worker_receipt["object_receipt_line_count"], "worker object-receipt line count"
            )
            or observed.byte_count
            != _strict_nonnegative_int(
                worker_receipt["object_receipt_byte_count"], "worker object-receipt byte count"
            )
            or observed.sha256 != worker_receipt["object_receipt_spool_sha256"]
        ):
            raise ValueError(
                f"Day1B object-receipt spool is not exactly worker-bound for {candidate_id}"
            )

    ledger_digests: list[str] = []
    consumed_category_keys: set[tuple[str, str, str]] = set()
    candidate_ledger_phases: dict[tuple[str, str], list[str]] = {key: [] for key in worker_receipts}
    candidate_ledger_outcomes: dict[tuple[str, str], list[str]] = {
        key: [] for key in worker_receipts
    }
    candidate_controller_charge_documents: dict[tuple[str, str], list[Day1BF1MChargedSizeClass]] = {
        key: [] for key in worker_receipts
    }
    f1m_category_specs = {
        "query-f1m-random-mask-ciphertexts": (
            "random-zero-sum",
            "f1m_random_zero_sum_ciphertext_bytes",
        ),
        "query-f1m-encrypted-zero-dummy-ciphertexts": (
            "encrypted-zero-dummy",
            "f1m_encrypted_zero_dummy_ciphertext_bytes",
        ),
    }

    def consume_ledger_line(index: int, _line: bytes, ledger: dict[str, object]) -> None:
        if index >= len(records):
            raise ValueError("Day1B artifact contains trailing serialization ledgers")
        record = records[index]
        _exact_object(
            ledger,
            _LEDGER_KEYS | {"physical_record_sha256", "serialization_ledger_sha256"},
            f"ledgers[{index}]",
        )
        if ledger["schema_version"] != DAY1B_SERIALIZATION_LEDGER_SCHEMA:
            raise ValueError("Day1B serialization-ledger schema changed")
        if (
            ledger["cell_binding_sha256"] != record["cell_binding_sha256"]
            or ledger["phase"] != record["phase"]
            or ledger["candidate_id"] != record["candidate_id"]
            or ledger["physical_record_sha256"] != _digest(record)
        ):
            raise ValueError("Day1B serialization ledger is spliced from its physical record")
        ledger_digest = _require_sha256(
            ledger["serialization_ledger_sha256"], f"ledgers[{index}] digest"
        )
        if ledger_digest != _digest(
            {key: value for key, value in ledger.items() if key != "serialization_ledger_sha256"}
        ):
            raise ValueError("Day1B serialization-ledger digest is not self-binding")
        ledger_digests.append(ledger_digest)
        candidate_key = (
            str(record["cell_binding_sha256"]),
            str(record["candidate_id"]),
        )
        worker_receipt = worker_receipts[candidate_key]
        input_contract = worker_contracts[candidate_key]
        controller_expected_counts = input_contract.controller_expected_counts
        if (
            ledger["worker_object_receipt_spool_sha256"]
            != worker_receipt["object_receipt_spool_sha256"]
        ):
            raise ValueError("Day1B ledger splices a foreign worker receipt spool")
        if (
            ledger["controller_expected_counts_sha256"]
            != input_contract.controller_expected_counts_sha256
            or ledger["controller_expected_counts_sha256"]
            != controller_expected_counts.expected_counts_sha256
            or ledger["controller_accounting_sha256"]
            != controller_expected_counts.accounting_sha256
            or ledger["controller_accounting_sha256"]
            != input_contract.f1m_controller_context.accounting_sha256
        ):
            raise ValueError("Day1B ledger splices foreign controller expected counts")
        for ledger_field, receipt_field in (
            ("f1m_controller_context_sha256", "f1m_controller_context_sha256"),
            ("f1m_route_coverage_sha256", "f1m_route_coverage_sha256"),
            (
                "f1m_charged_size_class_set_sha256",
                "f1m_charged_size_class_set_sha256",
            ),
        ):
            if (
                _require_sha256(ledger[ledger_field], f"ledger {ledger_field}")
                != worker_receipt[receipt_field]
            ):
                raise ValueError("Day1B ledger splices foreign F1-M controller roots")
        if (
            ledger["ciphertext_count_used_as_byte_proxy"] is not False
            or ledger["raw_serialized_protocol_bytes_retained"] is not False
        ):
            raise ValueError("Day1B ledger changed its byte or payload evidence basis")
        binding = str(worker_receipt["input_binding_sha256"])
        categories = ledger["categories"]
        candidate_ledger_phases[candidate_key].append(str(record["phase"]))
        candidate_ledger_outcomes[candidate_key].append(str(record["outcome"]))
        if record["outcome"] != "complete":
            if (
                ledger["byte_derivation"] is not None
                or categories is not None
                or ledger["update_serialized_bytes"] is not None
                or ledger["query_serialized_bytes"] is not None
                or ledger["controller_charged_query_bytes"] is not None
                or ledger["query_serialized_bytes_including_controller_charge"] is not None
                or ledger["one_time_serialized_bytes_excluded_from_primary_C"] is not None
                or record["update_serialized_bytes"] is not None
                or record["query_serialized_bytes"] is not None
            ):
                raise ValueError("incomplete record ledger retains partial quantity facts")
            return
        if (
            ledger["byte_derivation"]
            != "worker-streamed-spool-plus-controller-anchored-day2-size-class-v1"
        ):
            raise ValueError("complete Day1B ledger changed its dual-source byte derivation")
        if type(categories) is not list or len(categories) != len(
            SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
        ):
            raise ValueError("complete record ledger lost its exact category inventory")
        transaction_totals = {"update": 0, "query": 0, "one-time": 0}
        controller_charged_query_bytes = 0
        expected_phase_counts = controller_expected_counts.phase_counts(
            str(record["phase"])
        )
        for category_index, (category_value, expected_pair) in enumerate(
            zip(categories, SERIALIZED_PROTOCOL_OBJECT_CATEGORIES, strict=True)
        ):
            category = _exact_object(
                category_value,
                _CATEGORY_LEDGER_KEYS,
                f"ledgers[{index}].categories[{category_index}]",
            )
            if (category["category"], category["transaction"]) != expected_pair:
                raise ValueError("Day1B ledger category order or transaction changed")
            start = _strict_nonnegative_int(
                category["object_receipt_spool_start_line"], "category spool start"
            )
            line_count = _strict_nonnegative_int(
                category["object_receipt_spool_line_count"], "category spool line count"
            )
            charged_byte_count = _strict_nonnegative_int(
                category["charged_byte_count"], "category charged bytes"
            )
            protocol_object_count = _strict_nonnegative_int(
                category["protocol_object_count"], "category protocol-object count"
            )
            equivalence_class_count = _strict_nonnegative_int(
                category["serialization_equivalence_class_count"],
                "category equivalence-class count",
            )
            controller_expected_logical_count = _strict_nonnegative_int(
                category["controller_expected_logical_protocol_object_count"],
                "category controller-expected logical protocol-object count",
            )
            controller_expected_worker_count = _strict_nonnegative_int(
                category[
                    "controller_expected_worker_streamed_protocol_object_count"
                ],
                "category controller-expected worker protocol-object count",
            )
            if (
                controller_expected_logical_count
                != expected_phase_counts.logical_protocol_object_counts[
                    category_index
                ]
                or controller_expected_worker_count
                != expected_phase_counts.worker_streamed_protocol_object_counts[
                    category_index
                ]
                or protocol_object_count != controller_expected_worker_count
            ):
                raise ValueError(
                    "Day1B ledger category differs from controller expected multiplicity"
                )
            expected_metadata_size_class = (
                controller_expected_counts.metadata_size_class(expected_pair[0])
            )
            expected_combined_key_size_class = (
                controller_expected_counts.combined_evaluation_key_size_class_for(
                    expected_pair[0]
                )
            )
            documented_size = category[
                "controller_expected_serialized_byte_count"
            ]
            documented_metadata_root = category[
                "controller_expected_fixed_width_size_class_sha256"
            ]
            documented_combined_key_root = category[
                "controller_expected_combined_evaluation_key_size_class_sha256"
            ]
            if (
                expected_metadata_size_class is None
                and expected_combined_key_size_class is None
            ):
                if (
                    documented_size is not None
                    or documented_metadata_root is not None
                    or documented_combined_key_root is not None
                ):
                    raise ValueError(
                        "unpriced ledger row claims a controller size class"
                    )
            elif expected_metadata_size_class is not None:
                expected_metadata_class_count = int(
                    controller_expected_worker_count > 0
                )
                if (
                    documented_size
                    != expected_metadata_size_class.serialized_byte_count
                    or documented_combined_key_root is not None
                    or _require_sha256(
                        documented_metadata_root,
                        "ledger fixed-width metadata size-class digest",
                    )
                    != expected_metadata_size_class.metadata_size_class_sha256
                    or documented_metadata_root
                    != day1b_metadata_size_class_sha256(expected_pair[0])
                    or expected_metadata_size_class.transaction
                    != expected_pair[1]
                    or charged_byte_count
                    != controller_expected_worker_count
                    * expected_metadata_size_class.serialized_byte_count
                    or equivalence_class_count != expected_metadata_class_count
                    or line_count != expected_metadata_class_count
                ):
                    raise ValueError(
                        "Day1B metadata ledger row differs from its fixed-width size class"
                    )
            else:
                assert expected_combined_key_size_class is not None
                expected_key_class_count = int(
                    controller_expected_worker_count > 0
                )
                expected_key_root = (
                    expected_combined_key_size_class.combined_evaluation_key_size_class_sha256
                )
                if (
                    documented_size
                    != expected_combined_key_size_class.serialized_byte_count
                    or documented_metadata_root is not None
                    or _require_sha256(
                        documented_combined_key_root,
                        "ledger combined evaluation-key size-class digest",
                    )
                    != expected_key_root
                    or documented_combined_key_root
                    != day1b_combined_evaluation_key_size_class_sha256(
                        day2_outer_archive_sha256=(
                            expected_combined_key_size_class.day2_outer_archive_sha256
                        ),
                        serialized_object_size_profile_sha256=(
                            expected_combined_key_size_class.serialized_object_size_profile_sha256
                        ),
                        serialized_rotation_key_inventory_bytes=(
                            expected_combined_key_size_class.serialized_rotation_key_inventory_bytes
                        ),
                        serialized_eval_mult_key_bytes=(
                            expected_combined_key_size_class.serialized_eval_mult_key_bytes
                        ),
                    )
                    or expected_combined_key_size_class.transaction
                    != expected_pair[1]
                    or charged_byte_count
                    != controller_expected_worker_count
                    * expected_combined_key_size_class.serialized_byte_count
                    or equivalence_class_count != expected_key_class_count
                    or line_count != expected_key_class_count
                ):
                    raise ValueError(
                        "Day1B combined evaluation-key ledger row differs from its size class"
                    )
            key = (binding, str(record["phase"]), expected_pair[0])
            observed = category_facts.get(key)
            observed_count = 0 if observed is None else observed.line_count
            observed_sha256 = (
                hashlib.sha256(b"").hexdigest() if observed is None else observed.sha256
            )
            observed_charged = 0 if observed is None else observed.charged_byte_count
            observed_multiplicity = 0 if observed is None else observed.multiplicity
            if (
                observed_count != line_count
                or (observed is not None and observed.first_spool_ordinal != start)
                or observed_sha256
                != _require_sha256(category["object_receipt_stream_sha256"], "category stream")
                or observed_charged != charged_byte_count
                or observed_multiplicity != protocol_object_count
                or observed_count != equivalence_class_count
            ):
                raise ValueError("Day1B ledger category does not bind exact object-receipt rows")
            consumed_category_keys.add(key)
            transaction_totals[expected_pair[1]] += charged_byte_count
            controller_charge = _strict_nonnegative_int(
                category["controller_charged_byte_count"],
                "category controller-charged bytes",
            )
            controller_class_value = category["controller_charged_size_class"]
            if expected_pair[0] not in f1m_category_specs:
                if (
                    category["charge_authority"] != "worker-streamed-spool"
                    or controller_charge != 0
                    or controller_class_value is not None
                ):
                    raise ValueError("non-F1-M ledger row claims controller charge authority")
                continue
            if (
                category["charge_authority"] != "controller-anchored-day2-size-class"
                or charged_byte_count != 0
                or protocol_object_count != 0
                or equivalence_class_count != 0
                or line_count != 0
            ):
                raise ValueError("bridge F1-M row mixes worker and controller charge facts")
            if controller_class_value is None:
                if (
                    controller_charge != 0
                    or controller_expected_logical_count != 0
                ):
                    raise ValueError("null F1-M controller class carries a nonzero charge")
                continue
            controller_class = _exact_object(
                controller_class_value,
                _F1M_CHARGED_SIZE_CLASS_KEYS,
                f"ledgers[{index}].categories[{category_index}].controller charge",
            )
            expected_kind, expected_profile_key = f1m_category_specs[expected_pair[0]]
            multiplicity = _strict_nonnegative_int(
                controller_class["multiplicity"], "controller F1-M multiplicity"
            )
            ciphertext_bytes = _strict_nonnegative_int(
                controller_class["ciphertext_bytes"], "controller F1-M ciphertext bytes"
            )
            documented_charge = _strict_nonnegative_int(
                controller_class["charged_byte_count"], "controller F1-M charged bytes"
            )
            materialized_count = _strict_nonnegative_int(
                controller_class["materialized_cryptographic_object_count"],
                "controller F1-M materialized object count",
            )
            if (
                controller_class["schema_version"] != DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA
                or controller_class["accounting_basis"] != DAY1B_F1M_ACCOUNTING_BASIS
                or controller_class["phase"] != record["phase"]
                or controller_class["category"] != expected_pair[0]
                or controller_class["f1m_kind"] != expected_kind
                or controller_class["serialized_size_profile_key"] != expected_profile_key
                or multiplicity <= 0
                or multiplicity != controller_expected_logical_count
                or ciphertext_bytes <= 0
                or ciphertext_bytes != getattr(input_contract, expected_profile_key)
                or ciphertext_bytes != getattr(size_authority, expected_profile_key)
                or controller_class["serialized_object_size_profile_sha256"]
                != input_contract.serialized_object_size_profile_sha256
                or controller_class["serialized_object_size_profile_sha256"]
                != size_authority.serialized_object_size_profile_sha256
                or controller_class["day2_outer_archive_sha256"]
                != input_contract.day2_outer_archive_sha256
                or controller_class["day2_outer_archive_sha256"]
                != size_authority.day2_outer_archive_sha256
                or materialized_count != 0
                or documented_charge != multiplicity * ciphertext_bytes
                or controller_charge != documented_charge
            ):
                raise ValueError("Day1B controller F1-M charge document changed its semantics")
            _require_sha256(
                controller_class["serialized_object_size_profile_sha256"],
                "controller F1-M size-profile digest",
            )
            _require_sha256(
                controller_class["day2_outer_archive_sha256"],
                "controller F1-M Day 2 archive digest",
            )
            controller_charged_query_bytes += controller_charge
            candidate_controller_charge_documents[candidate_key].append(
                Day1BF1MChargedSizeClass.from_document(controller_class)
            )
        worker_query_bytes = _strict_nonnegative_int(
            ledger["query_serialized_bytes"], "ledger worker query bytes"
        )
        inclusive_query_bytes = _strict_nonnegative_int(
            ledger["query_serialized_bytes_including_controller_charge"],
            "ledger inclusive query bytes",
        )
        component_complete_query_bytes = (
            transaction_totals["query"] + controller_charged_query_bytes
        )
        if (
            transaction_totals["update"]
            != _strict_nonnegative_int(ledger["update_serialized_bytes"], "ledger update bytes")
            or transaction_totals["query"] != worker_query_bytes
            or transaction_totals["one-time"]
            != _strict_nonnegative_int(
                ledger["one_time_serialized_bytes_excluded_from_primary_C"],
                "ledger one-time bytes",
            )
            or controller_charged_query_bytes
            != _strict_nonnegative_int(
                ledger["controller_charged_query_bytes"],
                "ledger controller-charged query bytes",
            )
            or inclusive_query_bytes != component_complete_query_bytes
            or record["update_serialized_bytes"] != transaction_totals["update"]
            or record["query_serialized_bytes"] != component_complete_query_bytes
        ):
            raise ValueError("Day1B ledger worker, controller, or inclusive totals changed")

    ledger_stream = view.consume_canonical_jsonl(
        _LEDGER_FILENAME,
        maximum_file_bytes=min(
            output_limit,
            len(records) * _DAY1B_LEDGER_LINE_BYTES_MAXIMUM,
        ),
        maximum_line_bytes=_DAY1B_LEDGER_LINE_BYTES_MAXIMUM,
        consumer=consume_ledger_line,
    )
    if (
        ledger_stream.line_count != len(records)
        or ledger_stream.byte_count != member_sizes[_LEDGER_FILENAME]
        or ledger_stream.sha256 != checksum_digests[_LEDGER_FILENAME]
        or len(ledger_digests) != 486
    ):
        raise ValueError("Day1B artifact must contain exactly 486 bound serialization ledgers")
    if set(category_facts) - consumed_category_keys:
        raise ValueError("Day1B object receipts contain rows absent from the serialization ledgers")
    for candidate_key, worker_receipt in worker_receipts.items():
        candidate = worker_receipt["candidate"]
        expected_phases = (
            ["held-out"]
            if candidate["candidate_role"] == "ablation"
            else ["tuning-prefix", "held-out"]
        )
        if candidate_ledger_phases[candidate_key] != expected_phases:
            raise ValueError("Day1B candidate ledgers changed retained phase order")
        if all(outcome == "complete" for outcome in candidate_ledger_outcomes[candidate_key]):
            replayed_root = canonical_day1b_f1m_charged_size_class_set_sha256(
                tuple(candidate_controller_charge_documents[candidate_key])
            )
            if replayed_root != worker_receipt["f1m_charged_size_class_set_sha256"]:
                raise ValueError(
                    "Day1B retained ledgers do not replay the worker-bound F1-M charge set"
                )
            if replayed_root != worker_contracts[candidate_key].f1m_charged_size_class_set_sha256:
                raise ValueError(
                    "Day1B retained ledgers do not replay the open input-binding charge set"
                )

    fingerprint: tuple[object, ...] = (
        artifact_variant["kind"],
        *(digests[name] for name in _ARTIFACT_FILENAMES),
        trace_binding,
        tuple(cell_by_digest),
        tuple(ledger_digests),
        object_stream.line_count,
    )
    return _Day1BArtifactVerification(
        artifact_variant_kind=str(artifact_variant["kind"]),
        manifest_sha256=digests[_MANIFEST_FILENAME],
        heldout_fragment_sha256=digests[_FRAGMENT_FILENAME],
        schedule_sha256=digests[_SCHEDULE_FILENAME],
        serialization_ledger_sha256=digests[_LEDGER_FILENAME],
        serialized_object_receipt_sha256=digests[_OBJECT_RECEIPT_FILENAME],
        checksums_sha256=digests[_CHECKSUM_FILENAME],
        cardinality=(18, 252, 486, 486),
        semantic_fingerprint=fingerprint,
    )


def _install_verified_day1b_staging(
    *,
    staging: Path,
    staging_identity: tuple[int, int],
    output_dir: Path,
    artifact_variant_token: object,
    expected_verification: _Day1BArtifactVerification,
) -> _Day1BArtifactVerification:
    """Install one rendered unit only if every descriptor pass matches render facts."""

    if (
        not isinstance(staging, Path)
        or not isinstance(output_dir, Path)
        or type(staging_identity) is not tuple
        or len(staging_identity) != 2
        or any(type(value) is not int or value < 0 for value in staging_identity)
        or type(expected_verification) is not _Day1BArtifactVerification
    ):
        raise TypeError("Day1B staging install requires exact path, identity, and render facts")

    def verify(view: PublicationArtifactDirectory) -> _Day1BArtifactVerification:
        observed = _verify_day1b_unit_view(
            view,
            artifact_variant_token=artifact_variant_token,
        )
        if observed != expected_verification:
            raise ValueError("Day1B staged artifact differs from its exact render facts")
        return observed

    try:
        return install_verified_directory(
            staging,
            output_dir,
            staging_identity=staging_identity,
            verifier=verify,
            fingerprint=lambda verification: verification.semantic_fingerprint,
        )
    except BaseException:
        quarantine_owned_directory(staging, staging_identity=staging_identity)
        raise


def _open_new_day1b_member(directory_fd: int, name: str) -> BinaryIO:
    """Create one renderer-owned member relative to the held staging directory."""

    if type(directory_fd) is not int or directory_fd < 0 or name not in _ARTIFACT_FILENAMES:
        raise TypeError("Day1B member creation requires a held directory and canonical name")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != 0:
            raise OSError("new Day1B staging member is not one empty regular file")
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


def _write_new_file_at(directory_fd: int, name: str, content: bytes) -> tuple[str, int]:
    with _open_new_day1b_member(directory_fd, name) as handle:
        if handle.write(content) != len(content):
            raise OSError("Day1B staging member write was incomplete")
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(content).hexdigest(), len(content)


def _render_and_install_day1b_unit(
    *,
    output_dir: Path,
    repository_root: Path,
    fragment: Mapping[str, object],
    ledgers: tuple[Mapping[str, object], ...],
    object_receipt_archive: _UnitObjectReceiptArchive,
    programs: tuple[_PublicationScheduleAdapter, ...],
    manifest_base: Mapping[str, object],
    resource_policy: PublicationDay1BResourcePolicy,
    artifact_variant_token: object,
) -> PublicationDay1BUnitBundle:
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    resolved_repository = repository_root.resolve()
    resolved_output = output_dir.resolve(strict=False)
    if resolved_output == resolved_repository or resolved_output.is_relative_to(
        resolved_repository
    ):
        raise ValueError("output_dir must be outside the source checkout")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.publication-day1b-staging-",
            dir=output_dir.parent,
        )
    )
    staging_fd = os.open(
        staging,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        staging_observed = os.fstat(staging_fd)
        staging_identity = (staging_observed.st_dev, staging_observed.st_ino)
    except BaseException:
        os.close(staging_fd)
        raise
    try:
        fragment_bytes = canonical_json_bytes(fragment)
        fragment_sha, fragment_size = _write_new_file_at(
            staging_fd,
            _FRAGMENT_FILENAME,
            fragment_bytes,
        )
        ledger_hasher = hashlib.sha256()
        ledger_size = 0
        with _open_new_day1b_member(staging_fd, _LEDGER_FILENAME) as handle:
            for ledger in ledgers:
                line = canonical_json_bytes(ledger)
                if handle.write(line) != len(line):
                    raise OSError("Day1B serialization-ledger write was incomplete")
                ledger_hasher.update(line)
                ledger_size += len(line)
            handle.flush()
            os.fsync(handle.fileno())
        ledger_sha = ledger_hasher.hexdigest()
        with _open_new_day1b_member(staging_fd, _OBJECT_RECEIPT_FILENAME) as handle:
            object_receipt_sha, object_receipt_lines, object_receipt_size = (
                object_receipt_archive.copy_to(handle)
            )
            handle.flush()
            os.fsync(handle.fileno())

        schedule_hasher = hashlib.sha256()
        schedule_size = 0
        schedule_index: list[dict[str, object]] = []
        with _open_new_day1b_member(staging_fd, _SCHEDULE_FILENAME) as handle:
            for program in programs:
                program_hasher = hashlib.sha256()
                line_count = 0
                byte_count = 0
                for chunk in program.iter_canonical_bytes():
                    if type(chunk) is not bytes or not chunk.endswith(b"\n"):
                        raise ValueError(
                            "schedule chunks must be canonical newline-terminated bytes"
                        )
                    if handle.write(chunk) != len(chunk):
                        raise OSError("Day1B accepted-schedule write was incomplete")
                    schedule_hasher.update(chunk)
                    program_hasher.update(chunk)
                    line_count += 1
                    byte_count += len(chunk)
                if program_hasher.hexdigest() != program.canonical_schedule_sha256:
                    raise ValueError("schedule bytes do not match canonical_schedule_sha256")
                if line_count != program.accepted_group_count + 1:
                    raise ValueError("RLE schedule must contain one header plus one group record")
                schedule_size += byte_count
                schedule_index.append(
                    {
                        "rho": _fraction_text(program.rho),
                        "schema_version": program.schema_version,
                        "canonical_schedule_sha256": program.canonical_schedule_sha256,
                        "jsonl_line_count": line_count,
                        "byte_count": byte_count,
                        "query_events_materialized": False,
                    }
                )
            handle.flush()
            os.fsync(handle.fileno())
        schedule_sha = schedule_hasher.hexdigest()

        members = {
            _FRAGMENT_FILENAME: {"sha256": fragment_sha, "byte_count": fragment_size},
            _SCHEDULE_FILENAME: {"sha256": schedule_sha, "byte_count": schedule_size},
            _LEDGER_FILENAME: {"sha256": ledger_sha, "byte_count": ledger_size},
            _OBJECT_RECEIPT_FILENAME: {
                "sha256": object_receipt_sha,
                "byte_count": object_receipt_size,
                "jsonl_line_count": object_receipt_lines,
            },
        }
        manifest = {
            **manifest_base,
            "schedule_index": schedule_index,
            "members": members,
            "heldout_input_member_sha256": fragment_sha,
        }
        manifest_bytes = canonical_json_bytes(manifest)
        manifest_sha, manifest_size = _write_new_file_at(
            staging_fd,
            _MANIFEST_FILENAME,
            manifest_bytes,
        )
        member_bytes = {
            _MANIFEST_FILENAME: (manifest_sha, manifest_size),
            _FRAGMENT_FILENAME: (fragment_sha, fragment_size),
            _SCHEDULE_FILENAME: (schedule_sha, schedule_size),
            _LEDGER_FILENAME: (ledger_sha, ledger_size),
            _OBJECT_RECEIPT_FILENAME: (object_receipt_sha, object_receipt_size),
        }
        checksum_bytes = "".join(
            f"{member_bytes[name][0]}  {name}\n" for name in _CHECKSUM_TARGETS
        ).encode("ascii")
        checksums_sha, checksums_size = _write_new_file_at(
            staging_fd,
            _CHECKSUM_FILENAME,
            checksum_bytes,
        )
        os.fsync(staging_fd)
        total_output_bytes = sum(size for _digest_value, size in member_bytes.values()) + (
            checksums_size
        )
        if total_output_bytes > resource_policy.output_bytes_per_unit:
            raise PublicationDay1BHold("Day1B unit exceeded the frozen output-byte limit")
        artifact_variant, _unit_schema, _fragment_schema = _artifact_variant_schema_contract(
            artifact_variant_token
        )
        trace_units = fragment["trace_units"]
        cells = fragment["cell_bindings"]
        expected_verification = _Day1BArtifactVerification(
            artifact_variant_kind=str(artifact_variant["kind"]),
            manifest_sha256=manifest_sha,
            heldout_fragment_sha256=fragment_sha,
            schedule_sha256=schedule_sha,
            serialization_ledger_sha256=ledger_sha,
            serialized_object_receipt_sha256=object_receipt_sha,
            checksums_sha256=checksums_sha,
            cardinality=(18, 252, 486, 486),
            semantic_fingerprint=(
                artifact_variant["kind"],
                manifest_sha,
                fragment_sha,
                schedule_sha,
                ledger_sha,
                object_receipt_sha,
                checksums_sha,
                trace_units[0]["trace_binding_sha256"],
                tuple(cell["cell_binding_sha256"] for cell in cells),
                tuple(ledger["serialization_ledger_sha256"] for ledger in ledgers),
                object_receipt_lines,
            ),
        )
        os.close(staging_fd)
        staging_fd = -1
        installed = _install_verified_day1b_staging(
            staging=staging,
            staging_identity=staging_identity,
            output_dir=output_dir,
            artifact_variant_token=artifact_variant_token,
            expected_verification=expected_verification,
        )
        return PublicationDay1BUnitBundle(
            output_dir=output_dir,
            manifest_path=output_dir / _MANIFEST_FILENAME,
            heldout_fragment_path=output_dir / _FRAGMENT_FILENAME,
            schedule_path=output_dir / _SCHEDULE_FILENAME,
            serialization_ledger_path=output_dir / _LEDGER_FILENAME,
            serialized_object_receipt_path=output_dir / _OBJECT_RECEIPT_FILENAME,
            checksums_path=output_dir / _CHECKSUM_FILENAME,
            manifest_sha256=installed.manifest_sha256,
            heldout_fragment_sha256=installed.heldout_fragment_sha256,
            schedule_sha256=installed.schedule_sha256,
            serialization_ledger_sha256=installed.serialization_ledger_sha256,
            serialized_object_receipt_sha256=installed.serialized_object_receipt_sha256,
            checksums_sha256=installed.checksums_sha256,
        )
    except BaseException:
        if staging_fd >= 0:
            os.close(staging_fd)
        quarantine_owned_directory(staging, staging_identity=staging_identity)
        raise


@dataclass(frozen=True, slots=True)
class _Day1BWorkerContractSeed:
    """Core-owned candidate×cell facts; the adapter may bind only measured expectations."""

    invocation_id: str
    trace_manifest_sha256: str
    event_schedule_sha256: str
    query_vector_sha256: str
    candidate_catalog_sha256: str
    resource_policy_sha256: str
    day2_outer_archive_sha256: str
    serialized_object_size_profile_sha256: str
    ciphertext_bytes: int
    f1m_random_zero_sum_ciphertext_bytes: int
    f1m_encrypted_zero_dummy_ciphertext_bytes: int
    serialized_rotation_key_inventory_bytes: int
    serialized_eval_mult_key_bytes: int
    freshness: str
    rho: str
    candidate: Day1BWorkerCandidateSpec
    phase_ranges: tuple[Day1BWorkerPhaseRange, ...]
    resource_limits: Day1BWorkerResourceLimits
    f1m_controller_summary: Day1BF1MControllerSummary
    controller_expected_counts: Day1BControllerExpectedCounts

    def __post_init__(self) -> None:
        if type(self.f1m_controller_summary) is not Day1BF1MControllerSummary:
            raise TypeError("worker seed requires one exact F1-M controller summary")
        if type(self.controller_expected_counts) is not Day1BControllerExpectedCounts:
            raise TypeError("worker seed requires one exact controller count preimage")
        require_formal_day1b_f1m_worker_zero(self.controller_expected_counts)
        require_formal_day1b_fixed_width_metadata_size_classes(
            self.controller_expected_counts
        )
        require_formal_day1b_combined_evaluation_key_size_class(
            self.controller_expected_counts
        )
        summary = self.f1m_controller_summary
        expected_counts = self.controller_expected_counts
        combined_key_size_class = (
            expected_counts.combined_evaluation_key_size_class
        )
        assert combined_key_size_class is not None
        context = summary.context
        authority = summary.size_authority
        expected_phase_ranges = tuple(
            Day1BF1MPhaseBoundary(
                {"warmup": "warmup", "tuning": "tuning-prefix", "heldout": "held-out"}[phase.phase],
                phase.accepted_group_start,
                phase.accepted_group_end,
            )
            for phase in self.phase_ranges
        )
        expected_invocation_id = _digest(
            {
                "candidate_id": self.candidate.candidate_id,
                "cell_binding_sha256": context.cell_binding_sha256,
                "schema_version": ("dynamic-cssc-publication-day1b-candidate-cell-invocation-v1"),
            }
        )
        if (
            self.invocation_id != expected_invocation_id
            or context.trace_manifest_sha256 != self.trace_manifest_sha256
            or context.event_schedule_sha256 != self.event_schedule_sha256
            or context.query_vector_sha256 != self.query_vector_sha256
            or context.candidate_catalog_sha256 != self.candidate_catalog_sha256
            or context.resource_policy_sha256 != self.resource_policy_sha256
            or context.freshness != self.freshness
            or context.rho != self.rho
            or context.candidate_id != self.candidate.candidate_id
            or context.candidate_role != self.candidate.candidate_role
            or context.candidate_policy_sha256 != self.candidate.candidate_policy_digest
            or context.retained_phases != self.candidate.retained_phases
            or expected_counts.candidate_id != self.candidate.candidate_id
            or expected_counts.candidate_policy_sha256
            != self.candidate.candidate_policy_digest
            or expected_counts.accounting_sha256 != context.accounting_sha256
            or expected_counts.primitive_names != PRIMITIVE_NAMES
            or expected_counts.serialized_categories
            != SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
            or tuple(phase.phase for phase in expected_counts.phases)
            != self.candidate.retained_phases
            or context.phase_boundaries != expected_phase_ranges
            or authority.day2_outer_archive_sha256 != self.day2_outer_archive_sha256
            or authority.serialized_object_size_profile_sha256
            != self.serialized_object_size_profile_sha256
            or authority.ciphertext_bytes != self.ciphertext_bytes
            or authority.f1m_random_zero_sum_ciphertext_bytes
            != self.f1m_random_zero_sum_ciphertext_bytes
            or authority.f1m_encrypted_zero_dummy_ciphertext_bytes
            != self.f1m_encrypted_zero_dummy_ciphertext_bytes
            or authority.serialized_rotation_key_inventory_bytes
            != self.serialized_rotation_key_inventory_bytes
            or authority.serialized_eval_mult_key_bytes
            != self.serialized_eval_mult_key_bytes
            or combined_key_size_class.day2_outer_archive_sha256
            != authority.day2_outer_archive_sha256
            or combined_key_size_class.serialized_object_size_profile_sha256
            != authority.serialized_object_size_profile_sha256
            or combined_key_size_class.serialized_rotation_key_inventory_bytes
            != authority.serialized_rotation_key_inventory_bytes
            or combined_key_size_class.serialized_eval_mult_key_bytes
            != authority.serialized_eval_mult_key_bytes
            or summary.serialized_object_bytes_maximum
            != self.resource_limits.serialized_object_bytes_maximum
            or summary.serialized_payload_bytes_per_cell_maximum
            != self.resource_limits.serialized_payload_bytes_per_cell_maximum
        ):
            raise Day1BWorkerProtocolError(
                "worker seed and F1-M controller summary do not bind one candidate cell"
            )

    def bind(
        self,
        *,
        expected_f1m_size_class_set_sha256: str,
        expected_f1m_size_class_count: int,
        expected_serialized_equivalence_class_count: int,
        expected_f1m_cardinality_derivation_root_sha256: str,
    ) -> Day1BWorkerProtocolContract:
        combined_key_size_class = (
            self.controller_expected_counts.combined_evaluation_key_size_class
        )
        assert combined_key_size_class is not None
        return Day1BWorkerProtocolContract(
            invocation_id=self.invocation_id,
            trace_manifest_sha256=self.trace_manifest_sha256,
            event_schedule_sha256=self.event_schedule_sha256,
            query_vector_sha256=self.query_vector_sha256,
            candidate_catalog_sha256=self.candidate_catalog_sha256,
            resource_policy_sha256=self.resource_policy_sha256,
            day2_outer_archive_sha256=self.day2_outer_archive_sha256,
            serialized_object_size_profile_sha256=(self.serialized_object_size_profile_sha256),
            ciphertext_bytes=self.ciphertext_bytes,
            f1m_random_zero_sum_ciphertext_bytes=(self.f1m_random_zero_sum_ciphertext_bytes),
            f1m_encrypted_zero_dummy_ciphertext_bytes=(
                self.f1m_encrypted_zero_dummy_ciphertext_bytes
            ),
            serialized_rotation_key_inventory_bytes=(
                self.serialized_rotation_key_inventory_bytes
            ),
            serialized_eval_mult_key_bytes=self.serialized_eval_mult_key_bytes,
            combined_evaluation_key_size_class_sha256=(
                combined_key_size_class.combined_evaluation_key_size_class_sha256
            ),
            freshness=self.freshness,
            rho=self.rho,
            execution_basis=DAY1B_WORKER_EXECUTION_BASIS,
            candidate=self.candidate,
            phase_ranges=self.phase_ranges,
            primitive_names=PRIMITIVE_NAMES,
            serialized_categories=SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
            f1m_size_class_categories=DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES,
            f1m_controller_context=self.f1m_controller_summary.context,
            f1m_controller_context_sha256=(self.f1m_controller_summary.context.context_sha256),
            f1m_route_coverage=self.f1m_controller_summary.route_coverage,
            f1m_route_coverage_sha256=(self.f1m_controller_summary.route_coverage_sha256),
            f1m_charged_size_class_set_sha256=(
                self.f1m_controller_summary.charged_size_class_set_sha256
            ),
            controller_expected_counts=self.controller_expected_counts,
            controller_expected_counts_sha256=(
                self.controller_expected_counts.expected_counts_sha256
            ),
            expected_f1m_size_class_set_sha256=expected_f1m_size_class_set_sha256,
            expected_f1m_size_class_count=expected_f1m_size_class_count,
            expected_serialized_equivalence_class_count=(
                expected_serialized_equivalence_class_count
            ),
            expected_f1m_cardinality_derivation_root_sha256=(
                expected_f1m_cardinality_derivation_root_sha256
            ),
            resource_limits=self.resource_limits,
        )

    def require_exact_bound_contract(self, contract: Day1BWorkerProtocolContract) -> None:
        if type(contract) is not Day1BWorkerProtocolContract:
            raise TypeError("worker launch contract must be exact typed protocol input")
        expected = self.bind(
            expected_f1m_size_class_set_sha256=contract.expected_f1m_size_class_set_sha256,
            expected_f1m_size_class_count=contract.expected_f1m_size_class_count,
            expected_serialized_equivalence_class_count=(
                contract.expected_serialized_equivalence_class_count
            ),
            expected_f1m_cardinality_derivation_root_sha256=(
                contract.expected_f1m_cardinality_derivation_root_sha256
            ),
        )
        if contract != expected:
            raise Day1BWorkerProtocolError(
                "worker launch retargeted repository-owned candidate-cell contract facts"
            )


def _serialized_object_size_authority_document(
    authority: _Day1BSerializedObjectSizeAuthority,
) -> dict[str, object]:
    if type(authority) is not _Day1BSerializedObjectSizeAuthority:
        raise TypeError("Day1B size authority must be one exact typed authority")
    return {
        "schema_version": DAY1B_SERIALIZED_OBJECT_SIZE_AUTHORITY_SCHEMA,
        **authority.to_document(),
    }


def _parse_serialized_object_size_authority_document(
    value: object,
) -> _Day1BSerializedObjectSizeAuthority:
    document = _exact_object(
        value,
        _SERIALIZED_OBJECT_SIZE_AUTHORITY_KEYS,
        "manifest.serialized_object_size_authority",
    )
    if document["schema_version"] != DAY1B_SERIALIZED_OBJECT_SIZE_AUTHORITY_SCHEMA:
        raise ValueError("Day1B serialized-object size-authority schema changed")
    authority = _Day1BSerializedObjectSizeAuthority(
        source_git_sha=document["source_git_sha"],
        day2_experiment_source_git_sha=document["day2_experiment_source_git_sha"],
        day2_outer_archive_sha256=document["day2_outer_archive_sha256"],
        serialized_object_size_profile_sha256=(
            document["serialized_object_size_profile_sha256"]
        ),
        ciphertext_bytes=document["ciphertext_bytes"],
        f1m_random_zero_sum_ciphertext_bytes=(
            document["f1m_random_zero_sum_ciphertext_bytes"]
        ),
        f1m_encrypted_zero_dummy_ciphertext_bytes=(
            document["f1m_encrypted_zero_dummy_ciphertext_bytes"]
        ),
        serialized_rotation_key_inventory_bytes=(
            document["serialized_rotation_key_inventory_bytes"]
        ),
        serialized_eval_mult_key_bytes=document["serialized_eval_mult_key_bytes"],
    )
    if _serialized_object_size_authority_document(authority) != document:
        raise ValueError(
            "Day1B serialized-object size authority is not its exact typed projection"
        )
    return authority


def _candidate_policy_preimage(candidate: RegisteredCandidate) -> dict[str, object]:
    if type(candidate) is not RegisteredCandidate:
        raise TypeError("candidate policy requires one exact RegisteredCandidate")
    return {
        "candidate_id": candidate.candidate_id,
        "candidate_role": candidate.role,
        "packed_coo_segment_capacity": candidate.packed_coo_segment_capacity,
        "periodic_repack_windows": candidate.periodic_repack_windows,
        "reserved_slack_beta": (
            None if candidate.reserved_slack_beta is None else str(candidate.reserved_slack_beta)
        ),
        "strategy": candidate.strategy,
    }


def _candidate_policy_digest(candidate: RegisteredCandidate) -> str:
    return _digest(_candidate_policy_preimage(candidate))


def _candidate_policy_document(candidate: RegisteredCandidate) -> dict[str, object]:
    preimage = _candidate_policy_preimage(candidate)
    return {**preimage, "candidate_policy_digest": _digest(preimage)}


def _parse_candidate_policy_documents(value: object) -> tuple[RegisteredCandidate, ...]:
    if type(value) is not list or len(value) != len(FIXED_CANDIDATE_IDS):
        raise ValueError("Day1B candidate-policy catalog must contain exactly 14 entries")
    candidates: list[RegisteredCandidate] = []
    for index, raw_policy in enumerate(value):
        policy = _exact_object(
            raw_policy,
            _CANDIDATE_POLICY_KEYS,
            f"manifest.candidate_catalog.candidate_policies[{index}]",
        )
        beta_value = policy["reserved_slack_beta"]
        if beta_value is None:
            beta = None
        elif type(beta_value) is str:
            try:
                beta = Decimal(beta_value)
            except InvalidOperation as error:
                raise ValueError("Day1B candidate reserved-slack beta is invalid") from error
            if not beta.is_finite() or str(beta) != beta_value:
                raise ValueError("Day1B candidate reserved-slack beta is not canonical")
        else:
            raise ValueError("Day1B candidate reserved-slack beta must be a string or null")
        for field in ("periodic_repack_windows", "packed_coo_segment_capacity"):
            item = policy[field]
            if item is not None and (type(item) is not int or item <= 0):
                raise ValueError(f"Day1B candidate {field} must be a strict positive integer")
        candidate = RegisteredCandidate(
            candidate_id=policy["candidate_id"],
            strategy=policy["strategy"],
            role=policy["candidate_role"],
            reserved_slack_beta=beta,
            periodic_repack_windows=policy["periodic_repack_windows"],
            packed_coo_segment_capacity=policy["packed_coo_segment_capacity"],
        )
        if _candidate_policy_document(candidate) != policy:
            raise ValueError("Day1B candidate policy is not its exact self-bound preimage")
        candidates.append(candidate)
    return tuple(candidates)


def _candidate_worker_spec(candidate: RegisteredCandidate) -> Day1BWorkerCandidateSpec:
    if type(candidate) is not RegisteredCandidate:
        raise TypeError("worker candidate must be exact RegisteredCandidate")
    return Day1BWorkerCandidateSpec(
        candidate_id=candidate.candidate_id,
        candidate_role=candidate.role,
        strategy=candidate.strategy,
        f1m_policy=(
            "uniform-random-or-zero"
            if candidate.strategy == "Packed-COO-Cloud-Segmented-Delta"
            else "overlap-only"
        ),
        candidate_policy_digest=_candidate_policy_digest(candidate),
        retained_phases=(
            ("tuning-prefix", "held-out") if candidate.role == "reference" else ("held-out",)
        ),
    )


def _candidate_worker_contract_seed(
    *,
    trace: _Day1BTraceInput,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    candidate: RegisteredCandidate,
    cell_binding_sha256: str,
    candidate_catalog_sha256: str,
    resource_policy: PublicationDay1BResourcePolicy,
    resource_policy_sha256: str,
    size_authority: _Day1BSerializedObjectSizeAuthority,
    f1m_controller_summary: Day1BF1MControllerSummary,
    controller_expected_counts: Day1BControllerExpectedCounts,
) -> _Day1BWorkerContractSeed:
    invocation_id = _digest(
        {
            "candidate_id": candidate.candidate_id,
            "cell_binding_sha256": cell_binding_sha256,
            "schema_version": "dynamic-cssc-publication-day1b-candidate-cell-invocation-v1",
        }
    )
    return _Day1BWorkerContractSeed(
        invocation_id=invocation_id,
        trace_manifest_sha256=trace.trace_manifest_sha256,
        event_schedule_sha256=program.canonical_schedule_sha256,
        query_vector_sha256=trace.query_vector_sha256,
        candidate_catalog_sha256=candidate_catalog_sha256,
        resource_policy_sha256=resource_policy_sha256,
        day2_outer_archive_sha256=size_authority.day2_outer_archive_sha256,
        serialized_object_size_profile_sha256=(
            size_authority.serialized_object_size_profile_sha256
        ),
        ciphertext_bytes=size_authority.ciphertext_bytes,
        f1m_random_zero_sum_ciphertext_bytes=(size_authority.f1m_random_zero_sum_ciphertext_bytes),
        f1m_encrypted_zero_dummy_ciphertext_bytes=(
            size_authority.f1m_encrypted_zero_dummy_ciphertext_bytes
        ),
        serialized_rotation_key_inventory_bytes=(
            size_authority.serialized_rotation_key_inventory_bytes
        ),
        serialized_eval_mult_key_bytes=size_authority.serialized_eval_mult_key_bytes,
        freshness=_fraction_text(freshness),
        rho=_fraction_text(program.rho),
        candidate=_candidate_worker_spec(candidate),
        phase_ranges=tuple(
            Day1BWorkerPhaseRange(phase.name, phase.start, phase.end)
            for phase in program.phase_ranges
        ),
        resource_limits=resource_policy.to_worker_limits(),
        f1m_controller_summary=f1m_controller_summary,
        controller_expected_counts=controller_expected_counts,
    )


def _complete_cell_audit(
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
) -> _CellAudit:
    stream = _AuditedWindowStream(
        program.stream_windows(freshness),
        program.phase_ranges,
        program.rho,
    )
    for _window in stream:
        pass
    return stream.finish()


def _test_only_f1m_execution_lineage(
    *,
    source: _Day1BPreparatorySourceAttestation,
    trace: _Day1BTraceInput,
) -> _Day1BF1MExecutionLineage:
    """Conspicuously non-authoritative identities for the private artifact variant."""

    return _Day1BF1MExecutionLineage(
        day1_registration_anchor_sha256=_digest(
            {
                "kind": "test-only-day1-registration-anchor",
                "source_git_sha": source.git_sha,
            }
        ),
        trace_post_run_anchor_sha256=_digest(
            {
                "kind": "test-only-trace-post-run-anchor",
                "trace_manifest_sha256": trace.trace_manifest_sha256,
            }
        ),
        worker_build_identity_sha256=_digest(
            {
                "kind": "test-only-worker-build",
                "source_git_sha": source.git_sha,
            }
        ),
        worker_runtime_identity_sha256=_digest(
            {
                "kind": "test-only-worker-runtime",
                "source_git_sha": source.git_sha,
            }
        ),
    )


def _f1m_complete_schedule_audit(audit: _CellAudit) -> Day1BF1MCompleteScheduleAudit:
    if type(audit) is not _CellAudit:
        raise TypeError("F1-M schedule audit requires one exact cell audit")
    phase_name = {
        "warmup": "warmup",
        "tuning": "tuning-prefix",
        "heldout": "held-out",
    }
    return Day1BF1MCompleteScheduleAudit(
        tuple(
            Day1BF1MCompletePhaseAudit(
                phase=phase_name[item.phase],
                accepted_group_start=item.accepted_group_start,
                accepted_group_end=item.accepted_group_end,
                realized_window_count=item.realized_window_count,
                realized_set_count=item.realized_set_count,
                realized_query_count=item.realized_query_count,
                consumed_window_audit_stream_sha256=(item.consumed_window_audit_stream_sha256),
            )
            for item in audit.phase_audits
        )
    )


def _f1m_controller_context(
    *,
    source: _Day1BPreparatorySourceAttestation,
    trace: _Day1BTraceInput,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    cell: Mapping[str, object],
    cell_ordinal: int,
    candidate_spec: Day1BWorkerCandidateSpec,
    terminal_registration_sha256: str,
    candidate_catalog_sha256: str,
    resource_policy_sha256: str,
    lineage: _Day1BF1MExecutionLineage,
    accounting: PublicationDay1BAccounting,
    complete_schedule_audit: Day1BF1MCompleteScheduleAudit,
) -> Day1BF1MControllerContext:
    """Bind replay output to repository lineage and an independent full-window audit."""

    if type(lineage) is not _Day1BF1MExecutionLineage:
        raise TypeError("F1-M execution lineage type is not exact")
    if type(candidate_spec) is not Day1BWorkerCandidateSpec:
        raise TypeError("F1-M candidate spec type is not exact")
    if accounting.candidate_id != candidate_spec.candidate_id:
        raise Day1BWorkerProtocolError("F1-M accounting changed the candidate identity")
    if accounting.candidate_policy_sha256 != candidate_spec.candidate_policy_digest:
        raise Day1BWorkerProtocolError("F1-M accounting changed the candidate policy")
    _require_sha256(terminal_registration_sha256, "terminal registration SHA")
    _require_sha256(candidate_catalog_sha256, "Day1B candidate catalog SHA")
    _require_sha256(resource_policy_sha256, "Day1B resource policy SHA")
    behavior_schema = source.behavior_inventory.get("behavior_set_schema_version")
    behavior_sha256 = source.behavior_inventory.get("behavior_set_sha256")
    if type(behavior_schema) is not str or not behavior_schema:
        raise ValueError("Day1B behavior-set schema is unavailable to F1-M accounting")
    _require_sha256(behavior_sha256, "Day1B behavior-set inventory SHA")
    unit_identity_sha256 = _digest(
        {
            "dataset_id": trace.dataset_id,
            "dataset_release": trace.dataset_release,
            "semantics": trace.semantics,
            "source_partition": trace.source_partition,
        }
    )
    phase_boundaries = tuple(
        Day1BF1MPhaseBoundary(
            {"warmup": "warmup", "tuning": "tuning-prefix", "heldout": "held-out"}[phase.name],
            phase.start,
            phase.end,
        )
        for phase in program.phase_ranges
    )
    phase_query_counts = (
        accounting.phases[0].realized_query_count,
        accounting.phases[1].realized_query_count,
        accounting.phases[2].realized_query_count,
    )
    phase_window_counts = (
        accounting.phases[0].realized_window_count,
        accounting.phases[1].realized_window_count,
        accounting.phases[2].realized_window_count,
    )
    cell_binding_sha256 = _require_sha256(
        cell.get("cell_binding_sha256"),
        "Day1B F1-M cell binding SHA",
    )
    return Day1BF1MControllerContext(
        publication_source_git_sha=source.git_sha,
        trace_source_git_sha=trace.trace_source_git_sha,
        publication_behavior_set_schema_version=behavior_schema,
        publication_behavior_inventory_sha256=behavior_sha256,
        terminal_registration_sha256=terminal_registration_sha256,
        day1_registration_anchor_sha256=(lineage.day1_registration_anchor_sha256),
        trace_post_run_anchor_sha256=lineage.trace_post_run_anchor_sha256,
        acquisition_bundle_sha256=trace.source_bundle_sha256,
        trace_manifest_sha256=trace.trace_manifest_sha256,
        candidate_catalog_sha256=candidate_catalog_sha256,
        resource_policy_sha256=resource_policy_sha256,
        worker_build_identity_sha256=lineage.worker_build_identity_sha256,
        worker_runtime_identity_sha256=lineage.worker_runtime_identity_sha256,
        dataset_id=trace.dataset_id,
        dataset_release=trace.dataset_release,
        semantics=trace.semantics,
        source_partition=trace.source_partition,
        unit_identity_sha256=unit_identity_sha256,
        cell_binding_sha256=cell_binding_sha256,
        cell_ordinal=cell_ordinal,
        freshness=_fraction_text(freshness),
        rho=_fraction_text(program.rho),
        candidate_id=candidate_spec.candidate_id,
        candidate_role=candidate_spec.candidate_role,
        candidate_policy_sha256=accounting.candidate_policy_sha256,
        retained_phases=candidate_spec.retained_phases,
        phase_boundaries=phase_boundaries,
        event_schedule_sha256=program.canonical_schedule_sha256,
        query_vector_sha256=trace.query_vector_sha256,
        accepted_group_count=program.accepted_group_count,
        complete_window_count=accounting.realized_window_count,
        query_window_count=accounting.realized_query_window_count,
        zero_query_window_count=(
            accounting.realized_window_count - accounting.realized_query_window_count
        ),
        total_query_count=accounting.realized_query_count,
        phase_window_counts=phase_window_counts,
        phase_query_counts=phase_query_counts,
        complete_window_stream_sha256=accounting.window_stream_sha256,
        complete_phase_audit_root_sha256=(complete_schedule_audit.complete_phase_audit_root_sha256),
        accounting_sha256=accounting.accounting_sha256,
        query_window_stream_sha256=accounting.query_window_stream_sha256,
    )


def _replay_f1m_controller_for_candidate_cell(
    *,
    source: _Day1BPreparatorySourceAttestation,
    trace: _Day1BTraceInput,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    cell: Mapping[str, object],
    cell_ordinal: int,
    candidate: RegisteredCandidate,
    terminal_registration_sha256: str,
    candidate_catalog_sha256: str,
    resource_policy_sha256: str,
    lineage: _Day1BF1MExecutionLineage,
    size_authority: _Day1BSerializedObjectSizeAuthority,
    resource_policy: PublicationDay1BResourcePolicy,
    expected_complete_audit: _CellAudit,
    accounting_domain: Day1BAccountingDomain = PUBLICATION_DAY1B_ACCOUNTING_DOMAIN,
) -> _Day1BControllerReplay:
    """Replay one deterministic, independently audited controller accounting pass."""

    candidate_spec = _candidate_worker_spec(candidate)
    controller = Day1BF1MController(
        accepted_group_count=program.accepted_group_count,
        retained_phases=candidate_spec.retained_phases,
        f1m_policy=candidate_spec.f1m_policy,
        size_authority=size_authority,
        serialized_object_bytes_maximum=(resource_policy.serialized_object_bytes_maximum),
        serialized_payload_bytes_per_cell_maximum=(
            resource_policy.serialized_payload_bytes_per_cell_maximum
        ),
    )
    audited_windows = _AuditedWindowStream(
        program.stream_windows(freshness),
        program.phase_ranges,
        program.rho,
    )
    accounting = replay_publication_day1b_candidate_cell(
        candidate=candidate,
        windows=audited_windows,
        domain=accounting_domain,
        query_window_sink=controller.accept_query_window,
    )
    replay_audit = audited_windows.finish()
    if replay_audit != expected_complete_audit:
        raise Day1BWorkerProtocolError(
            "F1-M accounting replay did not consume the canonical complete cell schedule"
        )
    complete_schedule_audit = _f1m_complete_schedule_audit(replay_audit)
    context = _f1m_controller_context(
        source=source,
        trace=trace,
        program=program,
        freshness=freshness,
        cell=cell,
        cell_ordinal=cell_ordinal,
        candidate_spec=candidate_spec,
        terminal_registration_sha256=terminal_registration_sha256,
        candidate_catalog_sha256=candidate_catalog_sha256,
        resource_policy_sha256=resource_policy_sha256,
        lineage=lineage,
        accounting=accounting,
        complete_schedule_audit=complete_schedule_audit,
    )
    summary = controller.finish(
        context=context,
        accounting=accounting,
        complete_schedule_audit=complete_schedule_audit,
    )
    expected_counts = derive_day1b_controller_expected_counts(
        accounting=accounting,
        retained_phases=candidate_spec.retained_phases,
        primitive_names=PRIMITIVE_NAMES,
        serialized_categories=SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
        phase_random_route_counts=summary.phase_random_route_counts,
        phase_dummy_route_counts=summary.phase_dummy_route_counts,
        day2_outer_archive_sha256=size_authority.day2_outer_archive_sha256,
        serialized_object_size_profile_sha256=(
            size_authority.serialized_object_size_profile_sha256
        ),
        serialized_rotation_key_inventory_bytes=(
            size_authority.serialized_rotation_key_inventory_bytes
        ),
        serialized_eval_mult_key_bytes=size_authority.serialized_eval_mult_key_bytes,
    )
    return _Day1BControllerReplay(
        f1m_summary=summary,
        expected_counts=expected_counts,
    )


def _produce_publication_day1b_unit(
    *,
    trace: _Day1BTraceInput,
    output_dir: Path,
    source_attestation: _Day1BPreparatorySourceAttestation,
    candidate_catalog: Day1CandidateCatalog,
    resource_policy: PublicationDay1BResourcePolicy,
    size_authority: _Day1BSerializedObjectSizeAuthority,
    execution_adapter: _Day1BExecutionAdapter,
    repository_root: Path,
    artifact_variant_token: object,
    f1m_execution_lineage: _Day1BF1MExecutionLineage | None = None,
) -> PublicationDay1BUnitBundle:
    """Build one complete unit through typed internal seams and one-pass windows."""

    if not isinstance(output_dir, Path) or not isinstance(repository_root, Path):
        raise TypeError("output_dir and repository_root must be pathlib.Path values")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    if (
        artifact_variant_token is not _PRODUCTION_ARTIFACT_VARIANT_TOKEN
        and artifact_variant_token is not _TEST_ARTIFACT_VARIANT_TOKEN
    ):
        raise TypeError("Day1B artifact variant requires one exact producer capability")
    _validate_trace(trace)
    _validate_preparatory_source_attestation(source_attestation)
    candidates = _validate_catalog(candidate_catalog)
    if type(resource_policy) is not PublicationDay1BResourcePolicy:
        raise TypeError("resource_policy must be an exact fixed policy")
    if type(size_authority) is not _Day1BSerializedObjectSizeAuthority:
        raise TypeError("size_authority must be exact Day 2 size authority")
    if size_authority.source_git_sha != source_attestation.git_sha:
        raise ValueError("Day 2 size authority changed the Day1B source identity")
    if not callable(getattr(execution_adapter, "execute_candidate_cell", None)):
        raise TypeError("execution_adapter must provide the candidate-cell streaming seam")
    artifact_variant, unit_schema, fragment_schema = _artifact_variant_contract(
        artifact_variant_token,
        trace=trace,
        source=source_attestation,
    )
    if artifact_variant_token is _TEST_ARTIFACT_VARIANT_TOKEN:
        expected_test_lineage = _test_only_f1m_execution_lineage(
            source=source_attestation,
            trace=trace,
        )
        if f1m_execution_lineage is None:
            f1m_execution_lineage = expected_test_lineage
        elif f1m_execution_lineage != expected_test_lineage:
            raise ValueError("fixture F1-M lineage must be the exact test-only derivation")
        accounting_domain = _TEST_DAY1B_ACCOUNTING_DOMAIN
    elif type(f1m_execution_lineage) is not _Day1BF1MExecutionLineage:
        raise TypeError("production Day1B requires exact repository-admitted F1-M lineage")
    else:
        accounting_domain = PUBLICATION_DAY1B_ACCOUNTING_DOMAIN

    programs = tuple(trace.compile_schedule(Fraction(rho)) for rho in RHO_VALUES)
    for program, rho in zip(programs, (Fraction(value) for value in RHO_VALUES), strict=True):
        _validate_program(program, trace=trace, rho=rho)

    trace_unit = _trace_unit_document(trace, source_attestation)
    registration = asdict(candidate_catalog.registration)
    catalog_document = {
        "registration": registration,
        "registration_sha256": _digest(registration),
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": [ABLATION_CANDIDATE_ID],
        "candidate_policies": [_candidate_policy_document(candidate) for candidate in candidates],
    }
    candidate_catalog_sha256 = _digest(catalog_document)
    terminal_registration_sha256 = _require_sha256(
        catalog_document["registration_sha256"],
        "terminal Day1 registration SHA",
    )
    resource_document = resource_policy.to_document()
    resource_policy_sha256 = str(resource_document["resource_policy_sha256"])
    cells: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    cell_execution_receipts: list[dict[str, object]] = []
    candidate_cell_receipt_count = 0
    object_receipt_archive = _UnitObjectReceiptArchive()
    try:
        for freshness_text in FRESHNESS_VALUES:
            freshness = Fraction(freshness_text)
            for program in programs:
                cell_ordinal = len(cells)
                audit = _complete_cell_audit(program, freshness)
                cell = _cell_document(
                    trace_unit,
                    trace,
                    source_attestation,
                    program,
                    freshness,
                    audit,
                )
                tuning_records: list[dict[str, object]] = []
                tuning_ledgers: list[dict[str, object]] = []
                heldout_records: list[dict[str, object]] = []
                heldout_ledgers: list[dict[str, object]] = []
                candidate_receipts: list[dict[str, object]] = []
                peak_resident_memory_bytes = 0
                peak_scratch_bytes = 0

                for candidate in candidates:
                    launch: _Day1BWorkerLaunch | None = None
                    invocation_consumed = False
                    try:
                        controller_replay = _replay_f1m_controller_for_candidate_cell(
                            source=source_attestation,
                            trace=trace,
                            program=program,
                            freshness=freshness,
                            cell=cell,
                            cell_ordinal=cell_ordinal,
                            candidate=candidate,
                            terminal_registration_sha256=(terminal_registration_sha256),
                            candidate_catalog_sha256=candidate_catalog_sha256,
                            resource_policy_sha256=resource_policy_sha256,
                            lineage=f1m_execution_lineage,
                            size_authority=size_authority,
                            resource_policy=resource_policy,
                            expected_complete_audit=audit,
                            accounting_domain=accounting_domain,
                        )
                        f1m_controller_summary = controller_replay.f1m_summary
                        audited_windows = _AuditedWindowStream(
                            program.stream_windows(freshness),
                            program.phase_ranges,
                            program.rho,
                        )
                        seed = _candidate_worker_contract_seed(
                            trace=trace,
                            program=program,
                            freshness=freshness,
                            candidate=candidate,
                            cell_binding_sha256=str(cell["cell_binding_sha256"]),
                            candidate_catalog_sha256=candidate_catalog_sha256,
                            resource_policy=resource_policy,
                            resource_policy_sha256=resource_policy_sha256,
                            size_authority=size_authority,
                            f1m_controller_summary=f1m_controller_summary,
                            controller_expected_counts=(
                                controller_replay.expected_counts
                            ),
                        )
                        launch = execution_adapter.execute_candidate_cell(
                            windows=audited_windows,
                            contract_seed=seed,
                        )
                        if type(launch) is not _Day1BWorkerLaunch:
                            raise TypeError(
                                "execution adapter must return one exact candidate-cell launch"
                            )
                        candidate_audit = audited_windows.finish()
                        if candidate_audit != audit:
                            raise Day1BWorkerProtocolError(
                                "candidate did not consume the canonical complete cell schedule"
                            )
                        seed.require_exact_bound_contract(launch.contract)
                        evidence_capability = consume_day1b_worker_frames(
                            launch.frame_chunks,
                            contract=launch.contract,
                            invocation_capability=launch.invocation_capability,
                        )
                        invocation_consumed = True
                        with claim_day1b_worker_evidence(evidence_capability) as evidence:
                            receipt = evidence.receipt
                            if (
                                receipt.input_binding_sha256 != launch.contract.input_binding_sha256
                                or receipt.controller_schedule_phase_audits != audit.phase_audits
                            ):
                                raise Day1BWorkerProtocolError(
                                    "candidate receipt changed its bound input or schedule audit"
                                )
                            object_receipt_archive.accept_candidate_receipt(receipt)
                            _append_candidate_object_receipts(
                                evidence,
                                object_receipt_archive,
                            )
                            candidate_records, candidate_ledgers = _records_for_candidate_cell(
                                receipt,
                                trace=trace,
                                cell=cell,
                                f1m_controller_summary=f1m_controller_summary,
                            )
                            receipt_document = receipt.to_document()
                            if (
                                len(canonical_json_bytes(receipt_document))
                                > _DAY1B_WORKER_RECEIPT_CANONICAL_BYTES_MAXIMUM
                            ):
                                raise Day1BWorkerProtocolError(
                                    "candidate receipt exceeds its canonical byte bound"
                                )
                            candidate_receipts.append(receipt_document)
                            peak_resident_memory_bytes = max(
                                peak_resident_memory_bytes,
                                receipt.candidate.peak_resident_memory_bytes,
                            )
                            peak_scratch_bytes = max(
                                peak_scratch_bytes,
                                receipt.candidate.peak_scratch_bytes,
                            )
                    except BaseException as error:
                        if launch is not None and not invocation_consumed:
                            with suppress(BaseException):
                                abandon_day1b_worker_invocation(launch.invocation_capability)
                        if isinstance(
                            error,
                            (Day1BWorkerProtocolError, TypeError, ValueError, OSError),
                        ):
                            raise PublicationDay1BHold(
                                "HOLD: candidate-cell worker evidence failed closed validation"
                            ) from error
                        raise

                    if candidate.role == "reference":
                        if len(candidate_records) != 2 or len(candidate_ledgers) != 2:
                            raise RuntimeError(
                                "reference candidate did not yield tuning plus held-out records"
                            )
                        tuning_records.append(candidate_records[0])
                        tuning_ledgers.append(candidate_ledgers[0])
                        heldout_records.append(candidate_records[1])
                        heldout_ledgers.append(candidate_ledgers[1])
                    else:
                        if (
                            candidate.candidate_id != ABLATION_CANDIDATE_ID
                            or len(candidate_records) != 1
                            or len(candidate_ledgers) != 1
                        ):
                            raise RuntimeError(
                                "ablation candidate did not yield one held-out record"
                            )
                        heldout_records.append(candidate_records[0])
                        heldout_ledgers.append(candidate_ledgers[0])

                if (
                    len(candidate_receipts) != len(FIXED_CANDIDATE_IDS)
                    or len(tuning_records) != len(REFERENCE_CANDIDATE_IDS)
                    or len(heldout_records) != len(FIXED_CANDIDATE_IDS)
                ):
                    raise RuntimeError("candidate-cell coverage did not close canonically")
                cell_records = [*tuning_records, *heldout_records]
                cell_ledgers = [*tuning_ledgers, *heldout_ledgers]
                cells.append(cell)
                records.extend(cell_records)
                ledgers.extend(cell_ledgers)
                candidate_cell_receipt_count += len(candidate_receipts)
                cell_execution_receipts.append(
                    {
                        "cell_binding_sha256": cell["cell_binding_sha256"],
                        "freshness_seconds": cell["freshness_seconds"],
                        "rho": cell["rho"],
                        "phase_receipts": list(audit.phase_receipts),
                        "candidate_cell_receipts": candidate_receipts,
                        "candidate_cell_receipt_count": len(candidate_receipts),
                        "physical_record_count": len(cell_records),
                        "candidate_retry_count": 0,
                        "peak_resident_memory_bytes": peak_resident_memory_bytes,
                        "peak_scratch_bytes": peak_scratch_bytes,
                    }
                )
        if (
            len(cells),
            candidate_cell_receipt_count,
            len(records),
            len(ledgers),
        ) != (18, 252, 486, 486):
            raise RuntimeError("Day1B unit cardinality did not close at 18/252/486/486")
        object_receipt_archive.seal()

        fragment = {
            "schema_version": fragment_schema,
            "experiment_source_git_sha": source_attestation.git_sha,
            "trace_units": [trace_unit],
            "cell_bindings": cells,
            "records": records,
        }
        manifest_base = {
            "schema_version": unit_schema,
            "artifact_policy": "derived-publication-evidence-no-raw-source-redistribution",
            "artifact_variant": dict(artifact_variant),
            "unit_identity": {
                "dataset_id": trace.dataset_id,
                "dataset_release": trace.dataset_release,
                "semantics": trace.semantics,
                "source_partition": trace.source_partition,
            },
            "experiment_source": {
                "git_sha": source_attestation.git_sha,
                "source_attestation": source_attestation.source_attestation,
                "behavior_inventory": dict(source_attestation.behavior_inventory),
            },
            "trace_source": {
                "trace_manifest_schema_version": PUBLICATION_TRACE_MANIFEST_SCHEMA,
                "git_sha": trace.trace_source_git_sha,
                "trace_behavior_source_blob_sha256": dict(trace.trace_behavior_source_blob_sha256),
                "trace_behavior_source_inventory_sha256": (
                    trace.trace_behavior_source_inventory_sha256
                ),
                "repository_provenance_sha256": trace.repository_provenance_sha256,
                "trace_manifest_sha256": trace.trace_manifest_sha256,
                "trace_central_behavior_inventory_present": False,
                "trace_source_authority_verified": False,
                "authority_state": "HOLD-no-central-TRACE-post-run-anchor",
            },
            "acquisition_binding": {
                "schema_version": ACQUISITION_TRACE_BINDING_SCHEMA,
                "acquisition_transaction_sha256": trace.acquisition_transaction_sha256,
                "source_set_sha256": trace.source_set_sha256,
                "source_bundle_sha256": trace.source_bundle_sha256,
                "acquisition_behavior_set_sha256": trace.acquisition_behavior_set_sha256,
                "acquisition_behavior_inventory_sha256": (
                    trace.acquisition_behavior_inventory_sha256
                ),
                "acquisition_authority_state": trace.acquisition_authority_state,
                "central_behavior_inventory_present": (
                    trace.acquisition_behavior_set_sha256 is not None
                    and trace.acquisition_behavior_inventory_sha256 is not None
                ),
                "acquisition_network_authority_verified": False,
            },
            "query_vector": {
                "schema_version": QUERY_VECTOR_SCHEMA,
                "sha256": trace.query_vector_sha256,
                "reuse_scope": "one-paired-unit-all-18-cells-and-all-physical-candidates",
            },
            "candidate_catalog": catalog_document,
            "serialized_object_size_authority": (
                _serialized_object_size_authority_document(size_authority)
            ),
            "resource_policy": resource_document,
            "invocation": {
                "entrypoint": "scripts/run_publication_day1b.py",
                "public_interface": (
                    "produce_publication_day1b_unit(trace_bundle_dir:Path,output_dir:Path)"
                ),
                "caller_options_allowed": False,
                "shard_scope": "exactly-one-paired-unit-18-cells",
                "selective_candidate_retry_allowed": False,
            },
            "cardinality": {
                "cell_binding_count": 18,
                "candidate_cell_receipt_count": 252,
                "physical_record_count": 486,
                "schedule_program_count": 9,
                "serialization_ledger_count": 486,
            },
            "cell_execution_receipts": cell_execution_receipts,
            "authority": {
                "state": "HOLD-pre-S1-no-central-TRACE-anchor-no-runtime-admission",
                "local_integrity_verified": False,
                "schedule_v2_verified": False,
                "serialized_protocol_object_bytes_verified": False,
                "derived_aliases_materialized": False,
                "day1b_behavior_source_verified": False,
                "trace_source_authority_verified": False,
                "acquisition_network_authority_verified": False,
                "runtime_execution_isolation_verified": False,
                "publication_claim_allowed": False,
            },
        }
        return _render_and_install_day1b_unit(
            output_dir=output_dir,
            repository_root=repository_root,
            fragment=fragment,
            ledgers=tuple(ledgers),
            object_receipt_archive=object_receipt_archive,
            programs=programs,
            manifest_base=manifest_base,
            resource_policy=resource_policy,
            artifact_variant_token=artifact_variant_token,
        )
    finally:
        object_receipt_archive.close()


def _produce_publication_day1b_unit_for_test(
    *,
    trace: _Day1BTraceInput,
    output_dir: Path,
    source_attestation: _Day1BPreparatorySourceAttestation,
    candidate_catalog: Day1CandidateCatalog,
    resource_policy: PublicationDay1BResourcePolicy,
    execution_adapter: _Day1BExecutionAdapter,
) -> PublicationDay1BUnitBundle:
    """Private typed small-fixture seam; its artifacts have no publication authority."""

    current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
    if not current_test.startswith("tests/test_publication_day1b.py::"):
        raise RuntimeError("the private Day1B fixture seam is unavailable to production callers")
    return _produce_publication_day1b_unit(
        trace=trace,
        output_dir=output_dir,
        source_attestation=source_attestation,
        candidate_catalog=candidate_catalog,
        resource_policy=resource_policy,
        size_authority=_Day1BSerializedObjectSizeAuthority(
            source_git_sha=source_attestation.git_sha,
            day2_experiment_source_git_sha="0" * 40,
            day2_outer_archive_sha256="0" * 64,
            serialized_object_size_profile_sha256="1" * 64,
            ciphertext_bytes=64,
            f1m_random_zero_sum_ciphertext_bytes=65,
            f1m_encrypted_zero_dummy_ciphertext_bytes=66,
            serialized_rotation_key_inventory_bytes=128,
            serialized_eval_mult_key_bytes=256,
        ),
        execution_adapter=execution_adapter,
        repository_root=Path(__file__).resolve().parents[2],
        artifact_variant_token=_TEST_ARTIFACT_VARIANT_TOKEN,
    )


def _read_day1b_behavior_member(
    repository_root: Path,
    *,
    relative_path: str,
    maximum_bytes: int,
    field: str,
    source_attestation: RoleSourceAttestation,
    behavior_inventory: Mapping[str, object],
) -> bytes:
    """Read one current DAY1B 100644 member through its exact Git binding."""

    if (
        not isinstance(repository_root, Path)
        or type(relative_path) is not str
        or not relative_path
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
        or type(field) is not str
        or not field
        or type(source_attestation) is not RoleSourceAttestation
        or not isinstance(behavior_inventory, Mapping)
    ):
        raise TypeError("Day1B behavior-member read requires exact typed inputs")
    if (
        source_attestation.role is not EvidenceRole.DAY1B
        or source_attestation.git_sha != behavior_inventory.get("source_git_sha")
    ):
        raise ValueError("Day1B behavior-member source binding is inconsistent")
    entries = behavior_inventory.get("entries")
    if type(entries) is not list:
        raise ValueError(f"{field} Behavior inventory is malformed")
    selected_entries = [
        entry for entry in entries if type(entry) is dict and entry.get("path") == relative_path
    ]
    if len(selected_entries) != 1 or selected_entries[0].get("mode") != "100644":
        raise ValueError(f"{field} must be one exact Git 100644 blob")
    expected_sha256 = source_attestation.behavior_source_blob_sha256.get(relative_path)
    if type(expected_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError(f"{field} Git digest is missing")

    member_path = repository_root / relative_path
    descriptor = os.open(
        member_path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise ValueError(f"{field} worktree member is not exact")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                raise OSError(f"{field} read ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError(f"{field} grew while being read")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_mode, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
        ):
            raise OSError(f"{field} changed while being read")
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise ValueError(f"{field} differs from its exact Git blob")
    return content


def _read_repository_day1b_pending_policy(
    repository_root: Path,
) -> _PendingDay1BResourcePolicy:
    """Read the one exact clean-Git pending placeholder."""

    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be a pathlib.Path")
    first_attestation = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
    inventory = capture_behavior_inventory(
        EvidenceRole.DAY1B,
        source_git_sha=first_attestation.git_sha,
        repository_root=repository_root,
    )
    content = _read_day1b_behavior_member(
        repository_root,
        relative_path=_DAY1B_PENDING_RESOURCE_POLICY_PATH,
        maximum_bytes=_DAY1B_PENDING_RESOURCE_POLICY_BYTES_MAXIMUM,
        field="pending Day1B resource policy",
        source_attestation=first_attestation,
        behavior_inventory=inventory,
    )
    pending = _decode_pending_day1b_resource_policy(content)
    if verify_current_role_source(EvidenceRole.DAY1B, repository_root) != first_attestation:
        raise ValueError("DAY1B source changed while reading the pending resource policy")
    return pending


def _read_repository_day1b_resource_amendment(
    repository_root: Path,
) -> _Day1BResourceAmendment:
    """Read and bind the reviewed resource-only amendment without authority."""

    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be a pathlib.Path")
    first_attestation = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
    inventory = capture_behavior_inventory(
        EvidenceRole.DAY1B,
        source_git_sha=first_attestation.git_sha,
        repository_root=repository_root,
    )
    amendment_content = _read_day1b_behavior_member(
        repository_root,
        relative_path=_DAY1B_RESOURCE_AMENDMENT_PATH,
        maximum_bytes=_DAY1B_RESOURCE_AMENDMENT_BYTES_MAXIMUM,
        field="Day1B resource amendment",
        source_attestation=first_attestation,
        behavior_inventory=inventory,
    )
    review_content = _read_day1b_behavior_member(
        repository_root,
        relative_path=_DAY1B_RESOURCE_AMENDMENT_REVIEW_PATH,
        maximum_bytes=_DAY1B_RESOURCE_AMENDMENT_REVIEW_BYTES_MAXIMUM,
        field="Day1B resource-amendment review receipt",
        source_attestation=first_attestation,
        behavior_inventory=inventory,
    )
    amendment = _decode_day1b_resource_amendment(amendment_content)
    if hashlib.sha256(review_content).hexdigest() != amendment.review_receipt_sha256:
        raise ValueError("Day1B resource amendment does not bind its exact review receipt")
    verify_day1b_resource_amendment_schema_source(
        source_git_sha=amendment.schema_source_git_sha,
        current_git_sha=first_attestation.git_sha,
        expected_inventory_sha256=amendment.schema_source_behavior_inventory_sha256,
        repository_root=repository_root,
    )
    if verify_current_role_source(EvidenceRole.DAY1B, repository_root) != first_attestation:
        raise ValueError("DAY1B source changed while reading the resource amendment")
    return amendment


def _require_repository_day1b_resource_policy(
    repository_root: Path,
) -> PublicationDay1BResourcePolicy:
    """Return the reviewed budget while retaining all independent HOLD gates."""

    try:
        _read_repository_day1b_pending_policy(repository_root)
    except (EvidenceCompatibilityError, OSError, TypeError, ValueError) as error:
        raise PublicationDay1BHold(
            f"HOLD: repository Day1B pending resource policy is invalid: {error}"
        ) from error
    try:
        amendment = _read_repository_day1b_resource_amendment(repository_root)
    except (EvidenceCompatibilityError, OSError, TypeError, ValueError) as error:
        raise PublicationDay1BHold(
            f"HOLD: repository Day1B resource amendment is invalid: {error}"
        ) from error
    return amendment.resource_policy


def _repository_day1b_resource_policy() -> PublicationDay1BResourcePolicy:
    return _require_repository_day1b_resource_policy(Path(__file__).resolve().parents[2])


def _repository_day1b_execution_adapter(
    size_authority: _Day1BSerializedObjectSizeAuthority,
) -> _Day1BExecutionAdapter:
    if type(size_authority) is not _Day1BSerializedObjectSizeAuthority:
        raise TypeError("Day1B execution adapter requires exact Day 2 size authority")
    raise PublicationDay1BHold(
        "HOLD: the full OpenFHE Day1B runner and repository-owned streaming execution "
        "adapter are not installed"
    )


def _repository_day1b_profile_anchor_authority() -> _Day1BSerializedObjectSizeAuthority:
    """Require the registered profile and anchored Day 2 sizes before held-out input."""

    repository_root = Path(__file__).resolve().parents[2]
    try:
        history = verify_repository_anchor_history(
            EvidenceRole.DAY1_REGISTRATION,
            repository_root,
        )
        source = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
    except EvidenceCompatibilityError as error:
        raise PublicationDay1BHold(
            f"HOLD: Day1B profile-anchor history is unavailable: {error}"
        ) from error
    if (
        history.analysis_source_git_sha != source.git_sha
        or history.day1a_authority_receipt_sha256 is None
        or history.day1a_evidence_anchor_git_sha is None
        or history.day2_profile_installation_git_sha is None
    ):
        raise PublicationDay1BHold(
            "HOLD: Day1B requires the history-verified Day1A anchor and Day2 profile "
            "installation at its exact clean source"
        )
    try:
        day2_authority = repository_day2_calibration_authority()
        after = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
    except (Day2CalibrationAuthorityError, EvidenceCompatibilityError) as error:
        raise PublicationDay1BHold(
            f"HOLD: Day1B anchored Day2 size authority is unavailable: {error}"
        ) from error
    if after != source:
        raise PublicationDay1BHold(
            "HOLD: Day1B source changed while admitting the Day 2 size profile"
        )
    return _Day1BSerializedObjectSizeAuthority(
        source_git_sha=source.git_sha,
        day2_experiment_source_git_sha=day2_authority.source_git_sha,
        day2_outer_archive_sha256=day2_authority.outer_archive_sha256,
        serialized_object_size_profile_sha256=(
            day2_authority.serialized_object_size_profile_sha256
        ),
        ciphertext_bytes=day2_authority.ciphertext_bytes,
        f1m_random_zero_sum_ciphertext_bytes=(day2_authority.f1m_random_zero_sum_ciphertext_bytes),
        f1m_encrypted_zero_dummy_ciphertext_bytes=(
            day2_authority.f1m_encrypted_zero_dummy_ciphertext_bytes
        ),
        serialized_rotation_key_inventory_bytes=(
            day2_authority.serialized_rotation_key_inventory_bytes
        ),
        serialized_eval_mult_key_bytes=day2_authority.serialized_eval_mult_key_bytes,
    )


def _repository_trace_anchor_authority() -> _Day1BF1MExecutionLineage:
    """Fail closed until the central TRACE post-run anchor is repository-installed."""

    raise PublicationDay1BHold(
        "HOLD: the central TRACE post-run anchor and compatibility authority are not installed"
    )


def _repository_program_adapter(
    program: AcceptedGroupProgram,
    *,
    projection_token: object,
) -> _PublicationScheduleAdapter:
    if projection_token is _PRODUCTION_TRACE_PROJECTION_TOKEN:
        stream_windows = stream_publication_windows
    elif projection_token is _TEST_TRACE_PROJECTION_TOKEN:
        stream_windows = _stream_publication_windows_for_test
    else:
        raise TypeError("trace projection does not carry the required capability")
    return _PublicationScheduleAdapter(
        schema_version=program.schema_version,
        rho=program.rho,
        phase_ranges=program.phase_ranges,
        accepted_group_count=program.accepted_group_count,
        total_set_count=program.total_set_count,
        total_query_count=program.total_query_count,
        canonical_schedule_sha256=program.canonical_schedule_sha256,
        iter_canonical_bytes=program.iter_canonical_bytes,
        stream_windows=lambda freshness: stream_windows(program, freshness),
    )


def _day1b_trace_input(
    validated: ValidatedPublicationTrace,
    *,
    projection_token: object,
) -> _Day1BTraceInput:
    """Project one schedule-validated descriptor snapshot into Day1B facts."""

    if type(validated) is not ValidatedPublicationTrace:
        raise TypeError("validated trace must be an exact schedule capability")
    replay_receipt = {
        "schema_version": DAY1B_REPLAY_RECEIPT_SCHEMA,
        "trace_manifest_sha256": validated.manifest_sha256,
        "trace_jsonl_sha256": validated.trace_jsonl_sha256,
        "repository_provenance_sha256": validated.repository_provenance_sha256,
        "accepted_group_count": validated.accepted_group_count,
        "transition_count": validated.transition_count,
        "replayed_by_closed_schedule_loader": True,
    }

    if projection_token is _PRODUCTION_TRACE_PROJECTION_TOKEN:
        compiler = compile_accepted_group_program
    elif projection_token is _TEST_TRACE_PROJECTION_TOKEN:
        compiler = _compile_accepted_group_program_for_test
    else:
        raise TypeError("trace projection does not carry the required capability")

    def compile_schedule(rho: Fraction) -> _PublicationScheduleAdapter:
        return _repository_program_adapter(
            compiler(validated, rho),
            projection_token=projection_token,
        )

    return _Day1BTraceInput(
        dataset_id=validated.dataset_id,
        dataset_release=validated.dataset_release,
        semantics=validated.semantics,
        source_partition=validated.source_partition,
        trace_source_git_sha=validated.trace_source_git_sha,
        trace_behavior_source_blob_sha256=validated.behavior_source_blob_sha256,
        trace_behavior_source_inventory_sha256=(validated.behavior_source_inventory_sha256),
        repository_provenance_sha256=validated.repository_provenance_sha256,
        trace_manifest_sha256=validated.manifest_sha256,
        mapping_sha256=validated.mapping_sha256,
        accepted_events_sha256=validated.accepted_raw_event_sha256,
        replay_receipt_sha256=_digest(replay_receipt),
        source_bundle_sha256=validated.acquisition_binding_sha256,
        acquisition_transaction_sha256=validated.acquisition_transaction_sha256,
        source_set_sha256=validated.source_set_sha256,
        acquisition_behavior_set_sha256=validated.acquisition_behavior_set_sha256,
        acquisition_behavior_inventory_sha256=(validated.acquisition_behavior_inventory_sha256),
        acquisition_authority_state=validated.acquisition_authority_state,
        acquisition_network_authority_verified=(validated.acquisition_network_authority_verified),
        accepted_group_count=validated.accepted_group_count,
        query_vector=validated.query_vector,
        query_vector_canonical_bytes=validated.query_vector_canonical_bytes,
        query_vector_sha256=validated.query_vector_sha256,
        compile_schedule=compile_schedule,
        trace_source_authority_verified=False,
    )


def _load_repository_trace_input(trace_bundle_dir: Path) -> _Day1BTraceInput:
    return _day1b_trace_input(
        load_publication_trace_bundle(trace_bundle_dir),
        projection_token=_PRODUCTION_TRACE_PROJECTION_TOKEN,
    )


def _load_repository_trace_input_for_test(trace_bundle_dir: Path) -> _Day1BTraceInput:
    """Private small-fixture trace inspection through the production descriptor seam."""

    current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
    if not current_test.startswith("tests/test_publication_day1b.py::"):
        raise RuntimeError("the private Day1B trace fixture seam is unavailable to callers")
    return _day1b_trace_input(
        _load_publication_trace_bundle_for_test(trace_bundle_dir),
        projection_token=_TEST_TRACE_PROJECTION_TOKEN,
    )


def produce_publication_day1b_unit(
    trace_bundle_dir: Path,
    output_dir: Path,
) -> PublicationDay1BUnitBundle:
    """Produce one exact Day1B unit, or fail before creating output.

    The caller cannot supply candidates, schedules, ratios, freshness, source claims,
    serialization facts, or resource options. All production dependencies are obtained from
    zero-argument repository seams before the trace is executed.
    """

    if not isinstance(trace_bundle_dir, Path) or not isinstance(output_dir, Path):
        raise TypeError("trace_bundle_dir and output_dir must be pathlib.Path values")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    repository_root = Path(__file__).resolve().parents[2]
    try:
        source_attestation = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
        behavior_inventory = capture_behavior_inventory(
            EvidenceRole.DAY1B,
            source_git_sha=source_attestation.git_sha,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise PublicationDay1BHold(
            f"HOLD: DAY1B preparatory source inventory/identity is unavailable: {error}"
        ) from error
    preparatory_source_attestation = _Day1BPreparatorySourceAttestation(
        git_sha=source_attestation.git_sha,
        behavior_inventory=behavior_inventory,
        source_attestation=source_attestation.attestation,
    )
    resource_policy = _repository_day1b_resource_policy()
    size_authority = _repository_day1b_profile_anchor_authority()
    if size_authority.source_git_sha != source_attestation.git_sha:
        raise PublicationDay1BHold("HOLD: Day1B source changed across profile-anchor admission")
    try:
        catalog = repository_day1_candidate_catalog()
    except Day1CandidateRegistrationError as error:
        raise PublicationDay1BHold(
            f"HOLD: complete Day1B candidate catalog unavailable: {error}"
        ) from error
    trace = _load_repository_trace_input(trace_bundle_dir)
    f1m_execution_lineage = _repository_trace_anchor_authority()
    execution_adapter = _repository_day1b_execution_adapter(size_authority)
    return _produce_publication_day1b_unit(
        trace=trace,
        output_dir=output_dir,
        source_attestation=preparatory_source_attestation,
        candidate_catalog=catalog,
        resource_policy=resource_policy,
        size_authority=size_authority,
        execution_adapter=execution_adapter,
        repository_root=repository_root,
        artifact_variant_token=_PRODUCTION_ARTIFACT_VARIANT_TOKEN,
        f1m_execution_lineage=f1m_execution_lineage,
    )


__all__ = (
    "DAY1B_RESOURCE_AMENDMENT_SCHEMA",
    "DAY1B_RESOURCE_POLICY_SCHEMA",
    "DAY1B_SERIALIZATION_LEDGER_SCHEMA",
    "DAY1B_UNIT_FRAGMENT_SCHEMA",
    "DAY1B_UNIT_SCHEMA",
    "SERIALIZED_PROTOCOL_OBJECT_CATEGORIES",
    "PublicationDay1BHold",
    "PublicationDay1BResourcePolicy",
    "PublicationDay1BUnitBundle",
    "produce_publication_day1b_unit",
)
