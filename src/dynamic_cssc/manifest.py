from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MASK_BINDING = [
    "query_id",
    "version_id",
    "output_plan_digest",
    "component_id",
    "output_block_id",
]

LEAKAGE_ACL = {
    "allowed_to_client_a": [
        "matrix-and-updates",
        "cssc-metadata",
        "component-rowmaps-and-output-plan",
        "public-parameters",
        "query-version-and-output-plan-identifiers",
        "output-plan-digest",
    ],
    "allowed_to_client_b": [
        "query-vector-and-secret-key",
        "public-parameters",
        "component-column-index-metadata",
        "component-rowmaps-and-output-plan",
        "blinded-component-outputs",
        "final-logical-result",
        "output-plan-digest",
    ],
    "allowed_to_cloud": [
        "public-parameters",
        "ciphertext-shapes-and-counts",
        "component-and-output-block-identifiers",
        "operation-schedule",
        "query-and-version-identifiers",
        "output-plan-digest",
    ],
    "forbidden_to_cloud": [
        "matrix-and-update-values",
        "query-vector",
        "secret-key",
        "component-rowmaps-and-output-plan",
        "component-column-index-metadata",
        "mask-plaintexts",
        "unblinded-component-outputs",
    ],
}


class ManifestError(ValueError):
    """Raised when the frozen protocol manifest is internally inconsistent."""


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {manifest_path}: {exc}") from exc
    validate_manifest(data)
    return data


def _closed_object(value: object, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{context} must be an object")
    missing = sorted(fields - value.keys())
    if missing:
        raise ManifestError(f"missing {context} fields: {', '.join(missing)}")
    unexpected = sorted(value.keys() - fields)
    if unexpected:
        raise ManifestError(f"unexpected fields in {context}: {', '.join(unexpected)}")
    return value


def _strict_int(value: object, context: str, *, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ManifestError(f"{context} must be an integer")
    if minimum is not None and value < minimum:
        raise ManifestError(f"{context} must be an integer of at least {minimum}")
    return value


def _strict_number(value: object, context: str, *, positive: bool = False) -> int | float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ManifestError(f"{context} must be a number")
    if positive and value <= 0:
        raise ManifestError(f"{context} must be a positive number")
    return value


def _strict_bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise ManifestError(f"{context} must be a boolean")
    return value


def _strict_string(value: object, context: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        qualifier = "a non-empty string" if nonempty else "a string"
        raise ManifestError(f"{context} must be {qualifier}")
    return value


def _strict_string_list(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestError(f"{context} must be an array of strings")
    return value


def _require_equal(actual: object, expected: object, message: str) -> None:
    if actual != expected:
        raise ManifestError(message)


def validate_manifest(data: dict[str, Any]) -> None:
    top_fields = {
        "manifest_version",
        "protocol_version",
        "project",
        "frozen_at",
        "functional_mode",
        "threat_model",
        "leakage",
        "roles",
        "randomness",
        "blinding",
        "integer_correctness",
        "matrix",
        "packing",
        "openfhe",
        "runtime",
        "freshness",
        "synthetic_preflight",
        "provenance",
    }
    data = _closed_object(data, top_fields, "top-level manifest")

    _require_equal(
        _strict_string(data["manifest_version"], "manifest_version"),
        "0.2.0",
        "manifest_version must be 0.2.0 for the protocol 2.1b schema",
    )
    _require_equal(
        _strict_string(data["protocol_version"], "protocol_version"),
        "2.1b",
        "protocol_version must be 2.1b",
    )
    _require_equal(
        _strict_string(data["project"], "project"),
        "dynamic-cssc-spmv",
        "project must be dynamic-cssc-spmv",
    )
    frozen_at = _strict_string(data["frozen_at"], "frozen_at")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", frozen_at) is None:
        raise ManifestError("frozen_at must be a UTC second-resolution timestamp")
    _require_equal(
        _strict_string(data["functional_mode"], "functional_mode"),
        "F1-M-hidden-rowmap",
        "protocol 2.1b freezes F1-M-hidden-rowmap",
    )

    threat = _closed_object(
        data["threat_model"],
        {
            "adversary_model",
            "parties",
            "corruption_scope",
            "cloud_non_collusion_with_clients",
            "malicious_security_claimed",
        },
        "threat_model",
    )
    _require_equal(threat["adversary_model"], "semi-honest", "threat model must be semi-honest")
    parties = _strict_string_list(threat["parties"], "threat_model.parties")
    _require_equal(parties, ["Client A", "Client B", "Cloud"], "threat-model parties changed")
    _require_equal(
        threat["corruption_scope"],
        "at-most-one-party",
        "threat model requires an at-most-one-party corruption scope",
    )
    if not _strict_bool(
        threat["cloud_non_collusion_with_clients"],
        "threat_model.cloud_non_collusion_with_clients",
    ):
        raise ManifestError("the protocol requires Cloud/client non-collusion")
    if _strict_bool(
        threat["malicious_security_claimed"], "threat_model.malicious_security_claimed"
    ):
        raise ManifestError("malicious security is not claimed")

    leakage = _closed_object(
        data["leakage"],
        {
            "policy_id",
            "allowed_to_client_a",
            "allowed_to_client_b",
            "allowed_to_cloud",
            "forbidden_to_cloud",
            "cross_mode_result_pooling_allowed",
        },
        "leakage",
    )
    _require_equal(
        leakage["policy_id"],
        "F1-M-hidden-rowmap",
        "leakage policy must match F1-M-hidden-rowmap",
    )
    for field, expected in LEAKAGE_ACL.items():
        observed = _strict_string_list(leakage[field], f"leakage.{field}")
        _require_equal(observed, expected, f"leakage ACL changed at {field}")
    if _strict_bool(
        leakage["cross_mode_result_pooling_allowed"],
        "leakage.cross_mode_result_pooling_allowed",
    ):
        raise ManifestError("leakage modes must not be pooled in one result set")

    roles = _closed_object(
        data["roles"],
        {
            "matrix_owner",
            "query_owner_and_secret_key_holder",
            "result_recipient",
            "cloud",
            "mask_generator",
        },
        "roles",
    )
    expected_roles = {
        "matrix_owner": "Client A",
        "query_owner_and_secret_key_holder": "Client B",
        "result_recipient": "Client B",
        "cloud": "semi-honest non-colluding evaluator",
        "mask_generator": "Client A",
    }
    for field, expected in expected_roles.items():
        observed = _strict_string(roles[field], f"roles.{field}")
        if observed != expected:
            if field == "mask_generator":
                raise ManifestError(
                    "hidden-rowmap F1-M requires the matrix owner to generate masks"
                )
            raise ManifestError(f"roles.{field} must be {expected}")

    randomness = _closed_object(
        data["randomness"], {"cryptographic", "experimental"}, "randomness"
    )
    cryptographic = _closed_object(
        randomness["cryptographic"],
        {"source", "modular_sampling", "deterministic_seed_allowed"},
        "randomness.cryptographic",
    )
    _require_equal(
        cryptographic["source"],
        "operating-system-csprng",
        "cryptographic masks require the operating-system CSPRNG",
    )
    _require_equal(
        cryptographic["modular_sampling"],
        "unbiased-rejection-sampling",
        "uniform Z_t masks require unbiased rejection sampling",
    )
    if _strict_bool(
        cryptographic["deterministic_seed_allowed"],
        "randomness.cryptographic.deterministic_seed_allowed",
    ):
        raise ManifestError("a deterministic seed is forbidden for cryptographic randomness")
    experimental = _closed_object(
        randomness["experimental"],
        {"seed", "scope", "cryptographic_use_allowed"},
        "randomness.experimental",
    )
    _strict_int(experimental["seed"], "randomness.experimental.seed", minimum=0)
    _require_equal(
        experimental["scope"],
        "synthetic-workload-generation-and-policy-replay-only",
        "experimental seed scope must exclude cryptographic operations",
    )
    if _strict_bool(
        experimental["cryptographic_use_allowed"],
        "randomness.experimental.cryptographic_use_allowed",
    ):
        raise ManifestError("the experimental seed cannot seed cryptographic masks")

    blinding = _closed_object(
        data["blinding"],
        {
            "enabled",
            "mode",
            "rowmap_visibility_to_cloud",
            "mask_reuse_allowed",
            "mask_scope",
            "disjoint_output_rule",
            "output_plan_format",
            "output_plan_digest_algorithm",
            "mask_binding",
            "binding_ledger",
        },
        "blinding",
    )
    if not _strict_bool(blinding["enabled"], "blinding.enabled"):
        raise ManifestError("F1-M requires blinding")
    _require_equal(
        blinding["mode"],
        "encrypted-one-time-zero-sum",
        "hidden-rowmap F1-M requires encrypted one-time zero-sum masks",
    )
    if _strict_bool(
        blinding["rowmap_visibility_to_cloud"], "blinding.rowmap_visibility_to_cloud"
    ):
        raise ManifestError("hidden-rowmap mode cannot reveal RowMap to the cloud")
    if _strict_bool(blinding["mask_reuse_allowed"], "blinding.mask_reuse_allowed"):
        raise ManifestError("zero-sum masks must never be reused")
    _require_equal(
        blinding["mask_scope"],
        "logical-coordinate-overlap-only",
        "mask scope must be logical-coordinate overlap only",
    )
    _require_equal(
        blinding["disjoint_output_rule"],
        "concatenate-unmasked",
        "disjoint output blocks must concatenate unmasked",
    )
    _require_equal(
        blinding["output_plan_format"],
        "dynamic-cssc-output-plan-v1",
        "output-plan format must be dynamic-cssc-output-plan-v1",
    )
    _require_equal(
        blinding["output_plan_digest_algorithm"],
        "sha256-canonical-json-v1",
        "output-plan digest must use sha256-canonical-json-v1",
    )
    binding = _strict_string_list(blinding["mask_binding"], "blinding.mask_binding")
    _require_equal(binding, MASK_BINDING, "mask binding must use the frozen five-field tuple")
    ledger = _closed_object(
        blinding["binding_ledger"],
        {
            "owner",
            "scope",
            "persistent",
            "reservation_semantics",
            "duplicate_binding_action",
            "crash_semantics",
        },
        "blinding.binding_ledger",
    )
    expected_ledger = {
        "owner": "Client A",
        "scope": "per-query-binding",
        "reservation_semantics": "atomic-check-and-reserve-before-mask-generation",
        "duplicate_binding_action": "reject",
        "crash_semantics": "reserved-binding-remains-consumed",
    }
    for field, expected in expected_ledger.items():
        _require_equal(ledger[field], expected, f"binding ledger requires {field}={expected}")
    if not _strict_bool(ledger["persistent"], "blinding.binding_ledger.persistent"):
        raise ManifestError("binding ledger must be persistent")

    matrix = _closed_object(
        data["matrix"],
        {
            "rows",
            "cols",
            "max_nnz_per_row",
            "max_nnz_per_row_scope",
            "dimension_mode",
            "vertex_universe_rule",
        },
        "matrix",
    )
    rows = _strict_int(matrix["rows"], "matrix.rows", minimum=1)
    cols = _strict_int(matrix["cols"], "matrix.cols", minimum=1)
    max_nnz_per_row = _strict_int(
        matrix["max_nnz_per_row"], "matrix.max_nnz_per_row", minimum=1
    )
    _require_equal(
        matrix["max_nnz_per_row_scope"],
        "all-published-versions",
        "max_nnz_per_row must hold for all published matrix versions",
    )
    _require_equal(matrix["dimension_mode"], "fixed", "the paper freezes matrix dimensions")
    _require_equal(
        matrix["vertex_universe_rule"],
        "predeclare-full-range",
        "matrix vertex universe must be predeclared",
    )

    packing = _closed_object(
        data["packing"],
        {"mode", "total_slots", "row_slots", "effective_slots", "query_reorganization"},
        "packing",
    )
    total_slots = _strict_int(packing["total_slots"], "packing.total_slots", minimum=1)
    row_slots = _strict_int(packing["row_slots"], "packing.row_slots", minimum=1)
    effective_slots = _strict_int(
        packing["effective_slots"], "packing.effective_slots", minimum=1
    )
    _require_equal(packing["mode"], "single-batching-row", "packing mode must be single-row")
    if effective_slots > total_slots:
        raise ManifestError("packing.effective_slots must not exceed total_slots")
    if effective_slots > row_slots:
        raise ManifestError("single-row mode cannot use more than packing.row_slots")
    if row_slots * 2 != total_slots:
        raise ManifestError("protocol 2.1b assumes two equal BFV batching rows")
    if cols <= effective_slots:
        raise ManifestError(
            "matrix.cols must exceed effective slots to exercise global ColumnIndex addressing"
        )
    query_reorganization = _closed_object(
        packing["query_reorganization"],
        {
            "mode",
            "addressing",
            "column_index_sender",
            "column_index_recipient",
            "column_index_visibility_to_cloud",
            "version_synchronized",
            "communication_accounting_required",
        },
        "packing.query_reorganization",
    )
    expected_reorganization = {
        "mode": "versioned-column-index-per-cssc-chunk",
        "addressing": "global-column-index",
        "column_index_sender": "Client A",
        "column_index_recipient": "Client B",
    }
    for field, expected in expected_reorganization.items():
        _require_equal(
            query_reorganization[field],
            expected,
            f"query reorganization requires {field}={expected}",
        )
    if _strict_bool(
        query_reorganization["column_index_visibility_to_cloud"],
        "packing.query_reorganization.column_index_visibility_to_cloud",
    ):
        raise ManifestError("component ColumnIndex metadata must remain hidden from the Cloud")
    if not _strict_bool(
        query_reorganization["version_synchronized"],
        "packing.query_reorganization.version_synchronized",
    ):
        raise ManifestError("query reorganization ColumnIndex must be synchronized by version")
    if not _strict_bool(
        query_reorganization["communication_accounting_required"],
        "packing.query_reorganization.communication_accounting_required",
    ):
        raise ManifestError("ColumnIndex delivery requires communication accounting")
    if (rows, cols, total_slots, row_slots, effective_slots) != (4096, 8193, 8192, 4096, 4096):
        raise ManifestError("protocol 2.1b matrix and packing dimensions are frozen")

    integer = _closed_object(
        data["integer_correctness"],
        {
            "domain",
            "max_terms_per_output",
            "matrix_entry_abs_bound",
            "query_entry_abs_bound",
            "centered_result_abs_bound",
            "twice_centered_result_abs_bound",
            "plaintext_safety_condition",
            "centered_lift_stage",
        },
        "integer_correctness",
    )
    _require_equal(
        integer["domain"],
        "signed-integers-via-centered-lift",
        "integer correctness domain must use centered lifting",
    )
    max_terms = _strict_int(
        integer["max_terms_per_output"], "integer_correctness.max_terms_per_output", minimum=1
    )
    matrix_bound = _strict_int(
        integer["matrix_entry_abs_bound"],
        "integer_correctness.matrix_entry_abs_bound",
        minimum=0,
    )
    query_bound = _strict_int(
        integer["query_entry_abs_bound"],
        "integer_correctness.query_entry_abs_bound",
        minimum=0,
    )
    result_bound = _strict_int(
        integer["centered_result_abs_bound"],
        "integer_correctness.centered_result_abs_bound",
        minimum=0,
    )
    twice_bound = _strict_int(
        integer["twice_centered_result_abs_bound"],
        "integer_correctness.twice_centered_result_abs_bound",
        minimum=0,
    )
    if max_terms != 4096 or matrix_bound != 7 or query_bound != 1:
        raise ManifestError("integer input and term bounds are frozen at 4096*7*1")
    if max_nnz_per_row != max_terms:
        raise ManifestError(
            "integer bound requires matrix.max_nnz_per_row=max_terms_per_output=4096"
        )
    computed_bound = max_terms * matrix_bound * query_bound
    if result_bound != computed_bound:
        raise ManifestError("centered result bound must equal 4096*7*1=28672")
    if twice_bound != 2 * result_bound:
        raise ManifestError("twice centered result bound must equal 2B=57344")
    if max_terms > cols:
        raise ManifestError("max_terms_per_output cannot exceed matrix.cols")
    _require_equal(
        integer["plaintext_safety_condition"],
        "2B<t",
        "integer correctness must require 2B<t",
    )
    _require_equal(
        integer["centered_lift_stage"],
        "after-final-component-sum",
        "centered lifting is valid only after the final component sum",
    )

    openfhe_fields = {
        "repository",
        "version",
        "commit",
        "scheme",
        "ring_dimension",
        "plaintext_modulus",
        "batch_size",
        "security_level",
        "key_switch_technique",
        "bfv_multiplication_technique",
        "mixed_workload_parameterization",
        "noise_budget_profiles",
    }
    if isinstance(data["openfhe"], dict):
        legacy_noise_fields = {"multiplicative_depth", "eval_add_count", "key_switch_count"}
        if legacy_noise_fields & data["openfhe"].keys():
            raise ManifestError("legacy combined OpenFHE noise-budget fields are forbidden")
    openfhe = _closed_object(data["openfhe"], openfhe_fields, "openfhe")
    expected_openfhe_strings = {
        "repository": "https://github.com/openfheorg/openfhe-development.git",
        "version": "1.5.1",
        "scheme": "BFVRNS",
        "security_level": "HEStd_128_classic",
        "key_switch_technique": "HYBRID",
        "bfv_multiplication_technique": "HPSPOVERQLEVELED",
    }
    for field, expected in expected_openfhe_strings.items():
        observed = _strict_string(openfhe[field], f"openfhe.{field}")
        _require_equal(observed, expected, f"openfhe.{field} must be {expected}")
    commit = _strict_string(openfhe["commit"], "openfhe.commit")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ManifestError("openfhe.commit must be a full 40-character lowercase SHA")
    ring_dimension = _strict_int(openfhe["ring_dimension"], "openfhe.ring_dimension", minimum=1024)
    plaintext_modulus = _strict_int(
        openfhe["plaintext_modulus"], "openfhe.plaintext_modulus", minimum=3
    )
    batch_size = _strict_int(openfhe["batch_size"], "openfhe.batch_size", minimum=1)
    if total_slots != batch_size:
        raise ManifestError("packing.total_slots and openfhe.batch_size must agree")
    if batch_size > ring_dimension:
        raise ManifestError("BFV batch size must not exceed the frozen ring dimension")
    if plaintext_modulus <= total_slots:
        raise ManifestError("plaintext_modulus must exceed total_slots for the P0a labels")
    if (plaintext_modulus - 1) % (2 * ring_dimension) != 0:
        raise ManifestError("plaintext_modulus must be 1 mod 2N for the frozen CRT batching setup")
    if (ring_dimension, plaintext_modulus, batch_size) != (8192, 65537, 8192):
        raise ManifestError("protocol 2.1b OpenFHE dimensions are frozen")
    if twice_bound >= plaintext_modulus:
        raise ManifestError("integer correctness requires the strict inequality 2B<t")

    profiles = _closed_object(
        openfhe["noise_budget_profiles"],
        {"p0a_rotation", "day2_add_only", "day2_mult_only"},
        "openfhe.noise_budget_profiles",
    )
    expected_profiles = {
        "p0a_rotation": ("key-switch-only", "p0a-layout-semantics-only"),
        "day2_add_only": ("add-only", "isolated-unit-probe-only"),
        "day2_mult_only": ("multiplication-only", "isolated-unit-probe-only"),
    }
    estimator_fields = ("multiplicative_depth", "eval_add_count", "key_switch_count")
    profile_fields = {"operation_class", "evidence_scope", *estimator_fields}
    for profile_name, (operation_class, evidence_scope) in expected_profiles.items():
        profile = _closed_object(
            profiles[profile_name], profile_fields, f"openfhe.noise_budget_profiles.{profile_name}"
        )
        counts = [
            _strict_int(
                profile[field],
                f"openfhe.noise_budget_profiles.{profile_name}.{field}",
                minimum=0,
            )
            for field in estimator_fields
        ]
        if sum(count > 0 for count in counts) != 1:
            raise ManifestError(
                f"openfhe.{profile_name} must set exactly one noise estimator to a positive value"
            )
        if profile["operation_class"] != operation_class:
            raise ManifestError(
                f"openfhe.{profile_name} must use operation_class={operation_class}"
            )
        if profile["evidence_scope"] != evidence_scope:
            raise ManifestError(f"openfhe.{profile_name} must use evidence_scope={evidence_scope}")
    p0a_profile = profiles["p0a_rotation"]
    if p0a_profile["multiplicative_depth"] != 0 or p0a_profile["eval_add_count"] != 0:
        raise ManifestError("openfhe.p0a_rotation must be key-switch-only")
    add_profile = profiles["day2_add_only"]
    if add_profile["multiplicative_depth"] != 0 or add_profile["key_switch_count"] != 0:
        raise ManifestError("openfhe.day2_add_only must be add-only")
    mult_profile = profiles["day2_mult_only"]
    if mult_profile["eval_add_count"] != 0 or mult_profile["key_switch_count"] != 0:
        raise ManifestError("openfhe.day2_mult_only must be multiplication-only")

    mixed = _closed_object(
        openfhe["mixed_workload_parameterization"],
        {"status", "formal_parameter_claim_allowed", "required_gate"},
        "openfhe.mixed_workload_parameterization",
    )
    _require_equal(mixed["status"], "unfrozen", "mixed-workload status must remain unfrozen")
    if _strict_bool(
        mixed["formal_parameter_claim_allowed"],
        "openfhe.mixed_workload_parameterization.formal_parameter_claim_allowed",
    ):
        raise ManifestError("mixed-workload OpenFHE parameterization is not frozen")
    _require_equal(
        mixed["required_gate"],
        "mixed-circuit-decryption-correctness",
        "mixed-workload parameterization requires a decryption correctness gate",
    )

    runtime = _closed_object(
        data["runtime"],
        {"omp_threads", "cpu_affinity", "warmup_repetitions", "measurement_repetitions"},
        "runtime",
    )
    _strict_int(runtime["omp_threads"], "runtime.omp_threads", minimum=1)
    _strict_string(runtime["cpu_affinity"], "runtime.cpu_affinity")
    _strict_int(runtime["warmup_repetitions"], "runtime.warmup_repetitions", minimum=0)
    _strict_int(runtime["measurement_repetitions"], "runtime.measurement_repetitions", minimum=1)

    freshness = _closed_object(
        data["freshness"],
        {"max_seconds", "microbatch_max_updates", "query_requires_latest"},
        "freshness",
    )
    _strict_number(freshness["max_seconds"], "freshness.max_seconds", positive=True)
    _strict_int(
        freshness["microbatch_max_updates"], "freshness.microbatch_max_updates", minimum=1
    )
    if not _strict_bool(freshness["query_requires_latest"], "freshness.query_requires_latest"):
        raise ManifestError("every query must use the latest published state")

    preflight = _closed_object(
        data["synthetic_preflight"],
        {"required_before_day1", "rows", "cols", "effective_slots", "purpose"},
        "synthetic_preflight",
    )
    if not _strict_bool(
        preflight["required_before_day1"], "synthetic_preflight.required_before_day1"
    ):
        raise ManifestError("synthetic preflight is required before Day 1")
    preflight_dimensions = (
        _strict_int(preflight["rows"], "synthetic_preflight.rows", minimum=1),
        _strict_int(preflight["cols"], "synthetic_preflight.cols", minimum=1),
        _strict_int(
            preflight["effective_slots"], "synthetic_preflight.effective_slots", minimum=1
        ),
    )
    if preflight_dimensions != (257, 521, 256):
        raise ManifestError("synthetic preflight dimensions must be 257x521 with 256 slots")
    if not (
        preflight_dimensions[0] > preflight_dimensions[2]
        and preflight_dimensions[1] > preflight_dimensions[2]
    ):
        raise ManifestError(
            "synthetic preflight must exercise multi-output and global ColumnIndex addressing"
        )
    _require_equal(
        preflight["purpose"],
        "exercise-multi-output-and-global-column-index-beyond-slot-range",
        "synthetic preflight purpose is frozen",
    )

    provenance = _closed_object(
        data["provenance"],
        {"predicted_and_measured_must_be_separate", "held_out_required"},
        "provenance",
    )
    if not _strict_bool(
        provenance["predicted_and_measured_must_be_separate"],
        "provenance.predicted_and_measured_must_be_separate",
    ):
        raise ManifestError("predicted and measured data must be separated")
    if not _strict_bool(provenance["held_out_required"], "provenance.held_out_required"):
        raise ManifestError("held-out evaluation is mandatory")
