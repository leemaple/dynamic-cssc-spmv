from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from dynamic_cssc.cloud_execution_plan import canonical_cloud_program_payload
from dynamic_cssc.cssc import PublishedComponent
from dynamic_cssc.strong_execution import StrongExecutionBundle
from dynamic_cssc.strong_packed_coo import SegmentedDeltaState
from dynamic_cssc.strong_whole_query_witness import (
    COLS,
    EFFECTIVE_SLOTS,
    PLAINTEXT_MODULUS,
    ROWS,
    SEGMENT_WIDTH,
    build_strong_whole_query_fixture,
    canonical_whole_query_contract,
)

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "make_strong_whole_query_witness_binding.py"
WITNESS_SOURCE = ROOT / "cpp" / "strong_whole_query_witness.cpp"
VALIDATOR = ROOT / "scripts" / "validate_strong_whole_query_witness.py"
WORKFLOW = ROOT / ".github" / "workflows" / "strong-whole-query-witness.yml"
SCRIPT_ENV = {**os.environ, "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}"}
PROPERTY_SOURCES = (
    ROOT / "scripts" / "property_contract_spec.py",
    ROOT / "scripts" / "property_contract.py",
    ROOT / "scripts" / "validate_property_contract.py",
    ROOT / "tests" / "test_strong_property_contract.py",
    ROOT / "src" / "dynamic_cssc" / "strong_execution.py",
    ROOT / "src" / "dynamic_cssc" / "cloud_execution_plan.py",
    ROOT / "src" / "dynamic_cssc" / "cssc.py",
    ROOT / "src" / "dynamic_cssc" / "events.py",
    ROOT / "src" / "dynamic_cssc" / "mask_ledger.py",
    ROOT / "src" / "dynamic_cssc" / "output_plan.py",
    ROOT / "src" / "dynamic_cssc" / "plaintext_oracle.py",
    ROOT / "src" / "dynamic_cssc" / "strong_packed_coo.py",
)
PROPERTY_ARTIFACTS = (
    "case-records.json",
    "evidence.json",
    "junit.xml",
    "manifest.json",
)


def test_fixture_compiles_and_prepares_the_real_whole_query_bundle() -> None:
    fixture = build_strong_whole_query_fixture()

    assert isinstance(fixture.bundle, StrongExecutionBundle)
    assert isinstance(fixture.bundle.base, PublishedComponent)
    assert isinstance(fixture.bundle.delta, SegmentedDeltaState)
    assert fixture.bundle.base.layout_spec.rows == ROWS == 4096
    assert fixture.bundle.base.layout_spec.cols == COLS == 8193
    assert fixture.bundle.base.layout_spec.effective_slots == EFFECTIVE_SLOTS == 4096
    assert fixture.bundle.delta.segment_width == SEGMENT_WIDTH == 128
    assert fixture.modulus == PLAINTEXT_MODULUS == 65537

    base_width_three = next(
        spec
        for spec in fixture.bundle.value_operand_specs
        if spec.source_kind == "base-chunk" and spec.source_ordinal == 0
    )
    assert fixture.bundle.base.chunks[0].width == 3
    assert fixture.bundle.base.chunks[0].height == 1
    delta_page = next(
        spec for spec in fixture.bundle.value_operand_specs if spec.source_kind == "delta-page"
    )
    assert base_width_three.global_column_indices[:3] == (0, 1, 8192)
    assert delta_page.values[126] == 1
    assert delta_page.values[127] == 0
    assert fixture.query_values_by_ciphertext[base_width_three.query_ciphertext_id][:3] == (
        1,
        2,
        -3,
    )

    assert fixture.f1m_kinds == (
        "random-zero-sum",
        "encrypted-zero-dummy",
        "random-zero-sum",
    )
    assert fixture.bundle.cloud_counts.add_f1m_masks == 3
    assert fixture.bundle.cloud_counts.returned_ciphertexts == 3
    assert fixture.typed_plaintext_centered_output == fixture.direct_centered_output
    assert fixture.direct_centered_output[0] == 123
    assert fixture.direct_centered_output[4095] == 20
    assert sum(value != 0 for value in fixture.direct_centered_output) == 2


def test_binding_generator_emits_the_compiled_whole_query_contract(tmp_path: Path) -> None:
    output = tmp_path / "bindings.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--manifest",
            str(ROOT / "config" / "params_manifest.json"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert set(payload) == {"bindings", "fixture", "schema_version"}
    assert payload["schema_version"] == "strong-whole-query-witness-bindings-v2"
    assert set(payload["bindings"]) == {
        "cloud_program_digest",
        "execution_binding_digest",
        "expected_centered_output_digest",
        "output_plan_digest",
        "prepared_query_contract_digest",
        "private_plan_digest",
        "whole_query_contract_digest",
    }
    assert payload["fixture"] == {
        "active_delta_payload": 127,
        "base_active_coordinate_count": 4,
        "cols": 8193,
        "effective_slots": 4096,
        "kind": "actual-cssc-base-plus-strong-delta",
        "physical_batch_size": 8192,
        "rows": 4096,
        "segment_width": 128,
        "version_id": "strong-whole-query-witness-v2",
    }


def test_pinned_adapter_is_a_separate_real_whole_query_target() -> None:
    cmake = (ROOT / "cpp" / "CMakeLists.txt").read_text(encoding="utf-8")
    source = WITNESS_SOURCE.read_text(encoding="utf-8")

    assert "add_executable(strong_whole_query_witness strong_whole_query_witness.cpp)" in cmake
    assert "EvalMultNoRelin(valueCiphertext, queryCiphertext)" in source
    assert "Relinearize(product)" in source
    assert "EvalMult(valueCiphertext, queryCiphertext)" not in source
    assert "globalQuery.at(globalColumn)" in source
    assert "globalColumn % kEffectiveSlots" not in source
    assert "kRows = 4096" in source
    assert "kCols = 8193" in source
    assert "kBatchSize = 8192" in source
    assert "kEffectiveSlots = 4096" in source
    assert "kActiveDeltaPayload = 127" in source
    assert "kSegmentWidth = 128" in source
    assert "kCompleteReferenceSet = false" in source
    assert "kCandidateRegistered = false" in source


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _binding_payload(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    path = tmp_path / "bindings.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--manifest",
            str(ROOT / "config" / "params_manifest.json"),
            "--output",
            str(path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )
    assert completed.returncode == 0, completed.stderr
    return path, json.loads(path.read_text(encoding="utf-8"))


def _valid_witness(bindings: dict[str, str]) -> dict[str, object]:
    fixture = build_strong_whole_query_fixture()
    return {
        "adapter": {
            "physical_batch_size": 8192,
            "second_batching_row_zero": True,
            "typed_slot_count": 4096,
        },
        "bindings": bindings,
        "claims": {
            "candidate_registered": False,
            "complete_cost_claim_allowed": False,
            "complete_reference_set": False,
            "end_to_end_correctness_claim_allowed": False,
            "formal_correctness_claim": False,
            "formal_parameter_claim_allowed": False,
            "formal_performance_claim": False,
            "formal_security_claim": False,
            "gate_eligible": False,
            "mixed_workload_parameter_claim": False,
            "security_claim_allowed": False,
        },
        "correctness": {
            "active_offset_126_exercised": True,
            "decrypted_centered_output_sparse": [[0, 123], [4095, 20]],
            "decryptions_valid": True,
            "direct_spmv_centered_output_sparse": [[0, 123], [4095, 20]],
            "global_column_index_anti_alias": True,
            "matches_python_direct_spmv": True,
            "matches_python_typed_plaintext_oracle": True,
            "padding_offset_127_zero": True,
            "product_element_counts": [2, 2, 2],
            "products_relinearized": True,
            "unrelinearized_product_element_counts": [3, 3, 3],
        },
        "evidence_scope": ("actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe"),
        "execution_trace": canonical_cloud_program_payload(fixture.bundle.cloud_plan.program)[
            "nodes"
        ],
        "f1m": {
            "ciphertext_additions": 3,
            "dummy_exact_zero": True,
            "encrypted_zero_dummy_ciphertext_count": 1,
            "mask_values_redacted": True,
            "mode": "encrypted-correctness-test-operands",
            "persistent_ledger_exercised": False,
            "production_csprng_security_claim_allowed": False,
            "random_parts_nonzero": True,
            "random_zero_sum_ciphertext_count": 2,
            "return_ciphertext_count": 3,
            "zero_sum_mask": True,
        },
        "fixture": {
            "active_delta_payload": 127,
            "base_active_coordinate_count": 4,
            "cols": 8193,
            "global_column_index": 8192,
            "kind": "actual-cssc-base-plus-strong-delta",
            "padding_offset": 127,
            "return_count": 3,
            "rows": 4096,
            "segment_width": 128,
        },
        "openfhe": {
            "batch_size": 8192,
            "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
            "effective_first_row_slots": 4096,
            "eval_add_count": 0,
            "key_switch_count": 0,
            "multiplicative_depth": 2,
            "plaintext_modulus": 65537,
            "repository": "https://github.com/openfheorg/openfhe-development.git",
            "ring_dimension": 8192,
            "scheme": "BFVRNS",
            "version": "1.5.1",
        },
        "realized_contract": canonical_whole_query_contract(fixture),
        "schema_version": "strong-whole-query-witness-v2",
        "status": "pass",
    }


def _validate_payload(
    tmp_path: Path,
    witness: dict[str, object],
    *,
    provenance_mutation: tuple[str, str] | None = None,
    property_mutation: tuple[str, str] | None = None,
    extra_property_file: bool = False,
    duplicate_status_key: bool = False,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    witness_path = tmp_path / "witness.json"
    witness_text = json.dumps(witness)
    if duplicate_status_key:
        witness_text = witness_text[:-1] + ',"status":"pass"}'
    witness_path.write_text(witness_text, encoding="utf-8")
    bindings_path, _ = _binding_payload(tmp_path)
    binary = tmp_path / "strong_whole_query_witness"
    binary.write_bytes(b"test-only-binary")
    property_dir = tmp_path / "property-contract"
    property_dir.mkdir()
    for name in PROPERTY_ARTIFACTS:
        (property_dir / name).write_bytes(f"test-only-{name}\n".encode("ascii"))
    if extra_property_file:
        (property_dir / "unexpected.json").write_bytes(b"{}\n")
    manifest = ROOT / "config" / "params_manifest.json"
    provenance = {
        "binding_generator_sha256": _sha256(GENERATOR),
        "bindings_sha256": _sha256(bindings_path),
        "github_run_id": "123456",
        "manifest_sha256": _sha256(manifest),
        "openfhe_commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "schema_version": "strong-whole-query-witness-provenance-v2",
        "source_git_ref": "refs/heads/test",
        "source_git_sha": "1" * 40,
        "validator_sha256": _sha256(VALIDATOR),
        "witness_binary_sha256": _sha256(binary),
        "witness_sha256": _sha256(witness_path),
        "witness_source_sha256": _sha256(WITNESS_SOURCE),
        "property_contract": {
            "artifacts": {name: _sha256(property_dir / name) for name in PROPERTY_ARTIFACTS},
            "sources": {str(path.relative_to(ROOT)): _sha256(path) for path in PROPERTY_SOURCES},
        },
    }
    if provenance_mutation is not None:
        field, value = provenance_mutation
        provenance[field] = value
    if property_mutation is not None:
        section, field = property_mutation
        provenance["property_contract"][section][field] = "0" * 64
    provenance_path = tmp_path / "PROVENANCE.json"
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(witness_path),
            str(manifest),
            str(bindings_path),
            str(provenance_path),
            "--source-git-sha",
            "1" * 40,
            "--source-git-ref",
            "refs/heads/test",
            "--github-run-id",
            "123456",
            "--witness-source",
            str(WITNESS_SOURCE),
            "--witness-binary",
            str(binary),
            "--binding-generator",
            str(GENERATOR),
            "--validator-source",
            str(VALIDATOR),
            "--property-contract-dir",
            str(property_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )


def test_strict_validator_accepts_only_recomputed_whole_query_evidence(
    tmp_path: Path,
) -> None:
    _, binding_payload = _binding_payload(tmp_path)
    valid = _valid_witness(binding_payload["bindings"])  # type: ignore[arg-type]
    accepted = _validate_payload(tmp_path / "accepted", valid)
    assert accepted.returncode == 0, accepted.stderr

    tampered = json.loads(json.dumps(valid))
    tampered["realized_contract"]["private_plan"]["operands"][0]["global_column_indices"][2] = 0
    rejected = _validate_payload(tmp_path / "tampered", tampered)
    assert rejected.returncode != 0
    assert "realized_contract" in rejected.stderr


def test_validator_rejects_duplicate_json_and_provenance_retargeting(
    tmp_path: Path,
) -> None:
    _, binding_payload = _binding_payload(tmp_path)
    valid = _valid_witness(binding_payload["bindings"])  # type: ignore[arg-type]

    duplicate = _validate_payload(
        tmp_path / "duplicate",
        valid,
        duplicate_status_key=True,
    )
    assert duplicate.returncode != 0
    assert "duplicate JSON key" in duplicate.stderr

    for field in (
        "binding_generator_sha256",
        "bindings_sha256",
        "manifest_sha256",
        "validator_sha256",
        "witness_binary_sha256",
        "witness_sha256",
        "witness_source_sha256",
    ):
        retargeted = _validate_payload(
            tmp_path / field,
            valid,
            provenance_mutation=(field, "0" * 64),
        )
        assert retargeted.returncode != 0
        assert f"provenance.{field}" in retargeted.stderr

    for section, field in (
        ("artifacts", "evidence.json"),
        ("sources", "scripts/property_contract.py"),
    ):
        retargeted_property = _validate_payload(
            tmp_path / f"property-{section}",
            valid,
            property_mutation=(section, field),
        )
        assert retargeted_property.returncode != 0
        assert f"provenance.property_contract.{section}.{field}" in (retargeted_property.stderr)

    extra_property = _validate_payload(
        tmp_path / "property-extra",
        valid,
        extra_property_file=True,
    )
    assert extra_property.returncode != 0
    assert "exactly the four validated artifacts" in extra_property.stderr


def test_workflow_is_manual_pinned_fail_closed_and_evidence_preserving() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    trigger = workflow.split("permissions:", 1)[0]

    assert "workflow_dispatch:" in trigger
    for forbidden in ("schedule:", "push:", "pull_request:", "workflow_run:"):
        assert forbidden not in trigger
    assert "permissions:\n  contents: read" in workflow
    assert "scripts/bootstrap_openfhe.sh" in workflow
    assert "scripts/build_cpp.sh" in workflow
    assert "scripts/property_contract.py" in workflow
    assert "scripts/validate_property_contract.py" in workflow
    assert '--source-git-sha "$GITHUB_SHA" --seed 20260822' in workflow
    assert '--expected-source-git-sha "$GITHUB_SHA"' in workflow
    assert workflow.index("scripts/validate_property_contract.py") < workflow.index(
        "scripts/bootstrap_openfhe.sh"
    )
    assert "PROPERTY_OUTCOME" in workflow
    assert "property_contract_outcome" in workflow
    for property_source in (
        "scripts/property_contract_spec.py",
        "scripts/property_contract.py",
        "scripts/validate_property_contract.py",
        "tests/test_strong_property_contract.py",
        "src/dynamic_cssc/strong_execution.py",
        "src/dynamic_cssc/cloud_execution_plan.py",
        "src/dynamic_cssc/cssc.py",
        "src/dynamic_cssc/events.py",
        "src/dynamic_cssc/mask_ledger.py",
        "src/dynamic_cssc/output_plan.py",
        "src/dynamic_cssc/plaintext_oracle.py",
        "src/dynamic_cssc/strong_packed_coo.py",
    ):
        assert property_source in workflow
    for property_artifact in (
        "property-contract/evidence.json",
        "property-contract/manifest.json",
        "property-contract/case-records.json",
        "property-contract/junit.xml",
    ):
        assert property_artifact in workflow
    assert "scripts/make_strong_whole_query_witness_binding.py" in workflow
    assert "scripts/validate_strong_whole_query_witness.py" in workflow
    assert "build/cpp/strong_whole_query_witness" in workflow
    assert 'SOURCE_GIT_SHA="$(git rev-parse HEAD)"' in workflow
    assert '"$SOURCE_GIT_SHA" != "$GITHUB_SHA"' in workflow
    assert "OpenFHEConfigVersion.cmake" in workflow
    assert "witness_source_sha256" in workflow
    assert "witness_binary_sha256" in workflow
    assert "binding_generator_sha256" in workflow
    assert "validator_sha256" in workflow
    assert "manifest_sha256" in workflow
    assert "bindings_sha256" in workflow
    assert "witness_sha256" in workflow
    assert "RUN_STATUS.json" in workflow
    assert "strong-whole-query-witness-run-status-v2" in workflow
    assert "SHA256SUMS" in workflow
    assert "DIAGNOSTIC_SHA256SUMS" in workflow
    assert "if: always()" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "day1" not in workflow.lower()
    assert "day2" not in workflow.lower()
    assert "benchmark" not in workflow.lower()
