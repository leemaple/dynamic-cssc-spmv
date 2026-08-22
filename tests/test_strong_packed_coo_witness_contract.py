from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_strong_packed_coo_witness.py"
GENERATOR = ROOT / "scripts" / "make_strong_packed_coo_witness_binding.py"
SCRIPT_ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


def test_execution_trace_short_initializers_compile_without_warnings(tmp_path: Path) -> None:
    compiler = shutil.which("c++")
    if compiler is None:
        pytest.skip("c++ compiler is unavailable")

    source = (ROOT / "cpp" / "strong_packed_coo_witness.cpp").read_text(encoding="utf-8")
    definition_start = source.index("struct ExecutionTraceNode {")
    definition_end = source.index("\n};", definition_start) + len("\n};")
    definition = source[definition_start:definition_end]

    translation_unit = tmp_path / "execution_trace_initializers.cpp"
    translation_unit.write_text(
        f"""
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

{definition}

int main() {{
    std::vector<ExecutionTraceNode> execution_trace;
    execution_trace.push_back({{"multiply-ciphertexts", "product", "", "values", "query"}});
    execution_trace.push_back({{"relinearize", "relinearized", "product"}});
    execution_trace.push_back(
        {{"rotate", "rotated", "reduced", "", "", "", "", "", 1, 1}});
    execution_trace.push_back(
        {{"add-f1m-mask", "masked", "selected", "", "", "", "f1m-mask", "opaque-zero-sum"}});
    execution_trace.push_back({{"return-result", "result", "masked"}});
    return execution_trace.empty();
}}
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-Wmissing-field-initializers",
            "-fsyntax-only",
            str(translation_unit),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def _make_bindings(tmp_path: Path) -> dict[str, str]:
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
    return json.loads(output.read_text(encoding="utf-8"))


def _expected_execution_trace() -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json
from dynamic_cssc.cloud_execution_plan import canonical_cloud_program_payload
from scripts.make_strong_packed_coo_witness_binding import build_witness_cloud_program
print(json.dumps(canonical_cloud_program_payload(build_witness_cloud_program())["nodes"]))
""",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _expected_realized_contract() -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json
from scripts.make_strong_packed_coo_witness_binding import build_witness_realized_contract
print(json.dumps(build_witness_realized_contract()))
""",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _valid_witness(
    bindings: dict[str, str],
    execution_trace: list[dict[str, Any]],
    realized_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if realized_contract is None:
        realized_contract = _expected_realized_contract()
    return {
        "schema_version": "strong-packed-coo-witness-v1",
        "status": "pass",
        "evidence_scope": "fixed-stride-primitive-correctness-only-pinned-openfhe",
        "bindings": bindings,
        "adapter": {
            "typed_slot_count": 4096,
            "physical_batch_size": 8192,
            "second_batching_row_zero": True,
        },
        "openfhe": {
            "repository": "https://github.com/openfheorg/openfhe-development.git",
            "version": "1.5.1",
            "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
            "scheme": "BFVRNS",
            "ring_dimension": 8192,
            "plaintext_modulus": 65537,
            "batch_size": 8192,
            "effective_first_row_slots": 4096,
            "multiplicative_depth": 2,
            "eval_add_count": 0,
            "key_switch_count": 0,
        },
        "circuit": {
            "component_count": 2,
            "logical_payload_width": 127,
            "physical_segment_width": 128,
            "padding_lanes_per_segment": 1,
            "reduction_rotation_indices": [1, 2, 4, 8, 16, 32, 64],
            "reduction_eval_add_count_per_component": 7,
            "start_mask_applications_per_component": 1,
        },
        "realized_contract": realized_contract,
        "execution_trace": execution_trace,
        "correctness": {
            "expected_centered_result": [4, 6, 20, -8],
            "decrypted_centered_result": [4, 6, 20, -8],
            "matches_expected": True,
            "decryptions_valid": True,
            "products_relinearized": True,
            "unrelinearized_product_element_counts": [3, 3],
            "product_element_counts": [2, 2],
            "global_column_index": 8192,
            "global_column_index_anti_alias": True,
            "tail_segment_start": 3968,
            "tail_segment_exercised": True,
            "non_power_of_two_payload_boundary_exercised": True,
            "padding_lane_zero": True,
        },
        "f1m": {
            "mode": "encrypted-one-time-zero-sum",
            "mask_scope": "logical-coordinate-overlap-only",
            "encrypted_mask_ciphertext_count": 2,
            "overlap_coordinate_count": 2,
            "disjoint_mask_zero": True,
            "zero_sum_mask": True,
            "mask_values_redacted": True,
        },
        "claims": {
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "formal_parameter_claim_allowed": False,
            "end_to_end_correctness_claim_allowed": False,
            "security_claim_allowed": False,
            "formal_correctness_claim": False,
            "formal_security_claim": False,
            "formal_performance_claim": False,
            "mixed_workload_parameter_claim": False,
        },
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_test_provenance(
    tmp_path: Path,
    bindings: dict[str, str],
    *,
    mutation: tuple[str, Any] | None = None,
) -> tuple[Path, Path]:
    binary = tmp_path / "strong_packed_coo_witness"
    binary.write_bytes(b"test-only-binary")
    provenance: dict[str, Any] = {
        "schema_version": "strong-packed-coo-witness-provenance-v1",
        "source_git_sha": "1" * 40,
        "source_git_ref": "refs/heads/test",
        "github_run_id": "123456",
        "openfhe_commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "witness_source_sha256": _sha256(ROOT / "cpp" / "strong_packed_coo_witness.cpp"),
        "witness_binary_sha256": _sha256(binary),
        "binding_generator_sha256": _sha256(GENERATOR),
        "validator_sha256": _sha256(VALIDATOR),
        **bindings,
    }
    if mutation is not None:
        field, value = mutation
        provenance[field] = value
    provenance_path = tmp_path / "PROVENANCE.json"
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    return provenance_path, binary


def _validate_payload(
    tmp_path: Path,
    payload: dict[str, Any],
    *,
    manifest: Path | None = None,
    provenance_mutation: tuple[str, Any] | None = None,
) -> subprocess.CompletedProcess[str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    witness = tmp_path / "witness.json"
    witness.write_text(json.dumps(payload), encoding="utf-8")
    provenance, binary = _write_test_provenance(
        tmp_path,
        payload["bindings"],
        mutation=provenance_mutation,
    )
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(witness),
            str(manifest or ROOT / "config" / "params_manifest.json"),
            str(provenance),
            "--source-git-sha",
            "1" * 40,
            "--source-git-ref",
            "refs/heads/test",
            "--github-run-id",
            "123456",
            "--witness-source",
            str(ROOT / "cpp" / "strong_packed_coo_witness.cpp"),
            "--witness-binary",
            str(binary),
            "--binding-generator",
            str(GENERATOR),
            "--validator-source",
            str(VALIDATOR),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )


def _validate_payload_direct(
    tmp_path: Path,
    payload: dict[str, Any],
    witness_validator: Any,
) -> None:
    witness = tmp_path / "witness.json"
    witness.write_text(json.dumps(payload), encoding="utf-8")
    provenance, binary = _write_test_provenance(tmp_path, payload["bindings"])
    witness_validator.validate_witness(
        witness,
        ROOT / "config" / "params_manifest.json",
        provenance,
        source_git_sha="1" * 40,
        source_git_ref="refs/heads/test",
        github_run_id="123456",
        witness_source=ROOT / "cpp" / "strong_packed_coo_witness.cpp",
        witness_binary=binary,
        binding_generator=GENERATOR,
        validator_source=VALIDATOR,
    )


def test_witness_target_freezes_the_correctness_circuit_shape() -> None:
    cmake = (ROOT / "cpp" / "CMakeLists.txt").read_text(encoding="utf-8")
    source = (ROOT / "cpp" / "strong_packed_coo_witness.cpp").read_text(encoding="utf-8")

    assert "add_executable(strong_packed_coo_witness strong_packed_coo_witness.cpp)" in cmake
    for literal in ("8192", "65537", "4096", "127", "128"):
        assert literal in source
    assert "SetMultiplicativeDepth(kMultiplicativeDepth)" in source
    assert "kMultiplicativeDepth = 2" in source
    assert "SetEvalAddCount(kEstimatorEvalAddCount)" in source
    assert "kEstimatorEvalAddCount = 0" in source
    assert "SetKeySwitchCount(kEstimatorKeySwitchCount)" in source
    assert "kEstimatorKeySwitchCount = 0" in source
    assert "kLogicalPayloadWidth = 127" in source
    assert "kPhysicalSegmentWidth = 128" in source
    assert '\\"eval_add_count\\": ' in source
    assert '\\"key_switch_count\\": ' in source
    assert '\\"logical_payload_width\\": ' in source
    assert '\\"physical_segment_width\\": ' in source
    assert '\\"segment_width\\"' not in source
    for claim in (
        "gate_eligible",
        "complete_cost_claim_allowed",
        "formal_parameter_claim_allowed",
        "end_to_end_correctness_claim_allowed",
        "security_claim_allowed",
    ):
        assert f'\\"{claim}\\": false' in source
    assert "{1, 2, 4, 8, 16, 32, 64}" in source
    assert "kReductionEvalAddCount = 7" in source


def test_witness_executes_relinearized_two_component_tail_and_anti_alias_paths() -> None:
    source = (ROOT / "cpp" / "strong_packed_coo_witness.cpp").read_text(encoding="utf-8")

    assert "EvalMultNoRelin(valueCiphertext, queryCiphertext)" in source
    assert "Relinearize(product)" in source
    assert "EvalMult(valueCiphertext, queryCiphertext)" not in source
    assert "unrelinearizedElementCount" in source
    assert "relinearized->GetElements().size()" in source
    assert "kUnrelinearizedElementCount = 3" in source
    assert "kRelinearizedElementCount = 2" in source
    assert '\\"unrelinearized_product_element_counts\\": ' in source
    assert "EvalRotate(reduced, rotation)" in source
    assert "EvalAdd(reduced, rotated)" in source
    assert "EvalMult(reduced, startMask)" in source
    assert "kComponentCount = 2" in source
    assert "kTailSegmentStart = 3968" in source
    assert "kAntiAliasGlobalColumn = 8192" in source
    assert (
        "static_cast<std::int64_t>(value) - static_cast<std::int64_t>(kPlaintextModulus)"
    ) in source
    assert "static_cast<std::int64_t>(value - kPlaintextModulus)" not in source
    assert "kLogicalPayloadWidth - 1" in source
    assert "paddingLaneZero" in source
    assert "secondBatchingRowZero" in source
    assert '\\"typed_slot_count\\": 4096' in source
    assert '\\"physical_batch_size\\": 8192' in source
    assert '\\"second_batching_row_zero\\": ' in source
    assert "executionTrace.push_back" in source
    assert '\\"execution_trace\\": ' in source
    assert "WriteRealizedContract" in source
    assert '\\"realized_contract\\": ' in source
    assert "leaderPositions.push_back(slot)" in source
    assert "component.startToLogical" in source
    assert 'node.operation == "rotate"' in source
    assert 'node.operation == "return-result"' in source
    assert "component.f1mMaskInputId" in source
    assert "component.queryInputId" in source
    assert "component.valueInputId" in source
    assert "globalQuery.at(kAntiAliasGlobalColumn)" in source
    assert "globalQuery.at(0)" in source


def test_witness_executes_f1m_without_disclosing_mask_values() -> None:
    source = (ROOT / "cpp" / "strong_packed_coo_witness.cpp").read_text(encoding="utf-8")

    assert '"/dev/urandom"' in source
    assert "MakeF1MMasks" in source
    assert "Encrypt(publicKey, maskPlaintext)" in source
    assert "EvalAdd(unblinded, encryptedMask)" in source
    assert "disjointMaskZero" in source
    assert "zeroSumMask" in source
    assert '\\"mask_values_redacted\\": true' in source
    assert '\\"mask_values\\"' not in source


def test_validator_rejects_non_closed_top_level_json(tmp_path: Path) -> None:
    completed = _validate_payload(
        tmp_path,
        {"bindings": _make_bindings(tmp_path), "unexpected": True},
    )

    assert completed.returncode != 0
    assert "top-level keys" in completed.stderr


def _workflow_step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end == -1 else source[start:end]


def test_workflow_is_manual_pinned_fail_closed_and_evidence_preserving() -> None:
    workflow = (ROOT / ".github" / "workflows" / "strong-packed-coo-witness.yml").read_text(
        encoding="utf-8"
    )

    trigger = workflow.split("permissions:", 1)[0]
    assert "workflow_dispatch:" in trigger
    assert "push:" not in trigger
    assert "pull_request:" not in trigger
    assert "workflow_run:" not in trigger
    assert "day1" not in workflow.lower()
    assert "day2" not in workflow.lower()
    assert "scripts/bootstrap_openfhe.sh" in workflow
    assert "PYTHONPATH: 'src:.'" in workflow
    assert "pip install --require-hashes -r requirements-ci.txt" in workflow
    assert "pip install -e" not in workflow
    assert "git -C _openfhe/source rev-parse HEAD" in workflow
    assert 'SOURCE_GIT_SHA="$(git rev-parse HEAD)"' in workflow
    assert '"$SOURCE_GIT_SHA" != "$GITHUB_SHA"' in workflow
    assert "OpenFHEConfigVersion.cmake" in workflow
    assert "find results/strong-packed-coo-witness -mindepth 1 -delete" in workflow
    assert "scripts/make_strong_packed_coo_witness_binding.py" in workflow
    assert "cloud_program_digest" in workflow
    assert "output_plan_digest" in workflow
    assert "execution_binding_digest" in workflow
    assert "PROVENANCE.json" in workflow
    assert "results/strong-packed-coo-witness/config/params_manifest.json" in workflow
    for field in (
        "source_git_sha",
        "source_git_ref",
        "github_run_id",
        "witness_source_sha256",
        "witness_binary_sha256",
        "binding_generator_sha256",
        "validator_sha256",
    ):
        assert field in workflow

    run_step = _workflow_step(workflow, "Run and independently validate witness")
    assert "set -euo pipefail" in run_step
    assert "PIPESTATUS" in run_step
    assert "strong_packed_coo_witness" in run_step
    assert "validate_strong_packed_coo_witness.py" in run_step
    assert "exit 1" in run_step

    finalize_step = _workflow_step(workflow, "Finalize witness artifact")
    assert "if: always()" in finalize_step
    assert "RUN_STATUS.json" in finalize_step
    assert '"evidence_valid"' in finalize_step
    assert '"status"' in finalize_step
    assert '"expected_openfhe_commit"' in finalize_step
    assert "DIAGNOSTIC_SHA256SUMS" in finalize_step
    assert "sha256sum witness.json > witness.json.sha256.tmp" in finalize_step
    assert "sha256sum --check --strict witness.json.sha256.tmp" in finalize_step
    assert "mv witness.json.sha256.tmp witness.json.sha256" in finalize_step
    assert "find . -type f ! -name 'SHA256SUMS*'" in finalize_step
    assert "sha256sum --check --strict SHA256SUMS.tmp" in finalize_step
    assert "trap cleanup_checksums EXIT" in finalize_step
    assert "rm -f witness.json.sha256" in finalize_step
    assert "WITNESS_OUTCOME: ${{ steps.witness.outcome }}" in finalize_step
    assert "evidence_valid=false" in finalize_step
    assert "evidence_valid=true" in finalize_step

    upload_step = _workflow_step(workflow, "Upload correctness witness evidence")
    assert "if: always()" in upload_step
    assert "actions/upload-artifact@v4" in upload_step
    assert "job.status" in upload_step


def test_binding_generator_emits_only_canonical_typed_digests(tmp_path: Path) -> None:
    bindings = _make_bindings(tmp_path)
    assert set(bindings) == {
        "cloud_program_digest",
        "output_plan_digest",
        "execution_binding_digest",
    }
    assert all(
        isinstance(value, str) and len(value) == 64 and not (set(value) - set("0123456789abcdef"))
        for value in bindings.values()
    )

    source = GENERATOR.read_text(encoding="utf-8")
    assert "CloudProgram(" in source
    assert "ExecutionBinding(" in source
    assert "OutputPlan(" in source
    assert 'EXECUTION_BINDING_VERSION = "strong-witness-v1"' in source
    assert "version_id=EXECUTION_BINDING_VERSION" in source
    assert '"witness-component-0"' in source
    assert '"witness-component-1"' in source
    assert '"strong-packed-coo-base"' not in source

    inspected = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json
from scripts.make_strong_packed_coo_witness_binding import (
    build_witness_cloud_program,
    build_witness_output_plan,
    build_witness_realized_contract,
)
program = build_witness_cloud_program()
plan = build_witness_output_plan()
contract = build_witness_realized_contract()
print(json.dumps({
    "program_slots": program.slot_count,
    "output_slots": plan.slot_count,
    "input_lengths": sorted({item.length for item in program.ciphertext_inputs}),
    "mask_lengths": sorted({item.length for item in program.plaintext_masks}),
    "mask_value_lengths": sorted({len(item.values) for item in program.plaintext_masks}),
    "components": sorted({share.component_id for share in plan.shares}),
    "binding_version": contract["execution_binding"]["version_id"],
    "selection_leaders": contract["cloud_program"]["plaintext_masks"][0]["leader_positions"],
    "output_mapping": contract["output_plan"]["shares"][0]["slot_to_logical"],
}))
""",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout) == {
        "program_slots": 4096,
        "output_slots": 4096,
        "input_lengths": [4096],
        "mask_lengths": [4096],
        "mask_value_lengths": [4096],
        "components": ["witness-component-0", "witness-component-1"],
        "binding_version": "strong-witness-v1",
        "selection_leaders": list(range(0, 4096, 128)),
        "output_mapping": [[0, 0], [128, 1], [256, 2], [3968, 3]],
    }


def test_realized_contract_covers_every_non_node_binding_field() -> None:
    contract = _expected_realized_contract()
    assert set(contract) == {"execution_binding", "cloud_program", "output_plan"}
    assert contract["execution_binding"] == {
        "format": "dynamic-cssc-execution-binding-v1",
        "version_id": "strong-witness-v1",
    }

    cloud = contract["cloud_program"]
    assert set(cloud) == {
        "format",
        "slot_count",
        "ciphertext_inputs",
        "plaintext_masks",
        "rotation_catalog",
        "result_ids",
    }
    assert cloud["ciphertext_inputs"] == [
        {"ciphertext_id": f"witness-component-{component}-{suffix}", "length": 4096, "role": role}
        for component in range(2)
        for suffix, role in (("f1m-mask", "f1m-mask"), ("query", "query"), ("values", "value"))
    ]
    assert cloud["plaintext_masks"] == [
        {
            "length": 4096,
            "mask_id": "segment-starts",
            "role": "selection",
            "leader_positions": list(range(0, 4096, 128)),
        }
    ]
    assert cloud["rotation_catalog"] == [
        {"logical_shift": rotation, "openfhe_index": rotation}
        for rotation in (1, 2, 4, 8, 16, 32, 64)
    ]
    assert cloud["result_ids"] == [
        "witness-component-0-page-000000",
        "witness-component-1-page-000000",
    ]

    assert contract["output_plan"] == {
        "format": "dynamic-cssc-output-plan-v1",
        "logical_output_size": 4,
        "slot_count": 4096,
        "shares": [
            {
                "component_id": "witness-component-0",
                "output_block_id": "page-000000",
                "slot_to_logical": [[0, 0], [128, 1], [256, 2], [3968, 3]],
            },
            {
                "component_id": "witness-component-1",
                "output_block_id": "page-000000",
                "slot_to_logical": [[0, 0], [128, 2]],
            },
        ],
    }


def test_validator_accepts_only_the_exact_recomputed_witness(tmp_path: Path) -> None:
    trace = _expected_execution_trace()
    assert len(trace) == 38
    completed = _validate_payload(tmp_path, _valid_witness(_make_bindings(tmp_path), trace))

    assert completed.returncode == 0, completed.stderr


def test_validator_rebuilds_trace_when_typed_program_order_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import make_strong_packed_coo_witness_binding as binding_generator
    import validate_strong_packed_coo_witness as witness_validator

    original_program = binding_generator.build_witness_cloud_program()
    block_size = len(original_program.nodes) // 2
    drifted_program = replace(
        original_program,
        nodes=(
            original_program.nodes[block_size:-1]
            + original_program.nodes[: block_size - 1]
            + (original_program.nodes[block_size - 1], original_program.nodes[-1])
        ),
    )
    monkeypatch.setattr(
        binding_generator,
        "build_witness_cloud_program",
        lambda: drifted_program,
    )
    monkeypatch.setattr(
        witness_validator,
        "build_witness_cloud_program",
        lambda: drifted_program,
    )

    manifest_path = ROOT / "config" / "params_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bindings = binding_generator.make_witness_bindings(manifest)
    with pytest.raises(witness_validator.WitnessValidationError, match="execution_trace"):
        _validate_payload_direct(
            tmp_path,
            _valid_witness(bindings, _expected_execution_trace()),
            witness_validator,
        )


def test_validator_rejects_new_zero_selection_digest_with_old_realized_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import make_strong_packed_coo_witness_binding as binding_generator
    import validate_strong_packed_coo_witness as witness_validator

    original_program = binding_generator.build_witness_cloud_program()
    manifest = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    original_bindings = binding_generator.make_witness_bindings(manifest)
    selection_mask = original_program.plaintext_masks[0]
    drifted_program = replace(
        original_program,
        plaintext_masks=(replace(selection_mask, values=(0,) * selection_mask.length),),
    )
    monkeypatch.setattr(
        binding_generator,
        "build_witness_cloud_program",
        lambda: drifted_program,
    )
    monkeypatch.setattr(
        witness_validator,
        "build_witness_cloud_program",
        lambda: drifted_program,
    )
    bindings = binding_generator.make_witness_bindings(manifest)
    assert bindings["cloud_program_digest"] != original_bindings["cloud_program_digest"]
    assert bindings["output_plan_digest"] == original_bindings["output_plan_digest"]
    assert bindings["execution_binding_digest"] != original_bindings["execution_binding_digest"]

    with pytest.raises(witness_validator.WitnessValidationError, match="realized_contract"):
        _validate_payload_direct(
            tmp_path,
            _valid_witness(bindings, _expected_execution_trace()),
            witness_validator,
        )


def test_validator_rejects_new_output_mapping_digest_with_old_realized_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import make_strong_packed_coo_witness_binding as binding_generator
    import validate_strong_packed_coo_witness as witness_validator

    original_plan = binding_generator.build_witness_output_plan()
    manifest = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    original_bindings = binding_generator.make_witness_bindings(manifest)
    first_share = original_plan.shares[0]
    drifted_plan = replace(
        original_plan,
        shares=(
            replace(
                first_share,
                slot_to_logical=((0, 0), (384, 1), (256, 2), (3968, 3)),
            ),
            original_plan.shares[1],
        ),
    )
    monkeypatch.setattr(
        binding_generator,
        "build_witness_output_plan",
        lambda: drifted_plan,
    )
    bindings = binding_generator.make_witness_bindings(manifest)
    assert bindings["cloud_program_digest"] == original_bindings["cloud_program_digest"]
    assert bindings["output_plan_digest"] != original_bindings["output_plan_digest"]
    assert bindings["execution_binding_digest"] != original_bindings["execution_binding_digest"]

    with pytest.raises(witness_validator.WitnessValidationError, match="realized_contract"):
        _validate_payload_direct(
            tmp_path,
            _valid_witness(bindings, _expected_execution_trace()),
            witness_validator,
        )


def test_validator_rejects_new_binding_version_with_old_realized_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import make_strong_packed_coo_witness_binding as binding_generator
    import validate_strong_packed_coo_witness as witness_validator

    manifest = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    original_bindings = binding_generator.make_witness_bindings(manifest)
    monkeypatch.setattr(
        binding_generator,
        "EXECUTION_BINDING_VERSION",
        "strong-witness-mutated",
        raising=False,
    )
    bindings = binding_generator.make_witness_bindings(manifest)
    assert bindings["cloud_program_digest"] == original_bindings["cloud_program_digest"]
    assert bindings["output_plan_digest"] == original_bindings["output_plan_digest"]
    assert bindings["execution_binding_digest"] != original_bindings["execution_binding_digest"]

    with pytest.raises(witness_validator.WitnessValidationError, match="realized_contract"):
        _validate_payload_direct(
            tmp_path,
            _valid_witness(bindings, _expected_execution_trace()),
            witness_validator,
        )


def test_validator_requires_runtime_trace_and_actual_provenance(tmp_path: Path) -> None:
    bindings = _make_bindings(tmp_path)
    trace = _expected_execution_trace()
    missing_trace = _valid_witness(bindings, trace)
    del missing_trace["execution_trace"]
    assert _validate_payload(tmp_path / "missing-trace", missing_trace).returncode != 0

    witness = tmp_path / "witness-without-provenance.json"
    witness.write_text(json.dumps(_valid_witness(bindings, trace)), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            str(witness),
            str(ROOT / "config" / "params_manifest.json"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=SCRIPT_ENV,
    )
    assert completed.returncode != 0

    tampered = _validate_payload(
        tmp_path / "tampered-provenance",
        _valid_witness(bindings, trace),
        provenance_mutation=("witness_binary_sha256", "0" * 64),
    )
    assert tampered.returncode != 0

    for index, mutation in enumerate(
        (
            ("source_git_sha", "2" * 40),
            ("openfhe_commit", "0" * 40),
            ("witness_source_sha256", "0" * 64),
            ("binding_generator_sha256", "0" * 64),
            ("validator_sha256", "0" * 64),
            ("cloud_program_digest", "0" * 64),
            ("unexpected", True),
        )
    ):
        completed = _validate_payload(
            tmp_path / f"tampered-provenance-{index}",
            _valid_witness(bindings, trace),
            provenance_mutation=mutation,
        )
        assert completed.returncode != 0, mutation[0]


def test_validator_fails_closed_under_witness_and_manifest_mutations(tmp_path: Path) -> None:
    valid = _valid_witness(_make_bindings(tmp_path), _expected_execution_trace())
    mutations: list[tuple[str, Any]] = [
        ("status", "fail"),
        ("bindings.cloud_program_digest", "0" * 64),
        ("circuit.reduction_eval_add_count_per_component", 8),
        ("correctness.decrypted_centered_result", [4, 6, 19, -8]),
        ("correctness.products_relinearized", 1),
        ("correctness.unrelinearized_product_element_counts", [2, 2]),
        ("correctness.non_power_of_two_payload_boundary_exercised", False),
        ("correctness.padding_lane_zero", False),
        ("adapter.second_batching_row_zero", False),
        ("realized_contract.execution_binding.version_id", "strong-witness-mutated"),
        ("realized_contract.cloud_program.plaintext_masks.0.leader_positions", []),
        (
            "realized_contract.output_plan.shares.0.slot_to_logical",
            [[0, 0], [384, 1], [256, 2], [3968, 3]],
        ),
        ("execution_trace.0.op", "return-result"),
        ("execution_trace.0.left_id", "wrong-input"),
        ("execution_trace.2.result_id", "wrong-output"),
        ("execution_trace.2.logical_shift", 2),
        ("execution_trace.2.openfhe_index", -1),
        ("execution_trace.16.mask_id", "wrong-mask"),
        ("execution_trace.17.mask_role", "wrong-role"),
        ("execution_trace.18.result_id", "wrong-return"),
        ("f1m.disjoint_mask_zero", False),
        ("f1m.mask_values", [1, 2]),
        ("claims.formal_security_claim", True),
        ("claims.gate_eligible", True),
    ]
    for index, (path, value) in enumerate(mutations):
        mutated = json.loads(json.dumps(valid))
        parent: Any = mutated
        parts = path.split(".")
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        if isinstance(parent, list):
            parent[int(parts[-1])] = value
        else:
            parent[parts[-1]] = value
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        completed = _validate_payload(case_dir, mutated)
        assert completed.returncode != 0, path

    manifest = json.loads((ROOT / "config" / "params_manifest.json").read_text(encoding="utf-8"))
    manifest["openfhe"]["commit"] = "0" * 40
    mutated_manifest = tmp_path / "mutated-manifest.json"
    mutated_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    completed = _validate_payload(tmp_path / "manifest-case", valid, manifest=mutated_manifest)
    assert completed.returncode != 0
