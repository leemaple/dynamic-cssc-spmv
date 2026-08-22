from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

import pytest

import scripts.property_contract as property_contract_module
import scripts.validate_property_contract as validator_module
from scripts.property_contract import PropertyContractError, generate_property_contract_evidence
from scripts.validate_property_contract import (
    PropertyContractValidationError,
    validate_property_contract_evidence,
)

SOURCE_GIT_SHA = subprocess.run(
    ["git", "rev-parse", "--verify", "HEAD"],
    cwd=Path(__file__).resolve().parents[1],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
SEED = 20260822


@pytest.fixture
def real_source_snapshot() -> None:
    """Opt a test into the production Git/source binding instead of the test-only seam."""


@pytest.fixture(autouse=True)
def _test_only_allow_in_progress_source_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Keep contract TDD runnable before the new files are committed."""

    if "real_source_snapshot" in request.fixturenames:
        return
    monkeypatch.setattr(
        property_contract_module,
        "_require_source_snapshot",
        lambda _source_git_sha: None,
        raising=False,
    )
    monkeypatch.setattr(
        validator_module,
        "_require_source_snapshot",
        lambda _source_git_sha: None,
        raising=False,
    )


def test_property_gate_exposes_one_deep_generation_seam(tmp_path: Path) -> None:
    assert tuple(inspect.signature(generate_property_contract_evidence).parameters) == (
        "output_dir",
        "source_git_sha",
        "seed",
    )

    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )

    assert set(evidence) == {
        "schema_version",
        "evidence_scope",
        "gate_status",
        "source_git_sha",
        "seed",
        "case_set",
        "provenance",
        "artifacts",
        "summary",
        "claims",
    }
    assert evidence["schema_version"] == ("dynamic-cssc-strong-property-contract-evidence-v1")
    assert evidence["evidence_scope"] == "builder-property-contract-only"
    assert evidence["gate_status"] == "pass"
    assert evidence["source_git_sha"] == SOURCE_GIT_SHA
    assert evidence["seed"] == SEED
    assert evidence["claims"] == {
        "candidate_registration_allowed": False,
        "complete_reference_set": False,
        "end_to_end_correctness_claim_allowed": False,
        "formal_correctness_claim": False,
        "formal_parameter_claim_allowed": False,
        "formal_performance_claim": False,
        "formal_security_claim": False,
        "security_claim_allowed": False,
    }


def test_case_manifest_is_versioned_explicit_and_byte_repeatable(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    first = generate_property_contract_evidence(
        first_dir,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    second = generate_property_contract_evidence(
        second_dir,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )

    assert first == second
    assert (first_dir / "evidence.json").read_bytes() == (second_dir / "evidence.json").read_bytes()
    assert (first_dir / "manifest.json").read_bytes() == (second_dir / "manifest.json").read_bytes()
    manifest = json.loads((first_dir / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest) == {
        "schema_version",
        "case_set_id",
        "case_set_version",
        "seed",
        "cases",
    }
    assert manifest["schema_version"] == ("dynamic-cssc-strong-property-contract-manifest-v1")
    assert manifest["case_set_id"] == "phase2-strong-whole-query-property-cases"
    assert manifest["case_set_version"] == 2
    assert manifest["seed"] == SEED
    assert [case["case_id"] for case in manifest["cases"]] == [
        "base-only-global-ci",
        "mixed-multiwave-tombstone",
        "c128-boundary-127",
        "c128-boundary-128",
        "c128-boundary-129",
        "c128-multipage-257",
        "seeded-extension",
    ]
    for case in manifest["cases"]:
        assert set(case) == {
            "case_id",
            "dimensions",
            "versions",
            "base",
            "waves",
            "query",
            "contracts",
        }
        assert set(case["dimensions"]) == {
            "rows",
            "cols",
            "effective_slots",
            "partition_rows",
            "segment_width",
            "matrix_value_bound",
        }
        assert set(case["versions"]) == {"initial_delta", "final"}
        assert set(case["base"]) == {"entries", "physical_capacities"}
        assert set(case["query"]) == {"query_id", "modulus", "vector"}

    assert first["case_set"]["input_case_count"] == 7
    assert len(first["case_set"]["sha256"]) == 64
    assert len(first["case_set"]["manifest_sha256"]) == 64


def test_case_records_recompute_whole_query_against_independent_direct_spmv(
    tmp_path: Path,
) -> None:
    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )

    records_document = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))
    assert set(records_document) == {
        "schema_version",
        "case_set_id",
        "case_set_version",
        "seed",
        "records",
    }
    oracle_records = [
        record
        for record in records_document["records"]
        if record["contract_id"] == "oracle-direct-spmv"
    ]
    assert len(oracle_records) == 7
    for record in oracle_records:
        assert set(record) == {"case_id", "contract_id", "observations"}
        observations = {
            observation["name"]: observation["value"] for observation in record["observations"]
        }
        assert observations["execute_output"] == observations["direct_spmv_output"]
        assert observations["execute_output"] == observations["independent_output"]

    serialized = (tmp_path / "case-records.json").read_text(encoding="utf-8")
    assert "ledger_commitment_token" not in serialized
    assert "random_values" not in serialized
    assert "values_digest" not in serialized
    assert evidence["artifacts"]["case_records"]["path"] == "case-records.json"
    assert len(evidence["artifacts"]["case_records"]["sha256"]) == 64


def test_output_plan_and_f1m_records_distinguish_overlap_from_dummy(
    tmp_path: Path,
) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    f1m_records = [record for record in records if record["contract_id"] == "output-plan-f1m"]

    assert len(f1m_records) == 7
    mixed = next(
        record for record in f1m_records if record["case_id"] == "mixed-multiwave-tombstone"
    )
    observed = {item["name"]: item["value"] for item in mixed["observations"]}
    assert observed == {
        "overlap_coordinates": [0],
        "f1m_kinds": [
            "random-zero-sum",
            "encrypted-zero-dummy",
            "random-zero-sum",
        ],
        "random_zero_sum_ciphertexts": 2,
        "encrypted_zero_dummy_ciphertexts": 1,
        "mask_random_elements": 1,
        "f1m_additions_from_dag": 3,
        "delta_mapped_lanes": [0, 2, 4],
        "delta_segment_starts": [0, 2, 4],
    }


def test_multiwave_delta_record_proves_modify_delete_and_tombstone_reuse(
    tmp_path: Path,
) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    record = next(item for item in records if item["contract_id"] == "delta-multiwave-tombstone")
    observed = {item["name"]: item["value"] for item in record["observations"]}

    assert record["case_id"] == "mixed-multiwave-tombstone"
    assert observed == {
        "versions": ["pc-mixed-v0", "pc-mixed-v1", "pc-mixed-v2", "pc-mixed-v3"],
        "segment_counts": [0, 2, 3, 3],
        "modified_value": 6,
        "deleted_tombstone_location": [0, 1],
        "reused_entry_location": [0, 1],
        "reused_entry": [0, 13, 8],
        "final_active_entries": 4,
    }


def test_global_ci_and_c128_boundary_records_are_exact(tmp_path: Path) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    global_records = {
        record["case_id"]: {item["name"]: item["value"] for item in record["observations"]}
        for record in records
        if record["contract_id"] == "global-ci-no-modulo"
    }
    assert set(global_records) == {
        "base-only-global-ci",
        "c128-boundary-127",
        "c128-boundary-128",
        "c128-boundary-129",
        "c128-multipage-257",
    }
    assert global_records["c128-boundary-127"]["max_global_ci"] == 599
    assert global_records["c128-boundary-127"]["prepared_probe_value"] == 338
    assert global_records["c128-boundary-127"]["modulo_alias_value"] == -17

    boundary = {
        record["case_id"]: {item["name"]: item["value"] for item in record["observations"]}
        for record in records
        if record["contract_id"] in {"c128-boundary", "c128-multipage"}
    }
    assert boundary["c128-boundary-127"] == {
        "segment_width": 128,
        "active_entries": 127,
        "segment_count": 1,
        "page_count": 1,
        "final_segment_occupied": 127,
        "final_segment_padding": 1,
    }
    assert boundary["c128-boundary-128"]["final_segment_padding"] == 0
    assert boundary["c128-boundary-129"]["segment_count"] == 2
    assert boundary["c128-boundary-129"]["final_segment_padding"] == 127
    assert boundary["c128-multipage-257"]["segment_count"] == 3
    assert boundary["c128-multipage-257"]["page_count"] == 2


def test_hidden_rowmap_and_delta_owner_permutation_preserve_cloud_program_bytes(
    tmp_path: Path,
) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    record = next(item for item in records if item["contract_id"] == "hidden-owner-permutation")
    observed = {item["name"]: item["value"] for item in record["observations"]}

    assert record["case_id"] == "mixed-multiwave-tombstone"
    assert observed["owner_permutation"] == [1, 0, 3, 2]
    assert observed["original_cloud_program_sha256"] == (observed["permuted_cloud_program_sha256"])
    assert observed["original_output_plan_sha256"] != (observed["permuted_output_plan_sha256"])
    assert observed["original_private_plan_sha256"] != (observed["permuted_private_plan_sha256"])


def test_version_private_cloud_and_f1m_retargeting_all_reject_without_consuming(
    tmp_path: Path,
) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    rejection_records = {
        record["contract_id"]: {item["name"]: item["value"] for item in record["observations"]}
        for record in records
        if record["contract_id"].startswith("reject-")
    }

    assert set(rejection_records) == {
        "reject-version-retarget",
        "reject-private-plan-retarget",
        "reject-cloud-dag-retarget",
        "reject-f1m-retarget",
    }
    assert rejection_records["reject-version-retarget"]["rejection_class"] == (
        "StrongExecutionError"
    )
    assert rejection_records["reject-private-plan-retarget"]["rejection_class"] == (
        "PreparedF1MCommitmentError"
    )
    assert rejection_records["reject-cloud-dag-retarget"]["rejection_class"] == (
        "PreparedF1MCommitmentError"
    )
    assert rejection_records["reject-f1m-retarget"]["rejection_class"] == ("StrongExecutionError")
    assert {
        tuple(observed["original_execute_output"]) for observed in rejection_records.values()
    } == {(138, 69, 126, 64)}


def test_persistent_ledger_is_single_use_crash_burned_and_concurrent_single_winner(
    tmp_path: Path,
) -> None:
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    records = json.loads((tmp_path / "case-records.json").read_text(encoding="utf-8"))["records"]
    ledger_records = {
        record["contract_id"]: {item["name"]: item["value"] for item in record["observations"]}
        for record in records
        if record["contract_id"].startswith("ledger-")
    }

    assert ledger_records["ledger-single-use"] == {
        "first_execute_output": [138, 69, 126, 64],
        "second_rejection_class": "ConsumedPreparedF1MCommitmentError",
        "successful_consumptions": 1,
    }
    assert ledger_records["ledger-reservation-before-sampling"] == {
        "reservation_committed_before_sampling": True,
        "sampling_started": True,
        "duplicate_after_reopen": True,
    }
    assert ledger_records["ledger-consume-crash-reopen"] == {
        "injection_scope": "test-only-after-persistent-consume",
        "crash_exit_code": 23,
        "reopen_rejection_class": "ConsumedPreparedF1MCommitmentError",
        "successful_consumptions": 1,
    }
    assert ledger_records["ledger-concurrency"] == {
        "worker_count": 2,
        "success_count": 1,
        "consumed_count": 1,
        "successful_output": [138, 69, 126, 64],
    }


def test_seed_changes_only_the_frozen_extension_slot_and_all_contracts_are_recorded(
    tmp_path: Path,
) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first = generate_property_contract_evidence(
        first_dir,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    second = generate_property_contract_evidence(
        second_dir,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED + 1,
    )
    first_manifest = json.loads((first_dir / "manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((second_dir / "manifest.json").read_text(encoding="utf-8"))

    assert first["case_set"]["sha256"] == second["case_set"]["sha256"]
    assert first["case_set"]["manifest_sha256"] != second["case_set"]["manifest_sha256"]
    assert first_manifest["cases"][:-1] == second_manifest["cases"][:-1]
    assert first_manifest["cases"][-1] != second_manifest["cases"][-1]
    assert first["case_set"]["contract_case_count"] == 34
    assert first["summary"] == {"record_count": 34, "failed": 0}
    first_records = json.loads((first_dir / "case-records.json").read_text(encoding="utf-8"))[
        "records"
    ]
    assert len(first_records) == 34
    seeded = next(record for record in first_records if record["contract_id"] == "seeded-extension")
    assert seeded["case_id"] == "seeded-extension"


def test_junit_is_canonical_noise_free_and_has_one_entry_per_contract(
    tmp_path: Path,
) -> None:
    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    junit_path = tmp_path / "junit.xml"
    root = ET.fromstring(junit_path.read_bytes())

    assert root.tag == "testsuite"
    assert root.attrib == {
        "name": "phase2-strong-whole-query-property-cases-v2",
        "tests": "34",
        "failures": "0",
        "errors": "0",
        "skipped": "0",
    }
    testcases = list(root)
    assert len(testcases) == 34
    assert all(
        testcase.tag == "testcase"
        and set(testcase.attrib) == {"classname", "name"}
        and len(testcase) == 1
        and testcase[0].tag == "system-out"
        for testcase in testcases
    )
    assert b"timestamp=" not in junit_path.read_bytes()
    assert b"time=" not in junit_path.read_bytes()
    assert evidence["artifacts"]["junit"]["path"] == "junit.xml"
    assert len(evidence["artifacts"]["junit"]["sha256"]) == 64


def test_validator_binds_current_sources_and_recomputes_all_records(tmp_path: Path) -> None:
    assert tuple(inspect.signature(validate_property_contract_evidence).parameters) == (
        "evidence_dir",
        "expected_source_git_sha",
    )
    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )

    assert set(evidence["provenance"]) == {
        "cloud_execution_plan",
        "contract_spec",
        "compiler",
        "cssc",
        "events",
        "generator",
        "mask_ledger",
        "output_plan",
        "plaintext_oracle",
        "strong_packed_coo",
        "validator",
        "test_source",
    }
    assert evidence["provenance"]["compiler"]["path"] == ("src/dynamic_cssc/strong_execution.py")
    assert evidence["provenance"]["contract_spec"]["path"] == ("scripts/property_contract_spec.py")
    assert evidence["provenance"]["generator"]["path"] == ("scripts/property_contract.py")
    assert evidence["provenance"]["validator"]["path"] == ("scripts/validate_property_contract.py")
    assert evidence["provenance"]["test_source"]["path"] == (
        "tests/test_strong_property_contract.py"
    )
    assert evidence["provenance"]["mask_ledger"]["path"] == ("src/dynamic_cssc/mask_ledger.py")
    assert all(len(source["sha256"]) == 64 for source in evidence["provenance"].values())
    assert (
        validate_property_contract_evidence(
            tmp_path,
            expected_source_git_sha=SOURCE_GIT_SHA,
        )
        == evidence
    )


def test_generator_and_validator_reject_another_valid_git_commit(
    tmp_path: Path,
    real_source_snapshot: None,
) -> None:
    root = Path(__file__).resolve().parents[1]
    old_sha = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert len(old_sha) == 40
    assert old_sha != SOURCE_GIT_SHA

    with pytest.raises(PropertyContractError, match="current Git HEAD"):
        generate_property_contract_evidence(
            tmp_path / "generated",
            source_git_sha=old_sha,
            seed=SEED,
        )
    with pytest.raises(PropertyContractValidationError, match="current Git HEAD"):
        validate_property_contract_evidence(
            tmp_path / "missing",
            expected_source_git_sha=old_sha,
        )


def test_generator_and_validator_reject_dirty_mask_ledger_at_unchanged_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    real_source_snapshot: None,
) -> None:
    root = Path(__file__).resolve().parents[1]
    mask_ledger_path = "src/dynamic_cssc/mask_ledger.py"

    def simulated_git_blob(source_git_sha: str, relative_path: str) -> bytes:
        assert source_git_sha == SOURCE_GIT_SHA
        current = (root / relative_path).read_bytes()
        if relative_path == mask_ledger_path:
            return current + b"# simulated committed blob differs\n"
        return current

    monkeypatch.setattr(
        property_contract_module,
        "_current_git_head",
        lambda: SOURCE_GIT_SHA,
        raising=False,
    )
    monkeypatch.setattr(
        validator_module,
        "_current_git_head",
        lambda: SOURCE_GIT_SHA,
        raising=False,
    )
    monkeypatch.setattr(
        property_contract_module,
        "_git_blob_bytes",
        simulated_git_blob,
        raising=False,
    )
    monkeypatch.setattr(
        validator_module,
        "_git_blob_bytes",
        simulated_git_blob,
        raising=False,
    )

    with pytest.raises(PropertyContractError, match="mask_ledger.py"):
        generate_property_contract_evidence(
            tmp_path / "generated",
            source_git_sha=SOURCE_GIT_SHA,
            seed=SEED,
        )
    with pytest.raises(PropertyContractValidationError, match="mask_ledger.py"):
        validate_property_contract_evidence(
            tmp_path / "missing",
            expected_source_git_sha=SOURCE_GIT_SHA,
        )


def _write_canonical_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n",
        encoding="ascii",
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "evidence-extra-field",
        "claim-escalation",
        "source-digest",
        "case-set-digest",
        "manifest-rehashed",
        "record-rehashed",
        "junit-rehashed",
        "duplicate-json-key",
        "wrong-expected-git",
    ),
)
def test_validator_fails_closed_after_self_consistent_tampering(
    tmp_path: Path,
    mutation: str,
) -> None:
    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    evidence_path = tmp_path / "evidence.json"
    expected_git = SOURCE_GIT_SHA

    if mutation == "evidence-extra-field":
        evidence["unexpected"] = None
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "claim-escalation":
        evidence["claims"]["formal_security_claim"] = True
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "source-digest":
        evidence["provenance"]["compiler"]["sha256"] = "0" * 64
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "case-set-digest":
        evidence["case_set"]["sha256"] = "0" * 64
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "manifest-rehashed":
        manifest_path = tmp_path / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        manifest["cases"][0]["query"]["vector"][0] += 1
        _write_canonical_json(manifest_path, manifest)
        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        evidence["case_set"]["manifest_sha256"] = digest
        evidence["artifacts"]["manifest"]["sha256"] = digest
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "record-rehashed":
        records_path = tmp_path / "case-records.json"
        records = json.loads(records_path.read_text(encoding="ascii"))
        records["records"][0]["observations"][0]["value"][0] += 1
        _write_canonical_json(records_path, records)
        evidence["artifacts"]["case_records"]["sha256"] = hashlib.sha256(
            records_path.read_bytes()
        ).hexdigest()
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "junit-rehashed":
        junit_path = tmp_path / "junit.xml"
        junit_path.write_bytes(
            junit_path.read_bytes().replace(b"oracle-direct-spmv", b"claimed-pass", 1)
        )
        evidence["artifacts"]["junit"]["sha256"] = hashlib.sha256(
            junit_path.read_bytes()
        ).hexdigest()
        _write_canonical_json(evidence_path, evidence)
    elif mutation == "duplicate-json-key":
        evidence_path.write_bytes(
            b'{"schema_version":"duplicate",' + evidence_path.read_bytes()[1:]
        )
    elif mutation == "wrong-expected-git":
        expected_git = "2" * 40
    else:  # pragma: no cover - parameter list is closed
        raise AssertionError(mutation)

    with pytest.raises(PropertyContractValidationError):
        validate_property_contract_evidence(
            tmp_path,
            expected_source_git_sha=expected_git,
        )


def test_generator_and_validator_cli_form_a_fail_closed_artifact_seam(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_dir = tmp_path / "evidence"
    generated = property_contract_module._main(
        [
            "--output-dir",
            str(output_dir),
            "--source-git-sha",
            SOURCE_GIT_SHA,
            "--seed",
            str(SEED),
        ]
    )
    assert generated == 0
    assert capsys.readouterr().out == "property-contract evidence generated\n"

    validated = validator_module._main(
        [
            str(output_dir),
            "--expected-source-git-sha",
            SOURCE_GIT_SHA,
        ]
    )
    assert validated == 0
    assert capsys.readouterr().out == "property-contract validation passed\n"

    refused = property_contract_module._main(
        [
            "--output-dir",
            str(output_dir),
            "--source-git-sha",
            SOURCE_GIT_SHA,
            "--seed",
            str(SEED),
        ]
    )
    assert refused == 1
    assert "must be absent or empty" in capsys.readouterr().err


def test_validator_rejects_a_self_consistent_generator_recompute_bug(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_recompute = property_contract_module.recompute_case_records

    def buggy_recompute(manifest: dict[str, object]) -> dict[str, object]:
        records_document = deepcopy(original_recompute(manifest))
        records_document["records"][0]["observations"][0]["value"][0] += 1
        return records_document

    monkeypatch.setattr(property_contract_module, "recompute_case_records", buggy_recompute)
    if hasattr(validator_module, "recompute_case_records"):
        monkeypatch.setattr(validator_module, "recompute_case_records", buggy_recompute)
    generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )

    with pytest.raises(PropertyContractValidationError):
        validate_property_contract_evidence(
            tmp_path,
            expected_source_git_sha=SOURCE_GIT_SHA,
        )


def test_validator_manifest_interpreter_is_independent_of_a_decoder_missing_last_wave(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = generate_property_contract_evidence(
        tmp_path,
        source_git_sha=SOURCE_GIT_SHA,
        seed=SEED,
    )
    real_decode = property_contract_module.decode_segmented_delta

    def missing_last_wave(delta):
        decoded = real_decode(delta)
        if delta.version_id == "pc-mixed-v3":
            decoded.pop((0, 13), None)
            decoded[(1, 12)] = 4
        return decoded

    monkeypatch.setattr(
        property_contract_module,
        "decode_segmented_delta",
        missing_last_wave,
    )

    assert (
        validate_property_contract_evidence(
            tmp_path,
            expected_source_git_sha=SOURCE_GIT_SHA,
        )
        == evidence
    )
