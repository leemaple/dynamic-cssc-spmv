from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET

EVIDENCE_SCHEMA_VERSION = "dynamic-cssc-strong-property-contract-evidence-v1"
EVIDENCE_SCOPE = "builder-property-contract-only"
MANIFEST_SCHEMA_VERSION = "dynamic-cssc-strong-property-contract-manifest-v1"
RECORDS_SCHEMA_VERSION = "dynamic-cssc-strong-property-contract-records-v1"
CASE_SET_ID = "phase2-strong-whole-query-property-cases"
CASE_SET_VERSION = 2

CLAIMS = {
    "candidate_registration_allowed": False,
    "complete_reference_set": False,
    "end_to_end_correctness_claim_allowed": False,
    "formal_correctness_claim": False,
    "formal_parameter_claim_allowed": False,
    "formal_performance_claim": False,
    "formal_security_claim": False,
    "security_claim_allowed": False,
}


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _vector(length: int, *, multiplier: int, offset: int) -> list[int]:
    return [((index * multiplier + offset) % 47) - 23 for index in range(length)]


def _seed_word(seed: int, label: str, index: int) -> int:
    encoded = f"{seed}:{label}:{index}".encode("ascii")
    return int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big")


def _seed_nonzero(seed: int, label: str, index: int, bound: int) -> int:
    magnitude = _seed_word(seed, label, index) % bound + 1
    return magnitude if _seed_word(seed, f"{label}-sign", index) % 2 == 0 else -magnitude


def _case(
    *,
    case_id: str,
    dimensions: dict[str, int],
    initial_delta: str,
    final_version: str,
    base_entries: list[list[int]],
    physical_capacities: list[int],
    waves: list[dict[str, object]],
    query_id: str,
    modulus: int,
    vector: list[int],
    contracts: list[str],
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "dimensions": dimensions,
        "versions": {"initial_delta": initial_delta, "final": final_version},
        "base": {
            "entries": base_entries,
            "physical_capacities": physical_capacities,
        },
        "waves": waves,
        "query": {"query_id": query_id, "modulus": modulus, "vector": vector},
        "contracts": contracts,
    }


def build_frozen_manifest(seed: int) -> dict[str, object]:
    mixed_contracts = [
        "oracle-direct-spmv",
        "output-plan-f1m",
        "delta-multiwave-tombstone",
        "hidden-owner-permutation",
        "reject-version-retarget",
        "reject-private-plan-retarget",
        "reject-cloud-dag-retarget",
        "reject-f1m-retarget",
        "ledger-single-use",
        "ledger-reservation-before-sampling",
        "ledger-consume-crash-reopen",
        "ledger-concurrency",
    ]
    cases = [
        _case(
            case_id="base-only-global-ci",
            dimensions={
                "rows": 3,
                "cols": 19,
                "effective_slots": 8,
                "partition_rows": 2,
                "segment_width": 2,
                "matrix_value_bound": 50,
            },
            initial_delta="pc-base-only-v1",
            final_version="pc-base-only-v1",
            base_entries=[[0, 1, 3], [0, 17, 2], [1, 6, -1], [2, 9, 4]],
            physical_capacities=[3, 2, 1],
            waves=[],
            query_id="pc-query-base-only",
            modulus=97,
            vector=_vector(19, multiplier=7, offset=5),
            contracts=["oracle-direct-spmv", "output-plan-f1m", "global-ci-no-modulo"],
        ),
        _case(
            case_id="mixed-multiwave-tombstone",
            dimensions={
                "rows": 4,
                "cols": 41,
                "effective_slots": 8,
                "partition_rows": 2,
                "segment_width": 2,
                "matrix_value_bound": 50,
            },
            initial_delta="pc-mixed-v0",
            final_version="pc-mixed-v3",
            base_entries=[[0, 1, 3], [0, 30, 2], [3, 7, 4]],
            physical_capacities=[2, 0, 0, 1],
            waves=[
                {
                    "version_id": "pc-mixed-v1",
                    "updates": [],
                    "overflow": [[0, 10, 5], [0, 11, -2], [1, 12, 4]],
                },
                {
                    "version_id": "pc-mixed-v2",
                    "updates": [[0, 10, 5, 6], [0, 11, -2, 0]],
                    "overflow": [[2, 20, 7]],
                },
                {
                    "version_id": "pc-mixed-v3",
                    "updates": [[1, 12, 4, -3]],
                    "overflow": [[0, 13, 8]],
                },
            ],
            query_id="pc-query-mixed",
            modulus=257,
            vector=_vector(41, multiplier=11, offset=9),
            contracts=mixed_contracts,
        ),
    ]

    for count in (127, 128, 129):
        cols = 600
        vector = _vector(cols, multiplier=13, offset=count)
        vector[599] = 211 + count
        vector[599 % 256] = -17
        cases.append(
            _case(
                case_id=f"c128-boundary-{count}",
                dimensions={
                    "rows": 2,
                    "cols": cols,
                    "effective_slots": 256,
                    "partition_rows": 2,
                    "segment_width": 128,
                    "matrix_value_bound": 500,
                },
                initial_delta=f"pc-c128-{count}-v0",
                final_version=f"pc-c128-{count}-v1",
                base_entries=[[1, 599, 3]],
                physical_capacities=[0, 1],
                waves=[
                    {
                        "version_id": f"pc-c128-{count}-v1",
                        "updates": [],
                        "overflow": [[0, 100 + index, index % 19 + 1] for index in range(count)],
                    }
                ],
                query_id=f"pc-query-c128-{count}",
                modulus=65537,
                vector=vector,
                contracts=[
                    "oracle-direct-spmv",
                    "output-plan-f1m",
                    "global-ci-no-modulo",
                    "c128-boundary",
                ],
            )
        )

    multipage_vector = _vector(800, multiplier=17, offset=3)
    multipage_vector[799] = 509
    multipage_vector[799 % 256] = -31
    cases.append(
        _case(
            case_id="c128-multipage-257",
            dimensions={
                "rows": 2,
                "cols": 800,
                "effective_slots": 256,
                "partition_rows": 2,
                "segment_width": 128,
                "matrix_value_bound": 500,
            },
            initial_delta="pc-c128-257-v0",
            final_version="pc-c128-257-v1",
            base_entries=[[1, 799, -2]],
            physical_capacities=[0, 1],
            waves=[
                {
                    "version_id": "pc-c128-257-v1",
                    "updates": [],
                    "overflow": [[0, 100 + index, index % 23 + 1] for index in range(257)],
                }
            ],
            query_id="pc-query-c128-257",
            modulus=65537,
            vector=multipage_vector,
            contracts=[
                "oracle-direct-spmv",
                "output-plan-f1m",
                "global-ci-no-modulo",
                "c128-multipage",
            ],
        )
    )

    seeded_vector = [
        (_seed_word(seed, "extension-vector", index) % 101) - 50 for index in range(73)
    ]
    cases.append(
        _case(
            case_id="seeded-extension",
            dimensions={
                "rows": 5,
                "cols": 73,
                "effective_slots": 16,
                "partition_rows": 4,
                "segment_width": 4,
                "matrix_value_bound": 30,
            },
            initial_delta="pc-extension-v0",
            final_version="pc-extension-v1",
            base_entries=[
                [0, 2, _seed_nonzero(seed, "extension-base", 0, 20)],
                [1, 31, _seed_nonzero(seed, "extension-base", 1, 20)],
                [4, 70, _seed_nonzero(seed, "extension-base", 2, 20)],
            ],
            physical_capacities=[2, 1, 0, 0, 1],
            waves=[
                {
                    "version_id": "pc-extension-v1",
                    "updates": [],
                    "overflow": [
                        [0, 60, _seed_nonzero(seed, "extension-delta", 0, 20)],
                        [2, 71, _seed_nonzero(seed, "extension-delta", 1, 20)],
                        [3, 72, _seed_nonzero(seed, "extension-delta", 2, 20)],
                    ],
                }
            ],
            query_id="pc-query-extension",
            modulus=4093,
            vector=seeded_vector,
            contracts=["oracle-direct-spmv", "output-plan-f1m", "seeded-extension"],
        )
    )
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "case_set_id": CASE_SET_ID,
        "case_set_version": CASE_SET_VERSION,
        "seed": seed,
        "cases": cases,
    }


def case_set_descriptor(manifest: dict[str, object]) -> dict[str, object]:
    cases = manifest["cases"]
    assert isinstance(cases, list)
    return {
        "id": CASE_SET_ID,
        "version": CASE_SET_VERSION,
        "cases": [
            {
                "case_id": case["case_id"],
                "contracts": case["contracts"],
                "dimensions": case["dimensions"],
                "seeded_fields": (
                    ["base.entries.values", "query.vector", "waves.overflow.values"]
                    if case["case_id"] == "seeded-extension"
                    else []
                ),
            }
            for case in cases
        ],
    }


def canonical_junit_bytes(records_document: dict[str, object]) -> bytes:
    records = records_document["records"]
    assert isinstance(records, list)
    root = ET.Element(
        "testsuite",
        {
            "name": f"{CASE_SET_ID}-v{CASE_SET_VERSION}",
            "tests": str(len(records)),
            "failures": "0",
            "errors": "0",
            "skipped": "0",
        },
    )
    for record in records:
        testcase = ET.SubElement(
            root,
            "testcase",
            {
                "classname": f"strong_property_contract.{record['case_id']}",
                "name": record["contract_id"],
            },
        )
        system_out = ET.SubElement(testcase, "system-out")
        system_out.text = canonical_json_bytes(record).decode("ascii").rstrip("\n")
    return (
        ET.tostring(
            root,
            encoding="utf-8",
            xml_declaration=True,
            short_empty_elements=False,
        )
        + b"\n"
    )
