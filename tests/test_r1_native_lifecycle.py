"""Cheap adapter tests; fake results are explicitly NOT native evidence."""

import json
from dataclasses import replace

import pytest

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.r1_native_lifecycle import (
    MODULUS,
    STRATEGIES,
    SQLiteMaskBindingLedger,
    advance_publication,
    advance_strong_publication,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
    bundle_parts,
    canonical,
    compile_bundle,
    digest,
    engineering_workload,
    execute_cloud_plan,
    execute_compiled_query,
    initialize,
    metadata_roundtrip,
    prepare_ordinary_query,
    prepare_strong_query,
    publication_payload,
    role_metadata,
    verify_outputs,
)


def test_fixture_is_legal_disjoint_and_not_a_formal_entry_point():
    workload = engineering_workload()
    workload.validate()
    with pytest.raises(ValueError, match="engineering workloads only"):
        replace(workload, identity="formal").validate()
    duplicate = workload.windows[0] + (workload.windows[0][0],)
    with pytest.raises(ValueError, match="invalid, duplicate"):
        replace(workload, windows=(duplicate, workload.windows[1])).validate()
    bad_before = (NetUpdate(0, 0, 6, 3),) + workload.windows[0][1:]
    with pytest.raises(ValueError, match="invalid, duplicate"):
        replace(workload, windows=(bad_before, workload.windows[1])).validate()


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_publication_refreshes_and_binds_physical_pages(strategy):
    workload = engineering_workload()
    state = initialize(strategy, workload)
    bundle = compile_bundle(state)
    payload, keys, fingerprints = publication_payload(state, bundle, {}, None)
    assert len(payload["values"]) == len(keys) == state.base.ciphertext_count
    assert all(value["reencrypt"] for value in payload["values"])
    unchanged, _, _ = publication_payload(state, bundle, fingerprints, None)
    assert all(not value["reencrypt"] for value in unchanged["values"])
    for index, updates in enumerate(workload.windows):
        window = PublicationWindow(index, float(index), float(index + 1), updates, 2, "test")
        transition = (
            advance_strong_publication(state, window)
            if strategy == "strong"
            else advance_publication(state, window)
        )
        state = transition.state
        bundle = compile_bundle(state, transition)
        payload, keys, fingerprints = publication_payload(
            state, bundle, fingerprints, transition.facts
        )
        assert len(payload["values"]) == len(keys)
        assert payload["publication_id"] == f"v{index + 1:08d}"
        assert any(value["reencrypt"] for value in payload["values"])
        if strategy == "repack":
            assert all(value["reencrypt"] for value in payload["values"])
        if strategy == "strong":
            assert any(key.startswith("delta/") for key in keys.values())
        assert len(set(keys.values())) == len(keys)


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_role_metadata_excludes_private_matrix_and_masks(strategy):
    state = initialize(strategy, engineering_workload())
    bundle = compile_bundle(state)
    messages = role_metadata(bundle, state.version_id)
    receipts = metadata_roundtrip(messages)
    assert [r["direction"] for r in receipts] == ["A->Cloud", "A->B"]
    assert all(r["bytes"] > 0 for r in receipts)
    private = canonical(messages[1]["payload"])
    assert b'"values"' not in private
    assert b'"query_columns"' in private
    assert b'"output_plan"' in private
    cloud = canonical(messages[0]["payload"])
    assert b'"global_column_indices"' not in cloud
    assert b'"slot_to_logical"' not in cloud


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_all_slot_and_independent_logical_oracles(tmp_path, strategy):
    workload = engineering_workload()
    state = initialize(strategy, workload)
    window = PublicationWindow(0, 0.0, 1.0, workload.windows[0], 2, "test")
    transition = (
        advance_strong_publication(state, window)
        if strategy == "strong"
        else advance_publication(state, window)
    )
    state = transition.state
    bundle = compile_bundle(state, transition)
    ledger = SQLiteMaskBindingLedger(tmp_path / "ledger.sqlite")
    prepare = prepare_strong_query if strategy == "strong" else prepare_ordinary_query
    prepared = prepare(
        bundle, query_id="test-query", vector=workload.queries[0][0], modulus=MODULUS, ledger=ledger
    )
    build = (
        build_strong_openfhe_query_request
        if strategy == "strong"
        else build_ordinary_openfhe_query_request
    )
    request = json.loads(build(bundle, prepared))
    cloud, _, _, _ = bundle_parts(bundle)
    args = {
        "ciphertext_inputs": {
            v["ciphertext_id"]: tuple(v["values"]) for v in request["ciphertext_values"]
        },
        "plaintext_masks": {m.mask_id: m.values for m in cloud.program.plaintext_masks},
        "modulus": MODULUS,
    }
    expected = (
        execute_cloud_plan(cloud, **args)
        if strategy == "strong"
        else execute_compiled_query(bundle.compiled, expected_f1m_policy="overlap-only", **args)
    )
    # Intentionally fabricated plaintext-native stub, only to exercise rejection paths.
    native = {
        "outputs": {key: list(value) for key, value in expected.items()},
        "request_sha256": digest(request),
    }
    output = verify_outputs(bundle, request, native, state.logical, workload.queries[0][0])
    assert len(output) == workload.rows
    native["outputs"][next(iter(expected))][-1] = 1
    with pytest.raises(ValueError, match="all-slot"):
        verify_outputs(bundle, request, native, state.logical, workload.queries[0][0])
    native["request_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="request digest"):
        verify_outputs(bundle, request, native, state.logical, workload.queries[0][0])
