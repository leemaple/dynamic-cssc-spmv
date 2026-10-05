"""Cheap adapter tests; fake results are explicitly NOT native evidence."""

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.r1_native_lifecycle import (
    MODULUS,
    STRATEGIES,
    NativeSession,
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
    verify_native_counts,
    verify_outputs,
)


@pytest.fixture
def native_binary():
    value = os.environ.get("R1_NATIVE_EXECUTABLE")
    if not value:
        pytest.skip("native tests run only on a configured remote built binary")
    path = Path(value).resolve()
    assert path.is_file()
    return path


def test_native_failure_reports_bounded_stderr_without_losing_log(tmp_path, monkeypatch):
    real_popen = subprocess.Popen
    diagnostic = "fixture-only setup failure: exact cause"

    def failed_process(_command, **kwargs):
        return real_popen(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdin.readline(); "
                f"sys.stderr.write({diagnostic!r} + '\\n' + 'x' * 6000); sys.exit(1)",
            ],
            **kwargs,
        )

    monkeypatch.setattr(subprocess, "Popen", failed_process)
    log = tmp_path / "native.log"
    session = NativeSession(Path("fixture-only"), log)
    try:
        with pytest.raises(RuntimeError, match=diagnostic) as error:
            session.call("setup", {})
        assert len(str(error.value)) < 4300
    finally:
        session.close()
    assert log.read_text() == diagnostic + "\n" + "x" * 6000


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
    _, keys, _ = publication_payload(state, bundle, {}, None)
    messages = role_metadata(bundle, state.version_id, keys)
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
    assert messages[0]["payload"]["value_bindings"] == keys


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


def test_cli_never_writes_to_previous_output(tmp_path):
    original = tmp_path / "failure.json"
    original.write_bytes(b"original failure evidence")
    result = subprocess.run(
        [
            sys.executable,
            "scripts/r1_native_engineering.py",
            "--executable",
            "absent",
            "--output-dir",
            str(tmp_path),
            "--strategy",
            "repack",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "prior receipts must remain untouched" in result.stderr
    assert original.read_bytes() == b"original failure evidence"
    assert list(tmp_path.iterdir()) == [original]


def test_native_canonical_frame_signed_reuse_and_changed_reuse_rejection(tmp_path, native_binary):
    session = NativeSession(native_binary, tmp_path / "native.log")
    try:
        assert session.call("setup", {})["status"] == "pass"
        vector = [-2] + [0] * 4095
        first = session.call(
            "publish",
            {
                "publication_id": "v00000000",
                "slot_count": 4096,
                "values": [{"cache_key": "signed", "values": vector, "reencrypt": True}],
            },
        )
        assert first["matrix_encryptions"] == 1
        second = session.call(
            "publish",
            {
                "publication_id": "v00000001",
                "slot_count": 4096,
                "values": [{"cache_key": "signed", "values": vector, "reencrypt": False}],
            },
        )
        assert second["matrix_encryptions"] == 0 and second["matrix_reused"] == 1
        vector[0] = -3
        with pytest.raises(RuntimeError, match="native process failed"):
            session.call(
                "publish",
                {
                    "publication_id": "v00000002",
                    "slot_count": 4096,
                    "values": [{"cache_key": "signed", "values": vector, "reencrypt": False}],
                },
            )
    finally:
        session.close()
    assert "reuse of absent or changed matrix value" in (tmp_path / "native.log").read_text()


@pytest.mark.parametrize("failure", ["replay", "stale"])
def test_native_query_binding_and_replay_rejection(tmp_path, native_binary, failure):
    workload = engineering_workload()
    state = initialize("repack", workload)
    bundle = compile_bundle(state)
    publication, keys, _ = publication_payload(state, bundle, {}, None)
    ledger = SQLiteMaskBindingLedger(tmp_path / "ledger.sqlite")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="native-regression",
        vector=workload.queries[0][0],
        modulus=MODULUS,
        ledger=ledger,
    )
    request = json.loads(build_ordinary_openfhe_query_request(bundle, prepared))
    payload = {"publication_id": state.version_id, "request": request, "value_keys": keys}
    session = NativeSession(native_binary, tmp_path / "native.log")
    try:
        session.call("setup", {})
        session.call("publish", publication)
        result = session.call("query", payload)
        verify_outputs(bundle, request, result, state.logical, workload.queries[0][0])
        if failure == "stale":
            payload["publication_id"] = "wrong-version"
        with pytest.raises(RuntimeError, match="native process failed"):
            session.call("query", payload)
    finally:
        session.close()
    expected = (
        "repeated query preparation" if failure == "replay" else "publication binding mismatch"
    )
    assert expected in (tmp_path / "native.log").read_text()


def test_native_rotation_augmentation_preserves_prior_keys(tmp_path, native_binary):
    workload = engineering_workload()
    state = initialize("padding", workload)
    bundle = compile_bundle(state)
    ledger = SQLiteMaskBindingLedger(tmp_path / "ledger.sqlite")
    session = NativeSession(native_binary, tmp_path / "native.log")
    previous, indices = {}, set()
    try:
        session.call("setup", {})
        for index in range(2):
            facts = None
            if index:
                transition = advance_publication(
                    state, PublicationWindow(0, 0.0, 1.0, workload.windows[0], 1, "test")
                )
                state = transition.state
                facts = transition.facts
                bundle = compile_bundle(state)
            publication, keys, previous = publication_payload(state, bundle, previous, facts)
            session.call("publish", publication)
            prepared = prepare_ordinary_query(
                bundle,
                query_id=f"augmentation-{index}",
                vector=workload.queries[0][0],
                modulus=MODULUS,
                ledger=ledger,
            )
            request = json.loads(build_ordinary_openfhe_query_request(bundle, prepared))
            required = {
                value for _, value in bundle.compiled.cloud_plan.program.rotation_catalog.entries
            }
            additional = required - indices
            assert additional  # The fixture must genuinely exercise augmentation.
            result = session.call(
                "query",
                {"publication_id": state.version_id, "value_keys": keys, "request": request},
            )
            assert result["new_rotation_keys"] == len(additional)
            verify_native_counts(bundle, result)
            verify_outputs(bundle, request, result, state.logical, workload.queries[0][0])
            indices |= required
        session.call("close", {})
        assert session.process.wait(timeout=5) == 0
    finally:
        session.close()
