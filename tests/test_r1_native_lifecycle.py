"""Cheap adapter tests; fake results are explicitly NOT native evidence."""

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

import dynamic_cssc.r1_native_lifecycle as lifecycle
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
    delta_lane_inventory,
    digest,
    engineering_workload,
    execute_cloud_plan,
    execute_compiled_query,
    initialize,
    metadata_roundtrip,
    prepare_ordinary_query,
    prepare_strong_query,
    publication_payload,
    receive_client_publication,
    reconstruct_client_output,
    role_metadata,
    validate_client_query,
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


def received_metadata(bundle, publication, keys):
    received, _ = metadata_roundtrip(role_metadata(bundle, publication["publication_id"], keys))
    publication["cloud_metadata"] = received[0]
    return receive_client_publication(received[1], received[0])


def query_payload(version, request, keys, query_id):
    return {
        "publication_id": version,
        "request": request,
        "value_keys": keys,
        "query_binding": {
            "query_id": query_id,
            "version_id": version,
            "execution_binding_digest": request["bindings"]["execution_binding_sha256"],
            "query_preparation_sha256": request["bindings"]["query_preparation_sha256"],
        },
    }


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


def test_wrong_exported_b_columns_reject_before_native_query(tmp_path, monkeypatch):
    original = lifecycle.role_metadata

    def wrong_export(*args):
        messages = original(*args)
        columns = next(iter(messages[1]["payload"]["query_columns"].values()))
        lane = next(i for i, column in enumerate(columns) if column >= 0)
        columns[lane] = (columns[lane] + 1) % 65
        return messages

    class NoQuerySession:
        def __init__(self, *_args):
            self.process = type("Process", (), {"pid": os.getpid()})()

        def call(self, op, payload):
            if op == "setup":
                return {}
            if op == "publish":
                changed = sum(value["reencrypt"] for value in payload["values"])
                return {
                    "matrix_encryptions": changed,
                    "matrix_reused": len(payload["values"]) - changed,
                    "wire_objects": [],
                }
            raise AssertionError("wrong received B columns reached native query")

        def close(self):
            pass

    monkeypatch.setattr(lifecycle, "role_metadata", wrong_export)
    with pytest.raises(ValueError, match="received B columns"):
        lifecycle.run_engineering_trace(
            engineering_workload(),
            "repack",
            Path("unused"),
            tmp_path / "trace",
            session_factory=NoQuerySession,
        )


def test_fixture_is_legal_disjoint_and_not_a_formal_entry_point():
    workload = engineering_workload()
    workload.validate()
    with pytest.raises(ValueError, match="declared workload domain"):
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
    received, receipts = metadata_roundtrip(messages)
    client = receive_client_publication(received[1], received[0])
    assert client.version_id == state.version_id
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
    publication, keys, _ = publication_payload(state, bundle, {}, None)
    client = received_metadata(bundle, publication, keys)
    validate_client_query(client, prepared, workload.queries[0][0])
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
    output = reconstruct_client_output(client, native["outputs"])
    verify_outputs(bundle, request, native, state.logical, workload.queries[0][0], output)
    assert len(output) == workload.rows
    native["outputs"][next(iter(expected))][-1] = 1
    with pytest.raises(ValueError, match="all-slot"):
        verify_outputs(bundle, request, native, state.logical, workload.queries[0][0], output)
    native["request_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="request digest"):
        verify_outputs(bundle, request, native, state.logical, workload.queries[0][0], output)


def test_received_output_plan_binding_rejects_wrong_mapping():
    state = initialize("repack", engineering_workload())
    bundle = compile_bundle(state)
    _, keys, _ = publication_payload(state, bundle, {}, None)
    received, _ = metadata_roundtrip(role_metadata(bundle, state.version_id, keys))
    received[1]["output_plan"]["shares"][0]["slot_to_logical"][0][1] = 15
    with pytest.raises(ValueError, match="output plan differs"):
        receive_client_publication(received[1], received[0])


def test_delta_inventory_separates_live_tombstone_and_unused():
    workload = engineering_workload()
    state = initialize("strong", workload)
    for index, updates in enumerate(workload.windows):
        state = advance_strong_publication(
            state, PublicationWindow(index, float(index), float(index + 1), updates, 1, "test")
        ).state
    state = advance_strong_publication(
        state, PublicationWindow(2, 2.0, 3.0, (NetUpdate(0, 61, 6, 0),), 1, "test")
    ).state
    counts = delta_lane_inventory(state)
    assert counts["live"] > 0 and counts["tombstone"] == 1 and counts["unused"] > 0
    assert counts["live"] + counts["tombstone"] + counts["unused"] == counts["page_capacity_lanes"]
    assert counts["allocated_segment_lanes"] + counts["unallocated_page_tail"] == 4096
    assert delta_lane_inventory(initialize("repack", workload))["page_capacity_lanes"] == 0


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
    state = initialize("repack", engineering_workload())
    bundle = compile_bundle(state)
    _, keys, _ = publication_payload(state, bundle, {}, None)
    assert len(keys) == 1
    keys = dict.fromkeys(keys, "signed")
    original = role_metadata(bundle, state.version_id, keys)[0]["payload"]

    def cloud_metadata(version):
        payload = deepcopy(original)
        payload["version_id"] = version
        payload["cloud_plan"]["binding"]["version_id"] = version
        return payload

    session = NativeSession(native_binary, tmp_path / "native.log")
    try:
        assert session.call("setup", {})["status"] == "pass"
        vector = [-2] + [0] * 4095
        first = session.call(
            "publish",
            {
                "publication_id": "v00000000",
                "cloud_metadata": cloud_metadata("v00000000"),
                "slot_count": 4096,
                "values": [{"cache_key": "signed", "values": vector, "reencrypt": True}],
            },
        )
        assert first["matrix_encryptions"] == 1
        second = session.call(
            "publish",
            {
                "publication_id": "v00000001",
                "cloud_metadata": cloud_metadata("v00000001"),
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
                    "cloud_metadata": cloud_metadata("v00000002"),
                    "slot_count": 4096,
                    "values": [{"cache_key": "signed", "values": vector, "reencrypt": False}],
                },
            )
    finally:
        session.close()
    assert "reuse of absent or changed matrix value" in (tmp_path / "native.log").read_text()


@pytest.mark.parametrize("failure", ["replay", "stale", "replacement-program", "query-binding"])
def test_native_query_binding_and_replay_rejection(tmp_path, native_binary, failure):
    workload = engineering_workload()
    state = initialize("repack", workload)
    bundle = compile_bundle(state)
    publication, keys, _ = publication_payload(state, bundle, {}, None)
    client = received_metadata(bundle, publication, keys)
    ledger = SQLiteMaskBindingLedger(tmp_path / "ledger.sqlite")
    prepared = prepare_ordinary_query(
        bundle,
        query_id="native-regression",
        vector=workload.queries[0][0],
        modulus=MODULUS,
        ledger=ledger,
    )
    request = json.loads(build_ordinary_openfhe_query_request(bundle, prepared))
    payload = query_payload(state.version_id, request, keys, prepared.query_id)
    session = NativeSession(native_binary, tmp_path / "native.log")
    try:
        session.call("setup", {})
        session.call("publish", publication)
        result = session.call("query", payload)
        output = reconstruct_client_output(client, result["outputs"])
        verify_outputs(bundle, request, result, state.logical, workload.queries[0][0], output)
        if failure == "stale":
            payload["publication_id"] = "wrong-version"
        elif failure == "replacement-program":
            # Internally consistent replacement: rehash program, binding and key
            # plan. Only the stored received publication is the external anchor.
            request["program"]["plaintext_masks"][0]["values"][0] ^= 1
            program_sha = digest(request["program"])
            request["bindings"]["cloud_program_sha256"] = program_sha
            request["bindings"]["execution_binding"]["cloud_program_digest"] = program_sha
            request["bindings"]["execution_binding_sha256"] = digest(
                request["bindings"]["execution_binding"]
            )
            key_plan = request["key_generation_plan"]["rotation_key_plan"]
            key_plan["source_cloud_program_sha256"] = program_sha
            request["key_generation_plan"]["rotation_key_plan_sha256"] = hashlib.sha256(
                canonical(key_plan) + b"\n"
            ).hexdigest()
            payload = query_payload(state.version_id, request, keys, prepared.query_id)
        elif failure == "query-binding":
            payload["query_binding"]["query_preparation_sha256"] = "0" * 64
        with pytest.raises(RuntimeError, match="native process failed"):
            session.call("query", payload)
    finally:
        session.close()
    expected = {
        "replay": "repeated query preparation",
        "stale": "publication binding mismatch",
        "replacement-program": "differs from received Cloud publication",
        "query-binding": "received query binding mismatch",
    }[failure]
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
            client = received_metadata(bundle, publication, keys)
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
                query_payload(state.version_id, request, keys, prepared.query_id),
            )
            assert result["new_rotation_keys"] == len(additional)
            verify_native_counts(bundle, result)
            output = reconstruct_client_output(client, result["outputs"])
            verify_outputs(bundle, request, result, state.logical, workload.queries[0][0], output)
            indices |= required
        session.call("close", {})
        assert session.process.wait(timeout=5) == 0
    finally:
        session.close()
