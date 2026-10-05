"""Persistent, full-trace native *engineering* harness for the R1 supplement.

Not an admission interface, not a rerun of Route A, and not a network deployment.
The parent retains private test inputs; only typed role-permitted messages count
as wire payloads. All validation/oracle/IPC costs remain in whole-trace elapsed.
"""

from __future__ import annotations

import hashlib
import json
import os
import resource
import signal
import subprocess
import threading
import time
from collections import Counter
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dynamic_cssc.cloud_execution_plan import canonical_cloud_visible_payload
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    _expected_operation_counts,
    build_ordinary_openfhe_query_request,
    build_strong_openfhe_query_request,
)
from dynamic_cssc.ordinary_query_lifecycle import (
    OrdinaryExecutionBundle,
    authorize_ordinary_execution,
    bind_ordinary_execution,
    claim_ordinary_execution,
    prepare_ordinary_query,
)
from dynamic_cssc.output_plan import OutputPlan, OutputShare, canonical_output_plan_payload
from dynamic_cssc.plaintext_oracle import (
    direct_spmv,
    execute_cloud_plan,
    execute_compiled_query,
    reconstruct_output,
)
from dynamic_cssc.query_compiler import compile_query
from dynamic_cssc.strategy_state import (
    StrategyState,
    StrongStrategyState,
    TransitionFacts,
    advance_publication,
    advance_strong_publication,
    initialize_strategy,
    initialize_strong_strategy,
)
from dynamic_cssc.strong_execution import (
    StrongExecutionBundle,
    authorize_strong_execution,
    claim_strong_execution,
    compile_strong_execution,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import cloud_page_shapes

SCHEMA = "r1-native-engineering-v1"
MODULUS = 65537
SLOTS = 4096
STRATEGIES = ("repack", "padding", "strong")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Workload:
    identity: str
    rows: int
    cols: int
    initial: tuple[tuple[int, int, int], ...]
    windows: tuple[tuple[NetUpdate, ...], ...]
    queries: tuple[tuple[tuple[int, ...], ...], ...]

    def validate(self) -> None:
        if not self.identity.startswith("engineering-disjoint-"):
            raise ValueError("this unfrozen runner accepts engineering workloads only")
        if len(self.windows) != len(self.queries) or not self.windows:
            raise ValueError("one nonempty query group is required per publication")
        state = {(r, c): v for r, c, v in self.initial}
        if len(state) != len(self.initial):
            raise ValueError("duplicate initial coordinate")
        for (r, c), v in state.items():
            if not (0 <= r < self.rows and 0 <= c < self.cols and 0 < abs(v) <= 7):
                raise ValueError("invalid initial coordinate or value")
        for updates, queries in zip(self.windows, self.queries, strict=True):
            seen = set()
            for u in updates:
                key = u.row, u.col
                if key in seen or state.get(key, 0) != u.before or u.before == u.after:
                    raise ValueError("invalid, duplicate or cancelling update")
                if not (0 <= u.row < self.rows and 0 <= u.col < self.cols and abs(u.after) <= 7):
                    raise ValueError("update outside domain")
                seen.add(key)
                if u.after:
                    state[key] = u.after
                else:
                    del state[key]
            if not updates or not queries:
                raise ValueError("empty engineering window")
            if any(len(q) != self.cols or any(type(v) is not int for v in q) for q in queries):
                raise ValueError("invalid query vector")


def engineering_workload() -> Workload:
    """Hand-written disjoint fixture; no formal seed or prior-study input is used."""
    rows, cols = 16, 65
    initial = tuple(
        (r, c, -2 if (r, c) == (15, 31) else 2) for r in range(rows) for c in (r, r + 16)
    )
    windows = (
        (
            NetUpdate(0, 0, 2, 3),
            NetUpdate(1, 1, 2, 0),
            NetUpdate(1, 60, 0, 4),
            NetUpdate(0, 61, 0, 5),
        ),
        (
            NetUpdate(0, 61, 5, 6),
            NetUpdate(0, 16, 2, 0),
            NetUpdate(0, 62, 0, 3),
            NetUpdate(2, 63, 0, 1),
        ),
    )
    queries = tuple(
        tuple(tuple((c + w + j) % 7 - 3 for c in range(cols)) for j in range(2)) for w in range(2)
    )
    return Workload(
        "engineering-disjoint-handwritten-20261005-a", rows, cols, initial, windows, queries
    )


class NativeSession:
    """One process/context/key set, with no implicit retries or per-query relaunch."""

    def __init__(self, executable: Path, stderr_path: Path):
        self.stderr_path = stderr_path
        self.stderr = stderr_path.open("xb")
        self.process = subprocess.Popen(
            [str(executable), "--r1-lifecycle", "engineering-v1"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            env={**os.environ, "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1"},
        )
        self.sequence = 0

    def call(self, op: str, payload: dict) -> dict:
        command = {
            "schema_version": "r1-native-engineering-command-v1",
            "sequence": self.sequence,
            "op": op,
            "payload": payload,
        }
        wire = canonical(command)
        if len(wire) > 128 * 1024 * 1024:
            raise ValueError("private IPC frame too large")
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(wire + b"\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline(128 * 1024 * 1024 + 1)
        if not line.endswith(b"\n") or len(line) > 128 * 1024 * 1024:
            # The runner emits only exception diagnostics, never private request
            # frames. Preserve the complete log, but bound the exception excerpt.
            with self.stderr_path.open("rb") as diagnostic:
                detail = diagnostic.read(4096).decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                "native process failed or returned an unbounded frame"
                + (f": {detail}" if detail else "; see native stderr log")
            )
        result = json.loads(line)
        if (
            result.get("schema_version") != "r1-native-engineering-receipt-v1"
            or result.get("sequence") != self.sequence
            or result.get("op") != op
            or result.get("status") != "pass"
        ):
            raise ValueError("native receipt identity/status mismatch")
        self.sequence += 1
        # Private IPC is timed, but deliberately NOT counted as a protocol message.
        result["private_ipc_request_bytes"] = len(wire) + 1
        result["private_ipc_response_bytes"] = len(line)
        return result

    def close(self) -> None:
        try:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe:
                    pipe.close()
            self.stderr.close()


class TraceResourceSampler:
    """Non-atomic Linux RSS/disk samples: estimates, not guaranteed peak bounds."""

    def __init__(self, native_pid: int, directory: Path):
        self.pids = (os.getpid(), native_pid)
        self.directory = directory
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.peak_sum_rss_kib = 0
        self.peak_disk_bytes = 0
        self.samples = 0
        self.error = None
        self.thread.start()

    def _loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                rss = 0
                for pid in self.pids:
                    try:
                        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                            if line.startswith("VmRSS:"):
                                rss += int(line.split()[1])
                    except FileNotFoundError:
                        pass  # Native exit is expected at the final sample.
                disk = 0
                for path in self.directory.iterdir():
                    # SQLite may remove a journal between enumeration/stat.
                    with suppress(FileNotFoundError):
                        disk += path.stat().st_size
                self.peak_sum_rss_kib = max(self.peak_sum_rss_kib, rss)
                self.peak_disk_bytes = max(self.peak_disk_bytes, disk)
                self.samples += 1
                self.stop_event.wait(0.1)
        except Exception as error:
            self.error = error

    def close(self) -> dict:
        self.stop_event.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive() or self.error is not None:
            raise RuntimeError("resource sampling failed") from self.error
        return {
            "sample_interval_seconds": 0.1,
            "sample_count": self.samples,
            "peak_observed_sum_rss_kib": self.peak_sum_rss_kib,
            "peak_observed_harness_disk_bytes": self.peak_disk_bytes,
            "scope": (
                "Linux /proc Python+native RSS and trace files; non-atomic sampled sums, "
                "not a guaranteed simultaneous-peak bound"
            ),
        }


def initialize(strategy: str, workload: Workload) -> StrategyState | StrongStrategyState:
    args = dict(
        rows=workload.rows,
        cols=workload.cols,
        effective_slots=SLOTS,
        partition_rows=workload.rows,
        reserved_slack_beta=0.0,
    )
    initial = {(r, c): v for r, c, v in workload.initial}
    if strategy == "strong":
        return initialize_strong_strategy(initial, **args, segment_width=128)
    if strategy not in STRATEGIES:
        raise ValueError("unknown strategy")
    return initialize_strategy(
        "PeriodicRepack" if strategy == "repack" else "PaddingReuse-CSSC",
        initial,
        **args,
        periodic_repack_windows=1,
    )


def compile_bundle(state, transition=None):
    if isinstance(state, StrongStrategyState):
        if transition is not None and transition.execution_bundle is not None:
            return transition.execution_bundle
        return compile_strong_execution(state.base, state.delta)
    return bind_ordinary_execution(compile_query((state.base,)))


def bundle_parts(bundle):
    if isinstance(bundle, OrdinaryExecutionBundle):
        b = bundle.compiled
        return b.cloud_plan, b.output_plan, b.operand_specs, b.result_routes
    return bundle.cloud_plan, bundle.output_plan, bundle.value_operand_specs, bundle.result_routes


def publication_payload(state, bundle, prior: dict[str, str], facts: TransitionFacts | None):
    """Bind program operands to stable physical pages, never to terminal SSA IDs."""
    _, _, specs, _ = bundle_parts(bundle)
    base_chunks = [(block, chunk) for block in state.base.blocks for chunk in block.chunks]
    pages = cloud_page_shapes(state.delta) if isinstance(state, StrongStrategyState) else ()
    values, keys, fingerprints = [], {}, {}
    patched = set(facts.patched_chunk_ids) if facts else set()
    rebuilt = set(facts.rebuilt_output_block_ids) if facts else set()
    for spec in specs:
        if spec.source_kind in {"published-chunk", "base-chunk"}:
            block, chunk = base_chunks[spec.source_ordinal]
            key = f"{state.base.component_id}/{block.output_block_id}/{chunk.chunk_id}"
            physical = (asdict(chunk), block.row_map)
            forced = (
                state.base.component_id,
                chunk.chunk_id,
            ) in patched or block.output_block_id in rebuilt
        else:
            page = pages[spec.source_ordinal]
            key = f"delta/{page.page_id}"
            physical = tuple(
                asdict(segment)
                for segment in state.delta.segments
                if segment.page_ordinal == spec.source_ordinal
            )
            forced = False
        fingerprint = digest(physical)
        fingerprints[key] = fingerprint
        keys[spec.value_ciphertext_id] = key
        values.append(
            {
                "cache_key": key,
                "values": list(spec.values),
                "reencrypt": forced or prior.get(key) != fingerprint,
            }
        )
    if len(keys) != len(fingerprints):
        raise ValueError("non-bijective physical value binding")
    return (
        {"publication_id": state.version_id, "slot_count": SLOTS, "values": values},
        keys,
        fingerprints,
    )


def role_metadata(bundle, version: str, value_keys: dict[str, str]) -> tuple[dict, ...]:
    """Full snapshots, not hypothetical patches; A->B has no values/mask samples."""
    cloud, output, specs, routes = bundle_parts(bundle)
    return (
        {
            "direction": "A->Cloud",
            "kind": "publication-program",
            "payload": {
                "version_id": version,
                "value_bindings": value_keys,
                "cloud_plan": canonical_cloud_visible_payload(cloud),
            },
        },
        {
            "direction": "A->B",
            "kind": "private-query-and-reconstruction-metadata",
            "payload": {
                "version_id": version,
                "output_plan": canonical_output_plan_payload(output),
                "query_columns": {
                    s.query_ciphertext_id: list(s.global_column_indices) for s in specs
                },
                "routes": [
                    {
                        "result_id": r.result_id,
                        "component_id": r.component_id,
                        "output_block_id": r.output_block_id,
                    }
                    for r in routes
                ],
            },
        },
    )


def metadata_roundtrip(messages) -> tuple[tuple[dict, ...], list[dict]]:
    received, receipts = [], []
    for message in messages:
        wire = canonical(message["payload"])
        decoded = json.loads(wire)
        if decoded != message["payload"]:
            raise ValueError("metadata serialization roundtrip failed")
        received.append(decoded)
        receipts.append(
            {
                "direction": message["direction"],
                "kind": message["kind"],
                "bytes": len(wire),
                "sha256": hashlib.sha256(wire).hexdigest(),
            }
        )
    return tuple(received), receipts


@dataclass(frozen=True)
class ClientPublication:
    """B's received columns and reconstruction map, containing no A operands."""

    version_id: str
    query_columns: tuple[tuple[str, tuple[int, ...]], ...]
    output_plan: OutputPlan
    routes: tuple[tuple[str, str, str], ...]


def receive_client_publication(payload: dict, cloud: dict) -> ClientPublication:
    if set(payload) != {"version_id", "query_columns", "output_plan", "routes"}:
        raise ValueError("received B metadata keys changed")
    if payload["version_id"] != cloud["version_id"]:
        raise ValueError("received B publication version mismatch")
    raw_plan = payload["output_plan"]
    plan = OutputPlan(
        logical_output_size=raw_plan["logical_output_size"],
        slot_count=raw_plan["slot_count"],
        shares=tuple(
            OutputShare(
                s["component_id"],
                s["output_block_id"],
                tuple(tuple(pair) for pair in s["slot_to_logical"]),
            )
            for s in raw_plan["shares"]
        ),
    )
    if (
        canonical_output_plan_payload(plan) != raw_plan
        or digest(raw_plan) != cloud["cloud_plan"]["binding"]["output_plan_digest"]
    ):
        raise ValueError("received B output plan differs from published binding")
    columns = tuple((key, tuple(value)) for key, value in sorted(payload["query_columns"].items()))
    query_ids = {
        item["ciphertext_id"]
        for item in cloud["cloud_plan"]["program"]["ciphertext_inputs"]
        if item["role"] == "query"
    }
    if {key for key, _ in columns} != query_ids or any(
        len(values) != plan.slot_count or any(type(c) is not int or c < -1 for c in values)
        for _, values in columns
    ):
        raise ValueError("received B columns do not cover the published query operands")
    if any(set(r) != {"result_id", "component_id", "output_block_id"} for r in payload["routes"]):
        raise ValueError("received B route keys changed")
    routes = tuple(
        (r["result_id"], r["component_id"], r["output_block_id"]) for r in payload["routes"]
    )
    result_ids = set(cloud["cloud_plan"]["program"]["result_ids"])
    share_ids = {(s.component_id, s.output_block_id) for s in plan.shares}
    if (
        len(routes) != len(result_ids)
        or {r[0] for r in routes} != result_ids
        or len(routes) != len(share_ids)
        or {(r[1], r[2]) for r in routes} != share_ids
    ):
        raise ValueError("received B routes are not a published-result/share bijection")
    return ClientPublication(payload["version_id"], columns, plan, routes)


def validate_client_query(client: ClientPublication, prepared, vector: tuple) -> None:
    """Consume received columns before any native call; do not use private specs."""
    actual = {
        operand.ciphertext_id: tuple(v % MODULUS for v in operand.values)
        for operand in prepared.query_operands
    }
    if client.version_id != prepared.version_id or len(actual) != len(prepared.query_operands):
        raise ValueError("received B query identity mismatch")
    expected = {}
    for key, columns in client.query_columns:
        if any(column >= len(vector) for column in columns):
            raise ValueError("received B columns exceed query vector")
        expected[key] = tuple(vector[c] % MODULUS if c >= 0 else 0 for c in columns)
    if actual != expected:
        raise ValueError("received B columns disagree with aligned query operands")


def reconstruct_client_output(client: ClientPublication, outputs: dict) -> tuple:
    if set(outputs) != {route[0] for route in client.routes}:
        raise ValueError("received B result identifiers differ from received routes")
    shares = {
        (component, block): tuple(outputs[result]) for result, component, block in client.routes
    }
    return reconstruct_output(client.output_plan, shares, modulus=MODULUS)


def delta_lane_inventory(state) -> dict[str, int]:
    segments = state.delta.segments if isinstance(state, StrongStrategyState) else ()
    capacity = len(cloud_page_shapes(state.delta)) * SLOTS if segments else 0
    live = sum(entry is not None and entry.value != 0 for s in segments for entry in s.entries)
    tombstones = sum(
        entry is not None and entry.value == 0 for s in segments for entry in s.entries
    )
    empty = sum(entry is None for s in segments for entry in s.entries)
    allocated = sum(len(segment.entries) for segment in segments)
    tail = capacity - allocated
    if tail < 0 or live + tombstones + empty != allocated:
        raise ValueError("terminal delta lane inventory does not reconcile")
    return {
        "live": live,
        "tombstone": tombstones,
        "unused": empty + tail,
        "allocated_segment_lanes": allocated,
        "unallocated_page_tail": tail,
        "page_capacity_lanes": capacity,
    }


def verify_outputs(
    bundle, request: dict, native: dict, logical: dict, vector: tuple, reconstructed: tuple
) -> None:
    """Pure verification; required B reconstruction is timed separately."""
    cloud, output_plan, _, _ = bundle_parts(bundle)
    if native["request_sha256"] != digest(request):
        raise ValueError("native request digest mismatch")
    args = dict(
        ciphertext_inputs={
            v["ciphertext_id"]: tuple(v["values"]) for v in request["ciphertext_values"]
        },
        plaintext_masks={m.mask_id: m.values for m in cloud.program.plaintext_masks},
        modulus=MODULUS,
    )
    if isinstance(bundle, OrdinaryExecutionBundle):
        expected = execute_compiled_query(
            bundle.compiled, expected_f1m_policy="overlap-only", **args
        )
    else:
        expected = execute_cloud_plan(cloud, **args)
    actual = {key: tuple(values) for key, values in native["outputs"].items()}
    if actual != expected:
        raise ValueError("native all-slot plaintext DAG oracle mismatch")
    direct = direct_spmv(
        logical, vector, rows=output_plan.logical_output_size, cols=len(vector), modulus=MODULUS
    )
    if reconstructed != direct:
        raise ValueError("native independent logical SpMV oracle mismatch")


def verify_native_counts(bundle, native: dict) -> None:
    cloud, _, _, _ = bundle_parts(bundle)
    expected = _expected_operation_counts(cloud.program)
    encryptions = expected.pop("encrypt") - sum(
        operand.role == "value" for operand in cloud.program.ciphertext_inputs
    )
    decryptions = expected.pop("decrypt")
    if (
        native["operations"] != expected
        or native["query_encryptions"] != encryptions
        or native["decryptions"] != decryptions
    ):
        raise ValueError("native operation counts disagree with typed complete query")


def run_engineering_trace(
    workload: Workload,
    strategy: str,
    executable: Path,
    output_dir: Path,
    *,
    timeout_seconds: int = 600,
    session_factory=NativeSession,
) -> dict[str, Any]:
    """One complete trace, bounded externally by an alarm as well as the CI job."""
    start = time.perf_counter_ns()
    workload.validate()
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("engineering trace limit outside 1..3600 seconds")
    output_dir.mkdir(parents=True, exist_ok=False)
    session = None
    sampler = None
    previous_alarm = signal.getsignal(signal.SIGALRM)

    def timed_out(_signum, _frame):
        raise TimeoutError("bounded R1 engineering trace expired")

    signal.signal(signal.SIGALRM, timed_out)
    signal.alarm(timeout_seconds)
    try:
        log = (output_dir / "events.jsonl").open("xb")
        with log:

            def record(value):
                log.write(canonical(value) + b"\n")
                log.flush()

            session = session_factory(executable, output_dir / "native-stderr.log")
            if os.uname().sysname == "Linux":
                sampler = TraceResourceSampler(session.process.pid, output_dir)
            record({"phase": "setup", "native": session.call("setup", {})})
            initial_start = time.perf_counter_ns()
            state = initialize(strategy, workload)
            ledger = SQLiteMaskBindingLedger(output_dir / "private-mask-ledger.sqlite")
            previous, tokens, random_masks = {}, set(), set()
            random_batch_draws = 0
            coincident_random_batches = 0
            bundle = compile_bundle(state)

            def publish(current, current_bundle, facts):
                nonlocal previous
                payload, value_keys, fingerprints = publication_payload(
                    current, current_bundle, previous, facts
                )
                received, metadata = metadata_roundtrip(
                    role_metadata(current_bundle, current.version_id, value_keys)
                )
                cloud_metadata, client_metadata = received
                client = receive_client_publication(client_metadata, cloud_metadata)
                payload["cloud_metadata"] = cloud_metadata
                native = session.call("publish", payload)
                count = sum(value["reencrypt"] for value in payload["values"])
                if (
                    native["matrix_encryptions"] != count
                    or native["matrix_reused"] != len(payload["values"]) - count
                ):
                    raise ValueError("native publication counts disagree with physical dirty pages")
                previous = fingerprints
                native["wire_objects"].extend(metadata)
                return native, value_keys, client

            native, keys, client = publish(state, bundle, None)
            record(
                {
                    "phase": "initial-publication",
                    "native": native,
                    "elapsed_ns": time.perf_counter_ns() - initial_start,
                }
            )
            initial_complete_ns = time.perf_counter_ns() - start
            for wi, (updates, queries) in enumerate(
                zip(workload.windows, workload.queries, strict=True)
            ):
                publication_start = time.perf_counter_ns()
                window = PublicationWindow(
                    wi, float(wi), float(wi + 1), updates, len(queries), "r1-engineering"
                )
                transition = (
                    advance_strong_publication(state, window)
                    if strategy == "strong"
                    else advance_publication(state, window)
                )
                state = transition.state
                bundle = compile_bundle(state, transition)
                native, keys, client = publish(state, bundle, transition.facts)
                record(
                    {
                        "phase": "publication",
                        "window": wi,
                        "native": native,
                        "facts": asdict(transition.facts),
                        "elapsed_ns": time.perf_counter_ns() - publication_start,
                    }
                )
                for qi, vector in enumerate(queries):
                    query_start = time.perf_counter_ns()
                    strong = isinstance(bundle, StrongExecutionBundle)
                    prepare = prepare_strong_query if strong else prepare_ordinary_query
                    prepared = prepare(
                        bundle,
                        query_id=f"r1-w{wi}-q{qi}",
                        vector=vector,
                        modulus=MODULUS,
                        ledger=ledger,
                    )
                    validate_client_query(client, prepared, vector)
                    if prepared.ledger_commitment_token in tokens:
                        raise ValueError("ledger commitment token reused")
                    tokens.add(prepared.ledger_commitment_token)
                    # Whole random batches, not individual masks: opposite masks may
                    # legitimately coincide within a zero-sum batch; dummies are zero.
                    batch = [m.values for m in prepared.f1m_operands if m.kind == "random-zero-sum"]
                    if batch:
                        random_batch_draws += 1
                        batch_hash = digest(batch)
                        if batch_hash in random_masks:
                            # Independent uniform draws can coincide. Equality is
                            # not evidence of replay; single-use query bindings are.
                            coincident_random_batches += 1
                        random_masks.add(batch_hash)
                    builder = (
                        build_strong_openfhe_query_request
                        if strong
                        else build_ordinary_openfhe_query_request
                    )
                    request = json.loads(builder(bundle, prepared))
                    authorize = (
                        authorize_strong_execution if strong else authorize_ordinary_execution
                    )
                    claim = claim_strong_execution if strong else claim_ordinary_execution
                    authorization = claim(
                        authorize(bundle, prepared, ledger=ledger), bundle, prepared
                    )
                    received_control, control = metadata_roundtrip(
                        (
                            {
                                "direction": "B->Cloud",
                                "kind": "query-binding",
                                "payload": {
                                    "query_id": prepared.query_id,
                                    "version_id": state.version_id,
                                    "execution_binding_digest": (
                                        authorization.execution_binding_digest
                                    ),
                                    "query_preparation_sha256": request["bindings"][
                                        "query_preparation_sha256"
                                    ],
                                },
                            },
                        )
                    )
                    preparation_ns = time.perf_counter_ns() - query_start
                    native = session.call(
                        "query",
                        {
                            "publication_id": state.version_id,
                            "value_keys": keys,
                            "request": request,
                            "query_binding": received_control[0],
                        },
                    )
                    verify_native_counts(bundle, native)
                    reconstruction_start = time.perf_counter_ns()
                    output = reconstruct_client_output(client, native["outputs"])
                    reconstruction_ns = time.perf_counter_ns() - reconstruction_start
                    oracle_start = time.perf_counter_ns()
                    verify_outputs(bundle, request, native, state.logical, vector, output)
                    oracle_ns = time.perf_counter_ns() - oracle_start
                    native["all_slot_output_sha256"] = digest(native.pop("outputs"))
                    native["wire_objects"].extend(control)
                    record(
                        {
                            "phase": "query",
                            "window": wi,
                            "query": qi,
                            "native": native,
                            "preparation_ns": preparation_ns,
                            "reconstruction_ns": reconstruction_ns,
                            "oracle_ns": oracle_ns,
                            "elapsed_ns": time.perf_counter_ns() - query_start,
                            "all_slots_and_direct_oracle": "pass",
                            "output": list(output),
                            "query_vector_sha256": digest(vector),
                        }
                    )
            closing_receipt = session.call("close", {})
            record({"phase": "close", "native": closing_receipt})
            if session.process.wait(timeout=5) != 0:
                raise RuntimeError("native process exited unsuccessfully")
            session.close()
            session = None
            sampling = (
                sampler.close() if sampler is not None else {"scope": "unavailable off Linux"}
            )
            sampler = None
            total_ns = time.perf_counter_ns() - start
            lanes = Counter(lane for chunk in state.base.chunks for lane in chunk.slot_kinds)
            result = {
                "schema_version": SCHEMA,
                "evidence_class": "engineering-sentinel",
                "formal_authority": False,
                "strategy": strategy,
                "workload_sha256": digest(asdict(workload)),
                "workload_identity": workload.identity,
                "status": "pass",
                "whole_process_ns": total_ns,
                "initial_setup_and_publication_ns": initial_complete_ns,
                "post_initial_lifecycle_ns": total_ns - initial_complete_ns,
                "complete_queries": sum(len(q) for q in workload.queries),
                "terminal_base_lane_inventory": dict(lanes),
                "terminal_delta_lane_inventory": delta_lane_inventory(state),
                "terminal_delta_pages": len(cloud_page_shapes(state.delta))
                if strategy == "strong"
                else 0,
                "terminal_delta_segments": len(state.delta.segments) if strategy == "strong" else 0,
                "ledger_bytes": (output_dir / "private-mask-ledger.sqlite").stat().st_size,
                "consumed_query_batches": len(tokens),
                "random_batch_draws": random_batch_draws,
                "distinct_random_batch_digests": len(random_masks),
                "coincident_independently_prepared_batches": coincident_random_batches,
                "python_peak_rss_platform_units": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss,
                "rss_units": (
                    "KiB on Linux; bytes on macOS; separate process peaks, not simultaneous sum"
                ),
                "resource_samples": sampling,
                "native_peak_rss_platform_units": closing_receipt["native_peak_rss_platform_units"],
                "sum_of_observed_process_rss_high_water_marks_platform_units": (
                    resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                    + closing_receipt["native_peak_rss_platform_units"]
                ),
                "rss_high_water_scope": (
                    "native sampled before closing-receipt output/exit; Python sampled "
                    "after native exit before summary; not a full-lifetime peak upper bound"
                ),
                "timing_scope": (
                    "setup through native close; includes Python, IPC, validation, "
                    "oracle, ledger and event logging; excludes input generation "
                    "and terminal-summary preparation/serialization"
                ),
            }
            record({"phase": "summary", **result})
            return result
    finally:
        if session is not None:
            session.close()
        if sampler is not None:
            sampler.close()
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
