from __future__ import annotations

import hashlib
import json
from fractions import Fraction
from pathlib import Path

import pytest

import dynamic_cssc.route_a_openfhe_package as package_module
from dynamic_cssc.mask_ledger import SQLiteMaskBindingLedger
from dynamic_cssc.openfhe_query_runner import (
    OpenFHESerializedObjectReceipt,
    VerifiedRouteAOpenFHEProducerResult,
    build_ordinary_openfhe_query_request,
)
from dynamic_cssc.route_a_contract import RouteAEvaluationLane
from dynamic_cssc.route_a_native_case import (
    RouteANativeCasePlan,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_native_invocation import (
    authorize_route_a_native_invocation,
    claim_route_a_native_producer_capability,
    prepare_route_a_native_invocation,
    replay_route_a_native_invocation_read_only,
)
from dynamic_cssc.route_a_openfhe_package import (
    ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA,
    RouteAOpenFHEPackageError,
    build_route_a_openfhe_package,
    inspect_route_a_openfhe_package,
    read_route_a_openfhe_package_member,
)
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

ROOT = Path(__file__).resolve().parents[1]
MACHINE_PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
SHARD_ID = "8" * 64


@pytest.fixture(scope="module")
def ordinary_case() -> RouteANativeCasePlan:
    return compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id="periodic-repack/windows=1",
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _package(tmp_path: Path, members: tuple[tuple[str, str, bytes], ...]) -> Path:
    root = tmp_path / "package"
    root.mkdir()
    inventory: list[dict[str, object]] = []
    for ordinal, (role, subject_id, content) in enumerate(members):
        relative_path = f"member-{ordinal:06d}.bin"
        (root / relative_path).write_bytes(content)
        inventory.append(
            {
                "byte_count": len(content),
                "relative_path": relative_path,
                "role": role,
                "sha256": hashlib.sha256(content).hexdigest(),
                "subject_id": subject_id,
            }
        )
    content_by_role = {role: content for role, _subject_id, content in members}
    manifest = {
        "build_manifest_sha256": "a" * 64,
        "case_binding_sha256": hashlib.sha256(content_by_role["case-binding"]).hexdigest(),
        "formal_authority_granted": False,
        "lane_binding_sha256": hashlib.sha256(content_by_role["lane-binding"]).hexdigest(),
        "members": inventory,
        "publication_authority": False,
        "schema_version": ROUTE_A_OPENFHE_PACKAGE_MANIFEST_SCHEMA,
    }
    (root / "manifest.json").write_bytes(_canonical(manifest))
    return root


def _closed_members() -> tuple[tuple[str, str, bytes], ...]:
    return (
        ("authorization-receipt", "authorization-receipt", b"authorization"),
        ("canonical-request", "canonical-request", b"request"),
        ("case-binding", "case-binding", b"case-binding"),
        ("consumed-ledger", "consumed-ledger", b"SQLite format 3\x00ledger"),
        ("crypto-context", "crypto-context", b"context"),
        ("direct-oracle", "direct-oracle", b"direct"),
        ("evaluation-key-frame", "evaluation-key-material", b"D1BKEY01frame"),
        ("lane-binding", "lane-binding", b"lane-binding"),
        ("preparation", "preparation", b"preparation"),
        ("producer-result", "producer-result", b"producer-result"),
        ("public-key", "public-key", b"public-key"),
        ("secret-key", "secret-key", b"secret-key"),
        ("structural-vector", "structural-vector", b"structural"),
        ("typed-oracle", "typed-oracle", b"typed"),
        ("input-ciphertext", "input-0", b"input-ciphertext"),
        ("producer-result-ciphertext", "result-0", b"result-ciphertext"),
    )


def test_inspector_rehashes_one_closed_package(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        _closed_members(),
    )

    inspection = inspect_route_a_openfhe_package(root)

    assert inspection.build_manifest_sha256 == "a" * 64
    assert inspection.case_binding_sha256 == hashlib.sha256(b"case-binding").hexdigest()
    assert inspection.lane_binding_sha256 == hashlib.sha256(b"lane-binding").hexdigest()
    assert len(inspection.members) == len(_closed_members())
    assert inspection.manifest_sha256 == hashlib.sha256(inspection.manifest_bytes).hexdigest()


@pytest.mark.parametrize("mutation", ("member", "extra", "manifest-newline"))
def test_inspector_rejects_any_package_tree_change(
    tmp_path: Path,
    mutation: str,
) -> None:
    root = _package(tmp_path, _closed_members())
    if mutation == "member":
        (root / "member-000001.bin").write_bytes(b"changed")
    elif mutation == "extra":
        (root / "extra.bin").write_bytes(b"extra")
    else:
        manifest = root / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b"\n")

    with pytest.raises(RouteAOpenFHEPackageError):
        inspect_route_a_openfhe_package(root)


def test_inspector_rejects_duplicate_role_subject_identity(tmp_path: Path) -> None:
    root = _package(
        tmp_path,
        _closed_members() + (("input-ciphertext", "input-0", b"second"),),
    )

    with pytest.raises(RouteAOpenFHEPackageError, match="identity"):
        inspect_route_a_openfhe_package(root)


def test_inspector_rejects_boolean_byte_count(tmp_path: Path) -> None:
    root = _package(tmp_path, _closed_members())
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["members"][0]["byte_count"] = True
    manifest_path.write_bytes(_canonical(manifest))

    with pytest.raises(RouteAOpenFHEPackageError, match="identity"):
        inspect_route_a_openfhe_package(root)


def test_inspector_rejects_symlinked_member(tmp_path: Path) -> None:
    root = _package(tmp_path, _closed_members())
    member = root / "member-000001.bin"
    target = tmp_path / "target.bin"
    target.write_bytes(member.read_bytes())
    member.unlink()
    member.symlink_to(target)

    with pytest.raises(RouteAOpenFHEPackageError, match="unavailable"):
        inspect_route_a_openfhe_package(root)


def test_builder_installs_one_recorded_package_and_preserves_replay_lifecycle(
    ordinary_case: RouteANativeCasePlan,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lane = RouteAEvaluationLane.openfhe_recorded(
        shard_identity_sha256=SHARD_ID,
        strategy_candidate_id=ordinary_case.strategy_candidate_id,
        rho=Fraction(1),
        unit_attempt_ordinal=0,
        process_ordinal=2,
    )
    ledger_path = tmp_path / "producer-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_route_a_native_invocation(ordinary_case, lane, ledger=ledger)
    authorized = claim_route_a_native_producer_capability(
        authorize_route_a_native_invocation(prepared, ledger=ledger)
    )
    request_bytes = build_ordinary_openfhe_query_request(
        ordinary_case.execution_bundle,
        prepared.prepared_query,
    )
    request = json.loads(request_bytes)
    subjects = [
        "crypto-context",
        "secret-key",
        "public-key",
        "evaluation-key-material",
        *(item["ciphertext_id"] for item in request["ciphertext_values"]),
        *request["program"]["result_ids"],
    ]
    object_root = tmp_path / "producer-objects"
    object_root.mkdir()
    receipts: list[OpenFHESerializedObjectReceipt] = []
    for ordinal, subject_id in enumerate(subjects):
        relative_path = f"object-{ordinal:06d}.bin"
        content = f"producer-object-{ordinal}".encode()
        (object_root / relative_path).write_bytes(content)
        receipts.append(
            OpenFHESerializedObjectReceipt(
                category="test-category",
                subject_id=subject_id,
                relative_path=relative_path,
                byte_count=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    fake_verified = VerifiedRouteAOpenFHEProducerResult(
        request_sha256=hashlib.sha256(request_bytes).hexdigest(),
        cloud_program_operation_inventory=(),
        lifecycle_operation_inventory=(),
        decrypted_results=(),
        reconstructed_output=authorized.typed_oracle_output,
        key_material_receipt=None,  # type: ignore[arg-type]
        serialized_objects=tuple(receipts),
        second_batch_row_zero=True,
        publication_authority=False,
    )
    monkeypatch.setattr(
        package_module,
        "_verified_producer",
        lambda *_args, **_kwargs: fake_verified,
    )
    producer_result_path = tmp_path / "producer-result.json"
    producer_result_path.write_bytes(b"producer-result")
    package_root = tmp_path / "retained-package"

    inspection = build_route_a_openfhe_package(
        authorized,
        request_bytes=request_bytes,
        producer_result_path=producer_result_path,
        producer_object_root=object_root,
        build_manifest_sha256="f" * 64,
        output_directory=package_root,
    )

    assert inspection == inspect_route_a_openfhe_package(package_root)
    assert inspection.build_manifest_sha256 == "f" * 64
    assert {member.role for member in inspection.members} == {
        "authorization-receipt",
        "canonical-request",
        "case-binding",
        "consumed-ledger",
        "crypto-context",
        "direct-oracle",
        "evaluation-key-frame",
        "input-ciphertext",
        "lane-binding",
        "preparation",
        "producer-result",
        "producer-result-ciphertext",
        "public-key",
        "secret-key",
        "structural-vector",
        "typed-oracle",
    }
    consumed = next(member for member in inspection.members if member.role == "consumed-ledger")
    replay = replay_route_a_native_invocation_read_only(
        ordinary_case,
        lane,
        preparation_bytes=read_route_a_openfhe_package_member(inspection, role="preparation"),
        authorization_receipt_bytes=read_route_a_openfhe_package_member(
            inspection, role="authorization-receipt"
        ),
        consumed_ledger_path=package_root / consumed.relative_path,
    )
    assert replay.ledger_snapshot_sha256 == authorized.consumed_ledger_snapshot_sha256
