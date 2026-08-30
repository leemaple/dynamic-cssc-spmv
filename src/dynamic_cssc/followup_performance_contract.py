"""Closed Stage-1 and outer-evidence contract for the follow-up study.

This module deliberately does not generate a workload, query vector, snapshot,
or result cell.  Registered seeds are parsed only as opaque JSON scalars while
the Stage-2 source is being built and tested.  Scientific execution modules may
issue an inner admission only after their role-specific validator has accepted
fresh follow-up bytes; raw predecessor objects never enter the outer decoder.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

__all__ = (
    "FOLLOWUP_ARTIFACT_PREFIX",
    "FOLLOWUP_BASELINE_SHA256",
    "FOLLOWUP_ENVELOPE_SCHEMA",
    "FOLLOWUP_STAGE1_COMMIT_SHA",
    "FOLLOWUP_STAGE1_MANIFEST_SHA256",
    "FOLLOWUP_STAGE1_PLAN_SHA256",
    "FOLLOWUP_STUDY_ID",
    "FollowupContractError",
    "FollowupEvidenceEnvelope",
    "FollowupScientificPlan",
    "FollowupStage1Inspection",
    "admit_followup_control_inner_payload",
    "build_followup_unit_identity",
    "followup_artifact_name",
    "followup_inherited_unit_attempt_ordinal",
    "inspect_followup_outer_envelope",
    "inspect_followup_stage1",
    "materialize_followup_scientific_plan",
    "seal_followup_inner_payload",
)

FOLLOWUP_STUDY_ID: Final = "dynamic-cssc-followup-performance-2026-08-30"
FOLLOWUP_STAGE1_COMMIT_SHA: Final = "5421cecda19be559ba1c25297dd66c2634489c39"
FOLLOWUP_STAGE1_PLAN_SHA256: Final = (
    "a4600fbcbf630ab3a11e5004511f6b449645021ea2553243ddda80ed69f3484c"
)
FOLLOWUP_STAGE1_MANIFEST_SHA256: Final = (
    "7e52a743d8df08a21ab5bb9b84b7b7f90d443ae8ae8dbfae37ee88b968c141b3"
)
FOLLOWUP_OBJECT_SET_SHA256: Final = (
    "e79c174adde762f515a1be69c56c83867b1b3ffa254ff6b356795d19a7f4b8f3"
)
FOLLOWUP_BASELINE_SHA256: Final = (
    "0d307169356a50cc75f6ad7ba1c018321c0693e185cde7f5f2e7fef472da8e0e"
)
FOLLOWUP_PREDECESSOR_PLAN_SHA256: Final = (
    "ce09c1c9c82032ba8439188ce20d4cd8d6310a386efbe2d436595fd779b7268c"
)
FOLLOWUP_PREDECESSOR_BASE_COMMIT: Final = (
    "4f328afc079b328c31f2e0790cb65cdf96fcc1d7"
)
FOLLOWUP_ENVELOPE_SCHEMA: Final = (
    "dynamic-cssc-followup-performance-evidence-envelope-v1"
)
FOLLOWUP_UNIT_IDENTITY_SCHEMA: Final = (
    "dynamic-cssc-followup-performance-unit-identity-v1"
)
FOLLOWUP_ARTIFACT_PREFIX: Final = "followup-performance-v1-"

_PLAN_PATH = "config/followup-performance-study.json"
_MANIFEST_PATH = "config/followup-performance-stage1-manifest.json"
_PREDECESSOR_PLAN_PATH = "config/route-a-publication-plan.json"
_PLAN_SCHEMA_PATH = "schemas/followup-performance-study-v1.schema.json"
_ENVELOPE_SCHEMA_PATH = "schemas/followup-performance-evidence-envelope-v1.schema.json"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_ARTIFACT_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")

_STAGE1_OBJECTS: Final = {
    "config/followup-performance-study.json": FOLLOWUP_STAGE1_PLAN_SHA256,
    "docs/paper/followup-performance-claim-ledger.md": (
        "02cd27744d5cb2bbcdc91ad1c8ecdba82c5ee566b0a22a97dc1617e6c5ff28fc"
    ),
    "docs/paper/followup-performance-preregistration.md": (
        "306bf17e1391ca181ed9f3ac2d81387f0eed6dfa9c6cc96413dea495b7162734"
    ),
    "docs/research/followup-performance-novelty-inheritance-review-2026-08-30.md": (
        "0fc36653cce4913c12474421da31a07068b143a53487e11a1c182514af75060c"
    ),
}

_UNIT_ROLES: Final = {
    "analysis": frozenset({"analysis"}),
    "control-ci": frozenset({"ci-provenance"}),
    "control-independent-review": frozenset({"independent-review"}),
    "control-pre-s1": frozenset({"pre-s1-resource-validation"}),
    "control-registration": frozenset({"descriptive-registration"}),
    "control-source-anchor": frozenset({"source-anchor"}),
    "formal-acquisition": frozenset({"formal-acquisition"}),
    "formal-aggregate": frozenset({"formal-aggregate"}),
    "formal-native": frozenset(
        {"formal-native-private-handoff", "formal-native-guarded-case"}
    ),
    "formal-ordered-event": frozenset(
        {"formal-ordered-event-private-handoff", "formal-ordered-event-guarded-shard"}
    ),
    "formal-synthetic": frozenset(
        {"formal-synthetic-private-handoff", "formal-synthetic-guarded-shard"}
    ),
    "formal-terminal-admission": frozenset({"formal-terminal-admission"}),
    "qualification-q1": frozenset({"simulator-private-handoff"}),
    "qualification-q2": frozenset({"simulator-guarded-receipt"}),
    "qualification-q3": frozenset({"native-private-handoff"}),
    "qualification-q4": frozenset({"native-guarded-receipt"}),
    "qualification-q5": frozenset({"combined-guard"}),
    "qualification-q6": frozenset({"postrun-admission"}),
}
_CONTROL_UNIT_KINDS: Final = frozenset(
    {
        "control-ci",
        "control-independent-review",
        "control-pre-s1",
        "control-registration",
        "control-source-anchor",
    }
)
_RETRY_ELIGIBLE_UNIT_KINDS: Final = frozenset(
    {"formal-acquisition", "formal-native", "formal-ordered-event", "formal-synthetic"}
)
_INNER_ADMISSION_SEAL = object()


class FollowupContractError(ValueError):
    """One Stage-1, outer-envelope, or predecessor-rejection check failed."""


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise FollowupContractError(f"JSON document contains duplicate key {key!r}")
        document[key] = value
    return document


def _contains_float(value: object) -> bool:
    if type(value) is float:
        return True
    if type(value) is list:
        return any(_contains_float(item) for item in value)
    if type(value) is dict:
        return any(_contains_float(item) for item in value.values())
    return False


def _parse_ascii_json(document_bytes: bytes, *, label: str) -> object:
    if type(document_bytes) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    try:
        value = json.loads(
            document_bytes.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                FollowupContractError(f"{label} contains non-finite {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FollowupContractError(f"{label} is not duplicate-free ASCII JSON") from error
    if _contains_float(value):
        raise FollowupContractError(f"{label} contains a JSON float")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    if _contains_float(value):
        raise FollowupContractError("follow-up canonical JSON forbids floats")
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise FollowupContractError("follow-up value is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _read_regular_file(root: Path, relative_path: str) -> bytes:
    path = root / relative_path
    try:
        status = path.lstat()
    except OSError as error:
        raise FollowupContractError(f"required file is unavailable: {relative_path}") from error
    if path.is_symlink() or not path.is_file() or status.st_nlink != 1:
        raise FollowupContractError(f"required file is not one owned regular file: {relative_path}")
    return path.read_bytes()


def _sha256(document_bytes: bytes) -> str:
    return hashlib.sha256(document_bytes).hexdigest()


def _json_pointer_tokens(pointer: object) -> tuple[str, ...]:
    if type(pointer) is not str or not pointer.startswith("/") or pointer == "/":
        raise FollowupContractError("registered value change has an invalid JSON pointer")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))


def _replace_json_pointer(
    document: object,
    pointer: object,
    expected: object,
    value: object,
) -> None:
    tokens = _json_pointer_tokens(pointer)
    parent = document
    for token in tokens[:-1]:
        if type(parent) is list:
            if not token.isdecimal() or int(token) >= len(parent):
                raise FollowupContractError("registered JSON pointer misses a list member")
            parent = parent[int(token)]
        elif type(parent) is dict and token in parent:
            parent = parent[token]
        else:
            raise FollowupContractError("registered JSON pointer misses an object member")
    leaf = tokens[-1]
    if type(parent) is list:
        if not leaf.isdecimal() or int(leaf) >= len(parent):
            raise FollowupContractError("registered JSON pointer misses its list leaf")
        index = int(leaf)
        observed = parent[index]
        if observed != expected or type(observed) is not type(expected):
            raise FollowupContractError("registered predecessor value differs at its JSON pointer")
        parent[index] = value
    elif type(parent) is dict and leaf in parent:
        observed = parent[leaf]
        if observed != expected or type(observed) is not type(expected):
            raise FollowupContractError("registered predecessor value differs at its JSON pointer")
        parent[leaf] = value
    else:
        raise FollowupContractError("registered JSON pointer misses its object leaf")


def _git_output(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.check_output(
            ("git", "-C", str(root), *arguments),
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise FollowupContractError("Git ancestry or immutable-blob validation failed") from error


@dataclass(frozen=True, slots=True)
class FollowupStage1Inspection:
    """Reproduced hashes for one exact immutable Stage-1 ancestor."""

    stage1_commit_sha: str
    stage1_plan_sha256: str
    stage1_manifest_sha256: str
    object_set_sha256: str
    predecessor_plan_sha256: str
    materialized_baseline_sha256: str
    registered_value_change_count: int
    predecessor_top_level_key_count: int


@dataclass(frozen=True, slots=True)
class FollowupScientificPlan:
    """Exact materialized inner plan plus its non-authorizing scalar profile."""

    machine_plan_bytes: bytes
    machine_plan_sha256: str
    scientific_profile: RouteAScientificProfile

    def __post_init__(self) -> None:
        if (
            type(self.machine_plan_bytes) is not bytes
            or _sha256(self.machine_plan_bytes) != self.machine_plan_sha256
            or self.machine_plan_sha256 != FOLLOWUP_BASELINE_SHA256
            or type(self.scientific_profile) is not RouteAScientificProfile
            or self.scientific_profile.machine_plan_sha256 != self.machine_plan_sha256
        ):
            raise FollowupContractError("materialized follow-up scientific plan is not closed")


def inspect_followup_stage1(repository_root: Path) -> FollowupStage1Inspection:
    """Validate exact Stage-1 blobs, schema const, baseline, and Git ancestry.

    The registered integers are never passed to an execution API here.  They are
    compared and hashed only as opaque values, as required by the observation
    embargo.
    """

    if not isinstance(repository_root, Path):
        raise TypeError("repository_root must be an exact pathlib.Path")
    root = repository_root.resolve(strict=True)
    if not root.is_dir():
        raise FollowupContractError("repository root is not a directory")

    plan_bytes = _read_regular_file(root, _PLAN_PATH)
    manifest_bytes = _read_regular_file(root, _MANIFEST_PATH)
    predecessor_bytes = _read_regular_file(root, _PREDECESSOR_PLAN_PATH)
    if _sha256(plan_bytes) != FOLLOWUP_STAGE1_PLAN_SHA256:
        raise FollowupContractError("follow-up Stage-1 plan bytes changed")
    if _sha256(manifest_bytes) != FOLLOWUP_STAGE1_MANIFEST_SHA256:
        raise FollowupContractError("follow-up Stage-1 manifest bytes changed")
    if _sha256(predecessor_bytes) != FOLLOWUP_PREDECESSOR_PLAN_SHA256:
        raise FollowupContractError("predecessor plan bytes changed")

    plan = _parse_ascii_json(plan_bytes, label="follow-up Stage-1 plan")
    manifest = _parse_ascii_json(manifest_bytes, label="follow-up Stage-1 manifest")
    predecessor = _parse_ascii_json(predecessor_bytes, label="predecessor plan")
    if type(plan) is not dict or type(manifest) is not dict or type(predecessor) is not dict:
        raise FollowupContractError("Stage-1 and predecessor plans must be JSON objects")

    schema = _parse_ascii_json(
        _read_regular_file(root, _PLAN_SCHEMA_PATH),
        label="follow-up study-plan schema",
    )
    if (
        type(schema) is not dict
        or set(schema) != {"$id", "$schema", "const", "description", "title"}
        or schema.get("const") != plan
    ):
        raise FollowupContractError("study-plan schema does not close the exact Stage-1 value")

    if (
        manifest.get("schema_version")
        != "dynamic-cssc-followup-performance-stage1-manifest-v1"
        or manifest.get("study_id") != FOLLOWUP_STUDY_ID
        or manifest.get("authority") is not False
        or manifest.get("base_commit") != FOLLOWUP_PREDECESSOR_BASE_COMMIT
        or manifest.get("object_set_sha256") != FOLLOWUP_OBJECT_SET_SHA256
        or set(manifest)
        != {
            "authority",
            "base_commit",
            "base_tree",
            "entry_order",
            "file_sha256_scope",
            "object_set_digest_algorithm",
            "object_set_sha256",
            "objects",
            "schema_version",
            "self_reference_rule",
            "state",
            "study_id",
        }
    ):
        raise FollowupContractError("Stage-1 manifest header is not the frozen closed value")
    objects = manifest.get("objects")
    if type(objects) is not list or len(objects) != len(_STAGE1_OBJECTS):
        raise FollowupContractError("Stage-1 manifest object count changed")
    observed_paths: list[str] = []
    for item in objects:
        if type(item) is not dict or set(item) != {
            "byte_count",
            "line_count",
            "path",
            "role",
            "sha256",
        }:
            raise FollowupContractError("Stage-1 manifest entry is open or malformed")
        relative_path = item["path"]
        if type(relative_path) is not str or relative_path not in _STAGE1_OBJECTS:
            raise FollowupContractError("Stage-1 manifest contains an unknown object")
        observed_paths.append(relative_path)
        payload = _read_regular_file(root, relative_path)
        if (
            item["sha256"] != _STAGE1_OBJECTS[relative_path]
            or _sha256(payload) != item["sha256"]
            or item["byte_count"] != len(payload)
            or item["line_count"] != payload.count(b"\n")
        ):
            raise FollowupContractError("Stage-1 manifest entry differs from exact bytes")
    if observed_paths != sorted(observed_paths, key=lambda path: path.encode("utf-8")):
        raise FollowupContractError("Stage-1 manifest path order changed")
    object_set_bytes = _canonical_json_bytes(objects)
    if _sha256(object_set_bytes) != FOLLOWUP_OBJECT_SET_SHA256:
        raise FollowupContractError("Stage-1 manifest objects-array digest changed")

    scientific = plan.get("scientific_contract")
    if type(scientific) is not dict:
        raise FollowupContractError("Stage-1 scientific contract is absent")
    changes = scientific.get("registered_value_changes")
    if type(changes) is not list or len(changes) != 5:
        raise FollowupContractError("registered value-change set is not the frozen five")
    materialized = json.loads(predecessor_bytes.decode("ascii"))
    for change in changes:
        if type(change) is not dict or set(change) != {"followup", "json_path", "predecessor"}:
            raise FollowupContractError("registered value-change record is open")
        _replace_json_pointer(
            materialized,
            change["json_path"],
            change["predecessor"],
            change["followup"],
        )
    materialized_bytes = _canonical_json_bytes(materialized)
    if (
        _sha256(materialized_bytes) != FOLLOWUP_BASELINE_SHA256
        or scientific.get("materialized_predecessor_baseline_sha256")
        != FOLLOWUP_BASELINE_SHA256
    ):
        raise FollowupContractError("materialized predecessor comparison baseline changed")
    disposition = scientific.get("base_top_level_disposition")
    if type(disposition) is not dict or set(disposition) != set(predecessor):
        raise FollowupContractError("predecessor top-level disposition is incomplete")

    head_sha = _git_output(root, "rev-parse", "HEAD").decode("ascii").strip()
    if _LOWER_GIT_SHA.fullmatch(head_sha) is None:
        raise FollowupContractError("repository HEAD is not one exact Git SHA")
    _git_output(root, "merge-base", "--is-ancestor", FOLLOWUP_STAGE1_COMMIT_SHA, head_sha)
    parent = _git_output(root, "rev-parse", f"{FOLLOWUP_STAGE1_COMMIT_SHA}^").decode().strip()
    if parent != FOLLOWUP_PREDECESSOR_BASE_COMMIT:
        raise FollowupContractError("immutable Stage-1 commit does not have the exact base parent")
    for relative_path, expected_sha256 in {
        **_STAGE1_OBJECTS,
        _MANIFEST_PATH: FOLLOWUP_STAGE1_MANIFEST_SHA256,
    }.items():
        blob = _git_output(root, "show", f"{FOLLOWUP_STAGE1_COMMIT_SHA}:{relative_path}")
        if _sha256(blob) != expected_sha256:
            raise FollowupContractError("immutable Stage-1 Git blob differs from reviewed bytes")

    envelope_schema = _parse_ascii_json(
        _read_regular_file(root, _ENVELOPE_SCHEMA_PATH),
        label="follow-up evidence-envelope schema",
    )
    if (
        type(envelope_schema) is not dict
        or envelope_schema.get("additionalProperties") is not False
        or envelope_schema.get("properties", {}).get("schema_version", {}).get("const")
        != FOLLOWUP_ENVELOPE_SCHEMA
    ):
        raise FollowupContractError("outer-envelope schema is not closed")

    return FollowupStage1Inspection(
        stage1_commit_sha=FOLLOWUP_STAGE1_COMMIT_SHA,
        stage1_plan_sha256=FOLLOWUP_STAGE1_PLAN_SHA256,
        stage1_manifest_sha256=FOLLOWUP_STAGE1_MANIFEST_SHA256,
        object_set_sha256=FOLLOWUP_OBJECT_SET_SHA256,
        predecessor_plan_sha256=FOLLOWUP_PREDECESSOR_PLAN_SHA256,
        materialized_baseline_sha256=FOLLOWUP_BASELINE_SHA256,
        registered_value_change_count=len(changes),
        predecessor_top_level_key_count=len(predecessor),
    )


def materialize_followup_scientific_plan(
    repository_root: Path,
) -> FollowupScientificPlan:
    """Reproduce the five-value delta without entering a scientific generator."""

    inspect_followup_stage1(repository_root)
    root = repository_root.resolve(strict=True)
    plan_bytes = _git_output(
        root,
        "show",
        f"{FOLLOWUP_STAGE1_COMMIT_SHA}:{_PLAN_PATH}",
    )
    predecessor_bytes = _git_output(
        root,
        "show",
        f"{FOLLOWUP_STAGE1_COMMIT_SHA}:{_PREDECESSOR_PLAN_PATH}",
    )
    plan = _parse_ascii_json(plan_bytes, label="follow-up Stage-1 plan blob")
    predecessor = _parse_ascii_json(
        predecessor_bytes,
        label="follow-up predecessor-plan blob",
    )
    if type(plan) is not dict or type(predecessor) is not dict:
        raise FollowupContractError("follow-up scientific plans must be JSON objects")
    scientific = plan.get("scientific_contract")
    if type(scientific) is not dict or type(scientific.get("registered_value_changes")) is not list:
        raise FollowupContractError("follow-up registered delta is absent")
    materialized = json.loads(predecessor_bytes.decode("ascii"))
    for change in scientific["registered_value_changes"]:
        if type(change) is not dict or set(change) != {"followup", "json_path", "predecessor"}:
            raise FollowupContractError("follow-up registered delta is open")
        _replace_json_pointer(
            materialized,
            change["json_path"],
            change["predecessor"],
            change["followup"],
        )
    machine_plan_bytes = _canonical_json_bytes(materialized)
    if _sha256(machine_plan_bytes) != FOLLOWUP_BASELINE_SHA256:
        raise FollowupContractError("materialized follow-up plan digest changed")
    qualification = materialized.get("qualification")
    synthetic = materialized.get("synthetic")
    query_vector = materialized.get("query_vector")
    if (
        type(qualification) is not dict
        or type(synthetic) is not dict
        or type(query_vector) is not dict
        or type(qualification.get("seed")) is not int
        or type(synthetic.get("seeds")) is not list
        or len(synthetic["seeds"]) != 3
        or any(type(seed) is not int for seed in synthetic["seeds"])
        or type(query_vector.get("seed")) is not int
    ):
        raise FollowupContractError("materialized follow-up seed domain is malformed")
    profile = RouteAScientificProfile(
        profile_id=FOLLOWUP_STUDY_ID,
        qualification_seed=qualification["seed"],
        formal_seeds=tuple(synthetic["seeds"]),  # type: ignore[arg-type]
        query_vector_seed=query_vector["seed"],
        machine_plan_sha256=FOLLOWUP_BASELINE_SHA256,
    )
    return FollowupScientificPlan(
        machine_plan_bytes=machine_plan_bytes,
        machine_plan_sha256=FOLLOWUP_BASELINE_SHA256,
        scientific_profile=profile,
    )


@dataclass(frozen=True, slots=True)
class _FollowupInnerAdmission:
    inner_role: str
    inner_bytes: bytes
    inner_sha256: str
    _seal: object


def _issue_followup_inner_admission(
    *,
    inner_role: str,
    inner_bytes: bytes,
) -> _FollowupInnerAdmission:
    """Issue a process-local admission after a role-specific validator succeeds."""

    if type(inner_role) is not str or inner_role not in {
        role for roles in _UNIT_ROLES.values() for role in roles
    }:
        raise FollowupContractError("inner role is not in the closed follow-up domain")
    if type(inner_bytes) is not bytes or not inner_bytes:
        raise FollowupContractError("admitted inner payload must be nonempty exact bytes")
    return _FollowupInnerAdmission(
        inner_role=inner_role,
        inner_bytes=inner_bytes,
        inner_sha256=_sha256(inner_bytes),
        _seal=_INNER_ADMISSION_SEAL,
    )


def admit_followup_control_inner_payload(
    *,
    inner_role: str,
    inner_bytes: bytes,
) -> _FollowupInnerAdmission:
    """Admit one canonical follow-up-only authority-false control document."""

    if inner_role not in {role for kind in _CONTROL_UNIT_KINDS for role in _UNIT_ROLES[kind]}:
        raise FollowupContractError("control admission cannot issue a scientific inner role")
    document = _parse_ascii_json(inner_bytes, label="follow-up control inner payload")
    if type(document) is not dict or _canonical_json_bytes(document) != inner_bytes:
        raise FollowupContractError("follow-up control inner payload is not canonical JSON")
    schema_version = document.get("schema_version")
    if (
        type(schema_version) is not str
        or not schema_version.startswith("dynamic-cssc-followup-performance-")
        or schema_version.startswith("dynamic-cssc-route-a-")
        or document.get("study_id") != FOLLOWUP_STUDY_ID
        or document.get("authority") is not False
    ):
        raise FollowupContractError("control inner payload lacks follow-up-only identity")
    return _issue_followup_inner_admission(inner_role=inner_role, inner_bytes=inner_bytes)


def _require_unit_role(unit_kind: object, inner_role: object) -> tuple[str, str]:
    if type(unit_kind) is not str or unit_kind not in _UNIT_ROLES:
        raise FollowupContractError("unit kind is not in the closed follow-up domain")
    if type(inner_role) is not str or inner_role not in _UNIT_ROLES[unit_kind]:
        raise FollowupContractError("inner role is incompatible with its follow-up unit")
    return unit_kind, inner_role


def _require_attempt(unit_kind: str, unit_attempt_ordinal: object) -> int:
    if type(unit_attempt_ordinal) is not int:
        raise FollowupContractError("unit attempt ordinal must be a strict integer")
    allowed = {1, 2} if unit_kind in _RETRY_ELIGIBLE_UNIT_KINDS else {1}
    if unit_attempt_ordinal not in allowed:
        raise FollowupContractError("unit attempt ordinal is outside its frozen retry domain")
    return unit_attempt_ordinal


def followup_inherited_unit_attempt_ordinal(
    *,
    unit_kind: str,
    unit_attempt_ordinal: int,
) -> int:
    """Map one outer follow-up attempt onto the inherited Route-A ordinal.

    Follow-up envelopes deliberately use one-based ordinals (nominal ``1``,
    the sole eligible replacement ``2``).  The inherited scientific contract
    uses zero-based ordinals (nominal ``0``, replacement ``1``).  Keeping this
    translation here makes every scientific caller share the same closed
    retry domain.
    """

    if type(unit_kind) is not str or unit_kind not in _UNIT_ROLES:
        raise FollowupContractError("unit kind is not in the closed follow-up domain")
    outer_attempt = _require_attempt(unit_kind, unit_attempt_ordinal)
    return outer_attempt - 1 if unit_kind in _RETRY_ELIGIBLE_UNIT_KINDS else 0


def build_followup_unit_identity(
    *,
    unit_kind: str,
    unit_attempt_ordinal: int,
    scope: dict[str, object],
) -> tuple[bytes, str]:
    """Build one exact outer unit identity using caller-owned sentinel or live scope."""

    if type(unit_kind) is not str or unit_kind not in _UNIT_ROLES:
        raise FollowupContractError("unit kind is not in the closed follow-up domain")
    _require_attempt(unit_kind, unit_attempt_ordinal)
    if type(scope) is not dict or not scope or any(type(key) is not str for key in scope):
        raise FollowupContractError("unit identity scope must be one nonempty string-keyed object")
    document_bytes = _canonical_json_bytes(
        {
            "schema_version": FOLLOWUP_UNIT_IDENTITY_SCHEMA,
            "scope": scope,
            "study_id": FOLLOWUP_STUDY_ID,
            "unit_attempt_ordinal": unit_attempt_ordinal,
            "unit_kind": unit_kind,
        }
    )
    return document_bytes, _sha256(document_bytes)


@dataclass(frozen=True, slots=True)
class FollowupEvidenceEnvelope:
    """Canonical authority-false envelope plus the separately retained inner bytes."""

    document: dict[str, object]
    document_bytes: bytes
    sha256: str
    inner_bytes: bytes


def seal_followup_inner_payload(
    admission: _FollowupInnerAdmission,
    *,
    experiment_source_s1_sha: str,
    evidence_freeze_s2_sha: str,
    unit_kind: str,
    unit_identity_sha256: str,
    unit_attempt_ordinal: int,
) -> FollowupEvidenceEnvelope:
    """Bind one already-admitted inner payload to the exact follow-up lineage."""

    if (
        type(admission) is not _FollowupInnerAdmission
        or admission._seal is not _INNER_ADMISSION_SEAL
    ):
        raise FollowupContractError("inner payload lacks a process-local follow-up admission")
    unit_kind, inner_role = _require_unit_role(unit_kind, admission.inner_role)
    _require_attempt(unit_kind, unit_attempt_ordinal)
    if type(experiment_source_s1_sha) is not str or _LOWER_GIT_SHA.fullmatch(
        experiment_source_s1_sha
    ) is None:
        raise FollowupContractError("experiment source S1 must be lowercase Git SHA-1")
    if type(evidence_freeze_s2_sha) is not str or _LOWER_GIT_SHA.fullmatch(
        evidence_freeze_s2_sha
    ) is None:
        raise FollowupContractError("evidence freeze S2 must be lowercase Git SHA-1")
    if type(unit_identity_sha256) is not str or _LOWER_SHA256.fullmatch(
        unit_identity_sha256
    ) is None:
        raise FollowupContractError("unit identity must be lowercase SHA-256")
    if _sha256(admission.inner_bytes) != admission.inner_sha256:
        raise FollowupContractError("admitted inner payload changed before envelope sealing")
    document = {
        "authority": False,
        "evidence_freeze_S2_sha": evidence_freeze_s2_sha,
        "experiment_source_S1_sha": experiment_source_s1_sha,
        "inner_role": inner_role,
        "inner_sha256": admission.inner_sha256,
        "materialized_predecessor_baseline_sha256": FOLLOWUP_BASELINE_SHA256,
        "schema_version": FOLLOWUP_ENVELOPE_SCHEMA,
        "stage1_commit_sha": FOLLOWUP_STAGE1_COMMIT_SHA,
        "stage1_plan_sha256": FOLLOWUP_STAGE1_PLAN_SHA256,
        "study_id": FOLLOWUP_STUDY_ID,
        "unit_attempt_ordinal": unit_attempt_ordinal,
        "unit_identity_sha256": unit_identity_sha256,
        "unit_kind": unit_kind,
    }
    document_bytes = _canonical_json_bytes(document)
    return FollowupEvidenceEnvelope(
        document=document,
        document_bytes=document_bytes,
        sha256=_sha256(document_bytes),
        inner_bytes=admission.inner_bytes,
    )


def inspect_followup_outer_envelope(
    envelope_bytes: bytes,
    inner_bytes: bytes,
    *,
    expected_experiment_source_s1_sha: str | None = None,
    expected_evidence_freeze_s2_sha: str | None = None,
) -> FollowupEvidenceEnvelope:
    """Reject raw predecessor bytes before decoding or returning any inner payload."""

    document = _parse_ascii_json(envelope_bytes, label="follow-up outer envelope")
    required = {
        "authority",
        "evidence_freeze_S2_sha",
        "experiment_source_S1_sha",
        "inner_role",
        "inner_sha256",
        "materialized_predecessor_baseline_sha256",
        "schema_version",
        "stage1_commit_sha",
        "stage1_plan_sha256",
        "study_id",
        "unit_attempt_ordinal",
        "unit_identity_sha256",
        "unit_kind",
    }
    if type(document) is not dict or set(document) != required:
        raise FollowupContractError(
            "raw predecessor or open object rejected before follow-up inner decoding"
        )
    if _canonical_json_bytes(document) != envelope_bytes:
        raise FollowupContractError("follow-up outer envelope is not canonical JSON")
    unit_kind, _ = _require_unit_role(document["unit_kind"], document["inner_role"])
    _require_attempt(unit_kind, document["unit_attempt_ordinal"])
    if (
        document["schema_version"] != FOLLOWUP_ENVELOPE_SCHEMA
        or document["study_id"] != FOLLOWUP_STUDY_ID
        or document["stage1_commit_sha"] != FOLLOWUP_STAGE1_COMMIT_SHA
        or document["stage1_plan_sha256"] != FOLLOWUP_STAGE1_PLAN_SHA256
        or document["materialized_predecessor_baseline_sha256"]
        != FOLLOWUP_BASELINE_SHA256
        or document["authority"] is not False
    ):
        raise FollowupContractError("outer envelope does not bind the exact follow-up lineage")
    for field in ("experiment_source_S1_sha", "evidence_freeze_S2_sha"):
        value = document[field]
        if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
            raise FollowupContractError(f"{field} is not one lowercase Git SHA-1")
    for field in ("unit_identity_sha256", "inner_sha256"):
        value = document[field]
        if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
            raise FollowupContractError(f"{field} is not one lowercase SHA-256")
    if type(inner_bytes) is not bytes or _sha256(inner_bytes) != document["inner_sha256"]:
        raise FollowupContractError("outer envelope differs from separately retained inner bytes")
    if (
        expected_experiment_source_s1_sha is not None
        and document["experiment_source_S1_sha"] != expected_experiment_source_s1_sha
    ):
        raise FollowupContractError("outer envelope binds a different experiment source S1")
    if (
        expected_evidence_freeze_s2_sha is not None
        and document["evidence_freeze_S2_sha"] != expected_evidence_freeze_s2_sha
    ):
        raise FollowupContractError("outer envelope binds a different evidence freeze S2")
    return FollowupEvidenceEnvelope(
        document=document,
        document_bytes=envelope_bytes,
        sha256=_sha256(envelope_bytes),
        inner_bytes=inner_bytes,
    )


def followup_artifact_name(
    *,
    unit_kind: str,
    unit_identity_sha256: str,
    unit_attempt_ordinal: int,
) -> str:
    """Return one closed follow-up-only provider artifact name."""

    if type(unit_kind) is not str or unit_kind not in _UNIT_ROLES:
        raise FollowupContractError("artifact unit kind is not closed")
    _require_attempt(unit_kind, unit_attempt_ordinal)
    if type(unit_identity_sha256) is not str or _LOWER_SHA256.fullmatch(
        unit_identity_sha256
    ) is None:
        raise FollowupContractError("artifact unit identity must be lowercase SHA-256")
    token = unit_kind.replace("_", "-")
    if _SAFE_ARTIFACT_TOKEN.fullmatch(token) is None:
        raise FollowupContractError("artifact unit token is unsafe")
    return (
        f"{FOLLOWUP_ARTIFACT_PREFIX}{token}-"
        f"{unit_identity_sha256[:16]}-attempt-{unit_attempt_ordinal}"
    )
