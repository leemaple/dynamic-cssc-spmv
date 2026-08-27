from __future__ import annotations

import hashlib
import inspect
import io
import json
import stat
import zipfile
from pathlib import Path

import pytest

import dynamic_cssc.day2_calibration_producer as producer
from dynamic_cssc.day2_calibration_producer import (
    Day2CalibrationProducerError,
    produce_day2_calibration_archive_from_isolated_worker,
)

ROOT = Path(__file__).resolve().parents[1]


def _canonical(value: object) -> bytes:
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


def test_generated_key_inventory_binds_actual_serialized_evaluation_key_bytes() -> None:
    rotation_plan = {
        "required_exact_indices": [-3, -1, 1, 7],
    }
    rotation_keys = b"actual-rotation-evaluation-key-bytes\x00"
    eval_mult_keys = b"actual-multiplication-evaluation-key-bytes\x00"

    inventory = producer._generated_key_inventory(  # noqa: SLF001
        rotation_key_plan=rotation_plan,
        rotation_key_plan_sha256="a" * 64,
        serialized_rotation_keys=rotation_keys,
        serialized_eval_mult_keys=eval_mult_keys,
    )

    assert inventory == {
        "schema_version": "dynamic-cssc-publication-generated-key-inventory-v1",
        "rotation_key_plan_sha256": "a" * 64,
        "generated_exact_indices": [-3, -1, 1, 7],
        "serialized_rotation_key_inventory_sha256": hashlib.sha256(
            rotation_keys
        ).hexdigest(),
        "serialized_rotation_key_bytes": len(rotation_keys),
        "eval_mult_key_generated": True,
        "serialized_eval_mult_key_sha256": hashlib.sha256(eval_mult_keys).hexdigest(),
        "serialized_eval_mult_key_bytes": len(eval_mult_keys),
    }
    assert "secret" not in json.dumps(inventory).lower()


def test_generated_key_inventory_rejects_empty_or_spliced_plan_inputs() -> None:
    with pytest.raises(Day2CalibrationProducerError, match="rotation plan"):
        producer._generated_key_inventory(  # noqa: SLF001
            rotation_key_plan={"required_exact_indices": [1, 1]},
            rotation_key_plan_sha256="a" * 64,
            serialized_rotation_keys=b"rotation",
            serialized_eval_mult_keys=b"mult",
        )
    with pytest.raises(Day2CalibrationProducerError, match="nonempty"):
        producer._generated_key_inventory(  # noqa: SLF001
            rotation_key_plan={"required_exact_indices": [1]},
            rotation_key_plan_sha256="a" * 64,
            serialized_rotation_keys=b"",
            serialized_eval_mult_keys=b"mult",
        )


def test_serialized_object_size_profile_retains_formal_ciphertext_and_key_lengths() -> None:
    generated = producer._generated_key_inventory(  # noqa: SLF001
        rotation_key_plan={"required_exact_indices": [-1, 1]},
        rotation_key_plan_sha256="a" * 64,
        serialized_rotation_keys=b"rotation-key-bytes",
        serialized_eval_mult_keys=b"eval-mult-key-bytes",
    )

    profile = producer._serialized_object_size_profile(  # noqa: SLF001
        ciphertext_bytes=34567,
        f1m_random_zero_sum_ciphertext_bytes=34568,
        f1m_encrypted_zero_dummy_ciphertext_bytes=34569,
        generated_key_inventory=generated,
    )

    assert profile == {
        "schema_version": (
            "dynamic-cssc-publication-day2-serialized-object-size-profile-v2"
        ),
        "ciphertext_serialization_format": "openfhe-sertype-binary-v1",
        "ciphertext_measurement_method": (
            "formal-probe-exact-serialized-byte-length-v1"
        ),
        "ciphertext_bytes": 34567,
        "f1m_ciphertext_construction_profile": (
            "fresh-bfvrns-encryption-fixed-context-v1"
        ),
        "f1m_random_zero_sum_ciphertext_bytes": 34568,
        "f1m_encrypted_zero_dummy_ciphertext_bytes": 34569,
        "generated_key_inventory_sha256": hashlib.sha256(_canonical(generated)).hexdigest(),
        "serialized_rotation_key_inventory_bytes": len(b"rotation-key-bytes"),
        "serialized_eval_mult_key_bytes": len(b"eval-mult-key-bytes"),
    }


@pytest.mark.parametrize(
    "field",
    (
        "ciphertext_bytes",
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
    ),
)
@pytest.mark.parametrize("invalid_size", [None, True, 0, -1])
def test_serialized_object_size_profile_rejects_nonpositive_or_nonstrict_sizes(
    field: str,
    invalid_size: object,
) -> None:
    generated = {
        "serialized_rotation_key_bytes": 10,
        "serialized_eval_mult_key_bytes": 20,
    }
    sizes: dict[str, object] = {
        "ciphertext_bytes": 20,
        "f1m_random_zero_sum_ciphertext_bytes": 30,
        "f1m_encrypted_zero_dummy_ciphertext_bytes": 40,
    }
    sizes[field] = invalid_size
    with pytest.raises(Day2CalibrationProducerError, match=f"positive {field}"):
        producer._serialized_object_size_profile(  # noqa: SLF001
            ciphertext_bytes=sizes["ciphertext_bytes"],
            f1m_random_zero_sum_ciphertext_bytes=sizes[
                "f1m_random_zero_sum_ciphertext_bytes"
            ],
            f1m_encrypted_zero_dummy_ciphertext_bytes=sizes[
                "f1m_encrypted_zero_dummy_ciphertext_bytes"
            ],
            generated_key_inventory=generated,
        )


def test_canonical_zip_has_fixed_order_timestamp_mode_and_no_compression() -> None:
    members = {"b.json": b"b\n", "a.json": b"a\n"}
    archive_bytes = producer._canonical_zip_bytes(  # noqa: SLF001
        members,
        member_order=("a.json", "b.json"),
    )

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        infos = archive.infolist()
        assert [info.filename for info in infos] == ["a.json", "b.json"]
        assert all(info.date_time == (2026, 8, 23, 0, 0, 0) for info in infos)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        assert all(info.create_system == 3 for info in infos)
        assert all(
            (info.external_attr >> 16) == (stat.S_IFREG | 0o600) for info in infos
        )
        assert archive.read("a.json") == b"a\n"


def test_workflow_provenance_is_derived_from_exact_github_environment() -> None:
    workflow_path = ROOT / ".github/workflows/day2-publication-calibration.yml"
    assert workflow_path.is_file()
    environment = {
        "GITHUB_REPOSITORY": "leemaple/dynamic-cssc-spmv",
        "GITHUB_REPOSITORY_ID": "1341939625",
        "GITHUB_WORKFLOW_REF": (
            "leemaple/dynamic-cssc-spmv/.github/workflows/"
            "day2-publication-calibration.yml@refs/heads/main"
        ),
        "GITHUB_RUN_ID": "456",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "a" * 40,
    }

    provenance = producer._workflow_provenance_from_environment(  # noqa: SLF001
        repository_root=ROOT,
        source_git_sha="a" * 40,
        environment=environment,
    )

    assert provenance["workflow_path"] == (
        ".github/workflows/day2-publication-calibration.yml"
    )
    assert provenance["run_id"] == 456
    assert provenance["run_attempt"] == 2
    assert provenance["head_sha"] == "a" * 40
    assert provenance["artifact_name"] == "r3-day2-calibration-" + "a" * 40 + "-456-2"
    assert provenance["workflow_file_sha256"] == hashlib.sha256(
        workflow_path.read_bytes()
    ).hexdigest()


def test_isolated_worker_producer_has_no_caller_semantic_or_authority_flags() -> None:
    assert tuple(
        inspect.signature(produce_day2_calibration_archive_from_isolated_worker).parameters
    ) == (
        "day1a_directory",
        "github_artifact_metadata_path",
        "execution_root",
        "output_archive",
        "runtime_capability",
    )
