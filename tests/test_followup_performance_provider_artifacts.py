from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import BinaryIO

import pytest

from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)
from dynamic_cssc.followup_performance_provider_artifacts import (
    FollowupProviderArtifactBinding,
    install_followup_provider_artifact,
)


class _ArtifactTransport:
    def __init__(
        self,
        archive: bytes,
        *,
        artifact_id: int,
        name: str,
        digest: str,
    ) -> None:
        self.archive = archive
        self.artifact_id = artifact_id
        self.name = name
        self.digest = digest

    def metadata(self, *, repository: str, artifact_id: int) -> bytes:
        assert repository == "example/project"
        assert artifact_id == self.artifact_id
        return json.dumps(
            {
                "digest": self.digest,
                "expired": False,
                "id": self.artifact_id,
                "name": self.name,
                "size_in_bytes": len(self.archive),
                "workflow_run": {"head_sha": "1" * 40, "id": 70_001},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def download(
        self,
        *,
        repository: str,
        artifact_id: int,
        output: BinaryIO,
    ) -> None:
        assert repository == "example/project"
        assert artifact_id == self.artifact_id
        output.write(self.archive)


def _archive(name: str = "inner-payload.json") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        archive.writestr(name, b'{"sentinel":true}\n')
    return output.getvalue()


def test_provider_artifact_installs_only_exact_rehashed_archive(tmp_path: Path) -> None:
    content = _archive()
    digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
    name = "followup-performance-v1-formal-synthetic-sentinel"
    binding = FollowupProviderArtifactBinding(
        provider_artifact_id=80_001,
        artifact_name=name,
        provider_digest=digest,
        size_in_bytes_or_null=len(content),
    )
    root = (tmp_path / "artifacts").resolve()
    root.mkdir()

    installed = install_followup_provider_artifact(
        repository="example/project",
        binding=binding,
        expected_run_id=70_001,
        expected_head_sha="1" * 40,
        target_root=root,
        transport=_ArtifactTransport(
            content,
            artifact_id=80_001,
            name=name,
            digest=digest,
        ),
    )

    assert installed == root / name
    assert (installed / "inner-payload.json").read_bytes() == b'{"sentinel":true}\n'
    assert not (root / ".80001.zip").exists()


@pytest.mark.parametrize(
    ("archive", "message"),
    [
        (_archive(), "archive digest"),
        (_archive("../escape"), "path is unsafe"),
    ],
)
def test_provider_artifact_rejects_digest_or_path_tampering(
    tmp_path: Path,
    archive: bytes,
    message: str,
) -> None:
    actual = f"sha256:{hashlib.sha256(archive).hexdigest()}"
    declared = f"sha256:{'f' * 64}" if message == "archive digest" else actual
    name = "followup-performance-v1-formal-synthetic-tamper"
    root = (tmp_path / message.replace(" ", "-")).resolve()
    root.mkdir()
    with pytest.raises(FollowupCampaignControlError, match=message):
        install_followup_provider_artifact(
            repository="example/project",
            binding=FollowupProviderArtifactBinding(
                provider_artifact_id=80_002,
                artifact_name=name,
                provider_digest=declared,
                size_in_bytes_or_null=len(archive),
            ),
            expected_run_id=70_001,
            expected_head_sha="1" * 40,
            target_root=root,
            transport=_ArtifactTransport(
                archive,
                artifact_id=80_002,
                name=name,
                digest=declared,
            ),
        )
    assert not (root / name).exists()
