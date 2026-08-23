from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import dynamic_cssc.publication_artifact_install as artifact_install
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactDirectory,
    PublicationArtifactInstallError,
    install_verified_directory,
    quarantine_owned_directory,
    verify_existing_directory,
)


def _identity(path: Path) -> tuple[int, int]:
    observed = path.lstat()
    return observed.st_dev, observed.st_ino


def _fingerprint(view: PublicationArtifactDirectory) -> tuple[tuple[str, ...], str, int]:
    assert not hasattr(view, "root")
    return (
        view.entries(),
        view.sha256_regular("artifact.json"),
        view.regular_size("artifact.json"),
    )


def _claimed_root(parent: Path) -> Path:
    matches = [path for path in parent.iterdir() if ".owned-" in path.name]
    assert len(matches) == 1
    return matches[0]


def test_verified_directory_is_installed_without_replacement(tmp_path: Path) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    (staging / "metadata").mkdir()
    (staging / "metadata" / "receipt.txt").write_bytes(b"receipt\n")
    staging_identity = _identity(staging)
    output = tmp_path / "result"

    observed = install_verified_directory(
        staging,
        output,
        staging_identity=staging_identity,
        verifier=_fingerprint,
        fingerprint=lambda value: value,
    )

    assert observed == (
        ("artifact.json", "metadata", "metadata/receipt.txt"),
        hashlib.sha256(b"verified\n").hexdigest(),
        len(b"verified\n"),
    )
    assert not staging.exists()
    assert (output / "artifact.json").read_bytes() == b"verified\n"
    assert (output / "metadata" / "receipt.txt").read_bytes() == b"receipt\n"
    assert _identity(output) == staging_identity


def test_directory_view_reads_only_exact_regular_members(tmp_path: Path) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    (staging / "metadata").mkdir()
    output = tmp_path / "result"

    def verifier(view: PublicationArtifactDirectory) -> str:
        assert view.entries() == ("artifact.json", "metadata")
        assert view.read_regular("artifact.json") == b"verified\n"
        for invalid in ("", ".", "../artifact.json", "/artifact.json"):
            with pytest.raises(PublicationArtifactInstallError):
                view.read_regular(invalid)
        with pytest.raises(PublicationArtifactInstallError, match="regular file"):
            view.read_regular("metadata")
        with pytest.raises(PublicationArtifactInstallError, match="not present"):
            view.read_regular("missing.txt")
        return view.sha256_regular("artifact.json")

    install_verified_directory(
        staging,
        output,
        staging_identity=_identity(staging),
        verifier=verifier,
        fingerprint=lambda value: value,
    )


def test_staging_identity_change_after_verification_never_reaches_output(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    staging_identity = _identity(staging)
    output = tmp_path / "result"
    displaced = tmp_path / "verified-staging-preserved"
    calls = 0

    def verifier(view: PublicationArtifactDirectory) -> object:
        nonlocal calls
        calls += 1
        fingerprint = _fingerprint(view)
        if calls == 1:
            claimed = _claimed_root(tmp_path)
            claimed.rename(displaced)
            claimed.mkdir()
            (claimed / "foreign.txt").write_bytes(b"not verified\n")
        return fingerprint

    with pytest.raises(PublicationArtifactInstallError, match="identity changed"):
        install_verified_directory(
            staging,
            output,
            staging_identity=staging_identity,
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert not output.exists()
    assert (displaced / "artifact.json").read_bytes() == b"verified\n"
    assert (staging / "foreign.txt").read_bytes() == b"not verified\n"


def test_transient_verifier_path_substitution_cannot_change_verified_view(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    output = tmp_path / "result"
    displaced = tmp_path / "verified-staging-preserved"

    def verifier(view: PublicationArtifactDirectory) -> object:
        fingerprint = _fingerprint(view)
        claimed = _claimed_root(tmp_path)
        claimed.rename(displaced)
        claimed.mkdir()
        (claimed / "artifact.json").write_bytes(b"foreign!\n")
        assert view.read_regular("artifact.json") == b"verified\n"
        return fingerprint

    with pytest.raises(PublicationArtifactInstallError, match="identity changed"):
        install_verified_directory(
            staging,
            output,
            staging_identity=_identity(staging),
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert not output.exists()
    assert (displaced / "artifact.json").read_bytes() == b"verified\n"
    assert (staging / "artifact.json").read_bytes() == b"foreign!\n"


def test_same_inode_member_mutation_after_verifier_read_is_rejected(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    member = staging / "artifact.json"
    member.write_bytes(b"verified\n")
    member_identity = _identity(member)
    output = tmp_path / "result"
    calls = 0

    def verifier(view: PublicationArtifactDirectory) -> object:
        nonlocal calls
        calls += 1
        fingerprint = _fingerprint(view)
        if calls == 1:
            claimed = _claimed_root(tmp_path)
            (claimed / "artifact.json").write_bytes(b"tampered\n")
            assert _identity(claimed / "artifact.json") == member_identity
        return fingerprint

    with pytest.raises(
        PublicationArtifactInstallError,
        match="tree changed|snapshotted content",
    ):
        install_verified_directory(
            staging,
            output,
            staging_identity=_identity(staging),
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert not output.exists()
    assert (staging / "artifact.json").read_bytes() == b"tampered\n"


@pytest.mark.parametrize("operation", ("read", "sha256"))
def test_descriptor_read_rejects_same_inode_same_size_aba_content(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "result"
    root.mkdir()
    member = root / "artifact.json"
    original = b"verified\n"
    alternate = b"tampered\n"
    assert len(original) == len(alternate)
    member.write_bytes(original)
    member_identity = _identity(member)

    def verifier(view: PublicationArtifactDirectory) -> object:
        member.write_bytes(alternate)
        assert _identity(member) == member_identity
        try:
            if operation == "read":
                return view.read_regular("artifact.json")
            return view.sha256_regular("artifact.json")
        finally:
            member.write_bytes(original)
            assert _identity(member) == member_identity

    with pytest.raises(PublicationArtifactInstallError, match="snapshot|tree changed"):
        verify_existing_directory(root, verifier=verifier)

    assert member.read_bytes() == original


def test_concurrent_destination_is_preserved_and_never_replaced(tmp_path: Path) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    staging_identity = _identity(staging)
    output = tmp_path / "result"

    def verifier(view: PublicationArtifactDirectory) -> object:
        fingerprint = _fingerprint(view)
        output.mkdir()
        (output / "foreign.txt").write_bytes(b"concurrent owner\n")
        return fingerprint

    with pytest.raises(PublicationArtifactInstallError, match="already exists"):
        install_verified_directory(
            staging,
            output,
            staging_identity=staging_identity,
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert (output / "foreign.txt").read_bytes() == b"concurrent owner\n"
    assert (staging / "artifact.json").read_bytes() == b"verified\n"


def test_quarantine_refuses_a_same_name_directory_with_a_different_inode(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"owned\n")
    owned_identity = _identity(staging)
    displaced = tmp_path / "owned-preserved"
    staging.rename(displaced)
    staging.mkdir()
    (staging / "foreign.txt").write_bytes(b"foreign\n")

    assert quarantine_owned_directory(staging, staging_identity=owned_identity) is False
    assert (staging / "foreign.txt").read_bytes() == b"foreign\n"
    assert (displaced / "artifact.json").read_bytes() == b"owned\n"


def test_quarantine_claims_before_accepting_the_root_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"owned\n")
    owned_identity = _identity(staging)
    displaced = tmp_path / "owned-preserved"
    real_rename = artifact_install._rename_no_replace
    intervened = False

    def replace_before_claim(*args: object, **kwargs: object) -> None:
        nonlocal intervened
        if not intervened:
            intervened = True
            staging.rename(displaced)
            staging.mkdir()
            (staging / "foreign.txt").write_bytes(b"foreign\n")
        real_rename(*args, **kwargs)

    monkeypatch.setattr(artifact_install, "_rename_no_replace", replace_before_claim)

    assert quarantine_owned_directory(staging, staging_identity=owned_identity) is False
    assert (staging / "foreign.txt").read_bytes() == b"foreign\n"
    assert (displaced / "artifact.json").read_bytes() == b"owned\n"


def test_quarantine_retains_the_complete_owned_tree_without_unlink_or_rmdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"owned\n")
    (staging / "nested").mkdir()
    (staging / "nested" / "receipt.txt").write_bytes(b"receipt\n")
    owned_identity = _identity(staging)

    def forbid_unlink(*_: object, **__: object) -> None:
        raise AssertionError("quarantine must not unlink an entry by reusable pathname")

    def forbid_rmdir(*_: object, **__: object) -> None:
        raise AssertionError("quarantine must not rmdir an entry by reusable pathname")

    monkeypatch.setattr(artifact_install.os, "unlink", forbid_unlink)
    monkeypatch.setattr(artifact_install.os, "rmdir", forbid_rmdir)

    assert quarantine_owned_directory(staging, staging_identity=owned_identity) is True
    assert not staging.exists()
    [retained_root] = [path for path in tmp_path.iterdir() if ".retained-staging-" in path.name]
    assert _identity(retained_root) == owned_identity
    assert (retained_root / "artifact.json").read_bytes() == b"owned\n"
    assert (retained_root / "nested" / "receipt.txt").read_bytes() == b"receipt\n"


def test_rejected_output_foreign_replacement_is_restored_and_preserved(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    output = tmp_path / "result"
    displaced = tmp_path / "installed-artifact-preserved"
    calls = 0

    def verifier(view: PublicationArtifactDirectory) -> object:
        nonlocal calls
        calls += 1
        fingerprint = _fingerprint(view)
        if calls == 2:
            output.rename(displaced)
            output.mkdir()
            (output / "foreign.txt").write_bytes(b"foreign\n")
            raise ValueError("post-install rejection")
        return fingerprint

    with pytest.raises(PublicationArtifactInstallError, match="post-install verification"):
        install_verified_directory(
            staging,
            output,
            staging_identity=_identity(staging),
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert (output / "foreign.txt").read_bytes() == b"foreign\n"
    assert (displaced / "artifact.json").read_bytes() == b"verified\n"


def test_output_parent_path_replacement_never_yields_detached_success(
    tmp_path: Path,
) -> None:
    artifact_parent = tmp_path / "artifact-parent"
    artifact_parent.mkdir()
    staging = artifact_parent / ".result.tmp-owned"
    staging.mkdir()
    (staging / "artifact.json").write_bytes(b"verified\n")
    staging_identity = _identity(staging)
    output = artifact_parent / "result"
    detached_parent = tmp_path / "detached-artifact-parent"
    calls = 0

    def verifier(view: PublicationArtifactDirectory) -> object:
        nonlocal calls
        calls += 1
        fingerprint = _fingerprint(view)
        if calls == 1:
            artifact_parent.rename(detached_parent)
            artifact_parent.mkdir()
            output.mkdir()
            (output / "foreign.txt").write_bytes(b"foreign\n")
        return fingerprint

    with pytest.raises(PublicationArtifactInstallError, match="output parent identity changed"):
        install_verified_directory(
            staging,
            output,
            staging_identity=staging_identity,
            verifier=verifier,
            fingerprint=lambda value: value,
        )

    assert (output / "foreign.txt").read_bytes() == b"foreign\n"
    assert not (detached_parent / output.name).exists()
    [rejected_root] = [
        path
        for path in detached_parent.iterdir()
        if path.name.startswith(f".{output.name}.rejected-staging-")
    ]
    assert _identity(rejected_root) == staging_identity
    assert (rejected_root / "artifact.json").read_bytes() == b"verified\n"


def test_rebound_output_parent_requires_a_current_tree_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_parent = tmp_path / "artifact-parent"
    artifact_parent.mkdir()
    staging = artifact_parent / ".result.tmp-owned"
    staging.mkdir()
    member = staging / "artifact.json"
    member.write_bytes(b"verified\n")
    member_identity = _identity(member)
    staging_identity = _identity(staging)
    output = artifact_parent / "result"
    detached_parent = tmp_path / "detached-artifact-parent"
    real_require_current = artifact_install._require_current_directory_mapping
    rebound = False

    def rebind_then_require(*args: object, **kwargs: object) -> None:
        nonlocal rebound
        if not rebound:
            rebound = True
            artifact_parent.rename(detached_parent)
            installed_member = detached_parent / output.name / "artifact.json"
            installed_member.write_bytes(b"tampered\n")
            assert _identity(installed_member) == member_identity
            detached_parent.rename(artifact_parent)
        real_require_current(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        artifact_install,
        "_require_current_directory_mapping",
        rebind_then_require,
    )

    with pytest.raises(
        PublicationArtifactInstallError,
        match="tree changed|snapshotted content",
    ):
        install_verified_directory(
            staging,
            output,
            staging_identity=staging_identity,
            verifier=lambda view: view.read_regular("artifact.json"),
            fingerprint=lambda value: value,
        )

    assert rebound is True
    assert not output.exists()
    [rejected_root] = [
        path
        for path in artifact_parent.iterdir()
        if path.name.startswith(f".{output.name}.rejected-staging-")
    ]
    assert _identity(rejected_root) == staging_identity
    assert (rejected_root / "artifact.json").read_bytes() == b"tampered\n"


def test_rebound_existing_parent_requires_a_current_tree_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_parent = tmp_path / "artifact-parent"
    artifact_parent.mkdir()
    root = artifact_parent / "result"
    root.mkdir()
    member = root / "artifact.json"
    member.write_bytes(b"verified\n")
    member_identity = _identity(member)
    detached_parent = tmp_path / "detached-artifact-parent"
    real_require_current = artifact_install._require_current_directory_mapping
    rebound = False

    def rebind_then_require(*args: object, **kwargs: object) -> None:
        nonlocal rebound
        if not rebound:
            rebound = True
            artifact_parent.rename(detached_parent)
            detached_member = detached_parent / root.name / "artifact.json"
            detached_member.write_bytes(b"tampered\n")
            assert _identity(detached_member) == member_identity
            detached_parent.rename(artifact_parent)
        real_require_current(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        artifact_install,
        "_require_current_directory_mapping",
        rebind_then_require,
    )

    with pytest.raises(
        PublicationArtifactInstallError,
        match="tree changed|snapshotted content",
    ):
        verify_existing_directory(
            root,
            verifier=lambda view: view.read_regular("artifact.json"),
        )

    assert rebound is True
    assert _identity(member) == member_identity
    assert member.read_bytes() == b"tampered\n"
