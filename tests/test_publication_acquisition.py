from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import ssl
import subprocess
import tomllib
import urllib.request
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from dynamic_cssc.publication_acquisition import (
    AcquisitionError,
    _acquire_publication_sources,
    _acquire_publication_sources_production,
    _CurlCffiTermsTransport,
    _normalized_response_header_observation,
    _normalized_response_headers_sha256,
    _RepositoryTransport,
    _test_only_repository_snapshot,
    _TransportResponse,
    _UrllibTransport,
    _verify_acquisition_bundle,
    acquire_publication_sources,
)
from scripts import acquire_publication_sources as acquisition_cli


class _FakeTransport:
    def __init__(self, responses: dict[str, _TransportResponse]) -> None:
        self._responses = responses
        self.requested_urls: list[str] = []

    @contextmanager
    def open(self, url: str):  # type: ignore[no-untyped-def]
        self.requested_urls.append(url)
        yield self._responses[url]


class _FakeCurlHeaders:
    def __init__(self, values: list[tuple[str, str]]) -> None:
        self._values = values

    def get_list(self, name: str) -> list[str]:
        return [value for key, value in self._values if key.lower() == name.lower()]

    @property
    def raw(self) -> list[tuple[bytes, bytes]]:
        return [(key.encode("ascii"), value.encode("ascii")) for key, value in self._values]


class _FakeCurlSessionFactory:
    def __init__(
        self,
        body: bytes,
        *,
        response_headers: list[tuple[str, str]] | None = None,
        http_version: int = 3,
        response_url: str | None = None,
        status_code: int = 200,
        request_error: BaseException | None = None,
        chunks: tuple[bytes, ...] | None = None,
    ) -> None:
        self.body = body
        self.response_headers = (
            [
                ("Content-Type", "text/html; charset=utf-8"),
                ("ETag", '"fixture-etag"'),
            ]
            if response_headers is None
            else response_headers
        )
        self.http_version = http_version
        self.response_url = response_url
        self.status_code = status_code
        self.request_error = request_error
        self.chunks = (body,) if chunks is None else chunks
        self.session_arguments: list[dict[str, object]] = []
        self.request_arguments: list[tuple[str, dict[str, object]]] = []
        self.close_count = 0

    def __call__(self, **arguments: object):  # type: ignore[no-untyped-def]
        self.session_arguments.append(arguments)
        factory = self

        class Session:
            def get(self, url: str, **request_arguments: object):  # type: ignore[no-untyped-def]
                factory.request_arguments.append((url, request_arguments))
                if factory.request_error is not None:
                    raise factory.request_error
                callback = request_arguments["content_callback"]
                assert callable(callback)
                for chunk in factory.chunks:
                    callback(chunk)
                return SimpleNamespace(
                    status_code=factory.status_code,
                    url=url if factory.response_url is None else factory.response_url,
                    http_version=factory.http_version,
                    request=SimpleNamespace(
                        headers=_FakeCurlHeaders(
                            [
                                ("Accept-Encoding", "identity"),
                                (
                                    "User-Agent",
                                    (
                                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                                        "Chrome/150.0.0.0 Safari/537.36"
                                    ),
                                ),
                            ]
                        )
                    ),
                    headers=_FakeCurlHeaders(factory.response_headers),
                )

            def close(self) -> None:
                factory.close_count += 1

        return Session()


def _response(url: str, content: bytes, media_type: str) -> _TransportResponse:
    uses_curl = url in {
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    }
    user_agent = (
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.0.0 Safari/537.36"
        )
        if uses_curl
        else "dynamic-cssc-publication-acquisition/1"
    )
    normalized_response_headers = _normalized_response_header_observation(
        media_type=media_type,
        content_length=len(content),
        content_encoding=None,
        content_range=None,
        http_etag='"fixture-etag"',
        http_last_modified="Sun, 23 Aug 2026 00:00:00 GMT",
    )
    return _TransportResponse(
        final_url=url,
        http_status=200,
        media_type=media_type,
        content_encoding=None,
        content_range=None,
        content_length=len(content),
        http_etag='"fixture-etag"',
        http_last_modified="Sun, 23 Aug 2026 00:00:00 GMT",
        chunks=(content,),
        http_version="HTTP/2" if uses_curl else "HTTP/1.1",
        configured_request_headers=(
            ("accept-encoding", "identity"),
            ("user-agent", user_agent),
        ),
        normalized_response_headers=normalized_response_headers,
        normalized_response_headers_sha256=_normalized_response_headers_sha256(
            normalized_response_headers
        ),
    )


def _response_with_content_length(
    response: _TransportResponse,
    content_length: int | None,
    *,
    chunks: tuple[bytes, ...] | None = None,
) -> _TransportResponse:
    normalized_response_headers = _normalized_response_header_observation(
        media_type=response.media_type,
        content_length=content_length,
        content_encoding=response.content_encoding,
        content_range=response.content_range,
        http_etag=response.http_etag,
        http_last_modified=response.http_last_modified,
    )
    return replace(
        response,
        content_length=content_length,
        chunks=response.chunks if chunks is None else chunks,
        normalized_response_headers=normalized_response_headers,
        normalized_response_headers_sha256=_normalized_response_headers_sha256(
            normalized_response_headers
        ),
    )


def _stack_transport() -> _FakeTransport:
    a2q_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    c2q_url = "https://snap.stanford.edu/data/sx-stackoverflow-c2q.txt.gz"
    c2a_url = "https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz"
    urls = {
        a2q_url: (b"a2q\n", "application/x-gzip"),
        c2q_url: (b"c2q\n", "application/x-gzip"),
        c2a_url: (b"c2a\n", "application/x-gzip"),
        "https://stackoverflow.com/help/licensing": (b"licensing\n", "text/html"),
        "https://stackoverflow.com/legal/terms-of-service/public": (
            b"terms\n",
            "text/html; charset=UTF-8",
        ),
    }
    return _FakeTransport(
        {url: _response(url, content, media_type) for url, (content, media_type) in urls.items()}
    )


def _acquire_stack(tmp_path: Path):  # type: ignore[no-untyped-def]
    transport = _stack_transport()
    output_dir = tmp_path / "stack-overflow-acquisition"
    bundle = _acquire_publication_sources(
        "stack-overflow",
        output_dir,
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, 1, 2, 3, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )
    return bundle, transport


def _rewrite_sha256s(root: Path) -> None:
    transaction_path = root / "ACQUISITION-TRANSACTION.json"
    transaction = json.loads(transaction_path.read_text(encoding="ascii"))
    source_set_bytes = (root / "source-set.json").read_bytes()
    transaction["source_set"]["sha256"] = hashlib.sha256(source_set_bytes).hexdigest()
    transaction_path.chmod(0o644)
    transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    paths = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    checksums_path = root / "SHA256SUMS"
    checksums_path.chmod(0o644)
    checksums_path.write_text(
        "".join(
            f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n" for path in paths
        ),
        encoding="ascii",
    )


def _retarget_transaction_content_length(
    transaction: dict[str, object],
    object_index: int,
    content_length: int | None,
) -> None:
    objects = transaction["objects"]
    assert isinstance(objects, list)
    record = objects[object_index]
    assert isinstance(record, dict)
    record["response_content_length_bytes"] = content_length
    response_headers = record["normalized_response_headers"]
    assert isinstance(response_headers, list)
    [content_length_header] = [
        header
        for header in response_headers
        if isinstance(header, dict) and header.get("name") == "content-length"
    ]
    content_length_header["values"] = [] if content_length is None else [str(content_length)]
    record["normalized_response_headers_sha256"] = hashlib.sha256(
        (
            json.dumps(
                response_headers,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()


def test_acquisition_writes_prepare_compatible_source_set_and_fail_closed_transaction(
    tmp_path: Path,
) -> None:
    bundle, transport = _acquire_stack(tmp_path)

    source_set = json.loads(bundle.source_set_path.read_text(encoding="utf-8"))
    transaction = json.loads(bundle.transaction_path.read_text(encoding="utf-8"))
    assert source_set["schema_version"] == "dynamic-cssc-local-source-set-v5"
    assert source_set["dataset_release"] == "snap-stackoverflow-temporal-network"
    assert [item["role"] for item in source_set["objects"]] == ["a2q", "c2q", "c2a"]
    assert [item["source_url"] for item in source_set["terms_objects"]] == [
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    ]
    assert source_set["terms_objects"][1]["media_type"] == "text/html; charset=utf-8"
    assert transaction["network_fetch_performed"] is False
    assert transaction["formal_authority_granted"] is False
    assert transaction["acquisition_network_authority_verified"] is False
    assert transaction["post_run_anchor_verified"] is False
    assert transaction["evidence_compatibility_verified"] is False
    assert transaction["http_request_policy"] == {
        "accept_encoding": "identity",
        "content_encoding": "identity-or-absent",
        "data_http_content_length_policy": "required-positive-exact-byte-count",
        "content_range": "forbidden",
        "method": "GET",
        "redirect_policy": "reject-any-final-url-drift",
        "terms_http_content_length_policy": "absent-or-positive-exact-byte-count",
        "terms_max_byte_count": 2_097_152,
        "transport_adapters": {
            "default": {
                "adapter_id": "cpython-urllib-identity-v1",
                "ca_policy": "certifi-2026.7.22-sha256",
                "proxy_policy": "ProxyHandler-empty",
                "tls_minimum_version": "TLSv1.2",
                "user_agent": "dynamic-cssc-publication-acquisition/1",
            },
            "exact_url_override": {
                "acquisition_lock_sha256": (
                    "981196702bd46e00c408e39c441c0fdb4c4f98f1c343f7993c8a50a92a901cd5"
                ),
                "adapter_id": "curl-cffi-chrome150-stack-terms-v1",
                "ca_bundle_sha256": (
                    "9cc2a774b5198dcff14d9be1e66091f538975d867ce029a96bce15a55dfd730f"
                ),
                "certifi_version": "2026.7.22",
                "curl_cffi_version": "0.16.1",
                "default_headers": False,
                "discard_cookies": True,
                "http_version": "v2",
                "impersonation_target": "chrome150",
                "impersonation_target_browser": "Chrome 150",
                "impersonation_target_os": "macOS Tahoe",
                "retry_count": 0,
                "trust_env": False,
                "proxy_policy": "CURLOPT_PROXY-empty",
                "urls": [
                    "https://stackoverflow.com/help/licensing",
                    "https://stackoverflow.com/legal/terms-of-service/public",
                ],
                "user_agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/150.0.0.0 Safari/537.36"
                ),
            },
        },
    }
    assert transaction["transport_runtime"] == {
        "curl_adapter_runtime": None,
        "formal_authority_granted": False,
        "mode": "test-only-fixed-transport-runtime-v1",
        "platform_machine": "test-only",
        "platform_release": "test-only",
        "platform_system": "test-only",
        "platform_tag": "test-only",
        "python_implementation": "test-only",
        "python_version": "test-only",
        "requirements_acquisition_sha256": (
            "981196702bd46e00c408e39c441c0fdb4c4f98f1c343f7993c8a50a92a901cd5"
        ),
        "runtime_execution_isolation_verified": False,
        "schema_version": "dynamic-cssc-acquisition-transport-runtime-v1",
        "urllib_adapter_runtime": None,
    }
    repository_provenance = transaction["repository_provenance"]
    assert repository_provenance["source_git_sha"] == "f" * 40
    behavior_inventory = repository_provenance["behavior_inventory"]
    assert behavior_inventory["schema_version"] == ("dynamic-cssc-evidence-behavior-inventory-v1")
    assert behavior_inventory["role"] == "acquisition"
    assert behavior_inventory["source_git_sha"] == "f" * 40
    assert behavior_inventory["behavior_set_schema_version"] == (
        "dynamic-cssc-acquisition-behavior-set-v2"
    )
    behavior_entries = behavior_inventory["entries"]
    assert [entry["path"] for entry in behavior_entries] == [
        "config/params_manifest.json",
        "docs/paper/publication-preregistration-draft.md",
        "docs/research/publication-dataset-citation-record.md",
        "docs/research/publication-venues-datasets-preregistration.md",
        "pyproject.toml",
        "requirements-acquisition.txt",
        "scripts/acquire_publication_sources.py",
        "scripts/prepare_publication_traces.py",
        "src/dynamic_cssc/__init__.py",
        "src/dynamic_cssc/evidence_compatibility.py",
        "src/dynamic_cssc/publication_acquisition.py",
        "src/dynamic_cssc/publication_artifact_install.py",
        "src/dynamic_cssc/publication_traces.py",
    ]
    assert {
        (entry["mode"], entry["object_type"], len(entry["object_id"])) for entry in behavior_entries
    } == {("100644", "blob", 40)}
    assert transaction["source_set"]["sha256"] == bundle.source_set_sha256
    assert [item["transport_adapter_id"] for item in transaction["objects"]] == [
        "cpython-urllib-identity-v1",
        "cpython-urllib-identity-v1",
        "cpython-urllib-identity-v1",
        "curl-cffi-chrome150-stack-terms-v1",
        "curl-cffi-chrome150-stack-terms-v1",
    ]
    assert [item["http_version"] for item in transaction["objects"]] == [
        "HTTP/1.1",
        "HTTP/1.1",
        "HTTP/1.1",
        "HTTP/2",
        "HTTP/2",
    ]
    assert all(
        len(item["normalized_response_headers_sha256"]) == 64 for item in transaction["objects"]
    )
    assert all(
        item["normalized_response_headers_sha256"]
        == hashlib.sha256(
            (
                json.dumps(
                    item["normalized_response_headers"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        for item in transaction["objects"]
    )
    assert len(set(transport.requested_urls)) == 5
    assert len(transport.requested_urls) == 5
    assert bundle.checksums_path.read_text(encoding="ascii").endswith("\n")


def test_terms_without_content_length_are_bounded_and_recorded_honestly(
    tmp_path: Path,
) -> None:
    transport = _stack_transport()
    terms_urls = {
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    }
    for url in terms_urls:
        transport._responses[url] = _response_with_content_length(
            transport._responses[url],
            None,
        )

    bundle = _acquire_publication_sources(
        "stack-overflow",
        tmp_path / "stack-overflow-no-terms-content-length",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, 1, 2, 3, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    assert transaction["schema_version"] == "dynamic-cssc-acquisition-transaction-v3"
    data_objects = [item for item in transaction["objects"] if item["object_kind"] == "data"]
    terms_objects = [item for item in transaction["objects"] if item["object_kind"] == "terms"]
    assert all(item["response_content_length_bytes"] == item["byte_count"] for item in data_objects)
    assert {
        (
            item["request_url"],
            item["response_content_length_bytes"],
            item["body_length_mode"],
            item["body_limit_bytes"],
        )
        for item in terms_objects
    } == {(url, None, "terms-bounded-clean-transfer-v1", 2_097_152) for url in terms_urls}
    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    assert all(0 < item["byte_count"] <= 2_097_152 for item in source_set["terms_objects"])


def test_data_without_content_length_remains_fail_closed(tmp_path: Path) -> None:
    transport = _stack_transport()
    data_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    transport._responses[data_url] = replace(
        transport._responses[data_url],
        content_length=None,
    )
    output_dir = tmp_path / "missing-data-content-length"

    with pytest.raises(AcquisitionError, match="Content-Length"):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".missing-data-content-length.tmp-*")) == []


def test_terms_without_content_length_accept_exactly_the_frozen_limit(tmp_path: Path) -> None:
    transport = _stack_transport()
    terms_url = "https://stackoverflow.com/help/licensing"
    transport._responses[terms_url] = _response_with_content_length(
        transport._responses[terms_url],
        None,
        chunks=(b"x" * 2_097_152,),
    )

    bundle = _acquire_publication_sources(
        "stack-overflow",
        tmp_path / "terms-at-limit",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    [record] = [item for item in transaction["objects"] if item["request_url"] == terms_url]
    assert record["byte_count"] == 2_097_152
    assert record["response_content_length_bytes"] is None


@pytest.mark.parametrize(
    ("response", "error_match"),
    [
        (
            lambda original: _response_with_content_length(
                original,
                None,
                chunks=(),
            ),
            "nonempty",
        ),
        (
            lambda original: _response_with_content_length(
                original,
                None,
                chunks=(b"x" * 2_097_152, b"x"),
            ),
            "byte limit",
        ),
        (
            lambda original: _response_with_content_length(
                original,
                2_097_153,
                chunks=(b"x",),
            ),
            "byte limit",
        ),
    ],
    ids=("empty", "cap-plus-one", "declared-over-cap"),
)
def test_invalid_terms_body_length_is_atomic_and_fail_closed(
    tmp_path: Path,
    response,  # type: ignore[no-untyped-def]
    error_match: str,
) -> None:
    transport = _stack_transport()
    terms_url = "https://stackoverflow.com/help/licensing"
    transport._responses[terms_url] = response(transport._responses[terms_url])
    output_dir = tmp_path / "invalid-terms-length"

    with pytest.raises(AcquisitionError, match=error_match):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".invalid-terms-length.tmp-*")) == []


def test_repository_transport_routes_only_exact_stack_terms_to_frozen_adapter() -> None:
    data_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    stack_terms_urls = {
        "https://stackoverflow.com/help/licensing",
        "https://stackoverflow.com/legal/terms-of-service/public",
    }
    other_terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    default_transport = _FakeTransport(
        {
            data_url: _response(data_url, b"data", "application/x-gzip"),
            other_terms_url: _response(other_terms_url, b"terms", "text/html"),
        }
    )
    stack_transport = _FakeTransport(
        {url: _response(url, b"terms", "text/html") for url in stack_terms_urls}
    )
    transport = _RepositoryTransport(
        default_transport=default_transport,
        stack_terms_transport=stack_transport,
    )

    for url in (data_url, other_terms_url, *sorted(stack_terms_urls)):
        with transport.open(url) as response:
            assert response.final_url == url

    assert default_transport.requested_urls == [data_url, other_terms_url]
    assert stack_transport.requested_urls == sorted(stack_terms_urls)


def test_urllib_transport_disables_ambient_proxy_and_uses_explicit_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen_ca = ssl.get_default_verify_paths().cafile
    assert frozen_ca is not None
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/caller-ca.pem")

    transport = _UrllibTransport(ca_bundle_path=frozen_ca)

    proxy_handlers = [
        handler
        for handler in transport._opener.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    ]
    assert proxy_handlers == []
    https_handlers = [
        handler
        for handler in transport._opener.handlers
        if isinstance(handler, urllib.request.HTTPSHandler)
    ]
    assert len(https_handlers) == 1
    assert https_handlers[0]._context.verify_mode == ssl.CERT_REQUIRED
    assert https_handlers[0]._context.check_hostname is True


def test_curl_terms_adapter_uses_the_exact_frozen_one_shot_request_policy() -> None:
    url = "https://stackoverflow.com/help/licensing"
    factory = _FakeCurlSessionFactory(
        b"<html><title>What is the license for the content I post?</title></html>"
    )
    transport = _CurlCffiTermsTransport(
        session_factory=factory,
        ca_bundle_path="/frozen/certifi/cacert.pem",
    )

    with transport.open(url) as response:
        assert response.final_url == url
        assert response.http_status == 200
        assert response.content_length is None
        assert response.http_version == "HTTP/2"
        assert response.configured_request_headers == (
            ("accept-encoding", "identity"),
            (
                "user-agent",
                (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/150.0.0.0 Safari/537.36"
                ),
            ),
        )
        assert len(response.normalized_response_headers_sha256) == 64
        assert tuple(response.chunks) == (factory.body,)

    assert factory.session_arguments == [
        {
            "curl_options": {10004: b""},
            "default_headers": False,
            "discard_cookies": True,
            "headers": {
                "Accept-Encoding": "identity",
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/150.0.0.0 Safari/537.36"
                ),
            },
            "impersonate": "chrome150",
            "retry": 0,
            "trust_env": False,
        }
    ]
    [(requested_url, request_arguments)] = factory.request_arguments
    assert requested_url == url
    assert {
        key: value for key, value in request_arguments.items() if key != "content_callback"
    } == {
        "accept_encoding": "identity",
        "allow_redirects": False,
        "http_version": "v2",
        "timeout": 120,
        "verify": "/frozen/certifi/cacert.pem",
    }
    assert factory.close_count == 1


@pytest.mark.parametrize(
    ("factory", "error_match"),
    [
        (
            _FakeCurlSessionFactory(b"<html>challenge page</html>"),
            "page marker",
        ),
        (
            _FakeCurlSessionFactory(
                b"What is the license for the content I post?",
                response_headers=[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Content-Length", "45"),
                    ("Content-Length", "45"),
                ],
            ),
            "duplicate Content-Length",
        ),
        (
            _FakeCurlSessionFactory(
                b"What is the license for the content I post?",
                response_headers=[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Content-Length", "malformed"),
                ],
            ),
            "decimal digits",
        ),
        (
            _FakeCurlSessionFactory(
                b"What is the license for the content I post?",
                http_version=2,
            ),
            "HTTP/2",
        ),
        (
            _FakeCurlSessionFactory(
                b"unused",
                chunks=(b"x" * 2_097_152, b"x"),
            ),
            "byte limit",
        ),
        (
            _FakeCurlSessionFactory(
                b"unused",
                request_error=TimeoutError("fixture timeout"),
            ),
            "frozen curl terms request failed",
        ),
    ],
    ids=(
        "challenge-marker",
        "duplicate-content-length",
        "malformed-content-length",
        "wrong-http-version",
        "cap-plus-one",
        "transport-error",
    ),
)
def test_curl_terms_adapter_fails_closed_without_profile_or_browser_fallback(
    factory: _FakeCurlSessionFactory,
    error_match: str,
) -> None:
    transport = _CurlCffiTermsTransport(
        session_factory=factory,
        ca_bundle_path="/frozen/certifi/cacert.pem",
    )

    with (
        pytest.raises(AcquisitionError, match=error_match),
        transport.open("https://stackoverflow.com/help/licensing"),
    ):
        pass

    assert len(factory.session_arguments) == 1
    assert len(factory.request_arguments) == 1
    assert factory.close_count == 1


def test_acquisition_curl_extra_and_cross_platform_wheels_are_hash_locked() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((repository_root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["optional-dependencies"]["acquisition"] == ["curl-cffi==0.16.1"]

    lock_text = (repository_root / "requirements-acquisition.txt").read_text(encoding="utf-8")
    assert "--only-binary=:all:" in lock_text
    for requirement in (
        "certifi==2026.7.22",
        "cffi==2.1.1",
        "curl-cffi==0.16.1",
        "pycparser==3.0",
    ):
        assert lock_text.count(requirement) == 1
    assert set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock_text)) == {
        "1bc9f913212d9e13499dde43b6527fa3613f3846035ea9c5b05ca24be1153a75",
        "208f941bb9d18e768138677f0a6d2ce01f590df56043dda1df1535ac57c88517",
        "210019b6c7cf07f081b4c54635c8cf744377001350e29cc0f81c4377b4797735",
        "270c8eb46002d878d361f75265b17428a54afe06a35810de9f60acbd89bdec26",
        "37890c60c5865f98b32050326612e5eee570a9767da57d4c7ef698f0bc80c1e4",
        "62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775",
        "648f3150ef49fea01f6e13b99c524d2589bacf4ca080484aae0587c014f3f89d",
        "68e62fe11f30d5ca8289242866f0a5291402d8529ca2178ab8afc5c9694ae890",
        "793d79c61ad4f8b0aeb9fd13afa58ff38a48110946b781e257013f8ffe3501dc",
        "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992",
        "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
        "c8c69575568085ba0b1b10c0249d779a214aea6f6522e949a0fc9fb0fcb449d0",
        "dce85922435cb6678e8b01a982b65ce20e8fb681e5d18588073ba3984569e76a",
        "f81b3b8f3d4e343550fa4baa0e479bba9f2d29ce9c2e9b51d1ce1718d7442fcf",
    }


def test_rehashed_source_set_role_tamper_is_rejected(tmp_path: Path) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    source_set["objects"][0]["role"] = "forged-role"
    bundle.source_set_path.chmod(0o644)
    bundle.source_set_path.write_text(
        json.dumps(source_set, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    try:
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )
    except ValueError as error:
        assert "source-set" in str(error) or "source set" in str(error)
    else:  # pragma: no cover - documents the fail-closed expectation
        raise AssertionError("rehashed source-set role tamper was accepted")


@pytest.mark.parametrize(
    "late_mutation",
    ("add-member", "replace-member", "replace-root"),
)
def test_existing_bundle_must_remain_descriptor_bound_after_semantic_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    late_mutation: str,
) -> None:
    from dynamic_cssc import publication_acquisition as acquisition_module

    bundle, _ = _acquire_stack(tmp_path)
    original_verifier = acquisition_module._verify_acquisition_directory
    displaced_member = tmp_path / "verified-source-set-preserved.json"
    displaced_root = tmp_path / "verified-acquisition-preserved"

    def verifier(artifact_directory: object, **arguments: object):  # type: ignore[no-untyped-def]
        assert not hasattr(artifact_directory, "root")
        verified = original_verifier(artifact_directory, **arguments)  # type: ignore[arg-type]
        if late_mutation == "add-member":
            (bundle.output_dir / "late-unverified.txt").write_bytes(b"unverified\n")
        elif late_mutation == "replace-member":
            source_set = bundle.source_set_path
            original_bytes = source_set.read_bytes()
            source_set.rename(displaced_member)
            source_set.write_bytes(original_bytes)
        else:
            bundle.output_dir.rename(displaced_root)
            bundle.output_dir.mkdir()
            (bundle.output_dir / "foreign.txt").write_bytes(b"foreign\n")
        return verified

    monkeypatch.setattr(acquisition_module, "_verify_acquisition_directory", verifier)

    with pytest.raises(AcquisitionError, match="descriptor-bound verification"):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    if late_mutation == "add-member":
        assert (bundle.output_dir / "late-unverified.txt").read_bytes() == b"unverified\n"
    elif late_mutation == "replace-member":
        assert displaced_member.read_bytes() == bundle.source_set_path.read_bytes()
        assert (
            displaced_member.lstat().st_dev,
            displaced_member.lstat().st_ino,
        ) != (
            bundle.source_set_path.lstat().st_dev,
            bundle.source_set_path.lstat().st_ino,
        )
    else:
        assert (bundle.output_dir / "foreign.txt").read_bytes() == b"foreign\n"
        assert (displaced_root / "ACQUISITION-TRANSACTION.json").is_file()


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (
            lambda response: replace(response, final_url="https://example.invalid/redirected"),
            "redirect",
        ),
        (lambda response: replace(response, http_status=206), "status"),
        (lambda response: replace(response, media_type="text/plain"), "media type"),
        (
            lambda response: _response_with_content_length(
                response,
                response.content_length + 1,  # type: ignore[operator]
            ),
            "Content-Length",
        ),
        (lambda response: replace(response, content_encoding="gzip"), "Content-Encoding"),
        (
            lambda response: replace(response, content_range="bytes 0-3/8"),
            "Content-Range",
        ),
    ],
    ids=(
        "redirect",
        "wrong-status",
        "wrong-media",
        "truncated-stream",
        "content-encoding",
        "content-range",
    ),
)
def test_transport_attack_cleans_the_atomic_output(
    tmp_path: Path,
    mutation,  # type: ignore[no-untyped-def]
    error_match: str,
) -> None:
    transport = _stack_transport()
    attacked_url = "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz"
    transport._responses[attacked_url] = mutation(transport._responses[attacked_url])
    output_dir = tmp_path / "rejected-acquisition"

    with pytest.raises(AcquisitionError, match=error_match):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".rejected-acquisition.tmp-*")) == []


def test_missing_frozen_transport_response_is_atomic_and_fail_closed(tmp_path: Path) -> None:
    transport = _stack_transport()
    del transport._responses["https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz"]
    output_dir = tmp_path / "missing-role-acquisition"

    with pytest.raises(AcquisitionError, match="transport failed for frozen role c2a"):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert not output_dir.exists()
    assert list(tmp_path.glob(".missing-role-acquisition.tmp-*")) == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda transaction: transaction["objects"].pop(),
        lambda transaction: transaction["objects"].append(
            {
                **transaction["objects"][0],
                "role": "extra-role",
                "local_path": "objects/data/extra-role.bin",
            }
        ),
        lambda transaction: transaction["objects"][1].update(
            {"local_path": transaction["objects"][0]["local_path"]}
        ),
    ],
    ids=("missing-role", "extra-role", "duplicate-target"),
)
def test_rehashed_transaction_cannot_change_the_exact_role_or_target_set(
    tmp_path: Path,
    mutation,  # type: ignore[no-untyped-def]
) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    mutation(transaction)
    transaction["object_count"] = len(transaction["objects"])
    bundle.transaction_path.chmod(0o644)
    bundle.transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    with pytest.raises(AcquisitionError, match="role set|role|target"):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )


def test_rehashed_transaction_cannot_mint_network_authority(tmp_path: Path) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    transaction["formal_authority_granted"] = True
    transaction["acquisition_network_authority_verified"] = True
    bundle.transaction_path.chmod(0o644)
    bundle.transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    with pytest.raises(AcquisitionError, match="closed repository-owned contract"):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (
            lambda transaction: transaction.update(
                {"schema_version": "dynamic-cssc-acquisition-transaction-v2"}
            ),
            "closed repository-owned contract",
        ),
        (
            lambda transaction: transaction["objects"][3].update(
                {"transport_adapter_id": "cpython-urllib-identity-v1"}
            ),
            "adapter route",
        ),
        (
            lambda transaction: _retarget_transaction_content_length(
                transaction,
                3,
                None,
            ),
            "terms body length",
        ),
        (
            lambda transaction: transaction["objects"][3].update({"http_version": "HTTP/1.1"}),
            "HTTP version",
        ),
        (
            lambda transaction: transaction["objects"][3]["configured_request_headers"][0].update(
                {"value": "gzip"}
            ),
            "request headers",
        ),
        (
            lambda transaction: transaction["objects"][3]["normalized_response_headers"][0].update(
                {"values": ["application/json"]}
            ),
            "response headers",
        ),
        (
            lambda transaction: transaction["objects"][3].update(
                {"normalized_response_headers_sha256": "a" * 64}
            ),
            "response-header SHA-256",
        ),
        (
            lambda transaction: transaction["transport_runtime"].update(
                {"mode": "caller-authored-runtime"}
            ),
            "test-only transport_runtime",
        ),
    ],
    ids=(
        "legacy-schema",
        "adapter-splice",
        "null-length-mode-splice",
        "http-version-splice",
        "request-header-splice",
        "response-header-observation-splice",
        "response-header-digest-splice",
        "runtime-splice",
    ),
)
def test_rehashed_transaction_cannot_retarget_v3_transport_facts(
    tmp_path: Path,
    mutation,  # type: ignore[no-untyped-def]
    error_match: str,
) -> None:
    bundle, _ = _acquire_stack(tmp_path)
    transaction = json.loads(bundle.transaction_path.read_text(encoding="ascii"))
    mutation(transaction)
    bundle.transaction_path.chmod(0o644)
    bundle.transaction_path.write_text(
        json.dumps(transaction, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    _rewrite_sha256s(bundle.output_dir)

    with pytest.raises(AcquisitionError, match=error_match):
        _verify_acquisition_bundle(
            bundle.output_dir,
            repository_snapshot=_test_only_repository_snapshot(),
            repository_root=Path(__file__).resolve().parents[1],
        )


def test_existing_and_symlink_output_paths_fail_before_transport_use(tmp_path: Path) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    existing = tmp_path / "existing"
    existing.mkdir()
    symlink_target = tmp_path / "target"
    symlink_target.mkdir()
    symlink_output = tmp_path / "symlink-output"
    symlink_output.symlink_to(symlink_target, target_is_directory=True)
    fifo_output = tmp_path / "fifo-output"
    os.mkfifo(fifo_output)

    for output_dir in (existing, symlink_output, fifo_output):
        transport = _stack_transport()
        with pytest.raises(AcquisitionError, match="must not already exist"):
            _acquire_publication_sources(
                "stack-overflow",
                output_dir,
                transport=transport,
                clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
                repository_snapshot=_test_only_repository_snapshot(),
                repository_root=repository_root,
            )
        assert transport.requested_urls == []


def test_public_interface_does_not_accept_url_transport_header_clock_or_authority_injection(
    tmp_path: Path,
) -> None:
    assert tuple(inspect.signature(acquire_publication_sources).parameters) == (
        "dataset_id",
        "output_dir",
    )
    assert tuple(inspect.signature(_acquire_publication_sources_production).parameters) == (
        "dataset_id",
        "output_dir",
    )

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        acquire_publication_sources(  # type: ignore[call-arg]
            "stack-overflow",
            tmp_path / "never-created",
            source_url="https://example.invalid/forged",
        )

    assert not (tmp_path / "never-created").exists()


def test_private_fixture_seams_require_an_active_pytest_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _test_only_repository_snapshot()
    monkeypatch.delenv("PYTEST_CURRENT_TEST")

    with pytest.raises(RuntimeError, match="available only under pytest"):
        _acquire_publication_sources(
            "stack-overflow",
            tmp_path / "guarded-fixture",
            transport=_stack_transport(),
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=snapshot,
            repository_root=Path(__file__).resolve().parents[1],
        )

    repository_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment.pop("PYTEST_CURRENT_TEST", None)
    environment["PYTHONPATH"] = str(repository_root / "src")
    result = subprocess.run(
        [
            str(repository_root / ".venv/bin/python"),
            "-c",
            (
                "from dynamic_cssc.publication_acquisition import "
                "_test_only_repository_snapshot; _test_only_repository_snapshot()"
            ),
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "available only under pytest" in result.stderr


def test_injectable_acquisition_seam_rejects_hardened_provenance_before_transport(
    tmp_path: Path,
) -> None:
    fixture_snapshot = _test_only_repository_snapshot()
    hardened_snapshot = replace(
        fixture_snapshot,
        verification_mode="hardened-acquisition-role-git-object-worktree-v1",
    )
    transport = _stack_transport()
    output_dir = tmp_path / "forged-hardened-acquisition"

    with pytest.raises(AcquisitionError, match="only accepts the test-only snapshot"):
        _acquire_publication_sources(
            "stack-overflow",
            output_dir,
            transport=transport,
            clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
            repository_snapshot=hardened_snapshot,
            repository_root=Path(__file__).resolve().parents[1],
        )

    assert transport.requested_urls == []
    assert not output_dir.exists()


def test_descriptor_bound_acquisition_verification_ignores_transient_parent_name_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dynamic_cssc import publication_acquisition as acquisition_module

    original_verifier = acquisition_module._verify_acquisition_directory
    displaced = tmp_path / "verified-acquisition-displaced"
    foreign_preserved = tmp_path / "foreign-acquisition-preserved"
    verifier_calls = 0

    def verifier(artifact_directory: object, **arguments: object):  # type: ignore[no-untyped-def]
        nonlocal verifier_calls
        verifier_calls += 1
        if verifier_calls == 1:
            [claimed] = [
                path
                for path in tmp_path.iterdir()
                if "acquisition-output.tmp-" in path.name and ".owned-" in path.name
            ]
            claimed.rename(displaced)
            claimed.mkdir()
            (claimed / "foreign-unverified.txt").write_bytes(b"not verified\n")
            try:
                return original_verifier(  # type: ignore[arg-type]
                    artifact_directory,
                    **arguments,
                )
            finally:
                claimed.rename(foreign_preserved)
                displaced.rename(claimed)
        return original_verifier(artifact_directory, **arguments)  # type: ignore[arg-type]

    monkeypatch.setattr(acquisition_module, "_verify_acquisition_directory", verifier)
    output_dir = tmp_path / "acquisition-output"

    bundle = _acquire_publication_sources(
        "stack-overflow",
        output_dir,
        transport=_stack_transport(),
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    assert bundle.output_dir == output_dir
    assert (output_dir / "ACQUISITION-TRANSACTION.json").is_file()
    assert (foreign_preserved / "foreign-unverified.txt").read_bytes() == b"not verified\n"


def test_simplewiki_uses_the_exact_versioned_object_and_cc0_terms_url(tmp_path: Path) -> None:
    data_url = (
        "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
        "2026-07.simplewiki.all-time.tsv.bz2"
    )
    terms_url = "https://dumps.wikimedia.org/other/mediawiki_history/readme.html"
    transport = _FakeTransport(
        {
            data_url: _response(data_url, b"simplewiki-fixture\n", "application/octet-stream"),
            terms_url: _response(terms_url, b"cc0-terms\n", "text/html"),
        }
    )

    bundle = _acquire_publication_sources(
        "simplewiki-2026-07",
        tmp_path / "simplewiki-acquisition",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    assert source_set["dataset_release"] == "mediawiki-history-2026-07-simplewiki-all-time"
    assert source_set["objects"][0]["role"] == "history"
    assert source_set["objects"][0]["source_url"] == data_url
    assert source_set["objects"][0]["attribution_text"] == (
        "Wikimedia Analytics MediaWiki History (CC0)"
    )
    assert source_set["terms_objects"][0]["source_url"] == terms_url
    assert transport.requested_urls == [data_url, terms_url]


def test_nyc_acquisition_freezes_all_months_and_separates_overview_anchor(
    tmp_path: Path,
) -> None:
    monthly_urls = {
        (
            "https://d37ci6vzurychx.cloudfront.net/trip-data/"
            f"yellow_tripdata_2022-{month:02d}.parquet"
        ): (
            f"month-{month:02d}\n".encode("ascii"),
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        for month in range(1, 13)
    }
    zone_url = "https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv"
    terms_urls = {
        "https://opendata.cityofnewyork.us/faq/",
        "https://opendata.cityofnewyork.us/overview/",
        "https://cityofnewyork.github.io/opendatatsm/publicpolicies.html",
        "https://www.nyc.gov/main/terms-of-use",
    }
    responses = {
        url: _response(url, content, media_type)
        for url, (content, media_type) in monthly_urls.items()
    }
    responses[zone_url] = _response(zone_url, b"LocationID\n1\n", "text/csv")
    responses.update(
        {url: _response(url, f"terms:{url}\n".encode("ascii"), "text/html") for url in terms_urls}
    )
    transport = _FakeTransport(responses)

    bundle = _acquire_publication_sources(
        "nyc-tlc-yellow-2022",
        tmp_path / "nyc-acquisition",
        transport=transport,
        clock=lambda: datetime(2026, 8, 23, tzinfo=UTC),
        repository_snapshot=_test_only_repository_snapshot(),
        repository_root=Path(__file__).resolve().parents[1],
    )

    source_set = json.loads(bundle.source_set_path.read_text(encoding="ascii"))
    assert [item["role"] for item in source_set["objects"]] == [
        *(f"yellow-2022-{month:02d}" for month in range(1, 13)),
        "zone-lookup",
    ]
    assert {item["source_url"] for item in source_set["terms_objects"]} == terms_urls
    [overview] = [
        item
        for item in source_set["terms_objects"]
        if item["source_url"] == "https://opendata.cityofnewyork.us/overview/"
    ]
    assert overview["section_anchor"] == "termsofuse"
    assert "#" not in overview["source_url"]
    assert set(transport.requested_urls) == {*monthly_urls, zone_url, *terms_urls}
    assert len(transport.requested_urls) == 17


def test_cli_exposes_only_dataset_and_output_options(tmp_path: Path) -> None:
    calls: list[tuple[str, Path]] = []

    def fake_acquirer(dataset_id: str, output_dir: Path):  # type: ignore[no-untyped-def]
        calls.append((dataset_id, output_dir))
        return object()

    output_dir = tmp_path / "bundle"
    assert (
        acquisition_cli._run_cli(
            ["--dataset-id", "stack-overflow", "--output-dir", str(output_dir)],
            acquirer=fake_acquirer,  # type: ignore[arg-type]
        )
        == 0
    )
    assert calls == [("stack-overflow", output_dir)]

    with pytest.raises(SystemExit):
        acquisition_cli._run_cli(
            [
                "--dataset-id",
                "stack-overflow",
                "--output-dir",
                str(output_dir),
                "--source-url",
                "https://example.invalid/forged",
            ],
            acquirer=fake_acquirer,  # type: ignore[arg-type]
        )
