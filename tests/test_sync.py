"""Tests for lacme.sync — synchronous ACME client wrapper."""

from __future__ import annotations

import datetime
import warnings
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import (
    CertificateBuilder,
    DNSName,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    random_serial_number,
)
from cryptography.x509.oid import NameOID

from lacme.models import AccountStatus, Directory
from lacme.sync import SyncChallengeHandler, SyncClient, _SyncToAsyncAdapter

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


# ---------------------------------------------------------------------------
# Mock ACME transport (mirrors test_client.py patterns)
# ---------------------------------------------------------------------------

_NONCE_COUNTER = 0

DIRECTORY_DATA: dict[str, Any] = {
    "newNonce": "https://acme.test/new-nonce",
    "newAccount": "https://acme.test/new-account",
    "newOrder": "https://acme.test/new-order",
    "revokeCert": "https://acme.test/revoke-cert",
    "keyChange": "https://acme.test/key-change",
}

ORDER_DATA: dict[str, Any] = {
    "status": "pending",
    "identifiers": [{"type": "dns", "value": "example.com"}],
    "authorizations": ["https://acme.test/authz/1"],
    "finalize": "https://acme.test/finalize/1",
}


def _next_nonce() -> str:
    global _NONCE_COUNTER  # noqa: PLW0603
    _NONCE_COUNTER += 1
    return f"nonce-{_NONCE_COUNTER}"


def _json_response(
    data: dict[str, Any],
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    h = {"replay-nonce": _next_nonce(), "content-type": "application/json"}
    if headers:
        h.update(headers)
    return httpx.Response(status, json=data, headers=h)


def _make_sync_client(
    account_key: EllipticCurvePrivateKey,
    transport: httpx.MockTransport,
    **kwargs: Any,
) -> SyncClient:
    http = httpx.AsyncClient(transport=transport)
    return SyncClient(
        directory_url="https://acme.test/directory",
        account_key=account_key,
        http_client=http,
        poll_interval=0.01,
        poll_timeout=1.0,
        **kwargs,
    )


def _make_cert_pem(domain: str = "example.com") -> str:
    """Generate a self-signed cert PEM for mock responses."""
    cert_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = Name([NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(cert_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(SubjectAlternativeName([DNSName(domain)]), critical=False)
        .sign(cert_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_context_manager(self, account_key: EllipticCurvePrivateKey) -> None:
        """SyncClient works as a context manager."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            return httpx.Response(404)

        with _make_sync_client(account_key, httpx.MockTransport(handler)) as client:
            d = client.directory()
            assert d.new_nonce == "https://acme.test/new-nonce"


class TestIssue:
    def test_issue_delegates(self, account_key: EllipticCurvePrivateKey) -> None:
        """SyncClient.issue delegates to async Client.issue via the mock transport."""
        cert_pem = _make_cert_pem()
        authz_attempt = 0
        order_attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal authz_attempt, order_attempt
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/new-order":
                return _json_response(
                    ORDER_DATA,
                    status=201,
                    headers={"location": "https://acme.test/order/1"},
                )
            if request.url.path == "/authz/1":
                authz_attempt += 1
                status = "valid" if authz_attempt >= 2 else "pending"
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": status,
                        "challenges": [
                            {
                                "type": "http-01",
                                "url": "https://acme.test/chall/1",
                                "status": status,
                                "token": "test-token",
                            }
                        ],
                    }
                )
            if request.url.path == "/chall/1":
                return _json_response(
                    {
                        "type": "http-01",
                        "url": "https://acme.test/chall/1",
                        "status": "processing",
                        "token": "test-token",
                    }
                )
            if request.url.path == "/order/1":
                order_attempt += 1
                if order_attempt == 1:
                    return _json_response(
                        {
                            "status": "ready",
                            "identifiers": [{"type": "dns", "value": "example.com"}],
                            "authorizations": ["https://acme.test/authz/1"],
                            "finalize": "https://acme.test/finalize/1",
                        }
                    )
                return _json_response(
                    {
                        "status": "valid",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                        "certificate": "https://acme.test/cert/1",
                    }
                )
            if request.url.path == "/finalize/1":
                return _json_response(
                    {
                        "status": "processing",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                    }
                )
            if request.url.path == "/cert/1":
                return httpx.Response(
                    200,
                    text=cert_pem,
                    headers={
                        "replay-nonce": _next_nonce(),
                        "content-type": "application/pem-certificate-chain",
                    },
                )
            return httpx.Response(404)

        sync_handler = MagicMock(spec=SyncChallengeHandler)

        with _make_sync_client(
            account_key,
            httpx.MockTransport(handler),
            challenge_handler=sync_handler,
        ) as client:
            bundle = client.issue("example.com")

        assert bundle.domain == "example.com"
        assert bundle.domains == ("example.com",)
        assert b"BEGIN CERTIFICATE" in bundle.cert_pem
        assert b"BEGIN PRIVATE KEY" in bundle.key_pem

        sync_handler.provision.assert_called_once()
        sync_handler.deprovision.assert_called_once()


class TestDirectory:
    def test_directory(self, account_key: EllipticCurvePrivateKey) -> None:
        """directory() returns a Directory object synchronously."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            return httpx.Response(404)

        with _make_sync_client(account_key, httpx.MockTransport(handler)) as client:
            d = client.directory()
            assert isinstance(d, Directory)
            assert d.new_account == "https://acme.test/new-account"
            assert d.new_order == "https://acme.test/new-order"


class TestCreateAccount:
    def test_create_account(self, account_key: EllipticCurvePrivateKey) -> None:
        """create_account() works synchronously."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid", "contact": ["mailto:test@example.com"]},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        with _make_sync_client(account_key, httpx.MockTransport(handler)) as client:
            acct = client.create_account()
            assert acct.status == AccountStatus.VALID
            assert acct.url == "https://acme.test/acct/1"


class TestSyncChallengeHandlerAdapted:
    def test_sync_challenge_handler_adapted(self) -> None:
        """A SyncChallengeHandler is wrapped with _SyncToAsyncAdapter."""
        sync_handler = MagicMock(spec=SyncChallengeHandler)

        # Verify the sync handler satisfies the protocol
        assert isinstance(sync_handler, SyncChallengeHandler)

        # Wrap it
        adapter = _SyncToAsyncAdapter(sync_handler)

        # Verify the adapter's async methods call through to sync methods
        import asyncio

        asyncio.run(adapter.provision("example.com", "tok", "ka"))
        sync_handler.provision.assert_called_once_with("example.com", "tok", "ka")

        asyncio.run(adapter.deprovision("example.com", "tok"))
        sync_handler.deprovision.assert_called_once_with("example.com", "tok")

    def test_async_handler_passed_through(self, account_key: EllipticCurvePrivateKey) -> None:
        """An async ChallengeHandler is passed through without wrapping."""
        async_handler = AsyncMock()
        async_handler.provision = AsyncMock()
        async_handler.deprovision = AsyncMock()

        def handler(request: httpx.Request) -> httpx.Response:
            return _json_response(DIRECTORY_DATA)

        # When an async handler is provided, SyncClient should pass it through
        # directly to Client (no _SyncToAsyncAdapter wrapping).
        client = _make_sync_client(
            account_key,
            httpx.MockTransport(handler),
            challenge_handler=async_handler,
        )
        # The underlying Client should have the original async handler, not an adapter
        assert client._client._challenge_handler is async_handler
        client.close()


class TestCloseWithoutContextManager:
    def test_close_without_context_manager(self, account_key: EllipticCurvePrivateKey) -> None:
        """close() can be called directly without using a context manager."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            return httpx.Response(404)

        client = _make_sync_client(account_key, httpx.MockTransport(handler))
        d = client.directory()
        assert d.new_nonce == "https://acme.test/new-nonce"
        client.close()

        # After close, the runner should be shut down.
        # The coroutine created by Client.directory() will never be awaited,
        # which is expected — suppress the resulting RuntimeWarning.
        with (
            warnings.catch_warnings(),
            pytest.raises(RuntimeError, match="_AsyncRunner is not open"),
        ):
            warnings.simplefilter("ignore", RuntimeWarning)
            client.directory()
