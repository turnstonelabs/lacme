"""Tests for lacme.client — async ACME protocol client."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import httpx
import pytest

from lacme.client import Client
from lacme.crypto import b64url_decode, b64url_encode, generate_ec_key
from lacme.errors import (
    ACMEServerError,
    ACMETimeoutError,
    ACMEValidationError,
    AlreadyRevokedError,
    BadNonceError,
    MalformedError,
    RateLimitedError,
)
from lacme.models import AccountStatus, AuthorizationStatus, ChallengeStatus, OrderStatus
from lacme.store import MemoryStore

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey


# ---------------------------------------------------------------------------
# Mock ACME transport
# ---------------------------------------------------------------------------

_NONCE_COUNTER = 0

DIRECTORY_DATA = {
    "newNonce": "https://acme.test/new-nonce",
    "newAccount": "https://acme.test/new-account",
    "newOrder": "https://acme.test/new-order",
    "revokeCert": "https://acme.test/revoke-cert",
    "keyChange": "https://acme.test/key-change",
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


def _problem_response(
    error_type: str,
    detail: str = "",
    status: int = 400,
) -> httpx.Response:
    body = {
        "type": f"urn:ietf:params:acme:error:{error_type}",
        "detail": detail,
        "status": status,
    }
    return httpx.Response(
        status,
        json=body,
        headers={
            "replay-nonce": _next_nonce(),
            "content-type": "application/problem+json",
        },
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def account_key() -> EllipticCurvePrivateKey:
    return generate_ec_key()


def _make_client(
    account_key: EllipticCurvePrivateKey,
    transport: httpx.MockTransport,
) -> Client:
    http = httpx.AsyncClient(transport=transport)
    return Client(
        directory_url="https://acme.test/directory",
        account_key=account_key,
        http_client=http,
        poll_interval=0.01,
        poll_timeout=1.0,
    )


# ---------------------------------------------------------------------------
# Directory
# ---------------------------------------------------------------------------


class TestDirectory:
    @pytest.mark.anyio
    async def test_directory_fetch_and_cache(self, account_key: EllipticCurvePrivateKey) -> None:
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return _json_response(DIRECTORY_DATA)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            d = await client.directory()
            assert d.new_nonce == "https://acme.test/new-nonce"
            # Second call returns cached
            d2 = await client.directory()
            assert d2 is d
            assert call_count == 1


# ---------------------------------------------------------------------------
# Nonce management
# ---------------------------------------------------------------------------


class TestNonceManagement:
    @pytest.mark.anyio
    async def test_nonce_harvested_from_directory(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            # Directory fetch harvests a nonce, so newAccount doesn't need HEAD
            acct = await client.create_account()
            assert acct.status == "valid"


# ---------------------------------------------------------------------------
# badNonce retry
# ---------------------------------------------------------------------------


class TestBadNonceRetry:
    @pytest.mark.anyio
    async def test_retries_once_on_bad_nonce(self, account_key: EllipticCurvePrivateKey) -> None:
        attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-nonce":
                return httpx.Response(200, headers={"replay-nonce": _next_nonce()})
            if request.url.path == "/new-account":
                attempt += 1
                if attempt == 1:
                    return _problem_response("badNonce", "old nonce")
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            acct = await client.create_account()
            assert acct.status == "valid"
            assert attempt == 2

    @pytest.mark.anyio
    async def test_raises_after_max_retries(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-nonce":
                return httpx.Response(200, headers={"replay-nonce": _next_nonce()})
            if request.url.path == "/new-account":
                return _problem_response("badNonce", "always bad")
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            with pytest.raises(BadNonceError):
                await client.create_account()


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


class TestAccount:
    @pytest.mark.anyio
    async def test_create_account(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body["termsOfServiceAgreed"] is True
                # Verify JWK header (not KID) for newAccount
                header = json.loads(b64url_decode(json.loads(request.content)["protected"]))
                assert "jwk" in header
                assert "kid" not in header
                return _json_response(
                    {"status": "valid", "contact": ["mailto:a@b.com"]},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            acct = await client.create_account(contact=["mailto:a@b.com"])
            assert acct.status == AccountStatus.VALID
            assert acct.url == "https://acme.test/acct/1"

    @pytest.mark.anyio
    async def test_find_existing_account(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body.get("onlyReturnExisting") is True
                return _json_response(
                    {"status": "valid"},
                    status=200,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            acct = await client.create_account(only_return_existing=True)
            assert acct.url == "https://acme.test/acct/1"

    @pytest.mark.anyio
    async def test_deactivate_account(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/acct/1":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body["status"] == "deactivated"
                return _json_response({"status": "deactivated"})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            acct = await client.deactivate_account()
            assert acct.status == AccountStatus.DEACTIVATED

    @pytest.mark.anyio
    async def test_deactivate_without_account_raises(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        client = _make_client(account_key, httpx.MockTransport(lambda r: httpx.Response(404)))
        async with client:
            with pytest.raises(RuntimeError, match="No account URL"):
                await client.deactivate_account()


# ---------------------------------------------------------------------------
# Order lifecycle
# ---------------------------------------------------------------------------

ORDER_DATA: dict[str, Any] = {
    "status": "pending",
    "identifiers": [{"type": "dns", "value": "example.com"}],
    "authorizations": ["https://acme.test/authz/1"],
    "finalize": "https://acme.test/finalize/1",
}

AUTHZ_DATA: dict[str, Any] = {
    "identifier": {"type": "dns", "value": "example.com"},
    "status": "pending",
    "challenges": [
        {
            "type": "http-01",
            "url": "https://acme.test/chall/1",
            "status": "pending",
            "token": "test-token",
        }
    ],
}


class TestOrderLifecycle:
    @pytest.mark.anyio
    async def test_create_order(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/new-order":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body["identifiers"] == [{"type": "dns", "value": "example.com"}]
                return _json_response(
                    ORDER_DATA, status=201, headers={"location": "https://acme.test/order/1"}
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            order = await client.create_order("example.com")
            assert order.status == OrderStatus.PENDING
            assert order.url == "https://acme.test/order/1"

    @pytest.mark.anyio
    async def test_get_authorizations(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
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
                    ORDER_DATA, status=201, headers={"location": "https://acme.test/order/1"}
                )
            if request.url.path == "/authz/1":
                return _json_response(AUTHZ_DATA)
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            order = await client.create_order("example.com")
            authzs = await client.get_authorizations(order)
            assert len(authzs) == 1
            assert authzs[0].identifier.value == "example.com"
            chall = authzs[0].find_challenge("http-01")
            assert chall is not None
            assert chall.token == "test-token"

    @pytest.mark.anyio
    async def test_respond_to_challenge(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/chall/1":
                # Verify empty body
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body == {}
                return _json_response(
                    {
                        "type": "http-01",
                        "url": "https://acme.test/chall/1",
                        "status": "processing",
                        "token": "test-token",
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            from lacme.models import Challenge

            chall = Challenge.from_dict(
                {
                    "type": "http-01",
                    "url": "https://acme.test/chall/1",
                    "status": "pending",
                    "token": "test-token",
                }
            )
            updated = await client.respond_to_challenge(chall)
            assert updated.status == ChallengeStatus.PROCESSING

    @pytest.mark.anyio
    async def test_finalize_order(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/finalize/1":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert "csr" in body
                return _json_response(
                    {
                        "status": "processing",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            from lacme.models import Order

            order = Order.from_dict(ORDER_DATA, url="https://acme.test/order/1")
            csr = b"fake-csr-der"
            updated = await client.finalize_order(order, csr)
            assert updated.status == OrderStatus.PROCESSING


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------


class TestPolling:
    @pytest.mark.anyio
    async def test_poll_authorization_valid(self, account_key: EllipticCurvePrivateKey) -> None:
        attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/authz/1":
                attempt += 1
                status = "valid" if attempt >= 2 else "pending"
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": status,
                        "challenges": [],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            authz = await client.poll_authorization("https://acme.test/authz/1")
            assert authz.status == AuthorizationStatus.VALID
            assert attempt == 2

    @pytest.mark.anyio
    async def test_poll_authorization_invalid_raises(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/authz/1":
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": "invalid",
                        "challenges": [],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(ACMEValidationError):
                await client.poll_authorization("https://acme.test/authz/1")

    @pytest.mark.anyio
    async def test_poll_authorization_timeout(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/authz/1":
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": "pending",
                        "challenges": [],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        client._poll_timeout = 0.05
        async with client:
            await client.create_account()
            with pytest.raises(ACMETimeoutError):
                await client.poll_authorization("https://acme.test/authz/1")

    @pytest.mark.anyio
    async def test_poll_order_valid(self, account_key: EllipticCurvePrivateKey) -> None:
        attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/order/1":
                attempt += 1
                status = "valid" if attempt >= 2 else "processing"
                data: dict[str, Any] = {
                    "status": status,
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                }
                if status == "valid":
                    data["certificate"] = "https://acme.test/cert/1"
                return _json_response(data)
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            order = await client.poll_order("https://acme.test/order/1")
            assert order.status == OrderStatus.VALID
            assert order.certificate == "https://acme.test/cert/1"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    @pytest.mark.anyio
    async def test_rate_limited_error(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return httpx.Response(
                    429,
                    json={
                        "type": "urn:ietf:params:acme:error:rateLimited",
                        "detail": "too fast",
                        "status": 429,
                    },
                    headers={
                        "replay-nonce": _next_nonce(),
                        "content-type": "application/problem+json",
                        "retry-after": "60",
                    },
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            with pytest.raises(RateLimitedError) as exc_info:
                await client.create_account()
            assert exc_info.value.retry_after == 60

    @pytest.mark.anyio
    async def test_malformed_error(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _problem_response("malformed", "bad payload")
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            with pytest.raises(MalformedError):
                await client.create_account()


# ---------------------------------------------------------------------------
# Wildcard validation
# ---------------------------------------------------------------------------


class TestWildcard:
    @pytest.mark.anyio
    async def test_wildcard_with_http01_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        handler_mock = AsyncMock()
        handler_mock.provision = AsyncMock()
        handler_mock.deprovision = AsyncMock()

        def transport_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        http = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            challenge_handler=handler_mock,
        )
        async with client:
            with pytest.raises(ValueError, match="Wildcard.*requires dns-01"):
                await client.issue("*.example.com", challenge_type="http-01")


# ---------------------------------------------------------------------------
# Full issue flow
# ---------------------------------------------------------------------------


class TestIssueFlow:
    @pytest.mark.anyio
    async def test_full_issue_flow(self, account_key: EllipticCurvePrivateKey) -> None:
        """End-to-end test with mock transport simulating complete ACME flow."""
        # Generate a real self-signed cert for the mock to return
        import datetime

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
        )
        from cryptography.x509 import (
            CertificateBuilder,
            DNSName,
            Name,
            NameAttribute,
            SubjectAlternativeName,
            random_serial_number,
        )
        from cryptography.x509.oid import NameOID

        cert_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        subject = Name([NameAttribute(NameOID.COMMON_NAME, "example.com")])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(cert_key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(SubjectAlternativeName([DNSName("example.com")]), critical=False)
            .sign(cert_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(Encoding.PEM).decode("ascii")

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
                # Re-fetch order: return "ready" (or "valid" after finalize)
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

        challenge_handler = AsyncMock()
        challenge_handler.provision = AsyncMock()
        challenge_handler.deprovision = AsyncMock()

        store = MemoryStore()
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            store=store,
            challenge_handler=challenge_handler,
            poll_interval=0.01,
        )

        async with client:
            bundle = await client.issue("example.com")

        assert bundle.domain == "example.com"
        assert bundle.domains == ("example.com",)
        assert b"BEGIN CERTIFICATE" in bundle.cert_pem
        assert b"BEGIN PRIVATE KEY" in bundle.key_pem

        # Verify challenge handler was called
        challenge_handler.provision.assert_called_once()
        challenge_handler.deprovision.assert_called_once()

        # Verify stored in MemoryStore
        stored = store.load_cert("example.com")
        assert stored is not None


# ---------------------------------------------------------------------------
# Additional coverage: deprovision on failure, Retry-After, poll_order, etc.
# ---------------------------------------------------------------------------


class TestDeprovisionOnFailure:
    @pytest.mark.anyio
    async def test_deprovision_called_on_poll_failure(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        """Verify challenge deprovision happens even when polling fails."""
        authz_attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal authz_attempt
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
                if authz_attempt == 1:
                    return _json_response(AUTHZ_DATA)
                # Authorization becomes invalid on poll
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": "invalid",
                        "challenges": [],
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
            return httpx.Response(404)

        challenge_handler = AsyncMock()
        challenge_handler.provision = AsyncMock()
        challenge_handler.deprovision = AsyncMock()

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            challenge_handler=challenge_handler,
            poll_interval=0.01,
        )

        async with client:
            with pytest.raises(ACMEValidationError):
                await client.issue("example.com")

        # Deprovision MUST be called even though polling failed
        challenge_handler.deprovision.assert_called_once()


class TestRetryAfterParsing:
    @pytest.mark.anyio
    async def test_retry_after_respected_in_poll(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        attempt = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempt
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/authz/1":
                attempt += 1
                status = "valid" if attempt >= 2 else "pending"
                return httpx.Response(
                    200,
                    json={
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": status,
                        "challenges": [],
                    },
                    headers={
                        "replay-nonce": _next_nonce(),
                        "content-type": "application/json",
                        "retry-after": "1",
                    },
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            authz = await client.poll_authorization("https://acme.test/authz/1")
            assert authz.status == AuthorizationStatus.VALID
            assert attempt == 2


class TestPollOrderEdgeCases:
    @pytest.mark.anyio
    async def test_poll_order_timeout(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/order/1":
                return _json_response(
                    {
                        "status": "processing",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        client._poll_timeout = 0.05
        async with client:
            await client.create_account()
            with pytest.raises(ACMETimeoutError):
                await client.poll_order("https://acme.test/order/1")

    @pytest.mark.anyio
    async def test_poll_order_invalid_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/order/1":
                return _json_response(
                    {
                        "status": "invalid",
                        "identifiers": [{"type": "dns", "value": "example.com"}],
                        "error": {
                            "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                            "detail": "rejected",
                        },
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(ACMEValidationError, match="invalid"):
                await client.poll_order("https://acme.test/order/1")


class TestCreateAccountRestore:
    @pytest.mark.anyio
    async def test_account_url_restored_on_failure(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        """If create_account fails, _account_url should be restored."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _problem_response("malformed", "bad request")
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        # Manually set an account URL to simulate pre-existing state
        client._account_url = "https://acme.test/acct/old"
        async with client:
            with pytest.raises(MalformedError):
                await client.create_account()
            # URL should be restored after failure
            assert client._account_url == "https://acme.test/acct/old"


class TestIssueNoHandler:
    @pytest.mark.anyio
    async def test_issue_without_handler_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
        )
        async with client:
            with pytest.raises(ValueError, match="No challenge handler"):
                await client.issue("example.com")


class TestContactFallback:
    @pytest.mark.anyio
    async def test_create_account_uses_instance_contact(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        """create_account() without explicit contact should use constructor contact."""
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            contact="mailto:ops@example.com",
        )
        async with client:
            await client.create_account()

        assert captured_payload["contact"] == ["mailto:ops@example.com"]


# ---------------------------------------------------------------------------
# poll_authorization non-VALID terminal states
# ---------------------------------------------------------------------------


class TestPollAuthzTerminalStates:
    @pytest.mark.parametrize("terminal_status", ["deactivated", "expired", "revoked"])
    @pytest.mark.anyio
    async def test_non_valid_terminal_raises(
        self,
        account_key: EllipticCurvePrivateKey,
        terminal_status: str,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/authz/1":
                return _json_response(
                    {
                        "identifier": {"type": "dns", "value": "example.com"},
                        "status": terminal_status,
                        "challenges": [],
                    }
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(ACMEValidationError, match="terminal state"):
                await client.poll_authorization("https://acme.test/authz/1")


# ---------------------------------------------------------------------------
# Unexpected 2xx status
# ---------------------------------------------------------------------------


class TestUnexpectedStatus:
    @pytest.mark.anyio
    async def test_unexpected_2xx_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        """If expected_status={201} but server returns 200, should raise."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-order":
                # Return 200 instead of expected 201
                return _json_response(
                    ORDER_DATA,
                    status=200,
                    headers={"location": "https://acme.test/order/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        # Manually set account_url so we skip create_account
        client._account_url = "https://acme.test/acct/1"
        async with client:
            with pytest.raises(httpx.HTTPStatusError, match="Unexpected status 200"):
                await client.create_order("example.com")


# ---------------------------------------------------------------------------
# Pre-authorization
# ---------------------------------------------------------------------------

DIRECTORY_WITH_AUTHZ = {
    **DIRECTORY_DATA,
    "newAuthz": "https://acme.test/new-authz",
}


class TestPreAuthorization:
    @pytest.mark.anyio
    async def test_create_authorization(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_WITH_AUTHZ)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/new-authz":
                body = json.loads(b64url_decode(json.loads(request.content)["payload"]))
                assert body["identifier"] == {"type": "dns", "value": "example.com"}
                return _json_response(
                    AUTHZ_DATA,
                    status=201,
                    headers={"location": "https://acme.test/authz/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            authz = await client.create_authorization("example.com")
            assert authz.identifier.value == "example.com"
            assert authz.url == "https://acme.test/authz/1"

    @pytest.mark.anyio
    async def test_create_authorization_no_new_authz_raises(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)  # no newAuthz
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(RuntimeError, match="does not support pre-authorization"):
                await client.create_authorization("example.com")


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def _make_test_cert_pem() -> tuple[bytes, EllipticCurvePrivateKey]:
    """Generate a self-signed certificate and return (cert_pem_bytes, private_key)."""
    import datetime

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

    cert_key = ec_mod.generate_private_key(ec_mod.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = Name([NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(cert_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(SubjectAlternativeName([DNSName("example.com")]), critical=False)
        .sign(cert_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(Encoding.PEM)
    return cert_pem, cert_key


class TestRevocation:
    @pytest.mark.anyio
    async def test_revoke_with_account_key(self, account_key: EllipticCurvePrivateKey) -> None:
        cert_pem, _cert_key = _make_test_cert_pem()
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/revoke-cert":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response({})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            await client.revoke(cert_pem)

        assert "certificate" in captured_payload
        # Verify the certificate field is base64url-encoded DER
        from lacme.crypto import pem_to_der_certificate

        expected_der = pem_to_der_certificate(cert_pem)
        assert captured_payload["certificate"] == b64url_encode(expected_der)

    @pytest.mark.anyio
    async def test_revoke_with_reason(self, account_key: EllipticCurvePrivateKey) -> None:
        cert_pem, _cert_key = _make_test_cert_pem()
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/revoke-cert":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response({})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            await client.revoke(cert_pem, reason=1)

        assert captured_payload["reason"] == 1

    @pytest.mark.anyio
    async def test_revoke_invalid_reason(self, account_key: EllipticCurvePrivateKey) -> None:
        cert_pem, _cert_key = _make_test_cert_pem()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(ValueError, match="Invalid revocation reason 2"):
                await client.revoke(cert_pem, reason=2)

    @pytest.mark.anyio
    async def test_revoke_already_revoked(self, account_key: EllipticCurvePrivateKey) -> None:
        cert_pem, _cert_key = _make_test_cert_pem()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/revoke-cert":
                return _problem_response("alreadyRevoked", "Certificate already revoked")
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            with pytest.raises(AlreadyRevokedError):
                await client.revoke(cert_pem)

    @pytest.mark.anyio
    async def test_revoke_with_cert_key(self, account_key: EllipticCurvePrivateKey) -> None:
        """Sign with cert key — JWS should have jwk header, not kid."""
        cert_pem, cert_key = _make_test_cert_pem()
        captured_header: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-nonce":
                return httpx.Response(200, headers={"replay-nonce": _next_nonce()})
            if request.url.path == "/revoke-cert":
                jws = json.loads(request.content)
                captured_header.update(json.loads(b64url_decode(jws["protected"])))
                return _json_response({})
            return httpx.Response(404)

        # No create_account needed for cert-key revocation
        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.revoke_with_cert_key(cert_pem, cert_key)

        assert "jwk" in captured_header
        assert "kid" not in captured_header

    @pytest.mark.anyio
    async def test_revoke_accepts_str_pem(self, account_key: EllipticCurvePrivateKey) -> None:
        cert_pem_bytes, _cert_key = _make_test_cert_pem()
        cert_pem_str = cert_pem_bytes.decode("ascii")
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/revoke-cert":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response({})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            await client.revoke(cert_pem_str)

        assert "certificate" in captured_payload
        # Should produce same result as bytes
        from lacme.crypto import pem_to_der_certificate

        expected_der = pem_to_der_certificate(cert_pem_bytes)
        assert captured_payload["certificate"] == b64url_encode(expected_der)


# ---------------------------------------------------------------------------
# Key Rollover
# ---------------------------------------------------------------------------


class TestKeyRollover:
    @pytest.mark.anyio
    async def test_rollover_key_success(self, account_key: EllipticCurvePrivateKey) -> None:
        """Verify inner/outer JWS structure: outer has kid+nonce, inner has jwk + no nonce."""
        new_key = generate_ec_key()
        captured_outer_header: dict[str, Any] = {}
        captured_inner_jws: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/key-change":
                outer_jws = json.loads(request.content)
                captured_outer_header.update(json.loads(b64url_decode(outer_jws["protected"])))
                # The outer payload is the inner JWS (a dict)
                inner_jws = json.loads(b64url_decode(outer_jws["payload"]))
                captured_inner_jws.update(inner_jws)
                return _json_response({})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            await client.rollover_key(new_key)

        # Outer JWS: must have kid and nonce (standard account-key signed)
        assert "kid" in captured_outer_header
        assert "nonce" in captured_outer_header
        assert captured_outer_header["kid"] == "https://acme.test/acct/1"

        # Inner JWS: must have jwk (new key), no nonce
        inner_header = json.loads(b64url_decode(captured_inner_jws["protected"]))
        assert "jwk" in inner_header
        assert "nonce" not in inner_header

        # Inner payload: must have "account" and "oldKey"
        inner_payload = json.loads(b64url_decode(captured_inner_jws["payload"]))
        assert inner_payload["account"] == "https://acme.test/acct/1"
        assert "oldKey" in inner_payload

    @pytest.mark.anyio
    async def test_rollover_generates_key(self, account_key: EllipticCurvePrivateKey) -> None:
        """Call rollover_key with no args — verify key changed."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/key-change":
                return _json_response({})
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            original_key = client._account_key
            await client.rollover_key()
            assert client._account_key is not original_key
            assert client._account_key is not None

    @pytest.mark.anyio
    async def test_rollover_saves_to_store(self, account_key: EllipticCurvePrivateKey) -> None:
        store = MemoryStore()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/key-change":
                return _json_response({})
            return httpx.Response(404)

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            store=store,
        )
        async with client:
            await client.create_account()
            new_key = generate_ec_key()
            await client.rollover_key(new_key)

        stored_key = store.load_account_key()
        assert stored_key is not None
        # Compare public key numbers to verify it is the new key
        assert stored_key.public_key().public_numbers() == new_key.public_key().public_numbers()

    @pytest.mark.anyio
    async def test_rollover_failure_preserves_key(
        self, account_key: EllipticCurvePrivateKey
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            if request.url.path == "/key-change":
                return _problem_response("serverInternal", "key change failed", status=500)
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()
            original_key = client._account_key
            with pytest.raises(ACMEServerError):
                await client.rollover_key()
            # Key should remain unchanged after failure
            assert client._account_key is original_key

    @pytest.mark.anyio
    async def test_rollover_no_account_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        client = _make_client(account_key, httpx.MockTransport(lambda r: httpx.Response(404)))
        async with client:
            with pytest.raises(RuntimeError, match="No account URL"):
                await client.rollover_key()


# ---------------------------------------------------------------------------
# External Account Binding
# ---------------------------------------------------------------------------


class TestExternalAccountBinding:
    @pytest.mark.anyio
    async def test_create_account_with_eab(self, account_key: EllipticCurvePrivateKey) -> None:
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account(
                eab_kid="kid-12345",
                eab_hmac_key=b64url_encode(b"test-hmac-secret-key-value-here!"),
            )

        assert "externalAccountBinding" in captured_payload
        eab = captured_payload["externalAccountBinding"]
        # EAB is a JWS: verify protected header has alg=HS256 and kid=eab_kid
        eab_header = json.loads(b64url_decode(eab["protected"]))
        assert eab_header["alg"] == "HS256"
        assert eab_header["kid"] == "kid-12345"

    @pytest.mark.anyio
    async def test_eab_from_constructor(self, account_key: EllipticCurvePrivateKey) -> None:
        """EAB params from Client constructor should be used by create_account()."""
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = Client(
            directory_url="https://acme.test/directory",
            account_key=account_key,
            http_client=http,
            eab_kid="constructor-kid",
            eab_hmac_key=b64url_encode(b"constructor-hmac-secret-key!!!!!"),
        )
        async with client:
            # Call create_account without EAB params — should use constructor values
            await client.create_account()

        assert "externalAccountBinding" in captured_payload
        eab = captured_payload["externalAccountBinding"]
        eab_header = json.loads(b64url_decode(eab["protected"]))
        assert eab_header["kid"] == "constructor-kid"

    @pytest.mark.anyio
    async def test_eab_kid_without_key_raises(self, account_key: EllipticCurvePrivateKey) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            with pytest.raises(ValueError, match="Both eab_kid and eab_hmac_key must be provided"):
                await client.create_account(eab_kid="orphan-kid")

    @pytest.mark.anyio
    async def test_no_eab_no_binding(self, account_key: EllipticCurvePrivateKey) -> None:
        captured_payload: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/directory":
                return _json_response(DIRECTORY_DATA)
            if request.url.path == "/new-account":
                captured_payload.update(
                    json.loads(b64url_decode(json.loads(request.content)["payload"]))
                )
                return _json_response(
                    {"status": "valid"},
                    status=201,
                    headers={"location": "https://acme.test/acct/1"},
                )
            return httpx.Response(404)

        client = _make_client(account_key, httpx.MockTransport(handler))
        async with client:
            await client.create_account()

        assert "externalAccountBinding" not in captured_payload
