"""Tests for lacme.testing — MockACMEServer."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificates

from lacme.testing import MockACMEServer


@pytest.fixture
def server() -> MockACMEServer:
    return MockACMEServer()


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# Full issue flow
# ---------------------------------------------------------------------------


class TestMockServerFullFlow:
    @pytest.mark.anyio
    async def test_full_issue_flow(self, server: MockACMEServer, account_key):
        """End-to-end: issue a certificate through MockACMEServer."""
        import httpx

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["example.com"])

        assert bundle.domain == "example.com"
        assert bundle.domains == ("example.com",)
        assert bundle.cert_pem
        assert bundle.fullchain_pem
        assert bundle.key_pem

    @pytest.mark.anyio
    async def test_multi_domain_issue(self, server: MockACMEServer, account_key):
        """Issue a certificate for multiple domains."""
        import httpx

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["example.com", "www.example.com"])

        assert bundle.domains == ("example.com", "www.example.com")


# ---------------------------------------------------------------------------
# Account operations
# ---------------------------------------------------------------------------


class TestMockAccountCreate:
    @pytest.mark.anyio
    async def test_create_account(self, server: MockACMEServer, account_key):
        import httpx

        from lacme.client import Client

        transport = server.as_transport()
        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
            ) as client,
        ):
            account = await client.create_account(contact=["mailto:test@example.com"])

        assert account.status == "valid"
        assert account.url

    @pytest.mark.anyio
    async def test_find_existing_account(self, server: MockACMEServer, account_key):
        import httpx

        from lacme.client import Client

        transport = server.as_transport()
        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
            ) as client,
        ):
            acct1 = await client.create_account()
            acct2 = await client.create_account(only_return_existing=True)

        assert acct1.url == acct2.url


# ---------------------------------------------------------------------------
# Challenge validation
# ---------------------------------------------------------------------------


class TestMockAutoValidate:
    @pytest.mark.anyio
    async def test_auto_validate(self, account_key):
        """With auto_validate=True, challenges immediately become valid."""
        server = MockACMEServer(auto_validate=True)

        import httpx

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["auto.example.com"])

        assert bundle.domain == "auto.example.com"


class TestMockManualValidate:
    def test_manual_validate(self):
        """With auto_validate=False, challenges stay in processing."""
        server = MockACMEServer(auto_validate=False)

        # Create an order to get a challenge
        import httpx

        transport = server.as_transport()

        # Simulate creating an order
        req = httpx.Request(
            "POST",
            "https://acme.test/new-order",
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZXhhbXBsZS5jb20ifV19","signature":""}',
        )
        resp = transport.handle_request(req)
        assert resp.status_code == 201

        order_data = json.loads(resp.content)
        authz_url = order_data["authorizations"][0]

        # Get authz and respond to challenge
        req2 = httpx.Request(
            "POST",
            authz_url,
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"","signature":""}',
        )
        resp2 = transport.handle_request(req2)
        authz_data = json.loads(resp2.content)
        assert authz_data["status"] == "pending"

        # Respond to challenge
        chall_url = authz_data["challenges"][0]["url"]
        req3 = httpx.Request(
            "POST",
            chall_url,
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"e30","signature":""}',
        )
        resp3 = transport.handle_request(req3)
        chall_data = json.loads(resp3.content)
        assert chall_data["status"] == "processing"

        # Manually validate
        server.validate_challenge(chall_url)

        # Now authz should be valid
        resp4 = transport.handle_request(req2)
        authz_data2 = json.loads(resp4.content)
        assert authz_data2["status"] == "valid"


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestMockRevocation:
    @pytest.mark.anyio
    async def test_revoke(self, server: MockACMEServer, account_key):
        import httpx

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["revoke.example.com"])
            await client.revoke(bundle.cert_pem)


# ---------------------------------------------------------------------------
# Certificate validity
# ---------------------------------------------------------------------------


class TestMockCertParseable:
    @pytest.mark.anyio
    async def test_cert_is_valid_pem(self, server: MockACMEServer, account_key):
        """The generated certificate should be parseable."""
        import httpx

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["cert.example.com"])

        certs = load_pem_x509_certificates(bundle.fullchain_pem)
        assert len(certs) >= 1
        assert certs[0].subject.rfc4514_string().startswith("CN=cert.example.com")


# ---------------------------------------------------------------------------
# Transport helper
# ---------------------------------------------------------------------------


class TestAsTransport:
    def test_returns_mock_transport(self, server: MockACMEServer):
        import httpx

        transport = server.as_transport()
        assert isinstance(transport, httpx.MockTransport)
