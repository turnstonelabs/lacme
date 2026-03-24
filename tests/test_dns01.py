"""Tests for lacme.challenges.dns01 — DNS-01 challenge handler."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, patch

import pytest

from lacme.challenges import ChallengeHandler
from lacme.challenges.dns01 import (
    DNS01Handler,
    DNSProvider,
    _acme_challenge_domain,
    _dns01_digest,
)
from lacme.crypto import b64url_encode
from lacme.errors import ACMETimeoutError


class MockDNSProvider:
    """Minimal DNS provider for testing."""

    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str]] = []

    async def create_txt_record(self, domain: str, value: str) -> None:
        self.created.append((domain, value))

    async def delete_txt_record(self, domain: str, value: str) -> None:
        self.deleted.append((domain, value))


class TestAcmeChallengeDomain:
    def test_plain_domain(self) -> None:
        assert _acme_challenge_domain("example.com") == "_acme-challenge.example.com"

    def test_subdomain(self) -> None:
        assert _acme_challenge_domain("sub.example.com") == "_acme-challenge.sub.example.com"

    def test_wildcard_strips_star(self) -> None:
        assert _acme_challenge_domain("*.example.com") == "_acme-challenge.example.com"

    def test_wildcard_subdomain(self) -> None:
        assert _acme_challenge_domain("*.sub.example.com") == "_acme-challenge.sub.example.com"


class TestDNS01Digest:
    def test_digest_matches_rfc(self) -> None:
        """Verify base64url(SHA-256(key_authorization)) computation."""
        key_authz = "token123.thumbprint"
        expected = b64url_encode(hashlib.sha256(key_authz.encode("ascii")).digest())
        assert _dns01_digest(key_authz) == expected

    def test_digest_is_base64url(self) -> None:
        result = _dns01_digest("test.value")
        # base64url uses only these characters (no padding)
        assert all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in result
        )


class TestDNS01Handler:
    @pytest.mark.anyio
    async def test_provision_creates_txt_record(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider, propagation_delay=0.0)
        key_authz = "token123.thumbprint"
        await handler.provision("example.com", "token123", key_authz)

        expected_domain = "_acme-challenge.example.com"
        expected_digest = _dns01_digest(key_authz)
        assert len(provider.created) == 1
        assert provider.created[0] == (expected_domain, expected_digest)

    @pytest.mark.anyio
    async def test_deprovision_deletes_record(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider, propagation_delay=0.0)
        key_authz = "token123.thumbprint"
        await handler.provision("example.com", "token123", key_authz)
        await handler.deprovision("example.com", "token123")

        expected_domain = "_acme-challenge.example.com"
        expected_digest = _dns01_digest(key_authz)
        assert len(provider.deleted) == 1
        assert provider.deleted[0] == (expected_domain, expected_digest)

    @pytest.mark.anyio
    async def test_wildcard_strips_star(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider, propagation_delay=0.0)
        await handler.provision("*.example.com", "tok1", "tok1.thumb")

        assert provider.created[0][0] == "_acme-challenge.example.com"

    def test_implements_challenge_handler(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider)
        assert isinstance(handler, ChallengeHandler)

    @pytest.mark.anyio
    async def test_propagation_checker_polled(self) -> None:
        provider = MockDNSProvider()
        call_count = 0

        async def checker(domain: str, value: str) -> bool:
            nonlocal call_count
            call_count += 1
            # Return False twice, then True
            return call_count >= 3

        handler = DNS01Handler(
            provider,
            propagation_checker=checker,
            propagation_interval=0.01,
            propagation_timeout=5.0,
        )
        await handler.provision("example.com", "tok1", "tok1.thumb")

        assert call_count == 3

    @pytest.mark.anyio
    async def test_propagation_timeout(self) -> None:
        provider = MockDNSProvider()

        async def checker(domain: str, value: str) -> bool:
            return False

        handler = DNS01Handler(
            provider,
            propagation_checker=checker,
            propagation_interval=0.01,
            propagation_timeout=0.03,
        )

        with pytest.raises(ACMETimeoutError, match="DNS propagation timeout"):
            await handler.provision("example.com", "tok1", "tok1.thumb")

    @pytest.mark.anyio
    async def test_no_propagation_checker_sleeps(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider, propagation_delay=10.0)

        with patch("lacme.challenges.dns01.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await handler.provision("example.com", "tok1", "tok1.thumb")
            mock_sleep.assert_awaited_once_with(10.0)

    @pytest.mark.anyio
    async def test_deprovision_unknown_noop(self) -> None:
        provider = MockDNSProvider()
        handler = DNS01Handler(provider, propagation_delay=0.0)
        # Deprovision a token that was never provisioned — should not raise
        await handler.deprovision("example.com", "unknown-token")
        assert len(provider.deleted) == 0


class TestMockSatisfiesProtocol:
    def test_mock_is_dns_provider(self) -> None:
        assert isinstance(MockDNSProvider(), DNSProvider)
