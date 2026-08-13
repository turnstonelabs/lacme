"""Tests for lacme.renewal — RenewalManager auto-renewal system."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
from dataclasses import replace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lacme._identifiers import certificate_bundle_identifier_values
from lacme.renewal import RenewalManager
from lacme.store import MemoryStore

if TYPE_CHECKING:
    from collections.abc import Callable

    from lacme._types import CertBundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expiring_bundle(
    make_test_bundle: Callable[..., CertBundle],
    *,
    days: int,
    domain: str = "example.com",
) -> CertBundle:
    """Create a bundle that expires *days* from now."""
    now = datetime.datetime.now(datetime.UTC)
    return make_test_bundle(
        domain,
        expires_at=now + datetime.timedelta(days=days),
    )


def _expired_bundle(
    make_test_bundle: Callable[..., CertBundle],
    *,
    domain: str = "example.com",
) -> CertBundle:
    """Create a bundle that has already expired."""
    now = datetime.datetime.now(datetime.UTC)
    return make_test_bundle(
        domain,
        expires_at=now - datetime.timedelta(days=5),
    )


# ---------------------------------------------------------------------------
# _needs_renewal
# ---------------------------------------------------------------------------


class TestNeedsRenewal:
    def test_needs_renewal_expiring_soon(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """Cert expiring in 10 days with 30-day threshold should need renewal."""
        store = MemoryStore()
        client = MagicMock()
        manager = RenewalManager(client=client, store=store, days_before_expiry=30)

        bundle = _expiring_bundle(make_test_bundle, days=10)
        now = datetime.datetime.now(datetime.UTC)
        assert manager._needs_renewal(bundle, now) is True

    def test_needs_renewal_fresh(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """Cert expiring in 60 days with 30-day threshold should not need renewal."""
        store = MemoryStore()
        client = MagicMock()
        manager = RenewalManager(client=client, store=store, days_before_expiry=30)

        bundle = _expiring_bundle(make_test_bundle, days=60)
        now = datetime.datetime.now(datetime.UTC)
        assert manager._needs_renewal(bundle, now) is False

    def test_needs_renewal_already_expired(
        self, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        """Cert with expires_at in the past should need renewal."""
        store = MemoryStore()
        client = MagicMock()
        manager = RenewalManager(client=client, store=store, days_before_expiry=30)

        bundle = _expired_bundle(make_test_bundle)
        now = datetime.datetime.now(datetime.UTC)
        assert manager._needs_renewal(bundle, now) is True


# ---------------------------------------------------------------------------
# check_and_renew
# ---------------------------------------------------------------------------


class TestCheckAndRenew:
    @pytest.mark.anyio
    async def test_check_and_renew_renews_expiring(
        self, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        """Expiring cert should be renewed via client.issue."""
        store = MemoryStore()
        bundle = _expiring_bundle(make_test_bundle, days=10)
        store.save_cert(bundle)

        new_bundle = make_test_bundle("example.com")
        client = MagicMock()
        client.issue = AsyncMock(return_value=new_bundle)

        manager = RenewalManager(client=client, store=store, days_before_expiry=30)
        renewed = await manager.check_and_renew()

        assert len(renewed) == 1
        client.issue.assert_awaited_once_with(list(bundle.domains), challenge_type="http-01")

    @pytest.mark.anyio
    async def test_check_and_renew_recovers_ip_types_from_certificate(self) -> None:
        """Persisted string metadata does not turn IP SANs into DNS SANs on renewal."""
        from lacme.ca import CertificateAuthority

        ca = CertificateAuthority()
        ca.init()
        address = ipaddress.IPv6Address("2001:db8::1")
        bundle = ca.issue(["node.internal", address], validity_hours=1)
        store = MemoryStore()
        store.save_cert(bundle)

        client = MagicMock()
        client.issue = AsyncMock(return_value=bundle)
        manager = RenewalManager(client=client, store=store, days_before_expiry=30)

        renewed = await manager.check_and_renew()

        assert renewed == [bundle]
        client.issue.assert_awaited_once_with(
            ["node.internal", address],
            challenge_type="http-01",
        )

    @pytest.mark.anyio
    @pytest.mark.parametrize("corruption", ["invalid-pem", "metadata-mismatch"])
    async def test_check_and_renew_fails_closed_on_untrusted_identity_metadata(
        self,
        make_test_bundle: Callable[..., CertBundle],
        corruption: str,
    ) -> None:
        bundle = _expiring_bundle(make_test_bundle, days=10)
        if corruption == "invalid-pem":
            bundle = replace(bundle, cert_pem=b"not a certificate")
        else:
            bundle = replace(bundle, domains=("different.example",))
        store = MemoryStore()
        store.save_cert(bundle)
        client = MagicMock()
        client.issue = AsyncMock()
        manager = RenewalManager(client=client, store=store, days_before_expiry=30)

        renewed = await manager.check_and_renew()

        assert renewed == []
        client.issue.assert_not_awaited()

    def test_certificate_identity_recovery_respects_reordered_metadata(self) -> None:
        from lacme.ca import CertificateAuthority

        ca = CertificateAuthority()
        ca.init()
        address = ipaddress.IPv4Address("192.0.2.10")
        bundle = ca.issue(["node.internal", address])
        reordered = replace(
            bundle,
            domain=str(address),
            domains=(str(address), "node.internal"),
        )

        assert certificate_bundle_identifier_values(reordered) == [address, "node.internal"]

    def test_certificate_identity_recovery_matches_dns_case_insensitively(self) -> None:
        from lacme.ca import CertificateAuthority

        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("example.com")
        case_variant = replace(
            bundle,
            domain="Example.COM",
            domains=("Example.COM",),
        )

        assert certificate_bundle_identifier_values(case_variant) == ["example.com"]

    @pytest.mark.anyio
    async def test_check_and_renew_skips_fresh(
        self, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        """Fresh cert should NOT trigger client.issue."""
        store = MemoryStore()
        bundle = _expiring_bundle(make_test_bundle, days=60)
        store.save_cert(bundle)

        client = MagicMock()
        client.issue = AsyncMock()

        manager = RenewalManager(client=client, store=store, days_before_expiry=30)
        renewed = await manager.check_and_renew()

        assert len(renewed) == 0
        client.issue.assert_not_awaited()

    @pytest.mark.anyio
    async def test_check_and_renew_continues_on_failure(
        self, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        """If the first cert fails to renew, the second should still be renewed."""
        store = MemoryStore()
        bundle_a = _expiring_bundle(make_test_bundle, days=10, domain="a.example.com")
        bundle_b = _expiring_bundle(make_test_bundle, days=10, domain="b.example.com")
        store.save_cert(bundle_a)
        store.save_cert(bundle_b)

        new_bundle_b = make_test_bundle("b.example.com")
        client = MagicMock()
        client.issue = AsyncMock(side_effect=[RuntimeError("network error"), new_bundle_b])

        manager = RenewalManager(client=client, store=store, days_before_expiry=30)
        renewed = await manager.check_and_renew()

        assert len(renewed) == 1
        assert renewed[0].domain == "b.example.com"
        assert client.issue.await_count == 2


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    @pytest.mark.anyio
    async def test_callback_invoked(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """Async callback should be awaited with the new bundle."""
        store = MemoryStore()
        bundle = _expiring_bundle(make_test_bundle, days=10)
        store.save_cert(bundle)

        new_bundle = make_test_bundle("example.com")
        client = MagicMock()
        client.issue = AsyncMock(return_value=new_bundle)

        callback = AsyncMock()
        manager = RenewalManager(
            client=client, store=store, days_before_expiry=30, on_renewed=callback
        )
        await manager.check_and_renew()

        callback.assert_awaited_once_with(new_bundle)

    @pytest.mark.anyio
    async def test_sync_callback_invoked(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """Sync (non-async) callback should be called with the new bundle."""
        store = MemoryStore()
        bundle = _expiring_bundle(make_test_bundle, days=10)
        store.save_cert(bundle)

        new_bundle = make_test_bundle("example.com")
        client = MagicMock()
        client.issue = AsyncMock(return_value=new_bundle)

        callback = MagicMock(return_value=None)
        manager = RenewalManager(
            client=client, store=store, days_before_expiry=30, on_renewed=callback
        )
        await manager.check_and_renew()

        callback.assert_called_once_with(new_bundle)


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    @pytest.mark.anyio
    async def test_start_and_stop(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """start() creates a running task; stop() cancels it cleanly."""
        store = MemoryStore()
        client = MagicMock()
        client.issue = AsyncMock()

        manager = RenewalManager(client=client, store=store)

        with patch("lacme.renewal.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            mock_sleep.side_effect = asyncio.CancelledError

            task = manager.start()
            assert isinstance(task, asyncio.Task)
            assert not task.done()

            await manager.stop()
            assert task.done()

    @pytest.mark.anyio
    async def test_start_twice_raises(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """Calling start() twice without stop() should raise RuntimeError."""
        store = MemoryStore()
        client = MagicMock()
        client.issue = AsyncMock()

        manager = RenewalManager(client=client, store=store)

        with patch("lacme.renewal.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            mock_sleep.side_effect = asyncio.CancelledError

            manager.start()
            with pytest.raises(RuntimeError, match="already running"):
                manager.start()

            await manager.stop()


# ---------------------------------------------------------------------------
# CA-direct mode
# ---------------------------------------------------------------------------


class TestRenewalManagerCADirect:
    @pytest.mark.anyio
    async def test_ca_direct_renewal(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        """When ca is provided, check_and_renew() calls ca.issue() directly."""
        from lacme.ca import CertificateAuthority

        store = MemoryStore()
        ca = CertificateAuthority(store=store)
        ca.init()

        # Issue a cert with very short validity so it's already expiring
        bundle = ca.issue("example.com", validity_hours=1)
        store.save_cert(bundle)

        manager = RenewalManager(ca=ca, store=store, days_before_expiry=30)
        renewed = await manager.check_and_renew()

        assert len(renewed) == 1
        assert renewed[0].domain == "example.com"
        # Verify the new cert was saved to the store
        loaded = store.load_cert("example.com")
        assert loaded is not None
        assert loaded.cert_pem == renewed[0].cert_pem

    def test_ca_and_client_raises(self) -> None:
        """Passing both ca and client raises ValueError."""
        store = MemoryStore()
        client = MagicMock()
        ca = MagicMock()
        with pytest.raises(ValueError, match="not both"):
            RenewalManager(client=client, ca=ca, store=store)

    def test_neither_ca_nor_client_raises(self) -> None:
        """Passing neither ca nor client raises ValueError."""
        store = MemoryStore()
        with pytest.raises(ValueError, match="Either client or ca"):
            RenewalManager(store=store)
