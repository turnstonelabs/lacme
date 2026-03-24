"""Tests for lacme.renewal — RenewalManager auto-renewal system."""

from __future__ import annotations

import asyncio
import datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
