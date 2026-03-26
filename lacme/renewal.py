"""Automatic certificate renewal.

Provides :class:`RenewalManager` which periodically checks stored certificates
and re-issues any that are approaching expiry.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import inspect
import logging
import random
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from lacme._types import CertBundle
    from lacme.ca import CertificateAuthority
    from lacme.client import Client
    from lacme.events import EventDispatcher
    from lacme.store import Store

logger = logging.getLogger("lacme")


class RenewalManager:
    """Periodically check stored certificates and renew expiring ones.

    Provide either *client* (renew via ACME protocol) or *ca* (sign
    directly via :class:`~lacme.ca.CertificateAuthority`).  When *ca*
    is used, no network round-trip or running ACME responder is needed.

    Args:
        client: ACME client used to issue replacement certificates.
        ca: Certificate Authority for direct signing (alternative to *client*).
        store: Certificate store to enumerate and persist certificates.
        interval_hours: Hours between renewal sweeps.
        days_before_expiry: Renew certificates expiring within this many days.
        challenge_type: ACME challenge type for issuance (e.g. ``"http-01"``).
            Only used with *client*, not *ca*.
        on_renewed: Optional callback invoked with each renewed :class:`CertBundle`.
            May be synchronous or asynchronous.
        max_jitter_seconds: Maximum random jitter (seconds) added to each sleep
            interval to avoid thundering-herd renewals.
    """

    def __init__(
        self,
        *,
        client: Client | None = None,
        ca: CertificateAuthority | None = None,
        store: Store,
        interval_hours: float = 12.0,
        days_before_expiry: int = 30,
        challenge_type: str = "http-01",
        on_renewed: Callable[[CertBundle], Any] | None = None,
        max_jitter_seconds: float = 600.0,
        event_dispatcher: EventDispatcher | None = None,
    ) -> None:
        if client is None and ca is None:
            msg = "Either client or ca must be provided"
            raise ValueError(msg)
        if client is not None and ca is not None:
            msg = "Provide either client or ca, not both"
            raise ValueError(msg)
        self._client = client
        self._ca = ca
        self._store = store
        self._interval_hours = interval_hours
        self._days_before_expiry = days_before_expiry
        self._challenge_type = challenge_type
        self._on_renewed = on_renewed
        self._max_jitter_seconds = max_jitter_seconds
        self._event_dispatcher = event_dispatcher
        self._task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the renewal loop forever until cancelled."""
        while True:
            try:
                await self.check_and_renew()
            except Exception:
                logger.exception("Renewal sweep failed")

            jitter = random.uniform(0, self._max_jitter_seconds)  # noqa: S311
            delay = self._interval_hours * 3600.0 + jitter
            await asyncio.sleep(delay)

    async def check_and_renew(self) -> list[CertBundle]:
        """Single pass: check all certificates and renew expiring ones."""
        now = datetime.datetime.now(datetime.UTC)
        bundles = self._store.list_certs()
        renewed: list[CertBundle] = []

        for bundle in bundles:
            if not self._needs_renewal(bundle, now):
                continue

            days_remaining = max(0, (bundle.expires_at - now).days)

            # Emit expiring event
            if self._event_dispatcher is not None:
                from lacme.events import CertificateExpiring

                await self._event_dispatcher.emit(
                    CertificateExpiring(
                        domain=bundle.domain,
                        domains=bundle.domains,
                        expires_at=bundle.expires_at,
                        days_remaining=days_remaining,
                    )
                )

            try:
                logger.info(
                    "Renewing certificate for %s (expires %s)",
                    bundle.domain,
                    bundle.expires_at.isoformat(),
                )
                if self._ca is not None:
                    new_bundle = self._ca.issue(list(bundle.domains))
                else:
                    assert self._client is not None  # noqa: S101
                    new_bundle = await self._client.issue(
                        list(bundle.domains),
                        challenge_type=self._challenge_type,
                    )
                # Explicitly save to our store (Client/CA may have a different one)
                self._store.save_cert(new_bundle)
                renewed.append(new_bundle)
            except Exception:
                logger.exception("Failed to renew certificate for %s", bundle.domain)
                continue

            # Emit renewed event
            if self._event_dispatcher is not None:
                from lacme.events import CertificateRenewed

                await self._event_dispatcher.emit(
                    CertificateRenewed(
                        domain=new_bundle.domain,
                        domains=new_bundle.domains,
                        expires_at=new_bundle.expires_at,
                        previous_expires_at=bundle.expires_at,
                    )
                )

            if self._on_renewed is not None:
                try:
                    result = self._on_renewed(new_bundle)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    logger.exception("on_renewed callback failed for %s", bundle.domain)

        return renewed

    def _needs_renewal(self, bundle: CertBundle, now: datetime.datetime) -> bool:
        """Return ``True`` if *bundle* expires within the configured threshold."""
        threshold = now + datetime.timedelta(days=self._days_before_expiry)
        return bundle.expires_at <= threshold

    def start(self) -> asyncio.Task[None]:
        """Create and return a background task running the renewal loop.

        Raises:
            RuntimeError: If a renewal task is already running.
        """
        if self._task is not None and not self._task.done():
            msg = "Renewal task is already running"
            raise RuntimeError(msg)
        self._task = asyncio.get_running_loop().create_task(self.run())
        return self._task

    async def stop(self) -> None:
        """Cancel the background renewal task and wait for it to finish."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
