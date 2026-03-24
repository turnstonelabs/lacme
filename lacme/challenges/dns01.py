"""DNS-01 challenge handler (RFC 8555 §8.4).

Computes the ``_acme-challenge`` TXT record name and base64url-encoded
SHA-256 digest of the key authorization, delegates record creation and
deletion to a pluggable :class:`DNSProvider`, and optionally polls a
propagation checker before returning from :meth:`DNS01Handler.provision`.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from lacme.crypto import b64url_encode
from lacme.errors import ACMETimeoutError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

logger = logging.getLogger("lacme.challenges.dns01")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _acme_challenge_domain(domain: str) -> str:
    """Return the ``_acme-challenge`` record name for *domain*.

    Wildcard domains (``*.example.com``) have the leading ``*.`` stripped
    before prepending the prefix, per RFC 8555 §8.4.
    """
    if domain.startswith("*."):
        domain = domain[2:]
    return f"_acme-challenge.{domain}"


def _dns01_digest(key_authorization: str) -> str:
    """Compute ``base64url(SHA-256(key_authorization))`` per RFC 8555 §8.4."""
    digest = hashlib.sha256(key_authorization.encode("ascii")).digest()
    return b64url_encode(digest)


# ---------------------------------------------------------------------------
# DNSProvider protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class DNSProvider(Protocol):
    """Protocol for DNS record backends used by :class:`DNS01Handler`."""

    async def create_txt_record(self, domain: str, value: str) -> None:
        """Create a TXT record for *domain* with *value*."""
        ...

    async def delete_txt_record(self, domain: str, value: str) -> None:
        """Delete a TXT record for *domain* with *value*."""
        ...


# ---------------------------------------------------------------------------
# DNS-01 handler
# ---------------------------------------------------------------------------


class DNS01Handler:
    """DNS-01 challenge handler.

    Satisfies :class:`~lacme.challenges.ChallengeHandler`.
    """

    def __init__(
        self,
        provider: DNSProvider,
        *,
        propagation_delay: float = 10.0,
        propagation_timeout: float = 120.0,
        propagation_interval: float = 5.0,
        propagation_checker: Callable[[str, str], Awaitable[bool]] | None = None,
    ) -> None:
        self._provider = provider
        self._propagation_delay = propagation_delay
        self._propagation_timeout = propagation_timeout
        self._propagation_interval = propagation_interval
        self._propagation_checker = propagation_checker
        self._records: dict[tuple[str, str], tuple[str, str]] = {}

    # --- ChallengeHandler protocol ---

    async def provision(self, domain: str, token: str, key_authorization: str) -> None:
        """Create the ``_acme-challenge`` TXT record and wait for propagation."""
        record_name = _acme_challenge_domain(domain)
        digest = _dns01_digest(key_authorization)

        logger.debug(
            "Provisioning DNS-01 for %s (record=%s, token=%s…)",
            domain,
            record_name,
            token[:8],
        )

        await self._provider.create_txt_record(record_name, digest)
        self._records[(domain, token)] = (record_name, digest)

        if self._propagation_checker is not None:
            await self._wait_for_propagation(record_name, digest)
        else:
            logger.debug(
                "No propagation checker; sleeping %.1fs for DNS propagation",
                self._propagation_delay,
            )
            await asyncio.sleep(self._propagation_delay)

    async def deprovision(self, domain: str, token: str) -> None:
        """Remove the ``_acme-challenge`` TXT record."""
        record = self._records.pop((domain, token), None)
        if record is None:
            logger.debug("No DNS-01 record tracked for token=%s…; skipping", token[:8])
            return

        record_name, digest = record
        logger.debug(
            "Deprovisioning DNS-01 for %s (record=%s, token=%s…)",
            domain,
            record_name,
            token[:8],
        )
        await self._provider.delete_txt_record(record_name, digest)

    # --- Internal ---

    async def _wait_for_propagation(self, record_name: str, digest: str) -> None:
        """Poll the propagation checker until the record is visible or timeout."""
        from time import monotonic

        if self._propagation_checker is None:
            return
        start = monotonic()
        while True:
            if await self._propagation_checker(record_name, digest):
                logger.debug("DNS propagation confirmed for %s", record_name)
                return
            elapsed = monotonic() - start
            if elapsed >= self._propagation_timeout:
                break
            remaining = self._propagation_timeout - elapsed
            delay = min(self._propagation_interval, max(0.1, remaining))
            logger.debug(
                "DNS propagation check failed for %s (elapsed=%.1fs); retrying in %.1fs",
                record_name,
                elapsed,
                delay,
            )
            await asyncio.sleep(delay)

        raise ACMETimeoutError(
            f"DNS propagation timeout after {self._propagation_timeout}s for {record_name}",
            url=record_name,
            last_status="pending",
        )
