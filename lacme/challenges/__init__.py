"""ACME challenge handlers.

Defines the :class:`ChallengeHandler` protocol implemented by
:class:`~lacme.challenges.http01.HTTP01Handler` and (future) DNS-01 handlers.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ChallengeHandler(Protocol):
    """Protocol for ACME challenge provisioning and cleanup."""

    async def provision(self, domain: str, token: str, key_authorization: str) -> None:
        """Make the challenge response available for validation."""
        ...

    async def deprovision(self, domain: str, token: str) -> None:
        """Remove the challenge response after validation completes."""
        ...
