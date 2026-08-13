"""ACME challenge handlers.

Defines the :class:`ChallengeHandler` protocol implemented by
:class:`~lacme.challenges.http01.HTTP01Handler` and
:class:`~lacme.challenges.dns01.DNS01Handler`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterable

    from lacme._types import IdentifierValue


@runtime_checkable
class ChallengeHandler(Protocol):
    """Protocol for ACME challenge provisioning and cleanup."""

    async def provision(self, domain: str, token: str, key_authorization: str) -> None:
        """Make the challenge response available for validation."""
        ...

    async def deprovision(self, domain: str, token: str) -> None:
        """Remove the challenge response after validation completes."""
        ...


class ChallengeMap(Protocol):
    """Read-only per-identifier async challenge-handler overrides."""

    def items(
        self,
    ) -> Iterable[tuple[IdentifierValue, tuple[str, ChallengeHandler]]]:
        """Iterate over identifier challenge overrides."""
        ...
