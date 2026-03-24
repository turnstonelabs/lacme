"""Shared types that are not RFC 8555 protocol objects.

Contains :class:`CertBundle` (certificate issuance result),
:class:`CertMeta` (JSON sidecar for stored certificates),
and ASGI type aliases.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    import datetime
    from pathlib import Path


# ---------------------------------------------------------------------------
# Certificate types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CertBundle:
    """Complete certificate issuance result."""

    domain: str
    domains: tuple[str, ...]
    cert_pem: bytes
    fullchain_pem: bytes
    key_pem: bytes
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    cert_path: Path | None = None
    fullchain_path: Path | None = None
    key_path: Path | None = None


@dataclass(frozen=True, slots=True)
class CertMeta:
    """JSON-serializable metadata sidecar for a stored certificate."""

    domain: str
    domains: tuple[str, ...]
    issued_at: str  # ISO 8601
    expires_at: str  # ISO 8601

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "domains": list(self.domains),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            domain=data["domain"],
            domains=tuple(data["domains"]),
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
        )


# ---------------------------------------------------------------------------
# ASGI type aliases (avoids any framework dependency)
# ---------------------------------------------------------------------------

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
