"""RFC 8555 protocol data models.

Frozen dataclasses representing ACME directory, account, order,
authorization, and challenge objects.  Each model has a ``from_dict``
classmethod that parses the JSON body returned by an ACME server.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any, Self

# ---------------------------------------------------------------------------
# Status enumerations
# ---------------------------------------------------------------------------


class AccountStatus(StrEnum):
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class OrderStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChallengeStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class IdentifierType(StrEnum):
    DNS = "dns"
    IP = "ip"


class RevocationReason(IntEnum):
    """Certificate revocation reason codes (RFC 5280 §5.3.1).

    Only codes applicable for ACME client-initiated revocation are included.
    """

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DirectoryMeta:
    """Optional metadata from the ACME directory (RFC 8555 §7.1.1)."""

    terms_of_service: str | None = None
    website: str | None = None
    caa_identities: tuple[str, ...] = ()
    external_account_required: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            terms_of_service=data.get("termsOfService"),
            website=data.get("website"),
            caa_identities=tuple(data.get("caaIdentities", ())),
            external_account_required=data.get("externalAccountRequired", False),
        )


@dataclass(frozen=True, slots=True)
class Directory:
    """ACME directory resource (RFC 8555 §7.1.1)."""

    new_nonce: str
    new_account: str
    new_order: str
    revoke_cert: str
    key_change: str
    new_authz: str | None = None
    meta: DirectoryMeta | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        meta_raw = data.get("meta")
        return cls(
            new_nonce=data["newNonce"],
            new_account=data["newAccount"],
            new_order=data["newOrder"],
            revoke_cert=data["revokeCert"],
            key_change=data["keyChange"],
            new_authz=data.get("newAuthz"),
            meta=DirectoryMeta.from_dict(meta_raw) if meta_raw is not None else None,
        )


@dataclass(frozen=True, slots=True)
class Identifier:
    """ACME identifier object."""

    type: IdentifierType  # noqa: A003
    value: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(type=IdentifierType(data["type"]), value=data["value"])

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type.value, "value": self.value}


@dataclass(frozen=True, slots=True)
class SubProblem:
    """ACME subproblem (RFC 8555 §6.7.1)."""

    type: str  # noqa: A003
    detail: str | None = None
    identifier: Identifier | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        id_raw = data.get("identifier")
        return cls(
            type=data["type"],
            detail=data.get("detail"),
            identifier=Identifier.from_dict(id_raw) if id_raw is not None else None,
        )


@dataclass(frozen=True, slots=True)
class Problem:
    """RFC 7807 problem document with optional ACME subproblems."""

    type: str  # noqa: A003
    detail: str | None = None
    status: int | None = None
    subproblems: tuple[SubProblem, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            type=data.get("type", ""),
            detail=data.get("detail"),
            status=data.get("status"),
            subproblems=tuple(SubProblem.from_dict(sp) for sp in data.get("subproblems", ())),
        )


@dataclass(frozen=True, slots=True)
class Challenge:
    """ACME challenge object (RFC 8555 §8)."""

    type: str  # noqa: A003
    url: str
    status: ChallengeStatus
    token: str
    validated: datetime | None = None
    error: Problem | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        err_raw = data.get("error")
        return cls(
            type=data["type"],
            url=data["url"],
            status=ChallengeStatus(data["status"]),
            token=data["token"],
            validated=_parse_dt(data.get("validated")),
            error=Problem.from_dict(err_raw) if err_raw is not None else None,
        )


@dataclass(frozen=True, slots=True)
class Authorization:
    """ACME authorization object (RFC 8555 §7.1.4)."""

    identifier: Identifier
    status: AuthorizationStatus
    expires: datetime | None = None
    challenges: tuple[Challenge, ...] = ()
    wildcard: bool = False
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, url: str = "") -> Self:
        return cls(
            identifier=Identifier.from_dict(data["identifier"]),
            status=AuthorizationStatus(data["status"]),
            expires=_parse_dt(data.get("expires")),
            challenges=tuple(Challenge.from_dict(c) for c in data.get("challenges", ())),
            wildcard=data.get("wildcard", False),
            url=url,
        )

    def find_challenge(self, challenge_type: str) -> Challenge | None:
        """Return the first challenge matching *challenge_type*, or ``None``."""
        for c in self.challenges:
            if c.type == challenge_type:
                return c
        return None


@dataclass(frozen=True, slots=True)
class Account:
    """ACME account object (RFC 8555 §7.1.2)."""

    status: AccountStatus
    contact: tuple[str, ...] = ()
    orders: str | None = None
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, url: str = "") -> Self:
        return cls(
            status=AccountStatus(data["status"]),
            contact=tuple(data.get("contact", ())),
            orders=data.get("orders"),
            url=url,
        )


@dataclass(frozen=True, slots=True)
class Order:
    """ACME order object (RFC 8555 §7.1.3)."""

    status: OrderStatus
    identifiers: tuple[Identifier, ...]
    authorizations: tuple[str, ...] = ()
    finalize: str = ""
    expires: datetime | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    error: Problem | None = None
    certificate: str | None = None
    url: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, url: str = "") -> Self:
        err_raw = data.get("error")
        return cls(
            status=OrderStatus(data["status"]),
            identifiers=tuple(Identifier.from_dict(i) for i in data["identifiers"]),
            authorizations=tuple(data.get("authorizations", ())),
            finalize=data.get("finalize", ""),
            expires=_parse_dt(data.get("expires")),
            not_before=_parse_dt(data.get("notBefore")),
            not_after=_parse_dt(data.get("notAfter")),
            error=Problem.from_dict(err_raw) if err_raw is not None else None,
            certificate=data.get("certificate"),
            url=url,
        )
