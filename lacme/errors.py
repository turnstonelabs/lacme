"""ACME error types and server error factory.

Maps RFC 8555 Section 6.7 error URNs to typed Python exceptions.
Server responses with ``application/problem+json`` bodies are parsed
into the appropriate exception subclass via :func:`server_error_from_response`.
"""

from __future__ import annotations

from typing import Any

_ACME_ERROR_PREFIX = "urn:ietf:params:acme:error:"


class ACMEError(Exception):
    """Base exception for all lacme errors."""


class ACMEServerError(ACMEError):
    """Server returned an RFC 7807 problem document."""

    def __init__(
        self,
        *,
        type: str,  # noqa: A002 — RFC 7807 field name
        detail: str | None = None,
        status: int | None = None,
        subproblems: list[dict[str, Any]] | None = None,
        response_headers: dict[str, str] | None = None,
    ) -> None:
        self.type = type
        self.detail = detail
        self.status = status
        self.subproblems = subproblems
        self.response_headers = response_headers
        parts = [type]
        if detail is not None:
            parts.append(detail)
        super().__init__(" :: ".join(parts))


class BadNonceError(ACMEServerError):
    """``urn:ietf:params:acme:error:badNonce`` — triggers automatic retry."""


class RateLimitedError(ACMEServerError):
    """``urn:ietf:params:acme:error:rateLimited``"""

    @property
    def retry_after(self) -> int | None:
        """Seconds to wait before retrying, parsed from the Retry-After header."""
        if self.response_headers is None:
            return None
        value = self.response_headers.get("retry-after")
        if value is None:
            return None
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None


class UnauthorizedError(ACMEServerError):
    """``urn:ietf:params:acme:error:unauthorized``"""


class BadCSRError(ACMEServerError):
    """``urn:ietf:params:acme:error:badCSR``"""


class CAAError(ACMEServerError):
    """``urn:ietf:params:acme:error:caa``"""


class AccountDoesNotExistError(ACMEServerError):
    """``urn:ietf:params:acme:error:accountDoesNotExist``"""


class InvalidContactError(ACMEServerError):
    """``urn:ietf:params:acme:error:invalidContact``"""


class MalformedError(ACMEServerError):
    """``urn:ietf:params:acme:error:malformed``"""


class OrderNotReadyError(ACMEServerError):
    """``urn:ietf:params:acme:error:orderNotReady``"""


class RejectedIdentifierError(ACMEServerError):
    """``urn:ietf:params:acme:error:rejectedIdentifier``"""


class UnsupportedIdentifierError(ACMEServerError):
    """``urn:ietf:params:acme:error:unsupportedIdentifier``"""


class BadSignatureAlgorithmError(ACMEServerError):
    """``urn:ietf:params:acme:error:badSignatureAlgorithm``"""


class BadPublicKeyError(ACMEServerError):
    """``urn:ietf:params:acme:error:badPublicKey``"""


class ACMEConnectionError(ACMEServerError):
    """``urn:ietf:params:acme:error:connection``"""


class DNSError(ACMEServerError):
    """``urn:ietf:params:acme:error:dns``"""


class ServerInternalError(ACMEServerError):
    """``urn:ietf:params:acme:error:serverInternal``"""


class TLSError(ACMEServerError):
    """``urn:ietf:params:acme:error:tls``"""


class AlreadyRevokedError(ACMEServerError):
    """``urn:ietf:params:acme:error:alreadyRevoked``"""


class BadRevocationReasonError(ACMEServerError):
    """``urn:ietf:params:acme:error:badRevocationReason``"""


class ACMEValidationError(ACMEError):
    """A challenge validation failed (authorization became invalid)."""

    def __init__(
        self,
        message: str,
        *,
        identifier: str,
        error: dict[str, Any] | None = None,
    ) -> None:
        self.identifier = identifier
        self.error = error
        super().__init__(message)


class ACMETimeoutError(ACMEError):
    """Polling deadline exceeded (order or authorization)."""

    def __init__(self, message: str, *, url: str, last_status: str) -> None:
        self.url = url
        self.last_status = last_status
        super().__init__(message)


class ACMEStoreError(ACMEError):
    """Storage read/write failure."""


# ---------------------------------------------------------------------------
# Registry: ACME error short name → exception class
# ---------------------------------------------------------------------------

_ERROR_REGISTRY: dict[str, type[ACMEServerError]] = {
    "badNonce": BadNonceError,
    "rateLimited": RateLimitedError,
    "unauthorized": UnauthorizedError,
    "badCSR": BadCSRError,
    "caa": CAAError,
    "accountDoesNotExist": AccountDoesNotExistError,
    "invalidContact": InvalidContactError,
    "malformed": MalformedError,
    "orderNotReady": OrderNotReadyError,
    "rejectedIdentifier": RejectedIdentifierError,
    "unsupportedIdentifier": UnsupportedIdentifierError,
    "badSignatureAlgorithm": BadSignatureAlgorithmError,
    "badPublicKey": BadPublicKeyError,
    "connection": ACMEConnectionError,
    "dns": DNSError,
    "serverInternal": ServerInternalError,
    "tls": TLSError,
    "alreadyRevoked": AlreadyRevokedError,
    "badRevocationReason": BadRevocationReasonError,
}


def server_error_from_response(
    problem: dict[str, Any],
    response_headers: dict[str, str] | None = None,
) -> ACMEServerError:
    """Create the appropriate :class:`ACMEServerError` subclass from a problem document.

    Strips the ``urn:ietf:params:acme:error:`` prefix, looks up the short name
    in the registry, and falls back to :class:`ACMEServerError` for unknown types.
    """
    error_type: str = problem.get("type", "")
    short_name = error_type.removeprefix(_ACME_ERROR_PREFIX)
    cls = _ERROR_REGISTRY.get(short_name, ACMEServerError)
    return cls(
        type=error_type,
        detail=problem.get("detail"),
        status=problem.get("status"),
        subproblems=problem.get("subproblems"),
        response_headers=response_headers,
    )
