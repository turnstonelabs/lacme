"""Async ACME v2 protocol client (RFC 8555).

Provides the :class:`Client` class which implements the full ACME order
lifecycle: account creation, order placement, challenge handling,
finalization, and certificate download.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from time import monotonic
from typing import TYPE_CHECKING, Any

import httpx2

from lacme import crypto
from lacme._identifiers import (
    certificate_identifier_values,
    identifier_key_from_protocol,
    identifier_key_from_value,
    identifier_key_set,
    normalize_identifier_values,
    protocol_identifier_from_value,
    validate_dns_identifier,
)
from lacme.errors import (
    ACMEError,
    ACMETimeoutError,
    ACMEValidationError,
    BadNonceError,
    server_error_from_response,
)
from lacme.models import (
    Account,
    Authorization,
    AuthorizationStatus,
    Challenge,
    Directory,
    Identifier,
    IdentifierType,
    Order,
    OrderStatus,
    RevocationReason,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType

    from cryptography.hazmat.primitives.asymmetric import ec

    from lacme._types import CertBundle, IdentifierValue
    from lacme.challenges import ChallengeHandler, ChallengeMap
    from lacme.events import EventDispatcher
    from lacme.ratelimit import RateLimitStatus, RateLimitTracker
    from lacme.store import Store

logger = logging.getLogger("lacme")

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

_DEFAULT_POLL_TIMEOUT: float = 300.0
_DEFAULT_POLL_INTERVAL: float = 2.0
_MAX_BAD_NONCE_RETRIES = 1
_VALID_REVOCATION_REASONS = set(RevocationReason)


def _identifier_from_value(value: IdentifierValue) -> Identifier:
    """Build the ACME protocol identifier for a public API value."""
    identifier_type, identifier_value = protocol_identifier_from_value(value)
    return Identifier(type=IdentifierType(identifier_type), value=identifier_value)


def _parse_retry_after(value: str) -> float | None:
    """Parse a Retry-After header value (integer seconds or HTTP-date)."""
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    # Try HTTP-date format (RFC 7231 §7.1.1.1)
    from email.utils import parsedate_to_datetime

    try:
        dt = parsedate_to_datetime(value)
        import datetime

        delta = (dt - datetime.datetime.now(datetime.UTC)).total_seconds()
        return max(0.0, delta)
    except (ValueError, TypeError):
        return None


def _validate_revocation_reason(reason: int) -> None:
    if reason not in _VALID_REVOCATION_REASONS:
        valid = ", ".join(f"{r.name}({int(r)})" for r in sorted(_VALID_REVOCATION_REASONS, key=int))
        msg = f"Invalid revocation reason {reason}. Valid values: {valid}"
        raise ValueError(msg)


class Client:
    """Async ACME v2 client.

    Injected HTTP clients must be :class:`httpx2.AsyncClient` instances. The
    caller retains ownership of an injected client; :meth:`close` only closes
    clients created by ``Client``. HTTP transport and status errors propagate
    from HTTPX2. ACME redirects are never followed; configure the final request
    URLs on the server.

    Usage::

        async with Client(directory_url="...", account_key=key) as client:
            cert = await client.issue(["example.com"])
    """

    def __init__(
        self,
        *,
        directory_url: str = LETSENCRYPT_DIRECTORY,
        account_key: ec.EllipticCurvePrivateKey | None = None,
        store: Store | None = None,
        contact: str | list[str] | None = None,
        challenge_handler: ChallengeHandler | None = None,
        http_client: httpx2.AsyncClient | None = None,
        poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
        event_dispatcher: EventDispatcher | None = None,
        rate_limit_tracker: RateLimitTracker | None = None,
        ca_bundle: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        allow_insecure: bool = False,
    ) -> None:
        self._allow_insecure = allow_insecure
        self._validate_request_url(directory_url, label="ACME directory URL")
        self._directory_url = directory_url
        self._account_key = account_key
        self._store = store
        self._event_dispatcher = event_dispatcher
        self._rate_limit_tracker = rate_limit_tracker
        self._contact: list[str] | None
        if isinstance(contact, str):
            self._contact = [contact]
        else:
            self._contact = contact
        self._challenge_handler = challenge_handler
        self._poll_timeout = poll_timeout
        self._poll_interval = poll_interval
        self._eab_kid = eab_kid
        self._eab_hmac_key = eab_hmac_key

        if client_cert is not None and client_key is None:
            msg = "client_cert requires client_key"
            raise ValueError(msg)
        if client_key is not None and client_cert is None:
            msg = "client_key requires client_cert"
            raise ValueError(msg)

        if http_client is not None:
            if not isinstance(http_client, httpx2.AsyncClient):
                msg = "http_client must be an httpx2.AsyncClient"
                raise TypeError(msg)
            self._http = http_client
            self._owns_http = False
        else:
            ssl_context: ssl.SSLContext | None = None
            if ca_bundle is not None:
                ssl_context = ssl.create_default_context(cafile=ca_bundle)
            if client_cert is not None and client_key is not None:
                if ssl_context is None:
                    # Preserve HTTPX2's operating-system trust store while
                    # adding a client identity to the context.
                    ssl_context = httpx2.create_ssl_context()
                ssl_context.load_cert_chain(certfile=client_cert, keyfile=client_key)
            verify: bool | ssl.SSLContext = ssl_context if ssl_context is not None else True
            self._http = httpx2.AsyncClient(verify=verify)
            self._owns_http = True

        self._directory: Directory | None = None
        self._account_url: str | None = None
        self._nonces: list[str] = []

    # --- Context manager ---

    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_http:
            await self._http.aclose()

    # --- Directory ---

    async def directory(self) -> Directory:
        """Fetch and cache the ACME directory."""
        if self._directory is not None:
            return self._directory
        self._validate_request_url(self._directory_url, label="ACME directory URL")
        resp = await self._http.get(self._directory_url, follow_redirects=False)
        resp.raise_for_status()
        self._harvest_nonce(resp)
        self._directory = Directory.from_dict(resp.json())
        return self._directory

    # --- Nonce management ---

    async def _get_nonce(self) -> str:
        if self._nonces:
            return self._nonces.pop()
        d = await self.directory()
        self._validate_request_url(d.new_nonce)
        resp = await self._http.head(d.new_nonce, follow_redirects=False)
        resp.raise_for_status()
        self._harvest_nonce(resp)
        if self._nonces:
            return self._nonces.pop()
        msg = "Failed to obtain a nonce from the ACME server"
        raise RuntimeError(msg)

    def _harvest_nonce(self, response: httpx2.Response) -> None:
        nonce = response.headers.get("replay-nonce")
        if nonce:
            self._nonces.append(nonce)

    # --- JWS request ---

    async def _raw_signed_request(
        self,
        url: str,
        payload: dict[str, Any] | bytes | None,
        *,
        signing_key: ec.EllipticCurvePrivateKey,
        nonce: str,
        kid: str | None = None,
        expected_status: set[int] | None = None,
    ) -> httpx2.Response:
        """Low-level JWS-signed POST.  No badNonce retry."""
        self._validate_request_url(url)
        if payload is None:
            raw_payload = b""
        elif isinstance(payload, dict):
            raw_payload = json.dumps(payload).encode()
        else:
            raw_payload = payload

        jws_body = crypto.jws_encode(
            raw_payload,
            signing_key,
            nonce=nonce,
            url=url,
            kid=kid,
        )

        resp = await self._http.post(
            url,
            content=json.dumps(jws_body).encode(),
            headers={
                "content-type": "application/jose+json",
                "accept": "application/pem-certificate-chain, application/json, application/problem+json",
            },
            follow_redirects=False,
        )
        self._harvest_nonce(resp)
        self._check_response(resp, expected_status)
        return resp

    def _validate_request_url(self, url: str, *, label: str = "ACME URL") -> None:
        """Enforce the configured transport policy before an ACME request."""
        try:
            parsed = httpx2.URL(url)
        except httpx2.InvalidURL as exc:
            msg = f"{label} is invalid: {url!r}"
            raise ValueError(msg) from exc

        if not parsed.is_absolute_url or parsed.scheme not in {"http", "https"}:
            msg = f"{label} must use HTTP or HTTPS (got {url!r})"
            raise ValueError(msg)
        if not self._allow_insecure and parsed.scheme != "https":
            msg = (
                f"{label} must use HTTPS (got {url!r}). "
                "Pass allow_insecure=True to permit HTTP on a trusted network."
            )
            raise ValueError(msg)

    async def _signed_request(
        self,
        url: str,
        payload: dict[str, Any] | bytes | None,
        *,
        expected_status: set[int] | None = None,
    ) -> httpx2.Response:
        """Account-key signed POST with badNonce retry."""
        if self._account_key is None:
            msg = "No account key — call _ensure_account_key() first"
            raise RuntimeError(msg)
        for attempt in range(_MAX_BAD_NONCE_RETRIES + 1):
            nonce = await self._get_nonce()
            try:
                return await self._raw_signed_request(
                    url,
                    payload,
                    signing_key=self._account_key,
                    nonce=nonce,
                    kid=self._account_url,
                    expected_status=expected_status,
                )
            except BadNonceError:
                if attempt < _MAX_BAD_NONCE_RETRIES:
                    logger.debug("badNonce — retrying with fresh nonce")
                    continue
                raise

        # Unreachable, but satisfies mypy
        msg = "Exhausted badNonce retries"
        raise RuntimeError(msg)

    def _check_response(
        self,
        response: httpx2.Response,
        expected_status: set[int] | None,
    ) -> None:
        ct = response.headers.get("content-type", "")
        is_problem = "application/problem+json" in ct

        if expected_status is not None:
            if response.status_code in expected_status:
                return
            if is_problem:
                headers = dict(response.headers)
                raise server_error_from_response(response.json(), headers)
            response.raise_for_status()
            # raise_for_status only raises on 4xx/5xx; reject unexpected 2xx/3xx
            msg = f"Unexpected status {response.status_code}, expected one of {expected_status}"
            raise httpx2.HTTPStatusError(msg, request=response.request, response=response)
        else:
            if response.is_success:
                return
            if is_problem:
                headers = dict(response.headers)
                raise server_error_from_response(response.json(), headers)
            response.raise_for_status()

    # --- Account management ---

    async def _ensure_account_key(self) -> None:
        if self._account_key is not None:
            return
        if self._store is not None:
            self._account_key = self._store.load_account_key()
        if self._account_key is None:
            self._account_key = crypto.generate_ec_key()
            if self._store is not None:
                self._store.save_account_key(self._account_key)

    async def create_account(
        self,
        *,
        contact: list[str] | None = None,
        terms_of_service_agreed: bool = True,
        only_return_existing: bool = False,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
    ) -> Account:
        """Create or find an existing ACME account.

        Sets the internal account URL for subsequent requests.

        For CAs requiring External Account Binding (e.g. ZeroSSL), pass
        *eab_kid* and *eab_hmac_key* (base64url-encoded).  These fall
        back to the values provided at ``Client`` construction time.
        """
        await self._ensure_account_key()
        d = await self.directory()
        payload: dict[str, Any] = {
            "termsOfServiceAgreed": terms_of_service_agreed,
        }
        effective_contact = contact if contact is not None else self._contact
        if effective_contact:
            payload["contact"] = effective_contact
        if only_return_existing:
            payload["onlyReturnExisting"] = True

        # External Account Binding (RFC 8555 §7.3.4)
        eff_eab_kid = eab_kid if eab_kid is not None else self._eab_kid
        eff_eab_key = eab_hmac_key if eab_hmac_key is not None else self._eab_hmac_key
        if (eff_eab_kid is None) != (eff_eab_key is None):
            msg = "Both eab_kid and eab_hmac_key must be provided together"
            raise ValueError(msg)
        if eff_eab_kid is not None and eff_eab_key is not None:
            if self._account_key is None:
                msg = "No account key for EAB"
                raise RuntimeError(msg)
            account_jwk = crypto.public_key_to_jwk(self._account_key.public_key())
            eab_payload = json.dumps(account_jwk, separators=(",", ":")).encode()
            mac_key = crypto.b64url_decode(eff_eab_key)
            payload["externalAccountBinding"] = crypto.jws_encode_hmac(
                eab_payload,
                mac_key,
                kid=eff_eab_kid,
                url=d.new_account,
            )

        # newAccount uses JWK, not KID — temporarily clear account_url
        saved_url = self._account_url
        self._account_url = None
        try:
            resp = await self._signed_request(
                d.new_account,
                payload,
                expected_status={200, 201},
            )
        except Exception:
            self._account_url = saved_url
            raise

        self._account_url = resp.headers["location"]
        return Account.from_dict(resp.json(), url=self._account_url)

    async def deactivate_account(self) -> Account:
        """Deactivate the current account."""
        if self._account_url is None:
            msg = "No account URL — call create_account() first"
            raise RuntimeError(msg)
        resp = await self._signed_request(
            self._account_url,
            {"status": "deactivated"},
            expected_status={200},
        )
        return Account.from_dict(resp.json(), url=self._account_url)

    async def rollover_key(
        self,
        new_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        """Roll over the account key (RFC 8555 §7.3.5).

        Replaces the current account key with *new_key* (generated if ``None``).
        On success the new key is stored if a store was provided.
        """
        if self._account_url is None:
            msg = "No account URL — call create_account() first"
            raise RuntimeError(msg)
        if self._account_key is None:
            msg = "No account key"
            raise RuntimeError(msg)
        if new_key is None:
            new_key = crypto.generate_ec_key()

        d = await self.directory()
        old_jwk = crypto.public_key_to_jwk(self._account_key.public_key())

        # Inner JWS: signed by NEW key, JWK header, no nonce
        inner_payload = json.dumps(
            {"account": self._account_url, "oldKey": old_jwk},
            separators=(",", ":"),
        ).encode()
        inner_jws = crypto.jws_encode(
            inner_payload,
            new_key,
            url=d.key_change,
            # nonce omitted — RFC 8555 §7.3.5
            # kid omitted — inner JWS uses JWK of new key
        )

        # Outer JWS: standard account-key signed request
        await self._signed_request(
            d.key_change,
            inner_jws,
            expected_status={200},
        )

        # Success — update in-memory state (server has accepted the new key)
        self._account_key = new_key
        if self._store is not None:
            try:
                self._store.save_account_key(new_key)
            except Exception:
                logger.critical(
                    "Account key rolled over on server but FAILED to save locally. "
                    "The new key exists only in memory. Back up immediately.",
                    exc_info=True,
                )
                raise
            logger.info("Account key rolled over and saved to store")

    # --- Order lifecycle ---

    async def create_order(
        self,
        domains: IdentifierValue | Sequence[IdentifierValue],
        *,
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> Order:
        """Create a new certificate order for DNS names and/or typed IP addresses.

        Plain strings are DNS identifiers. Pass an
        :class:`ipaddress.IPv4Address` or :class:`ipaddress.IPv6Address` to
        request an RFC 8738 IP identifier.
        """
        identifier_values = normalize_identifier_values(domains)
        if self._account_url is None:
            msg = "No account URL — call create_account() first"
            raise RuntimeError(msg)
        d = await self.directory()
        identifiers = [_identifier_from_value(value).to_dict() for value in identifier_values]
        payload: dict[str, Any] = {"identifiers": identifiers}
        if not_before:
            payload["notBefore"] = not_before
        if not_after:
            payload["notAfter"] = not_after

        resp = await self._signed_request(
            d.new_order,
            payload,
            expected_status={201},
        )
        url = resp.headers.get("location")
        if not url:
            msg = "Server response for newOrder is missing required Location header"
            raise RuntimeError(msg)
        return Order.from_dict(resp.json(), url=url)

    async def get_authorization(self, url: str) -> Authorization:
        """Fetch an authorization via POST-as-GET."""
        resp = await self._signed_request(url, None, expected_status={200})
        return Authorization.from_dict(resp.json(), url=url)

    async def get_authorizations(self, order: Order) -> list[Authorization]:
        """Fetch all authorizations for an order.

        Fetches are serialized to avoid nonce pool contention.
        """
        return [await self.get_authorization(url) for url in order.authorizations]

    async def create_authorization(
        self,
        identifier_value: str,
        *,
        identifier_type: IdentifierType = IdentifierType.DNS,
    ) -> Authorization:
        """Create a pre-authorization for an identifier (RFC 8555 §7.4.1).

        Requires the server to support ``newAuthz`` (optional per RFC 8555).

        Args:
            identifier_value: Domain name or IP address.
            identifier_type: Identifier type (default ``dns``).

        Raises:
            RuntimeError: If the server does not expose a ``newAuthz`` endpoint.
        """
        d = await self.directory()
        if d.new_authz is None:
            msg = "Server does not support pre-authorization (no newAuthz in directory)"
            raise RuntimeError(msg)
        payload = {
            "identifier": Identifier(type=identifier_type, value=identifier_value).to_dict(),
        }
        resp = await self._signed_request(
            d.new_authz,
            payload,
            expected_status={201},
        )
        url = resp.headers.get("location")
        if not url:
            msg = "Server response for newAuthz is missing required Location header"
            raise RuntimeError(msg)
        return Authorization.from_dict(resp.json(), url=url)

    async def respond_to_challenge(self, challenge: Challenge) -> Challenge:
        """Signal readiness for challenge validation (POST ``{}`` to challenge URL)."""
        resp = await self._signed_request(
            challenge.url,
            {},
            expected_status={200},
        )
        return Challenge.from_dict(resp.json())

    async def poll_authorization(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> Authorization:
        """Poll an authorization until it reaches a terminal state."""
        if timeout is None:
            timeout = self._poll_timeout
        start = monotonic()
        while True:
            resp = await self._signed_request(url, None, expected_status={200})
            authz = Authorization.from_dict(resp.json(), url=url)
            if authz.status == AuthorizationStatus.VALID:
                return authz
            if authz.status in {
                AuthorizationStatus.INVALID,
                AuthorizationStatus.DEACTIVATED,
                AuthorizationStatus.EXPIRED,
                AuthorizationStatus.REVOKED,
            }:
                raise ACMEValidationError(
                    f"Authorization for {authz.identifier.value}"
                    f" reached terminal state: {authz.status}",
                    identifier=authz.identifier.value,
                )
            elapsed = monotonic() - start
            if elapsed >= timeout:
                raise ACMETimeoutError(
                    f"Timed out polling authorization {url}",
                    url=url,
                    last_status=authz.status,
                )
            delay = self._poll_interval
            retry_after = resp.headers.get("retry-after")
            if retry_after:
                parsed = _parse_retry_after(retry_after)
                if parsed is not None:
                    delay = max(1.0, parsed)
            remaining = timeout - (monotonic() - start)
            delay = min(delay, max(0.1, remaining))
            await asyncio.sleep(delay)

    async def finalize_order(self, order: Order, csr_der: bytes) -> Order:
        """Submit the CSR to finalize the order."""
        payload = {"csr": crypto.b64url_encode(csr_der)}
        resp = await self._signed_request(
            order.finalize,
            payload,
            expected_status={200},
        )
        return Order.from_dict(resp.json(), url=order.url)

    async def poll_order(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> Order:
        """Poll an order until it reaches a terminal state (valid or invalid)."""
        if timeout is None:
            timeout = self._poll_timeout
        start = monotonic()
        while True:
            resp = await self._signed_request(url, None, expected_status={200})
            order = Order.from_dict(resp.json(), url=url)
            if order.status == OrderStatus.VALID:
                return order
            if order.status == OrderStatus.INVALID:
                detail = ""
                if order.error:
                    detail = order.error.detail or ""
                raise ACMEValidationError(
                    f"Order {url} became invalid: {detail}",
                    identifier=order.identifiers[0].value if order.identifiers else "",
                )
            elapsed = monotonic() - start
            if elapsed >= timeout:
                raise ACMETimeoutError(
                    f"Timed out polling order {url}",
                    url=url,
                    last_status=order.status,
                )
            delay = self._poll_interval
            retry_after = resp.headers.get("retry-after")
            if retry_after:
                parsed = _parse_retry_after(retry_after)
                if parsed is not None:
                    delay = max(1.0, parsed)
            remaining = timeout - (monotonic() - start)
            delay = min(delay, max(0.1, remaining))
            await asyncio.sleep(delay)

    async def _poll_order_ready(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> Order:
        """Poll an order until it reaches ``ready`` (or a terminal state).

        Used internally before finalize to close the race between
        authorization completion and order state transition.
        """
        if timeout is None:
            timeout = self._poll_timeout
        start = monotonic()
        while True:
            resp = await self._signed_request(url, None, expected_status={200})
            order = Order.from_dict(resp.json(), url=url)
            if order.status in {
                OrderStatus.READY,
                OrderStatus.VALID,
                OrderStatus.PROCESSING,
            }:
                return order
            if order.status == OrderStatus.INVALID:
                detail = ""
                if order.error:
                    detail = order.error.detail or ""
                raise ACMEValidationError(
                    f"Order {url} became invalid: {detail}",
                    identifier=order.identifiers[0].value if order.identifiers else "",
                )
            elapsed = monotonic() - start
            if elapsed >= timeout:
                raise ACMETimeoutError(
                    f"Timed out waiting for order {url} to become ready",
                    url=url,
                    last_status=order.status,
                )
            delay = self._poll_interval
            retry_after = resp.headers.get("retry-after")
            if retry_after:
                parsed = _parse_retry_after(retry_after)
                if parsed is not None:
                    delay = max(1.0, parsed)
            remaining = timeout - (monotonic() - start)
            delay = min(delay, max(0.1, remaining))
            await asyncio.sleep(delay)

    async def download_certificate(self, url: str) -> str:
        """Download the certificate chain via POST-as-GET."""
        resp = await self._signed_request(url, None, expected_status={200})
        return resp.text

    # --- Revocation ---

    async def revoke(
        self,
        cert_pem: bytes | str,
        *,
        reason: int | None = None,
    ) -> None:
        """Revoke a certificate using the account key (RFC 8555 §7.6).

        Args:
            cert_pem: PEM-encoded certificate to revoke.
            reason: Optional revocation reason code
                (see :class:`~lacme.models.RevocationReason`).
        """
        d = await self.directory()
        payload = self._build_revocation_payload(cert_pem, reason)
        await self._signed_request(d.revoke_cert, payload, expected_status={200})

    async def revoke_with_cert_key(
        self,
        cert_pem: bytes | str,
        cert_key: ec.EllipticCurvePrivateKey,
        *,
        reason: int | None = None,
    ) -> None:
        """Revoke a certificate using its own key pair (RFC 8555 §7.6).

        Does not require an ACME account.  The JWS is signed with
        *cert_key* and uses a JWK header (not KID).
        """
        d = await self.directory()
        payload = self._build_revocation_payload(cert_pem, reason)
        for attempt in range(_MAX_BAD_NONCE_RETRIES + 1):
            nonce = await self._get_nonce()
            try:
                await self._raw_signed_request(
                    d.revoke_cert,
                    payload,
                    signing_key=cert_key,
                    nonce=nonce,
                    kid=None,
                    expected_status={200},
                )
                return
            except BadNonceError:
                if attempt < _MAX_BAD_NONCE_RETRIES:
                    logger.debug("badNonce on revoke_with_cert_key — retrying")
                    continue
                raise

    @staticmethod
    def _build_revocation_payload(
        cert_pem: bytes | str,
        reason: int | None,
    ) -> dict[str, Any]:
        cert_der = crypto.pem_to_der_certificate(cert_pem)
        payload: dict[str, Any] = {"certificate": crypto.b64url_encode(cert_der)}
        if reason is not None:
            _validate_revocation_reason(reason)
            payload["reason"] = reason
        return payload

    # --- High-level orchestration ---

    async def issue(
        self,
        domains: IdentifierValue | Sequence[IdentifierValue],
        *,
        challenge_type: str = "http-01",
        challenge_map: ChallengeMap | None = None,
    ) -> CertBundle:
        """Issue a certificate for DNS names and/or typed IP addresses.

        Orchestrates: account → order → authorize → finalize → download.

        Args:
            domains: DNS name(s) and/or typed IPv4/IPv6 address objects to
                include in the certificate. Plain strings are always treated
                as DNS identifiers.
            challenge_type: Default challenge type for all identifiers.
            challenge_map: Per-identifier overrides mapping
                ``{identifier: (challenge_type, handler)}``. Use the same
                typed IP address object used in *domains* for an IP override.
                Identifiers not in the map fall back to *challenge_type* and
                the client's default ``challenge_handler``.
        """
        import datetime

        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_pem_x509_certificates

        from lacme._types import CertBundle as _CertBundle

        identifier_values = normalize_identifier_values(domains)
        identifiers = [_identifier_from_value(value) for value in identifier_values]
        identifier_strings = [identifier.value for identifier in identifiers]

        # Build effective per-identifier (challenge_type, handler) map. Public
        # Callback arguments remain strings for compatibility. Typed challenge
        # map keys distinguish DNS "192.0.2.1" from IPv4Address("192.0.2.1").
        challenge_overrides = (
            {
                identifier_key_from_value(value): override
                for value, override in challenge_map.items()
            }
            if challenge_map is not None
            else {}
        )
        effective: dict[tuple[str, str], tuple[str, str, ChallengeHandler]] = {}
        for input_value, identifier in zip(identifier_values, identifiers, strict=True):
            value = identifier.value
            key = identifier_key_from_value(input_value)
            if key in challenge_overrides:
                ct, handler = challenge_overrides[key]
            elif self._challenge_handler is not None:
                ct, handler = challenge_type, self._challenge_handler
            else:
                msg = f"No challenge handler for identifier {value!r}"
                raise ValueError(msg)
            effective[key] = (value, ct, handler)

        # Identifier/challenge compatibility checks.
        for input_value, identifier in zip(identifier_values, identifiers, strict=True):
            value = identifier.value
            _, ct, _ = effective[identifier_key_from_value(input_value)]
            if identifier.type == IdentifierType.DNS and value.startswith("*.") and ct == "http-01":
                msg = f"Wildcard domain {value!r} requires dns-01, not http-01"
                raise ValueError(msg)
            if identifier.type == IdentifierType.IP and ct == "dns-01":
                msg = f"IP address {value!r} cannot use dns-01"
                raise ValueError(msg)

        # Registered-domain limits do not apply to RFC 8738 IP identifiers.
        rate_limit_domains = [
            identifier.value for identifier in identifiers if identifier.type == IdentifierType.DNS
        ]

        # 0. Rate limit check
        if self._rate_limit_tracker is not None:
            from lacme.errors import RateLimitPreventedError

            rl_status = self._rate_limit_tracker.check(rate_limit_domains)
            if not rl_status.allowed:
                msg = f"Rate limit would be exceeded: {'; '.join(rl_status.warnings)}"
                raise RateLimitPreventedError(msg)

        # 1. Ensure account
        await self._ensure_account_key()
        if self._account_url is None:
            await self.create_account(contact=self._contact)

        # 2. Create order
        order = await self.create_order(identifier_values)

        # 3. Solve challenges
        authzs = await self.get_authorizations(order)
        provisioned: list[tuple[str, str, ChallengeHandler]] = []
        authorization_routes: dict[str, tuple[str, str, ChallengeHandler]] = {}
        try:
            for authz in authzs:
                authorization_value = authz.identifier.value
                if authz.wildcard:
                    if authz.identifier.type != IdentifierType.DNS:
                        msg = "Server returned a wildcard authorization for a non-DNS identifier"
                        raise ValueError(msg)
                    validate_dns_identifier(authorization_value, allow_wildcard=False)
                    authorization_value = f"*.{authorization_value}"
                effective_key = identifier_key_from_protocol(
                    authz.identifier.type.value,
                    authorization_value,
                )
                if effective_key not in effective:
                    msg = (
                        "Server returned an unexpected authorization identifier: "
                        f"{authz.identifier.type.value}:{authorization_value}"
                    )
                    raise ValueError(msg)
                domain_val, ct, handler = effective[effective_key]
                authorization_routes[authz.url] = (domain_val, ct, handler)
                chall = authz.find_challenge(ct)
                if chall is None:
                    msg = f"No {ct} challenge for {domain_val}"
                    raise ValueError(msg)
                if self._account_key is None:
                    msg = "No account key — call _ensure_account_key() first"
                    raise RuntimeError(msg)
                ka = crypto.key_authorization(chall.token, self._account_key)
                await handler.provision(domain_val, chall.token, ka)
                provisioned.append((domain_val, chall.token, handler))
                await self.respond_to_challenge(chall)

            # 4. Poll authorizations
            for authz in authzs:
                try:
                    await self.poll_authorization(authz.url)
                except Exception as exc:
                    if self._event_dispatcher is not None:
                        from lacme.events import ChallengeFailed

                        domain_val, ct, _ = authorization_routes[authz.url]
                        await self._event_dispatcher.emit(
                            ChallengeFailed(
                                domain=domain_val,
                                challenge_type=ct,
                                error=str(exc),
                            )
                        )
                    raise

            # 5. Confirm order reached "ready" before finalizing
            order = await self._poll_order_ready(order.url)

            # 6. Generate cert key + CSR, finalize (skip if already processing/valid)
            cert_key = crypto.generate_ec_key()
            csr_der = crypto.generate_csr(cert_key, identifier_values)
            if order.status == OrderStatus.READY:
                order = await self.finalize_order(order, csr_der)

            # 7. Poll order until valid
            if order.status != OrderStatus.VALID:
                order = await self.poll_order(order.url)

            # 8. Download certificate
            if order.certificate is None:
                msg = "Order is valid but has no certificate URL"
                raise RuntimeError(msg)
            fullchain_pem_str = await self.download_certificate(order.certificate)
        finally:
            # Deprovision challenges — catch errors so all are cleaned up
            # and the original exception is not masked.
            for domain, token, handler in provisioned:
                try:
                    await handler.deprovision(domain, token)
                except Exception:
                    logger.warning("Failed to deprovision challenge for %s", domain, exc_info=True)

        # 8. Build result
        fullchain_pem = fullchain_pem_str.encode("ascii")
        key_pem = crypto.private_key_to_pem(cert_key)

        # Parse leaf cert from chain (first cert in PEM bundle)
        certs = load_pem_x509_certificates(fullchain_pem)
        if not certs:
            msg = "Server returned empty certificate chain"
            raise RuntimeError(msg)
        cert_obj = certs[0]
        try:
            certificate_identifiers = certificate_identifier_values(cert_obj)
        except (TypeError, ValueError) as exc:
            msg = f"Server returned a certificate with invalid identifiers: {exc}"
            raise ACMEError(msg) from exc
        if identifier_key_set(certificate_identifiers) != identifier_key_set(identifier_values):
            msg = "Server returned a certificate for a different identifier set"
            raise ACMEError(msg)

        public_key_format = serialization.PublicFormat.SubjectPublicKeyInfo
        certificate_public_key = cert_obj.public_key().public_bytes(
            serialization.Encoding.DER,
            public_key_format,
        )
        local_public_key = cert_key.public_key().public_bytes(
            serialization.Encoding.DER,
            public_key_format,
        )
        if certificate_public_key != local_public_key:
            msg = "Server returned a certificate for a different public key"
            raise ACMEError(msg)

        leaf_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        expires_at = cert_obj.not_valid_after_utc
        now = datetime.datetime.now(datetime.UTC)

        bundle = _CertBundle(
            domain=identifier_strings[0],
            domains=tuple(identifier_strings),
            cert_pem=leaf_pem,
            fullchain_pem=fullchain_pem,
            key_pem=key_pem,
            issued_at=now,
            expires_at=expires_at,
        )

        # 9. Save to store
        if self._store is not None:
            bundle = self._store.save_cert(bundle)

        # 10. Record issuance for rate limiting
        if self._rate_limit_tracker is not None:
            self._rate_limit_tracker.record(rate_limit_domains)

        # 11. Emit event
        if self._event_dispatcher is not None:
            from lacme.events import CertificateIssued

            await self._event_dispatcher.emit(
                CertificateIssued(
                    domain=bundle.domain,
                    domains=bundle.domains,
                    expires_at=bundle.expires_at,
                )
            )

        return bundle

    # --- Rate limits ---

    def check_rate_limits(
        self,
        domains: IdentifierValue | Sequence[IdentifierValue],
    ) -> RateLimitStatus:
        """Check if issuing for *domains* would exceed rate limits.

        Typed IP identifiers are excluded from registered-domain accounting.
        Requires a ``rate_limit_tracker`` to be set on the client.

        Raises:
            ValueError: If no rate limit tracker is configured.
        """
        if self._rate_limit_tracker is None:
            msg = "No rate_limit_tracker configured"
            raise ValueError(msg)
        identifiers = [
            _identifier_from_value(value) for value in normalize_identifier_values(domains)
        ]
        rate_limit_domains = [
            identifier.value for identifier in identifiers if identifier.type == IdentifierType.DNS
        ]
        return self._rate_limit_tracker.check(rate_limit_domains)

    # --- Auto-renewal ---

    async def auto_renew(
        self,
        *,
        interval_hours: float = 12.0,
        days_before_expiry: int = 30,
        on_renewed: Callable[[CertBundle], Any] | None = None,
    ) -> asyncio.Task[None]:
        """Start a background renewal task.  Requires a store.

        Returns the :class:`asyncio.Task` running the renewal loop.

        Raises:
            ValueError: If no store was provided to the client.
        """
        if self._store is None:
            msg = "auto_renew() requires a store"
            raise ValueError(msg)
        from lacme.renewal import RenewalManager

        manager = RenewalManager(
            client=self,
            store=self._store,
            interval_hours=interval_hours,
            days_before_expiry=days_before_expiry,
            on_renewed=on_renewed,
            event_dispatcher=self._event_dispatcher,
        )
        return manager.start()
