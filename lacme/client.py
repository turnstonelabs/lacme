"""Async ACME v2 protocol client (RFC 8555).

Provides the :class:`Client` class which implements the full ACME order
lifecycle: account creation, order placement, challenge handling,
finalization, and certificate download.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from time import monotonic
from typing import TYPE_CHECKING, Any

import httpx

from lacme import crypto
from lacme.errors import (
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
)

if TYPE_CHECKING:
    from types import TracebackType

    from cryptography.hazmat.primitives.asymmetric import ec

    from lacme._types import CertBundle
    from lacme.challenges import ChallengeHandler
    from lacme.store import Store

logger = logging.getLogger("lacme")

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

_DEFAULT_POLL_TIMEOUT: float = 300.0
_DEFAULT_POLL_INTERVAL: float = 2.0
_MAX_BAD_NONCE_RETRIES = 1


class Client:
    """Async ACME v2 client.

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
        http_client: httpx.AsyncClient | None = None,
        poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._directory_url = directory_url
        self._account_key = account_key
        self._store = store
        self._contact: list[str] | None
        if isinstance(contact, str):
            self._contact = [contact]
        else:
            self._contact = contact
        self._challenge_handler = challenge_handler
        self._poll_timeout = poll_timeout
        self._poll_interval = poll_interval

        if http_client is not None:
            self._http = http_client
            self._owns_http = False
        else:
            self._http = httpx.AsyncClient()
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
        resp = await self._http.get(self._directory_url)
        resp.raise_for_status()
        self._harvest_nonce(resp)
        self._directory = Directory.from_dict(resp.json())
        return self._directory

    # --- Nonce management ---

    async def _get_nonce(self) -> str:
        if self._nonces:
            return self._nonces.pop()
        d = await self.directory()
        resp = await self._http.head(d.new_nonce)
        resp.raise_for_status()
        self._harvest_nonce(resp)
        if self._nonces:
            return self._nonces.pop()
        msg = "Failed to obtain a nonce from the ACME server"
        raise RuntimeError(msg)

    def _harvest_nonce(self, response: httpx.Response) -> None:
        nonce = response.headers.get("replay-nonce")
        if nonce:
            self._nonces.append(nonce)

    # --- JWS request ---

    async def _signed_request(
        self,
        url: str,
        payload: dict[str, Any] | bytes | None,
        *,
        expected_status: set[int] | None = None,
    ) -> httpx.Response:
        """Send a JWS-signed POST.  Auto-retries once on badNonce."""
        for attempt in range(_MAX_BAD_NONCE_RETRIES + 1):
            nonce = await self._get_nonce()
            kid = self._account_url

            if payload is None:
                raw_payload = b""
            elif isinstance(payload, dict):
                raw_payload = json.dumps(payload).encode()
            else:
                raw_payload = payload

            if self._account_key is None:
                msg = "No account key — call _ensure_account_key() first"
                raise RuntimeError(msg)
            jws_body = crypto.jws_encode(
                raw_payload,
                self._account_key,
                nonce=nonce,
                url=url,
                kid=kid,
            )

            resp = await self._http.post(
                url,
                content=json.dumps(jws_body).encode(),
                headers={"content-type": "application/jose+json"},
            )
            self._harvest_nonce(resp)

            try:
                self._check_response(resp, expected_status)
            except BadNonceError:
                if attempt < _MAX_BAD_NONCE_RETRIES:
                    logger.debug("badNonce — retrying with fresh nonce")
                    continue
                raise

            return resp

        # Unreachable, but satisfies mypy
        msg = "Exhausted badNonce retries"
        raise RuntimeError(msg)

    def _check_response(
        self,
        response: httpx.Response,
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
            raise httpx.HTTPStatusError(msg, request=response.request, response=response)
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
    ) -> Account:
        """Create or find an existing ACME account.

        Sets the internal account URL for subsequent requests.
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

    # --- Order lifecycle ---

    async def create_order(
        self,
        domains: str | list[str],
        *,
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> Order:
        """Create a new certificate order."""
        if self._account_url is None:
            msg = "No account URL — call create_account() first"
            raise RuntimeError(msg)
        if isinstance(domains, str):
            domains = [domains]
        d = await self.directory()
        identifiers = [
            Identifier(type=IdentifierType.DNS, value=domain).to_dict() for domain in domains
        ]
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
                with contextlib.suppress(ValueError):
                    delay = max(1.0, float(retry_after))
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
                with contextlib.suppress(ValueError):
                    delay = max(1.0, float(retry_after))
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
                with contextlib.suppress(ValueError):
                    delay = max(1.0, float(retry_after))
            remaining = timeout - (monotonic() - start)
            delay = min(delay, max(0.1, remaining))
            await asyncio.sleep(delay)

    async def download_certificate(self, url: str) -> str:
        """Download the certificate chain via POST-as-GET."""
        resp = await self._signed_request(url, None, expected_status={200})
        return resp.text

    # --- High-level orchestration ---

    async def issue(
        self,
        domains: str | list[str],
        *,
        challenge_type: str = "http-01",
    ) -> CertBundle:
        """Issue a certificate for the given domain(s).

        Orchestrates: account → order → authorize → finalize → download.
        """
        import datetime

        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_pem_x509_certificates

        from lacme._types import CertBundle as _CertBundle

        if isinstance(domains, str):
            domains = [domains]

        # Wildcard check
        for d in domains:
            if d.startswith("*.") and challenge_type == "http-01":
                msg = f"Wildcard domain {d!r} requires dns-01, not http-01"
                raise ValueError(msg)

        handler = self._challenge_handler
        if handler is None:
            msg = "No challenge_handler provided — required for issue()"
            raise ValueError(msg)

        # 1. Ensure account
        await self._ensure_account_key()
        if self._account_url is None:
            await self.create_account(contact=self._contact)

        # 2. Create order
        order = await self.create_order(domains)

        # 3. Solve challenges
        authzs = await self.get_authorizations(order)
        provisioned: list[tuple[str, str]] = []
        try:
            for authz in authzs:
                chall = authz.find_challenge(challenge_type)
                if chall is None:
                    msg = f"No {challenge_type} challenge for {authz.identifier.value}"
                    raise ValueError(msg)
                if self._account_key is None:
                    msg = "No account key — call _ensure_account_key() first"
                    raise RuntimeError(msg)
                ka = crypto.key_authorization(chall.token, self._account_key)
                await handler.provision(authz.identifier.value, chall.token, ka)
                provisioned.append((authz.identifier.value, chall.token))
                await self.respond_to_challenge(chall)

            # 4. Poll authorizations
            for authz in authzs:
                await self.poll_authorization(authz.url)

            # 5. Confirm order reached "ready" before finalizing
            order = await self._poll_order_ready(order.url)

            # 6. Generate cert key + CSR, finalize (skip if already processing/valid)
            cert_key = crypto.generate_ec_key()
            csr_der = crypto.generate_csr(cert_key, domains)
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
            for domain, token in provisioned:
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
        leaf_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        expires_at = cert_obj.not_valid_after_utc
        now = datetime.datetime.now(datetime.UTC)

        bundle = _CertBundle(
            domain=domains[0],
            domains=tuple(domains),
            cert_pem=leaf_pem,
            fullchain_pem=fullchain_pem,
            key_pem=key_pem,
            issued_at=now,
            expires_at=expires_at,
        )

        # 9. Save to store
        if self._store is not None:
            bundle = self._store.save_cert(bundle)

        return bundle
