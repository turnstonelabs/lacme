"""Test utilities for lacme.

Provides :class:`MockACMEServer`, an in-process ACME server backed by
:class:`httpx.MockTransport` for integration testing.
"""

from __future__ import annotations

import base64
import datetime
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

import httpx

from lacme.crypto import b64url_encode

# ---------------------------------------------------------------------------
# Internal state models
# ---------------------------------------------------------------------------


@dataclass
class _MockAccount:
    url: str
    status: str = "valid"
    contact: list[str] = field(default_factory=list)
    jwk_thumbprint: str = ""


@dataclass
class _MockOrder:
    url: str
    domains: list[str]
    status: str = "pending"
    authz_urls: list[str] = field(default_factory=list)
    finalize_url: str = ""
    certificate_url: str | None = None


@dataclass
class _MockAuthorization:
    url: str
    domain: str
    status: str = "pending"
    token: str = ""
    challenge_url: str = ""
    dns_challenge_url: str = ""
    challenge_status: str = "pending"


# ---------------------------------------------------------------------------
# MockACMEServer
# ---------------------------------------------------------------------------


class MockACMEServer:
    """In-process mock ACME server for integration tests.

    Implements enough of the ACME protocol to support the full
    :meth:`~lacme.client.Client.issue` flow.  Does **not** verify
    JWS signatures — focuses on protocol flow testing.

    Not thread-safe.  Intended for single-threaded or single-async-task
    test scenarios.

    Usage::

        server = MockACMEServer()
        transport = server.as_transport()
        http = httpx.AsyncClient(transport=transport, base_url="https://acme.test")
        async with Client(
            directory_url="https://acme.test/directory",
            http_client=http,
            account_key=key,
            challenge_handler=handler,
        ) as client:
            bundle = await client.issue(["example.com"])
    """

    def __init__(
        self,
        *,
        auto_validate: bool = True,
        base_url: str = "https://acme.test",
    ) -> None:
        self._auto_validate = auto_validate
        self._base_url = base_url.rstrip("/")

        self._accounts: dict[str, _MockAccount] = {}
        self._orders: dict[str, _MockOrder] = {}
        self._authorizations: dict[str, _MockAuthorization] = {}
        self._certificates: dict[str, str] = {}  # url -> PEM

        self._nonce_counter = 0
        self._account_counter = 0
        self._order_counter = 0
        self._authz_counter = 0
        self._cert_counter = 0

    def as_transport(self) -> httpx.MockTransport:
        """Return an :class:`httpx.MockTransport` wrapping this server."""
        return httpx.MockTransport(self._handle_request)

    def validate_challenge(self, challenge_url: str) -> None:
        """Manually validate a challenge (when ``auto_validate=False``)."""
        for authz in self._authorizations.values():
            if authz.challenge_url == challenge_url or authz.dns_challenge_url == challenge_url:
                authz.challenge_status = "valid"
                authz.status = "valid"
                return
        msg = f"No challenge found for URL: {challenge_url}"
        raise ValueError(msg)

    # ------------------------------------------------------------------
    # Request handler
    # ------------------------------------------------------------------

    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        # Nonce for every response
        nonce = self._next_nonce()
        base_headers = {"Replay-Nonce": nonce}

        if path == "/directory":
            return self._handle_directory(base_headers)

        if path == "/new-nonce":
            if method == "HEAD":
                return httpx.Response(200, headers=base_headers)
            return httpx.Response(204, headers=base_headers)

        if path == "/new-account":
            return self._handle_new_account(request, base_headers)

        if path == "/new-order":
            return self._handle_new_order(request, base_headers)

        if path.startswith("/authz/"):
            return self._handle_authz(request, path, base_headers)

        if path.startswith("/chall/"):
            return self._handle_challenge(request, path, base_headers)

        if path.startswith("/finalize/"):
            return self._handle_finalize(request, path, base_headers)

        if path.startswith("/order/"):
            return self._handle_order(request, path, base_headers)

        if path.startswith("/cert/"):
            return self._handle_cert(path, base_headers)

        if path == "/revoke-cert":
            return self._handle_revoke(base_headers)

        if path == "/key-change":
            return self._handle_key_change(base_headers)

        return httpx.Response(404, json={"type": "not-found"}, headers=base_headers)

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    def _handle_directory(self, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "newNonce": f"{self._base_url}/new-nonce",
                "newAccount": f"{self._base_url}/new-account",
                "newOrder": f"{self._base_url}/new-order",
                "revokeCert": f"{self._base_url}/revoke-cert",
                "keyChange": f"{self._base_url}/key-change",
            },
            headers=headers,
        )

    def _handle_new_account(
        self, request: httpx.Request, headers: dict[str, str]
    ) -> httpx.Response:
        body = self._parse_jws_body(request)
        only_existing = body.get("onlyReturnExisting", False)

        # Look for existing account by JWK thumbprint from protected header
        protected = self._parse_jws_protected(request)
        jwk = protected.get("jwk", {})
        thumbprint = json.dumps(jwk, sort_keys=True)

        for acct in self._accounts.values():
            if acct.jwk_thumbprint == thumbprint:
                return httpx.Response(
                    200,
                    json={
                        "status": acct.status,
                        "contact": acct.contact,
                    },
                    headers={**headers, "Location": acct.url},
                )

        if only_existing:
            return httpx.Response(
                400,
                json={
                    "type": "urn:ietf:params:acme:error:accountDoesNotExist",
                    "detail": "Account not found",
                },
                headers=headers,
            )

        # Create new account
        self._account_counter += 1
        url = f"{self._base_url}/acct/{self._account_counter}"
        acct = _MockAccount(
            url=url,
            contact=body.get("contact", []),
            jwk_thumbprint=thumbprint,
        )
        self._accounts[url] = acct

        return httpx.Response(
            201,
            json={"status": "valid", "contact": acct.contact},
            headers={**headers, "Location": url},
        )

    def _handle_new_order(self, request: httpx.Request, headers: dict[str, str]) -> httpx.Response:
        body = self._parse_jws_body(request)
        identifiers = body.get("identifiers", [])
        domains = [i["value"] for i in identifiers]

        self._order_counter += 1
        order_url = f"{self._base_url}/order/{self._order_counter}"
        finalize_url = f"{self._base_url}/finalize/{self._order_counter}"

        # Create authorizations
        authz_urls = []
        for domain in domains:
            self._authz_counter += 1
            authz_url = f"{self._base_url}/authz/{self._authz_counter}"
            chall_url = f"{self._base_url}/chall/{self._authz_counter}"
            token = b64url_encode(secrets.token_bytes(32))

            authz = _MockAuthorization(
                url=authz_url,
                domain=domain,
                token=token,
                challenge_url=chall_url,
                dns_challenge_url=f"{chall_url}-dns",
            )
            self._authorizations[authz_url] = authz
            authz_urls.append(authz_url)

        order = _MockOrder(
            url=order_url,
            domains=domains,
            authz_urls=authz_urls,
            finalize_url=finalize_url,
        )
        self._orders[order_url] = order

        return httpx.Response(
            201,
            json={
                "status": "pending",
                "identifiers": identifiers,
                "authorizations": authz_urls,
                "finalize": finalize_url,
            },
            headers={**headers, "Location": order_url},
        )

    def _handle_authz(
        self, request: httpx.Request, path: str, headers: dict[str, str]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        authz = self._authorizations.get(url)
        if authz is None:
            return httpx.Response(404, json={"type": "not-found"}, headers=headers)

        return httpx.Response(
            200,
            json={
                "status": authz.status,
                "identifier": {"type": "dns", "value": authz.domain},
                "challenges": [
                    {
                        "type": "http-01",
                        "url": authz.challenge_url,
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                    {
                        "type": "dns-01",
                        "url": authz.challenge_url + "-dns",
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                ],
            },
            headers=headers,
        )

    def _handle_challenge(
        self, request: httpx.Request, path: str, headers: dict[str, str]
    ) -> httpx.Response:
        chall_url = f"{self._base_url}{path}"

        # Find the authorization for this challenge (HTTP-01 or DNS-01)
        for authz in self._authorizations.values():
            is_http = authz.challenge_url == chall_url
            is_dns = authz.dns_challenge_url == chall_url
            if is_http or is_dns:
                if self._auto_validate:
                    authz.challenge_status = "valid"
                    authz.status = "valid"
                else:
                    authz.challenge_status = "processing"

                chall_type = "dns-01" if is_dns else "http-01"
                return httpx.Response(
                    200,
                    json={
                        "type": chall_type,
                        "url": chall_url,
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                    headers=headers,
                )

        return httpx.Response(404, json={"type": "not-found"}, headers=headers)

    def _handle_finalize(
        self, request: httpx.Request, path: str, headers: dict[str, str]
    ) -> httpx.Response:
        # Extract order number from path
        order_num = path.split("/")[-1]
        order_url = f"{self._base_url}/order/{order_num}"
        order = self._orders.get(order_url)
        if order is None:
            return httpx.Response(404, json={"type": "not-found"}, headers=headers)

        # Verify all authorizations are valid (mirrors real ACME server behavior)
        for authz_url in order.authz_urls:
            authz = self._authorizations.get(authz_url)
            if authz is None or authz.status != "valid":
                return httpx.Response(
                    403,
                    json={
                        "type": "urn:ietf:params:acme:error:orderNotReady",
                        "detail": "Order is not ready for finalization",
                    },
                    headers=headers,
                )

        # Generate certificate
        self._cert_counter += 1
        cert_url = f"{self._base_url}/cert/{self._cert_counter}"
        cert_pem = self._generate_certificate(order.domains)
        self._certificates[cert_url] = cert_pem

        order.status = "valid"
        order.certificate_url = cert_url

        return httpx.Response(
            200,
            json={
                "status": "valid",
                "identifiers": [{"type": "dns", "value": d} for d in order.domains],
                "authorizations": order.authz_urls,
                "finalize": order.finalize_url,
                "certificate": cert_url,
            },
            headers={**headers, "Location": order_url},
        )

    def _handle_order(
        self, request: httpx.Request, path: str, headers: dict[str, str]
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        order = self._orders.get(url)
        if order is None:
            return httpx.Response(404, json={"type": "not-found"}, headers=headers)

        # Auto-transition: if all authzs are valid and order is pending → ready
        if order.status == "pending":
            all_valid = all(
                self._authorizations[aurl].status == "valid"
                for aurl in order.authz_urls
                if aurl in self._authorizations
            )
            if all_valid:
                order.status = "ready"

        body: dict[str, Any] = {
            "status": order.status,
            "identifiers": [{"type": "dns", "value": d} for d in order.domains],
            "authorizations": order.authz_urls,
            "finalize": order.finalize_url,
        }
        if order.certificate_url:
            body["certificate"] = order.certificate_url

        return httpx.Response(200, json=body, headers={**headers, "Location": url})

    def _handle_cert(self, path: str, headers: dict[str, str]) -> httpx.Response:
        url = f"{self._base_url}{path}"
        pem = self._certificates.get(url)
        if pem is None:
            return httpx.Response(404, json={"type": "not-found"}, headers=headers)

        return httpx.Response(
            200,
            content=pem.encode("ascii"),
            headers={**headers, "Content-Type": "application/pem-certificate-chain"},
        )

    def _handle_revoke(self, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(200, headers=headers)

    def _handle_key_change(self, headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(200, json={}, headers=headers)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_nonce(self) -> str:
        self._nonce_counter += 1
        return b64url_encode(f"nonce-{self._nonce_counter}".encode())

    @staticmethod
    def _parse_jws_body(request: httpx.Request) -> dict[str, Any]:
        """Extract the payload from a JWS POST body."""
        data = json.loads(request.content)
        payload_b64 = data.get("payload", "")
        if not payload_b64:
            return {}
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if not decoded:
            return {}
        return json.loads(decoded)  # type: ignore[no-any-return]

    @staticmethod
    def _parse_jws_protected(request: httpx.Request) -> dict[str, Any]:
        """Extract the protected header from a JWS POST body."""
        data = json.loads(request.content)
        protected_b64 = data.get("protected", "")
        padded = protected_b64 + "=" * (-len(protected_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)  # type: ignore[no-any-return]

    @staticmethod
    def _generate_certificate(domains: list[str]) -> str:
        """Generate a self-signed PEM certificate for testing."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import (
            CertificateBuilder,
            DNSName,
            Name,
            NameAttribute,
            SubjectAlternativeName,
            random_serial_number,
        )
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        subject = Name([NameAttribute(NameOID.COMMON_NAME, domains[0])])
        sans = [DNSName(d) for d in domains]

        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=90))
            .add_extension(SubjectAlternativeName(sans), critical=False)
            .sign(key, hashes.SHA256())
        )

        return cert.public_bytes(Encoding.PEM).decode("ascii")
