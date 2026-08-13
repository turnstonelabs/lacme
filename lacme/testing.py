"""Test utilities for lacme.

Provides :class:`MockACMEServer`, an in-process ACME server backed by
:class:`httpx2.MockTransport` for integration testing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx2

from lacme._identifiers import (
    UnsupportedIdentifierTypeError,
    decode_and_validate_csr,
    normalize_protocol_identifiers,
)
from lacme._jose import parse_unverified_jws
from lacme.ca import CertificateAuthority
from lacme.crypto import b64url_encode, jwk_thumbprint

if TYPE_CHECKING:
    from lacme._types import IdentifierValue

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
    identifiers: list[dict[str, str]]
    status: str = "pending"
    authz_urls: list[str] = field(default_factory=list)
    finalize_url: str = ""
    certificate_url: str | None = None


@dataclass
class _MockAuthorization:
    url: str
    domain: str
    identifier_type: str = "dns"
    wildcard: bool = False
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
        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=key,
                challenge_handler=handler,
            ) as client,
        ):
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
        self._ca = CertificateAuthority()
        self._ca.init(cn="lacme Mock ACME CA")

        self._accounts: dict[str, _MockAccount] = {}
        self._orders: dict[str, _MockOrder] = {}
        self._authorizations: dict[str, _MockAuthorization] = {}
        self._certificates: dict[str, str] = {}  # url -> PEM

        self._nonce_counter = 0
        self._account_counter = 0
        self._order_counter = 0
        self._authz_counter = 0
        self._cert_counter = 0

    def as_transport(self) -> httpx2.MockTransport:
        """Return an :class:`httpx2.MockTransport` wrapping this server."""
        return httpx2.MockTransport(self._handle_request)

    def validate_challenge(self, challenge_url: str) -> None:
        """Manually validate a challenge (when ``auto_validate=False``)."""
        for authz in self._authorizations.values():
            is_http = not authz.wildcard and authz.challenge_url == challenge_url
            is_dns = authz.identifier_type == "dns" and authz.dns_challenge_url == challenge_url
            if is_http or is_dns:
                authz.challenge_status = "valid"
                authz.status = "valid"
                return
        msg = f"No challenge found for URL: {challenge_url}"
        raise ValueError(msg)

    # ------------------------------------------------------------------
    # Request handler
    # ------------------------------------------------------------------

    def _handle_request(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        method = request.method

        # Nonce for every response
        nonce = self._next_nonce()
        base_headers = {"Replay-Nonce": nonce}

        if path == "/directory":
            return self._handle_directory(base_headers)

        if path == "/new-nonce":
            if method == "HEAD":
                return httpx2.Response(200, headers=base_headers)
            return httpx2.Response(204, headers=base_headers)

        is_jws_endpoint = path in {
            "/new-account",
            "/new-order",
            "/revoke-cert",
            "/key-change",
        } or path.startswith(("/authz/", "/chall/", "/finalize/", "/order/", "/cert/"))
        if is_jws_endpoint:
            try:
                parse_unverified_jws(
                    request.content,
                    payload_mode=(
                        "empty" if path.startswith(("/authz/", "/order/", "/cert/")) else "object"
                    ),
                )
            except (TypeError, ValueError) as exc:
                return self._problem_response(base_headers, error="malformed", detail=str(exc))

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

        return httpx2.Response(404, json={"type": "not-found"}, headers=base_headers)

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    def _handle_directory(self, headers: dict[str, str]) -> httpx2.Response:
        return httpx2.Response(
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
        self, request: httpx2.Request, headers: dict[str, str]
    ) -> httpx2.Response:
        try:
            body = self._parse_jws_body(request)
            only_existing = body.get("onlyReturnExisting", False)

            # Look for existing account by JWK thumbprint from protected header
            protected = self._parse_jws_protected(request)
            jwk = protected.get("jwk", {})
            if not isinstance(jwk, dict):
                msg = "JWS protected jwk must be an object"
                raise ValueError(msg)
            thumbprint = jwk_thumbprint(jwk)
        except (KeyError, TypeError, ValueError) as exc:
            return self._problem_response(headers, error="malformed", detail=str(exc))

        for acct in self._accounts.values():
            if acct.jwk_thumbprint == thumbprint:
                return httpx2.Response(
                    200,
                    json={
                        "status": acct.status,
                        "contact": acct.contact,
                    },
                    headers={**headers, "Location": acct.url},
                )

        if only_existing:
            return httpx2.Response(
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

        return httpx2.Response(
            201,
            json={"status": "valid", "contact": acct.contact},
            headers={**headers, "Location": url},
        )

    def _handle_new_order(
        self, request: httpx2.Request, headers: dict[str, str]
    ) -> httpx2.Response:
        try:
            body = self._parse_jws_body(request)
            if not isinstance(body, dict):
                msg = "newOrder payload must be an object"
                raise ValueError(msg)
            identifiers = normalize_protocol_identifiers(body.get("identifiers"))
        except UnsupportedIdentifierTypeError as exc:
            return self._problem_response(
                headers,
                error="unsupportedIdentifier",
                detail=str(exc),
            )
        except (TypeError, ValueError) as exc:
            return self._problem_response(headers, error="malformed", detail=str(exc))

        self._order_counter += 1
        order_url = f"{self._base_url}/order/{self._order_counter}"
        finalize_url = f"{self._base_url}/finalize/{self._order_counter}"

        # Create authorizations
        authz_urls = []
        for identifier in identifiers:
            self._authz_counter += 1
            authz_url = f"{self._base_url}/authz/{self._authz_counter}"
            chall_url = f"{self._base_url}/chall/{self._authz_counter}"
            token = b64url_encode(secrets.token_bytes(32))

            wildcard = identifier["type"] == "dns" and identifier["value"].startswith("*.")
            domain = identifier["value"][2:] if wildcard else identifier["value"]
            authz = _MockAuthorization(
                url=authz_url,
                domain=domain,
                identifier_type=identifier["type"],
                wildcard=wildcard,
                token=token,
                challenge_url=chall_url,
                dns_challenge_url=f"{chall_url}-dns",
            )
            self._authorizations[authz_url] = authz
            authz_urls.append(authz_url)

        order = _MockOrder(
            url=order_url,
            identifiers=identifiers,
            authz_urls=authz_urls,
            finalize_url=finalize_url,
        )
        self._orders[order_url] = order

        return httpx2.Response(
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
        self, request: httpx2.Request, path: str, headers: dict[str, str]
    ) -> httpx2.Response:
        url = f"{self._base_url}{path}"
        authz = self._authorizations.get(url)
        if authz is None:
            return httpx2.Response(404, json={"type": "not-found"}, headers=headers)

        body: dict[str, Any] = {
            "status": authz.status,
            "identifier": {"type": authz.identifier_type, "value": authz.domain},
            "challenges": self._authorization_challenges(authz),
        }
        if authz.wildcard:
            body["wildcard"] = True
        return httpx2.Response(
            200,
            json=body,
            headers=headers,
        )

    def _handle_challenge(
        self, request: httpx2.Request, path: str, headers: dict[str, str]
    ) -> httpx2.Response:
        chall_url = f"{self._base_url}{path}"

        # Find the authorization for this challenge (HTTP-01 or DNS-01)
        for authz in self._authorizations.values():
            is_http = not authz.wildcard and authz.challenge_url == chall_url
            is_dns = authz.identifier_type == "dns" and authz.dns_challenge_url == chall_url
            if is_http or is_dns:
                if self._auto_validate:
                    authz.challenge_status = "valid"
                    authz.status = "valid"
                else:
                    authz.challenge_status = "processing"

                chall_type = "dns-01" if is_dns else "http-01"
                return httpx2.Response(
                    200,
                    json={
                        "type": chall_type,
                        "url": chall_url,
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                    headers=headers,
                )

        return httpx2.Response(404, json={"type": "not-found"}, headers=headers)

    def _handle_finalize(
        self, request: httpx2.Request, path: str, headers: dict[str, str]
    ) -> httpx2.Response:
        # Extract order number from path
        order_num = path.split("/")[-1]
        order_url = f"{self._base_url}/order/{order_num}"
        order = self._orders.get(order_url)
        if order is None:
            return httpx2.Response(404, json={"type": "not-found"}, headers=headers)

        # Verify all authorizations are valid (mirrors real ACME server behavior).
        if order.status == "pending":
            all_valid = all(
                (authz := self._authorizations.get(authz_url)) is not None
                and authz.status == "valid"
                for authz_url in order.authz_urls
            )
            if all_valid:
                order.status = "ready"
        if order.status != "ready":
            return self._problem_response(
                headers,
                error="orderNotReady",
                detail="Order is not ready for finalization",
                status=403,
            )

        try:
            body = self._parse_jws_body(request)
            if not isinstance(body, dict):
                msg = "Finalize payload must be an object"
                raise ValueError(msg)
            csr_der, csr_identifiers = decode_and_validate_csr(
                body.get("csr"),
                order.identifiers,
            )
        except (TypeError, ValueError) as exc:
            return self._problem_response(headers, error="badCSR", detail=str(exc))

        # Generate certificate
        self._cert_counter += 1
        cert_url = f"{self._base_url}/cert/{self._cert_counter}"
        cert_pem = self._generate_certificate(csr_der, csr_identifiers)
        self._certificates[cert_url] = cert_pem

        order.status = "valid"
        order.certificate_url = cert_url

        return httpx2.Response(
            200,
            json={
                "status": "valid",
                "identifiers": order.identifiers,
                "authorizations": order.authz_urls,
                "finalize": order.finalize_url,
                "certificate": cert_url,
            },
            headers={**headers, "Location": order_url},
        )

    def _handle_order(
        self, request: httpx2.Request, path: str, headers: dict[str, str]
    ) -> httpx2.Response:
        url = f"{self._base_url}{path}"
        order = self._orders.get(url)
        if order is None:
            return httpx2.Response(404, json={"type": "not-found"}, headers=headers)

        # Auto-transition: if all authzs are valid and order is pending → ready
        if order.status == "pending":
            all_valid = all(
                (authz := self._authorizations.get(aurl)) is not None and authz.status == "valid"
                for aurl in order.authz_urls
            )
            if all_valid:
                order.status = "ready"

        body: dict[str, Any] = {
            "status": order.status,
            "identifiers": order.identifiers,
            "authorizations": order.authz_urls,
            "finalize": order.finalize_url,
        }
        if order.certificate_url:
            body["certificate"] = order.certificate_url

        return httpx2.Response(200, json=body, headers={**headers, "Location": url})

    def _handle_cert(self, path: str, headers: dict[str, str]) -> httpx2.Response:
        url = f"{self._base_url}{path}"
        pem = self._certificates.get(url)
        if pem is None:
            return httpx2.Response(404, json={"type": "not-found"}, headers=headers)

        return httpx2.Response(
            200,
            content=pem.encode("ascii"),
            headers={**headers, "Content-Type": "application/pem-certificate-chain"},
        )

    def _handle_revoke(self, headers: dict[str, str]) -> httpx2.Response:
        return httpx2.Response(200, headers=headers)

    def _handle_key_change(self, headers: dict[str, str]) -> httpx2.Response:
        return httpx2.Response(200, json={}, headers=headers)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_nonce(self) -> str:
        self._nonce_counter += 1
        return b64url_encode(f"nonce-{self._nonce_counter}".encode())

    @staticmethod
    def _problem_response(
        headers: dict[str, str],
        *,
        error: str,
        detail: str,
        status: int = 400,
    ) -> httpx2.Response:
        return httpx2.Response(
            status,
            json={
                "type": f"urn:ietf:params:acme:error:{error}",
                "detail": detail,
            },
            headers={**headers, "Content-Type": "application/problem+json"},
        )

    @staticmethod
    def _parse_jws_body(request: httpx2.Request) -> dict[str, Any]:
        """Extract the payload from a JWS POST body."""
        return parse_unverified_jws(request.content)[1]

    @staticmethod
    def _parse_jws_protected(request: httpx2.Request) -> dict[str, Any]:
        """Extract the protected header from a JWS POST body."""
        return parse_unverified_jws(request.content)[0]

    @staticmethod
    def _authorization_challenges(authz: _MockAuthorization) -> list[dict[str, str]]:
        """Return only challenge types valid for the authorization identifier."""
        challenges = []
        if not authz.wildcard:
            challenges.append(
                {
                    "type": "http-01",
                    "url": authz.challenge_url,
                    "token": authz.token,
                    "status": authz.challenge_status,
                }
            )
        if authz.identifier_type == "dns":
            challenges.append(
                {
                    "type": "dns-01",
                    "url": authz.dns_challenge_url,
                    "token": authz.token,
                    "status": authz.challenge_status,
                }
            )
        return challenges

    def _generate_certificate(
        self,
        csr_der: bytes,
        identifiers: list[IdentifierValue],
    ) -> str:
        """Issue a leaf plus reusable mock root using the submitted CSR key."""
        return self._ca.issue_from_csr(
            csr_der,
            validated_identifiers=identifiers,
            validity_days=90,
        ).fullchain_pem.decode("ascii")
