"""ASGI application implementing ACME protocol endpoints.

Provides :class:`ACMEResponder`, an ASGI app that implements enough of
RFC 8555 for :meth:`~lacme.client.Client.issue` to work against it.
Certificate signing is delegated to :class:`~lacme.ca.CertificateAuthority`.
Mount in your web framework (Starlette, FastAPI, etc.) at a path prefix.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from lacme.crypto import b64url_encode

if TYPE_CHECKING:
    from lacme._types import Receive, Scope, Send
    from lacme.ca import CertificateAuthority

logger = logging.getLogger("lacme.acme_server")


# ---------------------------------------------------------------------------
# ChallengeValidator protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ChallengeValidator(Protocol):
    """Protocol for external challenge validation."""

    async def validate(
        self, identifier: str, identifier_type: str, token: str, key_authorization: str
    ) -> bool:
        """Return True if the challenge is satisfied."""
        ...


# ---------------------------------------------------------------------------
# Internal state models
# ---------------------------------------------------------------------------


@dataclass
class _Account:
    url: str
    status: str = "valid"
    contact: list[str] = field(default_factory=list)
    jwk_thumbprint: str = ""


@dataclass
class _Order:
    url: str
    domains: list[str]
    status: str = "pending"
    authz_urls: list[str] = field(default_factory=list)
    finalize_url: str = ""
    certificate_url: str | None = None


@dataclass
class _Authorization:
    url: str
    identifier_value: str
    identifier_type: str = "dns"
    status: str = "pending"
    token: str = ""
    challenge_url: str = ""
    dns_challenge_url: str = ""
    challenge_status: str = "pending"
    key_authorization: str = ""


# ---------------------------------------------------------------------------
# ACMEResponder
# ---------------------------------------------------------------------------


class ACMEResponder:
    """ASGI application implementing ACME protocol endpoints.

    Delegates certificate signing to a :class:`~lacme.ca.CertificateAuthority`.
    Mount in your web framework at a path prefix.

    .. warning::

        This responder does **not** validate JWS signatures or nonces.
        It is intended for trusted internal networks where the transport
        layer (mTLS, private network) provides authentication.  Do not
        expose to untrusted clients without additional auth middleware.

    Usage::

        ca = CertificateAuthority(store=store)
        ca.init()
        responder = ACMEResponder(ca=ca, auto_approve=True)
        # Mount at /acme in your ASGI app
        # Clients use: directory_url="https://host/acme/directory"
    """

    def __init__(
        self,
        ca: CertificateAuthority,
        *,
        challenge_validator: ChallengeValidator | None = None,
        auto_approve: bool = False,
    ) -> None:
        self._ca = ca
        self._challenge_validator = challenge_validator
        self._auto_approve = auto_approve

        self._accounts: dict[str, _Account] = {}
        self._orders: dict[str, _Order] = {}
        self._authorizations: dict[str, _Authorization] = {}
        self._certificates: dict[str, str] = {}  # url -> PEM

        self._nonce_counter = 0
        self._account_counter = 0
        self._order_counter = 0
        self._authz_counter = 0
        self._cert_counter = 0

        # threading.Lock is used instead of asyncio.Lock because all locked
        # sections are short dict mutations (no I/O or await).
        self._lock = threading.Lock()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point."""
        if scope["type"] != "http":
            return

        path = scope.get("path", "")

        # Strip root_path prefix from path if the framework already included it.
        # The path we route on is relative to our mount point.
        root_path = scope.get("root_path", "")
        if root_path and path.startswith(root_path):
            path = path[len(root_path) :]

        base_url = self._get_base_url(scope)
        nonce = self._next_nonce()
        extra_headers: dict[str, str] = {"Replay-Nonce": nonce}

        if path == "/directory":
            await self._handle_directory(send, base_url, extra_headers)
            return

        if path == "/new-nonce":
            # RFC 8555 §7.2: both HEAD and POST return 200 with Replay-Nonce header
            await self._send_json(send, status=200, body={}, headers=extra_headers)
            return

        if path == "/new-account":
            raw = await self._read_body(receive)
            await self._handle_new_account(send, raw, base_url, extra_headers)
            return

        if path == "/new-order":
            raw = await self._read_body(receive)
            await self._handle_new_order(send, raw, base_url, extra_headers)
            return

        if path.startswith("/authz/"):
            _ = await self._read_body(receive)  # consume body
            await self._handle_authz(send, path, base_url, extra_headers)
            return

        if path.startswith("/chall/"):
            raw = await self._read_body(receive)
            await self._handle_challenge(send, raw, path, base_url, extra_headers)
            return

        if path.startswith("/finalize/"):
            raw = await self._read_body(receive)
            await self._handle_finalize(send, raw, path, base_url, extra_headers)
            return

        if path.startswith("/order/"):
            _ = await self._read_body(receive)  # consume body
            await self._handle_order(send, path, base_url, extra_headers)
            return

        if path.startswith("/cert/"):
            await self._handle_cert(send, path, base_url, extra_headers)
            return

        if path == "/ca.pem":
            await self._handle_ca_cert(send, extra_headers)
            return

        if path == "/key-change":
            raw = await self._read_body(receive)
            await self._handle_key_change(send, raw, extra_headers)
            return

        if path == "/revoke-cert":
            _ = await self._read_body(receive)  # consume body
            await self._handle_revoke(send, extra_headers)
            return

        await self._send_error(send, status=404, body={"type": "not-found"}, headers=extra_headers)

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def _handle_directory(self, send: Send, base_url: str, headers: dict[str, str]) -> None:
        await self._send_json(
            send,
            status=200,
            body={
                "newNonce": f"{base_url}/new-nonce",
                "newAccount": f"{base_url}/new-account",
                "newOrder": f"{base_url}/new-order",
                "revokeCert": f"{base_url}/revoke-cert",
                "keyChange": f"{base_url}/key-change",
            },
            headers=headers,
        )

    async def _handle_new_account(
        self, send: Send, raw: bytes, base_url: str, headers: dict[str, str]
    ) -> None:
        body = self._parse_jws_body(raw)
        only_existing = body.get("onlyReturnExisting", False)

        protected = self._parse_jws_protected(raw)
        jwk = protected.get("jwk", {})
        from lacme.crypto import jwk_thumbprint

        thumbprint = jwk_thumbprint(jwk)

        with self._lock:
            existing_acct: _Account | None = None
            for acct in self._accounts.values():
                if acct.jwk_thumbprint == thumbprint:
                    existing_acct = acct
                    break

            if existing_acct is not None:
                resp_status = 200
                resp_body = {"status": existing_acct.status, "contact": existing_acct.contact}
                resp_headers = {**headers, "Location": existing_acct.url}
            elif only_existing:
                resp_status = 400
                resp_body = {
                    "type": "urn:ietf:params:acme:error:accountDoesNotExist",
                    "detail": "Account not found",
                }
                resp_headers = headers
            else:
                self._account_counter += 1
                url = f"{base_url}/acct/{self._account_counter}"
                acct = _Account(
                    url=url,
                    contact=body.get("contact", []),
                    jwk_thumbprint=thumbprint,
                )
                self._accounts[url] = acct
                resp_status = 201
                resp_body = {"status": "valid", "contact": acct.contact}
                resp_headers = {**headers, "Location": url}

        if resp_status >= 400:
            await self._send_error(send, status=resp_status, body=resp_body, headers=resp_headers)
        else:
            await self._send_json(send, status=resp_status, body=resp_body, headers=resp_headers)

    async def _handle_new_order(
        self, send: Send, raw: bytes, base_url: str, headers: dict[str, str]
    ) -> None:
        body = self._parse_jws_body(raw)
        identifiers = body.get("identifiers", [])
        domains = [i["value"] for i in identifiers]

        with self._lock:
            self._order_counter += 1
            order_url = f"{base_url}/order/{self._order_counter}"
            finalize_url = f"{base_url}/finalize/{self._order_counter}"

            authz_urls = []
            for ident in identifiers:
                self._authz_counter += 1
                authz_url = f"{base_url}/authz/{self._authz_counter}"
                chall_url = f"{base_url}/chall/{self._authz_counter}"
                token = b64url_encode(secrets.token_bytes(32))

                authz = _Authorization(
                    url=authz_url,
                    identifier_value=ident["value"],
                    identifier_type=ident.get("type", "dns"),
                    token=token,
                    challenge_url=chall_url,
                    dns_challenge_url=f"{chall_url}-dns",
                )
                self._authorizations[authz_url] = authz
                authz_urls.append(authz_url)

            order = _Order(
                url=order_url,
                domains=domains,
                authz_urls=authz_urls,
                finalize_url=finalize_url,
            )
            self._orders[order_url] = order

        await self._send_json(
            send,
            status=201,
            body={
                "status": "pending",
                "identifiers": identifiers,
                "authorizations": authz_urls,
                "finalize": finalize_url,
            },
            headers={**headers, "Location": order_url},
        )

    async def _handle_authz(
        self, send: Send, path: str, base_url: str, headers: dict[str, str]
    ) -> None:
        url = f"{base_url}{path}"
        with self._lock:
            authz = self._authorizations.get(url)
        if authz is None:
            await self._send_error(send, status=404, body={"type": "not-found"}, headers=headers)
            return

        await self._send_json(
            send,
            status=200,
            body={
                "status": authz.status,
                "identifier": {
                    "type": authz.identifier_type,
                    "value": authz.identifier_value,
                },
                "challenges": [
                    {
                        "type": "http-01",
                        "url": authz.challenge_url,
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                    {
                        "type": "dns-01",
                        "url": authz.dns_challenge_url,
                        "token": authz.token,
                        "status": authz.challenge_status,
                    },
                ],
            },
            headers=headers,
        )

    async def _handle_challenge(
        self,
        send: Send,
        raw: bytes,
        path: str,
        base_url: str,
        headers: dict[str, str],
    ) -> None:
        chall_url = f"{base_url}{path}"

        with self._lock:
            target_authz: _Authorization | None = None
            is_dns = False
            for authz in self._authorizations.values():
                if authz.challenge_url == chall_url:
                    target_authz = authz
                    break
                if authz.dns_challenge_url == chall_url:
                    target_authz = authz
                    is_dns = True
                    break

        if target_authz is None:
            await self._send_error(send, status=404, body={"type": "not-found"}, headers=headers)
            return

        if self._auto_approve:
            with self._lock:
                target_authz.challenge_status = "valid"
                target_authz.status = "valid"
        elif self._challenge_validator is not None:
            valid = await self._challenge_validator.validate(
                target_authz.identifier_value,
                target_authz.identifier_type,
                target_authz.token,
                target_authz.key_authorization,
            )
            with self._lock:
                if valid:
                    target_authz.challenge_status = "valid"
                    target_authz.status = "valid"
                else:
                    target_authz.challenge_status = "invalid"
                    target_authz.status = "invalid"
        else:
            with self._lock:
                target_authz.challenge_status = "processing"

        await self._send_json(
            send,
            status=200,
            body={
                "type": "dns-01" if is_dns else "http-01",
                "url": chall_url,
                "token": target_authz.token,
                "status": target_authz.challenge_status,
            },
            headers=headers,
        )

    async def _handle_finalize(
        self,
        send: Send,
        raw: bytes,
        path: str,
        base_url: str,
        headers: dict[str, str],
    ) -> None:
        order_num = path.split("/")[-1]
        order_url = f"{base_url}/order/{order_num}"

        with self._lock:
            order = self._orders.get(order_url)
        if order is None:
            await self._send_error(send, status=404, body={"type": "not-found"}, headers=headers)
            return

        # Transition order to "ready" if all authzs are valid, then verify status
        with self._lock:
            if order.status == "pending":
                all_valid = all(
                    (a := self._authorizations.get(aurl)) is not None and a.status == "valid"
                    for aurl in order.authz_urls
                )
                if all_valid:
                    order.status = "ready"
            order_ready = order.status == "ready"
        if not order_ready:
            await self._send_error(
                send,
                status=403,
                body={
                    "type": "urn:ietf:params:acme:error:orderNotReady",
                    "detail": "Order is not ready for finalization",
                },
                headers=headers,
            )
            return

        # Extract CSR from body
        body = self._parse_jws_body(raw)
        csr_b64 = body.get("csr", "")
        padded = csr_b64 + "=" * (-len(csr_b64) % 4)
        csr_der = base64.urlsafe_b64decode(padded)

        # Sign with the CA
        bundle = self._ca.issue_from_csr(csr_der)
        cert_pem = bundle.fullchain_pem.decode("ascii")

        with self._lock:
            self._cert_counter += 1
            cert_url = f"{base_url}/cert/{self._cert_counter}"
            self._certificates[cert_url] = cert_pem

            order.status = "valid"
            order.certificate_url = cert_url

        await self._send_json(
            send,
            status=200,
            body={
                "status": "valid",
                "identifiers": [{"type": "dns", "value": d} for d in order.domains],
                "authorizations": order.authz_urls,
                "finalize": order.finalize_url,
                "certificate": cert_url,
            },
            headers={**headers, "Location": order_url},
        )

    async def _handle_order(
        self, send: Send, path: str, base_url: str, headers: dict[str, str]
    ) -> None:
        url = f"{base_url}{path}"

        with self._lock:
            order = self._orders.get(url)
        if order is None:
            await self._send_error(send, status=404, body={"type": "not-found"}, headers=headers)
            return

        # Auto-transition: if all authzs are valid and order is pending -> ready
        with self._lock:
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

        await self._send_json(send, status=200, body=body, headers={**headers, "Location": url})

    async def _handle_cert(
        self, send: Send, path: str, base_url: str, headers: dict[str, str]
    ) -> None:
        url = f"{base_url}{path}"

        with self._lock:
            pem = self._certificates.get(url)
        if pem is None:
            await self._send_error(send, status=404, body={"type": "not-found"}, headers=headers)
            return

        raw = pem.encode("ascii")
        response_headers: list[list[bytes]] = [
            [b"content-type", b"application/pem-certificate-chain"],
            [b"content-length", str(len(raw)).encode()],
        ]
        for k, v in headers.items():
            response_headers.append([k.encode(), v.encode()])
        await send({"type": "http.response.start", "status": 200, "headers": response_headers})
        await send({"type": "http.response.body", "body": raw})

    async def _handle_key_change(self, send: Send, raw: bytes, headers: dict[str, str]) -> None:
        # Accept key change without verification (trusted internal network)
        await self._send_json(send, status=200, body={}, headers=headers)

    async def _handle_revoke(self, send: Send, headers: dict[str, str]) -> None:
        # Accept revocation without verification (trusted internal network)
        await self._send_json(send, status=200, body={}, headers=headers)

    async def _handle_ca_cert(self, send: Send, headers: dict[str, str]) -> None:
        """Serve the CA root certificate for client bootstrapping."""
        pem = self._ca.root_cert_pem
        response_headers: list[list[bytes]] = [
            [b"content-type", b"application/x-pem-file"],
            [b"content-length", str(len(pem)).encode()],
        ]
        for k, v in headers.items():
            response_headers.append([k.encode(), v.encode()])
        await send({"type": "http.response.start", "status": 200, "headers": response_headers})
        await send({"type": "http.response.body", "body": pem})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_base_url(self, scope: Scope) -> str:
        """Build the base URL from the ASGI scope."""
        scheme = scope.get("scheme", "https")
        server = scope.get("server")
        if server:
            host, port = server
            if (
                port is None
                or (scheme == "https" and port == 443)
                or (scheme == "http" and port == 80)
            ):
                base = f"{scheme}://{host}"
            else:
                base = f"{scheme}://{host}:{port}"
        else:
            base = "https://localhost"
        root_path = scope.get("root_path", "")
        return f"{base}{root_path}"

    def _next_nonce(self) -> str:
        with self._lock:
            self._nonce_counter += 1
            counter = self._nonce_counter
        return b64url_encode(f"nonce-{counter}".encode())

    _MAX_BODY_SIZE = 64 * 1024  # 64 KiB — sufficient for ACME JWS payloads

    async def _read_body(self, receive: Receive) -> bytes:
        """Read the full request body from ASGI receive."""
        body = bytearray()
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            if chunk:
                body.extend(chunk)
            if len(body) > self._MAX_BODY_SIZE:
                msg = "Request body too large"
                raise ValueError(msg)
            if not message.get("more_body", False):
                break
        return bytes(body)

    async def _send_json(
        self,
        send: Send,
        *,
        status: int,
        body: dict[str, Any],
        headers: dict[str, str],
        content_type: bytes = b"application/json",
    ) -> None:
        """Send a JSON response via ASGI send."""
        raw = json.dumps(body).encode()
        response_headers: list[list[bytes]] = [
            [b"content-type", content_type],
            [b"content-length", str(len(raw)).encode()],
        ]
        for k, v in headers.items():
            response_headers.append([k.encode(), v.encode()])
        await send({"type": "http.response.start", "status": status, "headers": response_headers})
        await send({"type": "http.response.body", "body": raw})

    async def _send_error(
        self,
        send: Send,
        *,
        status: int,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> None:
        """Send an RFC 7807 problem+json error response."""
        await self._send_json(
            send,
            status=status,
            body=body,
            headers=headers,
            content_type=b"application/problem+json",
        )

    @staticmethod
    def _parse_jws_body(raw: bytes) -> dict[str, Any]:
        """Extract the payload from a JWS POST body."""
        data = json.loads(raw)
        payload_b64 = data.get("payload", "")
        if not payload_b64:
            return {}
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        if not decoded:
            return {}
        return json.loads(decoded)  # type: ignore[no-any-return]

    @staticmethod
    def _parse_jws_protected(raw: bytes) -> dict[str, Any]:
        """Extract the protected header from a JWS POST body."""
        data = json.loads(raw)
        protected_b64 = data.get("protected", "")
        padded = protected_b64 + "=" * (-len(protected_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)  # type: ignore[no-any-return]
