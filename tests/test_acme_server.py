"""Tests for lacme.acme_server — ACMEResponder ASGI app."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any
from unittest.mock import ANY, AsyncMock, call

import httpx2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    DNSName,
    IPAddress,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import NameOID

from lacme.acme_server import ACMEResponder, ChallengeValidator
from lacme.ca import CertificateAuthority
from lacme.challenges.http01 import HTTP01Handler
from lacme.client import Client
from lacme.crypto import b64url_encode, generate_csr, generate_ec_key
from lacme.errors import BadCSRError
from lacme.events import CertificateIssued, EventDispatcher
from lacme.models import IdentifierType
from lacme.ratelimit import MemoryRateLimitStore, RateLimitTracker
from lacme.store import MemoryStore


@pytest.fixture
def ca() -> CertificateAuthority:
    ca = CertificateAuthority(store=MemoryStore())
    ca.init()
    return ca


@pytest.fixture
def responder(ca: CertificateAuthority) -> ACMEResponder:
    return ACMEResponder(ca=ca, auto_approve=True)


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _jws_content(payload: Any) -> bytes:
    return json.dumps(
        {
            "protected": b64url_encode(b"{}"),
            "payload": b64url_encode(json.dumps(payload).encode()),
            "signature": "",
        }
    ).encode()


def _post_as_get_content() -> bytes:
    return json.dumps(
        {
            "protected": b64url_encode(b"{}"),
            "payload": "",
            "signature": "",
        }
    ).encode()


def _invalid_json_jws_contents() -> list[tuple[str, bytes]]:
    payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
    envelope = json.loads(_jws_content(payload))

    protected_utf16 = {**envelope, "protected": b64url_encode("{}".encode("utf-16"))}
    payload_utf16 = {
        **envelope,
        "payload": b64url_encode(json.dumps(payload).encode("utf-16")),
    }
    payload_nan = {
        **envelope,
        "payload": b64url_encode(
            b'{"identifiers":[{"type":"dns","value":"example.com"}],"invalid":NaN}'
        ),
    }
    outer_nan = json.dumps(envelope)[:-1] + ',"invalid":NaN}'
    return [
        ("outer UTF-16", json.dumps(envelope).encode("utf-16")),
        ("protected UTF-16", json.dumps(protected_utf16).encode()),
        ("payload UTF-16", json.dumps(payload_utf16).encode()),
        ("payload NaN", json.dumps(payload_nan).encode()),
        ("outer NaN", outer_nan.encode()),
    ]


# ---------------------------------------------------------------------------
# Directory endpoint
# ---------------------------------------------------------------------------


class TestDirectoryEndpoint:
    @pytest.mark.anyio
    async def test_directory_returns_urls(self, responder: ACMEResponder) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http:
            resp = await http.get("/directory")

        assert resp.status_code == 200
        data = resp.json()
        assert "newNonce" in data
        assert "newAccount" in data
        assert "newOrder" in data
        assert "revokeCert" in data
        assert "keyChange" in data
        # URLs should be absolute
        for key in ("newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"):
            assert data[key].startswith("https://")

    @pytest.mark.anyio
    async def test_external_url_overrides_request_address(self, ca: CertificateAuthority) -> None:
        responder = ACMEResponder(
            ca=ca,
            auto_approve=True,
            external_url="https://public.example:9443/acme/",
        )
        transport = httpx2.ASGITransport(app=responder, root_path="/acme")  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://172.18.0.13:8090",
        ) as http:
            resp = await http.get(
                "/acme/directory",
                headers={
                    "Host": "request.example:8443",
                    "X-Forwarded-Host": "forwarded.example:443",
                    "X-Forwarded-Proto": "http",
                },
            )

        assert resp.status_code == 200
        assert resp.json() == {
            "newNonce": "https://public.example:9443/acme/new-nonce",
            "newAccount": "https://public.example:9443/acme/new-account",
            "newOrder": "https://public.example:9443/acme/new-order",
            "revokeCert": "https://public.example:9443/acme/revoke-cert",
            "keyChange": "https://public.example:9443/acme/key-change",
        }


@pytest.mark.parametrize(
    ("external_url", "normalized"),
    [
        ("http://localhost", "http://localhost"),
        ("https://ca_service:8443/acme-v1", "https://ca_service:8443/acme-v1"),
        ("https://[2001:db8::1]:8443/acme/", "https://[2001:db8::1]:8443/acme"),
        ("https://ca.example/acme%20service", "https://ca.example/acme%20service"),
        ("https://ca.example/acm%C3%A9", "https://ca.example/acm%C3%A9"),
        ("https://xn--caf-dma.example/acme", "https://xn--caf-dma.example/acme"),
        ("http://192.168.0.239:8090/acme", "http://192.168.0.239:8090/acme"),
        ("http://100.64.0.1/acme", "http://100.64.0.1/acme"),
        (
            "http://[64:ff9b::a9fe:a9fe]/acme",
            "http://[64:ff9b::a9fe:a9fe]/acme",
        ),
    ],
)
def test_external_url_accepts_supported_uri_forms(
    ca: CertificateAuthority,
    external_url: str,
    normalized: str,
) -> None:
    responder = ACMEResponder(ca=ca, external_url=external_url)

    assert responder._get_base_url({}) == normalized


@pytest.mark.parametrize(
    "external_url",
    [
        "",
        "ca.example/acme",
        "ftp://ca.example/acme",
        "https://user:secret@ca.example/acme",
        "https://ca.example/acme?tenant=one",
        "https://ca.example/acme?",
        "https://ca.example/acme#section",
        "https://ca.example/acme#",
        " https://ca.example/acme",
        "https://ca.example/not a path",
        "\x00https://ca.example/acme",
        "https://ca.example/\x01acme",
        "https://ca.example/acme\x7f",
        "https://ca.example:not-a-port/acme",
        "https://ca.example/acme/./inside",
        "https://ca.example/acme/../outside",
        "https://ca.example/acme/%2e/inside",
        "https://ca.example/acme/%2E%2E/outside",
        "https://ca.example/acme/%2e%2e%2foutside",
        "https://ca.example/acme%2foutside",
        "https://ca.example/acme%5coutside",
        "https://ca.example/acme%00outside",
        "https://ca.example/acme/%",
        "https://ca.example/acme/%2",
        "https://ca.example/acme/%GG",
        "https://ca.example/acme%FF",
        "https://ca.example/acme%C3%28",
        "https://ca.example/acme%ED%A0%80",
        "https://café.example/acme",
        "https://ca.example/acmé",
        "https://ca.example/\ud800",
        "https://ca.example\\acme",
        "https://ca.example/{acme}",
        "https://{ca}.example/acme",
        "https://[v1.foo]/acme",
        "https://999.999.999.999/acme",
        "https://001.002.003.004/acme",
    ],
)
def test_external_url_rejects_invalid_values(ca: CertificateAuthority, external_url: str) -> None:
    with pytest.raises(ValueError, match="external_url"):
        ACMEResponder(ca=ca, external_url=external_url)


# ---------------------------------------------------------------------------
# Nonce endpoint
# ---------------------------------------------------------------------------


class TestNonceEndpoint:
    @pytest.mark.anyio
    async def test_nonce_returns_replay_nonce_header(self, responder: ACMEResponder) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http:
            resp = await http.head("/new-nonce")

        assert resp.status_code == 200
        assert "replay-nonce" in resp.headers


# ---------------------------------------------------------------------------
# Full issue flow
# ---------------------------------------------------------------------------


class TestFullIssueFlow:
    @pytest.mark.anyio
    async def test_full_issue_flow(
        self,
        responder: ACMEResponder,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        handler = HTTP01Handler()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["example.com"])

        assert bundle.domain == "example.com"
        assert bundle.domains == ("example.com",)
        assert bundle.cert_pem
        assert bundle.fullchain_pem
        assert bundle.key_pem

        # Verify the cert is valid PEM signed by the CA
        certs = load_pem_x509_certificates(bundle.fullchain_pem)
        assert len(certs) >= 2  # leaf + CA root
        leaf = certs[0]
        cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "example.com"

    @pytest.mark.anyio
    async def test_full_issue_flow_uses_external_url(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        responder = ACMEResponder(
            ca=ca,
            auto_approve=True,
            external_url="https://public.example:9443/acme",
        )
        request_hosts: list[str] = []

        async def record_requests(scope, receive, send):
            headers = dict(scope.get("headers", []))
            request_hosts.append(headers[b"host"].decode("ascii"))
            proxied_scope = dict(scope)
            proxied_scope["scheme"] = "http"
            proxied_scope["server"] = ("172.18.0.13", 8090)
            await responder(proxied_scope, receive, send)

        transport = httpx2.ASGITransport(
            app=record_requests,
            root_path="/acme",
        )
        handler = HTTP01Handler()

        async with (
            httpx2.AsyncClient(
                transport=transport,
                base_url="http://172.18.0.13:8090",
            ) as http,
            Client(  # noqa: SIM117
                directory_url="http://172.18.0.13:8090/acme/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
                allow_insecure=True,
            ) as client,
        ):
            bundle = await client.issue(["external.example"])

        assert bundle.domain == "external.example"
        assert bundle.cert_pem
        assert request_hosts[0] == "172.18.0.13:8090"
        assert request_hosts[1:]
        assert set(request_hosts[1:]) == {"public.example:9443"}

    @pytest.mark.anyio
    async def test_multi_domain_issue(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        handler = HTTP01Handler()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["a.com", "b.com"])

        assert bundle.domains == ("a.com", "b.com")

        # Verify both domains appear in the leaf cert SANs
        from cryptography.x509 import DNSName, SubjectAlternativeName

        certs = load_pem_x509_certificates(bundle.fullchain_pem)
        leaf = certs[0]
        san_ext = leaf.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(DNSName)
        assert "a.com" in dns_names
        assert "b.com" in dns_names


# ---------------------------------------------------------------------------
# Account creation
# ---------------------------------------------------------------------------


class TestAccountCreate:
    @pytest.mark.anyio
    async def test_create_account(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
            ) as client,
        ):
            account = await client.create_account(contact=["mailto:test@example.com"])

        assert account.status == "valid"
        assert account.url
        assert account.url.startswith("https://")


# ---------------------------------------------------------------------------
# Auto-approve mode
# ---------------------------------------------------------------------------


class TestAutoApprove:
    @pytest.mark.anyio
    async def test_auto_approve_mode(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """With auto_approve=True, challenges immediately become valid."""
        responder = ACMEResponder(ca=ca, auto_approve=True)
        handler = HTTP01Handler()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            # If auto_approve weren't working, this would time out
            bundle = await client.issue(["auto.example.com"])

        assert bundle.domain == "auto.example.com"


# ---------------------------------------------------------------------------
# Custom challenge validator
# ---------------------------------------------------------------------------


class TestChallengeValidator:
    @pytest.mark.anyio
    async def test_custom_validator_called(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """A custom validator returning True allows the issue flow to succeed."""
        calls: list[tuple[str, str, str, str]] = []

        class RecordingValidator:
            async def validate(
                self, identifier: str, identifier_type: str, token: str, key_authorization: str
            ) -> bool:
                calls.append((identifier, identifier_type, token, key_authorization))
                return True

        validator = RecordingValidator()
        assert isinstance(validator, ChallengeValidator)

        responder = ACMEResponder(ca=ca, challenge_validator=validator)
        handler = HTTP01Handler()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["validated.example.com"])

        assert bundle.domain == "validated.example.com"
        assert len(calls) == 1
        assert calls[0][0] == "validated.example.com"
        assert calls[0][1] == "dns"


# ---------------------------------------------------------------------------
# IP identifier
# ---------------------------------------------------------------------------


class TestIPIdentifier:
    @pytest.mark.anyio
    async def test_responder_preserves_ip_identifiers_through_order_lifecycle(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """Every responder order representation retains RFC 8738 identifier types."""
        from lacme import crypto

        identifier_values = [
            ipaddress.IPv4Address("192.0.2.10"),
            ipaddress.IPv6Address("2001:0db8::1"),
        ]
        expected = [
            (IdentifierType.IP, "192.0.2.10"),
            (IdentifierType.IP, "2001:db8::1"),
        ]
        responder = ACMEResponder(ca=ca, auto_approve=True)
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            await client.create_account()
            order = await client.create_order(identifier_values)
            assert [(i.type, i.value) for i in order.identifiers] == expected

            authzs = await client.get_authorizations(order)
            assert [(authz.identifier.type, authz.identifier.value) for authz in authzs] == expected
            for authz in authzs:
                chall = authz.find_challenge("http-01")
                assert chall is not None
                assert authz.find_challenge("dns-01") is None
                await client.respond_to_challenge(chall)
                await client.poll_authorization(authz.url)

            order = await client._poll_order_ready(order.url)
            assert [(i.type, i.value) for i in order.identifiers] == expected

            cert_key = crypto.generate_ec_key()
            csr_der = crypto.generate_csr(cert_key, identifier_values)
            order = await client.finalize_order(order, csr_der)
            assert [(i.type, i.value) for i in order.identifiers] == expected
            assert order.certificate is not None
            fullchain_pem_str = await client.download_certificate(order.certificate)

        certs = load_pem_x509_certificates(fullchain_pem_str.encode("ascii"))
        leaf = certs[0]
        san_ext = leaf.extensions.get_extension_for_class(SubjectAlternativeName)
        assert san_ext.value.get_values_for_type(IPAddress) == identifier_values

    @pytest.mark.anyio
    async def test_client_issue_mixed_dns_and_ip_identifiers(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """High-level issuance keeps typed internals and string-facing public metadata."""
        handler = AsyncMock()
        handler.provision = AsyncMock()
        handler.deprovision = AsyncMock()
        store = MemoryStore()
        dispatcher = EventDispatcher()
        issued_events: list[CertificateIssued] = []
        dispatcher.subscribe(issued_events.append, event_type=CertificateIssued)
        registered_domain_calls: list[str] = []

        def registered_domain(value: str) -> str:
            registered_domain_calls.append(value)
            return value

        tracker = RateLimitTracker(
            MemoryRateLimitStore(),
            registered_domain_func=registered_domain,
        )
        responder = ACMEResponder(ca=ca, auto_approve=True)
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        identifier_values = [ipaddress.IPv4Address("192.0.2.10"), "node.internal"]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                store=store,
                event_dispatcher=dispatcher,
                rate_limit_tracker=tracker,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(identifier_values)

        assert bundle.domain == "192.0.2.10"
        assert bundle.domains == ("192.0.2.10", "node.internal")
        assert store.load_cert("192.0.2.10") == bundle
        assert [(event.domain, event.domains) for event in issued_events] == [
            ("192.0.2.10", ("192.0.2.10", "node.internal"))
        ]
        handler.provision.assert_has_awaits(
            [
                call("192.0.2.10", ANY, ANY),
                call("node.internal", ANY, ANY),
            ]
        )
        handler.deprovision.assert_has_awaits(
            [
                call("192.0.2.10", ANY),
                call("node.internal", ANY),
            ]
        )
        assert registered_domain_calls == ["node.internal", "node.internal"]

        leaf = load_pem_x509_certificates(bundle.fullchain_pem)[0]
        sans = leaf.extensions.get_extension_for_class(SubjectAlternativeName).value
        assert sans.get_values_for_type(IPAddress) == [ipaddress.IPv4Address("192.0.2.10")]
        assert sans.get_values_for_type(DNSName) == ["node.internal"]


class TestProtocolIdentifierValidation:
    @pytest.mark.anyio
    @pytest.mark.skipif(
        sys.version_info[:2] != (3, 11),
        reason="This compact input reaches the recursion limit on CPython 3.11 only",
    )
    async def test_deep_json_returns_malformed_without_state(
        self,
        responder: ACMEResponder,
    ) -> None:
        envelope = json.loads(
            _jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]})
        )
        nested_extension = "[" * 1100 + "0" + "]" * 1100
        content = (json.dumps(envelope)[:-1] + f',"extension":{nested_extension}}}').encode()
        assert len(content) < responder._MAX_BODY_SIZE

        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-order", content=content)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._orders == {}
        assert responder._authorizations == {}

    @pytest.mark.anyio
    @pytest.mark.parametrize(("case", "content"), _invalid_json_jws_contents())
    async def test_new_order_rejects_non_utf8_or_nonstandard_json_without_state(
        self,
        responder: ACMEResponder,
        case: str,
        content: bytes,
    ) -> None:
        del case
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-order", content=content)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._orders == {}
        assert responder._authorizations == {}

    @pytest.mark.anyio
    async def test_new_account_rejects_literal_empty_payload_without_state(
        self,
        responder: ACMEResponder,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-account", content=_post_as_get_content())

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._accounts == {}

    @pytest.mark.anyio
    async def test_challenge_rejects_literal_empty_payload_before_validation(
        self,
        responder: ACMEResponder,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            created = await http.post(
                "/new-order",
                content=_jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]}),
            )
            authorization = responder._authorizations[created.json()["authorizations"][0]]

            rejected = await http.post(
                authorization.challenge_url,
                content=_post_as_get_content(),
            )

            assert rejected.status_code == 400
            assert rejected.json()["type"].endswith(":malformed")
            assert authorization.status == "pending"
            assert authorization.challenge_status == "pending"

            acknowledged = await http.post(
                authorization.challenge_url,
                content=_jws_content({}),
            )

        assert acknowledged.status_code == 200
        assert authorization.status == "valid"
        assert authorization.challenge_status == "valid"

    @pytest.mark.anyio
    async def test_new_account_rejects_missing_jwk_without_state(
        self,
        responder: ACMEResponder,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-account", content=_jws_content({}))

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._accounts == {}

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("payload", "error"),
        [
            ({}, "malformed"),
            ({"identifiers": []}, "malformed"),
            ({"identifiers": [{}]}, "malformed"),
            ({"identifiers": [{"type": "dns", "value": 42}]}, "malformed"),
            ({"identifiers": [{"type": "dns", "value": "bad..example"}]}, "malformed"),
            ({"identifiers": [{"type": "dns", "value": "xn--"}]}, "malformed"),
            ({"identifiers": [{"type": "dns", "value": "foo.*.example"}]}, "malformed"),
            ({"identifiers": [{"type": "ip", "value": "fe80::1%eth0"}]}, "malformed"),
            (
                {"identifiers": [{"type": "email", "value": "admin@example.com"}]},
                "unsupportedIdentifier",
            ),
        ],
    )
    async def test_new_order_rejects_invalid_identifiers_without_state(
        self,
        responder: ACMEResponder,
        payload: Any,
        error: str,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-order", content=_jws_content(payload))

        assert response.status_code == 400
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["type"] == f"urn:ietf:params:acme:error:{error}"
        assert responder._orders == {}
        assert responder._authorizations == {}

    @pytest.mark.anyio
    async def test_finalize_binds_typed_set_and_accepts_reordering(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        handler = AsyncMock()
        ip_value = ipaddress.IPv4Address("198.51.100.8")
        ordered_values = ["192.0.2.44", ip_value]
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            await client.create_account()
            order = await client.create_order(ordered_values)
            for authorization in await client.get_authorizations(order):
                challenge = authorization.find_challenge("http-01")
                assert challenge is not None
                await client.respond_to_challenge(challenge)
                await client.poll_authorization(authorization.url)
            order = await client._poll_order_ready(order.url)

            wrong_type_csr = generate_csr(
                generate_ec_key(),
                [ipaddress.IPv4Address("192.0.2.44"), ip_value],
            )
            with pytest.raises(BadCSRError):
                await client.finalize_order(order, wrong_type_csr)

            retained = await client._poll_order_ready(order.url)
            assert retained.status == "ready"

            padded_csr = _jws_content(
                {"csr": f"{b64url_encode(generate_csr(generate_ec_key(), ordered_values))}="}
            )
            padded_response = await http.post(order.finalize, content=padded_csr)
            assert padded_response.status_code == 400
            assert padded_response.json()["type"].endswith(":badCSR")
            retained = await client._poll_order_ready(order.url)
            assert retained.status == "ready"

            differing_cn_key = generate_ec_key()
            differing_cn_csr = (
                CertificateSigningRequestBuilder()
                .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, "different.example")]))
                .add_extension(
                    SubjectAlternativeName(
                        [DNSName("192.0.2.44"), IPAddress(ip_value)],
                    ),
                    critical=False,
                )
                .sign(differing_cn_key, hashes.SHA256())
                .public_bytes(serialization.Encoding.DER)
            )
            with pytest.raises(BadCSRError, match="identifiers do not match"):
                await client.finalize_order(retained, differing_cn_csr)

            retained = await client._poll_order_ready(order.url)
            assert retained.status == "ready"

            reordered_csr = generate_csr(generate_ec_key(), [ip_value, "192.0.2.44"])
            finalized = await client.finalize_order(retained, reordered_csr)
            assert finalized.status == "valid"

    @pytest.mark.anyio
    @pytest.mark.parametrize("shape", ["cn-only", "dns-cn-ip-san"])
    async def test_finalize_accepts_dns_identifiers_from_common_name(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
        shape: str,
    ) -> None:
        dns_value = "cn.example"
        ip_value = ipaddress.IPv4Address("192.0.2.55")
        requested = [dns_value] if shape == "cn-only" else [dns_value, ip_value]
        key = generate_ec_key()
        builder = CertificateSigningRequestBuilder().subject_name(
            Name([NameAttribute(NameOID.COMMON_NAME, dns_value)])
        )
        if shape == "dns-cn-ip-san":
            builder = builder.add_extension(
                SubjectAlternativeName([IPAddress(ip_value)]),
                critical=False,
            )
        csr_der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=AsyncMock(),
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            await client.create_account()
            order = await client.create_order(requested)
            for authz in await client.get_authorizations(order):
                challenge = authz.find_challenge("http-01")
                assert challenge is not None
                await client.respond_to_challenge(challenge)
            order = await client._poll_order_ready(order.url)
            finalized = await client.finalize_order(order, csr_der)
            assert finalized.certificate is not None
            chain = await client.download_certificate(finalized.certificate)

        leaf = load_pem_x509_certificates(chain.encode("ascii"))[0]
        sans = leaf.extensions.get_extension_for_class(SubjectAlternativeName).value
        assert sans.get_values_for_type(DNSName) == [dns_value]
        expected_ips = [] if shape == "cn-only" else [ip_value]
        assert sans.get_values_for_type(IPAddress) == expected_ips

    @pytest.mark.anyio
    async def test_finalize_uses_order_types_for_same_text_dns_and_ip(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        text_value = "192.0.2.77"
        ip_value = ipaddress.IPv4Address(text_value)
        key = generate_ec_key()
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, text_value)]))
            .add_extension(SubjectAlternativeName([IPAddress(ip_value)]), critical=False)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=AsyncMock(),
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            await client.create_account()
            order = await client.create_order([text_value, ip_value])
            for authz in await client.get_authorizations(order):
                challenge = authz.find_challenge("http-01")
                assert challenge is not None
                await client.respond_to_challenge(challenge)
            order = await client._poll_order_ready(order.url)
            finalized = await client.finalize_order(order, csr)
            chain = await client.download_certificate(finalized.certificate or "")

        sans = (
            load_pem_x509_certificates(chain.encode("ascii"))[0]
            .extensions.get_extension_for_class(SubjectAlternativeName)
            .value
        )
        assert sans.get_values_for_type(DNSName) == [text_value]
        assert sans.get_values_for_type(IPAddress) == [ip_value]

    @pytest.mark.anyio
    @pytest.mark.parametrize("field", ["protected", "payload", "signature"])
    async def test_rejects_noncanonical_outer_jws_before_state_mutation(
        self,
        responder: ACMEResponder,
        field: str,
    ) -> None:
        envelope = json.loads(
            _jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]})
        )
        envelope[field] += "="
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-order", json=envelope)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._orders == {}
        assert responder._authorizations == {}

    @pytest.mark.anyio
    @pytest.mark.parametrize("forbidden_member", ["header", "signatures"])
    async def test_rejects_forbidden_jws_serialization_members_before_state_mutation(
        self,
        responder: ACMEResponder,
        forbidden_member: str,
    ) -> None:
        envelope = json.loads(
            _jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]})
        )
        envelope[forbidden_member] = {} if forbidden_member == "header" else []
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            response = await http.post("/new-order", json=envelope)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert responder._orders == {}

    @pytest.mark.anyio
    @pytest.mark.parametrize("payload", [{}, {"unexpected": True}])
    async def test_post_as_get_requires_literal_empty_payload_without_transition(
        self,
        responder: ACMEResponder,
        payload: dict[str, Any],
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            created = await http.post(
                "/new-order",
                content=_jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]}),
            )
            order = created.json()
            responder._authorizations[order["authorizations"][0]].status = "valid"

            for path in ("/authz/1", "/order/1", "/cert/999"):
                response = await http.post(path, content=_jws_content(payload))
                assert response.status_code == 400
                assert response.json()["type"].endswith(":malformed")

        assert responder._orders[created.headers["location"]].status == "pending"

    @pytest.mark.anyio
    async def test_order_with_missing_authorization_stays_pending(
        self,
        responder: ACMEResponder,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            created = await http.post(
                "/new-order",
                content=_jws_content({"identifiers": [{"type": "dns", "value": "example.com"}]}),
            )
            order = created.json()
            del responder._authorizations[order["authorizations"][0]]

            response = await http.post("/order/1", content=_post_as_get_content())

        assert response.status_code == 200
        assert response.json()["status"] == "pending"


class TestWildcardAuthorization:
    @pytest.mark.anyio
    async def test_responder_projects_wildcard_authorization_and_hides_http01(
        self,
        responder: ACMEResponder,
    ) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="https://acme.test",
        ) as http:
            order_response = await http.post(
                "/new-order",
                content=_jws_content({"identifiers": [{"type": "dns", "value": "*.Example.COM"}]}),
            )
            assert order_response.status_code == 201
            order_data = order_response.json()
            assert order_data["identifiers"] == [{"type": "dns", "value": "*.Example.COM"}]

            authz_response = await http.post(
                order_data["authorizations"][0],
                content=_post_as_get_content(),
            )
            authz_data = authz_response.json()
            assert authz_data["identifier"] == {"type": "dns", "value": "Example.COM"}
            assert authz_data["wildcard"] is True
            assert [challenge["type"] for challenge in authz_data["challenges"]] == ["dns-01"]

            hidden_http = await http.post("/chall/1", content=_jws_content({}))
            assert hidden_http.status_code == 404
            assert responder._authorizations[order_data["authorizations"][0]].status == "pending"

    @pytest.mark.anyio
    async def test_client_issues_apex_and_wildcard_using_requested_presentations(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        handler = AsyncMock()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(
                ["Example.COM", "*.Example.COM"],
                challenge_type="dns-01",
            )

        assert bundle.domains == ("Example.COM", "*.Example.COM")
        handler.provision.assert_has_awaits(
            [call("Example.COM", ANY, ANY), call("*.Example.COM", ANY, ANY)]
        )
        handler.deprovision.assert_has_awaits(
            [call("Example.COM", ANY), call("*.Example.COM", ANY)]
        )


# ---------------------------------------------------------------------------
# Cert signed by CA
# ---------------------------------------------------------------------------


class TestCertSignedByCA:
    @pytest.mark.anyio
    async def test_issued_cert_signed_by_ca(
        self,
        responder: ACMEResponder,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """The issued cert's issuer should match the CA root subject."""
        handler = HTTP01Handler()
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(["signed.example.com"])

        # Parse leaf cert and CA root cert
        leaf_certs = load_pem_x509_certificates(bundle.fullchain_pem)
        leaf = leaf_certs[0]

        root_certs = load_pem_x509_certificates(ca.root_cert_pem)
        root = root_certs[0]

        # The leaf's issuer should match the root's subject
        assert leaf.issuer == root.subject


# ---------------------------------------------------------------------------
# Order auto-transition
# ---------------------------------------------------------------------------


class TestOrderAutoTransition:
    @pytest.mark.anyio
    async def test_order_transitions_to_ready(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """After all challenges are validated, polling the order returns 'ready'."""
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            await client.create_account()
            order = await client.create_order("ready.example.com")

            # Solve challenges
            authzs = await client.get_authorizations(order)
            for authz in authzs:
                chall = authz.find_challenge("http-01")
                assert chall is not None
                await client.respond_to_challenge(chall)
                await client.poll_authorization(authz.url)

            # Poll the order -- should transition from pending to ready
            order = await client._poll_order_ready(order.url)
            assert order.status == "ready"


# ---------------------------------------------------------------------------
# Non-ACME path returns 404
# ---------------------------------------------------------------------------


class TestResponderAsMiddleware:
    @pytest.mark.anyio
    async def test_non_acme_path_returns_404(self, responder: ACMEResponder) -> None:
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http:
            resp = await http.get("/unknown")

        assert resp.status_code == 404
        data = resp.json()
        assert data["type"] == "not-found"


# ---------------------------------------------------------------------------
# CA cert endpoint
# ---------------------------------------------------------------------------


class TestCACertEndpoint:
    @pytest.mark.anyio
    async def test_ca_cert_endpoint(
        self, responder: ACMEResponder, ca: CertificateAuthority
    ) -> None:
        """GET /ca.pem returns the CA root certificate as application/x-pem-file."""
        transport = httpx2.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http:
            resp = await http.get("/ca.pem")

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/x-pem-file"

        # The response body should be valid PEM parseable as a certificate
        pem_data = resp.content
        certs = load_pem_x509_certificates(pem_data)
        assert len(certs) == 1

        # It should match the CA's root cert
        assert pem_data == ca.root_cert_pem
