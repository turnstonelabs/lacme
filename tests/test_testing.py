"""Tests for lacme.testing — MockACMEServer."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import Any
from unittest.mock import ANY, AsyncMock

import httpx2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509 import (
    BasicConstraints,
    CertificateSigningRequestBuilder,
    DNSName,
    IPAddress,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import NameOID

from lacme.crypto import b64url_encode, generate_csr, generate_ec_key
from lacme.errors import BadCSRError
from lacme.testing import MockACMEServer


@pytest.fixture
def server() -> MockACMEServer:
    return MockACMEServer()


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# Full issue flow
# ---------------------------------------------------------------------------


class TestMockServerFullFlow:
    @pytest.mark.anyio
    async def test_full_issue_flow(self, server: MockACMEServer, account_key):
        """End-to-end: issue a certificate through MockACMEServer."""
        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

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

        chain = load_pem_x509_certificates(bundle.fullchain_pem)
        assert len(chain) == 2
        leaf, root = chain
        leaf.verify_directly_issued_by(root)
        root.verify_directly_issued_by(root)
        assert root.extensions.get_extension_for_class(BasicConstraints).value.ca is True
        private_key = load_pem_private_key(bundle.key_pem, password=None)
        assert leaf.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        ) == private_key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    @pytest.mark.anyio
    async def test_multi_domain_issue(self, server: MockACMEServer, account_key):
        """Issue a certificate for multiple domains."""
        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

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
            bundle = await client.issue(["example.com", "www.example.com"])

        assert bundle.domains == ("example.com", "www.example.com")

    @pytest.mark.anyio
    async def test_mixed_challenge_types(self, server: MockACMEServer, account_key):
        """Issue with per-domain challenge type overrides via challenge_map."""
        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        http_handler = HTTP01Handler()
        dns_handler = HTTP01Handler()  # use HTTP01Handler as mock for both
        transport = server.as_transport()

        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=http_handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(
                ["example.com", "api.example.com"],
                challenge_map={
                    "api.example.com": ("dns-01", dns_handler),
                },
            )

        assert bundle.domains == ("example.com", "api.example.com")

    @pytest.mark.anyio
    async def test_mock_reuses_one_root_across_issuances(
        self,
        server: MockACMEServer,
        account_key,
    ) -> None:
        from lacme.client import Client

        handler = AsyncMock()
        async with (
            httpx2.AsyncClient(transport=server.as_transport()) as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            first = await client.issue("one.example")
            second = await client.issue("two.example")

        first_root = load_pem_x509_certificates(first.fullchain_pem)[1]
        second_root = load_pem_x509_certificates(second.fullchain_pem)[1]
        assert first_root == second_root

    @pytest.mark.anyio
    async def test_challenge_map_distinguishes_same_text_dns_and_ip(
        self,
        server: MockACMEServer,
        account_key,
    ) -> None:
        from lacme.client import Client

        dns_value = "192.0.2.10"
        ip_value = ipaddress.IPv4Address(dns_value)
        dns_handler = AsyncMock()
        ip_handler = AsyncMock()

        async with (
            httpx2.AsyncClient(transport=server.as_transport()) as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue(
                [dns_value, ip_value],
                challenge_map={
                    dns_value: ("dns-01", dns_handler),
                    ip_value: ("http-01", ip_handler),
                },
            )

        assert bundle.domains == (dns_value, dns_value)
        dns_handler.provision.assert_awaited_once_with(dns_value, ANY, ANY)
        ip_handler.provision.assert_awaited_once_with(dns_value, ANY, ANY)


def _jws_request(path: str, payload: Any) -> httpx2.Request:
    encoded_payload = b64url_encode(json.dumps(payload).encode())
    return httpx2.Request(
        "POST",
        f"https://acme.test{path}",
        content=json.dumps(
            {"protected": b64url_encode(b"{}"), "payload": encoded_payload, "signature": ""}
        ).encode(),
    )


def _post_as_get_request(path: str) -> httpx2.Request:
    return httpx2.Request(
        "POST",
        f"https://acme.test{path}",
        content=json.dumps(
            {"protected": b64url_encode(b"{}"), "payload": "", "signature": ""}
        ).encode(),
    )


def _invalid_json_jws_requests() -> list[tuple[str, httpx2.Request]]:
    payload = {"identifiers": [{"type": "dns", "value": "example.com"}]}
    envelope = json.loads(_jws_request("/new-order", payload).content)

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
    contents = [
        ("outer UTF-16", json.dumps(envelope).encode("utf-16")),
        ("protected UTF-16", json.dumps(protected_utf16).encode()),
        ("payload UTF-16", json.dumps(payload_utf16).encode()),
        ("payload NaN", json.dumps(payload_nan).encode()),
        ("outer NaN", outer_nan.encode()),
    ]
    return [
        (case, httpx2.Request("POST", "https://acme.test/new-order", content=content))
        for case, content in contents
    ]


class TestMockProtocolValidation:
    @pytest.mark.skipif(
        sys.version_info[:2] != (3, 11),
        reason="This compact input reaches the recursion limit on CPython 3.11 only",
    )
    def test_deep_json_returns_malformed_without_state(
        self,
        server: MockACMEServer,
    ) -> None:
        envelope = json.loads(
            _jws_request(
                "/new-order",
                {"identifiers": [{"type": "dns", "value": "example.com"}]},
            ).content
        )
        nested_extension = "[" * 1100 + "0" + "]" * 1100
        content = (json.dumps(envelope)[:-1] + f',"extension":{nested_extension}}}').encode()
        assert len(content) < 64 * 1024

        response = server.as_transport().handle_request(
            httpx2.Request("POST", "https://acme.test/new-order", content=content)
        )

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._orders == {}
        assert server._authorizations == {}

    @pytest.mark.parametrize(("case", "wire_request"), _invalid_json_jws_requests())
    def test_new_order_rejects_non_utf8_or_nonstandard_json_without_state(
        self,
        server: MockACMEServer,
        case: str,
        wire_request: httpx2.Request,
    ) -> None:
        del case
        response = server.as_transport().handle_request(wire_request)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._orders == {}
        assert server._authorizations == {}

    def test_new_account_rejects_literal_empty_payload_without_state(
        self,
        server: MockACMEServer,
    ) -> None:
        response = server.as_transport().handle_request(_post_as_get_request("/new-account"))

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._accounts == {}

    def test_challenge_rejects_literal_empty_payload_before_validation(
        self,
        server: MockACMEServer,
    ) -> None:
        transport = server.as_transport()
        created = transport.handle_request(
            _jws_request(
                "/new-order",
                {"identifiers": [{"type": "dns", "value": "example.com"}]},
            )
        )
        authorization = server._authorizations[created.json()["authorizations"][0]]

        rejected = transport.handle_request(
            _post_as_get_request(authorization.challenge_url.removeprefix(server._base_url))
        )

        assert rejected.status_code == 400
        assert rejected.json()["type"].endswith(":malformed")
        assert authorization.status == "pending"
        assert authorization.challenge_status == "pending"

        acknowledged = transport.handle_request(
            _jws_request(
                authorization.challenge_url.removeprefix(server._base_url),
                {},
            )
        )

        assert acknowledged.status_code == 200
        assert authorization.status == "valid"
        assert authorization.challenge_status == "valid"

    def test_new_account_rejects_missing_jwk_without_state(
        self,
        server: MockACMEServer,
    ) -> None:
        response = server.as_transport().handle_request(_jws_request("/new-account", {}))

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._accounts == {}

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
            ({"identifiers": [{"type": "ip", "value": "2001:0db8::1"}]}, "malformed"),
            (
                {"identifiers": [{"type": "email", "value": "admin@example.com"}]},
                "unsupportedIdentifier",
            ),
        ],
    )
    def test_new_order_rejects_invalid_identifiers_without_state(
        self,
        server: MockACMEServer,
        payload: Any,
        error: str,
    ) -> None:
        response = server.as_transport().handle_request(_jws_request("/new-order", payload))

        assert response.status_code == 400
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["type"] == f"urn:ietf:params:acme:error:{error}"
        assert server._orders == {}
        assert server._authorizations == {}

    @pytest.mark.anyio
    async def test_finalize_rejects_same_text_with_wrong_identifier_type(
        self,
        server: MockACMEServer,
        account_key,
    ) -> None:
        from lacme.client import Client

        handler = AsyncMock()
        async with (
            httpx2.AsyncClient(transport=server.as_transport()) as http,
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
            order = await client.create_order("192.0.2.44")
            for authorization in await client.get_authorizations(order):
                challenge = authorization.find_challenge("http-01")
                assert challenge is not None
                await client.respond_to_challenge(challenge)
                await client.poll_authorization(authorization.url)
            order = await client._poll_order_ready(order.url)

            wrong_csr = generate_csr(
                generate_ec_key(),
                [ipaddress.IPv4Address("192.0.2.44")],
            )
            with pytest.raises(BadCSRError):
                await client.finalize_order(order, wrong_csr)

            retained = await client._poll_order_ready(order.url)
            assert retained.status == "ready"

            correct_csr = generate_csr(generate_ec_key(), ["192.0.2.44"])
            padded_request = _jws_request(
                "/unused",
                {"csr": f"{b64url_encode(correct_csr)}="},
            )
            padded_response = await http.post(order.finalize, content=padded_request.content)
            assert padded_response.status_code == 400
            assert padded_response.json()["type"].endswith(":badCSR")

            retained = await client._poll_order_ready(order.url)
            assert retained.status == "ready"
            finalized = await client.finalize_order(retained, correct_csr)
            assert finalized.status == "valid"

    @pytest.mark.anyio
    async def test_finalize_issues_dns_from_cn_with_ip_san(
        self,
        server: MockACMEServer,
        account_key,
    ) -> None:
        from lacme.client import Client

        dns_value = "cn.example"
        ip_value = ipaddress.IPv4Address("192.0.2.66")
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, dns_value)]))
            .add_extension(SubjectAlternativeName([IPAddress(ip_value)]), critical=False)
            .sign(generate_ec_key(), hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )
        async with (
            httpx2.AsyncClient(transport=server.as_transport()) as http,
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
            order = await client.create_order([dns_value, ip_value])
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
        assert sans.get_values_for_type(DNSName) == [dns_value]
        assert sans.get_values_for_type(IPAddress) == [ip_value]

    @pytest.mark.parametrize("field", ["protected", "payload", "signature"])
    def test_rejects_noncanonical_outer_jws_before_state_mutation(
        self,
        server: MockACMEServer,
        field: str,
    ) -> None:
        request = _jws_request(
            "/new-order",
            {"identifiers": [{"type": "dns", "value": "example.com"}]},
        )
        envelope = json.loads(request.content)
        envelope[field] += "="
        invalid_request = httpx2.Request(
            "POST",
            request.url,
            content=json.dumps(envelope).encode(),
        )

        response = server.as_transport().handle_request(invalid_request)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._orders == {}
        assert server._authorizations == {}

    @pytest.mark.parametrize("forbidden_member", ["header", "signatures"])
    def test_rejects_forbidden_jws_serialization_members_before_state_mutation(
        self,
        server: MockACMEServer,
        forbidden_member: str,
    ) -> None:
        request = _jws_request(
            "/new-order",
            {"identifiers": [{"type": "dns", "value": "example.com"}]},
        )
        envelope = json.loads(request.content)
        envelope[forbidden_member] = {} if forbidden_member == "header" else []
        invalid = httpx2.Request("POST", request.url, json=envelope)

        response = server.as_transport().handle_request(invalid)

        assert response.status_code == 400
        assert response.json()["type"].endswith(":malformed")
        assert server._orders == {}

    @pytest.mark.parametrize("payload", [{}, {"unexpected": True}])
    def test_post_as_get_requires_literal_empty_payload_without_transition(
        self,
        server: MockACMEServer,
        payload: dict[str, Any],
    ) -> None:
        transport = server.as_transport()
        created = transport.handle_request(
            _jws_request(
                "/new-order",
                {"identifiers": [{"type": "dns", "value": "example.com"}]},
            )
        )
        order = created.json()
        server._authorizations[order["authorizations"][0]].status = "valid"

        for path in ("/authz/1", "/order/1", "/cert/999"):
            response = transport.handle_request(_jws_request(path, payload))
            assert response.status_code == 400
            assert response.json()["type"].endswith(":malformed")

        assert server._orders[created.headers["location"]].status == "pending"

    def test_order_with_missing_authorization_stays_pending(
        self,
        server: MockACMEServer,
    ) -> None:
        transport = server.as_transport()
        created = transport.handle_request(
            _jws_request(
                "/new-order",
                {"identifiers": [{"type": "dns", "value": "example.com"}]},
            )
        )
        order = created.json()
        del server._authorizations[order["authorizations"][0]]

        response = transport.handle_request(_post_as_get_request("/order/1"))

        assert response.status_code == 200
        assert response.json()["status"] == "pending"


class TestMockWildcardAuthorization:
    def test_projects_wildcard_and_rejects_hidden_http_challenge(
        self,
        server: MockACMEServer,
    ) -> None:
        transport = server.as_transport()
        order_response = transport.handle_request(
            _jws_request(
                "/new-order",
                {"identifiers": [{"type": "dns", "value": "*.Example.COM"}]},
            )
        )
        order_data = order_response.json()
        authz_url = order_data["authorizations"][0]
        authz_response = transport.handle_request(
            _post_as_get_request(authz_url.removeprefix(server._base_url))
        )
        authz_data = authz_response.json()

        assert order_data["identifiers"] == [{"type": "dns", "value": "*.Example.COM"}]
        assert authz_data["identifier"] == {"type": "dns", "value": "Example.COM"}
        assert authz_data["wildcard"] is True
        assert [challenge["type"] for challenge in authz_data["challenges"]] == ["dns-01"]

        hidden_url = f"{server._base_url}/chall/1"
        hidden_response = transport.handle_request(_jws_request("/chall/1", {}))
        assert hidden_response.status_code == 404
        assert server._authorizations[authz_url].status == "pending"
        with pytest.raises(ValueError, match="No challenge"):
            server.validate_challenge(hidden_url)

    @pytest.mark.anyio
    async def test_client_issues_wildcard_through_mock(
        self,
        server: MockACMEServer,
        account_key,
    ) -> None:
        from lacme.client import Client

        handler = AsyncMock()
        async with (
            httpx2.AsyncClient(transport=server.as_transport()) as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
                challenge_handler=handler,
                poll_interval=0.01,
                poll_timeout=5.0,
            ) as client,
        ):
            bundle = await client.issue("*.Example.COM", challenge_type="dns-01")

        assert bundle.domains == ("*.Example.COM",)
        handler.provision.assert_awaited_once_with("*.Example.COM", ANY, ANY)
        handler.deprovision.assert_awaited_once_with("*.Example.COM", ANY)


# ---------------------------------------------------------------------------
# Account operations
# ---------------------------------------------------------------------------


class TestMockAccountCreate:
    @pytest.mark.anyio
    async def test_create_account(self, server: MockACMEServer, account_key):
        import httpx2

        from lacme.client import Client

        transport = server.as_transport()
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

    @pytest.mark.anyio
    async def test_find_existing_account(self, server: MockACMEServer, account_key):
        import httpx2

        from lacme.client import Client

        transport = server.as_transport()
        async with (
            httpx2.AsyncClient(transport=transport, base_url="https://acme.test") as http,
            Client(  # noqa: SIM117
                directory_url="https://acme.test/directory",
                http_client=http,
                account_key=account_key,
            ) as client,
        ):
            acct1 = await client.create_account()
            acct2 = await client.create_account(only_return_existing=True)

        assert acct1.url == acct2.url


# ---------------------------------------------------------------------------
# Challenge validation
# ---------------------------------------------------------------------------


class TestMockAutoValidate:
    @pytest.mark.anyio
    async def test_auto_validate(self, account_key):
        """With auto_validate=True, challenges immediately become valid."""
        server = MockACMEServer(auto_validate=True)

        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

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
            bundle = await client.issue(["auto.example.com"])

        assert bundle.domain == "auto.example.com"


class TestMockManualValidate:
    def test_manual_validate(self):
        """With auto_validate=False, challenges stay in processing."""
        server = MockACMEServer(auto_validate=False)

        # Create an order to get a challenge
        import httpx2

        transport = server.as_transport()

        # Simulate creating an order
        req = httpx2.Request(
            "POST",
            "https://acme.test/new-order",
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZXhhbXBsZS5jb20ifV19","signature":""}',
        )
        resp = transport.handle_request(req)
        assert resp.status_code == 201

        order_data = json.loads(resp.content)
        authz_url = order_data["authorizations"][0]

        # Get authz and respond to challenge
        req2 = httpx2.Request(
            "POST",
            authz_url,
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"","signature":""}',
        )
        resp2 = transport.handle_request(req2)
        authz_data = json.loads(resp2.content)
        assert authz_data["status"] == "pending"

        # Respond to challenge
        chall_url = authz_data["challenges"][0]["url"]
        req3 = httpx2.Request(
            "POST",
            chall_url,
            content=b'{"protected":"eyJhbGciOiJFUzI1NiJ9","payload":"e30","signature":""}',
        )
        resp3 = transport.handle_request(req3)
        chall_data = json.loads(resp3.content)
        assert chall_data["status"] == "processing"

        # Manually validate
        server.validate_challenge(chall_url)

        # Now authz should be valid
        resp4 = transport.handle_request(req2)
        authz_data2 = json.loads(resp4.content)
        assert authz_data2["status"] == "valid"


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestMockRevocation:
    @pytest.mark.anyio
    async def test_revoke(self, server: MockACMEServer, account_key):
        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

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
            bundle = await client.issue(["revoke.example.com"])
            await client.revoke(bundle.cert_pem)


# ---------------------------------------------------------------------------
# Certificate validity
# ---------------------------------------------------------------------------


class TestMockCertParseable:
    @pytest.mark.anyio
    async def test_cert_is_valid_pem(self, server: MockACMEServer, account_key):
        """The generated certificate should be parseable."""
        import httpx2

        from lacme.challenges.http01 import HTTP01Handler
        from lacme.client import Client

        handler = HTTP01Handler()
        transport = server.as_transport()

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
            bundle = await client.issue(["cert.example.com"])

        certs = load_pem_x509_certificates(bundle.fullchain_pem)
        assert len(certs) >= 1
        assert certs[0].subject.rfc4514_string().startswith("CN=cert.example.com")


# ---------------------------------------------------------------------------
# Transport helper
# ---------------------------------------------------------------------------


class TestAsTransport:
    def test_returns_mock_transport(self, server: MockACMEServer):
        import httpx2

        transport = server.as_transport()
        assert isinstance(transport, httpx2.MockTransport)
