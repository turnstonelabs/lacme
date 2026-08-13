"""Tests for lacme.acme_server — ACMEResponder ASGI app."""

from __future__ import annotations

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificates
from cryptography.x509.oid import NameOID

from lacme.acme_server import ACMEResponder, ChallengeValidator
from lacme.ca import CertificateAuthority
from lacme.challenges.http01 import HTTP01Handler
from lacme.client import Client
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
    async def test_ip_identifier(
        self,
        ca: CertificateAuthority,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        """Issue a cert for an IP address using create_order at a lower level."""
        from lacme import crypto

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
            # Manually drive the flow using create_order with an IP identifier.
            # Client.create_order currently uses IdentifierType.DNS for domain strings,
            # so we use it with a string and rely on the CA to handle it.
            await client.create_account()
            order = await client.create_order("192.168.1.1")

            # Authorize
            authzs = await client.get_authorizations(order)
            for authz in authzs:
                chall = authz.find_challenge("http-01")
                assert chall is not None
                await client.respond_to_challenge(chall)
                await client.poll_authorization(authz.url)

            # Wait for order to be ready
            order = await client._poll_order_ready(order.url)

            # Finalize with a CSR that includes the IP as a DNS SAN
            # (The CA's issue_from_csr extracts SANs from the CSR)
            cert_key = crypto.generate_ec_key()
            csr_der = crypto.generate_csr(cert_key, ["192.168.1.1"])
            order = await client.finalize_order(order, csr_der)

            if order.status != "valid":
                order = await client.poll_order(order.url)

            assert order.certificate is not None
            fullchain_pem_str = await client.download_certificate(order.certificate)

        # Parse the issued cert and verify the SAN contains the IP value.
        # The CSR used a DNS SAN for "192.168.1.1" (since generate_csr treats
        # plain strings as DNS names), so the CA extracts it as a DNSName.
        from cryptography.x509 import DNSName, SubjectAlternativeName

        certs = load_pem_x509_certificates(fullchain_pem_str.encode("ascii"))
        leaf = certs[0]
        san_ext = leaf.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(DNSName)
        assert "192.168.1.1" in dns_names


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
