"""Tests for lacme.acme_server — ACMEResponder ASGI app."""

from __future__ import annotations

import httpx
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http:
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


# ---------------------------------------------------------------------------
# Nonce endpoint
# ---------------------------------------------------------------------------


class TestNonceEndpoint:
    @pytest.mark.anyio
    async def test_nonce_returns_replay_nonce_header(self, responder: ACMEResponder) -> None:
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http:
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
    async def test_multi_domain_issue(
        self,
        responder: ACMEResponder,
        account_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        handler = HTTP01Handler()
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]

        async with (
            httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http:
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
        transport = httpx.ASGITransport(app=responder)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http:
            resp = await http.get("/ca.pem")

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/x-pem-file"

        # The response body should be valid PEM parseable as a certificate
        pem_data = resp.content
        certs = load_pem_x509_certificates(pem_data)
        assert len(certs) == 1

        # It should match the CA's root cert
        assert pem_data == ca.root_cert_pem
