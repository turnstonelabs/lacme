"""Tests for lacme.ca — CertificateAuthority."""

from __future__ import annotations

import datetime
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

import pytest
from cryptography.x509 import (
    BasicConstraints,
    ExtendedKeyUsage,
    KeyUsage,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lacme.ca import CertificateAuthority
from lacme.crypto import generate_csr, generate_ec_key
from lacme.errors import CertificateAuthorityError
from lacme.events import (
    CACertificateIssued,
    CertificateAuthorityInitialized,
    EventDispatcher,
)
from lacme.store import FileStore, MemoryStore

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# TestCAInit
# ---------------------------------------------------------------------------


class TestCAInit:
    def test_init_generates_root(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        assert ca.initialized is True
        certs = load_pem_x509_certificates(ca.root_cert_pem)
        assert len(certs) == 1

    def test_init_root_has_basic_constraints_ca_true(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        cert = load_pem_x509_certificates(ca.root_cert_pem)[0]
        bc = cert.extensions.get_extension_for_class(BasicConstraints).value
        assert bc.ca is True

    def test_init_root_has_key_usage(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        cert = load_pem_x509_certificates(ca.root_cert_pem)[0]
        ku = cert.extensions.get_extension_for_class(KeyUsage).value
        assert ku.key_cert_sign is True
        assert ku.crl_sign is True

    def test_init_root_has_subject_key_identifier(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        cert = load_pem_x509_certificates(ca.root_cert_pem)[0]
        ski = cert.extensions.get_extension_for_class(SubjectKeyIdentifier)
        assert ski.value.digest is not None
        assert len(ski.value.digest) > 0

    def test_init_custom_cn(self) -> None:
        ca = CertificateAuthority()
        ca.init(cn="My CA")
        cert = load_pem_x509_certificates(ca.root_cert_pem)[0]
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "My CA"

    def test_init_custom_validity(self) -> None:
        ca = CertificateAuthority()
        ca.init(validity_days=365)
        cert = load_pem_x509_certificates(ca.root_cert_pem)[0]
        now = datetime.datetime.now(datetime.UTC)
        expected = now + datetime.timedelta(days=365)
        # Allow 30 seconds tolerance for test execution time.
        delta = abs((cert.not_valid_after_utc - expected).total_seconds())
        assert delta < 30

    def test_init_idempotent_with_store(self) -> None:
        store = MemoryStore()
        ca1 = CertificateAuthority(store=store)
        ca1.init()
        root_pem_first = ca1.root_cert_pem

        ca2 = CertificateAuthority(store=store)
        ca2.init()
        assert ca2.root_cert_pem == root_pem_first

    def test_init_in_memory(self) -> None:
        ca = CertificateAuthority(store=None)
        ca.init()
        assert ca.initialized is True
        assert ca.root_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")


# ---------------------------------------------------------------------------
# TestCAIssueServer
# ---------------------------------------------------------------------------


class TestCAIssueServer:
    def test_issue_server_cert(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        assert bundle.cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert bundle.key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert bundle.domain == "api.internal"

    def test_issue_server_cert_has_san(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        from cryptography.x509 import DNSName

        dns_names = san.get_values_for_type(DNSName)
        assert "api.internal" in dns_names

    def test_issue_server_cert_has_server_auth_eku(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        eku = cert.extensions.get_extension_for_class(ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    def test_issue_server_cert_not_ca(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        bc = cert.extensions.get_extension_for_class(BasicConstraints).value
        assert bc.ca is False

    def test_issue_server_cert_signed_by_root(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        leaf = load_pem_x509_certificates(bundle.cert_pem)[0]
        root = load_pem_x509_certificates(ca.root_cert_pem)[0]
        assert leaf.issuer == root.subject

    def test_issue_multi_san(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue(["a.internal", "b.internal"])
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        from cryptography.x509 import DNSName

        dns_names = san.get_values_for_type(DNSName)
        assert "a.internal" in dns_names
        assert "b.internal" in dns_names

    def test_issue_ip_san(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue([IPv4Address("10.0.1.5")])
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        from cryptography.x509 import IPAddress

        ip_addrs = san.get_values_for_type(IPAddress)
        assert IPv4Address("10.0.1.5") in ip_addrs

    def test_issue_fullchain_contains_root(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("api.internal")
        certs = load_pem_x509_certificates(bundle.fullchain_pem)
        assert len(certs) == 2
        # First cert is the leaf, second is the root.
        root = load_pem_x509_certificates(ca.root_cert_pem)[0]
        assert certs[1] == root


# ---------------------------------------------------------------------------
# TestCAIssueClient
# ---------------------------------------------------------------------------


class TestCAIssueClient:
    def test_issue_client_cert(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("worker-1", client=True)
        assert bundle.domain == "worker-1"
        assert bundle.cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_issue_client_cert_has_client_auth_eku(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("worker-1", client=True)
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        eku = cert.extensions.get_extension_for_class(ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku


# ---------------------------------------------------------------------------
# TestCAIssueFromCSR
# ---------------------------------------------------------------------------


class TestCAIssueFromCSR:
    def test_issue_from_csr(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        key = generate_ec_key()
        csr_der = generate_csr(key, ["csr.internal"])
        bundle = ca.issue_from_csr(csr_der)
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        root = load_pem_x509_certificates(ca.root_cert_pem)[0]
        assert cert.issuer == root.subject

    def test_issue_from_csr_preserves_sans(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        key = generate_ec_key()
        csr_der = generate_csr(key, ["a.internal", "b.internal"])
        bundle = ca.issue_from_csr(csr_der)
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        from cryptography.x509 import DNSName

        dns_names = san.get_values_for_type(DNSName)
        assert "a.internal" in dns_names
        assert "b.internal" in dns_names

    def test_issue_from_csr_empty_key_pem(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        key = generate_ec_key()
        csr_der = generate_csr(key, ["csr.internal"])
        bundle = ca.issue_from_csr(csr_der)
        assert bundle.key_pem == b""


# ---------------------------------------------------------------------------
# TestCAValidity
# ---------------------------------------------------------------------------


class TestCAValidity:
    def test_default_validity_24h(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("short.internal")
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        duration = cert.not_valid_after_utc - cert.not_valid_before_utc
        # Default is 1 day = 24 hours. Allow 30s tolerance.
        assert abs(duration.total_seconds() - 86400) < 30

    def test_custom_validity_hours(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        bundle = ca.issue("short.internal", validity_hours=6)
        cert = load_pem_x509_certificates(bundle.cert_pem)[0]
        duration = cert.not_valid_after_utc - cert.not_valid_before_utc
        # 6 hours = 21600 seconds. Allow 30s tolerance.
        assert abs(duration.total_seconds() - 21600) < 30


# ---------------------------------------------------------------------------
# TestCAStorage
# ---------------------------------------------------------------------------


class TestCAStorage:
    def test_issue_saves_to_store(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        ca = CertificateAuthority(store=store)
        ca.init()
        ca.issue("saved.internal")
        cert_dir = tmp_path / "certs" / "saved.internal"
        assert (cert_dir / "cert.pem").exists()
        assert (cert_dir / "fullchain.pem").exists()
        assert (cert_dir / "key.pem").exists()

    def test_init_persists_root(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        ca = CertificateAuthority(store=store)
        ca.init()
        ca_dir = tmp_path / "ca" / "root"
        assert (ca_dir / "cert.pem").exists()
        assert (ca_dir / "key.pem").exists()

    def test_init_loads_existing_root(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        ca1 = CertificateAuthority(store=store)
        ca1.init()
        root_pem_first = ca1.root_cert_pem

        ca2 = CertificateAuthority(store=store)
        ca2.init()
        assert ca2.root_cert_pem == root_pem_first


# ---------------------------------------------------------------------------
# TestCAErrors
# ---------------------------------------------------------------------------


class TestCAErrors:
    def test_issue_before_init_raises(self) -> None:
        ca = CertificateAuthority()
        with pytest.raises(CertificateAuthorityError, match="not initialized"):
            ca.issue("x")

    def test_issue_empty_names_raises(self) -> None:
        ca = CertificateAuthority()
        ca.init()
        with pytest.raises(CertificateAuthorityError, match="At least one name"):
            ca.issue([])


# ---------------------------------------------------------------------------
# TestCAEvents
# ---------------------------------------------------------------------------


class TestCAEvents:
    def test_init_emits_event(self) -> None:
        dispatcher = EventDispatcher()
        received: list[CertificateAuthorityInitialized] = []
        dispatcher.subscribe(received.append, event_type=CertificateAuthorityInitialized)

        ca = CertificateAuthority(event_dispatcher=dispatcher)
        ca.init(cn="Test CA")

        assert len(received) == 1
        assert received[0].cn == "Test CA"
        assert isinstance(received[0].expires_at, datetime.datetime)

    def test_issue_emits_event(self) -> None:
        dispatcher = EventDispatcher()
        received: list[CACertificateIssued] = []
        dispatcher.subscribe(received.append, event_type=CACertificateIssued)

        ca = CertificateAuthority(event_dispatcher=dispatcher)
        ca.init()
        ca.issue("event.internal")

        assert len(received) == 1
        assert received[0].name == "event.internal"
        assert received[0].names == ("event.internal",)
        assert received[0].is_client is False
