"""Tests for lacme.mtls — mTLS SSL context helpers."""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

import pytest

from lacme.ca import CertificateAuthority
from lacme.mtls import client_ssl_context, server_ssl_context
from lacme.store import MemoryStore

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def ca():
    """Create a CA with root cert for testing."""
    store = MemoryStore()
    ca = CertificateAuthority(store)
    ca.init(cn="Test mTLS CA")
    return ca


# ---------------------------------------------------------------------------
# Server SSL context
# ---------------------------------------------------------------------------


class TestServerSSLContext:
    def test_basic_server_context(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("server.test")
        ctx = server_ssl_context(cert_pem=bundle.cert_pem, key_pem=bundle.key_pem)
        assert isinstance(ctx, ssl.SSLContext)

    def test_server_requires_client_cert(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("server.test")
        ctx = server_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca.root_cert_pem,
        )
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_server_no_client_auth(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("server.test")
        ctx = server_ssl_context(cert_pem=bundle.cert_pem, key_pem=bundle.key_pem)
        assert ctx.verify_mode != ssl.CERT_REQUIRED

    def test_server_tls_minimum_version(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("server.test")
        ctx = server_ssl_context(cert_pem=bundle.cert_pem, key_pem=bundle.key_pem)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_server_with_file_paths(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        bundle = ca.issue("server.test")
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(bundle.cert_pem)
        key_file.write_bytes(bundle.key_pem)

        ctx = server_ssl_context(cert_pem=cert_file, key_pem=key_file)
        assert isinstance(ctx, ssl.SSLContext)

    def test_server_with_str_paths(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        bundle = ca.issue("server.test")
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        cert_file.write_bytes(bundle.cert_pem)
        key_file.write_bytes(bundle.key_pem)

        ctx = server_ssl_context(cert_pem=str(cert_file), key_pem=str(key_file))
        assert isinstance(ctx, ssl.SSLContext)


# ---------------------------------------------------------------------------
# Client SSL context
# ---------------------------------------------------------------------------


class TestClientSSLContext:
    def test_basic_client_context(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("client.test", client=True)
        ctx = client_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca.root_cert_pem,
        )
        assert isinstance(ctx, ssl.SSLContext)

    def test_client_without_cert(self, ca: CertificateAuthority) -> None:
        ctx = client_ssl_context(ca_cert_pem=ca.root_cert_pem)
        assert isinstance(ctx, ssl.SSLContext)

    def test_client_tls_minimum_version(self, ca: CertificateAuthority) -> None:
        ctx = client_ssl_context(ca_cert_pem=ca.root_cert_pem)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_client_with_pem_bytes(self, ca: CertificateAuthority) -> None:
        bundle = ca.issue("client.test", client=True)
        ctx = client_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca.root_cert_pem,
        )
        assert isinstance(ctx, ssl.SSLContext)
