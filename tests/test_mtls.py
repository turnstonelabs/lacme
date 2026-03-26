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


# ---------------------------------------------------------------------------
# PEM file helpers
# ---------------------------------------------------------------------------


class TestPemPaths:
    def test_write_pem_files(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """write_pem_files creates cert and key files with correct contents."""
        from lacme.mtls import write_pem_files

        bundle = ca.issue("pem.test")
        paths = write_pem_files(bundle, directory=tmp_path)

        assert paths.cert.exists()
        assert paths.key.exists()
        assert paths.ca is None
        assert paths.cert.read_bytes() == bundle.fullchain_pem
        assert paths.key.read_bytes() == bundle.key_pem

    def test_write_pem_files_with_ca(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """When ca_pem is provided, the ca path exists with correct data."""
        from lacme.mtls import write_pem_files

        bundle = ca.issue("pem-ca.test")
        paths = write_pem_files(bundle, ca_pem=ca.root_cert_pem, directory=tmp_path)

        assert paths.ca is not None
        assert paths.ca.exists()
        assert paths.ca.read_bytes() == ca.root_cert_pem

    def test_write_pem_files_permissions(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """Key file should be 0o600, cert file should be 0o644."""
        import sys

        from lacme.mtls import write_pem_files

        if sys.platform == "win32":
            pytest.skip("POSIX permissions not available on Windows")

        bundle = ca.issue("pem-perms.test")
        paths = write_pem_files(bundle, directory=tmp_path)

        assert oct(paths.key.stat().st_mode & 0o777) == oct(0o600)
        assert oct(paths.cert.stat().st_mode & 0o777) == oct(0o644)

    def test_pem_files_context_manager(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """Files exist inside the context manager, deleted after exit."""
        from lacme.mtls import pem_files

        bundle = ca.issue("pem-ctx.test")

        with pem_files(bundle, ca_pem=ca.root_cert_pem, directory=tmp_path) as paths:
            assert paths.cert.exists()
            assert paths.key.exists()
            assert paths.ca is not None
            assert paths.ca.exists()
            parent_dir = paths.cert.parent

        # After exiting the context, the temp directory should be cleaned up
        assert not parent_dir.exists()

    def test_as_uvicorn_kwargs(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """as_uvicorn_kwargs returns dict with correct keys."""
        from lacme.mtls import write_pem_files

        bundle = ca.issue("pem-uvi.test")
        paths = write_pem_files(bundle, ca_pem=ca.root_cert_pem, directory=tmp_path)

        kwargs = paths.as_uvicorn_kwargs()
        assert "ssl_certfile" in kwargs
        assert "ssl_keyfile" in kwargs
        assert "ssl_ca_certs" in kwargs
        assert kwargs["ssl_certfile"] == str(paths.cert)
        assert kwargs["ssl_keyfile"] == str(paths.key)
        assert kwargs["ssl_ca_certs"] == str(paths.ca)

    def test_write_pem_files_persistent(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        """write_pem_files_persistent creates files that exist after the call."""
        from lacme.mtls import write_pem_files_persistent

        bundle = ca.issue("pem-persist.test")
        paths = write_pem_files_persistent(bundle, ca_pem=ca.root_cert_pem, directory=tmp_path)

        assert paths.cert.exists()
        assert paths.key.exists()
        assert paths.ca is not None
        assert paths.ca.exists()
        assert paths.cert.read_bytes() == bundle.fullchain_pem
        assert paths.key.read_bytes() == bundle.key_pem
        assert paths.ca.read_bytes() == ca.root_cert_pem
