"""Tests for lacme.store — FileStore and MemoryStore."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lacme.store import FileStore, MemoryStore, Store

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from lacme._types import CertBundle


# ---------------------------------------------------------------------------
# FileStore
# ---------------------------------------------------------------------------


class TestFileStore:
    def test_save_load_account_key_roundtrip(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        key = ec.generate_private_key(ec.SECP256R1())
        store.save_account_key(key)
        loaded = store.load_account_key()
        assert loaded is not None
        assert loaded.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ) == key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def test_load_account_key_returns_none_when_missing(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        assert store.load_account_key() is None

    def test_save_cert_creates_files(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle()
        result = store.save_cert(bundle)
        assert result.cert_path is not None
        assert result.cert_path.exists()
        assert result.fullchain_path is not None
        assert result.fullchain_path.exists()
        assert result.key_path is not None
        assert result.key_path.exists()

    def test_save_load_cert_roundtrip(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle()
        store.save_cert(bundle)
        loaded = store.load_cert(bundle.domain)
        assert loaded is not None
        assert loaded.cert_pem == bundle.cert_pem
        assert loaded.key_pem == bundle.key_pem
        assert loaded.domains == bundle.domains

    def test_load_cert_returns_none_when_missing(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        assert store.load_cert("nonexistent.com") is None

    def test_list_certs(self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]) -> None:
        store = FileStore(tmp_path)
        store.save_cert(make_test_bundle("a.example.com"))
        store.save_cert(make_test_bundle("b.example.com"))
        certs = store.list_certs()
        assert len(certs) == 2
        domains = {c.domain for c in certs}
        assert domains == {"a.example.com", "b.example.com"}

    def test_list_certs_empty(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        assert store.list_certs() == []

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_account_key_permissions(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        key = ec.generate_private_key(ec.SECP256R1())
        store.save_account_key(key)
        path = tmp_path / "account.key"
        assert oct(path.stat().st_mode & 0o777) == oct(0o600)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_cert_file_permissions(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        result = store.save_cert(make_test_bundle())
        assert result.key_path is not None
        assert oct(result.key_path.stat().st_mode & 0o777) == oct(0o600)
        assert result.cert_path is not None
        assert oct(result.cert_path.stat().st_mode & 0o777) == oct(0o644)


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


class TestMemoryStore:
    def test_save_load_account_key_roundtrip(self) -> None:
        store = MemoryStore()
        key = ec.generate_private_key(ec.SECP256R1())
        store.save_account_key(key)
        assert store.load_account_key() is key

    def test_load_account_key_returns_none_when_missing(self) -> None:
        store = MemoryStore()
        assert store.load_account_key() is None

    def test_save_load_cert_roundtrip(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        store = MemoryStore()
        bundle = make_test_bundle()
        store.save_cert(bundle)
        loaded = store.load_cert(bundle.domain)
        assert loaded is bundle

    def test_list_certs(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        store = MemoryStore()
        store.save_cert(make_test_bundle("a.example.com"))
        assert len(store.list_certs()) == 1

    def test_load_cert_returns_none_when_missing(self) -> None:
        store = MemoryStore()
        assert store.load_cert("missing.com") is None


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestStoreProtocol:
    def test_filestore_is_store(self, tmp_path: Path) -> None:
        assert isinstance(FileStore(tmp_path), Store)

    def test_memorystore_is_store(self) -> None:
        assert isinstance(MemoryStore(), Store)


# ---------------------------------------------------------------------------
# CertBundle / CertMeta
# ---------------------------------------------------------------------------


class TestCertMeta:
    def test_to_dict_roundtrip(self) -> None:
        from lacme._types import CertMeta

        meta = CertMeta(
            domain="example.com",
            domains=("example.com", "www.example.com"),
            issued_at="2024-01-01T00:00:00+00:00",
            expires_at="2024-04-01T00:00:00+00:00",
        )
        d = meta.to_dict()
        assert d["domain"] == "example.com"
        assert d["domains"] == ["example.com", "www.example.com"]
        restored = CertMeta.from_dict(d)
        assert restored == meta

    def test_from_dict(self) -> None:
        from lacme._types import CertMeta

        data = {
            "domain": "test.com",
            "domains": ["test.com"],
            "issued_at": "2024-06-01T12:00:00+00:00",
            "expires_at": "2024-09-01T12:00:00+00:00",
        }
        meta = CertMeta.from_dict(data)
        assert meta.domain == "test.com"
        assert meta.domains == ("test.com",)


class TestCertBundle:
    def test_cert_bundle_frozen(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        bundle = make_test_bundle()
        with pytest.raises(AttributeError):
            bundle.domain = "other.com"  # type: ignore[misc]

    def test_cert_bundle_paths_default_none(
        self, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        bundle = make_test_bundle()
        assert bundle.cert_path is None
        assert bundle.fullchain_path is None
        assert bundle.key_path is None


# ---------------------------------------------------------------------------
# FileStore corrupted files
# ---------------------------------------------------------------------------


class TestFileStoreCorruptedFiles:
    def test_load_cert_missing_cert_pem(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        """If meta.json exists but cert.pem is missing, load_cert raises."""
        store = FileStore(tmp_path)
        bundle = make_test_bundle()
        store.save_cert(bundle)
        (tmp_path / "certs" / bundle.domain / "cert.pem").unlink()
        with pytest.raises(FileNotFoundError):
            store.load_cert(bundle.domain)


# ---------------------------------------------------------------------------
# Path traversal prevention
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_save_cert_path_traversal_rejected(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        from dataclasses import replace

        store = FileStore(tmp_path)
        bundle = replace(make_test_bundle(), domain="../../../tmp/evil")
        with pytest.raises(ValueError, match="Invalid domain name"):
            store.save_cert(bundle)

    def test_load_cert_path_traversal_rejected(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(ValueError, match="Invalid domain name"):
            store.load_cert("../../../etc/passwd")

    def test_normal_domain_accepted(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle("example.com")
        result = store.save_cert(bundle)
        assert result.cert_path is not None


# ---------------------------------------------------------------------------
# Curve validation
# ---------------------------------------------------------------------------


class TestCurveValidation:
    def test_load_non_p256_key_raises(self, tmp_path: Path) -> None:
        """Loading a P-384 key should raise TypeError."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        p384_key = ec.generate_private_key(ec.SECP384R1())
        pem = p384_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        (tmp_path / "account.key").write_bytes(pem)

        store = FileStore(tmp_path)
        with pytest.raises(TypeError, match="P-256"):
            store.load_account_key()
