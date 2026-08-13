"""Tests for lacme.store — FileStore and MemoryStore."""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lacme.errors import ACMEStoreError
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

    def test_list_certs_rejects_metadata_in_unexpected_directory(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        store = FileStore(tmp_path)
        saved = store.save_cert(make_test_bundle("node.example"))
        assert saved.cert_path is not None
        unexpected_dir = tmp_path / "certs" / "misplaced.example"
        saved.cert_path.parent.rename(unexpected_dir)

        with pytest.raises(ACMEStoreError, match="unexpected directory"):
            store.list_certs()

    def test_ordinary_dns_name_keeps_existing_directory_layout(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        result = FileStore(tmp_path).save_cert(make_test_bundle("node.example"))

        assert result.cert_path is not None
        assert result.cert_path.parent == tmp_path / "certs" / "node.example"

    @pytest.mark.parametrize("domain", ["2001:db8::1", "*.example.com"])
    def test_unsafe_domain_component_roundtrip_is_portable(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
        domain: str,
    ) -> None:
        store = FileStore(tmp_path)
        saved = store.save_cert(make_test_bundle(domain))

        assert saved.cert_path is not None
        component = saved.cert_path.parent.name
        assert component.startswith("lacme-v2-")
        assert not component.startswith(".")
        assert ":" not in component
        assert "*" not in component
        assert store.load_cert(domain) is not None
        assert [bundle.domain for bundle in store.list_certs()] == [domain]
        assert store.delete_cert(domain) is True
        assert store.load_cert(domain) is None

    def test_load_rejects_metadata_for_a_different_key(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        store = FileStore(tmp_path)
        saved = store.save_cert(make_test_bundle("node.example"))
        assert saved.cert_path is not None
        meta_path = saved.cert_path.parent / "meta.json"
        metadata = json.loads(meta_path.read_text())
        metadata["domain"] = "other.example"
        meta_path.write_text(json.dumps(metadata))

        with pytest.raises(ACMEStoreError, match="belongs to"):
            store.load_cert("node.example")

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink creation may require privileges")
    def test_sibling_symlink_cannot_overwrite_or_delete_target(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        certs_dir = tmp_path / "certs"
        target_dir = certs_dir / "target"
        target_dir.mkdir(parents=True)
        target_cert = target_dir / "cert.pem"
        target_cert.write_bytes(b"original")
        sentinel = target_dir / "sentinel"
        sentinel.write_text("keep")
        (certs_dir / "alias").symlink_to(target_dir, target_is_directory=True)
        store = FileStore(tmp_path)

        with pytest.raises(ValueError, match="path traversal"):
            store.save_cert(make_test_bundle("alias"))
        with pytest.raises(ValueError, match="path traversal"):
            store.delete_cert("alias")

        assert target_cert.read_bytes() == b"original"
        assert sentinel.read_text() == "keep"
        assert target_dir.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink creation may require privileges")
    def test_list_rejects_sibling_symlink_entry(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        store = FileStore(tmp_path)
        saved = store.save_cert(make_test_bundle("target"))
        assert saved.cert_path is not None
        alias_dir = tmp_path / "certs" / "alias"
        alias_dir.symlink_to(saved.cert_path.parent, target_is_directory=True)

        with pytest.raises(ACMEStoreError, match="Unexpected.*symbolic link"):
            store.list_certs()

        assert saved.cert_path.read_bytes() == saved.cert_pem
        assert alias_dir.is_symlink()

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink creation may require privileges")
    def test_symlinked_certificate_root_is_rejected_by_every_operation(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        base = tmp_path / "store"
        backing_dir = tmp_path / "backing"
        base.mkdir()
        backing_dir.mkdir()
        sentinel = backing_dir / "sentinel"
        sentinel.write_text("keep")
        (base / "certs").symlink_to(backing_dir, target_is_directory=True)
        store = FileStore(base)

        with pytest.raises(ACMEStoreError, match="root must not be a symbolic link"):
            store.save_cert(make_test_bundle("node.example"))
        with pytest.raises(ACMEStoreError, match="root must not be a symbolic link"):
            store.load_cert("node.example")
        with pytest.raises(ACMEStoreError, match="root must not be a symbolic link"):
            store.list_certs()
        with pytest.raises(ACMEStoreError, match="root must not be a symbolic link"):
            store.delete_cert("node.example")

        assert sentinel.read_text() == "keep"
        assert list(backing_dir.iterdir()) == [sentinel]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_account_key_permissions(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        key = ec.generate_private_key(ec.SECP256R1())
        store.save_account_key(key)
        path = tmp_path / "account.key"
        assert oct(path.stat().st_mode & 0o777) == oct(0o600)

    def test_delete_cert(self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle("delete-me.example.com")
        store.save_cert(bundle)
        assert store.load_cert("delete-me.example.com") is not None
        result = store.delete_cert("delete-me.example.com")
        assert result is True
        assert store.load_cert("delete-me.example.com") is None

    def test_delete_cert_missing(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        result = store.delete_cert("nonexistent.example.com")
        assert result is False

    def test_delete_cert_without_metadata_leaves_directory(self, tmp_path: Path) -> None:
        domain_dir = tmp_path / "certs" / "incomplete.example"
        domain_dir.mkdir(parents=True)
        sentinel = domain_dir / "sentinel"
        sentinel.write_text("keep")

        assert FileStore(tmp_path).delete_cert("incomplete.example") is False
        assert sentinel.read_text() == "keep"

    def test_delete_cert_rejects_foreign_metadata_without_deleting(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        store = FileStore(tmp_path)
        saved = store.save_cert(make_test_bundle("node.example"))
        assert saved.cert_path is not None
        domain_dir = saved.cert_path.parent
        meta_path = domain_dir / "meta.json"
        metadata = json.loads(meta_path.read_text())
        metadata["domain"] = "other.example"
        meta_path.write_text(json.dumps(metadata))

        with pytest.raises(ACMEStoreError, match="belongs to"):
            store.delete_cert("node.example")

        assert domain_dir.exists()
        assert (domain_dir / "cert.pem").exists()
        assert meta_path.exists()

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

    def test_delete_cert(self, make_test_bundle: Callable[..., CertBundle]) -> None:
        store = MemoryStore()
        bundle = make_test_bundle("delete-me.example.com")
        store.save_cert(bundle)
        assert store.load_cert("delete-me.example.com") is not None
        result = store.delete_cert("delete-me.example.com")
        assert result is True
        assert store.load_cert("delete-me.example.com") is None

    def test_delete_cert_missing(self) -> None:
        store = MemoryStore()
        result = store.delete_cert("nonexistent.example.com")
        assert result is False

    def test_save_load_ca_roundtrip(self) -> None:
        store = MemoryStore()
        store.save_ca("root", b"---CERT---", b"---KEY---")
        result = store.load_ca("root")
        assert result is not None
        assert result == (b"---CERT---", b"---KEY---")

    def test_load_ca_returns_none_when_missing(self) -> None:
        store = MemoryStore()
        assert store.load_ca("nonexistent") is None


# ---------------------------------------------------------------------------
# FileStore CA
# ---------------------------------------------------------------------------


class TestFileStoreCA:
    def test_save_load_ca_roundtrip(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        store.save_ca("root", b"---CERT---", b"---KEY---")
        result = store.load_ca("root")
        assert result is not None
        assert result == (b"---CERT---", b"---KEY---")

    def test_load_ca_returns_none_when_missing(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        assert store.load_ca("missing") is None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_ca_key_permissions(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        store.save_ca("root", b"---CERT---", b"---KEY---")
        key_path = tmp_path / "ca" / "root" / "key.pem"
        assert oct(key_path.stat().st_mode & 0o777) == oct(0o600)

    def test_empty_name_raises(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(ValueError, match="non-empty"):
            store.save_ca("", b"---CERT---", b"---KEY---")

    def test_save_ca_path_traversal_rejected(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(ValueError, match="Invalid CA name"):
            store.save_ca("../../evil", b"---CERT---", b"---KEY---")

    def test_load_ca_path_traversal_rejected(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(ValueError, match="Invalid CA name"):
            store.load_ca("../../../etc/passwd")


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
        with pytest.raises(ValueError, match="Invalid certificate key"):
            store.save_cert(bundle)

    def test_load_cert_path_traversal_rejected(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(ValueError, match="Invalid certificate key"):
            store.load_cert("../../../etc/passwd")

    @pytest.mark.parametrize("domain", [".", ".."])
    def test_delete_dot_domain_key_cannot_remove_cert_store(
        self,
        tmp_path: Path,
        domain: str,
    ) -> None:
        certs_dir = tmp_path / "certs"
        victim_dir = certs_dir / "victim.example"
        victim_dir.mkdir(parents=True)
        sentinel = victim_dir / "sentinel"
        sentinel.write_text("keep")
        (certs_dir / "meta.json").write_text(json.dumps({"domain": domain}))

        with pytest.raises(ValueError, match="dot component"):
            FileStore(tmp_path).delete_cert(domain)

        assert certs_dir.exists()
        assert sentinel.read_text() == "keep"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlink creation may require privileges")
    def test_domain_resolution_rejects_symlink_to_cert_store_root(
        self,
        tmp_path: Path,
    ) -> None:
        certs_dir = tmp_path / "certs"
        certs_dir.mkdir()
        domain = "node.example"
        (certs_dir / domain).symlink_to(certs_dir, target_is_directory=True)
        with pytest.raises(ValueError, match="path traversal"):
            FileStore(tmp_path)._resolve_domain_dir(domain)

    def test_backslash_separator_rejected_on_every_platform(
        self,
        tmp_path: Path,
        make_test_bundle: Callable[..., CertBundle],
    ) -> None:
        from dataclasses import replace

        store = FileStore(tmp_path)
        bundle = replace(make_test_bundle(), domain="..\\evil")
        with pytest.raises(ValueError, match="path separator"):
            store.save_cert(bundle)

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
