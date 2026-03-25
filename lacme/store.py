"""Certificate and account key storage.

Provides a :class:`Store` protocol and two implementations:
:class:`FileStore` (filesystem-backed) and :class:`MemoryStore` (in-memory, for tests).
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

if TYPE_CHECKING:
    from pathlib import Path

    from lacme._types import CertBundle


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Store(Protocol):
    """Abstract storage interface for ACME account keys and certificates."""

    def save_account_key(self, key: ec.EllipticCurvePrivateKey) -> None: ...

    def load_account_key(self) -> ec.EllipticCurvePrivateKey | None: ...

    def save_cert(self, bundle: CertBundle) -> CertBundle: ...

    def load_cert(self, domain: str) -> CertBundle | None: ...

    def list_certs(self) -> list[CertBundle]: ...


# ---------------------------------------------------------------------------
# FileStore
# ---------------------------------------------------------------------------


class FileStore:
    """Filesystem-backed certificate and account key storage.

    Directory layout::

        {base}/
            account.key          (PEM, 0o600)
            certs/
                {domain}/
                    cert.pem     (leaf, 0o644)
                    fullchain.pem (0o644)
                    key.pem      (private key, 0o600)
                    meta.json    (0o644)
    """

    def __init__(self, base: str | Path) -> None:
        from pathlib import Path as _Path

        self._base = _Path(base).expanduser().resolve()
        self._certs_dir = self._base / "certs"

    @property
    def base(self) -> Path:
        """The resolved base directory path."""
        return self._base

    def _resolve_domain_dir(self, domain: str) -> Path:
        """Resolve a domain directory path, rejecting invalid names and traversal."""
        from pathlib import Path as _Path

        if not domain:
            msg = "Domain name must be non-empty"
            raise ValueError(msg)
        if any(sep in domain for sep in (os.sep, os.altsep) if sep):
            msg = f"Invalid domain name (path separator): {domain!r}"
            raise ValueError(msg)
        domain_dir = _Path(self._certs_dir / domain).resolve()
        if not domain_dir.is_relative_to(self._certs_dir.resolve()):
            msg = f"Invalid domain name (path traversal): {domain!r}"
            raise ValueError(msg)
        return domain_dir

    # --- Account key ---

    def save_account_key(self, key: ec.EllipticCurvePrivateKey) -> None:
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        self._base.mkdir(parents=True, exist_ok=True)
        _atomic_write(self._base / "account.key", pem, mode=0o600)

    def load_account_key(self) -> ec.EllipticCurvePrivateKey | None:
        path = self._base / "account.key"
        if not path.exists():
            return None
        raw_key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(raw_key, ec.EllipticCurvePrivateKey):
            msg = f"Expected EC private key, got {type(raw_key).__name__}"
            raise TypeError(msg)
        if not isinstance(raw_key.curve, ec.SECP256R1):
            msg = f"Expected P-256 key, got {raw_key.curve.name}"
            raise TypeError(msg)
        return raw_key

    # --- Certificates ---

    def save_cert(self, bundle: CertBundle) -> CertBundle:
        from dataclasses import replace

        domain_dir = self._resolve_domain_dir(bundle.domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        cert_path = domain_dir / "cert.pem"
        fullchain_path = domain_dir / "fullchain.pem"
        key_path = domain_dir / "key.pem"
        meta_path = domain_dir / "meta.json"

        _atomic_write(cert_path, bundle.cert_pem, mode=0o644)
        _atomic_write(fullchain_path, bundle.fullchain_pem, mode=0o644)
        _atomic_write(key_path, bundle.key_pem, mode=0o600)

        from lacme._types import CertMeta

        meta = CertMeta(
            domain=bundle.domain,
            domains=bundle.domains,
            issued_at=bundle.issued_at.isoformat(),
            expires_at=bundle.expires_at.isoformat(),
        )
        _atomic_write(
            meta_path,
            json.dumps(meta.to_dict(), indent=2).encode(),
            mode=0o644,
        )

        return replace(
            bundle,
            cert_path=cert_path,
            fullchain_path=fullchain_path,
            key_path=key_path,
        )

    def load_cert(self, domain: str) -> CertBundle | None:
        import datetime

        from lacme._types import CertBundle as _CertBundle
        from lacme._types import CertMeta as _CertMeta

        domain_dir = self._resolve_domain_dir(domain)
        meta_path = domain_dir / "meta.json"
        if not meta_path.exists():
            return None

        meta = _CertMeta.from_dict(json.loads(meta_path.read_text()))
        return _CertBundle(
            domain=meta.domain,
            domains=meta.domains,
            cert_pem=(domain_dir / "cert.pem").read_bytes(),
            fullchain_pem=(domain_dir / "fullchain.pem").read_bytes(),
            key_pem=(domain_dir / "key.pem").read_bytes(),
            issued_at=datetime.datetime.fromisoformat(meta.issued_at),
            expires_at=datetime.datetime.fromisoformat(meta.expires_at),
            cert_path=domain_dir / "cert.pem",
            fullchain_path=domain_dir / "fullchain.pem",
            key_path=domain_dir / "key.pem",
        )

    def list_certs(self) -> list[CertBundle]:
        if not self._certs_dir.exists():
            return []
        results: list[CertBundle] = []
        for domain_dir in sorted(self._certs_dir.iterdir()):
            if domain_dir.is_dir() and (domain_dir / "meta.json").exists():
                bundle = self.load_cert(domain_dir.name)
                if bundle is not None:
                    results.append(bundle)
        return results


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


class MemoryStore:
    """In-memory store for testing.  No filesystem access."""

    def __init__(self) -> None:
        self._account_key: ec.EllipticCurvePrivateKey | None = None
        self._certs: dict[str, CertBundle] = {}

    def save_account_key(self, key: ec.EllipticCurvePrivateKey) -> None:
        self._account_key = key

    def load_account_key(self) -> ec.EllipticCurvePrivateKey | None:
        return self._account_key

    def save_cert(self, bundle: CertBundle) -> CertBundle:
        self._certs[bundle.domain] = bundle
        return bundle

    def load_cert(self, domain: str) -> CertBundle | None:
        return self._certs.get(domain)

    def list_certs(self) -> list[CertBundle]:
        return list(self._certs.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write *data* atomically: write to temp file in same dir, then replace.

    Uses :func:`os.fsync` to ensure data reaches disk before the
    atomic :func:`os.replace`, and :func:`os.fdopen` to handle
    partial writes safely.
    """
    _has_fchmod = hasattr(os, "fchmod")
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            if _has_fchmod:
                os.fchmod(f.fileno(), mode)
        os.replace(tmp, path)
        if not _has_fchmod:
            os.chmod(path, mode)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
