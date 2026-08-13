"""Certificate and account key storage.

Provides a :class:`Store` protocol and two implementations:
:class:`FileStore` (filesystem-backed) and :class:`MemoryStore` (in-memory, for tests).
"""

from __future__ import annotations

import contextlib
import hashlib
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

from lacme.errors import ACMEStoreError

if TYPE_CHECKING:
    from pathlib import Path

    from lacme._types import CertBundle, CertMeta

_CERT_DIR_PREFIX = "lacme-v2-"
_WINDOWS_INVALID_CHARS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


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

    def delete_cert(self, domain: str) -> bool: ...

    def save_ca(self, name: str, cert_pem: bytes, key_pem: bytes) -> None: ...

    def load_ca(self, name: str) -> tuple[bytes, bytes] | None: ...


# ---------------------------------------------------------------------------
# FileStore
# ---------------------------------------------------------------------------


class FileStore:
    """Filesystem-backed certificate and account key storage.

    Directory layout::

        {base}/
            account.key          (PEM, 0o600)
            certs/
                {portable-certificate-key}/
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

    @staticmethod
    def _validate_domain_key(domain: str) -> None:
        """Validate the public string key before mapping it to a directory."""
        if not isinstance(domain, str) or not domain:
            msg = "Certificate key must be a non-empty string"
            raise ValueError(msg)
        if domain in {".", ".."}:
            msg = f"Invalid certificate key (dot component): {domain!r}"
            raise ValueError(msg)
        if "/" in domain or "\\" in domain:
            msg = f"Invalid certificate key (path separator): {domain!r}"
            raise ValueError(msg)

    @staticmethod
    def _is_portable_domain_component(domain: str) -> bool:
        """Return whether *domain* is a safe cross-platform certificate key."""
        first_segment = domain.split(".", 1)[0].rstrip(" .").upper()
        utf16_units = len(domain.encode("utf-16-le")) // 2
        return (
            domain not in {".", ".."}
            and not any(ord(char) < 32 or char in _WINDOWS_INVALID_CHARS for char in domain)
            and not domain.endswith((" ", "."))
            and first_segment not in _WINDOWS_RESERVED_NAMES
            and utf16_units <= 255
        )

    @staticmethod
    def _domain_component(domain: str) -> str:
        """Map a public key to a deterministic cross-platform path component."""
        FileStore._validate_domain_key(domain)
        is_portable = (
            not domain.startswith(_CERT_DIR_PREFIX)
            and FileStore._is_portable_domain_component(domain)
            and len(domain.encode("utf-8")) <= 200
        )
        if is_portable:
            return domain
        digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()
        return f"{_CERT_DIR_PREFIX}{digest}"

    def _resolve_certs_dir(self) -> Path:
        """Return the lexical certificate root, rejecting path aliases."""
        certs_dir = self._certs_dir
        if certs_dir.is_symlink() or certs_dir.resolve() != certs_dir:
            msg = f"Certificate store root must not be a symbolic link: {certs_dir}"
            raise ACMEStoreError(msg)
        return certs_dir

    def _resolve_domain_dir(self, domain: str) -> Path:
        """Resolve the portable directory for a public certificate key."""
        from pathlib import Path as _Path

        component = self._domain_component(domain)
        certs_dir = self._resolve_certs_dir()
        domain_path = _Path(certs_dir / component)
        domain_dir = domain_path.resolve()
        if (
            domain_dir != domain_path
            or domain_dir == certs_dir
            or not domain_dir.is_relative_to(certs_dir)
        ):
            msg = f"Invalid certificate key (path traversal): {domain!r}"
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

    # --- CA ---

    def _resolve_ca_dir(self, name: str) -> Path:
        """Resolve a CA directory path, rejecting invalid names and traversal."""
        from pathlib import Path as _Path

        if not name:
            msg = "CA name must be non-empty"
            raise ValueError(msg)
        if any(sep in name for sep in (os.sep, os.altsep) if sep):
            msg = f"Invalid CA name (path separator): {name!r}"
            raise ValueError(msg)
        ca_base = (self._base / "ca").resolve()
        ca_dir = _Path(self._base / "ca" / name).resolve()
        if not ca_dir.is_relative_to(ca_base):
            msg = f"Invalid CA name (path traversal): {name!r}"
            raise ValueError(msg)
        return ca_dir

    def save_ca(self, name: str, cert_pem: bytes, key_pem: bytes) -> None:
        ca_dir = self._resolve_ca_dir(name)
        ca_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write(ca_dir / "cert.pem", cert_pem, mode=0o644)
        _atomic_write(ca_dir / "key.pem", key_pem, mode=0o600)

    def load_ca(self, name: str) -> tuple[bytes, bytes] | None:
        ca_dir = self._resolve_ca_dir(name)
        cert_path = ca_dir / "cert.pem"
        key_path = ca_dir / "key.pem"
        if not cert_path.exists() or not key_path.exists():
            return None
        return (cert_path.read_bytes(), key_path.read_bytes())

    # --- Certificates ---

    def save_cert(self, bundle: CertBundle) -> CertBundle:
        from dataclasses import replace

        domain_dir = self._resolve_domain_dir(bundle.domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        cert_path = domain_dir / "cert.pem"
        fullchain_path = domain_dir / "fullchain.pem"
        key_path = domain_dir / "key.pem"
        meta_path = domain_dir / "meta.json"

        if meta_path.exists():
            existing = self._read_cert_meta(meta_path)
            if existing.domain != bundle.domain:
                msg = (
                    f"Certificate directory collision: {domain_dir} belongs to "
                    f"{existing.domain!r}, not {bundle.domain!r}"
                )
                raise ACMEStoreError(msg)

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
        domain_dir = self._resolve_domain_dir(domain)
        if not (domain_dir / "meta.json").exists():
            return None
        return self._load_cert_from_dir(domain_dir, expected_domain=domain)

    def list_certs(self) -> list[CertBundle]:
        certs_dir = self._resolve_certs_dir()
        if not certs_dir.exists():
            return []
        certs: list[CertBundle] = []
        for domain_dir in sorted(certs_dir.iterdir()):
            if domain_dir.is_symlink():
                msg = f"Unexpected certificate directory (symbolic link): {domain_dir}"
                raise ACMEStoreError(msg)
            if domain_dir.is_dir() and (domain_dir / "meta.json").exists():
                meta = self._read_cert_meta(domain_dir / "meta.json")
                expected_dir = self._resolve_domain_dir(meta.domain)
                if domain_dir != expected_dir:
                    msg = (
                        f"Certificate metadata for {meta.domain!r} is stored in an "
                        f"unexpected directory: {domain_dir}"
                    )
                    raise ACMEStoreError(msg)
                certs.append(self._load_cert_from_dir(domain_dir, expected_domain=meta.domain))
        return sorted(certs, key=lambda cert: cert.domain)

    def delete_cert(self, domain: str) -> bool:
        import shutil

        domain_dir = self._resolve_domain_dir(domain)
        meta_path = domain_dir / "meta.json"
        if not domain_dir.exists() or not meta_path.exists():
            return False
        meta = self._read_cert_meta(meta_path)
        if meta.domain != domain:
            msg = f"Certificate directory {domain_dir} belongs to {meta.domain!r}"
            raise ACMEStoreError(msg)
        shutil.rmtree(domain_dir)
        return True

    @staticmethod
    def _read_cert_meta(path: Path) -> CertMeta:
        from lacme._types import CertMeta as _CertMeta

        return _CertMeta.from_dict(json.loads(path.read_text()))

    def _load_cert_from_dir(self, domain_dir: Path, *, expected_domain: str) -> CertBundle:
        import datetime

        from lacme._types import CertBundle as _CertBundle

        meta = self._read_cert_meta(domain_dir / "meta.json")
        if meta.domain != expected_domain:
            msg = f"Certificate directory {domain_dir} belongs to {meta.domain!r}"
            raise ACMEStoreError(msg)
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


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


class MemoryStore:
    """In-memory store for testing.  No filesystem access."""

    def __init__(self) -> None:
        self._account_key: ec.EllipticCurvePrivateKey | None = None
        self._certs: dict[str, CertBundle] = {}
        self._cas: dict[str, tuple[bytes, bytes]] = {}

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

    def delete_cert(self, domain: str) -> bool:
        if domain in self._certs:
            del self._certs[domain]
            return True
        return False

    def save_ca(self, name: str, cert_pem: bytes, key_pem: bytes) -> None:
        self._cas[name] = (cert_pem, key_pem)

    def load_ca(self, name: str) -> tuple[bytes, bytes] | None:
        return self._cas.get(name)


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
