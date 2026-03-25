"""mTLS SSL context helpers.

Provides :func:`server_ssl_context` and :func:`client_ssl_context` for
creating :class:`ssl.SSLContext` objects configured for mutual TLS.
Accepts PEM data as ``bytes`` or file paths as ``str``/:class:`~pathlib.Path`.
"""

from __future__ import annotations

import contextlib
import os
import ssl
import tempfile
from pathlib import Path

PemInput = bytes | str | Path
"""PEM data (``bytes``) or a file path (``str`` or ``Path``)."""


def server_ssl_context(
    *,
    cert_pem: PemInput,
    key_pem: PemInput,
    ca_cert_pem: PemInput | None = None,
) -> ssl.SSLContext:
    """Create a TLS server context, optionally requiring client certificates.

    Args:
        cert_pem: Server certificate (PEM bytes or file path).
        key_pem: Server private key (PEM bytes or file path).
        ca_cert_pem: CA certificate for verifying clients (PEM bytes or
            file path).  When provided, the context requires client
            certificates (``CERT_REQUIRED``).

    Returns:
        Configured :class:`ssl.SSLContext` with TLSv1.2 minimum.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    _load_cert_chain(ctx, cert_pem, key_pem)
    if ca_cert_pem is not None:
        _load_verify_locations(ctx, ca_cert_pem)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_ssl_context(
    *,
    cert_pem: PemInput | None = None,
    key_pem: PemInput | None = None,
    ca_cert_pem: PemInput | None = None,
) -> ssl.SSLContext:
    """Create a TLS client context for mTLS connections.

    Args:
        cert_pem: Client certificate to present (PEM bytes or file path).
        key_pem: Client private key (PEM bytes or file path).
        ca_cert_pem: CA certificate for verifying the server (PEM bytes or
            file path).  Overrides the system default trust store.

    Returns:
        Configured :class:`ssl.SSLContext` with TLSv1.2 minimum.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_pem is not None and key_pem is not None:
        _load_cert_chain(ctx, cert_pem, key_pem)
    if ca_cert_pem is not None:
        _load_verify_locations(ctx, ca_cert_pem)
    else:
        ctx.load_default_certs()
    return ctx


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_cert_chain(ctx: ssl.SSLContext, cert: PemInput, key: PemInput) -> None:
    """Load cert+key into *ctx*, handling both bytes and file paths."""
    cert_path = _ensure_path(cert)
    key_path = _ensure_path(key)
    try:
        ctx.load_cert_chain(str(cert_path.resolved), str(key_path.resolved))
    finally:
        cert_path.cleanup()
        key_path.cleanup()


def _load_verify_locations(ctx: ssl.SSLContext, ca_cert: PemInput) -> None:
    """Load CA cert into *ctx* for peer verification."""
    if isinstance(ca_cert, bytes):
        # load_verify_locations(cadata=...) accepts PEM as a string
        ctx.load_verify_locations(cadata=ca_cert.decode("ascii"))
    elif isinstance(ca_cert, Path):
        ctx.load_verify_locations(cafile=str(ca_cert))
    else:
        ctx.load_verify_locations(cafile=ca_cert)


class _TempPath:
    """Wrapper that either holds a real path or a temp file that needs cleanup."""

    __slots__ = ("resolved", "_needs_cleanup")

    def __init__(self, path: str | Path, *, needs_cleanup: bool = False) -> None:
        self.resolved = str(path)
        self._needs_cleanup = needs_cleanup

    def cleanup(self) -> None:
        if self._needs_cleanup:
            with contextlib.suppress(OSError):
                os.unlink(self.resolved)


_HAS_FCHMOD = hasattr(os, "fchmod")


def _ensure_path(pem: PemInput) -> _TempPath:
    """Return a file path for *pem*, writing to a temp file if needed."""
    if isinstance(pem, Path):
        return _TempPath(pem)
    if isinstance(pem, str):
        return _TempPath(pem)
    # bytes — write to temp file with restricted permissions (may contain key material)
    fd, tmp = tempfile.mkstemp(suffix=".pem")
    try:
        if _HAS_FCHMOD:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
    except BaseException:
        # os.fdopen may not have been reached (e.g. fchmod failed),
        # so close fd if still open.  If fdopen already closed it,
        # os.close raises EBADF which is suppressed.
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return _TempPath(tmp, needs_cleanup=True)
