"""mTLS SSL context helpers.

Provides :func:`server_ssl_context` and :func:`client_ssl_context` for
creating :class:`ssl.SSLContext` objects configured for mutual TLS.
Also provides :func:`write_pem_files` and :func:`pem_files` for writing
PEM data to secure temporary files (useful for uvicorn which only accepts
file paths).  Accepts PEM data as ``bytes`` or file paths as
``str``/:class:`~pathlib.Path`.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

    from lacme._types import CertBundle

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
# PEM file helpers (for uvicorn and other path-only consumers)
# ---------------------------------------------------------------------------


def _write_pem_file(path: Path, data: bytes, *, mode: int) -> None:
    """Write PEM data with permissions set before content is written."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


@dataclass(frozen=True, slots=True)
class PemPaths:
    """Paths to PEM files written by :func:`write_pem_files`."""

    cert: Path
    key: Path
    ca: Path | None = None

    def as_uvicorn_kwargs(self) -> dict[str, str]:
        """Return kwargs suitable for ``uvicorn.run()``.

        When ``ca`` is set, includes ``ssl_ca_certs``.  To enforce
        mTLS (require client certificates), also pass
        ``ssl_cert_reqs=ssl.CERT_REQUIRED`` to uvicorn — it defaults
        to ``CERT_NONE`` even when ``ssl_ca_certs`` is provided.
        """
        result = {
            "ssl_certfile": str(self.cert),
            "ssl_keyfile": str(self.key),
        }
        if self.ca is not None:
            result["ssl_ca_certs"] = str(self.ca)
        return result


def write_pem_files(
    bundle: CertBundle,
    ca_pem: bytes | None = None,
    directory: Path | str | None = None,
) -> PemPaths:
    """Write certificate PEM data to secure temporary files.

    Creates a directory with ``0o700`` permissions containing cert/CA
    files (``0o644``) and the private key (``0o600``).  Useful
    for uvicorn and other servers that only accept file paths.

    The caller is responsible for cleanup.  For automatic cleanup, use
    :func:`pem_files` (context manager) instead.

    Args:
        bundle: Certificate bundle with ``fullchain_pem`` and ``key_pem``.
        ca_pem: Optional CA certificate PEM bytes.
        directory: Parent directory for the temp dir.  Defaults to system temp.

    Returns:
        :class:`PemPaths` with file paths.
    """
    parent = str(directory) if directory is not None else None
    tmpdir = Path(tempfile.mkdtemp(prefix="lacme-pem-", dir=parent))
    os.chmod(tmpdir, 0o700)

    cert_path = tmpdir / "fullchain.pem"
    key_path = tmpdir / "key.pem"

    _write_pem_file(cert_path, bundle.fullchain_pem, mode=0o644)
    _write_pem_file(key_path, bundle.key_pem, mode=0o600)

    ca_path: Path | None = None
    if ca_pem is not None:
        ca_path = tmpdir / "ca.pem"
        _write_pem_file(ca_path, ca_pem, mode=0o644)

    return PemPaths(cert=cert_path, key=key_path, ca=ca_path)


def _cleanup_pem_dir(path: Path) -> None:
    """Remove a PEM temp directory."""
    import shutil

    with contextlib.suppress(OSError):
        shutil.rmtree(path)


@contextlib.contextmanager
def pem_files(
    bundle: CertBundle,
    ca_pem: bytes | None = None,
    directory: Path | str | None = None,
) -> Generator[PemPaths, None, None]:
    """Context manager: write PEM files and clean up on exit.

    Usage::

        with pem_files(bundle, ca_pem=ca.root_cert_pem) as paths:
            uvicorn.run("app:app", **paths.as_uvicorn_kwargs())
        # temp files deleted automatically
    """
    paths = write_pem_files(bundle, ca_pem=ca_pem, directory=directory)
    try:
        yield paths
    finally:
        _cleanup_pem_dir(paths.cert.parent)


def write_pem_files_persistent(
    bundle: CertBundle,
    ca_pem: bytes | None = None,
    directory: Path | str | None = None,
) -> PemPaths:
    """Like :func:`write_pem_files` but registers ``atexit`` cleanup.

    Suitable for long-lived processes where a context manager is
    inconvenient (e.g., passing paths to uvicorn before ``app.run()``).
    """
    paths = write_pem_files(bundle, ca_pem=ca_pem, directory=directory)
    atexit.register(_cleanup_pem_dir, paths.cert.parent)
    return paths


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
