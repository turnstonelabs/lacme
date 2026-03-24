"""Uvicorn integration helpers for lacme certificate management.

Provides functions to extract SSL configuration from a
:class:`~lacme.store.FileStore` for use with ``uvicorn.run()``.
No extra dependencies required.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lacme.store import FileStore


def ssl_kwargs_from_store(store: FileStore, domain: str) -> dict[str, Any]:
    """Return kwargs for ``uvicorn.run()`` with SSL cert/key from store.

    Usage::

        import uvicorn
        from lacme.store import FileStore
        from lacme.uvicorn import ssl_kwargs_from_store

        store = FileStore("~/.lacme")
        uvicorn.run("app:app", **ssl_kwargs_from_store(store, "example.com"))

    Returns:
        Dict with ``ssl_keyfile`` and ``ssl_certfile`` keys.

    Raises:
        FileNotFoundError: If no certificate is stored for *domain*.
        ValueError: If the stored bundle has no file paths.
    """
    bundle = store.load_cert(domain)
    if bundle is None:
        msg = f"No certificate stored for {domain!r}"
        raise FileNotFoundError(msg)
    if bundle.fullchain_path is None or bundle.key_path is None:
        msg = f"Certificate for {domain!r} has no file paths (not from FileStore?)"
        raise ValueError(msg)
    return {
        "ssl_keyfile": str(bundle.key_path),
        "ssl_certfile": str(bundle.fullchain_path),
    }


def ssl_context_from_store(store: FileStore, domain: str) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` from a stored certificate.

    Useful for custom server configurations or non-uvicorn ASGI servers.

    Raises:
        FileNotFoundError: If no certificate is stored for *domain*.
        ValueError: If the stored bundle has no file paths.
    """
    kwargs = ssl_kwargs_from_store(store, domain)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(kwargs["ssl_certfile"], kwargs["ssl_keyfile"])
    return ctx
