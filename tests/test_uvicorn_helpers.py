"""Tests for lacme.uvicorn — Uvicorn SSL helpers."""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

import pytest

from lacme.store import FileStore
from lacme.uvicorn import ssl_context_from_store, ssl_kwargs_from_store

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from lacme._types import CertBundle


# ---------------------------------------------------------------------------
# ssl_kwargs_from_store
# ---------------------------------------------------------------------------


class TestSSLKwargsFromStore:
    def test_returns_paths(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle("example.com")
        store.save_cert(bundle)

        kwargs = ssl_kwargs_from_store(store, "example.com")
        assert "ssl_keyfile" in kwargs
        assert "ssl_certfile" in kwargs
        assert kwargs["ssl_keyfile"].endswith("key.pem")
        assert kwargs["ssl_certfile"].endswith("fullchain.pem")

    def test_missing_cert_raises(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(FileNotFoundError, match="No certificate stored"):
            ssl_kwargs_from_store(store, "missing.com")

    def test_no_paths_raises(self, tmp_path: Path) -> None:
        """Bundle without file paths (e.g. from MemoryStore) raises ValueError."""
        # Use MemoryStore which doesn't set paths, but wrap in a FileStore-compatible way
        from unittest.mock import MagicMock

        from lacme.uvicorn import ssl_kwargs_from_store as _ssl_kwargs

        mock_store = MagicMock(spec=FileStore)
        mock_bundle = MagicMock()
        mock_bundle.fullchain_path = None
        mock_bundle.key_path = None
        mock_store.load_cert.return_value = mock_bundle

        with pytest.raises(ValueError, match="no file paths"):
            _ssl_kwargs(mock_store, "example.com")


# ---------------------------------------------------------------------------
# ssl_context_from_store
# ---------------------------------------------------------------------------


class TestSSLContextFromStore:
    def test_creates_context(
        self, tmp_path: Path, make_test_bundle: Callable[..., CertBundle]
    ) -> None:
        store = FileStore(tmp_path)
        bundle = make_test_bundle("example.com")
        store.save_cert(bundle)

        ctx = ssl_context_from_store(store, "example.com")
        assert isinstance(ctx, ssl.SSLContext)

    def test_missing_cert_raises(self, tmp_path: Path) -> None:
        store = FileStore(tmp_path)
        with pytest.raises(FileNotFoundError):
            ssl_context_from_store(store, "missing.com")
