"""Tests for lacme.fastapi — FastAPI integration."""

from __future__ import annotations

import importlib
from unittest.mock import AsyncMock, MagicMock

import pytest

# fastapi is an optional dependency — skip entire module if missing.
# We use importlib because lacme.ext_fastapi shadows the name in some contexts.
try:
    importlib.import_module("fastapi")
except ModuleNotFoundError:
    pytest.skip("fastapi not installed", allow_module_level=True)

import httpx  # noqa: E402

from lacme.challenges.http01 import HTTP01Handler  # noqa: E402
from lacme.ext_fastapi import (  # noqa: E402
    acme_challenge_router,
    get_client_dependency,
    lifespan_issue,
)

# ---------------------------------------------------------------------------
# Challenge router
# ---------------------------------------------------------------------------


class TestACMEChallengeRouter:
    @pytest.mark.anyio
    async def test_serves_challenge(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("example.com", "test-token", "authz-value")
        router = acme_challenge_router(handler)

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/test-token")
            assert resp.status_code == 200
            assert resp.text == "authz-value"

    @pytest.mark.anyio
    async def test_missing_token_returns_404(self) -> None:
        handler = HTTP01Handler()
        router = acme_challenge_router(handler)

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/missing")
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Client dependency
# ---------------------------------------------------------------------------


class TestClientDependency:
    @pytest.mark.anyio
    async def test_returns_client(self) -> None:
        mock_client = MagicMock()
        dep = get_client_dependency(mock_client)
        result = await dep()
        assert result is mock_client


# ---------------------------------------------------------------------------
# lifespan_issue
# ---------------------------------------------------------------------------


class TestLifespanIssue:
    @pytest.mark.anyio
    async def test_calls_client_issue(self) -> None:
        mock_client = AsyncMock()
        bundle = MagicMock()
        bundle.domain = "example.com"
        bundle.expires_at = MagicMock()
        mock_client.issue.return_value = bundle

        await lifespan_issue(mock_client, ["example.com", "www.example.com"])
        mock_client.issue.assert_awaited_once_with(
            ["example.com", "www.example.com"], challenge_type="http-01"
        )
