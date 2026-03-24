"""Tests for lacme.starlette — Starlette integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

starlette = pytest.importorskip("starlette")

import httpx  # noqa: E402

from lacme.challenges.http01 import HTTP01Handler  # noqa: E402
from lacme.starlette import acme_challenge_route, configure_app, on_startup_issue  # noqa: E402

# ---------------------------------------------------------------------------
# Challenge route
# ---------------------------------------------------------------------------


class TestACMEChallengeRoute:
    @pytest.mark.anyio
    async def test_serves_challenge(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("example.com", "test-token", "authz-value")
        route = acme_challenge_route(handler)

        from starlette.applications import Starlette
        from starlette.routing import Route

        app = Starlette(routes=[route, Route("/", lambda r: None)])
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/test-token")
            assert resp.status_code == 200
            assert resp.text == "authz-value"
            assert "application/octet-stream" in resp.headers["content-type"]

    @pytest.mark.anyio
    async def test_missing_token_returns_404(self) -> None:
        handler = HTTP01Handler()
        route = acme_challenge_route(handler)

        from starlette.applications import Starlette

        app = Starlette(routes=[route])
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/missing")
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# on_startup_issue
# ---------------------------------------------------------------------------


class TestOnStartupIssue:
    @pytest.mark.anyio
    async def test_calls_client_issue(self) -> None:
        mock_client = AsyncMock()
        bundle = MagicMock()
        bundle.domain = "example.com"
        bundle.expires_at = MagicMock()
        bundle.expires_at.__str__ = lambda s: "2026-01-01"
        mock_client.issue.return_value = bundle

        await on_startup_issue(mock_client, "example.com")
        mock_client.issue.assert_awaited_once_with("example.com", challenge_type="http-01")


# ---------------------------------------------------------------------------
# configure_app
# ---------------------------------------------------------------------------


class TestConfigureApp:
    def test_adds_route(self) -> None:
        from starlette.applications import Starlette

        handler = HTTP01Handler()
        app = Starlette()

        initial_route_count = len(app.routes)
        configure_app(app, handler=handler)
        assert len(app.routes) == initial_route_count + 1
