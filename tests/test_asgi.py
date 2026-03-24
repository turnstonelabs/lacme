"""Tests for lacme.asgi — ACME challenge ASGI middleware."""

from __future__ import annotations

import httpx
import pytest

from lacme.asgi import ACMEChallengeMiddleware, challenge_middleware
from lacme.challenges.http01 import HTTP01Handler


async def _dummy_app(scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
    """Minimal ASGI app that returns 200 with 'inner app' body."""
    await send(  # type: ignore[operator]
        {"type": "http.response.start", "status": 200, "headers": []}
    )
    await send({"type": "http.response.body", "body": b"inner app"})  # type: ignore[operator]


class TestACMEChallengeMiddleware:
    @pytest.mark.anyio
    async def test_serves_challenge_response(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("example.com", "tok", "authz-value")
        middleware = ACMEChallengeMiddleware(_dummy_app, handler)  # type: ignore[arg-type]
        transport = httpx.ASGITransport(app=middleware)  # type: ignore[arg-type]

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/tok")
            assert resp.status_code == 200
            assert resp.text == "authz-value"
            assert resp.headers["content-type"] == "application/octet-stream"

    @pytest.mark.anyio
    async def test_missing_token_returns_404(self) -> None:
        handler = HTTP01Handler()
        middleware = ACMEChallengeMiddleware(_dummy_app, handler)  # type: ignore[arg-type]
        transport = httpx.ASGITransport(app=middleware)  # type: ignore[arg-type]

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/acme-challenge/missing")
            assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_non_challenge_passes_through(self) -> None:
        handler = HTTP01Handler()
        middleware = ACMEChallengeMiddleware(_dummy_app, handler)  # type: ignore[arg-type]
        transport = httpx.ASGITransport(app=middleware)  # type: ignore[arg-type]

        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/health")
            assert resp.status_code == 200
            assert resp.text == "inner app"

    @pytest.mark.anyio
    async def test_websocket_passes_through(self) -> None:
        handler = HTTP01Handler()
        inner_called = False

        async def ws_app(scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
            nonlocal inner_called
            inner_called = True

        middleware = ACMEChallengeMiddleware(ws_app, handler)  # type: ignore[arg-type]
        # Simulate a websocket scope directly
        scope = {"type": "websocket", "path": "/.well-known/acme-challenge/tok"}

        async def noop() -> dict:  # type: ignore[type-arg]
            return {}

        async def noop_send(msg: dict) -> None:  # type: ignore[type-arg]
            pass

        await middleware(scope, noop, noop_send)  # type: ignore[arg-type]
        assert inner_called


class TestChallengeMiddlewareFactory:
    def test_returns_middleware(self) -> None:
        handler = HTTP01Handler()
        app = challenge_middleware(_dummy_app, handler)  # type: ignore[arg-type]
        assert isinstance(app, ACMEChallengeMiddleware)
