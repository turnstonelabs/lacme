"""Tests for lacme.challenges.http01 — HTTP-01 challenge handler."""

from __future__ import annotations

import pytest

from lacme.challenges import ChallengeHandler
from lacme.challenges.http01 import HTTP01Handler


class TestHTTP01Handler:
    @pytest.mark.anyio
    async def test_provision_and_get(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("example.com", "token123", "token123.thumbprint")
        assert handler.get_response("token123") == "token123.thumbprint"

    @pytest.mark.anyio
    async def test_get_missing_returns_none(self) -> None:
        handler = HTTP01Handler()
        assert handler.get_response("nonexistent") is None

    @pytest.mark.anyio
    async def test_deprovision_removes(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("example.com", "token123", "token123.thumbprint")
        await handler.deprovision("example.com", "token123")
        assert handler.get_response("token123") is None

    @pytest.mark.anyio
    async def test_deprovision_missing_is_noop(self) -> None:
        handler = HTTP01Handler()
        await handler.deprovision("example.com", "nonexistent")

    @pytest.mark.anyio
    async def test_multiple_tokens(self) -> None:
        handler = HTTP01Handler()
        await handler.provision("a.com", "tok1", "auth1")
        await handler.provision("b.com", "tok2", "auth2")
        assert handler.get_response("tok1") == "auth1"
        assert handler.get_response("tok2") == "auth2"

    def test_implements_challenge_handler_protocol(self) -> None:
        assert isinstance(HTTP01Handler(), ChallengeHandler)


class TestHTTP01StandaloneServer:
    @pytest.mark.anyio
    async def test_serves_challenge_response(self) -> None:
        import httpx

        handler = HTTP01Handler()
        await handler.provision("example.com", "test-token", "test-authz")
        server = await handler.start_server(host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://127.0.0.1:{port}/.well-known/acme-challenge/test-token"
                )
                assert resp.status_code == 200
                assert resp.text == "test-authz"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.anyio
    async def test_missing_token_returns_404(self) -> None:
        import httpx

        handler = HTTP01Handler()
        server = await handler.start_server(host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://127.0.0.1:{port}/.well-known/acme-challenge/missing"
                )
                assert resp.status_code == 404
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.anyio
    async def test_non_challenge_path_returns_404(self) -> None:
        import httpx

        handler = HTTP01Handler()
        server = await handler.start_server(host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"http://127.0.0.1:{port}/other")
                assert resp.status_code == 404
        finally:
            server.close()
            await server.wait_closed()
