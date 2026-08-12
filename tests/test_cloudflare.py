"""Tests for the HTTPX2-backed Cloudflare DNS provider."""

from __future__ import annotations

import json

import httpx2
import pytest

from lacme.challenges.providers.cloudflare import CloudflareDNSProvider


def _provider_with_transport(
    handler: httpx2.MockTransport,
) -> tuple[CloudflareDNSProvider, httpx2.AsyncClient]:
    provider = CloudflareDNSProvider(api_token="secret-token", zone_id="zone-123")
    http = httpx2.AsyncClient(
        transport=handler,
        headers={"Authorization": "Bearer secret-token"},
    )
    provider._client = http
    return provider, http


class TestCloudflareDNSProvider:
    @pytest.mark.anyio
    async def test_create_and_delete_txt_record(self) -> None:
        requests: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests.append(request)
            if request.method == "POST":
                return httpx2.Response(200, json={"success": True, "result": {"id": "record-1"}})
            return httpx2.Response(200, json={"success": True, "result": {}})

        provider, http = _provider_with_transport(httpx2.MockTransport(handler))
        try:
            await provider.create_txt_record("_acme-challenge.example.com", "proof")
            await provider.delete_txt_record("_acme-challenge.example.com", "proof")
        finally:
            await provider.close()

        assert [request.method for request in requests] == ["POST", "DELETE"]
        assert requests[0].headers["authorization"] == "Bearer secret-token"
        assert json.loads(requests[0].content) == {
            "type": "TXT",
            "name": "_acme-challenge.example.com",
            "content": "proof",
            "ttl": 120,
        }
        assert requests[1].url.path.endswith("/dns_records/record-1")
        assert http.is_closed is True
        assert provider._client is None

    @pytest.mark.anyio
    async def test_delete_treats_not_found_as_success(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST":
                return httpx2.Response(200, json={"result": {"id": "record-1"}})
            return httpx2.Response(404, json={"success": False})

        provider, _ = _provider_with_transport(httpx2.MockTransport(handler))
        try:
            await provider.create_txt_record("_acme-challenge.example.com", "proof")
            await provider.delete_txt_record("_acme-challenge.example.com", "proof")
        finally:
            await provider.close()

    @pytest.mark.anyio
    async def test_error_is_sanitized(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(403, text="permission denied")

        provider, _ = _provider_with_transport(httpx2.MockTransport(handler))
        try:
            with pytest.raises(
                RuntimeError, match="Cloudflare API error 403: permission denied"
            ) as exc:
                await provider.create_txt_record("_acme-challenge.example.com", "proof")
        finally:
            await provider.close()

        assert "secret-token" not in str(exc.value)

    @pytest.mark.anyio
    async def test_httpx2_transport_error_propagates(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("network unavailable", request=request)

        provider, _ = _provider_with_transport(httpx2.MockTransport(handler))
        try:
            with pytest.raises(httpx2.ConnectError, match="network unavailable"):
                await provider.create_txt_record("_acme-challenge.example.com", "proof")
        finally:
            await provider.close()

    @pytest.mark.anyio
    async def test_client_is_pooled_and_close_is_idempotent(self) -> None:
        provider = CloudflareDNSProvider(api_token="secret-token", zone_id="zone-123")
        http = provider._get_client()

        assert provider._get_client() is http

        await provider.close()
        await provider.close()

        assert http.is_closed is True
        assert provider._client is None
