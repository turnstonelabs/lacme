"""Cloudflare DNS provider for DNS-01 challenges.

Uses the Cloudflare REST API v4 via :mod:`httpx` to create and delete
TXT records in a specified zone.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("lacme.challenges.providers.cloudflare")

_CF_API_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareDNSProvider:
    """DNS provider backed by the Cloudflare API.

    Satisfies :class:`~lacme.challenges.dns01.DNSProvider`.
    Reuses a single :class:`httpx.AsyncClient` for connection pooling.
    """

    def __init__(self, *, api_token: str, zone_id: str) -> None:
        self._api_token = api_token
        self._zone_id = zone_id
        self._record_ids: dict[tuple[str, str], str] = {}
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {self._api_token}"},
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def create_txt_record(self, domain: str, value: str) -> None:
        """Create a TXT record via the Cloudflare API."""
        url = f"{_CF_API_BASE}/zones/{self._zone_id}/dns_records"
        payload: dict[str, Any] = {
            "type": "TXT",
            "name": domain,
            "content": value,
            "ttl": 120,
        }
        client = self._get_client()
        resp = await client.post(url, json=payload)
        _check_cf_response(resp)
        data = resp.json()

        record_id: str = data["result"]["id"]
        self._record_ids[(domain, value)] = record_id
        logger.debug("Created Cloudflare TXT record %s for %s", record_id, domain)

    async def delete_txt_record(self, domain: str, value: str) -> None:
        """Delete a TXT record via the Cloudflare API."""
        record_id = self._record_ids.pop((domain, value), None)
        if record_id is None:
            logger.warning("No tracked Cloudflare record ID for %s; skipping delete", domain)
            return

        url = f"{_CF_API_BASE}/zones/{self._zone_id}/dns_records/{record_id}"
        client = self._get_client()
        resp = await client.delete(url)
        if resp.status_code == 404:
            logger.debug("Cloudflare record %s already deleted", record_id)
            return
        _check_cf_response(resp)
        logger.debug("Deleted Cloudflare TXT record %s for %s", record_id, domain)


def _check_cf_response(resp: httpx.Response) -> None:
    """Check a Cloudflare API response, sanitizing errors to avoid token leaks."""
    if resp.is_success:
        return
    # Do NOT use resp.raise_for_status() — it includes the Authorization header
    body = resp.text[:500]
    msg = f"Cloudflare API error {resp.status_code}: {body}"
    raise RuntimeError(msg)
