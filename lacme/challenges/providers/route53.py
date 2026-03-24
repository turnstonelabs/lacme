"""AWS Route 53 DNS provider for DNS-01 challenges.

Uses :mod:`boto3` (sync) wrapped in :func:`asyncio.get_running_loop().run_in_executor`
to create and delete TXT records in a specified hosted zone.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("lacme.challenges.providers.route53")


class Route53DNSProvider:
    """DNS provider backed by AWS Route 53.

    Satisfies :class:`~lacme.challenges.dns01.DNSProvider`.

    Requires ``boto3`` at runtime (install with ``pip install lacme[aws]``).
    """

    def __init__(self, *, hosted_zone_id: str) -> None:
        self._hosted_zone_id = hosted_zone_id
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("route53")
        return self._client

    async def create_txt_record(self, domain: str, value: str) -> None:
        """Create a TXT record via Route 53 UPSERT."""
        logger.debug("Creating Route 53 TXT record for %s", domain)
        await self._change_record("UPSERT", domain, value)

    async def delete_txt_record(self, domain: str, value: str) -> None:
        """Delete a TXT record via Route 53 DELETE."""
        logger.debug("Deleting Route 53 TXT record for %s", domain)
        await self._change_record("DELETE", domain, value)

    async def _change_record(self, action: str, domain: str, value: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._sync_change_record, action, domain, value)

    def _sync_change_record(self, action: str, domain: str, value: str) -> None:
        client = self._get_client()
        change_batch: dict[str, Any] = {
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "TXT",
                        "TTL": 120,
                        "ResourceRecords": [{"Value": f'"{value}"'}],
                    },
                }
            ]
        }
        client.change_resource_record_sets(
            HostedZoneId=self._hosted_zone_id,
            ChangeBatch=change_batch,
        )
        logger.debug("Route 53 %s completed for %s", action, domain)
