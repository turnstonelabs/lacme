#!/usr/bin/env python3
"""Example: Issue a wildcard certificate using DNS-01 with Cloudflare.

Demonstrates:
- DNS-01 challenge flow (required for wildcard domains)
- CloudflareDNSProvider for automated TXT record management
- Async Client usage with EventDispatcher for observability

Prerequisites:
    - Cloudflare API token with Zone:DNS:Edit permissions
    - Zone ID for the target domain

Run:
    export LACME_CLOUDFLARE_TOKEN="your-api-token"
    export LACME_CLOUDFLARE_ZONE_ID="your-zone-id"
    pip install lacme
    python examples/dns01_cloudflare.py example.com
"""

from __future__ import annotations

import asyncio
import os
import sys

from lacme import Client, EventDispatcher, FileStore
from lacme.challenges.dns01 import DNS01Handler
from lacme.challenges.providers.cloudflare import CloudflareDNSProvider
from lacme.client import LETSENCRYPT_STAGING_DIRECTORY
from lacme.events import CertificateIssued, ChallengeFailed


async def main(base_domain: str) -> None:
    # --- Setup event dispatcher for visibility ---
    dispatcher = EventDispatcher()
    dispatcher.subscribe(
        lambda e: print(f"  [event] Issued: {e.domain}, expires {e.expires_at}"),  # noqa: T201
        event_type=CertificateIssued,
    )
    dispatcher.subscribe(
        lambda e: print(f"  [event] Challenge failed: {e.domain} ({e.error})"),  # noqa: T201
        event_type=ChallengeFailed,
    )

    # --- Configure DNS-01 with Cloudflare ---
    api_token = os.environ["LACME_CLOUDFLARE_TOKEN"]
    zone_id = os.environ["LACME_CLOUDFLARE_ZONE_ID"]

    provider = CloudflareDNSProvider(api_token=api_token, zone_id=zone_id)
    dns_handler = DNS01Handler(provider=provider, propagation_delay=15.0)

    store = FileStore("~/.lacme")

    # --- Issue wildcard certificate ---
    domains = [base_domain, f"*.{base_domain}"]
    print(f"Requesting certificate for: {', '.join(domains)}")  # noqa: T201

    async with Client(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        challenge_handler=dns_handler,
        contact=f"mailto:admin@{base_domain}",
        event_dispatcher=dispatcher,
    ) as client:
        bundle = await client.issue(domains, challenge_type="dns-01")

    print("\nCertificate issued successfully!")  # noqa: T201
    print(f"  Domain:    {bundle.domain}")  # noqa: T201
    print(f"  SANs:      {', '.join(bundle.domains)}")  # noqa: T201
    print(f"  Expires:   {bundle.expires_at.isoformat()}")  # noqa: T201

    # Clean up the Cloudflare HTTP client
    await provider.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:  # noqa: PLR2004
        print("Usage: python dns01_cloudflare.py DOMAIN", file=sys.stderr)  # noqa: T201
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
