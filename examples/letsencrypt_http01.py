#!/usr/bin/env python3
"""Example: Issue a certificate from Let's Encrypt staging via HTTP-01.

The simplest possible lacme workflow:
1. Create a FileStore for persistence
2. Create an HTTP01Handler to serve challenge tokens
3. Use SyncClient to issue a certificate

Prerequisites:
    - Domain must point to the machine running this script
    - Port 80 must be available (HTTP-01 requires it)

Run:
    pip install lacme
    python examples/letsencrypt_http01.py example.com
"""

from __future__ import annotations

import sys

from lacme import LETSENCRYPT_STAGING_DIRECTORY, FileStore, SyncClient
from lacme.challenges.http01 import HTTP01Handler


def main(domains: list[str]) -> None:
    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    with SyncClient(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
    ) as client:
        bundle = client.issue(domains)

    print(f"Certificate issued for {bundle.domain}")  # noqa: T201
    print(f"  Domains:   {', '.join(bundle.domains)}")  # noqa: T201
    print(f"  Expires:   {bundle.expires_at.isoformat()}")  # noqa: T201
    if bundle.cert_path:
        print(f"  Cert:      {bundle.cert_path}")  # noqa: T201
    if bundle.fullchain_path:
        print(f"  Fullchain: {bundle.fullchain_path}")  # noqa: T201
    if bundle.key_path:
        print(f"  Key:       {bundle.key_path}")  # noqa: T201


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python letsencrypt_http01.py DOMAIN [DOMAIN ...]", file=sys.stderr)  # noqa: T201
        sys.exit(1)
    main(sys.argv[1:])
