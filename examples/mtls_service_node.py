#!/usr/bin/env python3
"""Example: Service node requesting certs from an internal CA.

Demonstrates the Turnstone Bridge/Node-Service pattern:
- Connect to CA server via standard Client
- Issue cert for this node's identity (hostname or IP)
- Auto-renew with RenewalManager
- Build mTLS SSL contexts for serving and connecting

Prerequisites:
    1. Run the CA server: python examples/mtls_ca_server.py
    2. Download root CA cert: curl -o root-ca.pem http://localhost:8443/root-ca.pem

Run:
    pip install lacme
    python examples/mtls_service_node.py
"""

from __future__ import annotations

import asyncio

from lacme import Client, FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.mtls import client_ssl_context, server_ssl_context

CA_SERVER = "http://localhost:8443/acme/directory"
ROOT_CA_PEM = "root-ca.pem"  # Downloaded from CA server
NODE_IDENTITY = "worker-1.internal"


async def main() -> None:
    store = FileStore("~/.lacme-node")
    handler = HTTP01Handler()

    async with Client(
        directory_url=CA_SERVER,
        # ca_bundle=ROOT_CA_PEM,  # Uncomment if CA serves over HTTPS
        allow_insecure=True,  # Allow HTTP for local testing
        store=store,
        challenge_handler=handler,
    ) as client:
        # --- Issue certificate for this node ---
        print(f"Requesting certificate for {NODE_IDENTITY}...")  # noqa: T201
        bundle = await client.issue([NODE_IDENTITY])
        print(f"Certificate issued, expires {bundle.expires_at}")  # noqa: T201

        # --- Build mTLS SSL contexts ---

        # Read root CA cert for trust verification
        with open(ROOT_CA_PEM, "rb") as f:
            ca_cert_pem = f.read()

        # Server context: other nodes must present valid client certs
        _server_ctx = server_ssl_context(
            cert_pem=bundle.fullchain_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca_cert_pem,  # Verify client certs against CA
        )
        print("Server SSL context ready (requires client certs)")  # noqa: T201

        # Client context: present our cert when connecting to other nodes
        _client_ctx = client_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca_cert_pem,  # Verify server certs against CA
        )
        print("Client SSL context ready")  # noqa: T201

        # --- Auto-renew in background ---
        # Certs are short-lived (24h default), so auto-renewal is essential.
        # RenewalManager checks expiry and re-issues before threshold.

        def on_renewed(new_bundle):  # noqa: ANN001, ANN202
            print(f"Certificate renewed, new expiry: {new_bundle.expires_at}")  # noqa: T201
            # In production: rebuild SSL contexts and reload servers

        task = await client.auto_renew(
            interval_hours=12,
            days_before_expiry=1,  # Renew 1 day before expiry (for 24h certs)
            on_renewed=on_renewed,
        )
        print("Auto-renewal started")  # noqa: T201

        # Keep running (in production, your app does real work here)
        try:
            await asyncio.sleep(3600)
        except KeyboardInterrupt:
            task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
