# Examples

Complete, runnable examples demonstrating common lacme workflows. Each example
is self-contained and can be copied directly into your project.

---

## Internal CA Server

**File:** `examples/mtls_ca_server.py`

Sets up a `CertificateAuthority` with `FileStore` persistence, mounts an
`ACMEResponder` as a Starlette ASGI app, and serves the root CA certificate
for distribution to service nodes. This is the server half of the mTLS pattern.

```python
#!/usr/bin/env python3
"""Example: Internal CA server using CertificateAuthority + ACMEResponder.

Demonstrates the Turnstone Console pattern:
- Initialize a CA with a FileStore for persistence and audit
- Mount ACMEResponder as an ASGI app
- Service nodes connect with standard lacme Client

Run:
    pip install lacme uvicorn starlette
    python examples/mtls_ca_server.py

Service nodes then use (for local testing over HTTP):
    Client(directory_url="http://localhost:8443/acme/directory", allow_insecure=True, ...)
"""

from __future__ import annotations

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from lacme.acme_server import ACMEResponder
from lacme.ca import CertificateAuthority
from lacme import FileStore

# --- CA Setup ---

store = FileStore("~/.lacme-ca")
ca = CertificateAuthority(store)
ca.init(cn="My Service Mesh CA", validity_days=3650)

print(f"CA root certificate:\n{ca.root_cert_pem.decode()}")

# --- ACME Responder ---

# auto_approve=True: skip challenge validation (trusted internal network)
responder = ACMEResponder(ca=ca, auto_approve=True)


# --- Web App ---


async def health(request):
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "ca_initialized": ca.initialized})


async def root_cert(request):
    """Serve the CA root certificate for distribution to nodes."""
    from starlette.responses import Response

    return Response(
        content=ca.root_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=root-ca.pem"},
    )


app = Starlette(
    routes=[
        Route("/health", health),
        Route("/root-ca.pem", root_cert),
        Mount("/acme", app=responder),
    ],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8443)
```

---

## Service Node with Auto-Renewal

**File:** `examples/mtls_service_node.py`

Connects to the internal CA server, issues a certificate for the node's identity,
builds mTLS SSL contexts for both server and client roles, and starts background
auto-renewal. This is the client half of the mTLS pattern.

```python
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
        print(f"Requesting certificate for {NODE_IDENTITY}...")
        bundle = await client.issue([NODE_IDENTITY])
        print(f"Certificate issued, expires {bundle.expires_at}")

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
        print("Server SSL context ready (requires client certs)")

        # Client context: present our cert when connecting to other nodes
        _client_ctx = client_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca_cert_pem,  # Verify server certs against CA
        )
        print("Client SSL context ready")

        # --- Auto-renew in background ---
        # Certs are short-lived (24h default), so auto-renewal is essential.
        # RenewalManager checks expiry and re-issues before threshold.

        def on_renewed(new_bundle):
            print(f"Certificate renewed, new expiry: {new_bundle.expires_at}")
            # In production: rebuild SSL contexts and reload servers

        task = await client.auto_renew(
            interval_hours=12,
            days_before_expiry=1,  # Renew 1 day before expiry (for 24h certs)
            on_renewed=on_renewed,
        )
        print("Auto-renewal started")

        # Keep running (in production, your app does real work here)
        try:
            await asyncio.sleep(3600)
        except KeyboardInterrupt:
            task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Let's Encrypt HTTP-01

**File:** `examples/letsencrypt_http01.py`

The simplest possible lacme workflow: create a `FileStore`, an `HTTP01Handler`,
and use `SyncClient` to issue a certificate from Let's Encrypt staging. This
is the starting point for most public-facing web servers.

```python
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

    print(f"Certificate issued for {bundle.domain}")
    print(f"  Domains:   {', '.join(bundle.domains)}")
    print(f"  Expires:   {bundle.expires_at.isoformat()}")
    if bundle.cert_path:
        print(f"  Cert:      {bundle.cert_path}")
    if bundle.fullchain_path:
        print(f"  Fullchain: {bundle.fullchain_path}")
    if bundle.key_path:
        print(f"  Key:       {bundle.key_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python letsencrypt_http01.py DOMAIN [DOMAIN ...]", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1:])
```

---

## DNS-01 with Cloudflare

**File:** `examples/dns01_cloudflare.py`

Issues a wildcard certificate using DNS-01 validation with the Cloudflare DNS
provider. Demonstrates the async `Client`, `CloudflareDNSProvider`, and
`EventDispatcher` for real-time visibility into the issuance process.

```python
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
        lambda e: print(f"  [event] Issued: {e.domain}, expires {e.expires_at}"),
        event_type=CertificateIssued,
    )
    dispatcher.subscribe(
        lambda e: print(f"  [event] Challenge failed: {e.domain} ({e.error})"),
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
    print(f"Requesting certificate for: {', '.join(domains)}")

    async with Client(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        challenge_handler=dns_handler,
        contact=f"mailto:admin@{base_domain}",
        event_dispatcher=dispatcher,
    ) as client:
        bundle = await client.issue(domains, challenge_type="dns-01")

    print(f"\nCertificate issued successfully!")
    print(f"  Domain:    {bundle.domain}")
    print(f"  SANs:      {', '.join(bundle.domains)}")
    print(f"  Expires:   {bundle.expires_at.isoformat()}")

    # Clean up the Cloudflare HTTP client
    await provider.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python dns01_cloudflare.py DOMAIN", file=sys.stderr)
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
```

---

## FastAPI Integration

**File:** `examples/fastapi_acme.py`

A FastAPI application that serves HTTP-01 challenge responses through a route
and issues a certificate at startup. Demonstrates how to integrate lacme into
an existing web framework.

```python
#!/usr/bin/env python3
"""Example: FastAPI application with ACME HTTP-01 challenge endpoint.

Demonstrates:
- Serving HTTP-01 challenge responses through FastAPI
- Issuing a certificate at application startup
- Using the certificate to configure HTTPS

Run:
    pip install lacme fastapi uvicorn
    python examples/fastapi_acme.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

from lacme import Client, FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.client import LETSENCRYPT_STAGING_DIRECTORY

DOMAIN = "example.com"
handler = HTTP01Handler()
store = FileStore("~/.lacme")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Issue a certificate at startup using the HTTP-01 handler."""
    # Start issuing in the background so the server can respond to challenges
    task = asyncio.create_task(_issue_certificate())
    yield
    task.cancel()


async def _issue_certificate() -> None:
    """Background task: wait briefly for the server to start, then issue."""
    await asyncio.sleep(1.0)  # Give the server a moment to bind

    async with Client(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
    ) as client:
        bundle = await client.issue([DOMAIN])
        print(f"Certificate issued for {bundle.domain}")
        print(f"  Expires: {bundle.expires_at.isoformat()}")
        if bundle.fullchain_path:
            print(f"  Fullchain: {bundle.fullchain_path}")
        if bundle.key_path:
            print(f"  Key: {bundle.key_path}")


app = FastAPI(title="ACME Example", lifespan=lifespan)


@app.get("/.well-known/acme-challenge/{token}")
async def acme_challenge(token: str) -> Response:
    """Serve ACME HTTP-01 challenge responses."""
    key_authz = handler.get_response(token)
    if key_authz is None:
        return PlainTextResponse("Not found", status_code=404)
    return PlainTextResponse(key_authz)


@app.get("/")
async def index(request: Request) -> dict[str, str]:
    """Application root."""
    return {"status": "ok", "domain": DOMAIN}


if __name__ == "__main__":
    import uvicorn

    # Start on port 80 (HTTP-01 requires it) - needs root/sudo
    uvicorn.run(app, host="0.0.0.0", port=80)
```

---

## Prometheus Metrics

**File:** `examples/prometheus_metrics.py`

Wires up `EventDispatcher` with `setup_metrics()` to track certificate lifecycle
events as Prometheus counters and gauges. Uses `MockACMEServer` so it runs
without network access.

```python
#!/usr/bin/env python3
"""Example: Prometheus metrics integration with lacme.

Demonstrates:
- Setting up EventDispatcher + MetricsCollector
- Issuing a certificate against MockACMEServer
- Reading the resulting Prometheus counter values

Run:
    pip install lacme prometheus-client
    python examples/prometheus_metrics.py
"""

from __future__ import annotations

import asyncio

from prometheus_client import CollectorRegistry

from lacme import Client, EventDispatcher, MemoryStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.crypto import generate_ec_key
from lacme.metrics import setup_metrics
from lacme.testing import MockACMEServer


async def main() -> None:
    # --- Use a dedicated registry to avoid global state ---
    registry = CollectorRegistry()

    # --- Wire up events + metrics ---
    dispatcher = EventDispatcher()
    metrics = setup_metrics(dispatcher, registry=registry)

    # --- Create an in-process mock ACME server ---
    server = MockACMEServer()
    transport = server.as_transport()

    import httpx

    http = httpx.AsyncClient(transport=transport, base_url="https://acme.test")

    # --- Issue a certificate ---
    store = MemoryStore()
    handler = HTTP01Handler()
    account_key = generate_ec_key()

    async with Client(
        directory_url="https://acme.test/directory",
        http_client=http,
        account_key=account_key,
        store=store,
        challenge_handler=handler,
        event_dispatcher=dispatcher,
    ) as client:
        bundle = await client.issue(["example.com", "www.example.com"])
        print(f"Certificate issued for: {', '.join(bundle.domains)}")
        print(f"  Expires: {bundle.expires_at.isoformat()}")

    # --- Read Prometheus metrics ---
    issued_count = metrics.certificates_issued.labels(domain="example.com")._value.get()
    print(f"\nPrometheus metrics:")
    print(f"  lacme_certificates_issued_total{{domain='example.com'}} = {issued_count}")

    # Issue a second cert to see the counter increment
    http = httpx.AsyncClient(transport=transport, base_url="https://acme.test")
    async with Client(
        directory_url="https://acme.test/directory",
        http_client=http,
        account_key=account_key,
        store=store,
        challenge_handler=handler,
        event_dispatcher=dispatcher,
    ) as client:
        await client.issue(["api.example.com"])

    issued_api = metrics.certificates_issued.labels(domain="api.example.com")._value.get()
    print(f"  lacme_certificates_issued_total{{domain='api.example.com'}} = {issued_api}")


if __name__ == "__main__":
    asyncio.run(main())
```
