# lacme Documentation

lacme is a modern, async-native Python library for automating TLS certificate management using the ACME protocol (RFC 8555). It is designed to be embedded directly into Python applications -- no subprocess calls, no sidecar daemons, just import and issue.

## Features

**Async-native with sync wrapper.**
The core `Client` is fully async, built on httpx. For blocking code or scripts, `SyncClient` wraps every method with a managed event loop so you can call `client.issue()` without touching asyncio.

**HTTP-01 and DNS-01 challenges.**
`HTTP01Handler` serves challenge responses over a built-in TCP server or via ASGI middleware. `DNS01Handler` delegates record creation to pluggable providers -- Cloudflare, Route 53, and shell-hook providers are included out of the box.

**Built-in Certificate Authority.**
`CertificateAuthority` generates a self-signed root CA and signs server or client certificates on the fly. Useful for mTLS between internal services, dev/test environments, or as the backend for the ACME Responder.

**ACME Responder.**
`ACMEResponder` is a full ASGI application that implements the ACME protocol endpoints. Backed by `CertificateAuthority`, it lets your internal services use the same `Client.issue()` workflow against a private CA -- no public internet required.

**Framework integrations.**
First-class helpers for Starlette (`acme_challenge_route`, `on_startup_issue`), FastAPI (`acme_challenge_router`, `get_client_dependency`), and Uvicorn (`ssl_kwargs_from_store`). Add ACME challenge serving and auto-issuance with a few lines of code.

**CLI tool.**
The `lacme` command provides `issue`, `renew`, `revoke`, and `account` subcommands for managing certificates from the terminal. Supports Let's Encrypt production and staging, DNS provider selection, and configurable storage paths.

**Auto-renewal.**
`RenewalManager` periodically scans your certificate store and re-issues any certificate approaching expiry. It runs as a background asyncio task with configurable intervals and jitter to avoid thundering-herd renewals.

**Rate limit tracking.**
`RateLimitTracker` maintains client-side awareness of Let's Encrypt rate limits (50 certificates per registered domain per week). It warns when approaching the threshold and optionally blocks issuance to prevent hitting the limit.

**Event system and Prometheus metrics.**
`EventDispatcher` emits typed events for certificate issued, renewed, expiring, challenge failed, and rate limit warnings. `MetricsCollector` subscribes to the dispatcher and updates Prometheus counters and gauges automatically.

**MockACMEServer for testing.**
An in-process mock ACME server backed by `httpx.MockTransport`. Implements the full issue flow so you can integration-test your certificate automation without network access or a real CA.

## Installation

=== "pip"

    ```bash
    pip install lacme
    ```

=== "uv"

    ```bash
    uv add lacme
    ```

**Optional extras:**

```bash
pip install lacme[starlette]    # Starlette integration
pip install lacme[fastapi]      # FastAPI integration
pip install lacme[prometheus]   # Prometheus metrics
pip install lacme[aws]          # Route 53 DNS provider (boto3)
pip install lacme[test]         # pytest, hypothesis, anyio
```

## Quick Example

```python
import asyncio
from lacme import Client
from lacme.challenges.http01 import HTTP01Handler

async def main():
    handler = HTTP01Handler()
    async with Client(
        directory_url="https://acme-v02.api.letsencrypt.org/directory",
        contact="mailto:you@example.com",
        challenge_handler=handler,
    ) as client:
        server = await handler.start_server()  # port 80
        bundle = await client.issue("example.com")
        server.close()
        await server.wait_closed()
    print(bundle.fullchain_pem.decode())

asyncio.run(main())
```

## Architecture

lacme is organized around a few core components:

- **`Client`** communicates with an ACME server (Let's Encrypt, ZeroSSL, or any RFC 8555-compliant CA) over HTTPS. It handles account creation, order placement, challenge orchestration, CSR generation, finalization, and certificate download in a single `issue()` call.

- **`CertificateAuthority`** generates a self-signed root CA and signs leaf certificates locally. It does not speak the ACME protocol -- it operates entirely in-process.

- **`ACMEResponder`** bridges the two: it is an ASGI application that exposes ACME protocol endpoints, and delegates certificate signing to a `CertificateAuthority`. Internal services point their `Client` at the responder's directory URL to obtain certificates from the private CA.

- **`Store`** is a protocol for persisting account keys and certificates. `FileStore` writes to disk with atomic operations and restrictive permissions. `MemoryStore` keeps everything in memory for tests.

- **Challenge handlers** (`HTTP01Handler`, `DNS01Handler`) implement the `ChallengeHandler` protocol. The client calls `provision()` before responding to the ACME server and `deprovision()` after validation completes.

## Next Steps

- [Getting Started](getting-started.md) -- issue your first certificate in under 5 minutes
- [ACME Client Guide](guides/acme-client.md) -- deep dive into the async client
- [Private CA & mTLS Guide](guides/private-ca.md) -- set up internal PKI
- [Framework Integration Guide](guides/frameworks.md) -- Starlette, FastAPI, and Uvicorn
- [API Reference](api/client.md) -- full API documentation
