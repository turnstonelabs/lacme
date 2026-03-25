# lacme

[![CI](https://github.com/turnstonelabs/lacme/actions/workflows/ci.yml/badge.svg)](https://github.com/turnstonelabs/lacme/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/lacme)](https://pypi.org/project/lacme/)
[![Python](https://img.shields.io/pypi/pyversions/lacme)](https://pypi.org/project/lacme/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

Modern, async-native Python ACME client library for embedding TLS certificate automation.

## What is lacme?

lacme fills the gap between full-featured CLI tools like certbot (not designed for embedding) and low-level ACME protocol libraries that leave orchestration to you. It provides a high-level `Client.issue()` one-liner alongside full access to every step of the ACME workflow. lacme has just two runtime dependencies -- httpx and cryptography -- and supports Python 3.11+.

## Features

- **Async-native with sync wrapper** -- `Client` for asyncio, `SyncClient` for blocking code
- **HTTP-01 and DNS-01 challenges** -- built-in handlers with pluggable DNS providers (Cloudflare, Route 53, shell hooks)
- **Built-in Certificate Authority** -- `CertificateAuthority` for issuing private CA certs, ideal for mTLS
- **ACME Responder** -- `ACMEResponder` ASGI app backed by the built-in CA for internal PKI
- **Framework integrations** -- first-class support for Starlette, FastAPI, and Uvicorn
- **CLI tool** -- `lacme issue`, `lacme renew`, `lacme revoke` from the command line
- **Auto-renewal** -- `RenewalManager` runs in the background and re-issues expiring certificates
- **Rate limit tracking** -- client-side awareness of Let's Encrypt rate limits with warnings and blocking
- **Event system + Prometheus metrics** -- `EventDispatcher` with typed events; optional `MetricsCollector`
- **`MockACMEServer` for testing** -- in-process mock ACME server via `httpx.MockTransport`

## Quick Start

```bash
pip install lacme
```

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

## Private CA / mTLS

```python
from lacme import CertificateAuthority, client_ssl_context, server_ssl_context

ca = CertificateAuthority()
ca.init()

server_cert = ca.issue("myservice.internal")
client_cert = ca.issue("worker-1", client=True)

server_ctx = server_ssl_context(
    cert_pem=server_cert.fullchain_pem,
    key_pem=server_cert.key_pem,
    ca_cert_pem=ca.root_cert_pem,  # require client certs
)
client_ctx = client_ssl_context(
    cert_pem=client_cert.cert_pem,
    key_pem=client_cert.key_pem,
    ca_cert_pem=ca.root_cert_pem,
)
```

## CLI

```bash
# Issue a certificate via Let's Encrypt staging
lacme --staging --contact you@example.com issue example.com

# Renew all certificates expiring within 30 days
lacme renew --days 30

# Revoke a certificate
lacme revoke example.com
```

## Documentation

Full documentation is available at [turnstonelabs.github.io/lacme](https://turnstonelabs.github.io/lacme/).

## License

Apache-2.0
