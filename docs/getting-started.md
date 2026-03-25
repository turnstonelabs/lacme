# Getting Started

This guide walks you through issuing your first certificate with lacme, starting with the simplest path (private CA, no domain required) and progressing to Let's Encrypt staging.

## Prerequisites

- **Python 3.11 or later**
- **A domain name** (for Let's Encrypt) -- or just localhost (for the private CA path)

## Installation

```bash
pip install lacme
```

This installs lacme and its two runtime dependencies: httpx and cryptography.

## Your First Certificate (Private CA)

The fastest way to see lacme in action is with the built-in Certificate Authority. No domain name, no internet access, no port 80 required.

### 1. Create a CA and issue a certificate

```python
from lacme import CertificateAuthority

ca = CertificateAuthority()
ca.init()

bundle = ca.issue("myapp.local")
```

That is it -- three lines. The CA generates a self-signed root, then signs a server certificate for `myapp.local`.

### 2. Examine the CertBundle

The returned `CertBundle` contains everything you need:

```python
print(bundle.domain)           # "myapp.local"
print(bundle.domains)          # ("myapp.local",)
print(bundle.expires_at)       # datetime, 24 hours from now by default
print(len(bundle.cert_pem))    # PEM-encoded leaf certificate (bytes)
print(len(bundle.key_pem))     # PEM-encoded private key (bytes)
print(len(bundle.fullchain_pem))  # leaf + CA root concatenated (bytes)
```

You can pass `cert_pem` and `key_pem` directly to any server that accepts PEM data, or write them to files. For mTLS, use the `server_ssl_context` and `client_ssl_context` helpers:

```python
from lacme import CertificateAuthority, server_ssl_context, client_ssl_context

ca = CertificateAuthority()
ca.init()

server_cert = ca.issue("myservice.internal")
client_cert = ca.issue("worker-1", client=True)

server_ctx = server_ssl_context(
    cert_pem=server_cert.fullchain_pem,
    key_pem=server_cert.key_pem,
    ca_cert_pem=ca.root_cert_pem,
)
client_ctx = client_ssl_context(
    cert_pem=client_cert.cert_pem,
    key_pem=client_cert.key_pem,
    ca_cert_pem=ca.root_cert_pem,
)
```

## Let's Encrypt Staging

Ready to issue a real certificate? Let's Encrypt's staging environment is rate-limit-free and ideal for testing. You will need a publicly reachable server on port 80 for HTTP-01 validation.

### 1. Set up a FileStore

`FileStore` persists your account key and certificates to disk so they survive restarts:

```python
from lacme import FileStore

store = FileStore("~/.lacme")
```

### 2. Use SyncClient for simplicity

`SyncClient` wraps the async client so you can use it from regular Python scripts:

```python
from lacme import SyncClient, LETSENCRYPT_STAGING_DIRECTORY
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()

client = SyncClient(
    directory_url=LETSENCRYPT_STAGING_DIRECTORY,
    store=store,
    contact="mailto:you@example.com",
    challenge_handler=handler,
)
```

### 3. Issue the certificate

The HTTP-01 handler needs to serve challenge responses on port 80. In a sync context, use the async client's standalone server through a helper, or integrate the handler into your web framework (see the [Framework Integration Guide](guides/frameworks.md)). For a standalone script:

```python
import asyncio
from lacme import Client, LETSENCRYPT_STAGING_DIRECTORY
from lacme import FileStore
from lacme.challenges.http01 import HTTP01Handler

async def main():
    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    async with Client(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        contact="mailto:you@example.com",
        challenge_handler=handler,
    ) as client:
        server = await handler.start_server(port=80)
        try:
            bundle = await client.issue("example.com")
        finally:
            server.close()
            await server.wait_closed()

    print(f"Certificate issued for {bundle.domain}")
    print(f"Expires: {bundle.expires_at.isoformat()}")
    print(f"Cert:    {bundle.cert_path}")
    print(f"Key:     {bundle.key_path}")

asyncio.run(main())
```

### 4. Examine saved files

`FileStore` writes certificates with this layout:

```
~/.lacme/
    account.key
    certs/
        example.com/
            cert.pem
            fullchain.pem
            key.pem
            meta.json
```

Private keys are written with `0o600` permissions. All writes are atomic (write to temp file, fsync, then rename).

## Auto-Renewal

`RenewalManager` scans your certificate store on a schedule and re-issues any certificate approaching expiry:

```python
import asyncio
from lacme import Client, LETSENCRYPT_STAGING_DIRECTORY
from lacme import FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.renewal import RenewalManager

async def main():
    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    async with Client(
        directory_url=LETSENCRYPT_STAGING_DIRECTORY,
        store=store,
        contact="mailto:you@example.com",
        challenge_handler=handler,
    ) as client:
        server = await handler.start_server(port=80)

        manager = RenewalManager(
            client=client,
            store=store,
            interval_hours=12,
            days_before_expiry=30,
        )
        task = manager.start()  # runs in the background

        # Your application runs here...
        await asyncio.sleep(3600)

        await manager.stop()
        server.close()

asyncio.run(main())
```

The manager checks every 12 hours (with random jitter) and renews any certificate expiring within 30 days. You can also pass an `on_renewed` callback to reload your server's TLS context when a certificate is replaced.

## Next Steps

- [ACME Client Guide](guides/acme-client.md) -- account management, EAB, wildcard certs, revocation
- [Private CA & mTLS Guide](guides/private-ca.md) -- ACMEResponder, SSL contexts, cert rotation
- [DNS Providers Guide](guides/dns-providers.md) -- Cloudflare, Route 53, and custom hooks
- [Framework Integration Guide](guides/frameworks.md) -- Starlette, FastAPI, and Uvicorn helpers
- [Observability Guide](guides/observability.md) -- events, logging, and Prometheus metrics
- [CLI Reference](guides/cli.md) -- command-line usage
