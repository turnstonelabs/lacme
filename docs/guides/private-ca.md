# Private CA & mTLS Guide

This guide walks through setting up a lightweight internal Certificate Authority
using lacme's `CertificateAuthority` and `ACMEResponder`. Service nodes request
certificates through the standard ACME protocol, enabling mutual TLS (mTLS)
across your infrastructure without any external CA dependency.

## Architecture

```
                          ┌─────────────────────────┐
                          │     Console CA Server    │
                          │                         │
                          │  CertificateAuthority   │
                          │         +               │
                          │  ACMEResponder (ASGI)   │
                          │         +               │
                          │  /root-ca.pem endpoint  │
                          └────────┬────────────────┘
                                   │
                    ACME protocol  │  (HTTP or HTTPS)
                    over trusted   │
                    network        │
                 ┌─────────────────┼─────────────────┐
                 │                 │                  │
        ┌────────▼──────┐  ┌──────▼───────┐  ┌──────▼───────┐
        │  Service Node │  │ Service Node  │  │ Service Node │
        │    (worker-1) │  │   (worker-2)  │  │   (worker-3) │
        │               │  │               │  │              │
        │  Client +     │  │  Client +     │  │  Client +    │
        │  auto_renew() │  │  auto_renew() │  │  auto_renew()│
        └───────────────┘  └──────────────-┘  └──────────────┘
                 │                 │                  │
                 └─────── mTLS connections ──────────┘
```

Each service node uses the standard lacme `Client` to request certificates from
the CA server, then builds SSL contexts for mutual TLS communication with peers.

## Step 1: Initialize the CA

Create a `CertificateAuthority` backed by a `FileStore` for persistence:

```python
from lacme import CertificateAuthority, FileStore

store = FileStore("~/.lacme-ca")
ca = CertificateAuthority(store, name="turnstone")
ca.init(cn="My Service Mesh CA", validity_days=3650)
```

The optional `name` parameter (default `"root"`) controls the store key used
by `save_ca()`/`load_ca()`. This allows multiple CAs in the same store (e.g.,
one for mTLS, one for client-only certs).

The `init()` method either loads an existing root CA from the store or generates
a new self-signed root certificate. The root CA uses a P-256 EC key and is valid
for the specified number of days (10 years by default).

!!! note
    If the store already contains a root CA (from a previous run), `init()`
    loads it rather than generating a new one. This means you can safely call
    `init()` on every server startup.

### CA Parameters

| Parameter        | Default                  | Description                        |
|------------------|--------------------------|------------------------------------|
| `cn`             | `"lacme Internal CA"`    | Common Name for the root certificate |
| `validity_days`  | `3650`                   | Root CA validity period in days    |

## Step 2: Mount the ACME Responder

The `ACMEResponder` is a pure ASGI application that implements the ACME protocol
endpoints. Mount it in your web framework (Starlette, FastAPI, etc.):

```python
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse
from lacme import ACMEResponder, CertificateAuthority, FileStore

store = FileStore("~/.lacme-ca")
ca = CertificateAuthority(store)
ca.init(cn="My Service Mesh CA", validity_days=3650)

# auto_approve=True: skip challenge validation on trusted networks
responder = ACMEResponder(ca=ca, auto_approve=True)

async def health(request):
    return JSONResponse({"status": "ok", "ca_initialized": ca.initialized})

app = Starlette(
    routes=[
        Route("/health", health),
        Mount("/acme", app=responder),
    ],
)
```

Service nodes connect to `http://ca-server:8443/acme/directory` as their
ACME directory URL.

The responder also serves the CA root certificate at `GET /ca.pem`, so service
nodes can fetch it during bootstrapping:

```bash
curl -o root-ca.pem https://console:8443/acme/ca.pem
```

### Challenge Validation

The responder supports three modes:

**`auto_approve=True`** -- Immediately validates all challenges. Use this when
the CA and service nodes share a trusted network (the most common case for
internal CAs):

```python
responder = ACMEResponder(ca=ca, auto_approve=True)
```

**Custom `ChallengeValidator`** -- Implement the `ChallengeValidator` protocol
for custom validation logic:

```python
from lacme import ChallengeValidator

class MyValidator:
    async def validate(
        self,
        identifier: str,
        identifier_type: str,
        token: str,
        key_authorization: str,
    ) -> bool:
        # Custom validation logic (e.g., check DNS ownership)
        allowed_hosts = {"worker-1.internal", "worker-2.internal"}
        return identifier in allowed_hosts

responder = ACMEResponder(
    ca=ca,
    challenge_validator=MyValidator(),
)
```

**Neither** -- Challenges remain in "processing" state. You must approve them
out-of-band (rarely used).

!!! warning
    The ACME responder does **not** verify JWS signatures or validate nonces.
    It is designed for trusted internal networks where transport-level security
    (private network, firewall rules, or mTLS) provides authentication.
    Do not expose it to untrusted clients without additional auth middleware.

## Step 3: Distribute the Root Certificate

Service nodes need the CA's root certificate to verify peer certificates.
Serve it from the CA server:

```python
from starlette.responses import Response

async def root_cert(request):
    return Response(
        content=ca.root_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=root-ca.pem"},
    )

# Add to your Starlette routes:
Route("/root-ca.pem", root_cert),
```

Service nodes download the root certificate at startup:

```bash
curl -o root-ca.pem http://ca-server:8443/root-ca.pem
```

Or fetch it programmatically:

```python
import httpx

resp = httpx.get("http://ca-server:8443/root-ca.pem")
root_ca_pem = resp.content
with open("root-ca.pem", "wb") as f:
    f.write(root_ca_pem)
```

## Step 4: Service Nodes Request Certificates

Each service node uses the standard lacme `Client` to request a certificate
from the CA:

```python
import asyncio
from lacme import Client, FileStore
from lacme.challenges.http01 import HTTP01Handler

CA_DIRECTORY = "http://ca-server:8443/acme/directory"

async def main():
    store = FileStore("~/.lacme-node")
    handler = HTTP01Handler()

    async with Client(
        directory_url=CA_DIRECTORY,
        allow_insecure=True,  # HTTP on trusted network
        store=store,
        challenge_handler=handler,
    ) as client:
        bundle = await client.issue("worker-1.internal")
        print(f"Certificate issued, expires {bundle.expires_at}")

asyncio.run(main())
```

!!! tip
    If the CA server uses HTTPS with the internal CA's own certificate, pass
    `ca_bundle` instead of `allow_insecure`:

    ```python
    async with Client(
        directory_url="https://ca-server:8443/acme/directory",
        ca_bundle="/path/to/root-ca.pem",
        store=store,
        challenge_handler=handler,
    ) as client:
        bundle = await client.issue("worker-1.internal")
    ```

## Step 5: Build mTLS SSL Contexts

Once a service node has its certificate and the root CA cert, build SSL
contexts for mutual TLS:

```python
from lacme.mtls import server_ssl_context, client_ssl_context

# Read the root CA certificate
with open("root-ca.pem", "rb") as f:
    ca_cert_pem = f.read()

# Server context: serve TLS and require client certificates
server_ctx = server_ssl_context(
    cert_pem=bundle.fullchain_pem,
    key_pem=bundle.key_pem,
    ca_cert_pem=ca_cert_pem,     # Verify connecting clients
)

# Client context: present our cert when connecting to peers
client_ctx = client_ssl_context(
    cert_pem=bundle.cert_pem,
    key_pem=bundle.key_pem,
    ca_cert_pem=ca_cert_pem,     # Verify the server we connect to
)
```

### Using with asyncio

```python
import asyncio
import ssl

# Start a TLS server
server = await asyncio.start_server(
    handle_client,
    host="0.0.0.0",
    port=8443,
    ssl=server_ctx,
)

# Connect to a peer with mTLS
reader, writer = await asyncio.open_connection(
    "worker-2.internal",
    8443,
    ssl=client_ctx,
)
```

### Using with aiohttp

```python
import aiohttp

# Server
from aiohttp import web
app = web.Application()
web.run_app(app, ssl_context=server_ctx)

# Client
async with aiohttp.ClientSession() as session:
    async with session.get(
        "https://worker-2.internal:8443/api",
        ssl=client_ctx,
    ) as resp:
        data = await resp.json()
```

### PEM Data vs File Paths

Both `server_ssl_context()` and `client_ssl_context()` accept PEM data as
`bytes`, file paths as `str`, or `pathlib.Path` objects:

```python
# Using in-memory PEM bytes (from CertBundle)
ctx = server_ssl_context(
    cert_pem=bundle.fullchain_pem,   # bytes
    key_pem=bundle.key_pem,          # bytes
    ca_cert_pem=ca_cert_pem,         # bytes
)

# Using file paths (from FileStore)
ctx = server_ssl_context(
    cert_pem=str(bundle.fullchain_path),   # str path
    key_pem=str(bundle.key_path),          # str path
    ca_cert_pem="/etc/pki/root-ca.pem",    # str path
)
```

!!! note
    When PEM `bytes` are passed, lacme writes them to a temporary file
    (with 0o600 permissions) for the SSL context to load, then cleans up
    the file immediately. All SSL contexts enforce TLSv1.2 minimum.

## Step 6: Auto-Renewal on Service Nodes

Internal CA certificates are typically short-lived (24 hours by default).
Auto-renewal keeps them fresh:

```python
async with Client(
    directory_url=CA_DIRECTORY,
    allow_insecure=True,
    store=store,
    challenge_handler=handler,
) as client:
    # Issue initial certificate
    bundle = await client.issue("worker-1.internal")

    # Rebuild SSL contexts when certificates renew
    def on_renewed(new_bundle):
        nonlocal server_ctx, client_ctx
        server_ctx = server_ssl_context(
            cert_pem=new_bundle.fullchain_pem,
            key_pem=new_bundle.key_pem,
            ca_cert_pem=ca_cert_pem,
        )
        client_ctx = client_ssl_context(
            cert_pem=new_bundle.cert_pem,
            key_pem=new_bundle.key_pem,
            ca_cert_pem=ca_cert_pem,
        )
        print(f"Renewed: {new_bundle.domain}, expires {new_bundle.expires_at}")

    # Check every 12 hours, renew 1 day before expiry
    task = await client.auto_renew(
        interval_hours=12,
        days_before_expiry=1,
        on_renewed=on_renewed,
    )

    # Run your application...
    try:
        await serve_forever()
    finally:
        task.cancel()
```

### CA-Direct Renewal (Same Process)

When the CA and renewal manager run in the same process, you can skip the ACME
round-trip entirely by passing `ca` instead of `client`:

```python
from lacme import CertificateAuthority, RenewalManager, FileStore

store = FileStore("~/.lacme")
ca = CertificateAuthority(store)
ca.init()

# Issue initial cert
ca.issue("api.internal")

# Renew directly — no ACME responder or network needed
manager = RenewalManager(ca=ca, store=store, days_before_expiry=1)
task = manager.start()
```

This eliminates the startup ordering dependency (responder doesn't need to be
running before renewal starts) and avoids the network round-trip.

## Short-Lived Certificates

The internal CA issues certificates with short validity periods by default:

| Parameter         | Default | Description                        |
|-------------------|---------|------------------------------------|
| `validity_days`   | `1`     | Certificate validity in days       |
| `validity_hours`  | `None`  | Override validity in hours         |

Short-lived certificates provide several security benefits:

- **No revocation infrastructure needed** -- certificates expire before
  revocation would typically propagate
- **Reduced blast radius** -- a compromised key is only valid for hours,
  not months
- **Forced rotation** -- services must regularly prove they can still
  authenticate with the CA

For direct CA issuance (without the ACME protocol), you can specify validity
explicitly:

```python
# Issue a 24-hour certificate (has both serverAuth + clientAuth EKU)
bundle = ca.issue("worker-1.internal", validity_hours=24)

# Issue a client-only certificate (clientAuth EKU only)
client_bundle = ca.issue(
    "worker-1.internal",
    client=True,
    validity_hours=6,
)
```

!!! note
    By default, `ca.issue()` includes **both** `serverAuth` and `clientAuth` in the
    Extended Key Usage extension. This is standard for mTLS deployments where the same
    cert is used as a server cert (uvicorn TLS listener) and a client cert (connecting
    to other services). Pass `client=True` only when you need a client-only cert.

!!! tip
    A common rotation strategy: issue 24-hour certificates and set the renewal
    threshold to 1 day (`days_before_expiry=1`). This ensures certificates are
    always renewed before they expire, with a comfortable margin for transient
    failures.

## Security Notes

- **Trusted network assumption**: The `ACMEResponder` does not verify JWS
  signatures. Any client that can reach the responder can request certificates.
  Restrict access with firewall rules or deploy on a private network.

- **auto_approve mode**: When `auto_approve=True`, all certificate requests
  are fulfilled immediately. Only use this on networks where every client
  is trusted.

- **Root CA key protection**: The CA private key is stored in the `FileStore`
  with 0o600 permissions. In production, consider using a Hardware Security
  Module (HSM) or a secrets manager, and implementing a custom `Store` that
  delegates to it.

- **No CRL/OCSP**: The internal CA does not support Certificate Revocation
  Lists or OCSP. Short-lived certificates are the intended mitigation --
  keep validity periods short enough that revocation is unnecessary.

## Complete Example

### CA Server (`ca_server.py`)

```python
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from lacme import ACMEResponder, CertificateAuthority, FileStore

store = FileStore("~/.lacme-ca")
ca = CertificateAuthority(store)
ca.init(cn="My Service Mesh CA", validity_days=3650)

responder = ACMEResponder(ca=ca, auto_approve=True)

async def health(request):
    return JSONResponse({"status": "ok"})

async def root_cert(request):
    return Response(
        content=ca.root_cert_pem,
        media_type="application/x-pem-file",
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

### Service Node (`service_node.py`)

```python
import asyncio
from lacme import Client, FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.mtls import client_ssl_context, server_ssl_context

CA_DIRECTORY = "http://localhost:8443/acme/directory"
ROOT_CA_PEM = "root-ca.pem"
NODE_IDENTITY = "worker-1.internal"

async def main():
    store = FileStore("~/.lacme-node")
    handler = HTTP01Handler()

    async with Client(
        directory_url=CA_DIRECTORY,
        allow_insecure=True,
        store=store,
        challenge_handler=handler,
    ) as client:
        bundle = await client.issue(NODE_IDENTITY)

        with open(ROOT_CA_PEM, "rb") as f:
            ca_cert_pem = f.read()

        srv_ctx = server_ssl_context(
            cert_pem=bundle.fullchain_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca_cert_pem,
        )

        cli_ctx = client_ssl_context(
            cert_pem=bundle.cert_pem,
            key_pem=bundle.key_pem,
            ca_cert_pem=ca_cert_pem,
        )

        def on_renewed(new_bundle):
            print(f"Renewed: {new_bundle.domain}")

        task = await client.auto_renew(
            interval_hours=12,
            days_before_expiry=1,
            on_renewed=on_renewed,
        )

        try:
            await asyncio.sleep(3600)
        finally:
            task.cancel()

asyncio.run(main())
```
