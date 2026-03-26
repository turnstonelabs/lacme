# Framework Integration Guide

lacme integrates with ASGI frameworks to serve HTTP-01 challenge responses
from your running web application, eliminating the need for a standalone
challenge server on port 80.

## Pure ASGI Middleware

`ACMEChallengeMiddleware` works with any ASGI application -- no framework
dependency required. It intercepts requests to
`/.well-known/acme-challenge/{token}` and serves the key authorization from
the challenge handler. All other requests pass through unchanged.

```python
from lacme.asgi import ACMEChallengeMiddleware
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()

# your_app is any ASGI callable
app = ACMEChallengeMiddleware(your_app, handler)
```

Or use the factory function:

```python
from lacme.asgi import challenge_middleware

app = challenge_middleware(your_app, handler)
```

### How It Works

1. A request arrives at the ASGI app
2. If the path starts with `/.well-known/acme-challenge/`, the middleware
   looks up the token in the `HTTP01Handler`
3. If found, it returns the key authorization with status 200 and content
   type `application/octet-stream`
4. If not found, it returns 404
5. All other paths pass through to the inner app

### Full Example

```python
import asyncio
from lacme import Client, FileStore
from lacme.asgi import ACMEChallengeMiddleware
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()

async def my_app(scope, receive, send):
    """Simple ASGI app."""
    if scope["type"] == "http":
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"text/plain"]],
        })
        await send({
            "type": "http.response.body",
            "body": b"Hello, world!",
        })

# Wrap with ACME challenge handling
app = ACMEChallengeMiddleware(my_app, handler)

# Issue a certificate using the same handler
async def issue_cert():
    store = FileStore("~/.lacme")
    async with Client(
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
    ) as client:
        bundle = await client.issue("example.com")
        return bundle
```

## Starlette

lacme provides dedicated Starlette helpers in `lacme.starlette`.

### Challenge Route

Add a route that serves HTTP-01 challenge responses:

```python
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import PlainTextResponse
from lacme.starlette import acme_challenge_route
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()

async def homepage(request):
    return PlainTextResponse("Hello, world!")

app = Starlette(
    routes=[
        acme_challenge_route(handler),
        Route("/", homepage),
    ],
)
```

The route handles `GET /.well-known/acme-challenge/{token}` and returns the
key authorization from the handler, or 404 if the token is not found.

### Startup Issuance

Issue a certificate when the application starts:

```python
from lacme import Client, FileStore
from lacme.starlette import on_startup_issue
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
store = FileStore("~/.lacme")
client = Client(
    store=store,
    challenge_handler=handler,
    contact="mailto:admin@example.com",
)

app = Starlette(
    routes=[
        acme_challenge_route(handler),
        Route("/", homepage),
    ],
    on_startup=[
        lambda: on_startup_issue(client, "example.com"),
    ],
)
```

!!! note
    `on_startup_issue` is an async function. Starlette's `on_startup` hooks
    accept both sync and async callables.

### configure_app()

Insert the challenge route into an existing Starlette app at highest priority:

```python
from lacme.starlette import configure_app

app = Starlette(routes=[Route("/", homepage)])
configure_app(app, handler=handler)
# The challenge route is now at position 0 in app.routes
```

## FastAPI

lacme provides FastAPI-specific helpers in `lacme.ext_fastapi`.

!!! note
    Import from `lacme.ext_fastapi` (not `lacme.fastapi`) to avoid shadowing
    the `fastapi` package.

### Challenge Router

Include a router that serves HTTP-01 challenges:

```python
from fastapi import FastAPI
from lacme.ext_fastapi import acme_challenge_router
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
app = FastAPI()
app.include_router(acme_challenge_router(handler))

@app.get("/")
async def homepage():
    return {"message": "Hello, world!"}
```

### Client Dependency

Use FastAPI's dependency injection to access the lacme client in route handlers:

```python
from fastapi import Depends, FastAPI
from lacme import Client, FileStore
from lacme.ext_fastapi import acme_challenge_router, get_client_dependency
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
store = FileStore("~/.lacme")
client = Client(
    store=store,
    challenge_handler=handler,
    contact="mailto:admin@example.com",
)

get_client = get_client_dependency(client)
app = FastAPI()
app.include_router(acme_challenge_router(handler))

@app.get("/cert-info/{domain}")
async def cert_info(domain: str, acme: Client = Depends(get_client)):
    bundle = store.load_cert(domain)
    if bundle is None:
        return {"error": "No certificate found"}
    return {
        "domain": bundle.domain,
        "expires_at": bundle.expires_at.isoformat(),
    }
```

### Lifespan Issuance

Issue a certificate during the FastAPI lifespan startup phase:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from lacme import Client, FileStore
from lacme.ext_fastapi import acme_challenge_router, lifespan_issue
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
store = FileStore("~/.lacme")
client = Client(
    store=store,
    challenge_handler=handler,
    contact="mailto:admin@example.com",
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Issue certificate at startup
    await lifespan_issue(client, ["example.com", "www.example.com"])
    yield
    # Clean up on shutdown
    await client.close()

app = FastAPI(lifespan=lifespan)
app.include_router(acme_challenge_router(handler))
```

### Complete FastAPI Example

```python
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from lacme import Client, FileStore
from lacme.ext_fastapi import (
    acme_challenge_router,
    get_client_dependency,
    lifespan_issue,
)
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
store = FileStore("~/.lacme")
client = Client(
    store=store,
    challenge_handler=handler,
    contact="mailto:admin@example.com",
)
get_client = get_client_dependency(client)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await lifespan_issue(client, "example.com")
    task = await client.auto_renew(
        interval_hours=12,
        days_before_expiry=30,
    )
    yield
    task.cancel()
    await client.close()

app = FastAPI(lifespan=lifespan)
app.include_router(acme_challenge_router(handler))

@app.get("/")
async def root():
    return {"status": "ok"}

@app.get("/certs")
async def list_certs():
    bundles = store.list_certs()
    return [
        {"domain": b.domain, "expires_at": b.expires_at.isoformat()}
        for b in bundles
    ]
```

## Uvicorn

lacme provides helpers to configure Uvicorn's SSL settings from stored
certificates.

### ssl_kwargs_from_store()

Returns a dict suitable for passing to `uvicorn.run()`:

```python
import uvicorn
from lacme import FileStore
from lacme.uvicorn import ssl_kwargs_from_store

store = FileStore("~/.lacme")

# Returns {"ssl_keyfile": "...", "ssl_certfile": "..."}
ssl_kwargs = ssl_kwargs_from_store(store, "example.com")

uvicorn.run(
    "myapp:app",
    host="0.0.0.0",
    port=443,
    **ssl_kwargs,
)
```

!!! warning
    `ssl_kwargs_from_store` raises `FileNotFoundError` if no certificate is
    stored for the domain, and `ValueError` if the bundle has no file paths
    (e.g., from `MemoryStore`).

### ssl_context_from_store()

For custom SSL configurations or non-Uvicorn ASGI servers:

```python
from lacme.uvicorn import ssl_context_from_store

ctx = ssl_context_from_store(store, "example.com")
# ctx is an ssl.SSLContext with TLSv1.2 minimum
```

### TLS Version

Both helpers create SSL contexts with TLSv1.2 as the minimum version. This is
consistent with modern security requirements and supported by all current
browsers and clients.

### Complete Uvicorn Example

```python
import asyncio
import uvicorn
from lacme import Client, FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.uvicorn import ssl_kwargs_from_store

async def issue_cert():
    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    async with Client(
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
    ) as client:
        # Start HTTP server for challenges
        server = await handler.start_server(port=80)
        try:
            await client.issue("example.com")
        finally:
            server.close()
            await server.wait_closed()

# Issue cert first (HTTP on port 80)
asyncio.run(issue_cert())

# Then run HTTPS on port 443
store = FileStore("~/.lacme")
uvicorn.run(
    "myapp:app",
    host="0.0.0.0",
    port=443,
    **ssl_kwargs_from_store(store, "example.com"),
)
```

### PEM File Helpers

Uvicorn only accepts file paths for SSL configuration, not `ssl.SSLContext` or
in-memory PEM bytes. lacme provides helpers to bridge this gap:

```python
from lacme.mtls import pem_files

with pem_files(bundle, ca_pem=ca.root_cert_pem) as paths:
    uvicorn.run("app:app", **paths.as_uvicorn_kwargs())
# temp files cleaned up automatically
```

For long-lived processes where a context manager is inconvenient:

```python
from lacme.mtls import write_pem_files_persistent

paths = write_pem_files_persistent(bundle, ca_pem=ca.root_cert_pem)
uvicorn.run("app:app", **paths.as_uvicorn_kwargs())
# cleaned up via atexit when process exits
```

!!! note
    To enforce client certificates (mTLS), also pass
    `ssl_cert_reqs=ssl.CERT_REQUIRED` to uvicorn — it defaults to `CERT_NONE`
    even when `ssl_ca_certs` is provided.

## Django

Django is a synchronous framework, so use `SyncClient` for certificate
management. Since Django does not natively run as an ASGI app, you need to
serve challenge responses manually.

### Challenge View

Create a Django view that serves HTTP-01 challenge responses:

```python
# views.py
from django.http import HttpResponse, HttpResponseNotFound
from lacme.challenges.http01 import HTTP01Handler

# Create handler at module level (shared state)
handler = HTTP01Handler()

def acme_challenge(request, token):
    """Serve ACME HTTP-01 challenge responses."""
    key_authz = handler.get_response(token)
    if key_authz is None:
        return HttpResponseNotFound("Challenge not found")
    return HttpResponse(
        key_authz,
        content_type="application/octet-stream",
    )
```

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path(
        ".well-known/acme-challenge/<str:token>",
        views.acme_challenge,
    ),
    # ... your other URLs
]
```

### Issue a Certificate

Use `SyncClient` in a Django management command:

```python
# management/commands/issue_cert.py
from django.core.management.base import BaseCommand
from lacme import SyncClient, FileStore
from myapp.views import handler  # import the shared handler

class Command(BaseCommand):
    help = "Issue a TLS certificate"

    def add_arguments(self, parser):
        parser.add_argument("domains", nargs="+")

    def handle(self, *args, **options):
        store = FileStore("~/.lacme")
        with SyncClient(
            store=store,
            challenge_handler=handler,
            contact="mailto:admin@example.com",
        ) as client:
            bundle = client.issue(options["domains"])
            self.stdout.write(
                f"Certificate issued for {bundle.domain}, "
                f"expires {bundle.expires_at}"
            )
```

```bash
python manage.py issue_cert example.com www.example.com
```

!!! tip
    For production Django deployments, consider issuing certificates separately
    (via the lacme CLI or a cron job) and configuring your reverse proxy
    (nginx, Caddy) to use the certificate files from the store directory.
