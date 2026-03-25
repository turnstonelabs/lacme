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
        print(f"Certificate issued for {bundle.domain}")  # noqa: T201
        print(f"  Expires: {bundle.expires_at.isoformat()}")  # noqa: T201
        if bundle.fullchain_path:
            print(f"  Fullchain: {bundle.fullchain_path}")  # noqa: T201
        if bundle.key_path:
            print(f"  Key: {bundle.key_path}")  # noqa: T201


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
