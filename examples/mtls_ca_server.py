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
from lacme.store import FileStore

# --- CA Setup ---

store = FileStore("~/.lacme-ca")
ca = CertificateAuthority(store)
ca.init(cn="My Service Mesh CA", validity_days=3650)

print(f"CA root certificate:\n{ca.root_cert_pem.decode()}")  # noqa: T201

# --- ACME Responder ---

# auto_approve=True: skip challenge validation (trusted internal network)
responder = ACMEResponder(ca=ca, auto_approve=True)


# --- Web App ---


async def health(request):  # noqa: ANN001, ANN201
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "ca_initialized": ca.initialized})


async def root_cert(request):  # noqa: ANN001, ANN201
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
