"""FastAPI integration for lacme ACME certificate management.

Provides :func:`acme_challenge_router` for serving HTTP-01 challenges
and :func:`get_client_dependency` for FastAPI dependency injection.
Requires ``fastapi`` (install with ``pip install lacme[fastapi]``).

Import from ``lacme.ext_fastapi`` (not ``lacme.fastapi``) to avoid
shadowing the ``fastapi`` package.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi import APIRouter

    from lacme.challenges.http01 import HTTP01Handler
    from lacme.client import Client

logger = logging.getLogger("lacme.ext_fastapi")


def acme_challenge_router(handler: HTTP01Handler) -> APIRouter:
    """Return a FastAPI ``APIRouter`` serving HTTP-01 challenge responses.

    Usage::

        from lacme.ext_fastapi import acme_challenge_router

        app.include_router(acme_challenge_router(handler))
    """
    from fastapi import APIRouter as _APIRouter
    from fastapi.responses import Response as _Response

    router = _APIRouter()

    @router.get("/.well-known/acme-challenge/{token}")  # type: ignore[untyped-decorator]
    async def _challenge_endpoint(token: str) -> _Response:
        key_authz = handler.get_response(token)
        if key_authz is None:
            return _Response(content="Challenge not found", status_code=404)
        return _Response(
            content=key_authz,
            media_type="application/octet-stream",
        )

    return router


def get_client_dependency(client: Client) -> Callable[[], Any]:
    """Create a FastAPI dependency that returns the lacme ``Client``.

    Usage::

        from fastapi import Depends
        from lacme.ext_fastapi import get_client_dependency

        get_client = get_client_dependency(client)

        @app.get("/certs/{domain}")
        async def get_cert(client: Client = Depends(get_client)):
            ...
    """

    async def _dep() -> Client:
        return client

    return _dep


async def lifespan_issue(
    client: Client,
    domains: str | list[str],
    *,
    challenge_type: str = "http-01",
) -> None:
    """Issue a certificate during FastAPI lifespan startup.

    Usage::

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            await lifespan_issue(client, "example.com")
            yield
    """
    bundle = await client.issue(domains, challenge_type=challenge_type)
    logger.info("Issued certificate for %s (expires %s)", bundle.domain, bundle.expires_at)
