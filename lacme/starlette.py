"""Starlette integration for lacme ACME certificate management.

Provides a :func:`acme_challenge_route` for serving HTTP-01 challenges
and an :func:`on_startup_issue` helper for auto-issuing at startup.
Requires ``starlette`` (install with ``pip install lacme[starlette]``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    from lacme.challenges.http01 import HTTP01Handler
    from lacme.client import Client

logger = logging.getLogger("lacme.starlette")


def acme_challenge_route(handler: HTTP01Handler) -> Route:
    """Return a Starlette ``Route`` serving HTTP-01 challenge responses.

    Usage::

        from starlette.routing import Route
        from lacme.starlette import acme_challenge_route

        routes = [
            acme_challenge_route(handler),
            Route("/", homepage),
        ]
    """
    from starlette.responses import Response as _Response
    from starlette.routing import Route as _Route

    async def _challenge_endpoint(request: Request) -> Response:
        token = request.path_params["token"]
        key_authz = handler.get_response(token)
        if key_authz is None:
            return _Response("Challenge not found", status_code=404)
        return _Response(
            content=key_authz,
            media_type="application/octet-stream",
        )

    return _Route(
        "/.well-known/acme-challenge/{token}",
        _challenge_endpoint,
        methods=["GET"],
    )


async def on_startup_issue(
    client: Client,
    domains: str | list[str],
    *,
    challenge_type: str = "http-01",
) -> None:
    """Issue a certificate during application startup.

    Intended for use with Starlette's ``on_startup`` hooks::

        app.add_event_handler(
            "startup",
            lambda: on_startup_issue(client, "example.com"),
        )
    """
    bundle = await client.issue(domains, challenge_type=challenge_type)
    logger.info("Issued certificate for %s (expires %s)", bundle.domain, bundle.expires_at)


def configure_app(
    app: Starlette,
    *,
    handler: HTTP01Handler,
) -> None:
    """Add the ACME challenge route to a Starlette app.

    Inserts the challenge route at position 0 (highest priority).
    For auto-issuing at startup, use :func:`on_startup_issue` in
    a lifespan context manager.
    """
    route = acme_challenge_route(handler)
    app.routes.insert(0, route)
