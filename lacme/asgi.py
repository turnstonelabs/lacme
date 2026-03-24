"""Pure ASGI middleware for serving HTTP-01 ACME challenge responses.

Intercepts requests to ``/.well-known/acme-challenge/{token}`` and returns
the key authorization from the challenge handler.  All other requests pass
through to the inner application unchanged.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lacme._types import ASGIApp, Receive, Scope, Send
    from lacme.challenges.http01 import HTTP01Handler

_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ACMEChallengeMiddleware:
    """Pure ASGI middleware that serves HTTP-01 challenge responses."""

    def __init__(self, app: ASGIApp, handler: HTTP01Handler) -> None:
        self._app = app
        self._handler = handler

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not path.startswith(_CHALLENGE_PREFIX):
            await self._app(scope, receive, send)
            return

        token = path[len(_CHALLENGE_PREFIX) :]
        if not _TOKEN_RE.match(token):
            await _send_response(send, status=400, body=b"Invalid token")
            return

        key_authz = self._handler.get_response(token)

        if key_authz is None:
            await _send_response(send, status=404, body=b"Challenge not found")
            return

        await _send_response(
            send,
            status=200,
            body=key_authz.encode("ascii"),
            content_type=b"application/octet-stream",
        )


def challenge_middleware(app: ASGIApp, handler: HTTP01Handler) -> ACMEChallengeMiddleware:
    """Wrap an ASGI *app* with ACME HTTP-01 challenge serving."""
    return ACMEChallengeMiddleware(app, handler)


async def _send_response(
    send: Send,
    *,
    status: int,
    body: bytes,
    content_type: bytes = b"text/plain",
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", content_type],
                [b"content-length", str(len(body)).encode()],
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
