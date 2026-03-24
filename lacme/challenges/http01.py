"""HTTP-01 challenge handler (RFC 8555 §8.3).

Maintains an in-memory token → key authorization mapping and optionally
runs a minimal standalone HTTP server on port 80.
"""

from __future__ import annotations

import asyncio
import logging
import re

logger = logging.getLogger("lacme.challenges.http01")

_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_REQUEST_LINE = 8192


class HTTP01Handler:
    """HTTP-01 challenge handler.

    Satisfies :class:`~lacme.challenges.ChallengeHandler`.
    """

    def __init__(self) -> None:
        self._challenges: dict[str, str] = {}

    # --- ChallengeHandler protocol ---

    async def provision(self, domain: str, token: str, key_authorization: str) -> None:
        logger.debug("Provisioning HTTP-01 for %s (token=%s…)", domain, token[:8])
        self._challenges[token] = key_authorization

    async def deprovision(self, domain: str, token: str) -> None:
        logger.debug("Deprovisioning HTTP-01 for %s (token=%s…)", domain, token[:8])
        self._challenges.pop(token, None)

    # --- Lookup ---

    def get_response(self, token: str) -> str | None:
        """Return the key authorization for *token*, or ``None``."""
        return self._challenges.get(token)

    # --- Standalone server ---

    async def start_server(
        self,
        host: str = "0.0.0.0",  # noqa: S104
        port: int = 80,
    ) -> asyncio.Server:
        """Start a minimal HTTP server serving ACME challenge responses.

        Returns the :class:`asyncio.Server` so the caller can close it.
        Use ``port=0`` in tests to let the OS pick an available port.
        """
        server = await asyncio.start_server(self._handle_connection, host, port)
        logger.info("HTTP-01 standalone server listening on %s:%d", host, port)
        return server

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single HTTP connection — minimal HTTP/1.1 parser."""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not request_line:
                return

            if len(request_line) > _MAX_REQUEST_LINE:
                writer.write(b"HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\n\r\n")
                return

            line = request_line.decode("ascii", errors="replace").strip()
            parts = line.split(" ")
            if len(parts) < 2:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return

            method, path = parts[0], parts[1]

            # Drain remaining headers before responding (capped for safety)
            for _ in range(100):
                header_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if header_line in (b"\r\n", b"\n", b""):
                    break

            if method == "GET" and path.startswith(_CHALLENGE_PREFIX):
                token = path[len(_CHALLENGE_PREFIX) :]
                if not _TOKEN_RE.match(token):
                    writer.write(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                    )
                    return
                key_authz = self.get_response(token)
                if key_authz is not None:
                    body = key_authz.encode("ascii")
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/octet-stream\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                        b"\r\n" + body
                    )
                else:
                    writer.write(
                        b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    )
            else:
                writer.write(
                    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
        except (
            TimeoutError,
            ConnectionError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
        ):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
