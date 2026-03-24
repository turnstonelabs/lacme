"""Synchronous wrapper around the async :class:`~lacme.client.Client`.

Provides :class:`SyncClient`, a blocking interface that delegates every
operation to the async ``Client`` through a managed event loop.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, runtime_checkable

from lacme.client import LETSENCRYPT_DIRECTORY, Client
from lacme.models import IdentifierType

logger = logging.getLogger("lacme.sync")

if TYPE_CHECKING:
    from collections.abc import Coroutine
    from types import TracebackType

    import httpx
    from cryptography.hazmat.primitives.asymmetric import ec

    from lacme._types import CertBundle
    from lacme.challenges import ChallengeHandler
    from lacme.events import EventDispatcher
    from lacme.models import Account, Authorization, Challenge, Directory, Order
    from lacme.store import Store

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Sync challenge handler protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SyncChallengeHandler(Protocol):
    """Synchronous protocol for ACME challenge provisioning and cleanup."""

    def provision(self, domain: str, token: str, key_authorization: str) -> None:
        """Make the challenge response available for validation."""
        ...

    def deprovision(self, domain: str, token: str) -> None:
        """Remove the challenge response after validation completes."""
        ...


# ---------------------------------------------------------------------------
# Internal adapter: sync handler -> async handler
# ---------------------------------------------------------------------------


class _SyncToAsyncAdapter:
    """Wraps a :class:`SyncChallengeHandler` to satisfy the async
    :class:`~lacme.challenges.ChallengeHandler` protocol.

    Sync methods are run in the default executor to avoid blocking
    the event loop.
    """

    def __init__(self, handler: SyncChallengeHandler) -> None:
        self._handler = handler

    async def provision(self, domain: str, token: str, key_authorization: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._handler.provision, domain, token, key_authorization)

    async def deprovision(self, domain: str, token: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._handler.deprovision, domain, token)


# ---------------------------------------------------------------------------
# Internal async runner
# ---------------------------------------------------------------------------


class _AsyncRunner:
    """Manages an event loop for running coroutines synchronously.

    Two modes:

    * **Runner mode** — no event loop is running in the current thread;
      uses :class:`asyncio.Runner` (Python 3.11+).
    * **Thread mode** — an event loop is already running (e.g. inside
      Jupyter); starts a background thread with its own loop and uses
      :func:`asyncio.run_coroutine_threadsafe`.
    """

    def __init__(self) -> None:
        self._runner: asyncio.Runner | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._is_open = False

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        """Start the runner or background loop thread."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — use Runner mode.
            self._runner = asyncio.Runner()
            self._runner.__enter__()
            self._is_open = True
            return

        # A loop is already running — use thread mode.
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._is_open = True

    def _check_open(self) -> None:
        """Raise if the runner is not open.  Call BEFORE creating coroutines."""
        if not self._is_open:
            msg = "_AsyncRunner is not open"
            raise RuntimeError(msg)

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run *coro* and return its result, blocking the calling thread."""
        if not self._is_open:
            coro.close()  # Prevent RuntimeWarning for un-awaited coroutine
            msg = "_AsyncRunner is not open"
            raise RuntimeError(msg)
        if self._runner is not None:
            return self._runner.run(coro)
        if self._loop is not None and self._thread is not None:
            future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            return future.result()
        msg = "_AsyncRunner is in an inconsistent state"
        raise RuntimeError(msg)

    def close(self) -> None:
        """Shut down the runner or background loop thread."""
        self._is_open = False
        if self._runner is not None:
            self._runner.__exit__(None, None, None)
            self._runner = None
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5.0)
                if self._thread.is_alive():
                    logger.warning("_AsyncRunner background thread did not stop within 5s")
                self._thread = None
            self._loop.close()
            self._loop = None


# ---------------------------------------------------------------------------
# SyncClient
# ---------------------------------------------------------------------------


class SyncClient:
    """Synchronous ACME v2 client.

    Wraps the async :class:`~lacme.client.Client` and exposes every public
    method as a blocking call.

    Usage::

        with SyncClient(directory_url="...", account_key=key) as client:
            cert = client.issue(["example.com"])
    """

    def __init__(
        self,
        *,
        directory_url: str = LETSENCRYPT_DIRECTORY,
        account_key: ec.EllipticCurvePrivateKey | None = None,
        store: Store | None = None,
        contact: str | list[str] | None = None,
        challenge_handler: SyncChallengeHandler | ChallengeHandler | None = None,
        http_client: httpx.AsyncClient | None = None,
        poll_timeout: float = 300.0,
        poll_interval: float = 2.0,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
        event_dispatcher: EventDispatcher | None = None,
    ) -> None:
        self._runner = _AsyncRunner()
        self._runner.open()

        try:
            self._init_client(
                directory_url=directory_url,
                account_key=account_key,
                store=store,
                contact=contact,
                challenge_handler=challenge_handler,
                http_client=http_client,
                poll_timeout=poll_timeout,
                poll_interval=poll_interval,
                eab_kid=eab_kid,
                eab_hmac_key=eab_hmac_key,
                event_dispatcher=event_dispatcher,
            )
        except Exception:
            self._runner.close()
            raise

    def _init_client(
        self,
        *,
        challenge_handler: SyncChallengeHandler | ChallengeHandler | None,
        **kwargs: Any,
    ) -> None:
        # Adapt sync challenge handler to async if needed.
        # Both ChallengeHandler and SyncChallengeHandler are @runtime_checkable
        # with the same method names, so isinstance() cannot distinguish them.
        # Check whether .provision is a coroutine function to detect async handlers.
        async_handler: ChallengeHandler | None = None
        if challenge_handler is not None:
            if inspect.iscoroutinefunction(getattr(challenge_handler, "provision", None)):
                async_handler = challenge_handler  # type: ignore[assignment]
            else:
                async_handler = _SyncToAsyncAdapter(challenge_handler)  # type: ignore[arg-type]

        self._client = Client(
            challenge_handler=async_handler,
            **kwargs,
        )

    # --- Context manager ---

    def __enter__(self) -> SyncClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying async client and event loop."""
        try:
            self._runner.run(self._client.close())
        finally:
            self._runner.close()

    # --- Directory ---

    def directory(self) -> Directory:
        """Fetch and cache the ACME directory."""
        return self._runner.run(self._client.directory())

    # --- Account management ---

    def create_account(
        self,
        *,
        contact: list[str] | None = None,
        terms_of_service_agreed: bool = True,
        only_return_existing: bool = False,
        eab_kid: str | None = None,
        eab_hmac_key: str | None = None,
    ) -> Account:
        """Create or find an existing ACME account."""
        return self._runner.run(
            self._client.create_account(
                contact=contact,
                terms_of_service_agreed=terms_of_service_agreed,
                only_return_existing=only_return_existing,
                eab_kid=eab_kid,
                eab_hmac_key=eab_hmac_key,
            )
        )

    def deactivate_account(self) -> Account:
        """Deactivate the current account."""
        return self._runner.run(self._client.deactivate_account())

    def rollover_key(
        self,
        new_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        """Roll over the account key."""
        self._runner.run(self._client.rollover_key(new_key=new_key))

    # --- Order lifecycle ---

    def create_order(
        self,
        domains: str | list[str],
        *,
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> Order:
        """Create a new certificate order."""
        return self._runner.run(
            self._client.create_order(domains, not_before=not_before, not_after=not_after)
        )

    def get_authorization(self, url: str) -> Authorization:
        """Fetch an authorization via POST-as-GET."""
        return self._runner.run(self._client.get_authorization(url))

    def get_authorizations(self, order: Order) -> list[Authorization]:
        """Fetch all authorizations for an order."""
        return self._runner.run(self._client.get_authorizations(order))

    def create_authorization(
        self,
        identifier_value: str,
        *,
        identifier_type: IdentifierType = IdentifierType.DNS,
    ) -> Authorization:
        """Create a pre-authorization for an identifier."""
        return self._runner.run(
            self._client.create_authorization(
                identifier_value,
                identifier_type=identifier_type,
            )
        )

    def respond_to_challenge(self, challenge: Challenge) -> Challenge:
        """Signal readiness for challenge validation."""
        return self._runner.run(self._client.respond_to_challenge(challenge))

    def poll_authorization(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> Authorization:
        """Poll an authorization until it reaches a terminal state."""
        return self._runner.run(self._client.poll_authorization(url, timeout=timeout))

    def finalize_order(self, order: Order, csr_der: bytes) -> Order:
        """Submit the CSR to finalize the order."""
        return self._runner.run(self._client.finalize_order(order, csr_der))

    def poll_order(
        self,
        url: str,
        *,
        timeout: float | None = None,
    ) -> Order:
        """Poll an order until it reaches a terminal state."""
        return self._runner.run(self._client.poll_order(url, timeout=timeout))

    def download_certificate(self, url: str) -> str:
        """Download the certificate chain via POST-as-GET."""
        return self._runner.run(self._client.download_certificate(url))

    # --- High-level orchestration ---

    def issue(
        self,
        domains: str | list[str],
        *,
        challenge_type: str = "http-01",
    ) -> CertBundle:
        """Issue a certificate for the given domain(s)."""
        return self._runner.run(self._client.issue(domains, challenge_type=challenge_type))

    # --- Revocation ---

    def revoke(
        self,
        cert_pem: bytes | str,
        *,
        reason: int | None = None,
    ) -> None:
        """Revoke a certificate using the account key."""
        self._runner.run(self._client.revoke(cert_pem, reason=reason))

    def revoke_with_cert_key(
        self,
        cert_pem: bytes | str,
        cert_key: ec.EllipticCurvePrivateKey,
        *,
        reason: int | None = None,
    ) -> None:
        """Revoke a certificate using its own key pair."""
        self._runner.run(self._client.revoke_with_cert_key(cert_pem, cert_key, reason=reason))
