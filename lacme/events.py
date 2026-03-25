"""Event system for lacme observability.

Provides typed event dataclasses and a centralized :class:`EventDispatcher`
for subscribing to certificate lifecycle events. Events are also logged
via stdlib :mod:`logging` with structured ``extra`` fields.
"""

from __future__ import annotations

import dataclasses
import inspect
import logging
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import datetime
    from collections.abc import Callable

logger = logging.getLogger("lacme.events")


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CertificateIssued:
    """Emitted after a certificate is successfully issued."""

    domain: str
    domains: tuple[str, ...]
    expires_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CertificateRenewed:
    """Emitted after a certificate is successfully renewed."""

    domain: str
    domains: tuple[str, ...]
    expires_at: datetime.datetime
    previous_expires_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CertificateExpiring:
    """Emitted when a certificate is approaching its expiry threshold."""

    domain: str
    domains: tuple[str, ...]
    expires_at: datetime.datetime
    days_remaining: int


@dataclass(frozen=True, slots=True)
class ChallengeFailed:
    """Emitted when an ACME challenge validation fails."""

    domain: str
    challenge_type: str
    error: str


@dataclass(frozen=True, slots=True)
class RateLimitWarning:
    """Emitted when certificate issuance is approaching a rate limit."""

    registered_domain: str
    current_count: int
    limit: int
    window_hours: int


@dataclass(frozen=True, slots=True)
class CertificateAuthorityInitialized:
    """Emitted when a CA root certificate is created or loaded."""

    cn: str
    expires_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CACertificateIssued:
    """Emitted when the CA signs a new certificate."""

    name: str
    names: tuple[str, ...]
    is_client: bool
    expires_at: datetime.datetime


Event = (
    CertificateIssued
    | CertificateRenewed
    | CertificateExpiring
    | ChallengeFailed
    | RateLimitWarning
    | CertificateAuthorityInitialized
    | CACertificateIssued
)

_EVENT_NAMES: dict[type[Event], str] = {
    CertificateIssued: "certificate_issued",
    CertificateRenewed: "certificate_renewed",
    CertificateExpiring: "certificate_expiring",
    ChallengeFailed: "challenge_failed",
    RateLimitWarning: "rate_limit_warning",
    CertificateAuthorityInitialized: "ca_initialized",
    CACertificateIssued: "ca_certificate_issued",
}


# ---------------------------------------------------------------------------
# EventDispatcher
# ---------------------------------------------------------------------------


class EventDispatcher:
    """Central event bus for lacme lifecycle events.

    Supports both sync and async subscribers.  Thread-safe for use with
    :class:`~lacme.sync.SyncClient`.

    Example::

        dispatcher = EventDispatcher()
        dispatcher.subscribe(lambda e: print(e), event_type=CertificateIssued)
        await dispatcher.emit(CertificateIssued(...))
    """

    def __init__(self) -> None:
        self._typed: dict[type[Event], list[Callable[..., Any]]] = {}
        self._global: list[Callable[..., Any]] = []
        self._lock = threading.Lock()

    def subscribe(
        self,
        callback: Callable[..., Any],
        event_type: type[Event] | None = None,
    ) -> None:
        """Register *callback* for events of *event_type*, or all events."""
        with self._lock:
            if event_type is None:
                self._global.append(callback)
            else:
                self._typed.setdefault(event_type, []).append(callback)

    def unsubscribe(self, callback: Callable[..., Any]) -> None:
        """Remove *callback* from all subscription lists."""
        with self._lock:
            self._global = [cb for cb in self._global if cb != callback]
            for event_type in self._typed:
                self._typed[event_type] = [cb for cb in self._typed[event_type] if cb != callback]

    async def emit(self, event: Event) -> None:
        """Emit *event*: log it, then invoke all matching subscribers.

        Both sync and async callbacks are supported.  If a sync callback
        returns an awaitable, it is awaited.  Exceptions in callbacks are
        caught and logged — they never propagate to the caller.

        For synchronous contexts, use :meth:`emit_sync` instead, which
        skips async callbacks entirely (with a warning).
        """
        self._log_event(event)

        with self._lock:
            callbacks = list(self._typed.get(type(event), []))
            callbacks.extend(self._global)

        for cb in callbacks:
            try:
                result = cb(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception("Event callback %r failed for %s", cb, type(event).__name__)

    def emit_sync(self, event: Event) -> None:
        """Emit *event* from synchronous code.

        Callbacks detected as coroutine functions (via
        :func:`inspect.iscoroutinefunction`) are skipped with a warning.
        Unlike :meth:`emit`, this method does **not** await return values.
        If a sync callback accidentally returns a coroutine, it is closed
        to prevent un-awaited coroutine warnings and a warning is logged.
        """
        self._log_event(event)

        with self._lock:
            callbacks = list(self._typed.get(type(event), []))
            callbacks.extend(self._global)

        for cb in callbacks:
            if inspect.iscoroutinefunction(cb):
                logger.warning(
                    "Skipping async callback %r in emit_sync for %s",
                    cb,
                    type(event).__name__,
                )
                continue
            try:
                result = cb(event)
                if inspect.isawaitable(result):
                    # Close un-awaited coroutines to prevent RuntimeWarning
                    if hasattr(result, "close"):
                        result.close()
                    logger.warning(
                        "Sync callback %r returned an awaitable in emit_sync for %s; "
                        "result was discarded",
                        cb,
                        type(event).__name__,
                    )
            except Exception:
                logger.exception("Event callback %r failed for %s", cb, type(event).__name__)

    @staticmethod
    def _log_event(event: Event) -> None:
        """Log the event with structured extra fields."""
        event_name = _EVENT_NAMES.get(type(event), type(event).__name__)
        fields = dataclasses.asdict(event)
        # Convert datetimes to ISO strings for logging
        for key, value in fields.items():
            if hasattr(value, "isoformat"):
                fields[key] = value.isoformat()
        identifier = (
            fields.get("domain")
            or fields.get("name")
            or fields.get("cn")
            or fields.get("registered_domain")
            or ""
        )
        logger.info(
            "%s: %s",
            event_name,
            identifier,
            extra={"lacme_event": event_name, **fields},
        )
