"""Rate limit tracking for certificate issuance.

Provides store-backed awareness of Let's Encrypt rate limits
(50 certificates per registered domain per week).  Includes
:class:`RateLimitTracker` for checking and recording issuance counts,
with pluggable storage via the :class:`RateLimitStore` protocol.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from lacme.events import EventDispatcher
    from lacme.store import FileStore

logger = logging.getLogger("lacme.ratelimit")


# ---------------------------------------------------------------------------
# Registered domain extraction
# ---------------------------------------------------------------------------

# Common second-level domains where the registered domain has 3+ labels.
# This is a best-effort heuristic — for complete accuracy, use
# ``registered_domain_func`` with a library like ``tldextract`` or
# ``publicsuffix2``.
_KNOWN_SLDS = frozenset(
    {
        # UK
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "net.uk",
        # Japan
        "co.jp",
        "or.jp",
        "ne.jp",
        "ac.jp",
        "go.jp",
        # Australia
        "com.au",
        "org.au",
        "net.au",
        "edu.au",
        "gov.au",
        # New Zealand
        "co.nz",
        "org.nz",
        "net.nz",
        # South Africa
        "co.za",
        "org.za",
        "web.za",
        # Brazil
        "com.br",
        "org.br",
        "net.br",
        # China
        "com.cn",
        "org.cn",
        "net.cn",
        "gov.cn",
        # India
        "co.in",
        "org.in",
        "net.in",
        "gen.in",
        # South Korea
        "co.kr",
        "or.kr",
        "ne.kr",
        # Mexico
        "com.mx",
        "org.mx",
        "net.mx",
        # Turkey
        "com.tr",
        "org.tr",
        "net.tr",
        # Russia
        "com.ru",
        # Other common
        "com.sg",
        "com.hk",
        "com.tw",
        "com.my",
        "com.ph",
        "com.ar",
        "com.co",
        "com.ve",
        "com.pe",
    }
)


def _default_registered_domain(domain: str) -> str:
    """Extract registered domain.

    ``*.example.com`` → ``example.com``,
    ``www.example.com`` → ``example.com``,
    ``foo.co.uk`` → ``foo.co.uk``.
    """
    # Strip leading wildcard prefix and trailing dot
    if domain.startswith("*."):
        domain = domain[2:]
    domain = domain.rstrip(".")

    parts = domain.split(".")
    if len(parts) <= 2:  # noqa: PLR2004
        return domain

    # Check for known two-level SLDs
    candidate_sld = f"{parts[-2]}.{parts[-1]}"
    if candidate_sld in _KNOWN_SLDS:
        if len(parts) >= 3:  # noqa: PLR2004
            return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        return domain

    return f"{parts[-2]}.{parts[-1]}"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuanceRecord:
    """A single certificate issuance event."""

    registered_domain: str
    domains: tuple[str, ...]
    issued_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class RateLimitStatus:
    """Result of a rate limit check."""

    allowed: bool
    counts: dict[str, int]  # registered_domain → count in window
    warnings: list[str]


# ---------------------------------------------------------------------------
# RateLimitStore protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class RateLimitStore(Protocol):
    """Abstract storage interface for rate limit records."""

    def record_issuance(self, record: IssuanceRecord) -> None: ...

    def get_issuances(
        self,
        registered_domain: str,
        since: datetime.datetime,
    ) -> list[IssuanceRecord]: ...


# ---------------------------------------------------------------------------
# MemoryRateLimitStore
# ---------------------------------------------------------------------------


class MemoryRateLimitStore:
    """In-memory rate limit store for testing.  No filesystem access.  Thread-safe."""

    def __init__(self) -> None:
        self._records: list[IssuanceRecord] = []
        self._lock = threading.Lock()

    def record_issuance(self, record: IssuanceRecord) -> None:
        with self._lock:
            self._records.append(record)

    def get_issuances(
        self,
        registered_domain: str,
        since: datetime.datetime,
    ) -> list[IssuanceRecord]:
        with self._lock:
            return [
                r
                for r in self._records
                if r.registered_domain == registered_domain and r.issued_at >= since
            ]


# ---------------------------------------------------------------------------
# FileRateLimitStore
# ---------------------------------------------------------------------------


class FileRateLimitStore:
    """JSON-file-backed rate limit store.

    Stores records in ``{base}/rate_limits.json``.  Uses atomic writes
    (tempfile + :func:`os.replace`) consistent with :mod:`lacme.store`.
    Prunes records older than 7 days on every write.  Thread-safe.
    """

    def __init__(self, *, base: Path) -> None:
        from pathlib import Path as _Path

        self._base = _Path(base).expanduser().resolve()
        self._path = self._base / "rate_limits.json"
        self._lock = threading.Lock()

    def record_issuance(self, record: IssuanceRecord) -> None:
        with self._lock:
            records = self._load()
            records.append(record)
            self._save(records)

    def get_issuances(
        self,
        registered_domain: str,
        since: datetime.datetime,
    ) -> list[IssuanceRecord]:
        with self._lock:
            records = self._load()
        return [
            r for r in records if r.registered_domain == registered_domain and r.issued_at >= since
        ]

    def _load(self) -> list[IssuanceRecord]:
        """Load records from disk.  Returns empty list if file is missing."""
        if not self._path.exists():
            return []
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Corrupt or unreadable rate limit file %s; starting fresh", self._path)
            return []
        try:
            return [
                IssuanceRecord(
                    registered_domain=entry["registered_domain"],
                    domains=tuple(entry["domains"]),
                    issued_at=datetime.datetime.fromisoformat(entry["issued_at"]),
                )
                for entry in raw
            ]
        except (TypeError, KeyError, ValueError):
            logger.warning("Corrupt rate limit data in %s; starting fresh", self._path)
            return []

    def _save(self, records: list[IssuanceRecord]) -> None:
        """Atomically write records, pruning entries older than 7 days."""
        cutoff = datetime.datetime.now(datetime.UTC) - datetime.timedelta(weeks=1)
        records = [r for r in records if r.issued_at >= cutoff]

        data = [
            {
                "registered_domain": r.registered_domain,
                "domains": list(r.domains),
                "issued_at": r.issued_at.isoformat(),
            }
            for r in records
        ]
        raw = json.dumps(data, indent=2).encode("utf-8")

        self._base.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._base, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


# ---------------------------------------------------------------------------
# RateLimitTracker
# ---------------------------------------------------------------------------


class RateLimitTracker:
    """Check and record certificate issuance against rate limits.

    Uses a :class:`RateLimitStore` to persist issuance records and
    optionally emits :class:`~lacme.events.RateLimitWarning` events
    when approaching the configured threshold.
    """

    def __init__(
        self,
        store: RateLimitStore,
        *,
        limit: int = 50,
        window: datetime.timedelta = datetime.timedelta(weeks=1),
        warn_threshold: float = 0.9,
        block: bool = True,
        registered_domain_func: Callable[[str], str] | None = None,
        event_dispatcher: EventDispatcher | None = None,
    ) -> None:
        self._store = store
        self._limit = limit
        self._window = window
        self._warn_threshold = warn_threshold
        self._block = block
        self._registered_domain_func = registered_domain_func or _default_registered_domain
        self._event_dispatcher = event_dispatcher

    @classmethod
    def from_file_store(cls, file_store: FileStore, **kwargs: Any) -> RateLimitTracker:
        """Create tracker using same base directory as *file_store*."""
        rate_store = FileRateLimitStore(base=file_store.base)
        return cls(rate_store, **kwargs)

    def check(self, domains: list[str]) -> RateLimitStatus:
        """Check if issuing for *domains* would exceed rate limits.

        Emits :class:`~lacme.events.RateLimitWarning` events for domains
        approaching the threshold.  Returns :class:`RateLimitStatus` with
        ``allowed=False`` if any domain would exceed the limit.
        """
        since = datetime.datetime.now(datetime.UTC) - self._window
        registered = {self._registered_domain_func(d) for d in domains}

        counts: dict[str, int] = {}
        warnings: list[str] = []
        allowed = True

        for rd in sorted(registered):
            existing = self._store.get_issuances(rd, since)
            count = len(existing)
            counts[rd] = count

            if count >= self._limit and self._block:
                allowed = False
                warnings.append(
                    f"{rd}: {count}/{self._limit} certificates issued in window (blocked)"
                )
            elif count >= self._warn_threshold * self._limit:
                warnings.append(
                    f"{rd}: {count}/{self._limit} certificates issued in window (warning)"
                )

            if count >= self._warn_threshold * self._limit and self._event_dispatcher is not None:
                from lacme.events import RateLimitWarning

                self._event_dispatcher.emit_sync(
                    RateLimitWarning(
                        registered_domain=rd,
                        current_count=count,
                        limit=self._limit,
                        window_hours=int(self._window.total_seconds() // 3600),
                    )
                )

        return RateLimitStatus(allowed=allowed, counts=counts, warnings=warnings)

    def record(self, domains: list[str]) -> None:
        """Record an issuance for the given *domains*."""
        now = datetime.datetime.now(datetime.UTC)
        registered = {self._registered_domain_func(d) for d in domains}

        for rd in sorted(registered):
            self._store.record_issuance(
                IssuanceRecord(
                    registered_domain=rd,
                    domains=tuple(domains),
                    issued_at=now,
                )
            )
