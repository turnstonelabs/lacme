"""Tests for lacme.ratelimit — rate limit tracking."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest  # noqa: TCH002

from lacme.ratelimit import (
    FileRateLimitStore,
    IssuanceRecord,
    MemoryRateLimitStore,
    RateLimitStore,
    RateLimitTracker,
    _default_registered_domain,
)

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Registered domain extraction
# ---------------------------------------------------------------------------


class TestRegisteredDomain:
    def test_simple_domain(self) -> None:
        assert _default_registered_domain("example.com") == "example.com"

    def test_subdomain(self) -> None:
        assert _default_registered_domain("www.example.com") == "example.com"

    def test_deep_subdomain(self) -> None:
        assert _default_registered_domain("a.b.c.example.com") == "example.com"

    def test_wildcard(self) -> None:
        assert _default_registered_domain("*.example.com") == "example.com"

    def test_known_sld(self) -> None:
        assert _default_registered_domain("foo.co.uk") == "foo.co.uk"

    def test_deep_subdomain_with_sld(self) -> None:
        assert _default_registered_domain("api.foo.co.uk") == "foo.co.uk"

    def test_single_label(self) -> None:
        assert _default_registered_domain("localhost") == "localhost"

    def test_custom_func(self) -> None:
        tracker = RateLimitTracker(
            store=MemoryRateLimitStore(),
            registered_domain_func=lambda d: "custom.com",
        )
        status = tracker.check(["anything.example.com"])
        assert "custom.com" in status.counts


# ---------------------------------------------------------------------------
# MemoryRateLimitStore
# ---------------------------------------------------------------------------


class TestMemoryRateLimitStore:
    def test_record_and_get(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        record = IssuanceRecord(
            registered_domain="example.com",
            domains=("example.com",),
            issued_at=now,
        )
        store.record_issuance(record)
        results = store.get_issuances("example.com", since=now - datetime.timedelta(hours=1))
        assert len(results) == 1
        assert results[0] == record

    def test_filters_by_domain(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        store.record_issuance(IssuanceRecord("example.com", ("example.com",), now))
        store.record_issuance(IssuanceRecord("other.com", ("other.com",), now))
        results = store.get_issuances("example.com", since=now - datetime.timedelta(hours=1))
        assert len(results) == 1

    def test_filters_by_time(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        old = now - datetime.timedelta(days=10)
        store.record_issuance(IssuanceRecord("example.com", ("example.com",), old))
        store.record_issuance(IssuanceRecord("example.com", ("example.com",), now))
        results = store.get_issuances("example.com", since=now - datetime.timedelta(days=7))
        assert len(results) == 1

    def test_protocol_conformance(self) -> None:
        assert isinstance(MemoryRateLimitStore(), RateLimitStore)


# ---------------------------------------------------------------------------
# FileRateLimitStore
# ---------------------------------------------------------------------------


class TestFileRateLimitStore:
    def test_persistence_roundtrip(self, tmp_path: Path) -> None:
        store = FileRateLimitStore(base=tmp_path)
        now = datetime.datetime.now(datetime.UTC)
        record = IssuanceRecord("example.com", ("example.com",), now)
        store.record_issuance(record)

        # Create a new store instance to verify persistence
        store2 = FileRateLimitStore(base=tmp_path)
        results = store2.get_issuances("example.com", since=now - datetime.timedelta(hours=1))
        assert len(results) == 1
        assert results[0].registered_domain == "example.com"

    def test_prunes_old_records(self, tmp_path: Path) -> None:
        store = FileRateLimitStore(base=tmp_path)
        now = datetime.datetime.now(datetime.UTC)
        old = now - datetime.timedelta(days=10)
        store.record_issuance(IssuanceRecord("example.com", ("example.com",), old))
        store.record_issuance(IssuanceRecord("example.com", ("example.com",), now))

        # Pruning happens on write, so the old record should be gone
        store2 = FileRateLimitStore(base=tmp_path)
        all_records = store2.get_issuances("example.com", since=now - datetime.timedelta(days=30))
        assert len(all_records) == 1  # old one was pruned

    def test_protocol_conformance(self, tmp_path: Path) -> None:
        assert isinstance(FileRateLimitStore(base=tmp_path), RateLimitStore)


# ---------------------------------------------------------------------------
# RateLimitTracker
# ---------------------------------------------------------------------------


class TestRateLimitTracker:
    def test_check_under_limit(self) -> None:
        tracker = RateLimitTracker(store=MemoryRateLimitStore(), limit=50)
        status = tracker.check(["example.com"])
        assert status.allowed is True
        assert status.counts["example.com"] == 0
        assert status.warnings == []

    def test_check_at_limit_blocked(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        for i in range(50):
            store.record_issuance(
                IssuanceRecord("example.com", ("example.com",), now - datetime.timedelta(hours=i))
            )

        tracker = RateLimitTracker(store=store, limit=50, block=True)
        status = tracker.check(["example.com"])
        assert status.allowed is False
        assert status.counts["example.com"] == 50

    def test_check_at_limit_non_blocking(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        for i in range(50):
            store.record_issuance(
                IssuanceRecord("example.com", ("example.com",), now - datetime.timedelta(hours=i))
            )

        tracker = RateLimitTracker(store=store, limit=50, block=False)
        status = tracker.check(["example.com"])
        assert status.allowed is True  # non-blocking allows it
        assert len(status.warnings) > 0

    def test_warning_at_threshold(self, caplog: pytest.LogCaptureFixture) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        for i in range(46):  # 46/50 = 92% > 90% threshold
            store.record_issuance(
                IssuanceRecord("example.com", ("example.com",), now - datetime.timedelta(hours=i))
            )

        tracker = RateLimitTracker(store=store, limit=50, warn_threshold=0.9)
        status = tracker.check(["example.com"])
        assert status.allowed is True
        assert len(status.warnings) == 1
        assert "example.com" in status.warnings[0]

    def test_record_increments_count(self) -> None:
        store = MemoryRateLimitStore()
        tracker = RateLimitTracker(store=store)
        tracker.record(["example.com", "www.example.com"])

        now = datetime.datetime.now(datetime.UTC)
        results = store.get_issuances("example.com", since=now - datetime.timedelta(hours=1))
        assert len(results) == 1

    def test_from_file_store(self, tmp_path: Path) -> None:
        from lacme.store import FileStore

        file_store = FileStore(tmp_path)
        tracker = RateLimitTracker.from_file_store(file_store)
        tracker.record(["example.com"])
        status = tracker.check(["example.com"])
        assert status.counts["example.com"] == 1

    def test_emits_rate_limit_warning_event(self) -> None:
        from lacme.events import EventDispatcher, RateLimitWarning

        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        for i in range(46):
            store.record_issuance(
                IssuanceRecord("example.com", ("example.com",), now - datetime.timedelta(hours=i))
            )

        received: list = []
        dispatcher = EventDispatcher()
        dispatcher.subscribe(received.append, event_type=RateLimitWarning)

        tracker = RateLimitTracker(
            store=store, limit=50, warn_threshold=0.9, event_dispatcher=dispatcher
        )
        tracker.check(["example.com"])
        assert len(received) == 1
        assert isinstance(received[0], RateLimitWarning)
        assert received[0].current_count == 46

    def test_multiple_registered_domains(self) -> None:
        store = MemoryRateLimitStore()
        now = datetime.datetime.now(datetime.UTC)
        for i in range(50):
            store.record_issuance(
                IssuanceRecord("blocked.com", ("blocked.com",), now - datetime.timedelta(hours=i))
            )

        tracker = RateLimitTracker(store=store, limit=50, block=True)
        # One domain blocked, one ok
        status = tracker.check(["sub.blocked.com", "ok.com"])
        assert status.allowed is False
        assert status.counts["blocked.com"] == 50
        assert status.counts["ok.com"] == 0
