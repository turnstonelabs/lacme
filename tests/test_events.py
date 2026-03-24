"""Tests for lacme.events — EventDispatcher and event dataclasses."""

from __future__ import annotations

import datetime
import logging
from unittest.mock import MagicMock

import pytest

from lacme.events import (
    CertificateExpiring,
    CertificateIssued,
    CertificateRenewed,
    ChallengeFailed,
    EventDispatcher,
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def _issued_event() -> CertificateIssued:
    return CertificateIssued(
        domain="example.com",
        domains=("example.com",),
        expires_at=_now() + datetime.timedelta(days=90),
    )


def _renewed_event() -> CertificateRenewed:
    return CertificateRenewed(
        domain="example.com",
        domains=("example.com",),
        expires_at=_now() + datetime.timedelta(days=90),
        previous_expires_at=_now() + datetime.timedelta(days=5),
    )


def _expiring_event() -> CertificateExpiring:
    return CertificateExpiring(
        domain="example.com",
        domains=("example.com",),
        expires_at=_now() + datetime.timedelta(days=5),
        days_remaining=5,
    )


def _failed_event() -> ChallengeFailed:
    return ChallengeFailed(
        domain="example.com",
        challenge_type="http-01",
        error="Connection refused",
    )


# ---------------------------------------------------------------------------
# EventDispatcher
# ---------------------------------------------------------------------------


class TestEventDispatcher:
    @pytest.mark.anyio
    async def test_subscribe_and_emit(self) -> None:
        dispatcher = EventDispatcher()
        received: list[CertificateIssued] = []
        dispatcher.subscribe(received.append, event_type=CertificateIssued)

        event = _issued_event()
        await dispatcher.emit(event)
        assert received == [event]

    @pytest.mark.anyio
    async def test_typed_subscriber_ignores_other_events(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []
        dispatcher.subscribe(received.append, event_type=CertificateIssued)

        await dispatcher.emit(_failed_event())
        assert received == []

    @pytest.mark.anyio
    async def test_global_subscriber_receives_all_events(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []
        dispatcher.subscribe(received.append)

        await dispatcher.emit(_issued_event())
        await dispatcher.emit(_failed_event())
        assert len(received) == 2
        assert isinstance(received[0], CertificateIssued)
        assert isinstance(received[1], ChallengeFailed)

    @pytest.mark.anyio
    async def test_async_callback(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []

        async def async_handler(event: CertificateIssued) -> None:
            received.append(event)

        dispatcher.subscribe(async_handler, event_type=CertificateIssued)
        event = _issued_event()
        await dispatcher.emit(event)
        assert received == [event]

    @pytest.mark.anyio
    async def test_unsubscribe(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []
        dispatcher.subscribe(received.append, event_type=CertificateIssued)
        dispatcher.unsubscribe(received.append)

        await dispatcher.emit(_issued_event())
        assert received == []

    @pytest.mark.anyio
    async def test_unsubscribe_global(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []
        dispatcher.subscribe(received.append)
        dispatcher.unsubscribe(received.append)

        await dispatcher.emit(_issued_event())
        assert received == []

    @pytest.mark.anyio
    async def test_callback_exception_isolated(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()
        good_received: list = []

        def bad_callback(event: CertificateIssued) -> None:
            msg = "boom"
            raise RuntimeError(msg)

        dispatcher.subscribe(bad_callback, event_type=CertificateIssued)
        dispatcher.subscribe(good_received.append, event_type=CertificateIssued)

        with caplog.at_level(logging.ERROR, logger="lacme.events"):
            await dispatcher.emit(_issued_event())

        # Good callback still received the event
        assert len(good_received) == 1
        assert "boom" in caplog.text

    @pytest.mark.anyio
    async def test_multiple_typed_subscribers(self) -> None:
        dispatcher = EventDispatcher()
        a: list = []
        b: list = []
        dispatcher.subscribe(a.append, event_type=CertificateIssued)
        dispatcher.subscribe(b.append, event_type=CertificateIssued)

        await dispatcher.emit(_issued_event())
        assert len(a) == 1
        assert len(b) == 1


# ---------------------------------------------------------------------------
# emit_sync
# ---------------------------------------------------------------------------


class TestEmitSync:
    def test_sync_callback_called(self) -> None:
        dispatcher = EventDispatcher()
        received: list = []
        dispatcher.subscribe(received.append, event_type=CertificateIssued)

        event = _issued_event()
        dispatcher.emit_sync(event)
        assert received == [event]

    def test_async_callback_skipped_with_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()

        async def async_handler(event: CertificateIssued) -> None:
            pass  # pragma: no cover

        dispatcher.subscribe(async_handler, event_type=CertificateIssued)

        with caplog.at_level(logging.WARNING, logger="lacme.events"):
            dispatcher.emit_sync(_issued_event())

        assert "Skipping async callback" in caplog.text

    def test_sync_callback_exception_isolated(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()
        good_received: list = []

        def bad_callback(event: CertificateIssued) -> None:
            msg = "sync boom"
            raise RuntimeError(msg)

        dispatcher.subscribe(bad_callback, event_type=CertificateIssued)
        dispatcher.subscribe(good_received.append, event_type=CertificateIssued)

        with caplog.at_level(logging.ERROR, logger="lacme.events"):
            dispatcher.emit_sync(_issued_event())

        assert len(good_received) == 1
        assert "sync boom" in caplog.text


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------


class TestStructuredLogging:
    @pytest.mark.anyio
    async def test_emit_logs_with_extra_fields(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()

        with caplog.at_level(logging.INFO, logger="lacme.events"):
            await dispatcher.emit(_issued_event())

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.lacme_event == "certificate_issued"  # type: ignore[attr-defined]
        assert record.domain == "example.com"  # type: ignore[attr-defined]

    @pytest.mark.anyio
    async def test_all_event_types_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()
        events = [_issued_event(), _renewed_event(), _expiring_event(), _failed_event()]

        with caplog.at_level(logging.INFO, logger="lacme.events"):
            for event in events:
                await dispatcher.emit(event)

        assert len(caplog.records) == 4
        event_names = [r.lacme_event for r in caplog.records]  # type: ignore[attr-defined]
        assert event_names == [
            "certificate_issued",
            "certificate_renewed",
            "certificate_expiring",
            "challenge_failed",
        ]

    def test_emit_sync_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        dispatcher = EventDispatcher()

        with caplog.at_level(logging.INFO, logger="lacme.events"):
            dispatcher.emit_sync(_issued_event())

        assert len(caplog.records) == 1
        assert caplog.records[0].lacme_event == "certificate_issued"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------


class TestEventDataclasses:
    def test_certificate_issued_frozen(self) -> None:
        event = _issued_event()
        with pytest.raises(AttributeError):
            event.domain = "other.com"  # type: ignore[misc]

    def test_certificate_renewed_fields(self) -> None:
        event = _renewed_event()
        assert event.domain == "example.com"
        assert event.previous_expires_at < event.expires_at

    def test_certificate_expiring_days(self) -> None:
        event = _expiring_event()
        assert event.days_remaining == 5

    def test_challenge_failed_fields(self) -> None:
        event = _failed_event()
        assert event.challenge_type == "http-01"
        assert event.error == "Connection refused"


# ---------------------------------------------------------------------------
# Thread safety (basic)
# ---------------------------------------------------------------------------


class TestThreadSafety:
    @pytest.mark.anyio
    async def test_concurrent_subscribe_emit(self) -> None:
        """Subscribe and emit from multiple threads without crashing."""
        import threading

        dispatcher = EventDispatcher()
        mock = MagicMock()
        errors: list[Exception] = []

        def subscribe_many() -> None:
            try:
                for _ in range(50):
                    dispatcher.subscribe(mock, event_type=CertificateIssued)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=subscribe_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        await dispatcher.emit(_issued_event())
        assert mock.call_count == 200  # 4 threads × 50 subscriptions
