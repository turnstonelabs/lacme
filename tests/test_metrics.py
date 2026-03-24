"""Tests for lacme.metrics — Prometheus metrics integration."""

from __future__ import annotations

import datetime

import pytest

prometheus_client = pytest.importorskip("prometheus_client")

from lacme.events import (  # noqa: E402
    CertificateExpiring,
    CertificateIssued,
    CertificateRenewed,
    ChallengeFailed,
    EventDispatcher,
)
from lacme.metrics import MetricsCollector, setup_metrics  # noqa: E402


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


@pytest.fixture
def registry():
    """Create an isolated Prometheus registry for each test."""
    return prometheus_client.CollectorRegistry()


# ---------------------------------------------------------------------------
# setup_metrics
# ---------------------------------------------------------------------------


class TestSetupMetrics:
    def test_returns_collector(self, registry) -> None:
        dispatcher = EventDispatcher()
        collector = setup_metrics(dispatcher, registry=registry)
        assert isinstance(collector, MetricsCollector)


# ---------------------------------------------------------------------------
# Counter tests
# ---------------------------------------------------------------------------


class TestIssuedCounter:
    @pytest.mark.anyio
    async def test_increments_on_issued(self, registry) -> None:
        dispatcher = EventDispatcher()
        collector = setup_metrics(dispatcher, registry=registry)

        await dispatcher.emit(
            CertificateIssued(
                domain="example.com",
                domains=("example.com",),
                expires_at=_now() + datetime.timedelta(days=90),
            )
        )

        assert collector.certificates_issued.labels(domain="example.com")._value.get() == 1.0


class TestRenewedCounter:
    @pytest.mark.anyio
    async def test_increments_on_renewed(self, registry) -> None:
        dispatcher = EventDispatcher()
        collector = setup_metrics(dispatcher, registry=registry)

        await dispatcher.emit(
            CertificateRenewed(
                domain="example.com",
                domains=("example.com",),
                expires_at=_now() + datetime.timedelta(days=90),
                previous_expires_at=_now() + datetime.timedelta(days=5),
            )
        )

        assert collector.certificates_renewed.labels(domain="example.com")._value.get() == 1.0


class TestFailureCounter:
    @pytest.mark.anyio
    async def test_increments_on_failure(self, registry) -> None:
        dispatcher = EventDispatcher()
        collector = setup_metrics(dispatcher, registry=registry)

        await dispatcher.emit(
            ChallengeFailed(
                domain="example.com",
                challenge_type="http-01",
                error="Connection refused",
            )
        )

        assert collector.certificate_failures.labels(domain="example.com")._value.get() == 1.0


# ---------------------------------------------------------------------------
# Gauge test
# ---------------------------------------------------------------------------


class TestExpiryGauge:
    @pytest.mark.anyio
    async def test_sets_days_remaining(self, registry) -> None:
        dispatcher = EventDispatcher()
        collector = setup_metrics(dispatcher, registry=registry)

        await dispatcher.emit(
            CertificateExpiring(
                domain="example.com",
                domains=("example.com",),
                expires_at=_now() + datetime.timedelta(days=15),
                days_remaining=15,
            )
        )

        assert collector.days_until_expiry.labels(domain="example.com")._value.get() == 15.0
