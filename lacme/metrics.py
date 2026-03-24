"""Optional Prometheus metrics for lacme.

Subscribes to :class:`~lacme.events.EventDispatcher` events and
updates Prometheus counters and gauges.  Requires ``prometheus_client``
(install with ``pip install lacme[prometheus]``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lacme.events import Event, EventDispatcher

logger = logging.getLogger("lacme.metrics")


class MetricsCollector:
    """Prometheus metrics collector for lacme events.

    Created by :func:`setup_metrics`.  Subscribes to the event dispatcher
    and updates counters/gauges on each event.
    """

    def __init__(self, dispatcher: EventDispatcher, registry: Any = None) -> None:
        from prometheus_client import REGISTRY, Counter, Gauge

        reg = registry if registry is not None else REGISTRY
        self.certificates_issued = Counter(
            "lacme_certificates_issued_total",
            "Total certificates issued",
            ["domain"],
            registry=reg,
        )
        self.certificates_renewed = Counter(
            "lacme_certificates_renewed_total",
            "Total certificates renewed",
            ["domain"],
            registry=reg,
        )
        self.certificate_failures = Counter(
            "lacme_certificate_failures_total",
            "Total certificate issuance/renewal failures",
            ["domain"],
            registry=reg,
        )
        self.days_until_expiry = Gauge(
            "lacme_certificate_days_until_expiry",
            "Days until certificate expiry",
            ["domain"],
            registry=reg,
        )

        from lacme.events import (
            CertificateExpiring,
            CertificateIssued,
            CertificateRenewed,
            ChallengeFailed,
        )

        dispatcher.subscribe(self._on_issued, event_type=CertificateIssued)
        dispatcher.subscribe(self._on_renewed, event_type=CertificateRenewed)
        dispatcher.subscribe(self._on_failed, event_type=ChallengeFailed)
        dispatcher.subscribe(self._on_expiring, event_type=CertificateExpiring)

    def _on_issued(self, event: Event) -> None:
        from lacme.events import CertificateIssued

        if not isinstance(event, CertificateIssued):
            return
        self.certificates_issued.labels(domain=event.domain).inc()

    def _on_renewed(self, event: Event) -> None:
        from lacme.events import CertificateRenewed

        if not isinstance(event, CertificateRenewed):
            return
        self.certificates_renewed.labels(domain=event.domain).inc()

    def _on_failed(self, event: Event) -> None:
        from lacme.events import ChallengeFailed

        if not isinstance(event, ChallengeFailed):
            return
        self.certificate_failures.labels(domain=event.domain).inc()

    def _on_expiring(self, event: Event) -> None:
        from lacme.events import CertificateExpiring

        if not isinstance(event, CertificateExpiring):
            return
        self.days_until_expiry.labels(domain=event.domain).set(event.days_remaining)


def setup_metrics(dispatcher: EventDispatcher, registry: Any = None) -> MetricsCollector:
    """Register Prometheus metrics and subscribe to lacme events.

    Args:
        dispatcher: Event dispatcher to subscribe to.
        registry: Optional Prometheus ``CollectorRegistry``.  Defaults to
            the global ``REGISTRY``.  Pass a custom registry to avoid
            conflicts when creating multiple collectors.

    Returns:
        A :class:`MetricsCollector` holding all metric objects.

    Raises:
        ImportError: If ``prometheus_client`` is not installed.
    """
    return MetricsCollector(dispatcher, registry=registry)
