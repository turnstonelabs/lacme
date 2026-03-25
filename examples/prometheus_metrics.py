#!/usr/bin/env python3
"""Example: Prometheus metrics integration with lacme.

Demonstrates:
- Setting up EventDispatcher + MetricsCollector
- Issuing a certificate against MockACMEServer
- Reading the resulting Prometheus counter values

Run:
    pip install lacme prometheus-client
    python examples/prometheus_metrics.py
"""

from __future__ import annotations

import asyncio

from prometheus_client import CollectorRegistry

from lacme import Client, EventDispatcher, MemoryStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.crypto import generate_ec_key
from lacme.metrics import setup_metrics
from lacme.testing import MockACMEServer


async def main() -> None:
    # --- Use a dedicated registry to avoid global state ---
    registry = CollectorRegistry()

    # --- Wire up events + metrics ---
    dispatcher = EventDispatcher()
    metrics = setup_metrics(dispatcher, registry=registry)

    # --- Create an in-process mock ACME server ---
    server = MockACMEServer()
    transport = server.as_transport()

    import httpx

    http = httpx.AsyncClient(transport=transport, base_url="https://acme.test")

    # --- Issue a certificate ---
    store = MemoryStore()
    handler = HTTP01Handler()
    account_key = generate_ec_key()

    async with Client(
        directory_url="https://acme.test/directory",
        http_client=http,
        account_key=account_key,
        store=store,
        challenge_handler=handler,
        event_dispatcher=dispatcher,
    ) as client:
        bundle = await client.issue(["example.com", "www.example.com"])
        print(f"Certificate issued for: {', '.join(bundle.domains)}")  # noqa: T201
        print(f"  Expires: {bundle.expires_at.isoformat()}")  # noqa: T201

    # --- Read Prometheus metrics ---
    issued_count = metrics.certificates_issued.labels(domain="example.com")._value.get()
    print(f"\nPrometheus metrics:")  # noqa: T201
    print(f"  lacme_certificates_issued_total{{domain='example.com'}} = {issued_count}")  # noqa: T201

    # Issue a second cert to see the counter increment
    http = httpx.AsyncClient(transport=transport, base_url="https://acme.test")
    async with Client(
        directory_url="https://acme.test/directory",
        http_client=http,
        account_key=account_key,
        store=store,
        challenge_handler=handler,
        event_dispatcher=dispatcher,
    ) as client:
        await client.issue(["api.example.com"])

    issued_api = metrics.certificates_issued.labels(domain="api.example.com")._value.get()
    print(f"  lacme_certificates_issued_total{{domain='api.example.com'}} = {issued_api}")  # noqa: T201


if __name__ == "__main__":
    asyncio.run(main())
