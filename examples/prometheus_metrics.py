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

import httpx
from prometheus_client import CollectorRegistry, generate_latest

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
    setup_metrics(dispatcher, registry=registry)

    # --- Create an in-process mock ACME server ---
    server = MockACMEServer()
    transport = server.as_transport()

    # --- Issue a certificate ---
    store = MemoryStore()
    handler = HTTP01Handler()
    account_key = generate_ec_key()

    async with (  # noqa: SIM117
        httpx.AsyncClient(transport=transport, base_url="https://acme.test") as http,
        Client(
            directory_url="https://acme.test/directory",
            http_client=http,
            account_key=account_key,
            store=store,
            challenge_handler=handler,
            event_dispatcher=dispatcher,
        ) as client,
    ):
        bundle = await client.issue(["example.com", "www.example.com"])
        print(f"Certificate issued for: {', '.join(bundle.domains)}")  # noqa: T201
        print(f"  Expires: {bundle.expires_at.isoformat()}")  # noqa: T201

        # Issue a second cert to see a different domain counter
        await client.issue(["api.example.com"])

    # --- Read Prometheus metrics via public API ---
    print("\nPrometheus metrics:")  # noqa: T201
    output = generate_latest(registry).decode()
    for line in output.splitlines():
        if line.startswith("lacme_"):
            print(f"  {line}")  # noqa: T201


if __name__ == "__main__":
    asyncio.run(main())
