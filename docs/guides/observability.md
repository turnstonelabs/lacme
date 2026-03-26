# Observability Guide

lacme provides a built-in event system and optional Prometheus metrics for
monitoring certificate lifecycle events. Events are emitted automatically by
the `Client`, `RenewalManager`, `CertificateAuthority`, and `RateLimitTracker`,
and can be consumed by your application for alerting, logging, and dashboards.

## Event System

### Setup

Create an `EventDispatcher` and pass it to the components you want to observe:

```python
from lacme import Client, EventDispatcher, FileStore, RateLimitTracker
from lacme.challenges.http01 import HTTP01Handler
from lacme.ratelimit import FileRateLimitStore

dispatcher = EventDispatcher()
store = FileStore("~/.lacme")

tracker = RateLimitTracker(
    store=FileRateLimitStore(base=store.base),
    event_dispatcher=dispatcher,
)

async with Client(
    store=store,
    challenge_handler=HTTP01Handler(),
    contact="mailto:admin@example.com",
    event_dispatcher=dispatcher,
    rate_limit_tracker=tracker,
) as client:
    bundle = await client.issue("example.com")
```

### Subscribing to Events

Register callbacks for specific event types or all events:

```python
from lacme import (
    CertificateIssued,
    CertificateRenewed,
    ChallengeFailed,
    EventDispatcher,
)

dispatcher = EventDispatcher()

# Subscribe to a specific event type
def on_issued(event: CertificateIssued):
    print(f"Certificate issued for {event.domain}, expires {event.expires_at}")

dispatcher.subscribe(on_issued, event_type=CertificateIssued)

# Subscribe to all events
def on_any_event(event):
    print(f"Event: {type(event).__name__}")

dispatcher.subscribe(on_any_event)

# Unsubscribe when done
dispatcher.unsubscribe(on_issued)
```

### Async Subscribers

Both sync and async callbacks are supported with `emit()`:

```python
import aiohttp

async def notify_slack(event: CertificateIssued):
    async with aiohttp.ClientSession() as session:
        await session.post(
            "https://hooks.slack.com/services/...",
            json={"text": f"Certificate issued: {event.domain}"},
        )

dispatcher.subscribe(notify_slack, event_type=CertificateIssued)
```

When an async `emit()` encounters a sync callback that returns an awaitable,
it awaits the result automatically.

!!! note
    Exceptions in callbacks are caught and logged -- they never propagate to
    the caller. This ensures a misbehaving callback cannot break certificate
    issuance.

## Available Events

### CertificateIssued

Emitted after a certificate is successfully issued via `Client.issue()`.

| Field        | Type                | Description              |
|--------------|---------------------|--------------------------|
| `domain`     | `str`               | Primary domain name      |
| `domains`    | `tuple[str, ...]`   | All domains in the cert  |
| `expires_at` | `datetime`          | Certificate expiry       |

```python
from lacme import CertificateIssued

def on_issued(event: CertificateIssued):
    print(f"Issued: {event.domain} ({len(event.domains)} SANs)")
    print(f"Expires: {event.expires_at.isoformat()}")

dispatcher.subscribe(on_issued, event_type=CertificateIssued)
```

### CertificateRenewed

Emitted after a certificate is successfully renewed by `RenewalManager`.

| Field                  | Type                | Description                     |
|------------------------|---------------------|---------------------------------|
| `domain`               | `str`               | Primary domain name             |
| `domains`              | `tuple[str, ...]`   | All domains in the cert         |
| `expires_at`           | `datetime`          | New certificate expiry          |
| `previous_expires_at`  | `datetime`          | Previous certificate expiry     |

```python
from lacme import CertificateRenewed

def on_renewed(event: CertificateRenewed):
    days_gained = (event.expires_at - event.previous_expires_at).days
    print(f"Renewed {event.domain}: +{days_gained} days")

dispatcher.subscribe(on_renewed, event_type=CertificateRenewed)
```

### CertificateExpiring

Emitted when `RenewalManager` finds a certificate approaching its expiry
threshold. This event fires before the renewal attempt.

| Field            | Type                | Description                        |
|------------------|---------------------|------------------------------------|
| `domain`         | `str`               | Primary domain name                |
| `domains`        | `tuple[str, ...]`   | All domains in the cert            |
| `expires_at`     | `datetime`          | Certificate expiry                 |
| `days_remaining` | `int`               | Days until expiry (may be 0)       |

```python
from lacme import CertificateExpiring

def on_expiring(event: CertificateExpiring):
    if event.days_remaining <= 7:
        send_alert(f"URGENT: {event.domain} expires in {event.days_remaining} days!")

dispatcher.subscribe(on_expiring, event_type=CertificateExpiring)
```

### ChallengeFailed

Emitted when an ACME challenge validation fails during `Client.issue()`.

| Field             | Type   | Description                    |
|-------------------|--------|--------------------------------|
| `domain`          | `str`  | Domain that failed validation  |
| `challenge_type`  | `str`  | Challenge type (e.g., `http-01`) |
| `error`           | `str`  | Error message                  |

```python
from lacme import ChallengeFailed

def on_failed(event: ChallengeFailed):
    print(f"Challenge failed: {event.domain} ({event.challenge_type})")
    print(f"Error: {event.error}")

dispatcher.subscribe(on_failed, event_type=ChallengeFailed)
```

### RateLimitWarning

Emitted when `RateLimitTracker.check()` detects that issuance is approaching
the configured threshold.

| Field               | Type   | Description                        |
|---------------------|--------|------------------------------------|
| `registered_domain` | `str`  | The registered domain              |
| `current_count`     | `int`  | Certificates issued in the window  |
| `limit`             | `int`  | Configured rate limit              |
| `window_hours`      | `int`  | Rate limit window in hours         |

```python
from lacme import RateLimitWarning

def on_rate_limit(event: RateLimitWarning):
    pct = event.current_count / event.limit * 100
    print(
        f"Rate limit warning: {event.registered_domain} "
        f"at {event.current_count}/{event.limit} ({pct:.0f}%) "
        f"in {event.window_hours}h window"
    )

dispatcher.subscribe(on_rate_limit, event_type=RateLimitWarning)
```

### CertificateAuthorityInitialized

Emitted when a `CertificateAuthority` root certificate is created or loaded
via `ca.init()`.

| Field        | Type       | Description                    |
|--------------|------------|--------------------------------|
| `cn`         | `str`      | Common Name of the root cert   |
| `expires_at` | `datetime` | Root certificate expiry        |

```python
from lacme import CertificateAuthorityInitialized

def on_ca_init(event: CertificateAuthorityInitialized):
    print(f"CA initialized: {event.cn}, expires {event.expires_at}")

dispatcher.subscribe(on_ca_init, event_type=CertificateAuthorityInitialized)
```

### CACertificateIssued

Emitted when the `CertificateAuthority` signs a new leaf certificate.

| Field        | Type                | Description                     |
|--------------|---------------------|---------------------------------|
| `name`       | `str`               | Primary name (CN)               |
| `names`      | `tuple[str, ...]`   | All names (SANs)                |
| `is_client`  | `bool`              | True if client cert (clientAuth)|
| `expires_at` | `datetime`          | Certificate expiry              |

```python
from lacme import CACertificateIssued

def on_ca_issued(event: CACertificateIssued):
    cert_type = "client" if event.is_client else "server"
    print(f"CA issued {cert_type} cert: {event.name}")

dispatcher.subscribe(on_ca_issued, event_type=CACertificateIssued)
```

## Sync vs Async Subscribers

The `EventDispatcher` provides two emission methods:

### emit() -- for async contexts

Used by `Client` and `RenewalManager`. Supports both sync and async callbacks:

```python
# Inside Client.issue(), RenewalManager, etc.
await dispatcher.emit(CertificateIssued(...))
```

- Sync callbacks are called directly
- If a sync callback returns an awaitable, it is awaited
- Async callbacks (coroutine functions) are awaited

### emit_sync() -- for synchronous contexts

Used by `CertificateAuthority` and `RateLimitTracker`. Only calls sync
callbacks:

```python
# Inside CertificateAuthority.init(), RateLimitTracker.check(), etc.
dispatcher.emit_sync(CertificateAuthorityInitialized(...))
```

- Sync callbacks are called directly
- Async callbacks (coroutine functions) are **skipped** with a warning
- If a sync callback accidentally returns a coroutine, it is closed to
  prevent `RuntimeWarning` for unawaited coroutines

!!! warning
    If you subscribe an `async def` callback and expect it to fire for CA
    events, it will be skipped because `CertificateAuthority` uses
    `emit_sync()`. Use a plain `def` callback for those event types:

    ```python
    # This works for both emit() and emit_sync()
    def on_ca_init(event: CertificateAuthorityInitialized):
        print(f"CA initialized: {event.cn}")

    # This ONLY works with emit(), skipped by emit_sync()
    async def on_ca_init_async(event: CertificateAuthorityInitialized):
        await notify_slack(event)
    ```

## Structured Logging

Every event is automatically logged via Python's standard `logging` module
with structured extra fields. The log message follows the format:

```
<event_name>: <identifier>
```

The `extra` dict on each log record includes:

- `lacme_event` -- event name string (e.g., `"certificate_issued"`)
- All event dataclass fields, **prefixed with `lacme_`** to avoid collisions with
  `LogRecord` built-in attributes (e.g., `lacme_domain`, `lacme_expires_at`,
  `lacme_name`). Datetime values are converted to ISO strings.

### Event Name Mapping

| Event Class                      | Log Name                |
|----------------------------------|-------------------------|
| `CertificateIssued`              | `certificate_issued`    |
| `CertificateRenewed`             | `certificate_renewed`   |
| `CertificateExpiring`            | `certificate_expiring`  |
| `ChallengeFailed`                | `challenge_failed`      |
| `RateLimitWarning`               | `rate_limit_warning`    |
| `CertificateAuthorityInitialized`| `ca_initialized`        |
| `CACertificateIssued`            | `ca_certificate_issued` |

### Configuring Log Handlers

Capture structured event data with a custom handler:

```python
import json
import logging

class StructuredHandler(logging.Handler):
    def emit(self, record):
        event = getattr(record, "lacme_event", None)
        if event is None:
            return
        entry = {
            "timestamp": record.created,
            "event": event,
            "message": record.getMessage(),
        }
        # Collect all lacme_ prefixed fields from the record
        for key in vars(record):
            if key.startswith("lacme_") and key != "lacme_event":
                entry[key.removeprefix("lacme_")] = getattr(record, key)
        print(json.dumps(entry))

handler = StructuredHandler()
logging.getLogger("lacme.events").addHandler(handler)
logging.getLogger("lacme.events").setLevel(logging.INFO)
```

### Integration with Existing Logging

lacme uses the `"lacme"` logger hierarchy. Configure it alongside your
application logging:

```python
import logging

logging.basicConfig(level=logging.INFO)

# Adjust lacme log level
logging.getLogger("lacme").setLevel(logging.DEBUG)

# Or silence lacme events
logging.getLogger("lacme.events").setLevel(logging.WARNING)
```

## Prometheus Metrics

lacme provides optional Prometheus metrics via `prometheus_client`.

### Installation

```bash
pip install lacme[prometheus]
```

### Setup

```python
from lacme import EventDispatcher
from lacme.metrics import setup_metrics

dispatcher = EventDispatcher()

# Register metrics and subscribe to events
metrics = setup_metrics(dispatcher)

# Pass dispatcher to Client, RenewalManager, etc.
```

### Available Metrics

| Metric Name                              | Type    | Labels   | Description                    |
|------------------------------------------|---------|----------|--------------------------------|
| `lacme_certificates_issued_total`        | Counter | `domain` | Total certificates issued      |
| `lacme_certificates_renewed_total`       | Counter | `domain` | Total certificates renewed     |
| `lacme_certificate_failures_total`       | Counter | `domain` | Total issuance/renewal failures|
| `lacme_certificate_days_until_expiry`    | Gauge   | `domain` | Days until certificate expiry  |

### Isolated Registry

To avoid conflicts with other Prometheus collectors (e.g., in tests or
multi-tenant applications), pass a custom registry:

```python
from prometheus_client import CollectorRegistry
from lacme.metrics import setup_metrics

registry = CollectorRegistry()
metrics = setup_metrics(dispatcher, registry=registry)

# Access individual metrics
metrics.certificates_issued.labels(domain="example.com").inc()
metrics.days_until_expiry.labels(domain="example.com").set(45)
```

### Exposing Metrics

Serve the metrics endpoint in your web application:

```python
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

async def metrics_endpoint(request):
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
```

Or use `prometheus_client`'s built-in HTTP server:

```python
from prometheus_client import start_http_server

# Start metrics server on port 9090
start_http_server(9090)
```

### Complete Prometheus Example

```python
import asyncio
from prometheus_client import start_http_server
from lacme import Client, EventDispatcher, FileStore
from lacme.challenges.http01 import HTTP01Handler
from lacme.metrics import setup_metrics

dispatcher = EventDispatcher()
metrics = setup_metrics(dispatcher)

# Start Prometheus metrics server
start_http_server(9090)

async def main():
    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    async with Client(
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
        event_dispatcher=dispatcher,
    ) as client:
        # Issue certificate -- metrics are updated automatically
        bundle = await client.issue("example.com")

        # Start auto-renewal -- renewed/expiring metrics update on each sweep
        task = await client.auto_renew(
            interval_hours=12,
            days_before_expiry=30,
        )

        try:
            await asyncio.sleep(3600)
        finally:
            task.cancel()

asyncio.run(main())
```

## Rate Limit Monitoring

### RateLimitWarning Events

The `RateLimitTracker` emits `RateLimitWarning` events when the issuance
count for a registered domain reaches the warning threshold (default 90%
of the limit):

```python
from lacme import EventDispatcher, RateLimitTracker, RateLimitWarning
from lacme.ratelimit import FileRateLimitStore
from lacme import FileStore

dispatcher = EventDispatcher()

def on_rate_limit(event: RateLimitWarning):
    remaining = event.limit - event.current_count
    print(
        f"Rate limit: {event.registered_domain} -- "
        f"{remaining} issuances remaining in {event.window_hours}h window"
    )

dispatcher.subscribe(on_rate_limit, event_type=RateLimitWarning)

store = FileStore("~/.lacme")
tracker = RateLimitTracker(
    store=FileRateLimitStore(base=store.base),
    limit=50,
    warn_threshold=0.9,  # 90% = 45 issuances triggers warning
    event_dispatcher=dispatcher,
)
```

### Proactive Checking with check_rate_limits()

Check rate limits before attempting issuance:

```python
status = client.check_rate_limits(["example.com", "*.example.com"])

if not status.allowed:
    print("Rate limit would be exceeded!")
    for warning in status.warnings:
        print(f"  {warning}")
else:
    print(f"Issuance allowed. Current counts: {status.counts}")
    if status.warnings:
        print("Approaching limits:")
        for warning in status.warnings:
            print(f"  {warning}")
```

The `RateLimitStatus` object contains:

| Field      | Type              | Description                              |
|------------|-------------------|------------------------------------------|
| `allowed`  | `bool`            | True if issuance is within limits        |
| `counts`   | `dict[str, int]`  | Current count per registered domain      |
| `warnings` | `list[str]`       | Human-readable warning messages          |
