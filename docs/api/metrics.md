# Metrics

Optional Prometheus metrics integration. Subscribes to `EventDispatcher` events
and updates Prometheus counters and gauges for certificate lifecycle observability.
Requires `prometheus_client` (install with `pip install lacme[prometheus]`).

## setup_metrics

::: lacme.metrics.setup_metrics
    options:
      show_root_heading: true

## MetricsCollector

::: lacme.metrics.MetricsCollector
    options:
      show_bases: true
      members:
        - __init__
        - certificates_issued
        - certificates_renewed
        - certificate_failures
        - days_until_expiry
