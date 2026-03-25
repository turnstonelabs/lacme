# Testing

Test utilities for lacme. Provides `MockACMEServer`, an in-process ACME server
backed by `httpx.MockTransport` for integration testing without network access.

::: lacme.testing.MockACMEServer
    options:
      show_bases: true
      members:
        - __init__
        - as_transport
        - validate_challenge
