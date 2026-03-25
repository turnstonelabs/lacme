# mTLS

Helpers for creating `ssl.SSLContext` objects configured for mutual TLS. Accepts
PEM data as `bytes` or file paths as `str`/`Path`.

## PemInput

::: lacme.mtls.PemInput
    options:
      show_root_heading: true

## Server Context

::: lacme.mtls.server_ssl_context
    options:
      show_root_heading: true

## Client Context

::: lacme.mtls.client_ssl_context
    options:
      show_root_heading: true
