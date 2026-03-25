# Events

Typed event system for lacme observability. Provides frozen dataclasses for
certificate lifecycle events and a centralized `EventDispatcher` for subscribing
to and emitting events.

## EventDispatcher

::: lacme.events.EventDispatcher
    options:
      show_bases: true
      members:
        - __init__
        - subscribe
        - unsubscribe
        - emit
        - emit_sync

## Certificate Events

::: lacme.events.CertificateIssued
    options:
      show_bases: true

::: lacme.events.CertificateRenewed
    options:
      show_bases: true

::: lacme.events.CertificateExpiring
    options:
      show_bases: true

## Challenge Events

::: lacme.events.ChallengeFailed
    options:
      show_bases: true

## Rate Limit Events

::: lacme.events.RateLimitWarning
    options:
      show_bases: true

## CA Events

::: lacme.events.CertificateAuthorityInitialized
    options:
      show_bases: true

::: lacme.events.CACertificateIssued
    options:
      show_bases: true
