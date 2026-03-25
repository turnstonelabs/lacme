# Sync Client

Synchronous wrapper around the async `Client`. Provides `SyncClient`, a blocking
interface that delegates every operation to the async client through a managed event loop.

## SyncClient

::: lacme.sync.SyncClient
    options:
      show_bases: true
      members:
        - __init__
        - close
        - directory
        - create_account
        - deactivate_account
        - rollover_key
        - create_order
        - get_authorization
        - get_authorizations
        - create_authorization
        - respond_to_challenge
        - poll_authorization
        - finalize_order
        - poll_order
        - download_certificate
        - issue
        - revoke
        - revoke_with_cert_key
        - check_rate_limits

## SyncChallengeHandler

::: lacme.sync.SyncChallengeHandler
    options:
      show_bases: true
      members:
        - provision
        - deprovision
