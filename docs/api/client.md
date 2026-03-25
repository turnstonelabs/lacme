# Client

Async ACME v2 protocol client implementing the full certificate lifecycle: account
creation, order placement, challenge handling, finalization, and certificate download.

## Directory URLs

::: lacme.client.LETSENCRYPT_DIRECTORY
    options:
      show_root_heading: true

::: lacme.client.LETSENCRYPT_STAGING_DIRECTORY
    options:
      show_root_heading: true

## Client

::: lacme.client.Client
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
        - auto_renew
