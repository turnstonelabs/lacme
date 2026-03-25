# Rate Limiting

Store-backed awareness of Let's Encrypt rate limits (50 certificates per registered
domain per week). Checks issuance counts before requesting certificates and optionally
emits warning events when approaching thresholds.

## RateLimitTracker

::: lacme.ratelimit.RateLimitTracker
    options:
      show_bases: true
      members:
        - __init__
        - from_file_store
        - check
        - record

## Data Models

::: lacme.ratelimit.IssuanceRecord
    options:
      show_bases: true

::: lacme.ratelimit.RateLimitStatus
    options:
      show_bases: true

## Stores

::: lacme.ratelimit.RateLimitStore
    options:
      show_bases: true
      members:
        - record_issuance
        - get_issuances

::: lacme.ratelimit.MemoryRateLimitStore
    options:
      show_bases: true
      members:
        - __init__
        - record_issuance
        - get_issuances

::: lacme.ratelimit.FileRateLimitStore
    options:
      show_bases: true
      members:
        - __init__
        - record_issuance
        - get_issuances
