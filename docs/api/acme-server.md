# ACME Responder

ASGI application implementing ACME protocol endpoints. Delegates certificate signing
to a `CertificateAuthority` and can be mounted in any ASGI framework (Starlette,
FastAPI, etc.) at a path prefix.

## ACMEResponder

::: lacme.acme_server.ACMEResponder
    options:
      show_bases: true
      members:
        - __init__
        - __call__

## ChallengeValidator

::: lacme.acme_server.ChallengeValidator
    options:
      show_bases: true
      members:
        - validate
