# Errors

ACME error types and server error factory. Maps RFC 8555 Section 6.7 error URNs
to typed Python exceptions. Server responses with `application/problem+json` bodies
are parsed into the appropriate exception subclass.

## Base Exceptions

::: lacme.errors.ACMEError
    options:
      show_bases: true

::: lacme.errors.ACMEServerError
    options:
      show_bases: true

## ACME Protocol Errors

::: lacme.errors.BadNonceError
    options:
      show_bases: true

::: lacme.errors.RateLimitedError
    options:
      show_bases: true
      members:
        - retry_after

::: lacme.errors.UnauthorizedError
    options:
      show_bases: true

::: lacme.errors.BadCSRError
    options:
      show_bases: true

::: lacme.errors.CAAError
    options:
      show_bases: true

::: lacme.errors.AccountDoesNotExistError
    options:
      show_bases: true

::: lacme.errors.InvalidContactError
    options:
      show_bases: true

::: lacme.errors.MalformedError
    options:
      show_bases: true

::: lacme.errors.OrderNotReadyError
    options:
      show_bases: true

::: lacme.errors.RejectedIdentifierError
    options:
      show_bases: true

::: lacme.errors.UnsupportedIdentifierError
    options:
      show_bases: true

::: lacme.errors.ExternalAccountRequiredError
    options:
      show_bases: true

::: lacme.errors.AlreadyRevokedError
    options:
      show_bases: true

## Client-Side Errors

::: lacme.errors.ACMEValidationError
    options:
      show_bases: true

::: lacme.errors.ACMETimeoutError
    options:
      show_bases: true

::: lacme.errors.ACMEStoreError
    options:
      show_bases: true

::: lacme.errors.RateLimitPreventedError
    options:
      show_bases: true

::: lacme.errors.CertificateAuthorityError
    options:
      show_bases: true

## Factory

::: lacme.errors.server_error_from_response
    options:
      show_root_heading: true
