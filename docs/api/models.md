# Models

RFC 8555 protocol data models. Frozen dataclasses representing ACME directory,
account, order, authorization, and challenge objects, plus status enumerations
and revocation reason codes.

## Core Models

::: lacme.models.Directory
    options:
      show_bases: true

::: lacme.models.DirectoryMeta
    options:
      show_bases: true

::: lacme.models.Account
    options:
      show_bases: true

::: lacme.models.Order
    options:
      show_bases: true

::: lacme.models.Authorization
    options:
      show_bases: true
      members:
        - find_challenge

::: lacme.models.Challenge
    options:
      show_bases: true

::: lacme.models.Identifier
    options:
      show_bases: true

## Error Models

::: lacme.models.Problem
    options:
      show_bases: true

::: lacme.models.SubProblem
    options:
      show_bases: true

## Status Enumerations

::: lacme.models.AccountStatus
    options:
      show_bases: true

::: lacme.models.OrderStatus
    options:
      show_bases: true

::: lacme.models.AuthorizationStatus
    options:
      show_bases: true

::: lacme.models.ChallengeStatus
    options:
      show_bases: true

::: lacme.models.IdentifierType
    options:
      show_bases: true

## Revocation

::: lacme.models.RevocationReason
    options:
      show_bases: true
