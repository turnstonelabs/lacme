"""Tests for lacme.models — RFC 8555 protocol data models."""

from __future__ import annotations

import pytest

from lacme.models import (
    Account,
    AccountStatus,
    Authorization,
    AuthorizationStatus,
    Challenge,
    ChallengeStatus,
    Directory,
    DirectoryMeta,
    Identifier,
    IdentifierType,
    Order,
    OrderStatus,
    Problem,
    RevocationReason,
    SubProblem,
)

# ---------------------------------------------------------------------------
# StrEnum
# ---------------------------------------------------------------------------


class TestStrEnums:
    def test_account_status_equals_string(self) -> None:
        assert AccountStatus.VALID == "valid"

    def test_order_status_values(self) -> None:
        assert set(OrderStatus) == {"pending", "ready", "processing", "valid", "invalid"}

    def test_authz_status_values(self) -> None:
        assert set(AuthorizationStatus) == {
            "pending",
            "valid",
            "invalid",
            "deactivated",
            "expired",
            "revoked",
        }

    def test_challenge_status_values(self) -> None:
        assert set(ChallengeStatus) == {"pending", "processing", "valid", "invalid"}

    def test_identifier_type(self) -> None:
        assert set(IdentifierType) == {"dns", "ip"}


# ---------------------------------------------------------------------------
# DirectoryMeta
# ---------------------------------------------------------------------------


class TestDirectoryMeta:
    def test_from_dict_full(self) -> None:
        meta = DirectoryMeta.from_dict(
            {
                "termsOfService": "https://example.com/tos",
                "website": "https://example.com",
                "caaIdentities": ["example.com", "example.org"],
                "externalAccountRequired": True,
            }
        )
        assert meta.terms_of_service == "https://example.com/tos"
        assert meta.website == "https://example.com"
        assert meta.caa_identities == ("example.com", "example.org")
        assert meta.external_account_required is True

    def test_from_dict_defaults(self) -> None:
        meta = DirectoryMeta.from_dict({})
        assert meta.terms_of_service is None
        assert meta.website is None
        assert meta.caa_identities == ()
        assert meta.external_account_required is False


# ---------------------------------------------------------------------------
# Directory
# ---------------------------------------------------------------------------

_DIRECTORY_DATA: dict[str, object] = {
    "newNonce": "https://acme.example/new-nonce",
    "newAccount": "https://acme.example/new-account",
    "newOrder": "https://acme.example/new-order",
    "revokeCert": "https://acme.example/revoke-cert",
    "keyChange": "https://acme.example/key-change",
}


class TestDirectory:
    def test_from_dict_required_fields(self) -> None:
        d = Directory.from_dict(_DIRECTORY_DATA)
        assert d.new_nonce == "https://acme.example/new-nonce"
        assert d.new_account == "https://acme.example/new-account"
        assert d.new_order == "https://acme.example/new-order"
        assert d.revoke_cert == "https://acme.example/revoke-cert"
        assert d.key_change == "https://acme.example/key-change"
        assert d.new_authz is None
        assert d.meta is None

    def test_from_dict_with_optional(self) -> None:
        data = {
            **_DIRECTORY_DATA,
            "newAuthz": "https://acme.example/new-authz",
            "meta": {"termsOfService": "https://example.com/tos"},
        }
        d = Directory.from_dict(data)
        assert d.new_authz == "https://acme.example/new-authz"
        assert d.meta is not None
        assert d.meta.terms_of_service == "https://example.com/tos"


# ---------------------------------------------------------------------------
# Identifier
# ---------------------------------------------------------------------------


class TestIdentifier:
    def test_from_dict(self) -> None:
        ident = Identifier.from_dict({"type": "dns", "value": "example.com"})
        assert ident.type == IdentifierType.DNS
        assert ident.value == "example.com"

    def test_to_dict_roundtrip(self) -> None:
        data = {"type": "dns", "value": "example.com"}
        ident = Identifier.from_dict(data)
        assert ident.to_dict() == data

    def test_ip_identifier(self) -> None:
        ident = Identifier.from_dict({"type": "ip", "value": "192.0.2.1"})
        assert ident.type == IdentifierType.IP
        assert ident.value == "192.0.2.1"
        assert ident.to_dict() == {"type": "ip", "value": "192.0.2.1"}

    def test_ip_identifier_v6(self) -> None:
        ident = Identifier.from_dict({"type": "ip", "value": "2001:db8::1"})
        assert ident.type == IdentifierType.IP
        assert ident.value == "2001:db8::1"


# ---------------------------------------------------------------------------
# SubProblem / Problem
# ---------------------------------------------------------------------------


class TestProblem:
    def test_from_dict_full(self) -> None:
        p = Problem.from_dict(
            {
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "bad request",
                "status": 400,
                "subproblems": [
                    {
                        "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                        "detail": "not allowed",
                        "identifier": {"type": "dns", "value": "evil.com"},
                    }
                ],
            }
        )
        assert p.type == "urn:ietf:params:acme:error:malformed"
        assert p.detail == "bad request"
        assert p.status == 400
        assert len(p.subproblems) == 1
        sp = p.subproblems[0]
        assert sp.identifier is not None
        assert sp.identifier.value == "evil.com"

    def test_from_dict_defaults(self) -> None:
        p = Problem.from_dict({})
        assert p.type == ""
        assert p.detail is None
        assert p.status is None
        assert p.subproblems == ()


class TestSubProblem:
    def test_without_identifier(self) -> None:
        sp = SubProblem.from_dict({"type": "some:error", "detail": "oops"})
        assert sp.identifier is None


# ---------------------------------------------------------------------------
# Challenge
# ---------------------------------------------------------------------------


class TestChallenge:
    def test_from_dict_pending(self) -> None:
        c = Challenge.from_dict(
            {
                "type": "http-01",
                "url": "https://acme.example/chall/1",
                "status": "pending",
                "token": "abc123",
            }
        )
        assert c.type == "http-01"
        assert c.status == ChallengeStatus.PENDING
        assert c.token == "abc123"
        assert c.validated is None
        assert c.error is None

    def test_from_dict_valid_with_timestamp(self) -> None:
        c = Challenge.from_dict(
            {
                "type": "dns-01",
                "url": "https://acme.example/chall/2",
                "status": "valid",
                "token": "xyz",
                "validated": "2024-06-15T12:00:00Z",
            }
        )
        assert c.status == ChallengeStatus.VALID
        assert c.validated is not None
        assert c.validated.year == 2024

    def test_from_dict_with_error(self) -> None:
        c = Challenge.from_dict(
            {
                "type": "http-01",
                "url": "https://acme.example/chall/3",
                "status": "invalid",
                "token": "tok",
                "error": {
                    "type": "urn:ietf:params:acme:error:connection",
                    "detail": "could not connect",
                },
            }
        )
        assert c.error is not None
        assert c.error.detail == "could not connect"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_from_dict_full(self) -> None:
        authz = Authorization.from_dict(
            {
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "pending",
                "expires": "2024-12-31T23:59:59Z",
                "challenges": [
                    {
                        "type": "http-01",
                        "url": "https://acme.example/chall/1",
                        "status": "pending",
                        "token": "tok1",
                    },
                    {
                        "type": "dns-01",
                        "url": "https://acme.example/chall/2",
                        "status": "pending",
                        "token": "tok2",
                    },
                ],
                "wildcard": False,
            },
            url="https://acme.example/authz/1",
        )
        assert authz.identifier.value == "example.com"
        assert authz.status == AuthorizationStatus.PENDING
        assert authz.url == "https://acme.example/authz/1"
        assert len(authz.challenges) == 2

    def test_find_challenge(self) -> None:
        authz = Authorization.from_dict(
            {
                "identifier": {"type": "dns", "value": "x.com"},
                "status": "pending",
                "challenges": [
                    {"type": "http-01", "url": "u1", "status": "pending", "token": "t1"},
                    {"type": "dns-01", "url": "u2", "status": "pending", "token": "t2"},
                ],
            },
        )
        http = authz.find_challenge("http-01")
        assert http is not None
        assert http.token == "t1"

        dns = authz.find_challenge("dns-01")
        assert dns is not None
        assert dns.token == "t2"

        assert authz.find_challenge("tls-alpn-01") is None

    def test_wildcard_default(self) -> None:
        authz = Authorization.from_dict(
            {
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "valid",
            }
        )
        assert authz.wildcard is False

    def test_wildcard_true(self) -> None:
        authz = Authorization.from_dict(
            {
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "valid",
                "wildcard": True,
            }
        )
        assert authz.wildcard is True


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


class TestAccount:
    def test_from_dict_full(self) -> None:
        acct = Account.from_dict(
            {
                "status": "valid",
                "contact": ["mailto:admin@example.com"],
                "orders": "https://acme.example/orders/1",
            },
            url="https://acme.example/acct/1",
        )
        assert acct.status == AccountStatus.VALID
        assert acct.contact == ("mailto:admin@example.com",)
        assert acct.orders == "https://acme.example/orders/1"
        assert acct.url == "https://acme.example/acct/1"

    def test_from_dict_defaults(self) -> None:
        acct = Account.from_dict({"status": "deactivated"})
        assert acct.contact == ()
        assert acct.orders is None
        assert acct.url == ""


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


class TestOrder:
    def test_from_dict_pending(self) -> None:
        order = Order.from_dict(
            {
                "status": "pending",
                "identifiers": [
                    {"type": "dns", "value": "example.com"},
                    {"type": "dns", "value": "www.example.com"},
                ],
                "authorizations": [
                    "https://acme.example/authz/1",
                    "https://acme.example/authz/2",
                ],
                "finalize": "https://acme.example/finalize/1",
                "expires": "2025-01-01T00:00:00Z",
            },
            url="https://acme.example/order/1",
        )
        assert order.status == OrderStatus.PENDING
        assert len(order.identifiers) == 2
        assert order.identifiers[0].value == "example.com"
        assert len(order.authorizations) == 2
        assert order.finalize == "https://acme.example/finalize/1"
        assert order.expires is not None
        assert order.expires.year == 2025
        assert order.certificate is None
        assert order.url == "https://acme.example/order/1"

    def test_from_dict_valid_with_certificate(self) -> None:
        order = Order.from_dict(
            {
                "status": "valid",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "certificate": "https://acme.example/cert/1",
            }
        )
        assert order.status == OrderStatus.VALID
        assert order.certificate == "https://acme.example/cert/1"

    def test_from_dict_with_error(self) -> None:
        order = Order.from_dict(
            {
                "status": "invalid",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "error": {
                    "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                    "detail": "nope",
                },
            }
        )
        assert order.error is not None
        assert order.error.detail == "nope"

    def test_from_dict_defaults(self) -> None:
        order = Order.from_dict(
            {
                "status": "pending",
                "identifiers": [{"type": "dns", "value": "a.com"}],
            }
        )
        assert order.authorizations == ()
        assert order.finalize == ""
        assert order.expires is None
        assert order.not_before is None
        assert order.not_after is None
        assert order.error is None
        assert order.certificate is None


# ---------------------------------------------------------------------------
# Frozen immutability
# ---------------------------------------------------------------------------


class TestFrozen:
    def test_identifier_frozen(self) -> None:
        ident = Identifier(type=IdentifierType.DNS, value="x.com")
        with pytest.raises(AttributeError):
            ident.value = "y.com"  # type: ignore[misc]

    def test_order_frozen(self) -> None:
        order = Order.from_dict(
            {
                "status": "pending",
                "identifiers": [{"type": "dns", "value": "a.com"}],
            }
        )
        with pytest.raises(AttributeError):
            order.status = OrderStatus.VALID  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RevocationReason
# ---------------------------------------------------------------------------


class TestRevocationReason:
    def test_values(self) -> None:
        assert RevocationReason.UNSPECIFIED == 0
        assert RevocationReason.KEY_COMPROMISE == 1
        assert RevocationReason.AFFILIATION_CHANGED == 3
        assert RevocationReason.SUPERSEDED == 4
        assert RevocationReason.CESSATION_OF_OPERATION == 5

    def test_is_int(self) -> None:
        assert isinstance(RevocationReason.KEY_COMPROMISE, int)

    def test_usable_as_int(self) -> None:
        # Can be passed directly where int is expected
        assert RevocationReason.SUPERSEDED + 0 == 4
