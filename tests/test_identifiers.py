"""Tests for shared DNS/IP identifier invariants."""

from __future__ import annotations

import ipaddress

import pytest

from lacme._identifiers import (
    identifier_key_from_value,
    normalize_protocol_identifier,
    validate_dns_identifier,
)
from lacme._jose import b64url_decode_strict, parse_unverified_jws
from lacme.ca import CertificateAuthority
from lacme.crypto import b64url_encode, generate_csr, generate_ec_key
from lacme.errors import CertificateAuthorityError
from lacme.models import Identifier, IdentifierType


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("", "non-empty"),
        ("2001:0db8::1", "canonical"),
        ("fe80::1%eth0", "Scoped IPv6"),
        ("192.168.001.1", "Invalid IP"),
    ],
)
def test_protocol_ip_identifiers_require_canonical_unscoped_values(
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_protocol_identifier("ip", value)


def test_identifier_model_rejects_noncanonical_ip() -> None:
    with pytest.raises(ValueError, match="canonical"):
        Identifier(type=IdentifierType.IP, value="2001:0db8::1")


def test_crypto_rejects_scoped_ipv6() -> None:
    address = ipaddress.IPv6Address("fe80::1%eth0")

    with pytest.raises(ValueError, match="Scoped IPv6"):
        generate_csr(generate_ec_key(), [address])


def test_ca_rejects_scoped_ipv6() -> None:
    ca = CertificateAuthority()
    ca.init()
    address = ipaddress.IPv6Address("fe80::1%eth0")

    with pytest.raises(CertificateAuthorityError, match="Scoped IPv6"):
        ca.issue(address)


@pytest.mark.parametrize(
    "value",
    [
        "Example.COM",
        "worker-1",
        "api.internal",
        "123",
        "xn--tst-qla.example",
        "*.Example.COM",
        "192.0.2.1",
    ],
)
def test_dns_identifier_validation_preserves_valid_ascii(value: str) -> None:
    assert validate_dns_identifier(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "täst.example",
        "bad..example",
        ".example",
        "example.",
        "xn--",
        "xn--a",
        "_bad.example",
        "-bad.example",
        "bad-.example",
        f"{'a' * 64}.example",
        "foo.*.example",
        "www*.example",
    ],
)
def test_dns_identifier_validation_rejects_invalid_certificate_names(value: str) -> None:
    with pytest.raises(ValueError):
        validate_dns_identifier(value)


def test_dns_identifier_semantic_keys_ignore_ascii_case_but_preserve_type() -> None:
    assert identifier_key_from_value("Example.COM") == identifier_key_from_value("example.com")
    assert identifier_key_from_value("192.0.2.1") != identifier_key_from_value(
        ipaddress.IPv4Address("192.0.2.1")
    )


def test_wildcard_can_be_disallowed_for_authorization_values() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        validate_dns_identifier("*.example.com", allow_wildcard=False)


@pytest.mark.parametrize(
    "value",
    ["e30", "", b64url_encode(b"canonical bytes")],
)
def test_strict_base64url_accepts_canonical_unpadded_values(value: str) -> None:
    assert b64url_encode(b64url_decode_strict(value)) == value


@pytest.mark.parametrize(
    "value",
    ["e30=", "e31", "ab+/", "!!!!", "a", "e3 0"],
)
def test_strict_base64url_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValueError):
        b64url_decode_strict(value)


def test_unverified_jws_parser_requires_all_flattened_fields() -> None:
    raw = b'{"protected":"e30","payload":"e30"}'
    with pytest.raises(ValueError, match="signature"):
        parse_unverified_jws(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'\xef\xbb\xbf{"protected":"e30","payload":"e30","signature":""}',
        b'{"protected":"77u_e30","payload":"e30","signature":""}',
        b'{"protected":"e30","payload":"77u_e30","signature":""}',
    ],
)
def test_unverified_jws_parser_rejects_utf8_bom(raw: bytes) -> None:
    with pytest.raises(ValueError, match="BOM"):
        parse_unverified_jws(raw)


def test_unverified_jws_parser_distinguishes_object_and_empty_payloads() -> None:
    object_payload = b'{"protected":"e30","payload":"e30","signature":""}'
    empty_payload = b'{"protected":"e30","payload":"","signature":""}'

    assert parse_unverified_jws(object_payload)[1] == {}
    assert parse_unverified_jws(empty_payload, payload_mode="empty")[1] == {}
    with pytest.raises(ValueError, match="JSON object"):
        parse_unverified_jws(empty_payload)
    with pytest.raises(ValueError, match="POST-as-GET"):
        parse_unverified_jws(object_payload, payload_mode="empty")
