"""Shared test fixtures."""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509 import (
    CertificateBuilder,
    DNSName,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    random_serial_number,
)
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Callable

    from lacme._types import CertBundle


@pytest.fixture
def account_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def make_test_bundle() -> Callable[..., CertBundle]:
    """Factory fixture that generates a self-signed cert and returns a CertBundle."""

    def _make(domain: str = "example.com") -> CertBundle:
        from lacme._types import CertBundle as _CertBundle

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        expires = now + datetime.timedelta(days=90)
        subject = Name([NameAttribute(NameOID.COMMON_NAME, domain)])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(SubjectAlternativeName([DNSName(domain)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(Encoding.PEM)
        key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return _CertBundle(
            domain=domain,
            domains=(domain,),
            cert_pem=cert_pem,
            fullchain_pem=cert_pem,
            key_pem=key_pem,
            issued_at=now,
            expires_at=expires,
        )

    return _make
