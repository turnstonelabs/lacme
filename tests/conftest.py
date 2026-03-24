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

    def _make(
        domain: str = "example.com",
        *,
        expires_at: datetime.datetime | None = None,
        issued_at: datetime.datetime | None = None,
    ) -> CertBundle:
        from lacme._types import CertBundle as _CertBundle

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        effective_issued = issued_at if issued_at is not None else now
        effective_expires = (
            expires_at
            if expires_at is not None
            else now
            + datetime.timedelta(
                days=90,
            )
        )
        # Ensure not_valid_before < not_valid_after for the X.509 builder,
        # even when effective_expires is in the past (e.g. testing expired certs).
        cert_not_before = min(now, effective_expires - datetime.timedelta(days=1))
        subject = Name([NameAttribute(NameOID.COMMON_NAME, domain)])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(cert_not_before)
            .not_valid_after(effective_expires)
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
            issued_at=effective_issued,
            expires_at=effective_expires,
        )

    return _make
