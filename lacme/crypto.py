"""Cryptographic operations for ACME (RFC 8555).

Pure functions for base64url encoding, EC P-256 key generation,
JWK/JWS construction, CSR generation, and key authorization computation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import (
    CertificateSigningRequestBuilder,
    DNSName,
    Name,
    NameAttribute,
    SubjectAlternativeName,
)
from cryptography.x509.oid import NameOID

# Precomputed padding table: length % 4 -> padding needed
_PAD = {0: "", 2: "==", 3: "="}


# ---------------------------------------------------------------------------
# base64url (RFC 4648 §5, no padding)
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    """Encode *data* to a base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    mod = len(s) % 4
    if mod == 1:
        msg = f"Invalid base64url string length: {len(s)}"
        raise ValueError(msg)
    padded = s + _PAD[mod]
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    """Generate a new EC P-256 private key."""
    return ec.generate_private_key(ec.SECP256R1())


# ---------------------------------------------------------------------------
# PEM serialization
# ---------------------------------------------------------------------------


def private_key_to_pem(
    key: ec.EllipticCurvePrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialize *key* to PEM format, optionally encrypted."""
    enc: serialization.KeySerializationEncryption
    if password is not None:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def private_key_from_pem(
    pem_data: bytes,
    password: bytes | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Deserialize a PEM-encoded private key."""
    key = serialization.load_pem_private_key(pem_data, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        msg = f"Expected EC private key, got {type(key).__name__}"
        raise TypeError(msg)
    if not isinstance(key.curve, ec.SECP256R1):
        msg = f"Expected P-256 key, got {key.curve.name}"
        raise TypeError(msg)
    return key


# ---------------------------------------------------------------------------
# JWK (RFC 7517)
# ---------------------------------------------------------------------------


def public_key_to_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Convert an EC public key to a JWK dict.

    Returns ``{kty, crv, x, y}`` with base64url-encoded fixed 32-byte
    coordinates.  Per erratum 7565, leading zeros in the fixed-length
    ECDSA coordinate fields are preserved.
    """
    nums = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(nums.x.to_bytes(32, "big")),
        "y": b64url_encode(nums.y.to_bytes(32, "big")),
    }


# RFC 7638 §3.2: required members per key type
_EC_REQUIRED_MEMBERS = ("crv", "kty", "x", "y")


def jwk_thumbprint(jwk: dict[str, str]) -> str:
    """Compute the JWK Thumbprint per RFC 7638.

    Only the required members for the key type are included in the
    canonical JSON (RFC 7638 §3.2).  For EC keys these are
    ``crv``, ``kty``, ``x``, ``y`` in lexicographic order.

    Returns a base64url-encoded SHA-256 digest.
    """
    required = {k: jwk[k] for k in _EC_REQUIRED_MEMBERS}
    canonical = json.dumps(required, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return b64url_encode(digest)


def account_thumbprint(account_key: ec.EllipticCurvePrivateKey) -> str:
    """Compute the JWK Thumbprint of the account key's public key."""
    return jwk_thumbprint(public_key_to_jwk(account_key.public_key()))


# ---------------------------------------------------------------------------
# Key authorization (RFC 8555 §8.1)
# ---------------------------------------------------------------------------


def key_authorization(token: str, account_key: ec.EllipticCurvePrivateKey) -> str:
    """Compute ``token + '.' + base64url(Thumbprint(accountKey))``."""
    return token + "." + account_thumbprint(account_key)


# ---------------------------------------------------------------------------
# CSR generation
# ---------------------------------------------------------------------------


def generate_csr(key: ec.EllipticCurvePrivateKey, domains: list[str]) -> bytes:
    """Generate a DER-encoded CSR with *domains* as SANs.

    CN is set to the first domain.  All domains appear in the SAN extension.
    """
    if not domains:
        msg = "At least one domain is required"
        raise ValueError(msg)
    builder = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(
            SubjectAlternativeName([DNSName(d) for d in domains]),
            critical=False,
        )
    )
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# JWS (RFC 7515, Flattened JSON Serialization)
# ---------------------------------------------------------------------------


def jws_encode(
    payload: bytes,
    key: ec.EllipticCurvePrivateKey,
    *,
    nonce: str | None = None,
    url: str,
    kid: str | None = None,
) -> dict[str, Any]:
    """Create a JWS in Flattened JSON Serialization.

    Protected header always contains ``alg`` (ES256) and ``url``.
    ``nonce`` is included when provided (omit for key rollover inner JWS).
    If *kid* is ``None`` the header includes ``jwk`` (for ``newAccount``).
    Otherwise it includes ``kid`` (for all subsequent requests).

    An empty *payload* (``b""``) signifies POST-as-GET: the ``"payload"``
    field in the returned dict will be the empty string ``""``.
    """
    # Build protected header
    header: dict[str, Any] = {"alg": "ES256", "url": url}
    if nonce is not None:
        header["nonce"] = nonce
    if kid is not None:
        header["kid"] = kid
    else:
        header["jwk"] = public_key_to_jwk(key.public_key())

    protected_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))

    # Encode payload
    payload_b64 = "" if payload == b"" else b64url_encode(payload)

    # Signing input: ASCII(BASE64URL(header)) + '.' + BASE64URL(payload)
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    signature = _sign_es256(signing_input, key)

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url_encode(signature),
    }


def _sign_es256(signing_input: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign with ES256 and return raw R||S (64 bytes).

    The ``cryptography`` library produces DER-encoded ECDSA signatures.
    This function decodes them to *(r, s)* integers and re-encodes each
    as a fixed 32-byte big-endian value, concatenated.
    """
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# JWS HMAC (for External Account Binding)
# ---------------------------------------------------------------------------


def jws_encode_hmac(
    payload: bytes,
    mac_key: bytes,
    *,
    alg: str = "HS256",
    kid: str,
    url: str,
) -> dict[str, Any]:
    """Create a JWS in Flattened JSON Serialization using HMAC.

    Used for External Account Binding (RFC 8555 §7.3.4).
    Protected header contains ``alg``, ``kid``, and ``url`` only.

    Args:
        payload: Raw bytes to sign (typically a serialized JWK).
        mac_key: Decoded HMAC key (raw bytes, not base64url-encoded).
        alg: MAC algorithm identifier.  Only ``"HS256"`` is supported.
        kid: External account key identifier (from the CA).
        url: ACME ``newAccount`` URL.

    Raises:
        ValueError: If *alg* is not ``"HS256"``.
    """
    if alg != "HS256":
        msg = f"Unsupported MAC algorithm: {alg!r} (only HS256 is supported)"
        raise ValueError(msg)

    header: dict[str, Any] = {"alg": alg, "kid": kid, "url": url}
    protected_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(payload)

    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    signature = _hmac.digest(mac_key, signing_input, "sha256")

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": b64url_encode(signature),
    }


# ---------------------------------------------------------------------------
# Certificate DER conversion
# ---------------------------------------------------------------------------


def pem_to_der_certificate(cert_pem: bytes | str) -> bytes:
    """Convert a PEM-encoded certificate to DER format.

    If the PEM contains a chain, only the first (leaf) certificate
    is converted.
    """
    from cryptography.x509 import load_pem_x509_certificates

    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode("ascii")
    certs = load_pem_x509_certificates(cert_pem)
    if not certs:
        msg = "No certificates found in PEM data"
        raise ValueError(msg)
    return certs[0].public_bytes(serialization.Encoding.DER)
