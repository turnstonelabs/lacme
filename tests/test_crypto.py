"""Tests for lacme.crypto — base64url, JWK, JWS, CSR, key authorization."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_csr

from lacme.crypto import (
    _sign_es256,
    account_thumbprint,
    b64url_decode,
    b64url_encode,
    generate_csr,
    generate_ec_key,
    jwk_thumbprint,
    jws_encode,
    jws_encode_hmac,
    key_authorization,
    pem_to_der_certificate,
    private_key_from_pem,
    private_key_to_pem,
    public_key_to_jwk,
)

# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


class TestBase64Url:
    def test_encode_empty(self) -> None:
        assert b64url_encode(b"") == ""

    def test_encode_no_padding(self) -> None:
        encoded = b64url_encode(b"hello")
        assert "=" not in encoded

    def test_roundtrip(self) -> None:
        data = b"\x00\x01\x02\xff\xfe\xfd"
        assert b64url_decode(b64url_encode(data)) == data

    def test_decode_with_padding(self) -> None:
        encoded_no_pad = b64url_encode(b"test")
        encoded_padded = encoded_no_pad + "=="
        assert b64url_decode(encoded_padded) == b"test"

    def test_url_safe_characters(self) -> None:
        # Bytes that would produce + and / in standard base64
        data = b"\xfb\xff\xfe"
        encoded = b64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_decode_invalid_length_mod4_eq_1(self) -> None:
        with pytest.raises(ValueError, match="Invalid base64url string length"):
            b64url_decode("A")  # length 1 % 4 == 1 is invalid

    def test_decode_invalid_length_5(self) -> None:
        with pytest.raises(ValueError, match="Invalid base64url string length"):
            b64url_decode("ABCDE")  # length 5 % 4 == 1


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    def test_generates_p256(self) -> None:
        key = generate_ec_key()
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)
        assert key.key_size == 256

    def test_keys_are_unique(self) -> None:
        k1 = generate_ec_key()
        k2 = generate_ec_key()
        n1 = k1.public_key().public_numbers()
        n2 = k2.public_key().public_numbers()
        assert n1.x != n2.x or n1.y != n2.y


# ---------------------------------------------------------------------------
# PEM serialization
# ---------------------------------------------------------------------------


class TestPEMSerialization:
    def test_roundtrip_unencrypted(self) -> None:
        key = generate_ec_key()
        pem = private_key_to_pem(key)
        loaded = private_key_from_pem(pem)
        assert loaded.public_key().public_numbers() == key.public_key().public_numbers()

    def test_roundtrip_encrypted(self) -> None:
        key = generate_ec_key()
        pem = private_key_to_pem(key, password=b"secret")
        loaded = private_key_from_pem(pem, password=b"secret")
        assert loaded.public_key().public_numbers() == key.public_key().public_numbers()

    def test_wrong_password_raises(self) -> None:
        key = generate_ec_key()
        pem = private_key_to_pem(key, password=b"correct")
        with pytest.raises(Exception):  # noqa: B017
            private_key_from_pem(pem, password=b"wrong")

    def test_pem_starts_with_marker(self) -> None:
        key = generate_ec_key()
        pem = private_key_to_pem(key)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_non_ec_key_raises_type_error(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with pytest.raises(TypeError, match="Expected EC private key"):
            private_key_from_pem(pem)

    def test_non_p256_ec_key_raises_type_error(self) -> None:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        p384_key = ec.generate_private_key(ec.SECP384R1())
        pem = p384_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with pytest.raises(TypeError, match="P-256"):
            private_key_from_pem(pem)


# ---------------------------------------------------------------------------
# JWK
# ---------------------------------------------------------------------------


class TestJWK:
    def test_jwk_fields(self) -> None:
        key = generate_ec_key()
        jwk = public_key_to_jwk(key.public_key())
        assert set(jwk.keys()) == {"kty", "crv", "x", "y"}
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"

    def test_coordinate_length_32_bytes(self) -> None:
        # P-256 coordinates must always be exactly 32 bytes (erratum 7565)
        for _ in range(10):
            key = generate_ec_key()
            jwk = public_key_to_jwk(key.public_key())
            assert len(b64url_decode(jwk["x"])) == 32
            assert len(b64url_decode(jwk["y"])) == 32

    def test_deterministic(self) -> None:
        key = generate_ec_key()
        jwk1 = public_key_to_jwk(key.public_key())
        jwk2 = public_key_to_jwk(key.public_key())
        assert jwk1 == jwk2


# ---------------------------------------------------------------------------
# JWK Thumbprint
# ---------------------------------------------------------------------------


class TestJWKThumbprint:
    def test_thumbprint_is_base64url(self) -> None:
        key = generate_ec_key()
        jwk = public_key_to_jwk(key.public_key())
        tp = jwk_thumbprint(jwk)
        # SHA-256 = 32 bytes → base64url = 43 chars (no padding)
        assert len(tp) == 43
        # Verify it decodes
        raw = b64url_decode(tp)
        assert len(raw) == 32

    def test_thumbprint_uses_sorted_keys(self) -> None:
        # Manually construct JWK with unsorted keys — thumbprint should
        # still sort them canonically
        jwk_unsorted = {"y": "abc", "kty": "EC", "x": "def", "crv": "P-256"}
        jwk_sorted = {"crv": "P-256", "kty": "EC", "x": "def", "y": "abc"}
        assert jwk_thumbprint(jwk_unsorted) == jwk_thumbprint(jwk_sorted)

    def test_account_thumbprint_convenience(self) -> None:
        key = generate_ec_key()
        jwk = public_key_to_jwk(key.public_key())
        assert account_thumbprint(key) == jwk_thumbprint(jwk)

    def test_thumbprint_ignores_extra_jwk_fields(self) -> None:
        key = generate_ec_key()
        jwk = public_key_to_jwk(key.public_key())
        tp_clean = jwk_thumbprint(jwk)
        # Add extra fields that RFC 7638 says should be excluded
        jwk_extra = {**jwk, "kid": "some-id", "use": "sig", "key_ops": ["verify"]}
        tp_extra = jwk_thumbprint(jwk_extra)
        assert tp_clean == tp_extra


# ---------------------------------------------------------------------------
# Key authorization
# ---------------------------------------------------------------------------


class TestKeyAuthorization:
    def test_format(self) -> None:
        key = generate_ec_key()
        token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        ka = key_authorization(token, key)
        assert ka.startswith(token + ".")
        # The thumbprint part should be 43 chars
        parts = ka.split(".")
        assert len(parts) == 2
        assert len(parts[1]) == 43


# ---------------------------------------------------------------------------
# CSR generation
# ---------------------------------------------------------------------------


class TestCSRGeneration:
    def test_single_domain(self) -> None:
        key = generate_ec_key()
        der = generate_csr(key, ["example.com"])
        csr = load_der_x509_csr(der)
        assert csr.is_signature_valid
        # Check CN
        from cryptography.x509.oid import NameOID

        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "example.com"

    def test_multiple_domains_in_san(self) -> None:
        key = generate_ec_key()
        domains = ["example.com", "www.example.com", "api.example.com"]
        der = generate_csr(key, domains)
        csr = load_der_x509_csr(der)
        from cryptography.x509 import DNSName, SubjectAlternativeName

        san_ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)
        san_domains = san_ext.value.get_values_for_type(DNSName)
        assert san_domains == domains

    def test_empty_domains_raises(self) -> None:
        key = generate_ec_key()
        with pytest.raises(ValueError, match="At least one domain"):
            generate_csr(key, [])

    def test_returns_der_bytes(self) -> None:
        key = generate_ec_key()
        der = generate_csr(key, ["example.com"])
        assert isinstance(der, bytes)
        # DER starts with 0x30 (SEQUENCE tag)
        assert der[0] == 0x30


# ---------------------------------------------------------------------------
# JWS encoding
# ---------------------------------------------------------------------------


class TestJWSEncode:
    def test_structure(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b'{"test": true}',
            key,
            nonce="nonce123",
            url="https://acme.example/new-account",
        )
        assert set(jws.keys()) == {"protected", "payload", "signature"}

    def test_protected_header_with_jwk(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b"{}",
            key,
            nonce="n1",
            url="https://acme.example/new-account",
        )
        header = json.loads(b64url_decode(jws["protected"]))
        assert header["alg"] == "ES256"
        assert header["nonce"] == "n1"
        assert header["url"] == "https://acme.example/new-account"
        assert "jwk" in header
        assert "kid" not in header

    def test_protected_header_with_kid(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b"{}",
            key,
            nonce="n2",
            url="https://acme.example/order/1",
            kid="https://acme.example/acct/1",
        )
        header = json.loads(b64url_decode(jws["protected"]))
        assert header["kid"] == "https://acme.example/acct/1"
        assert "jwk" not in header

    def test_post_as_get_empty_payload(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b"",
            key,
            nonce="n3",
            url="https://acme.example/order/1",
            kid="https://acme.example/acct/1",
        )
        assert jws["payload"] == ""

    def test_payload_encoding(self) -> None:
        key = generate_ec_key()
        payload = b'{"hello": "world"}'
        jws = jws_encode(
            payload,
            key,
            nonce="n4",
            url="https://acme.example/test",
        )
        decoded = b64url_decode(jws["payload"])
        assert decoded == payload

    def test_signature_verifiable(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b'{"test": true}',
            key,
            nonce="nonce",
            url="https://acme.example/test",
        )
        # Reconstruct signing input and verify
        signing_input = (jws["protected"] + "." + jws["payload"]).encode("ascii")
        sig_bytes = b64url_decode(jws["signature"])
        # Convert R||S back to DER for verification
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = encode_dss_signature(r, s)
        # This will raise if invalid
        from cryptography.hazmat.primitives.hashes import SHA256

        key.public_key().verify(
            der_sig,
            signing_input,
            ec.ECDSA(SHA256()),
        )


# ---------------------------------------------------------------------------
# _sign_es256
# ---------------------------------------------------------------------------


class TestSignES256:
    def test_output_length(self) -> None:
        key = generate_ec_key()
        sig = _sign_es256(b"test data", key)
        assert len(sig) == 64

    def test_signature_verifiable(self) -> None:
        key = generate_ec_key()
        data = b"hello world"
        sig = _sign_es256(data, key)
        # Convert R||S back to DER
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives.hashes import SHA256

        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der_sig = encode_dss_signature(r, s)
        key.public_key().verify(der_sig, data, ec.ECDSA(SHA256()))


# ---------------------------------------------------------------------------
# JWS nonce=None (for key rollover inner JWS)
# ---------------------------------------------------------------------------


class TestJWSNonceOptional:
    def test_nonce_omitted_from_header(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b'{"test": true}',
            key,
            url="https://acme.example/key-change",
        )
        header = json.loads(b64url_decode(jws["protected"]))
        assert "nonce" not in header
        assert header["alg"] == "ES256"
        assert header["url"] == "https://acme.example/key-change"

    def test_nonce_included_when_provided(self) -> None:
        key = generate_ec_key()
        jws = jws_encode(
            b"{}",
            key,
            nonce="test-nonce",
            url="https://acme.example/test",
        )
        header = json.loads(b64url_decode(jws["protected"]))
        assert header["nonce"] == "test-nonce"


# ---------------------------------------------------------------------------
# JWS HMAC (for External Account Binding)
# ---------------------------------------------------------------------------


class TestJWSEncodeHMAC:
    def test_structure(self) -> None:
        jws = jws_encode_hmac(
            b'{"kty":"EC"}',
            b"secret-key",
            kid="external-kid",
            url="https://acme.example/new-account",
        )
        assert set(jws.keys()) == {"protected", "payload", "signature"}

    def test_protected_header(self) -> None:
        jws = jws_encode_hmac(
            b'{"kty":"EC"}',
            b"secret-key",
            kid="ext-123",
            url="https://acme.example/new-account",
        )
        header = json.loads(b64url_decode(jws["protected"]))
        assert header == {
            "alg": "HS256",
            "kid": "ext-123",
            "url": "https://acme.example/new-account",
        }
        # Must NOT contain nonce or jwk
        assert "nonce" not in header
        assert "jwk" not in header

    def test_payload_roundtrip(self) -> None:
        payload = b'{"kty":"EC","crv":"P-256"}'
        jws = jws_encode_hmac(
            payload,
            b"key",
            kid="k",
            url="https://example.com",
        )
        decoded = b64url_decode(jws["payload"])
        assert decoded == payload

    def test_signature_verifiable(self) -> None:
        import hmac

        mac_key = b"test-mac-key-1234"
        payload = b'{"test": true}'
        jws = jws_encode_hmac(
            payload,
            mac_key,
            kid="kid-1",
            url="https://acme.example/new-account",
        )
        signing_input = (jws["protected"] + "." + jws["payload"]).encode("ascii")
        expected_sig = hmac.digest(mac_key, signing_input, "sha256")
        actual_sig = b64url_decode(jws["signature"])
        assert actual_sig == expected_sig

    def test_unsupported_alg_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported MAC algorithm"):
            jws_encode_hmac(b"{}", b"key", alg="HS512", kid="k", url="u")


# ---------------------------------------------------------------------------
# PEM to DER certificate conversion
# ---------------------------------------------------------------------------


class TestPEMToDER:
    def test_roundtrip(self) -> None:
        import datetime

        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import (
            CertificateBuilder,
            DNSName,
            Name,
            NameAttribute,
            SubjectAlternativeName,
            load_der_x509_certificate,
            random_serial_number,
        )
        from cryptography.x509.oid import NameOID

        key = generate_ec_key()
        now = datetime.datetime.now(datetime.UTC)
        subject = Name([NameAttribute(NameOID.COMMON_NAME, "test.com")])
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(SubjectAlternativeName([DNSName("test.com")]), critical=False)
            .sign(key, _hashes.SHA256())
        )
        pem = cert.public_bytes(Encoding.PEM)
        der = pem_to_der_certificate(pem)
        # Verify DER can be parsed back
        loaded = load_der_x509_certificate(der)
        assert loaded.subject == cert.subject

    def test_accepts_str(self) -> None:
        import datetime

        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import (
            CertificateBuilder,
            Name,
            NameAttribute,
            random_serial_number,
        )
        from cryptography.x509.oid import NameOID

        key = generate_ec_key()
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            CertificateBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, "t.com")]))
            .issuer_name(Name([NameAttribute(NameOID.COMMON_NAME, "t.com")]))
            .public_key(key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, _hashes.SHA256())
        )
        pem_str = cert.public_bytes(Encoding.PEM).decode("ascii")
        der = pem_to_der_certificate(pem_str)
        assert isinstance(der, bytes)
        assert der[0] == 0x30  # DER SEQUENCE tag

    def test_invalid_pem_raises(self) -> None:
        with pytest.raises(ValueError):
            pem_to_der_certificate(b"not a PEM")
