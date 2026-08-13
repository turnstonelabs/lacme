"""Internal DNS/IP identifier normalization and X.509 projection helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, TypeAlias

import idna
from cryptography.x509 import (
    DNSName,
    ExtensionNotFound,
    IPAddress,
    SubjectAlternativeName,
    load_der_x509_csr,
    load_pem_x509_certificates,
)
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cryptography.x509 import Certificate, CertificateSigningRequest, GeneralName

    from lacme._types import CertBundle, IdentifierValue

IdentifierKey: TypeAlias = tuple[str, str]

_IP_ADDRESS_TYPES = (ipaddress.IPv4Address, ipaddress.IPv6Address)
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class UnsupportedIdentifierTypeError(ValueError):
    """An ACME identifier uses a syntactically valid but unsupported type."""


def validate_dns_identifier(value: object, *, allow_wildcard: bool = True) -> str:
    """Validate an ASCII certificate-form DNS identifier without rewriting it."""
    if not isinstance(value, str) or not value:
        msg = "DNS identifier values must be non-empty strings"
        raise ValueError(msg)
    if not value.isascii():
        msg = f"DNS identifier {value!r} must use ASCII A-label form"
        raise ValueError(msg)

    name = value
    if name.startswith("*."):
        if not allow_wildcard:
            msg = f"Wildcard DNS identifier {value!r} is not allowed here"
            raise ValueError(msg)
        name = name[2:]
    if "*" in name:
        msg = f"DNS identifier {value!r} has an invalid wildcard"
        raise ValueError(msg)
    if len(value) > 253:
        msg = f"DNS identifier {value!r} is too long"
        raise ValueError(msg)

    labels = name.split(".")
    if not labels or any(not label for label in labels):
        msg = f"DNS identifier {value!r} contains an empty label"
        raise ValueError(msg)
    for label in labels:
        if len(label) > 63 or not _DNS_LABEL_RE.fullmatch(label):
            msg = f"DNS identifier {value!r} contains an invalid label"
            raise ValueError(msg)
        if label.lower().startswith("xn--"):
            try:
                decoded = idna.decode(label.encode("ascii"))
                encoded = idna.encode(decoded, uts46=False, std3_rules=True).decode("ascii")
            except idna.IDNAError as exc:
                msg = f"DNS identifier {value!r} contains an invalid A-label"
                raise ValueError(msg) from exc
            if encoded.lower() != label.lower():
                msg = f"DNS identifier {value!r} contains a non-canonical A-label"
                raise ValueError(msg)
    return value


def validate_identifier_value(value: object) -> IdentifierValue:
    """Validate one public certificate identifier without changing its type."""
    if isinstance(value, str):
        return validate_dns_identifier(value)
    if isinstance(value, ipaddress.IPv4Address):
        return value
    if isinstance(value, ipaddress.IPv6Address):
        if value.scope_id is not None:
            msg = f"Scoped IPv6 address {value!s} is not a valid certificate identifier"
            raise ValueError(msg)
        return value
    msg = f"Identifier values must be str, IPv4Address, or IPv6Address, got {type(value).__name__}"
    raise TypeError(msg)


def normalize_identifier_values(
    values: IdentifierValue | Iterable[IdentifierValue],
) -> list[IdentifierValue]:
    """Normalize a public single-or-list input while preserving DNS/IP types."""
    if isinstance(values, (str, *_IP_ADDRESS_TYPES)):
        candidates: list[object] = [values]
    else:
        try:
            candidates = list(values)
        except TypeError as exc:
            msg = "Identifiers must be a value or list of values"
            raise TypeError(msg) from exc
    if not candidates:
        msg = "At least one identifier is required"
        raise ValueError(msg)
    return [validate_identifier_value(value) for value in candidates]


def identifier_key_from_value(value: IdentifierValue) -> IdentifierKey:
    """Return a case-normalized semantic key for a public API value."""
    checked = validate_identifier_value(value)
    if isinstance(checked, _IP_ADDRESS_TYPES):
        return ("ip", str(checked))
    return ("dns", checked.lower())


def protocol_identifier_from_value(value: IdentifierValue) -> IdentifierKey:
    """Return the ACME type and presentation-preserving wire value."""
    checked = validate_identifier_value(value)
    if isinstance(checked, _IP_ADDRESS_TYPES):
        return ("ip", str(checked))
    return ("dns", checked)


def identifier_key_from_protocol(identifier_type: object, value: object) -> IdentifierKey:
    """Return a semantic key for an ACME wire identifier."""
    checked_type, checked_value = normalize_protocol_identifier(identifier_type, value)
    if checked_type == "dns":
        return (checked_type, checked_value.lower())
    return (checked_type, checked_value)


def normalize_protocol_identifier(identifier_type: object, value: object) -> IdentifierKey:
    """Validate an ACME wire identifier and return its unchanged canonical form."""
    if not isinstance(identifier_type, str) or not isinstance(value, str) or not value:
        msg = "ACME identifiers require explicit non-empty string type and value fields"
        raise ValueError(msg)
    if identifier_type not in {"dns", "ip"}:
        msg = f"Unsupported ACME identifier type: {identifier_type!r}"
        raise UnsupportedIdentifierTypeError(msg)
    if identifier_type == "dns":
        return (identifier_type, validate_dns_identifier(value))

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        msg = f"Invalid IP identifier: {value!r}"
        raise ValueError(msg) from exc
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        msg = f"Scoped IPv6 address {value!r} is not a valid ACME identifier"
        raise ValueError(msg)
    if str(address) != value:
        msg = f"IP identifier is not in canonical textual form: {value!r}"
        raise ValueError(msg)
    return (identifier_type, value)


def normalize_protocol_identifiers(raw_identifiers: object) -> list[dict[str, str]]:
    """Validate a non-empty ACME identifier array without coercing its fields."""
    if not isinstance(raw_identifiers, list) or not raw_identifiers:
        msg = "identifiers must be a non-empty array"
        raise ValueError(msg)

    identifiers: list[dict[str, str]] = []
    for raw_identifier in raw_identifiers:
        if not isinstance(raw_identifier, dict):
            msg = "Each identifier must be an object"
            raise ValueError(msg)
        if "type" not in raw_identifier or "value" not in raw_identifier:
            msg = "Each identifier requires type and value fields"
            raise ValueError(msg)
        identifier_type, value = normalize_protocol_identifier(
            raw_identifier["type"],
            raw_identifier["value"],
        )
        identifiers.append({"type": identifier_type, "value": value})
    return identifiers


def identifier_key_set(values: Iterable[IdentifierValue]) -> frozenset[IdentifierKey]:
    """Return an order-independent typed identifier set."""
    return frozenset(identifier_key_from_value(value) for value in values)


def protocol_identifier_key_set(
    identifiers: Iterable[dict[str, str]],
) -> frozenset[IdentifierKey]:
    """Return an order-independent typed set from validated wire identifiers."""
    return frozenset(
        identifier_key_from_protocol(identifier["type"], identifier["value"])
        for identifier in identifiers
    )


def protocol_identifier_values(
    identifiers: Iterable[dict[str, str]],
) -> list[IdentifierValue]:
    """Project validated ACME wire identifiers back to typed public values."""
    values: list[IdentifierValue] = []
    for identifier in identifiers:
        identifier_type, value = normalize_protocol_identifier(
            identifier["type"],
            identifier["value"],
        )
        values.append(ipaddress.ip_address(value) if identifier_type == "ip" else value)
    return values


def _identifier_value_from_general_name(name: GeneralName) -> IdentifierValue:
    if isinstance(name, DNSName):
        return validate_identifier_value(name.value)
    if isinstance(name, IPAddress):
        ip_value = name.value
        if isinstance(ip_value, _IP_ADDRESS_TYPES):
            return validate_identifier_value(ip_value)
        msg = "IP network SANs are not certificate identifiers"
        raise ValueError(msg)
    msg = f"Unsupported certificate SAN type: {type(name).__name__}"
    raise ValueError(msg)


def _identifier_values_from_sans(sans: SubjectAlternativeName) -> list[IdentifierValue]:
    return [_identifier_value_from_general_name(name) for name in sans]


def csr_san_identifier_values(csr: CertificateSigningRequest) -> list[IdentifierValue]:
    """Extract the typed subjectAltName identifiers from a CSR."""
    try:
        sans = csr.extensions.get_extension_for_class(SubjectAlternativeName).value
    except ExtensionNotFound:
        return []
    return _identifier_values_from_sans(sans)


def csr_ca_identifier_values(csr: CertificateSigningRequest) -> list[IdentifierValue]:
    """Project a CSR for direct CA issuance using SANs, then CN fallback."""
    values = csr_san_identifier_values(csr)
    if values:
        return values
    common_names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if common_names:
        return [validate_dns_identifier(str(common_names[0].value))]
    msg = "CSR contains no certificate identifiers"
    raise ValueError(msg)


def validate_csr_identifiers(
    csr: CertificateSigningRequest,
    expected_identifiers: Iterable[dict[str, str]],
) -> list[IdentifierValue]:
    """Validate an ACME CSR against the order's exact semantic identifier set."""
    expected_keys = protocol_identifier_key_set(expected_identifiers)
    values = csr_san_identifier_values(csr)
    represented_keys = set(identifier_key_set(values))
    san_text = {str(value).lower() for value in values}
    for attribute in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        common_name = str(attribute.value)
        dns_key = ("dns", common_name.lower())
        if (
            dns_key in expected_keys and dns_key not in represented_keys
        ) or common_name.lower() not in san_text:
            values.append(validate_dns_identifier(common_name))
            represented_keys.add(dns_key)

    if not values:
        msg = "CSR contains no certificate identifiers"
        raise ValueError(msg)
    if frozenset(represented_keys) != expected_keys:
        msg = "CSR identifiers do not match the order"
        raise ValueError(msg)
    return values


def decode_and_validate_csr(
    csr_b64: object,
    expected_identifiers: Iterable[dict[str, str]],
) -> tuple[bytes, list[IdentifierValue]]:
    """Strictly decode, verify, and identifier-bind an ACME finalize CSR."""
    from lacme._jose import b64url_decode_strict

    if not isinstance(csr_b64, str) or not csr_b64:
        msg = "Finalize payload requires a non-empty CSR"
        raise ValueError(msg)
    expected = list(expected_identifiers)
    csr_der = b64url_decode_strict(csr_b64)
    try:
        csr = load_der_x509_csr(csr_der)
    except ValueError as exc:
        msg = "CSR is not valid DER"
        raise ValueError(msg) from exc
    if not csr.is_signature_valid:
        msg = "CSR signature is invalid"
        raise ValueError(msg)
    validate_csr_identifiers(csr, expected)
    return csr_der, protocol_identifier_values(expected)


def certificate_identifier_values(certificate: Certificate) -> list[IdentifierValue]:
    """Extract typed identifiers from a leaf certificate SAN extension."""
    try:
        sans = certificate.extensions.get_extension_for_class(SubjectAlternativeName).value
    except ExtensionNotFound as exc:
        msg = "Certificate has no subjectAltName extension"
        raise ValueError(msg) from exc
    values = _identifier_values_from_sans(sans)
    if not values:
        msg = "Certificate has no DNS or IP SAN identifiers"
        raise ValueError(msg)
    return values


def certificate_bundle_identifier_values(bundle: CertBundle) -> list[IdentifierValue]:
    """Recover typed renewal values from a bundle's authoritative leaf SANs.

    The public bundle metadata stays string-only, so values are reordered to
    match ``bundle.domains`` after verifying that it describes exactly the
    same identifiers as the certificate.
    """
    if not bundle.domains or bundle.domain != bundle.domains[0]:
        msg = f"Certificate metadata has an invalid primary identifier for {bundle.domain!r}"
        raise ValueError(msg)

    try:
        certificates = load_pem_x509_certificates(bundle.cert_pem)
    except (TypeError, ValueError) as exc:
        msg = f"Cannot recover identifiers for {bundle.domain!r}: invalid certificate PEM"
        raise ValueError(msg) from exc
    if len(certificates) != 1:
        msg = f"Cannot recover identifiers for {bundle.domain!r}: expected one leaf certificate"
        raise ValueError(msg)

    try:
        values = certificate_identifier_values(certificates[0])
    except ValueError as exc:
        msg = f"Cannot recover identifiers for {bundle.domain!r}: {exc}"
        raise ValueError(msg) from exc

    remaining = list(values)
    ordered: list[IdentifierValue] = []
    for domain in bundle.domains:
        match = next(
            (
                index
                for index, value in enumerate(remaining)
                if (
                    value.lower() == domain.lower()
                    if isinstance(value, str)
                    else str(value) == domain
                )
            ),
            None,
        )
        if match is None:
            msg = f"Certificate identifiers do not match stored metadata for {bundle.domain!r}"
            raise ValueError(msg)
        ordered.append(remaining.pop(match))

    if remaining:
        msg = f"Certificate identifiers do not match stored metadata for {bundle.domain!r}"
        raise ValueError(msg)
    return ordered
