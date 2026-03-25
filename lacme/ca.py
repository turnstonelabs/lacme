"""Lightweight Certificate Authority for internal/mTLS use.

Generates a self-signed root CA certificate and signs server/client
certificates.  Uses the :class:`~lacme.store.Store` protocol for
persistence.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import threading
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import (
    AuthorityKeyIdentifier,
    BasicConstraints,
    CertificateBuilder,
    DNSName,
    ExtendedKeyUsage,
    KeyUsage,
    Name,
    NameAttribute,
    SubjectAlternativeName,
    SubjectKeyIdentifier,
    load_der_x509_csr,
    load_pem_x509_certificates,
    random_serial_number,
)
from cryptography.x509 import (
    IPAddress as X509IPAddress,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from cryptography import x509

    from lacme._types import CertBundle
    from lacme.events import EventDispatcher
    from lacme.store import Store

logger = logging.getLogger("lacme.ca")


class CertificateAuthority:
    """Lightweight Certificate Authority for internal/mTLS use.

    Generates a self-signed root CA certificate and signs server/client
    certificates.  Uses the :class:`~lacme.store.Store` protocol for
    persistence.
    """

    def __init__(
        self,
        store: Store | None = None,
        *,
        event_dispatcher: EventDispatcher | None = None,
    ) -> None:
        self._store = store
        self._event_dispatcher = event_dispatcher
        self._root_cert: x509.Certificate | None = None
        self._root_key: ec.EllipticCurvePrivateKey | None = None
        self._lock = threading.Lock()

    def init(
        self,
        *,
        cn: str = "lacme Internal CA",
        validity_days: int = 3650,
    ) -> None:
        """Initialize the CA: generate or load root CA cert + key.

        If a store is provided and a root CA already exists (via
        ``store.load_ca("root")``), loads it.  Otherwise generates a
        new self-signed root.
        """
        with self._lock:
            # Try loading from store first.
            if self._store is not None:
                loaded = self._store.load_ca("root")
                if loaded is not None:
                    cert_pem, key_pem = loaded
                    certs = load_pem_x509_certificates(cert_pem)
                    if not certs:
                        from lacme.errors import CertificateAuthorityError

                        msg = "No certificates found in stored CA PEM data"
                        raise CertificateAuthorityError(msg)
                    self._root_cert = certs[0]
                    raw_key = load_pem_private_key(key_pem, password=None)
                    if not isinstance(raw_key, ec.EllipticCurvePrivateKey):
                        from lacme.errors import CertificateAuthorityError

                        msg = f"Expected EC private key, got {type(raw_key).__name__}"
                        raise CertificateAuthorityError(msg)
                    self._root_key = raw_key
                    cn_val = self._root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                        0
                    ].value
                    self._emit_initialized(
                        cn=str(cn_val),
                        expires_at=self._root_cert.not_valid_after_utc,
                    )
                    return

            # Generate new root CA.
            from lacme.crypto import generate_ec_key

            key = generate_ec_key()
            now = datetime.datetime.now(datetime.UTC)
            not_valid_after = now + datetime.timedelta(days=validity_days)

            subject = Name([NameAttribute(NameOID.COMMON_NAME, cn)])
            cert = (
                CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(random_serial_number())
                .not_valid_before(now)
                .not_valid_after(not_valid_after)
                .add_extension(
                    BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    SubjectKeyIdentifier.from_public_key(key.public_key()),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            self._root_cert = cert
            self._root_key = key

            # Persist if store is available.
            if self._store is not None:
                cert_pem = cert.public_bytes(Encoding.PEM)
                key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                self._store.save_ca("root", cert_pem, key_pem)

            self._emit_initialized(cn=cn, expires_at=not_valid_after)

    def issue(
        self,
        names: str | list[str | ipaddress.IPv4Address | ipaddress.IPv6Address],
        *,
        client: bool = False,
        validity_days: int = 1,
        validity_hours: int | None = None,
    ) -> CertBundle:
        """Issue a server or client certificate signed by this CA.

        Args:
            names: Domain name(s) and/or IP addresses for SANs.
            client: If True, issue client cert (clientAuth EKU).
                Default: server cert (serverAuth EKU).
            validity_days: Certificate validity in days (default 1 = 24 hours).
            validity_hours: If provided, overrides validity_days.

        Returns:
            CertBundle with cert_pem, fullchain_pem (leaf + root), key_pem.

        Raises:
            CertificateAuthorityError: If not initialized.
        """
        with self._lock:
            self._check_initialized()

            # Normalize names to a list.
            if isinstance(names, str):
                name_list: list[str | ipaddress.IPv4Address | ipaddress.IPv6Address] = [names]
            else:
                name_list = list(names)

            if not name_list:
                from lacme.errors import CertificateAuthorityError

                msg = "At least one name is required"
                raise CertificateAuthorityError(msg)

            # Generate a new key for this certificate.
            from lacme.crypto import generate_ec_key

            new_key = generate_ec_key()

            cert, not_valid_after = self._build_leaf_cert(
                public_key=new_key.public_key(),
                names=name_list,
                client=client,
                validity_days=validity_days,
                validity_hours=validity_hours,
            )

            # Build PEM bytes.
            cert_pem = cert.public_bytes(Encoding.PEM)
            key_pem = new_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            fullchain_pem = cert_pem + self.root_cert_pem

            bundle = self._build_bundle(
                names=name_list,
                cert_pem=cert_pem,
                fullchain_pem=fullchain_pem,
                key_pem=key_pem,
                not_valid_after=not_valid_after,
            )

            if self._store is not None:
                bundle = self._store.save_cert(bundle)

        self._emit_issued(
            name=str(name_list[0]),
            names=tuple(str(n) for n in name_list),
            is_client=client,
            expires_at=not_valid_after,
        )
        return bundle

    def issue_from_csr(
        self,
        csr_der: bytes,
        *,
        client: bool = False,
        validity_days: int = 1,
        validity_hours: int | None = None,
    ) -> CertBundle:
        """Sign an externally-provided CSR.

        Used by ACMEResponder's finalize endpoint.  Extracts SANs from
        the CSR.  The CSR's public key is used (no new key generated).

        Returns:
            CertBundle (key_pem will be empty bytes since we don't have
            the private key).

        Raises:
            CertificateAuthorityError: If not initialized or CSR is invalid.
        """
        from lacme.errors import CertificateAuthorityError

        with self._lock:
            self._check_initialized()

            # Parse and verify the CSR.
            csr = load_der_x509_csr(csr_der)
            if not csr.is_signature_valid:
                msg = "CSR signature is invalid"
                raise CertificateAuthorityError(msg)

            # Extract SANs from the CSR.
            name_list: list[str | ipaddress.IPv4Address | ipaddress.IPv6Address] = []
            try:
                san_ext = csr.extensions.get_extension_for_class(SubjectAlternativeName)
                for dns_name in san_ext.value.get_values_for_type(DNSName):
                    name_list.append(dns_name)
                for ip_addr in san_ext.value.get_values_for_type(X509IPAddress):
                    if isinstance(ip_addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                        name_list.append(ip_addr)
            except Exception:  # noqa: BLE001 — extension may not be present
                pass

            # Fall back to CN if no SANs.
            if not name_list:
                cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    name_list.append(str(cn_attrs[0].value))

            if not name_list:
                msg = "CSR contains no SANs and no CN"
                raise CertificateAuthorityError(msg)

            cert, not_valid_after = self._build_leaf_cert(
                public_key=csr.public_key(),
                names=name_list,
                client=client,
                validity_days=validity_days,
                validity_hours=validity_hours,
            )

            # Build PEM bytes — no key_pem since we don't own the private key.
            cert_pem = cert.public_bytes(Encoding.PEM)
            fullchain_pem = cert_pem + self.root_cert_pem

            bundle = self._build_bundle(
                names=name_list,
                cert_pem=cert_pem,
                fullchain_pem=fullchain_pem,
                key_pem=b"",
                not_valid_after=not_valid_after,
            )

            if self._store is not None:
                bundle = self._store.save_cert(bundle)

        self._emit_issued(
            name=str(name_list[0]),
            names=tuple(str(n) for n in name_list),
            is_client=client,
            expires_at=not_valid_after,
        )
        return bundle

    @property
    def root_cert_pem(self) -> bytes:
        """The PEM-encoded root CA certificate."""
        if self._root_cert is None:
            from lacme.errors import CertificateAuthorityError

            msg = "CA not initialized — call init() first"
            raise CertificateAuthorityError(msg)
        return self._root_cert.public_bytes(Encoding.PEM)

    @property
    def initialized(self) -> bool:
        """True if init() has been called."""
        return self._root_cert is not None and self._root_key is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_initialized(self) -> None:
        """Raise if the CA has not been initialized."""
        if self._root_cert is None or self._root_key is None:
            from lacme.errors import CertificateAuthorityError

            msg = "CA not initialized — call init() first"
            raise CertificateAuthorityError(msg)

    def _build_leaf_cert(
        self,
        *,
        public_key: Any,
        names: list[str | ipaddress.IPv4Address | ipaddress.IPv6Address],
        client: bool,
        validity_days: int,
        validity_hours: int | None,
    ) -> tuple[x509.Certificate, datetime.datetime]:
        """Build and sign a leaf certificate.

        Returns the signed certificate and its not-valid-after datetime.
        Caller must hold ``self._lock``.
        """
        assert self._root_cert is not None  # noqa: S101
        assert self._root_key is not None  # noqa: S101

        # Build SAN entries.
        san_entries: list[DNSName | X509IPAddress] = []
        for name in names:
            if isinstance(name, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                san_entries.append(X509IPAddress(name))
            else:
                san_entries.append(DNSName(str(name)))

        now = datetime.datetime.now(datetime.UTC)
        if validity_hours is not None:
            not_valid_after = now + datetime.timedelta(hours=validity_hours)
        else:
            not_valid_after = now + datetime.timedelta(days=validity_days)

        # Choose EKU based on client vs server.
        if client:
            eku = ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        else:
            eku = ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])

        subject = Name([NameAttribute(NameOID.COMMON_NAME, str(names[0]))])

        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_cert.subject)
            .public_key(public_key)
            .serial_number(random_serial_number())
            .not_valid_before(now)
            .not_valid_after(not_valid_after)
            .add_extension(
                BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                SubjectAlternativeName(san_entries),
                critical=False,
            )
            .add_extension(eku, critical=False)
            .add_extension(
                KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                AuthorityKeyIdentifier.from_issuer_public_key(self._root_key.public_key()),
                critical=False,
            )
            .add_extension(
                SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .sign(self._root_key, hashes.SHA256())
        )

        return cert, not_valid_after

    @staticmethod
    def _build_bundle(
        *,
        names: list[str | ipaddress.IPv4Address | ipaddress.IPv6Address],
        cert_pem: bytes,
        fullchain_pem: bytes,
        key_pem: bytes,
        not_valid_after: datetime.datetime,
    ) -> CertBundle:
        """Construct a :class:`CertBundle` from the given parameters."""
        from lacme._types import CertBundle as _CertBundle

        return _CertBundle(
            domain=str(names[0]),
            domains=tuple(str(n) for n in names),
            cert_pem=cert_pem,
            fullchain_pem=fullchain_pem,
            key_pem=key_pem,
            issued_at=datetime.datetime.now(datetime.UTC),
            expires_at=not_valid_after,
        )

    def _emit_initialized(self, *, cn: str, expires_at: datetime.datetime) -> None:
        """Emit a :class:`CertificateAuthorityInitialized` event."""
        if self._event_dispatcher is None:
            return
        from lacme.events import CertificateAuthorityInitialized

        self._event_dispatcher.emit_sync(
            CertificateAuthorityInitialized(cn=cn, expires_at=expires_at),
        )

    def _emit_issued(
        self,
        *,
        name: str,
        names: tuple[str, ...],
        is_client: bool,
        expires_at: datetime.datetime,
    ) -> None:
        """Emit a :class:`CACertificateIssued` event."""
        if self._event_dispatcher is None:
            return
        from lacme.events import CACertificateIssued

        self._event_dispatcher.emit_sync(
            CACertificateIssued(
                name=name,
                names=names,
                is_client=is_client,
                expires_at=expires_at,
            ),
        )
