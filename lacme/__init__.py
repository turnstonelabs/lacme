"""lacme — Modern, async-native Python ACME client library."""

from __future__ import annotations

from lacme._types import CertBundle
from lacme.acme_server import ACMEResponder, ChallengeValidator
from lacme.ca import CertificateAuthority
from lacme.challenges import ChallengeHandler
from lacme.challenges.dns01 import DNS01Handler, DNSProvider
from lacme.client import LETSENCRYPT_DIRECTORY, LETSENCRYPT_STAGING_DIRECTORY, Client
from lacme.crypto import generate_ec_key, private_key_from_pem, private_key_to_pem
from lacme.errors import (
    ACMEError,
    ACMEServerError,
    ACMEStoreError,
    ACMETimeoutError,
    ACMEValidationError,
    BadNonceError,
    CertificateAuthorityError,
    RateLimitedError,
    RateLimitPreventedError,
)
from lacme.events import (
    CACertificateIssued,
    CertificateAuthorityInitialized,
    CertificateExpiring,
    CertificateIssued,
    CertificateRenewed,
    ChallengeFailed,
    EventDispatcher,
    RateLimitWarning,
)
from lacme.models import (
    Account,
    Authorization,
    Challenge,
    Directory,
    Identifier,
    Order,
    RevocationReason,
)
from lacme.mtls import client_ssl_context, server_ssl_context
from lacme.ratelimit import RateLimitTracker
from lacme.renewal import RenewalManager
from lacme.store import FileStore, MemoryStore, Store
from lacme.sync import SyncChallengeHandler, SyncClient

__all__ = [
    "ACMEError",
    "ACMEResponder",
    "ACMEServerError",
    "ACMEStoreError",
    "ACMETimeoutError",
    "ACMEValidationError",
    "Account",
    "Authorization",
    "BadNonceError",
    "CACertificateIssued",
    "CertBundle",
    "CertificateAuthority",
    "CertificateAuthorityError",
    "CertificateAuthorityInitialized",
    "CertificateExpiring",
    "CertificateIssued",
    "CertificateRenewed",
    "Challenge",
    "ChallengeFailed",
    "ChallengeHandler",
    "ChallengeValidator",
    "Client",
    "DNS01Handler",
    "DNSProvider",
    "Directory",
    "EventDispatcher",
    "FileStore",
    "Identifier",
    "LETSENCRYPT_DIRECTORY",
    "LETSENCRYPT_STAGING_DIRECTORY",
    "MemoryStore",
    "Order",
    "RateLimitedError",
    "RateLimitPreventedError",
    "RateLimitTracker",
    "RateLimitWarning",
    "RenewalManager",
    "RevocationReason",
    "Store",
    "SyncChallengeHandler",
    "SyncClient",
    "client_ssl_context",
    "generate_ec_key",
    "private_key_from_pem",
    "private_key_to_pem",
    "server_ssl_context",
]

__version__ = "1.0.4"
