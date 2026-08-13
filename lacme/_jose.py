"""Strict parsing helpers for unverified ACME JWS request bodies."""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Literal

from lacme.crypto import b64url_encode

_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")

PayloadMode = Literal["object", "empty"]


def _json_loads_strict(value: bytes, *, description: str) -> Any:
    """Load BOM-free UTF-8 JSON without non-standard numeric constants."""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = f"{description} must be UTF-8 encoded"
        raise ValueError(msg) from exc
    if text.startswith("\ufeff"):
        msg = f"{description} must not include a UTF-8 BOM"
        raise ValueError(msg)

    def reject_constant(constant: str) -> None:
        msg = f"{description} contains invalid JSON constant {constant}"
        raise ValueError(msg)

    try:
        return json.loads(text, parse_constant=reject_constant)
    except (RecursionError, TypeError, ValueError) as exc:
        msg = f"{description} must be valid JSON"
        raise ValueError(msg) from exc


def b64url_decode_strict(value: object) -> bytes:
    """Decode canonical, unpadded base64url used on the ACME wire."""
    if not isinstance(value, str):
        msg = "ACME base64url values must be strings"
        raise ValueError(msg)
    if not _BASE64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        msg = "Invalid ACME base64url value"
        raise ValueError(msg)

    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = "Invalid ACME base64url value"
        raise ValueError(msg) from exc
    if b64url_encode(decoded) != value:
        msg = "Non-canonical ACME base64url value"
        raise ValueError(msg)
    return decoded


def parse_unverified_jws(
    raw: bytes,
    *,
    payload_mode: PayloadMode = "object",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate a flattened JWS envelope and return protected/payload objects.

    Signature verification is intentionally outside this helper. ``object``
    mode requires a JSON object carried by a non-empty JWS payload; ``empty``
    mode requires the literal empty payload used by POST-as-GET. An empty
    signature remains accepted by lacme's trusted-network responder and test
    server.
    """
    envelope = _json_loads_strict(raw, description="JWS body")
    if not isinstance(envelope, dict):
        msg = "JWS body must be an object"
        raise ValueError(msg)

    missing = {name for name in ("protected", "payload", "signature") if name not in envelope}
    if missing:
        msg = f"JWS body is missing required field: {sorted(missing)[0]}"
        raise ValueError(msg)
    if "header" in envelope:
        msg = "ACME JWS requests must not include an unprotected header"
        raise ValueError(msg)
    if "signatures" in envelope:
        msg = "ACME requests require flattened JWS serialization"
        raise ValueError(msg)

    protected_raw = b64url_decode_strict(envelope["protected"])
    payload_raw = b64url_decode_strict(envelope["payload"])
    b64url_decode_strict(envelope["signature"])

    protected = _json_loads_strict(protected_raw, description="JWS protected header")
    if not isinstance(protected, dict):
        msg = "JWS protected header must be a JSON object"
        raise ValueError(msg)

    if payload_mode == "empty":
        if payload_raw:
            msg = "POST-as-GET requests require an empty JWS payload"
            raise ValueError(msg)
        payload: dict[str, Any] = {}
    elif payload_mode == "object":
        if not payload_raw:
            msg = "This ACME request requires a JSON object payload"
            raise ValueError(msg)
        parsed_payload = _json_loads_strict(payload_raw, description="JWS payload")
        if not isinstance(parsed_payload, dict):
            msg = "JWS payload must be a JSON object"
            raise ValueError(msg)
        payload = parsed_payload
    else:
        msg = f"Unknown JWS payload mode: {payload_mode}"
        raise ValueError(msg)

    return protected, payload
