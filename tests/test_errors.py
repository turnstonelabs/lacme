"""Tests for lacme.errors — exception hierarchy and server error factory."""

from __future__ import annotations

import pytest

from lacme.errors import (
    AccountDoesNotExistError,
    ACMEConnectionError,
    ACMEError,
    ACMEServerError,
    ACMEStoreError,
    ACMETimeoutError,
    ACMEValidationError,
    AlreadyRevokedError,
    BadCSRError,
    BadNonceError,
    BadPublicKeyError,
    BadRevocationReasonError,
    BadSignatureAlgorithmError,
    CAAError,
    DNSError,
    InvalidContactError,
    MalformedError,
    OrderNotReadyError,
    RateLimitedError,
    RejectedIdentifierError,
    ServerInternalError,
    TLSError,
    UnauthorizedError,
    UnsupportedIdentifierError,
    server_error_from_response,
)

# ---------------------------------------------------------------------------
# Hierarchy
# ---------------------------------------------------------------------------


class TestHierarchy:
    @pytest.mark.parametrize(
        "cls",
        [
            ACMEServerError,
            BadNonceError,
            RateLimitedError,
            UnauthorizedError,
            BadCSRError,
            CAAError,
            AccountDoesNotExistError,
            InvalidContactError,
            MalformedError,
            OrderNotReadyError,
            RejectedIdentifierError,
            UnsupportedIdentifierError,
            BadSignatureAlgorithmError,
            BadPublicKeyError,
            ACMEConnectionError,
            DNSError,
            ServerInternalError,
            TLSError,
            AlreadyRevokedError,
            BadRevocationReasonError,
            ACMEValidationError,
            ACMETimeoutError,
            ACMEStoreError,
        ],
    )
    def test_all_subclass_acme_error(self, cls: type) -> None:
        assert issubclass(cls, ACMEError)

    @pytest.mark.parametrize(
        "cls",
        [
            BadNonceError,
            RateLimitedError,
            UnauthorizedError,
            BadCSRError,
            CAAError,
            AccountDoesNotExistError,
            InvalidContactError,
            MalformedError,
            OrderNotReadyError,
            RejectedIdentifierError,
            UnsupportedIdentifierError,
            BadSignatureAlgorithmError,
            BadPublicKeyError,
            ACMEConnectionError,
            DNSError,
            ServerInternalError,
            TLSError,
            AlreadyRevokedError,
            BadRevocationReasonError,
        ],
    )
    def test_server_errors_subclass_acme_server_error(self, cls: type) -> None:
        assert issubclass(cls, ACMEServerError)


# ---------------------------------------------------------------------------
# ACMEServerError
# ---------------------------------------------------------------------------


class TestACMEServerError:
    def test_stores_all_fields(self) -> None:
        err = ACMEServerError(
            type="urn:ietf:params:acme:error:malformed",
            detail="bad request",
            status=400,
            subproblems=[{"type": "x", "detail": "y"}],
            response_headers={"retry-after": "60"},
        )
        assert err.type == "urn:ietf:params:acme:error:malformed"
        assert err.detail == "bad request"
        assert err.status == 400
        assert err.subproblems == [{"type": "x", "detail": "y"}]
        assert err.response_headers == {"retry-after": "60"}

    def test_str_includes_type_and_detail(self) -> None:
        err = ACMEServerError(type="urn:ietf:params:acme:error:caa", detail="CAA failed")
        assert "caa" in str(err)
        assert "CAA failed" in str(err)

    def test_str_without_detail(self) -> None:
        err = ACMEServerError(type="urn:ietf:params:acme:error:caa")
        assert "caa" in str(err)

    def test_defaults(self) -> None:
        err = ACMEServerError(type="test")
        assert err.detail is None
        assert err.status is None
        assert err.subproblems is None
        assert err.response_headers is None

    def test_str_with_empty_detail(self) -> None:
        err = ACMEServerError(type="urn:ietf:params:acme:error:caa", detail="")
        # Empty detail should still be included (not swallowed by truthiness)
        s = str(err)
        assert "caa" in s


# ---------------------------------------------------------------------------
# RateLimitedError
# ---------------------------------------------------------------------------


class TestRateLimitedError:
    def test_retry_after_parsed(self) -> None:
        err = RateLimitedError(
            type="urn:ietf:params:acme:error:rateLimited",
            response_headers={"retry-after": "120"},
        )
        assert err.retry_after == 120

    def test_retry_after_missing_header(self) -> None:
        err = RateLimitedError(
            type="urn:ietf:params:acme:error:rateLimited",
            response_headers={},
        )
        assert err.retry_after is None

    def test_retry_after_no_headers(self) -> None:
        err = RateLimitedError(type="urn:ietf:params:acme:error:rateLimited")
        assert err.retry_after is None

    def test_retry_after_non_numeric(self) -> None:
        err = RateLimitedError(
            type="urn:ietf:params:acme:error:rateLimited",
            response_headers={"retry-after": "Thu, 01 Jan 2099 00:00:00 GMT"},
        )
        assert err.retry_after is None

    def test_retry_after_negative_returns_none(self) -> None:
        err = RateLimitedError(
            type="urn:ietf:params:acme:error:rateLimited",
            response_headers={"retry-after": "-5"},
        )
        assert err.retry_after is None


# ---------------------------------------------------------------------------
# ACMEValidationError
# ---------------------------------------------------------------------------


class TestACMEValidationError:
    def test_stores_fields(self) -> None:
        err = ACMEValidationError(
            "challenge failed",
            identifier="example.com",
            error={"type": "urn:ietf:params:acme:error:connection"},
        )
        assert err.identifier == "example.com"
        assert err.error is not None
        assert "challenge failed" in str(err)

    def test_defaults(self) -> None:
        err = ACMEValidationError("fail", identifier="x.com")
        assert err.error is None


# ---------------------------------------------------------------------------
# ACMETimeoutError
# ---------------------------------------------------------------------------


class TestACMETimeoutError:
    def test_stores_fields(self) -> None:
        err = ACMETimeoutError("timed out", url="https://acme/order/1", last_status="processing")
        assert err.url == "https://acme/order/1"
        assert err.last_status == "processing"
        assert "timed out" in str(err)


# ---------------------------------------------------------------------------
# server_error_from_response factory
# ---------------------------------------------------------------------------


class TestServerErrorFactory:
    @pytest.mark.parametrize(
        ("short_name", "expected_cls"),
        [
            ("badNonce", BadNonceError),
            ("rateLimited", RateLimitedError),
            ("unauthorized", UnauthorizedError),
            ("badCSR", BadCSRError),
            ("caa", CAAError),
            ("accountDoesNotExist", AccountDoesNotExistError),
            ("invalidContact", InvalidContactError),
            ("malformed", MalformedError),
            ("orderNotReady", OrderNotReadyError),
            ("rejectedIdentifier", RejectedIdentifierError),
            ("unsupportedIdentifier", UnsupportedIdentifierError),
            ("badSignatureAlgorithm", BadSignatureAlgorithmError),
            ("badPublicKey", BadPublicKeyError),
            ("connection", ACMEConnectionError),
            ("dns", DNSError),
            ("serverInternal", ServerInternalError),
            ("tls", TLSError),
            ("alreadyRevoked", AlreadyRevokedError),
            ("badRevocationReason", BadRevocationReasonError),
        ],
    )
    def test_known_error_types(self, short_name: str, expected_cls: type[ACMEServerError]) -> None:
        problem = {
            "type": f"urn:ietf:params:acme:error:{short_name}",
            "detail": "some detail",
            "status": 400,
        }
        err = server_error_from_response(problem)
        assert isinstance(err, expected_cls)
        assert err.detail == "some detail"
        assert err.status == 400

    def test_unknown_error_falls_back(self) -> None:
        problem = {
            "type": "urn:ietf:params:acme:error:someFutureError",
            "detail": "unknown",
        }
        err = server_error_from_response(problem)
        assert type(err) is ACMEServerError
        assert err.type == "urn:ietf:params:acme:error:someFutureError"

    def test_non_acme_type(self) -> None:
        problem = {"type": "about:blank", "detail": "generic"}
        err = server_error_from_response(problem)
        assert type(err) is ACMEServerError
        assert err.type == "about:blank"

    def test_missing_type(self) -> None:
        problem = {"detail": "no type field"}
        err = server_error_from_response(problem)
        assert type(err) is ACMEServerError
        assert err.type == ""

    def test_response_headers_forwarded(self) -> None:
        problem = {"type": "urn:ietf:params:acme:error:rateLimited"}
        headers = {"retry-after": "30"}
        err = server_error_from_response(problem, response_headers=headers)
        assert isinstance(err, RateLimitedError)
        assert err.retry_after == 30

    def test_subproblems_forwarded(self) -> None:
        problem = {
            "type": "urn:ietf:params:acme:error:malformed",
            "subproblems": [
                {
                    "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                    "detail": "bad domain",
                    "identifier": {"type": "dns", "value": "evil.com"},
                }
            ],
        }
        err = server_error_from_response(problem)
        assert isinstance(err, MalformedError)
        assert err.subproblems is not None
        assert len(err.subproblems) == 1
