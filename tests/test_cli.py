"""Tests for lacme.cli — command-line interface."""

from __future__ import annotations

import datetime
import logging
from unittest.mock import MagicMock, patch

import pytest

from lacme.cli import main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_bundle(
    domain: str = "example.com",
    *,
    expires_at: datetime.datetime | None = None,
) -> MagicMock:
    now = datetime.datetime.now(datetime.UTC)
    bundle = MagicMock(
        spec=[
            "domain",
            "domains",
            "expires_at",
            "cert_pem",
            "key_pem",
            "fullchain_pem",
            "cert_path",
            "fullchain_path",
            "key_path",
            "issued_at",
        ]
    )
    bundle.domain = domain
    bundle.domains = (domain,)
    bundle.expires_at = expires_at or (now + datetime.timedelta(days=90))
    bundle.issued_at = now
    bundle.cert_pem = b"---CERT---"
    bundle.key_pem = b"---KEY---"
    bundle.fullchain_pem = b"---FULLCHAIN---"
    bundle.cert_path = f"/tmp/certs/{domain}/cert.pem"
    bundle.fullchain_path = f"/tmp/certs/{domain}/fullchain.pem"
    bundle.key_path = f"/tmp/certs/{domain}/key.pem"
    return bundle


def _mock_account() -> MagicMock:
    account = MagicMock(spec=["url", "status", "contact"])
    account.url = "https://acme.test/acct/1"
    account.status = "valid"
    account.contact = ("mailto:test@example.com",)
    return account


# ---------------------------------------------------------------------------
# No subcommand
# ---------------------------------------------------------------------------


class TestNoSubcommand:
    def test_no_args_returns_1(self) -> None:
        assert main([]) == 1

    def test_help_flag(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Directory resolution
# ---------------------------------------------------------------------------


class TestDirectoryResolution:
    def test_default_is_production(self) -> None:
        from lacme.cli import _resolve_directory

        args = MagicMock(directory=None, staging=False)
        url = _resolve_directory(args)
        assert "acme-v02.api.letsencrypt.org" in url

    def test_staging_flag(self) -> None:
        from lacme.cli import _resolve_directory

        args = MagicMock(directory=None, staging=True)
        url = _resolve_directory(args)
        assert "staging" in url

    def test_directory_overrides_staging(self) -> None:
        from lacme.cli import _resolve_directory

        args = MagicMock(directory="https://custom.example.com/dir", staging=True)
        url = _resolve_directory(args)
        assert url == "https://custom.example.com/dir"


# ---------------------------------------------------------------------------
# Contact resolution
# ---------------------------------------------------------------------------


class TestContactResolution:
    def test_none(self) -> None:
        from lacme.cli import _resolve_contact

        args = MagicMock(contact=None)
        assert _resolve_contact(args) is None

    def test_adds_mailto(self) -> None:
        from lacme.cli import _resolve_contact

        args = MagicMock(contact="test@example.com")
        assert _resolve_contact(args) == "mailto:test@example.com"

    def test_already_mailto(self) -> None:
        from lacme.cli import _resolve_contact

        args = MagicMock(contact="mailto:test@example.com")
        assert _resolve_contact(args) == "mailto:test@example.com"


# ---------------------------------------------------------------------------
# Issue subcommand
# ---------------------------------------------------------------------------


class TestIssue:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_issue_calls_client(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.issue.return_value = _mock_bundle()
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "issue", "example.com"])
        assert result == 0

        mock_client.issue.assert_called_once_with(["example.com"], challenge_type="http-01")
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_issue_multiple_domains(
        self, mock_store_cls: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.issue.return_value = _mock_bundle()
        mock_client_cls.return_value = mock_client

        main(["--store", "/tmp/test", "issue", "example.com", "www.example.com"])
        mock_client.issue.assert_called_once_with(
            ["example.com", "www.example.com"], challenge_type="http-01"
        )

    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_issue_error_returns_1(
        self, mock_store_cls: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.issue.side_effect = RuntimeError("ACME error")
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "issue", "example.com"])
        assert result == 1


# ---------------------------------------------------------------------------
# Renew subcommand
# ---------------------------------------------------------------------------


class TestRenew:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_renew_expiring(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        now = datetime.datetime.now(datetime.UTC)
        expiring = _mock_bundle(expires_at=now + datetime.timedelta(days=5))

        mock_store = MagicMock()
        mock_store.list_certs.return_value = [expiring]
        mock_store_cls.return_value = mock_store

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        new_bundle = _mock_bundle(expires_at=now + datetime.timedelta(days=90))
        mock_client.issue.return_value = new_bundle
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "renew"])
        assert result == 0

        mock_client.issue.assert_called_once()
        captured = capsys.readouterr()
        assert "Renewed" in captured.out

    @patch("lacme.store.FileStore")
    def test_renew_no_expiring(
        self, mock_store_cls: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_store = MagicMock()
        mock_store.list_certs.return_value = [
            _mock_bundle(
                expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=90)
            )
        ]
        mock_store_cls.return_value = mock_store

        result = main(["--store", "/tmp/test", "renew"])
        assert result == 0

        captured = capsys.readouterr()
        assert "No certificates need renewal" in captured.out


# ---------------------------------------------------------------------------
# Revoke subcommand
# ---------------------------------------------------------------------------


class TestRevoke:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_revoke(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_store = MagicMock()
        mock_store.load_cert.return_value = _mock_bundle()
        mock_store_cls.return_value = mock_store

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "revoke", "example.com"])
        assert result == 0

        mock_client.revoke.assert_called_once()
        captured = capsys.readouterr()
        assert "revoked" in captured.out

    @patch("lacme.store.FileStore")
    def test_revoke_missing_domain(
        self, mock_store_cls: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_store = MagicMock()
        mock_store.load_cert.return_value = None
        mock_store_cls.return_value = mock_store

        result = main(["--store", "/tmp/test", "revoke", "missing.com"])
        assert result == 1

        captured = capsys.readouterr()
        assert "No certificate found" in captured.err

    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_revoke_with_reason(
        self, mock_store_cls: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_store = MagicMock()
        mock_store.load_cert.return_value = _mock_bundle()
        mock_store_cls.return_value = mock_store

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        main(["--store", "/tmp/test", "revoke", "example.com", "--reason", "1"])
        mock_client.revoke.assert_called_once_with(b"---CERT---", reason=1)


# ---------------------------------------------------------------------------
# Account subcommands
# ---------------------------------------------------------------------------


class TestAccount:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_account_create(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.create_account.return_value = _mock_account()
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "account", "create"])
        assert result == 0

        captured = capsys.readouterr()
        assert "Account URL" in captured.out

    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_account_info(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.create_account.return_value = _mock_account()
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "account", "info"])
        assert result == 0

        mock_client.create_account.assert_called_once_with(only_return_existing=True)

    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_account_deactivate(
        self,
        mock_store_cls: MagicMock,
        mock_client_cls: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.deactivate_account.return_value = _mock_account()
        mock_client_cls.return_value = mock_client

        result = main(["--store", "/tmp/test", "account", "deactivate"])
        assert result == 0

        captured = capsys.readouterr()
        assert "deactivated" in captured.out


# ---------------------------------------------------------------------------
# Verbose flag
# ---------------------------------------------------------------------------


class TestVerbose:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_verbose_sets_debug(
        self, mock_store_cls: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.issue.return_value = _mock_bundle()
        mock_client_cls.return_value = mock_client

        main(["-v", "--store", "/tmp/test", "issue", "example.com"])
        log = logging.getLogger("lacme")
        assert log.level == logging.DEBUG

        # Reset for other tests
        log.setLevel(logging.WARNING)
        log.handlers.clear()


# ---------------------------------------------------------------------------
# Staging flag
# ---------------------------------------------------------------------------


class TestStagingFlag:
    @patch("lacme.sync.SyncClient")
    @patch("lacme.store.FileStore")
    def test_staging_passes_staging_url(
        self, mock_store_cls: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.issue.return_value = _mock_bundle()
        mock_client_cls.return_value = mock_client

        main(["--staging", "--store", "/tmp/test", "issue", "example.com"])
        call_kwargs = mock_client_cls.call_args[1]
        assert "staging" in call_kwargs["directory_url"]
