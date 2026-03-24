"""Minimal ACME certificate management CLI.

Provides ``lacme`` console command with subcommands for certificate
issuance, renewal, revocation, and account management.  Uses
:class:`~lacme.sync.SyncClient` and :class:`~lacme.store.FileStore`.
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lacme.challenges import ChallengeHandler
    from lacme.sync import SyncChallengeHandler

logger = logging.getLogger("lacme.cli")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    _setup_logging(args.verbose)

    try:
        result: int = args.func(args)
        return result
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)  # noqa: T201
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)  # noqa: T201
        return 1


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lacme",
        description="Minimal ACME certificate management CLI",
    )
    parser.add_argument("--directory", default=None, help="ACME directory URL")
    parser.add_argument("--staging", action="store_true", help="Use Let's Encrypt staging")
    parser.add_argument(
        "--store", default="~/.lacme", help="Certificate store path (default: ~/.lacme)"
    )
    parser.add_argument(
        "--contact", default=None, help="Account contact email (mailto: added automatically)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command")

    # --- issue ---
    issue_p = subparsers.add_parser("issue", help="Issue a certificate")
    issue_p.add_argument("domains", nargs="+", help="Domain name(s)")
    issue_p.add_argument(
        "--dns-provider",
        choices=["cloudflare", "route53", "hook"],
        default=None,
        help="Use DNS-01 with specified provider",
    )
    issue_p.add_argument(
        "--cloudflare-token",
        default=None,
        help="Cloudflare API token (prefer LACME_CLOUDFLARE_TOKEN env var to avoid process-table exposure)",
    )
    issue_p.add_argument(
        "--cloudflare-zone-id",
        default=None,
        help="Cloudflare zone ID (or LACME_CLOUDFLARE_ZONE_ID env var)",
    )
    issue_p.add_argument(
        "--route53-zone-id",
        default=None,
        help="Route53 hosted zone ID (or LACME_ROUTE53_ZONE_ID env var)",
    )
    issue_p.add_argument("--hook-create", default=None, help="DNS create hook command")
    issue_p.add_argument("--hook-delete", default=None, help="DNS delete hook command")
    issue_p.set_defaults(func=_cmd_issue)

    # --- renew ---
    renew_p = subparsers.add_parser("renew", help="Renew expiring certificates")
    renew_p.add_argument(
        "--days", type=int, default=30, help="Days before expiry threshold (default: 30)"
    )
    renew_p.add_argument(
        "--dns-provider",
        choices=["cloudflare", "route53", "hook"],
        default=None,
        help="Use DNS-01 with specified provider",
    )
    renew_p.add_argument("--cloudflare-token", default=None)
    renew_p.add_argument("--cloudflare-zone-id", default=None)
    renew_p.add_argument("--route53-zone-id", default=None)
    renew_p.add_argument("--hook-create", default=None)
    renew_p.add_argument("--hook-delete", default=None)
    renew_p.set_defaults(func=_cmd_renew)

    # --- revoke ---
    revoke_p = subparsers.add_parser("revoke", help="Revoke a certificate")
    revoke_p.add_argument("domain", help="Domain to revoke")
    revoke_p.add_argument("--reason", type=int, default=None, help="Revocation reason code")
    revoke_p.set_defaults(func=_cmd_revoke)

    # --- account ---
    account_p = subparsers.add_parser("account", help="Account management")
    account_sub = account_p.add_subparsers(dest="account_command")
    create_p = account_sub.add_parser("create", help="Create or find an ACME account")
    create_p.set_defaults(func=_cmd_account_create)
    info_p = account_sub.add_parser("info", help="Show account info")
    info_p.set_defaults(func=_cmd_account_info)
    deactivate_p = account_sub.add_parser("deactivate", help="Deactivate account")
    deactivate_p.set_defaults(func=_cmd_account_deactivate)

    return parser


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


_CLI_HANDLER_NAME = "_lacme_cli"


def _setup_logging(verbose: bool) -> None:
    log = logging.getLogger("lacme")
    log.setLevel(logging.DEBUG if verbose else logging.WARNING)
    if not any(getattr(h, "name", None) == _CLI_HANDLER_NAME for h in log.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.name = _CLI_HANDLER_NAME
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        log.addHandler(handler)


def _resolve_directory(args: argparse.Namespace) -> str:
    if args.directory is not None:
        return str(args.directory)
    if args.staging:
        from lacme.client import LETSENCRYPT_STAGING_DIRECTORY

        return LETSENCRYPT_STAGING_DIRECTORY
    from lacme.client import LETSENCRYPT_DIRECTORY

    return LETSENCRYPT_DIRECTORY


def _resolve_contact(args: argparse.Namespace) -> str | None:
    contact: str | None = args.contact
    if contact is None:
        return None
    if not contact.startswith("mailto:"):
        contact = f"mailto:{contact}"
    return contact


def _build_challenge_handler(
    args: argparse.Namespace,
) -> SyncChallengeHandler | ChallengeHandler | None:
    provider = getattr(args, "dns_provider", None)
    if provider is None:
        return None

    if provider == "cloudflare":
        from lacme.challenges.providers.cloudflare import CloudflareDNSProvider

        token = args.cloudflare_token or os.environ.get("LACME_CLOUDFLARE_TOKEN")
        zone_id = args.cloudflare_zone_id or os.environ.get("LACME_CLOUDFLARE_ZONE_ID")
        if not token or not zone_id:
            msg = (
                "--cloudflare-token/LACME_CLOUDFLARE_TOKEN and "
                "--cloudflare-zone-id/LACME_CLOUDFLARE_ZONE_ID are required "
                "with --dns-provider cloudflare"
            )
            raise ValueError(msg)
        from lacme.challenges.dns01 import DNS01Handler

        return DNS01Handler(provider=CloudflareDNSProvider(api_token=token, zone_id=zone_id))

    if provider == "route53":
        from lacme.challenges.providers.route53 import Route53DNSProvider

        zone_id = args.route53_zone_id or os.environ.get("LACME_ROUTE53_ZONE_ID")
        if not zone_id:
            msg = "--route53-zone-id/LACME_ROUTE53_ZONE_ID is required with --dns-provider route53"
            raise ValueError(msg)
        from lacme.challenges.dns01 import DNS01Handler

        return DNS01Handler(provider=Route53DNSProvider(hosted_zone_id=zone_id))

    if provider == "hook":
        from lacme.challenges.providers.hook import HookDNSProvider

        create_cmd = args.hook_create
        delete_cmd = args.hook_delete
        if not create_cmd or not delete_cmd:
            msg = "--hook-create and --hook-delete are required with --dns-provider hook"
            raise ValueError(msg)
        from lacme.challenges.dns01 import DNS01Handler

        return DNS01Handler(
            provider=HookDNSProvider(create_command=create_cmd, delete_command=delete_cmd)
        )

    msg = f"Unknown DNS provider: {provider}"
    raise ValueError(msg)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def _cmd_issue(args: argparse.Namespace) -> int:
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    store = FileStore(args.store)
    handler = _build_challenge_handler(args)
    challenge_type = "dns-01" if args.dns_provider else "http-01"
    contact = _resolve_contact(args)

    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
        challenge_handler=handler,
        contact=contact,
    ) as client:
        bundle = client.issue(args.domains, challenge_type=challenge_type)

    print(f"Certificate issued for {bundle.domain}")  # noqa: T201
    print(f"  Domains: {', '.join(bundle.domains)}")  # noqa: T201
    print(f"  Expires: {bundle.expires_at.isoformat()}")  # noqa: T201
    if bundle.cert_path:
        print(f"  Cert:      {bundle.cert_path}")  # noqa: T201
    if bundle.fullchain_path:
        print(f"  Fullchain: {bundle.fullchain_path}")  # noqa: T201
    if bundle.key_path:
        print(f"  Key:       {bundle.key_path}")  # noqa: T201
    return 0


def _cmd_renew(args: argparse.Namespace) -> int:
    from lacme.challenges.http01 import HTTP01Handler
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    store = FileStore(args.store)
    now = datetime.datetime.now(datetime.UTC)
    threshold = now + datetime.timedelta(days=args.days)
    bundles = store.list_certs()
    expiring = [b for b in bundles if b.expires_at <= threshold]

    if not expiring:
        print("No certificates need renewal.")  # noqa: T201
        return 0

    handler = _build_challenge_handler(args) or HTTP01Handler()
    challenge_type = "dns-01" if getattr(args, "dns_provider", None) else "http-01"
    contact = _resolve_contact(args)
    renewed_count = 0
    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
        challenge_handler=handler,
        contact=contact,
    ) as client:
        for bundle in expiring:
            try:
                new_bundle = client.issue(list(bundle.domains), challenge_type=challenge_type)
                print(f"Renewed: {bundle.domain} (expires {new_bundle.expires_at.isoformat()})")  # noqa: T201
                renewed_count += 1
            except Exception as exc:
                print(f"Failed to renew {bundle.domain}: {exc}", file=sys.stderr)  # noqa: T201

    print(f"\n{renewed_count}/{len(expiring)} certificates renewed.")  # noqa: T201
    return 0 if renewed_count == len(expiring) else 1


def _cmd_revoke(args: argparse.Namespace) -> int:
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    store = FileStore(args.store)
    bundle = store.load_cert(args.domain)
    if bundle is None:
        print(f"No certificate found for {args.domain}", file=sys.stderr)  # noqa: T201
        return 1

    contact = _resolve_contact(args)
    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
        contact=contact,
    ) as client:
        client.revoke(bundle.cert_pem, reason=args.reason)

    print(f"Certificate for {args.domain} revoked.")  # noqa: T201
    return 0


def _cmd_account_create(args: argparse.Namespace) -> int:
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    contact = _resolve_contact(args)
    contact_list = [contact] if contact else None

    store = FileStore(args.store)
    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
    ) as client:
        account = client.create_account(contact=contact_list)

    print(f"Account URL: {account.url}")  # noqa: T201
    print(f"Status:      {account.status}")  # noqa: T201
    if account.contact:
        print(f"Contact:     {', '.join(account.contact)}")  # noqa: T201
    return 0


def _cmd_account_info(args: argparse.Namespace) -> int:
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    store = FileStore(args.store)
    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
    ) as client:
        account = client.create_account(only_return_existing=True)

    print(f"Account URL: {account.url}")  # noqa: T201
    print(f"Status:      {account.status}")  # noqa: T201
    if account.contact:
        print(f"Contact:     {', '.join(account.contact)}")  # noqa: T201
    return 0


def _cmd_account_deactivate(args: argparse.Namespace) -> int:
    from lacme.store import FileStore
    from lacme.sync import SyncClient

    store = FileStore(args.store)
    with SyncClient(
        directory_url=_resolve_directory(args),
        store=store,
    ) as client:
        account = client.deactivate_account()

    print(f"Account {account.url} deactivated.")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
