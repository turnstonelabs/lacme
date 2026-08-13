"""Static compatibility checks for public identifier-bearing APIs."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from lacme import CertificateAuthority, Client, SyncClient
    from lacme.challenges import ChallengeHandler
    from lacme.sync import SyncChallengeHandler

    async def async_calls(
        async_client: Client,
        async_handler: ChallengeHandler,
    ) -> None:
        dns_names: list[str] = ["example.com"]
        dns_map: dict[str, tuple[str, ChallengeHandler]] = {
            "example.com": ("dns-01", async_handler)
        }
        ip_map: dict[IPv4Address, tuple[str, ChallengeHandler]] = {
            IPv4Address("192.0.2.1"): ("http-01", async_handler)
        }
        await async_client.create_order(dns_names)
        await async_client.issue(dns_names, challenge_map=dns_map)
        await async_client.issue(IPv4Address("192.0.2.1"), challenge_map=ip_map)
        await async_client.issue(
            ["192.0.2.1", IPv4Address("192.0.2.1")],
            challenge_map={
                "192.0.2.1": ("dns-01", async_handler),
                IPv4Address("192.0.2.1"): ("http-01", async_handler),
            },
        )
        async_client.check_rate_limits(dns_names)

        bad_map: dict[int, tuple[str, ChallengeHandler]] = {1: ("http-01", async_handler)}
        await async_client.issue(
            "example.com",
            challenge_map=bad_map,  # type: ignore[arg-type]
        )

    def sync_calls(
        sync_client: SyncClient,
        sync_handler: SyncChallengeHandler,
        async_handler: ChallengeHandler,
        ca: CertificateAuthority,
    ) -> None:
        dns_names: list[str] = ["example.com"]
        sync_client.create_order(dns_names)
        sync_client.issue(
            ["192.0.2.1", IPv4Address("192.0.2.1")],
            challenge_map={
                "192.0.2.1": ("dns-01", sync_handler),
                IPv4Address("192.0.2.1"): ("http-01", async_handler),
            },
        )
        sync_client.check_rate_limits(dns_names)
        ca.issue(dns_names)
