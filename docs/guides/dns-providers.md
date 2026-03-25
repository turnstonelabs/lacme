# DNS Providers Guide

DNS-01 challenges prove domain ownership by creating TXT records under
`_acme-challenge.<domain>`. lacme ships with providers for Cloudflare,
AWS Route 53, and external hook scripts, plus a protocol for writing
your own.

## Cloudflare

### Create an API Token

1. Go to [Cloudflare Dashboard > API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Edit zone DNS** template, or create a custom token with:
    - **Permissions**: Zone > DNS > Edit
    - **Zone Resources**: Include > Specific zone > your domain
4. Copy the token

### Find Your Zone ID

The Zone ID is displayed on your domain's **Overview** page in the Cloudflare
dashboard, in the right sidebar under **API**.

### Usage

```python
from lacme import Client, FileStore, DNS01Handler
from lacme.challenges.providers.cloudflare import CloudflareDNSProvider

provider = CloudflareDNSProvider(
    api_token="your-cloudflare-api-token",
    zone_id="your-zone-id",
)
handler = DNS01Handler(provider=provider)

async with Client(
    store=FileStore("~/.lacme"),
    challenge_handler=handler,
    contact="mailto:admin@example.com",
) as client:
    bundle = await client.issue(
        ["example.com", "*.example.com"],
        challenge_type="dns-01",
    )

# Clean up the HTTP client used by the provider
await provider.close()
```

!!! tip
    Use environment variables to keep tokens out of source code:

    ```python
    import os

    provider = CloudflareDNSProvider(
        api_token=os.environ["LACME_CLOUDFLARE_TOKEN"],
        zone_id=os.environ["LACME_CLOUDFLARE_ZONE_ID"],
    )
    ```

    The CLI also supports these environment variables -- see
    [CLI Reference](cli.md#environment-variables).

### How It Works

The `CloudflareDNSProvider`:

1. **Creates** a TXT record via `POST /zones/{zone_id}/dns_records` with TTL 120
2. Tracks the record ID returned by Cloudflare
3. **Deletes** the record via `DELETE /zones/{zone_id}/dns_records/{id}` after
   validation

Error responses are sanitized to avoid leaking API tokens in logs or stack
traces.

## Route 53

### IAM Policy

Create an IAM user or role with the following minimum permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetChange"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/YOUR_HOSTED_ZONE_ID",
                "arn:aws:route53:::change/*"
            ]
        }
    ]
}
```

### Find Your Hosted Zone ID

```bash
aws route53 list-hosted-zones --query 'HostedZones[*].[Id,Name]' --output table
```

Or find it in the Route 53 console under **Hosted zones**.

### Configure Credentials

Route 53 uses `boto3`, which reads credentials from the standard chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM role (if running on EC2/ECS/Lambda)

### Usage

```python
from lacme import Client, FileStore, DNS01Handler
from lacme.challenges.providers.route53 import Route53DNSProvider

provider = Route53DNSProvider(
    hosted_zone_id="Z0123456789ABCDEFGHIJ",
)
handler = DNS01Handler(provider=provider)

async with Client(
    store=FileStore("~/.lacme"),
    challenge_handler=handler,
    contact="mailto:admin@example.com",
) as client:
    bundle = await client.issue(
        ["example.com", "*.example.com"],
        challenge_type="dns-01",
    )
```

!!! note
    `Route53DNSProvider` uses `boto3` (a synchronous library) internally. Calls
    to `create_txt_record` and `delete_txt_record` are automatically run in a
    thread executor via `asyncio.run_in_executor` to avoid blocking the event
    loop.

    Install the AWS extra: `pip install lacme[aws]`

### How It Works

The `Route53DNSProvider`:

1. **Creates** a TXT record via `UPSERT` in `ChangeResourceRecordSets` with TTL 120
2. **Deletes** the record via `DELETE` in `ChangeResourceRecordSets` after validation

The `UPSERT` action creates the record if it does not exist, or replaces it if
it does. This is idempotent and safe for retries.

## Hook (External Script)

The hook provider delegates DNS record management to external scripts. This is
useful for DNS providers that do not have a dedicated lacme integration.

### Usage

```python
from lacme import DNS01Handler
from lacme.challenges.providers.hook import HookDNSProvider

provider = HookDNSProvider(
    create_command="/usr/local/bin/dns-create.sh",
    delete_command="/usr/local/bin/dns-delete.sh",
    timeout=30.0,  # seconds (default)
)
handler = DNS01Handler(provider=provider)
```

### Script Interface

Both scripts receive two positional arguments:

```
<command> <domain> <txt-value>
```

For example, when issuing a certificate for `*.example.com`:

```bash
# Create is called with:
/usr/local/bin/dns-create.sh _acme-challenge.example.com dGVzdC12YWx1ZQ...

# Delete is called with:
/usr/local/bin/dns-delete.sh _acme-challenge.example.com dGVzdC12YWx1ZQ...
```

Scripts must exit with code 0 on success. Any non-zero exit code causes the
challenge to fail. stderr output is captured and included in the error message.

### Example Hook Script

```bash
#!/bin/bash
# dns-create.sh -- Create a TXT record via your DNS API
set -euo pipefail

DOMAIN="$1"
VALUE="$2"

curl -s -X POST "https://api.mydns.example/records" \
    -H "Authorization: Bearer ${DNS_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"type\": \"TXT\", \"name\": \"${DOMAIN}\", \"content\": \"${VALUE}\", \"ttl\": 120}"
```

### String vs List Commands

Commands can be passed as strings (split with `shlex.split`) or lists:

```python
# String form -- split automatically
provider = HookDNSProvider(
    create_command="python /opt/dns/create.py --verbose",
    delete_command="python /opt/dns/delete.py --verbose",
)

# List form -- exact argv
provider = HookDNSProvider(
    create_command=["python", "/opt/dns/create.py", "--verbose"],
    delete_command=["python", "/opt/dns/delete.py", "--verbose"],
)
```

### Timeout

If a hook script does not complete within the timeout (default 30 seconds),
lacme kills the process and raises a `RuntimeError`:

```python
provider = HookDNSProvider(
    create_command="/usr/local/bin/slow-dns-create.sh",
    delete_command="/usr/local/bin/slow-dns-delete.sh",
    timeout=120.0,  # 2 minutes
)
```

!!! warning
    The `HookDNSProvider` validates that both commands exist (via `shutil.which`)
    at construction time. A `FileNotFoundError` is raised immediately if a
    command is not found on `PATH`.

## Custom Provider

Implement the `DNSProvider` protocol to integrate any DNS service:

```python
from lacme.challenges.dns01 import DNSProvider

class MyDNSProvider:
    """Custom DNS provider for MyDNS service."""

    def __init__(self, api_key: str, domain: str) -> None:
        self._api_key = api_key
        self._domain = domain

    async def create_txt_record(self, domain: str, value: str) -> None:
        """Create a TXT record.

        Args:
            domain: Full record name (e.g., '_acme-challenge.example.com')
            value: Base64url-encoded SHA-256 digest to set as the TXT value
        """
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://api.mydns.example/v1/records",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "type": "TXT",
                    "name": domain,
                    "content": value,
                    "ttl": 120,
                },
            )
            resp.raise_for_status()

    async def delete_txt_record(self, domain: str, value: str) -> None:
        """Delete a TXT record.

        Args:
            domain: Full record name
            value: The TXT value to remove (used to identify the record)
        """
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"https://api.mydns.example/v1/records",
                headers={"Authorization": f"Bearer {self._api_key}"},
                params={"name": domain, "content": value},
            )
            resp.raise_for_status()
```

Then use it with `DNS01Handler`:

```python
from lacme import DNS01Handler

provider = MyDNSProvider(api_key="secret", domain="example.com")
handler = DNS01Handler(provider=provider)
```

!!! note
    The `DNSProvider` protocol is `@runtime_checkable`, so `isinstance(obj,
    DNSProvider)` returns `True` for any object with matching
    `create_txt_record` and `delete_txt_record` methods -- no explicit
    inheritance needed.

## DNS01Handler Configuration

The `DNS01Handler` wraps a `DNSProvider` and adds propagation waiting:

```python
from lacme import DNS01Handler

handler = DNS01Handler(
    provider=provider,
    propagation_delay=10.0,       # seconds to wait if no checker (default: 10)
    propagation_timeout=120.0,    # max seconds to poll checker (default: 120)
    propagation_interval=5.0,     # seconds between checker polls (default: 5)
    propagation_checker=my_checker,  # optional async callback
)
```

### Parameters

| Parameter              | Default | Description                                    |
|------------------------|---------|------------------------------------------------|
| `propagation_delay`    | `10.0`  | Fixed sleep (seconds) when no checker is set   |
| `propagation_timeout`  | `120.0` | Maximum time to wait for propagation checker   |
| `propagation_interval` | `5.0`   | Interval between propagation checker polls     |
| `propagation_checker`  | `None`  | Async callback to verify DNS propagation       |

### Propagation Checker

Without a `propagation_checker`, `DNS01Handler` sleeps for `propagation_delay`
seconds after creating the record. With a checker, it polls until the record is
visible or the timeout is reached:

```python
import dns.asyncresolver

async def check_propagation(domain: str, expected_value: str) -> bool:
    """Check if the TXT record has propagated to public DNS."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                if txt.decode() == expected_value:
                    return True
    except dns.asyncresolver.NXDOMAIN:
        pass
    return False

handler = DNS01Handler(
    provider=provider,
    propagation_checker=check_propagation,
    propagation_timeout=180.0,
)
```

!!! tip
    If the propagation checker times out, lacme raises `ACMETimeoutError`.
    Increase `propagation_timeout` if your DNS provider is slow to propagate.

## Wildcard Certificates

Wildcard certificates (`*.example.com`) always require DNS-01 validation.
lacme automatically strips the `*.` prefix when constructing the challenge
record name:

| Domain              | Challenge Record Name             |
|---------------------|-----------------------------------|
| `example.com`       | `_acme-challenge.example.com`     |
| `*.example.com`     | `_acme-challenge.example.com`     |
| `*.sub.example.com` | `_acme-challenge.sub.example.com` |

This means that a certificate for both `example.com` and `*.example.com` creates
a single `_acme-challenge.example.com` TXT record. Most ACME servers handle this
by requiring two separate TXT records with the same name (one per authorization).

```python
# Issue a wildcard + apex certificate
bundle = await client.issue(
    ["example.com", "*.example.com"],
    challenge_type="dns-01",
)
```

!!! warning
    lacme raises a `ValueError` if you try to use `http-01` with a wildcard
    domain:

    ```python
    # This raises ValueError:
    await client.issue("*.example.com", challenge_type="http-01")
    ```
