# ACME Client Guide

This guide covers everything you need to issue, renew, and manage TLS certificates
using the lacme ACME client library. Both the async (`Client`) and synchronous
(`SyncClient`) APIs are shown side by side.

## Async vs Sync API

lacme provides two client classes with identical capabilities:

- **`Client`** -- async-native, uses `async with` and `await`
- **`SyncClient`** -- blocking wrapper, uses `with` and direct calls

=== "Async"

    ```python
    import asyncio
    from lacme import Client, FileStore
    from lacme.challenges.http01 import HTTP01Handler

    async def main():
        store = FileStore("~/.lacme")
        handler = HTTP01Handler()

        async with Client(
            store=store,
            challenge_handler=handler,
            contact="mailto:admin@example.com",
        ) as client:
            bundle = await client.issue("example.com")
            print(f"Certificate expires: {bundle.expires_at}")

    asyncio.run(main())
    ```

=== "Sync"

    ```python
    from lacme import SyncClient, FileStore
    from lacme.challenges.http01 import HTTP01Handler

    store = FileStore("~/.lacme")
    handler = HTTP01Handler()

    with SyncClient(
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
    ) as client:
        bundle = client.issue("example.com")
        print(f"Certificate expires: {bundle.expires_at}")
    ```

!!! tip
    The `SyncClient` accepts both sync and async challenge handlers. If you pass
    a `SyncChallengeHandler` (with plain `def provision`/`def deprovision`), it is
    automatically wrapped to run in a thread executor. If you pass an async handler,
    it is used directly.

## Account Management

### Creating an Account

Accounts are created automatically during `issue()`, but you can create one
explicitly for more control:

=== "Async"

    ```python
    async with Client(
        store=store,
        contact="mailto:admin@example.com",
    ) as client:
        account = await client.create_account(
            contact=["mailto:admin@example.com"],
        )
        print(f"Account URL: {account.url}")
        print(f"Status: {account.status}")
    ```

=== "Sync"

    ```python
    with SyncClient(
        store=store,
        contact="mailto:admin@example.com",
    ) as client:
        account = client.create_account(
            contact=["mailto:admin@example.com"],
        )
        print(f"Account URL: {account.url}")
        print(f"Status: {account.status}")
    ```

### Finding an Existing Account

Use `only_return_existing=True` to look up an account without creating a new one.
This requires the account key already stored (or passed explicitly):

=== "Async"

    ```python
    async with Client(store=store) as client:
        account = await client.create_account(only_return_existing=True)
        print(f"Found account: {account.url}")
    ```

=== "Sync"

    ```python
    with SyncClient(store=store) as client:
        account = client.create_account(only_return_existing=True)
        print(f"Found account: {account.url}")
    ```

!!! note
    If no matching account exists, the ACME server returns an
    `accountDoesNotExist` error, which lacme raises as
    `AccountDoesNotExistError`.

### Deactivating an Account

=== "Async"

    ```python
    async with Client(store=store) as client:
        await client.create_account(only_return_existing=True)
        account = await client.deactivate_account()
        print(f"Account status: {account.status}")  # "deactivated"
    ```

=== "Sync"

    ```python
    with SyncClient(store=store) as client:
        client.create_account(only_return_existing=True)
        account = client.deactivate_account()
        print(f"Account status: {account.status}")  # "deactivated"
    ```

!!! warning
    Account deactivation is **permanent**. The ACME server will reject all
    future requests signed with this account key.

### Key Rollover

Replace the account key on the ACME server. The new key is saved to the store
on success:

=== "Async"

    ```python
    from lacme import generate_ec_key

    async with Client(store=store) as client:
        await client.create_account(only_return_existing=True)
        new_key = generate_ec_key()
        await client.rollover_key(new_key)
        # Pass None to auto-generate a new key:
        # await client.rollover_key()
    ```

=== "Sync"

    ```python
    from lacme import generate_ec_key

    with SyncClient(store=store) as client:
        client.create_account(only_return_existing=True)
        new_key = generate_ec_key()
        client.rollover_key(new_key)
    ```

!!! warning
    If the key rollover succeeds on the server but fails to save locally, lacme
    logs a `CRITICAL` message. The new key exists only in memory at that point.
    Back it up immediately.

## Certificate Issuance

### Single Domain

```python
bundle = await client.issue("example.com")
```

The `issue()` method orchestrates the full ACME flow:

1. Ensure an account exists (create if needed)
2. Create an order
3. Solve challenges for each domain
4. Finalize with a CSR
5. Download the certificate chain

The returned `CertBundle` contains:

| Field             | Type                | Description                    |
|-------------------|---------------------|--------------------------------|
| `domain`          | `str`               | Primary domain                 |
| `domains`         | `tuple[str, ...]`   | All domains in the certificate |
| `cert_pem`        | `bytes`             | Leaf certificate (PEM)         |
| `fullchain_pem`   | `bytes`             | Full chain (leaf + intermediates) |
| `key_pem`         | `bytes`             | Private key (PEM)              |
| `issued_at`       | `datetime`          | Issuance timestamp             |
| `expires_at`      | `datetime`          | Expiry timestamp               |
| `cert_path`       | `Path | None`       | File path (if using FileStore) |
| `fullchain_path`  | `Path | None`       | File path (if using FileStore) |
| `key_path`        | `Path | None`       | File path (if using FileStore) |

### Multi-Domain (SAN) Certificates

Pass a list of domains. The first domain becomes the Common Name (CN):

```python
bundle = await client.issue([
    "example.com",
    "www.example.com",
    "api.example.com",
])
```

### Wildcard Certificates

Wildcard certificates require DNS-01 validation:

```python
from lacme import Client, FileStore, DNS01Handler
from lacme.challenges.providers.cloudflare import CloudflareDNSProvider

provider = CloudflareDNSProvider(
    api_token="your-cloudflare-token",
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
```

!!! note
    lacme raises a `ValueError` if you attempt to use `http-01` with a
    wildcard domain. Wildcard domains always require `dns-01`.

## Challenge Types

### HTTP-01 with Standalone Server

The `HTTP01Handler` can run a minimal HTTP server on port 80 to respond to
challenges:

```python
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()
server = await handler.start_server(host="0.0.0.0", port=80)

async with Client(
    store=store,
    challenge_handler=handler,
) as client:
    bundle = await client.issue("example.com")

server.close()
await server.wait_closed()
```

### HTTP-01 with ASGI Middleware

Serve challenge responses from your existing web application:

```python
from lacme.asgi import ACMEChallengeMiddleware
from lacme.challenges.http01 import HTTP01Handler

handler = HTTP01Handler()

# Wrap any ASGI app
app = ACMEChallengeMiddleware(your_app, handler)
```

Requests to `/.well-known/acme-challenge/{token}` are intercepted; everything
else passes through to the inner app.

### DNS-01 with Providers

DNS-01 challenges work by creating TXT records. See the
[DNS Providers guide](dns-providers.md) for full setup instructions.

```python
from lacme import DNS01Handler
from lacme.challenges.providers.cloudflare import CloudflareDNSProvider

provider = CloudflareDNSProvider(
    api_token="your-token",
    zone_id="your-zone-id",
)
handler = DNS01Handler(
    provider=provider,
    propagation_delay=10.0,
    propagation_timeout=120.0,
)
```

## Mixed Challenge Types

Use the `challenge_map` parameter to assign different challenge types and
handlers per domain. This is useful when some domains need DNS-01 (e.g.,
wildcards) while others can use HTTP-01:

```python
from lacme.challenges.http01 import HTTP01Handler
from lacme import DNS01Handler
from lacme.challenges.providers.cloudflare import CloudflareDNSProvider

http_handler = HTTP01Handler()
dns_provider = CloudflareDNSProvider(
    api_token="your-token",
    zone_id="your-zone-id",
)
dns_handler = DNS01Handler(provider=dns_provider)

async with Client(
    store=store,
    challenge_handler=http_handler,  # default for domains not in map
    contact="mailto:admin@example.com",
) as client:
    bundle = await client.issue(
        ["example.com", "*.example.com", "api.example.com"],
        challenge_type="http-01",  # default challenge type
        challenge_map={
            # Wildcard must use DNS-01
            "*.example.com": ("dns-01", dns_handler),
        },
    )
```

Domains not present in `challenge_map` use the default `challenge_type` and
the client's `challenge_handler`.

## Certificate Revocation

### Revoke with Account Key

Revoke a certificate using the ACME account that issued it:

=== "Async"

    ```python
    from lacme import RevocationReason

    async with Client(store=store) as client:
        await client.create_account(only_return_existing=True)
        bundle = store.load_cert("example.com")
        await client.revoke(
            bundle.cert_pem,
            reason=RevocationReason.KEY_COMPROMISE,
        )
    ```

=== "Sync"

    ```python
    from lacme import RevocationReason

    with SyncClient(store=store) as client:
        client.create_account(only_return_existing=True)
        bundle = store.load_cert("example.com")
        client.revoke(
            bundle.cert_pem,
            reason=RevocationReason.KEY_COMPROMISE,
        )
    ```

### Revoke with Certificate Key

Revoke using the certificate's own private key. This does not require an
ACME account:

```python
from lacme import private_key_from_pem

cert_key = private_key_from_pem(bundle.key_pem)

async with Client(
    directory_url="https://acme-v02.api.letsencrypt.org/directory",
) as client:
    await client.revoke_with_cert_key(
        bundle.cert_pem,
        cert_key,
        reason=RevocationReason.SUPERSEDED,
    )
```

### Revocation Reason Codes

| Code | Name                       | Value |
|------|----------------------------|-------|
| 0    | `UNSPECIFIED`              | 0     |
| 1    | `KEY_COMPROMISE`           | 1     |
| 2    | `CA_COMPROMISE`            | 2     |
| 3    | `AFFILIATION_CHANGED`      | 3     |
| 4    | `SUPERSEDED`               | 4     |
| 5    | `CESSATION_OF_OPERATION`   | 5     |

## Auto-Renewal

### Using Client.auto_renew()

Start a background task that checks stored certificates and renews them when
they approach expiry:

```python
async with Client(
    store=store,
    challenge_handler=handler,
    contact="mailto:admin@example.com",
) as client:
    # Issue the initial certificate
    await client.issue("example.com")

    # Start auto-renewal (checks every 12 hours, renews 30 days before expiry)
    task = await client.auto_renew(
        interval_hours=12.0,
        days_before_expiry=30,
        on_renewed=lambda bundle: print(f"Renewed: {bundle.domain}"),
    )

    # Your application runs here...
    await asyncio.sleep(3600)

    # Cancel when shutting down
    task.cancel()
```

### Using RenewalManager Directly

For more control, use `RenewalManager` directly:

```python
from lacme import RenewalManager

manager = RenewalManager(
    client=client,
    store=store,
    interval_hours=12.0,
    days_before_expiry=30,
    challenge_type="http-01",
    on_renewed=lambda bundle: print(f"Renewed: {bundle.domain}"),
    max_jitter_seconds=600.0,  # random delay to avoid thundering herd
)

# Run a single check-and-renew pass
renewed = await manager.check_and_renew()

# Or start the continuous background loop
task = manager.start()
```

!!! tip
    The `on_renewed` callback accepts both sync and async functions. If it
    returns an awaitable, lacme will `await` it automatically.

## External Account Binding

Some CAs (ZeroSSL, enterprise CAs) require External Account Binding (EAB).
Pass the `eab_kid` and `eab_hmac_key` to the client:

=== "Async"

    ```python
    async with Client(
        directory_url="https://acme.zerossl.com/v2/DV90",
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
        eab_kid="your-kid-from-zerossl",
        eab_hmac_key="your-base64url-hmac-key",
    ) as client:
        bundle = await client.issue("example.com")
    ```

=== "Sync"

    ```python
    with SyncClient(
        directory_url="https://acme.zerossl.com/v2/DV90",
        store=store,
        challenge_handler=handler,
        contact="mailto:admin@example.com",
        eab_kid="your-kid-from-zerossl",
        eab_hmac_key="your-base64url-hmac-key",
    ) as client:
        bundle = client.issue("example.com")
    ```

You can also pass EAB credentials per-call to `create_account()`:

```python
account = await client.create_account(
    eab_kid="override-kid",
    eab_hmac_key="override-hmac-key",
)
```

!!! note
    Both `eab_kid` and `eab_hmac_key` must be provided together. The HMAC key
    must be base64url-encoded.

## Custom ACME Servers

### Using step-ca or Other Private CAs

Point `directory_url` at your CA's ACME directory. For CAs using a private
root certificate, pass `ca_bundle`:

```python
async with Client(
    directory_url="https://ca.internal:8443/acme/acme/directory",
    ca_bundle="/path/to/ca-root.pem",
    store=store,
    challenge_handler=handler,
) as client:
    bundle = await client.issue("service.internal")
```

### HTTPS Enforcement

By default, lacme requires the directory URL to use HTTPS:

```python
# This raises ValueError:
client = Client(directory_url="http://localhost:8080/directory")
```

For local development or trusted networks, set `allow_insecure=True`:

```python
async with Client(
    directory_url="http://localhost:8080/directory",
    allow_insecure=True,
    store=store,
    challenge_handler=handler,
) as client:
    bundle = await client.issue("dev.local")
```

!!! warning
    Never use `allow_insecure=True` in production. ACME requests contain
    cryptographic signatures, but an HTTP transport allows interception and
    replay attacks.

### Client Certificate Authentication

Some CAs require mTLS for API access. Pass `client_cert` and `client_key`:

```python
async with Client(
    directory_url="https://ca.corp.example.com/acme/directory",
    ca_bundle="/etc/pki/corp-ca.pem",
    client_cert="/etc/pki/my-client.pem",
    client_key="/etc/pki/my-client-key.pem",
    store=store,
    challenge_handler=handler,
) as client:
    bundle = await client.issue("app.corp.example.com")
```

## Rate Limit Awareness

Let's Encrypt enforces rate limits (50 certificates per registered domain per
week). lacme can track issuance locally and prevent requests that would exceed
the limit.

### Setup

```python
from lacme import Client, FileStore, RateLimitTracker
from lacme.ratelimit import FileRateLimitStore

store = FileStore("~/.lacme")
rate_store = FileRateLimitStore(base=store.base)
tracker = RateLimitTracker(
    store=rate_store,
    limit=50,                   # Let's Encrypt default
    warn_threshold=0.9,         # Warn at 90% (45 certs)
    block=True,                 # Block issuance at limit
)

# Or create from FileStore directly:
tracker = RateLimitTracker.from_file_store(store)

async with Client(
    store=store,
    challenge_handler=handler,
    rate_limit_tracker=tracker,
) as client:
    bundle = await client.issue("example.com")
```

### Checking Limits Before Issuance

```python
status = client.check_rate_limits(["example.com", "www.example.com"])
print(f"Allowed: {status.allowed}")
print(f"Counts: {status.counts}")      # {"example.com": 3}
print(f"Warnings: {status.warnings}")  # ["example.com: 45/50 ... (warning)"]
```

When `block=True` (the default), `issue()` raises `RateLimitPreventedError`
if the limit would be exceeded. The check happens before any network requests
are made.

!!! tip
    For accurate registered domain extraction with complex TLDs (e.g.,
    `foo.co.uk`), pass a custom `registered_domain_func` using a library
    like `tldextract`:

    ```python
    import tldextract

    def get_registered_domain(domain: str) -> str:
        ext = tldextract.extract(domain)
        return f"{ext.domain}.{ext.suffix}"

    tracker = RateLimitTracker(
        store=rate_store,
        registered_domain_func=get_registered_domain,
    )
    ```

## Storage

### FileStore

Persists account keys and certificates to disk with safe permissions:

```python
from lacme import FileStore

store = FileStore("~/.lacme")
```

Directory layout:

```
~/.lacme/
    account.key          (PEM, 0o600)
    certs/
        example.com/
            cert.pem     (leaf, 0o644)
            fullchain.pem (0o644)
            key.pem      (private key, 0o600)
            meta.json    (0o644)
```

### MemoryStore

In-memory store for testing -- no filesystem access:

```python
from lacme import MemoryStore

store = MemoryStore()
```

### Loading Stored Certificates

```python
store = FileStore("~/.lacme")

# Load a single certificate
bundle = store.load_cert("example.com")
if bundle is not None:
    print(f"Expires: {bundle.expires_at}")

# List all stored certificates
for bundle in store.list_certs():
    print(f"{bundle.domain}: expires {bundle.expires_at}")
```

### Deleting Certificates

Remove a certificate from the store:

```python
deleted = store.delete_cert("example.com")  # returns True if existed
```
