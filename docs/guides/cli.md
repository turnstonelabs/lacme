# CLI Reference

The `lacme` command-line tool provides certificate issuance, renewal,
revocation, and account management. It uses `SyncClient` and `FileStore`
under the hood.

## Installation

```bash
pip install lacme
```

The `lacme` command is installed as a console script entry point.

## Global Flags

These flags are available on all subcommands:

| Flag            | Default            | Description                              |
|-----------------|--------------------|------------------------------------------|
| `--directory`   | Let's Encrypt prod | ACME directory URL                       |
| `--staging`     | (off)              | Use Let's Encrypt staging environment    |
| `--store`       | `~/.lacme`         | Certificate store directory path         |
| `--contact`     | (none)             | Account contact email                    |
| `-v, --verbose` | (off)              | Enable debug logging to stderr           |

### Examples

```bash
# Use Let's Encrypt staging
lacme --staging issue example.com

# Custom ACME server
lacme --directory https://ca.internal:8443/acme/directory issue app.internal

# Custom store location
lacme --store /etc/lacme issue example.com

# With contact email (mailto: prefix added automatically)
lacme --contact admin@example.com issue example.com

# Debug output
lacme -v issue example.com
```

!!! tip
    The `--contact` flag automatically prepends `mailto:` if not already
    present, so `--contact admin@example.com` becomes
    `mailto:admin@example.com`.

## lacme issue

Issue a new certificate for one or more domains.

```
lacme issue [options] DOMAIN [DOMAIN ...]
```

### Options

| Flag                    | Description                                              |
|-------------------------|----------------------------------------------------------|
| `--dns-provider`        | DNS-01 provider: `cloudflare`, `route53`, or `hook`      |
| `--cloudflare-token`    | Cloudflare API token (prefer `LACME_CLOUDFLARE_TOKEN`)   |
| `--cloudflare-zone-id`  | Cloudflare zone ID (or `LACME_CLOUDFLARE_ZONE_ID`)       |
| `--route53-zone-id`     | Route 53 hosted zone ID (or `LACME_ROUTE53_ZONE_ID`)     |
| `--hook-create`         | Path to DNS record creation script                       |
| `--hook-delete`         | Path to DNS record deletion script                       |

Without `--dns-provider`, the CLI uses HTTP-01 challenges (requires port 80
access).

### Examples

**Single domain with HTTP-01:**

```bash
lacme issue example.com
```

**Multi-domain (SAN) certificate:**

```bash
lacme issue example.com www.example.com api.example.com
```

**Wildcard with Cloudflare DNS-01:**

```bash
export LACME_CLOUDFLARE_TOKEN="your-api-token"
export LACME_CLOUDFLARE_ZONE_ID="your-zone-id"

lacme issue --dns-provider cloudflare example.com "*.example.com"
```

**DNS-01 with Route 53:**

```bash
export LACME_ROUTE53_ZONE_ID="Z0123456789ABCDEFGHIJ"

lacme issue --dns-provider route53 example.com "*.example.com"
```

**DNS-01 with hook scripts:**

```bash
lacme issue \
    --dns-provider hook \
    --hook-create /usr/local/bin/dns-create.sh \
    --hook-delete /usr/local/bin/dns-delete.sh \
    example.com "*.example.com"
```

**Staging environment (for testing):**

```bash
lacme --staging issue example.com
```

### Output

On success, the CLI prints:

```
Certificate issued for example.com
  Domains: example.com, www.example.com
  Expires: 2026-06-23T12:00:00+00:00
  Cert:      /home/user/.lacme/certs/example.com/cert.pem
  Fullchain: /home/user/.lacme/certs/example.com/fullchain.pem
  Key:       /home/user/.lacme/certs/example.com/key.pem
```

!!! warning
    When using `--cloudflare-token` on the command line, the token is visible
    in the process table. Prefer the `LACME_CLOUDFLARE_TOKEN` environment
    variable to avoid exposure.

## lacme renew

Check all stored certificates and renew those approaching expiry.

```
lacme renew [options]
```

### Options

| Flag                    | Default | Description                                       |
|-------------------------|---------|---------------------------------------------------|
| `--days`                | `30`    | Renew certificates expiring within this many days  |
| `--dns-provider`        | (none)  | DNS-01 provider for renewal                        |
| `--cloudflare-token`    | (none)  | Cloudflare API token                               |
| `--cloudflare-zone-id`  | (none)  | Cloudflare zone ID                                 |
| `--route53-zone-id`     | (none)  | Route 53 hosted zone ID                            |
| `--hook-create`         | (none)  | DNS record creation script                         |
| `--hook-delete`         | (none)  | DNS record deletion script                         |

### Examples

**Renew with HTTP-01 (default threshold 30 days):**

```bash
lacme renew
```

**Renew with custom threshold:**

```bash
lacme renew --days 14
```

**Renew with DNS-01:**

```bash
export LACME_CLOUDFLARE_TOKEN="your-token"
export LACME_CLOUDFLARE_ZONE_ID="your-zone-id"

lacme renew --dns-provider cloudflare
```

### Output

```
Renewed: example.com (expires 2026-06-23T12:00:00+00:00)
Renewed: api.example.com (expires 2026-06-23T12:00:00+00:00)

2/2 certificates renewed.
```

If no certificates need renewal:

```
No certificates need renewal.
```

!!! tip
    Set up a cron job or systemd timer to run `lacme renew` daily:

    ```bash
    # /etc/cron.d/lacme
    0 3 * * * root lacme renew --days 30
    ```

## lacme revoke

Revoke a stored certificate.

```
lacme revoke [options] DOMAIN
```

### Options

| Flag       | Description                                |
|------------|--------------------------------------------|
| `--reason` | Revocation reason code (integer, optional) |

### Revocation Reason Codes

| Code | Meaning                    |
|------|----------------------------|
| 0    | Unspecified                |
| 1    | Key compromise             |
| 2    | CA compromise              |
| 3    | Affiliation changed        |
| 4    | Superseded                 |
| 5    | Cessation of operation     |

### Examples

**Revoke without reason:**

```bash
lacme revoke example.com
```

**Revoke with reason code:**

```bash
lacme revoke --reason 1 example.com
```

### Output

```
Certificate for example.com revoked.
```

If no certificate is found:

```
No certificate found for example.com
```

## lacme account

Account management subcommands.

### lacme account create

Create a new ACME account or find an existing one:

```bash
lacme --contact admin@example.com account create
```

Output:

```
Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456
Status:      valid
Contact:     mailto:admin@example.com
```

### lacme account info

Display information about the existing account (requires a stored account key):

```bash
lacme account info
```

Output:

```
Account URL: https://acme-v02.api.letsencrypt.org/acme/acct/123456
Status:      valid
Contact:     mailto:admin@example.com
```

!!! note
    `account info` uses `only_return_existing=True` internally. If no account
    exists for the stored key, the command fails with an error.

### lacme account deactivate

Permanently deactivate the ACME account:

```bash
lacme account deactivate
```

Output:

```
Account https://acme-v02.api.letsencrypt.org/acme/acct/123456 deactivated.
```

!!! warning
    Account deactivation is **permanent and irreversible**. You will need to
    create a new account to issue certificates.

## Environment Variables

The following environment variables are recognized by the CLI:

| Variable                   | Used By                        | Description            |
|----------------------------|--------------------------------|------------------------|
| `LACME_CLOUDFLARE_TOKEN`   | `--dns-provider cloudflare`    | Cloudflare API token   |
| `LACME_CLOUDFLARE_ZONE_ID` | `--dns-provider cloudflare`    | Cloudflare zone ID     |
| `LACME_ROUTE53_ZONE_ID`    | `--dns-provider route53`       | Route 53 hosted zone ID|

Environment variables are used as fallbacks when the corresponding command-line
flag is not provided. Command-line flags take precedence.

### Example

```bash
# Set credentials once
export LACME_CLOUDFLARE_TOKEN="your-api-token"
export LACME_CLOUDFLARE_ZONE_ID="your-zone-id"

# Use without repeating credentials
lacme issue --dns-provider cloudflare example.com "*.example.com"
lacme renew --dns-provider cloudflare
```

## Exit Codes

| Code | Meaning                                        |
|------|------------------------------------------------|
| 0    | Success                                        |
| 1    | Error (missing arguments, API failure, etc.)   |
| 130  | Interrupted (Ctrl+C)                           |

## Store Layout

The `--store` directory (default `~/.lacme`) has the following layout after
issuing a certificate:

```
~/.lacme/
    account.key                  # ACME account private key (0o600)
    certs/
        example.com/
            cert.pem             # Leaf certificate (0o644)
            fullchain.pem        # Full chain (leaf + intermediates) (0o644)
            key.pem              # Certificate private key (0o600)
            meta.json            # Metadata (domain, dates) (0o644)
        api.example.com/
            cert.pem
            fullchain.pem
            key.pem
            meta.json
    rate_limits.json             # Rate limit tracking (if enabled)
```

Private keys (`account.key`, `key.pem`) are written with 0o600 permissions.
All writes are atomic (temp file + `os.replace`) with `fsync` to ensure data
integrity.
