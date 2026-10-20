# Changelog

## 1.2.1

### Security

- The `aws` extra now requires `certifi>=2026.10.19`. The private keys of
  several eMudhra intermediate CAs can be recovered by anyone (certifi advisory
  GHSA-6q48-6c7w-9gw2), so a client that trusts their root, emSign ECC Root
  CA - G3, accepts a forged certificate for any host. The Route 53 provider
  connects through botocore, which trusts the bundle that `AWS_CA_BUNDLE`, the
  AWS config file's `ca_bundle`, or `REQUESTS_CA_BUNDLE` names, and otherwise
  certifi's bundle; it does not fall back to the operating system's store.
  certifi 2026.10.19 drops that root. Upgrade with `pip install -U "lacme[aws]"`
  or upgrade certifi itself (a plain `pip install -U lacme` does not apply the
  extra's new floor), or remove the root from a bundle you name, then restart
  long-running processes.
- The ACME client adds no roots of its own: a client lacme creates trusts the
  operating system's store, or the bundle or directory that `SSL_CERT_FILE` or
  `SSL_CERT_DIR` names when either is set, or only `ca_bundle` when one is
  given. Update the system's CA certificates (Debian 13: `ca-certificates`
  20250419+deb13u1, DSA-6572-1), or remove the root from a bundle you
  maintain, then restart long-running processes: a client can keep the roots
  it loaded when it was created. The ACME client and DNS provider guides now
  say where lacme's trust comes from.

## 1.2.0

### Added

- `Client.create_order()`, `Client.issue()`, and their `SyncClient` counterparts
  now accept typed `IPv4Address` and `IPv6Address` values and carry RFC 8738
  `ip` identifiers through order creation, CSR generation, responders, testing
  helpers, certificate SANs, and stable string-facing result metadata. Typed IP
  identifiers are excluded from registered-domain rate-limit tracking and
  rejected with `dns-01`, which RFC 8738 does not permit for IP validation.
  Renewal also recovers identifier types from the stored certificate SANs.

### Fixed

- Order creation now rejects empty, malformed, non-canonical, unsupported, and
  scoped-IP identifiers before state is created. DNS names are validated in
  certificate-form ASCII, compared case-insensitively without changing their
  presentation, and wildcard authorizations use the RFC 8555 base-name form
  with DNS-01 only. Finalization strictly decodes and binds the CSR's exact
  typed identifier set to the order, and clients reject downloaded leaf
  certificates whose SAN set or public key does not match the request.
- `MockACMEServer` now returns a verifiable leaf-plus-root chain from one
  reusable per-server CA, and `SyncClient.issue()` adapts synchronous handlers
  supplied through `challenge_map` as it does the default handler.
- Renewal fails closed when stored certificate identity data cannot be parsed or
  reconciled with metadata. `FileStore` uses deterministic portable directory
  components for IPv6, wildcard, and other filesystem-unsafe primary values
  and validates metadata ownership before loading or deleting a certificate.
  Earlier raw directories whose names now require encoding are not discovered
  automatically; they must be moved, or removed before reissuance. Unexpected
  metadata-bearing layouts fail closed during certificate listing.

## 1.1.1

### Fixed

- `ACMEResponder` now accepts an `external_url` for deployments behind Docker
  port publishing, NAT, or reverse proxies, ensuring every advertised ACME URL
  uses one externally reachable responder address.
- The default HTTPS requirement is now enforced for every outbound ACME request,
  including server-discovered resource URLs; `allow_insecure=True` remains the
  explicit opt-in for trusted HTTP deployments. ACME redirects are no longer
  inherited from an injected HTTP client's redirect policy.

## 1.1.0

This release completes [lacme #31](https://github.com/turnstonelabs/lacme/issues/31)
and provides the HTTPX2-based lacme dependency required by
[Turnstone #1011](https://github.com/turnstonelabs/turnstone/issues/1011).

### Breaking changes

- Replaced the HTTPX runtime dependency with `httpx2>=2,<3`.
- `Client(http_client=...)` and `SyncClient(http_client=...)` now require an
  `httpx2.AsyncClient`. HTTPX clients are rejected rather than accepted through
  an unsafe mixed-object path.
- An HTTPX2 client injected into async `Client` remains caller-owned. A fresh,
  unused client injected into `SyncClient` transfers ownership to the sync
  wrapper, which closes it on its managed event loop.
- `MockACMEServer.as_transport()` now returns `httpx2.MockTransport`.
- HTTP transport and status failures now use HTTPX2 exception classes. Catch
  `httpx2.TransportError` and `httpx2.HTTPStatusError` instead of their HTTPX
  counterparts.

### Changed

- Migrated the ACME protocol client, Cloudflare DNS provider, test server,
  examples, and integration helpers to HTTPX2.
- Owned clients use HTTPX2's operating-system trust store by default. Custom CA
  bundles and client certificate/key pairs are loaded through explicit SSL
  contexts.
- Owned clients now send HTTPX2's `python-httpx2/...` default user agent, and
  transport logs use the `httpx2` and `httpcore2.*` logger names.
- The Cloudflare provider continues to pool one async client and sanitize API
  errors without exposing its authorization token.

### Upgrade

Replace `import httpx` with `import httpx2` anywhere constructing a client or
using `MockACMEServer.as_transport()`. Do not pass HTTPX request, response,
transport, or exception objects across the lacme 1.1 boundary.

If you inject an HTTPX2 client into `SyncClient`, create it exclusively for that
wrapper and do not close or reuse it afterward; `SyncClient.close()` owns its
cleanup.
