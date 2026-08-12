# Changelog

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
