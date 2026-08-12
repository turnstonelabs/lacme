"""HTTPX2 trust-store and mTLS integration tests for the ACME client."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import ssl
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING
from unittest.mock import Mock

import httpx2
import pytest

from lacme.ca import CertificateAuthority
from lacme.client import Client

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

_DIRECTORY_DATA = {
    "newNonce": "https://acme.test/new-nonce",
    "newAccount": "https://acme.test/new-account",
    "newOrder": "https://acme.test/new-order",
    "revokeCert": "https://acme.test/revoke-cert",
    "keyChange": "https://acme.test/key-change",
}


@dataclass(frozen=True)
class _TLSMaterial:
    root_cert: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path


@pytest.fixture
def tls_material(tmp_path: Path) -> _TLSMaterial:
    ca = CertificateAuthority()
    ca.init(cn="lacme HTTPX2 test CA")
    server = ca.issue([ipaddress.ip_address("127.0.0.1")])
    client = ca.issue("lacme-test-client", client=True)

    material = _TLSMaterial(
        root_cert=tmp_path / "root.pem",
        server_cert=tmp_path / "server.pem",
        server_key=tmp_path / "server-key.pem",
        client_cert=tmp_path / "client.pem",
        client_key=tmp_path / "client-key.pem",
    )
    material.root_cert.write_bytes(ca.root_cert_pem)
    material.server_cert.write_bytes(server.cert_pem)
    material.server_key.write_bytes(server.key_pem)
    material.client_cert.write_bytes(client.cert_pem)
    material.client_key.write_bytes(client.key_pem)
    return material


def _server_ssl_context(material: _TLSMaterial, *, require_client_cert: bool) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(material.server_cert, material.server_key)
    if require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(material.root_cert)
    return context


async def _handle_directory_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        await reader.readuntil(b"\r\n\r\n")
        body = json.dumps(_DIRECTORY_DATA).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        with suppress(ConnectionError):
            await writer.wait_closed()


@asynccontextmanager
async def _directory_server(context: ssl.SSLContext) -> AsyncIterator[str]:
    server = await asyncio.start_server(
        _handle_directory_request,
        "127.0.0.1",
        0,
        ssl=context,
    )
    socket = server.sockets[0]
    port = socket.getsockname()[1]
    try:
        yield f"https://127.0.0.1:{port}/directory"
    finally:
        server.close()
        await server.wait_closed()


class TestTLSVerification:
    @pytest.mark.anyio
    async def test_default_os_trust_rejects_private_ca(self, tls_material: _TLSMaterial) -> None:
        context = _server_ssl_context(tls_material, require_client_cert=False)
        async with (
            _directory_server(context) as directory_url,
            Client(directory_url=directory_url) as client,
        ):
            with pytest.raises(httpx2.TransportError):
                await client.directory()

    @pytest.mark.anyio
    async def test_custom_ca_bundle_is_trusted(self, tls_material: _TLSMaterial) -> None:
        context = _server_ssl_context(tls_material, require_client_cert=False)
        async with (
            _directory_server(context) as directory_url,
            Client(
                directory_url=directory_url,
                ca_bundle=str(tls_material.root_cert),
            ) as client,
        ):
            directory = await client.directory()

        assert directory.new_nonce == _DIRECTORY_DATA["newNonce"]

    @pytest.mark.anyio
    async def test_mtls_requires_client_certificate(self, tls_material: _TLSMaterial) -> None:
        context = _server_ssl_context(tls_material, require_client_cert=True)
        async with (
            _directory_server(context) as directory_url,
            Client(
                directory_url=directory_url,
                ca_bundle=str(tls_material.root_cert),
            ) as client,
        ):
            with pytest.raises(httpx2.TransportError):
                await client.directory()

    @pytest.mark.anyio
    async def test_mtls_client_certificate_and_key(self, tls_material: _TLSMaterial) -> None:
        context = _server_ssl_context(tls_material, require_client_cert=True)
        async with (
            _directory_server(context) as directory_url,
            Client(
                directory_url=directory_url,
                ca_bundle=str(tls_material.root_cert),
                client_cert=str(tls_material.client_cert),
                client_key=str(tls_material.client_key),
            ) as client,
        ):
            directory = await client.directory()

        assert directory.new_order == _DIRECTORY_DATA["newOrder"]

    def test_client_identity_without_custom_ca_uses_httpx2_os_trust(
        self,
        tls_material: _TLSMaterial,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = ssl.create_default_context()
        create_ssl_context = Mock(return_value=context)
        monkeypatch.setattr(httpx2, "create_ssl_context", create_ssl_context)

        client = Client(
            client_cert=str(tls_material.client_cert),
            client_key=str(tls_material.client_key),
        )

        create_ssl_context.assert_called_once_with()
        asyncio.run(client.close())

    @pytest.mark.parametrize(
        ("client_cert", "client_key", "message"),
        [
            ("client.pem", None, "client_cert requires client_key"),
            (None, "client-key.pem", "client_key requires client_cert"),
        ],
    )
    def test_client_certificate_and_key_must_be_paired(
        self,
        client_cert: str | None,
        client_key: str | None,
        message: str,
    ) -> None:
        with pytest.raises(ValueError, match=message):
            Client(client_cert=client_cert, client_key=client_key)
