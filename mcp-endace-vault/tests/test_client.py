"""Targeted client tests for Endace Vault Basic auth and error handling."""

from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import httpx
import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / file_name)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


client_module = _load_module("mcp_endace_client", "client.py")
EndaceVaultClient = client_module.EndaceVaultClient
EndaceVaultClientError = client_module.EndaceVaultClientError


@pytest.mark.asyncio
async def test_client_uses_basic_auth_for_list_requests() -> None:
    async def api_handler(request: httpx.Request) -> httpx.Response:
        expected = "Basic " + base64.b64encode(b"vaultapi:secret").decode()
        assert request.headers["Authorization"] == expected
        assert request.url.params["page"] == "1"
        return httpx.Response(200, json={"payload": {"vaultEntries": []}, "meta": {"error": False}})

    client = EndaceVaultClient(
        username="vaultapi",
        password="secret",
        base_url="https://vault.example/api/v5/vault",
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    payload = await client.list_requests(page=1)
    assert payload["payload"]["vaultEntries"] == []
    await client.aclose()


@pytest.mark.asyncio
async def test_client_create_request_uses_type_format_path_and_query_params() -> None:
    async def api_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/packets/pcap")
        assert request.url.params["datasources"] == "tag:rotation-file"
        assert request.url.params["reltime"] == "10m"
        return httpx.Response(200, json={"payload": {"status": "Downloading"}, "meta": {"error": False}})

    client = EndaceVaultClient(
        username="vaultapi",
        password="secret",
        base_url="https://vault.example/api/v5/vault",
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    payload = await client.create_request(
        request_type="packets",
        request_format="pcap",
        params={"datasources": "tag:rotation-file", "reltime": "10m"},
    )
    assert payload["payload"]["status"] == "Downloading"
    await client.aclose()


@pytest.mark.asyncio
async def test_client_raises_safe_error_for_invalid_credentials() -> None:
    async def api_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    client = EndaceVaultClient(
        username="vaultapi",
        password="bad",
        base_url="https://vault.example/api/v5/vault",
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    with pytest.raises(EndaceVaultClientError, match="Check ENDACE_VAULT_USERNAME and ENDACE_VAULT_PASSWORD"):
        await client.get_request("abc")

    await client.aclose()


@pytest.mark.asyncio
async def test_client_raises_safe_error_for_server_busy() -> None:
    async def api_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "busy"})

    client = EndaceVaultClient(
        username="vaultapi",
        password="secret",
        base_url="https://vault.example/api/v5/vault",
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    with pytest.raises(EndaceVaultClientError, match="returned 503"):
        await client.get_request("abc")

    await client.aclose()
