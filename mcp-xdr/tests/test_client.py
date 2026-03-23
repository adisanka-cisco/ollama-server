from __future__ import annotations

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


client_module = _load_module("mcp_xdr_client", "client.py")
CiscoXDRClient = client_module.CiscoXDRClient
XDRClientError = client_module.XDRClientError


@pytest.mark.asyncio
async def test_client_caches_client_credentials_token_until_refresh_window() -> None:
    token_calls = 0
    api_calls = 0

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls
        token_calls += 1
        return httpx.Response(200, json={"access_token": "token-1", "token_type": "Bearer", "expires_in": 3600})

    async def api_handler(request: httpx.Request) -> httpx.Response:
        nonlocal api_calls
        api_calls += 1
        assert request.headers["Authorization"] == "Bearer token-1"
        return httpx.Response(200, json={"items": []})

    client = CiscoXDRClient(
        client_id="id",
        client_secret="secret",
        token_url="https://visibility.amp.cisco.com/iroh/oauth2/token",
        conure_base_url="https://conure.us.security.cisco.com",
        auth_client=httpx.AsyncClient(transport=httpx.MockTransport(auth_handler)),
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    await client.list_incidents(limit=5)
    await client.list_incidents(limit=5)

    assert token_calls == 1
    assert api_calls == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_client_retries_once_with_fresh_token_on_401() -> None:
    tokens = iter(
        [
            {"access_token": "stale-token", "token_type": "Bearer", "expires_in": 3600},
            {"access_token": "fresh-token", "token_type": "Bearer", "expires_in": 3600},
        ]
    )
    seen_auth_headers: list[str] = []

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(tokens))

    async def api_handler(request: httpx.Request) -> httpx.Response:
        seen_auth_headers.append(request.headers["Authorization"])
        if request.headers["Authorization"] == "Bearer stale-token":
            return httpx.Response(401, json={"error": "expired"})
        return httpx.Response(200, json={"id": "INC-123"})

    client = CiscoXDRClient(
        client_id="id",
        client_secret="secret",
        token_url="https://visibility.amp.cisco.com/iroh/oauth2/token",
        conure_base_url="https://conure.us.security.cisco.com",
        auth_client=httpx.AsyncClient(transport=httpx.MockTransport(auth_handler)),
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
    )

    payload = await client.get_incident("INC-123")

    assert payload["id"] == "INC-123"
    assert seen_auth_headers == ["Bearer stale-token", "Bearer fresh-token"]
    await client.aclose()


@pytest.mark.asyncio
async def test_client_raises_safe_error_for_invalid_credentials() -> None:
    async def auth_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    client = CiscoXDRClient(
        client_id="id",
        client_secret="secret",
        token_url="https://visibility.amp.cisco.com/iroh/oauth2/token",
        conure_base_url="https://conure.us.security.cisco.com",
        auth_client=httpx.AsyncClient(transport=httpx.MockTransport(auth_handler)),
        api_client=httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(500))),
    )

    with pytest.raises(XDRClientError, match="Check XDR_CLIENT_ID and XDR_CLIENT_SECRET"):
        await client.list_incidents(limit=5)

    await client.aclose()
