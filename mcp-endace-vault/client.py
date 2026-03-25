"""Async Endace Vault client for packet-capture request lifecycle operations."""

from __future__ import annotations

from typing import Any

import httpx


class EndaceVaultClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class EndaceVaultClient:
    def __init__(
        self,
        *,
        username: str,
        password: str,
        base_url: str,
        http_timeout: float = 30.0,
        verify_tls: bool = False,
        api_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.base_url = base_url.rstrip("/")
        self._api_client = api_client or httpx.AsyncClient(
            timeout=http_timeout,
            verify=verify_tls,
            auth=(username, password),
            headers={"Accept": "application/json"},
        )
        self._owns_api_client = api_client is None

    async def aclose(self) -> None:
        if self._owns_api_client:
            await self._api_client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        try:
            response = await self._api_client.request(method, url, params=params)
        except httpx.TimeoutException as exc:
            raise EndaceVaultClientError("Timed out while calling the Endace Vault API.") from exc
        except httpx.HTTPError as exc:
            raise EndaceVaultClientError("Could not reach the Endace Vault API.") from exc

        if response.status_code == 401:
            raise EndaceVaultClientError(
                "Endace Vault rejected the credentials. Check ENDACE_VAULT_USERNAME and ENDACE_VAULT_PASSWORD.",
                status_code=401,
            )
        if response.status_code == 403:
            raise EndaceVaultClientError(
                "Endace Vault rejected this request with 403. The account likely lacks the required Vault role.",
                status_code=403,
            )
        if response.status_code == 404:
            raise EndaceVaultClientError("The requested Endace Vault resource was not found.", status_code=404)
        if response.status_code == 503:
            raise EndaceVaultClientError(
                "Endace Vault is busy and returned 503. Try again shortly.",
                status_code=503,
            )
        if response.status_code >= 500:
            raise EndaceVaultClientError(
                f"Endace Vault returned a server error ({response.status_code}).",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise EndaceVaultClientError(
                f"Endace Vault request failed with status {response.status_code}.",
                status_code=response.status_code,
            )

        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            return response.json()
        return response.text

    async def list_requests(
        self,
        *,
        page: int = 1,
        search_string: str | None = None,
        type_filter: str | None = None,
        user_filter: str | None = None,
        sort_by: str | None = None,
        sort_direction: str | None = None,
    ) -> Any:
        params = {
            "page": max(page, 1),
            "searchString": search_string,
            "typeFilter": type_filter,
            "userFilter": user_filter,
            "sortBy": sort_by,
            "sortDirection": sort_direction,
        }
        return await self._request("GET", "/", params={k: v for k, v in params.items() if v not in (None, "")})

    async def create_request(
        self,
        *,
        request_type: str,
        request_format: str,
        params: dict[str, Any],
    ) -> Any:
        return await self._request(
            "POST",
            f"/{request_type}/{request_format}",
            params={k: v for k, v in params.items() if v not in (None, "")},
        )

    async def get_request(self, request_id: str) -> Any:
        return await self._request("GET", f"/{request_id}")

    async def delete_request(self, request_id: str) -> Any:
        return await self._request("DELETE", f"/{request_id}")
