from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx


class XDRClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CiscoXDRClient:
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        token_url: str,
        conure_base_url: str,
        http_timeout: float = 30.0,
        verify_tls: bool = True,
        refresh_skew_seconds: int = 60,
        api_client: httpx.AsyncClient | None = None,
        auth_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url.rstrip("/")
        self.conure_base_url = conure_base_url.rstrip("/")
        self.refresh_skew_seconds = refresh_skew_seconds
        self._timeout = http_timeout
        self._verify_tls = verify_tls

        self._api_client = api_client or httpx.AsyncClient(
            timeout=http_timeout,
            verify=verify_tls,
            headers={"Accept": "application/json"},
        )
        self._auth_client = auth_client or httpx.AsyncClient(
            timeout=http_timeout,
            verify=verify_tls,
            headers={"Accept": "application/json"},
        )
        self._owns_api_client = api_client is None
        self._owns_auth_client = auth_client is None

        self._access_token: str | None = None
        self._token_type: str = "Bearer"
        self._expires_at: float = 0.0
        self._token_lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_api_client:
            await self._api_client.aclose()
        if self._owns_auth_client:
            await self._auth_client.aclose()

    async def _fetch_access_token(self) -> str:
        try:
            response = await self._auth_client.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.TimeoutException as exc:
            raise XDRClientError("Timed out while requesting a Cisco XDR access token.") from exc
        except httpx.HTTPError as exc:
            raise XDRClientError("Could not reach the Cisco XDR token endpoint.") from exc

        if response.status_code in {401, 403}:
            raise XDRClientError(
                "Cisco XDR token request was rejected. Check XDR_CLIENT_ID and XDR_CLIENT_SECRET.",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise XDRClientError(
                f"Cisco XDR token request failed with status {response.status_code}.",
                status_code=response.status_code,
            )

        payload = response.json()
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise XDRClientError("Cisco XDR token response did not include an access token.")

        token_type = payload.get("token_type")
        if isinstance(token_type, str) and token_type:
            # Normalize auth scheme casing so downstream Authorization headers
            # are always accepted as "Bearer <token>".
            self._token_type = "Bearer"

        expires_in = payload.get("expires_in")
        try:
            expires_in_int = int(expires_in)
        except (TypeError, ValueError):
            expires_in_int = 300

        self._access_token = access_token
        self._expires_at = time.time() + max(expires_in_int, 60)
        return access_token

    async def _get_access_token(self, *, force_refresh: bool = False) -> str:
        if not force_refresh and self._access_token:
            if time.time() < self._expires_at - self.refresh_skew_seconds:
                return self._access_token

        async with self._token_lock:
            if not force_refresh and self._access_token:
                if time.time() < self._expires_at - self.refresh_skew_seconds:
                    return self._access_token
            return await self._fetch_access_token()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        retry_on_401: bool = True,
    ) -> Any:
        token = await self._get_access_token()
        url = f"{self.conure_base_url}{path}"

        try:
            response = await self._api_client.request(
                method,
                url,
                params=params,
                headers={"Authorization": f"{self._token_type} {token}"},
            )
        except httpx.TimeoutException as exc:
            raise XDRClientError("Timed out while calling the Cisco XDR Conure API.") from exc
        except httpx.HTTPError as exc:
            raise XDRClientError("Could not reach the Cisco XDR Conure API.") from exc

        if response.status_code == 401 and retry_on_401:
            await self._get_access_token(force_refresh=True)
            return await self._request(method, path, params=params, retry_on_401=False)

        if response.status_code == 401:
            raise XDRClientError(
                "Cisco XDR rejected the access token after retry. Check the client credentials.",
                status_code=401,
            )
        if response.status_code == 403:
            raise XDRClientError(
                "Cisco XDR rejected this request with 403. The OAuth client likely lacks the required scope.",
                status_code=403,
            )
        if response.status_code == 404:
            raise XDRClientError("The requested Cisco XDR incident resource was not found.", status_code=404)
        if response.status_code == 429:
            raise XDRClientError("Cisco XDR rate-limited the request. Try again shortly.", status_code=429)
        if response.status_code >= 500:
            raise XDRClientError(
                f"Cisco XDR returned a server error ({response.status_code}).",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise XDRClientError(
                f"Cisco XDR request failed with status {response.status_code}.",
                status_code=response.status_code,
            )

        content_type = response.headers.get("content-type", "")
        if "json" in content_type:
            return response.json()
        return response.text

    async def list_incidents(self, *, limit: int = 25) -> Any:
        capped_limit = max(1, min(limit, 100))
        return await self._request("GET", "/v2/incident/search", params={"limit": capped_limit})

    async def get_incident(self, incident_id: str) -> Any:
        return await self._request("GET", f"/v2/incident/{incident_id}")

    async def get_incident_export(self, incident_id: str) -> Any:
        return await self._request("GET", f"/v2/incident/{incident_id}/export")

    async def get_incident_report(self, incident_id: str) -> Any:
        return await self._request("GET", f"/v2/incident/{incident_id}/report")

    async def get_incident_events(self, incident_id: str, *, limit: int = 100) -> Any:
        capped_limit = max(1, min(limit, 500))
        return await self._request("GET", f"/v2/incident/{incident_id}/events", params={"limit": capped_limit})

    async def get_incident_entities(self, incident_id: str) -> Any:
        return await self._request("GET", f"/v2/incident/{incident_id}/entities")

    async def get_incident_observables(self, incident_id: str) -> Any:
        return await self._request("GET", f"/v2/incident/{incident_id}/observables")
