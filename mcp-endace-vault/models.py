"""Normalization helpers for Endace Vault request lifecycle payloads."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


PACKET_FILTER_FIELDS = (
    "ip",
    "sip",
    "dip",
    "ipp",
    "port",
    "sport",
    "dport",
    "app",
    "clientip",
    "serverip",
    "clientport",
    "serverport",
    "tools",
)


class ToolEnvelope(BaseModel):
    summary_text: str
    data: dict[str, Any]
    truncated: bool = False
    returned_count: int | None = None
    total_available: int | None = None
    truncation_notes: list[str] = Field(default_factory=list)


def _get_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def first_present(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _get_path(data, path)
        if value not in (None, "", [], {}):
            return value
    return None


def compact(value: Any) -> Any:
    if isinstance(value, dict):
        items = {key: compact(val) for key, val in value.items()}
        return {key: val for key, val in items.items() if val not in (None, "", [], {})}
    if isinstance(value, list):
        items = [compact(item) for item in value]
        return [item for item in items if item not in (None, "", [], {})]
    return value


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", {}, []):
        return []
    return [value]


def normalize_vault_request(vault_request: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "id": first_present(vault_request, "id"),
        "title": first_present(vault_request, "title"),
        "datasources": first_present(vault_request, "datasources"),
        "start": first_present(vault_request, "start"),
        "end": first_present(vault_request, "end"),
        "reltime": first_present(vault_request, "reltime"),
        "type": first_present(vault_request, "vaultRequestType"),
        "format": first_present(vault_request, "vaultRequestFormat"),
        "username": first_present(vault_request, "username"),
        "tools": first_present(vault_request, "tools"),
        "packet_filters": {
            key: first_present(vault_request, key)
            for key in PACKET_FILTER_FIELDS
            if first_present(vault_request, key) not in (None, "", [], {})
        }
        or None,
    }

    for key in PACKET_FILTER_FIELDS:
        normalized[key] = first_present(vault_request, key)
    return compact(normalized)


def normalize_vault_entry(entry: dict[str, Any]) -> dict[str, Any]:
    vault_request = entry.get("vaultRequest") if isinstance(entry.get("vaultRequest"), dict) else {}
    normalized_request = normalize_vault_request(vault_request)
    normalized = {
        "request_id": normalized_request.get("id"),
        "status": first_present(entry, "status"),
        "created": first_present(entry, "created"),
        "bytes": first_present(entry, "bytes"),
        "download_url": first_present(entry, "downloadUrl"),
        "view_url": first_present(entry, "viewUrl"),
        "vault_request": normalized_request,
        "type": normalized_request.get("type"),
        "format": normalized_request.get("format"),
        "title": normalized_request.get("title"),
        "datasources": normalized_request.get("datasources"),
        "start": normalized_request.get("start"),
        "end": normalized_request.get("end"),
        "reltime": normalized_request.get("reltime"),
    }
    return compact(normalized)


def extract_vault_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    entries = first_present(payload, "payload.vaultEntries")
    return [item for item in _as_list(entries) if isinstance(item, dict)]


def extract_filtered_count(payload: dict[str, Any]) -> int | None:
    count = first_present(payload, "payload.filteredVaultEntries")
    try:
        return int(count) if count is not None else None
    except (TypeError, ValueError):
        return None


def extract_request_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        inner = payload.get("payload")
        if isinstance(inner, dict):
            return inner
        return payload
    return {"value": payload}
