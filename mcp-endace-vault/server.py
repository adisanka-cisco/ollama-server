"""FastMCP server for Endace Vault packet-capture request workflows."""

from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from client import EndaceVaultClient, EndaceVaultClientError
from formatters import summarize_download, summarize_vault_request, summarize_vault_request_list
from models import (
    ToolEnvelope,
    compact,
    extract_filtered_count,
    extract_request_payload,
    extract_vault_entries,
    normalize_vault_entry,
)


ENDACE_VAULT_BASE_URL = os.getenv("ENDACE_VAULT_BASE_URL", "https://172.16.0.71/api/v5/vault").strip().rstrip("/")
ENDACE_VAULT_USERNAME = os.getenv("ENDACE_VAULT_USERNAME", "").strip()
ENDACE_VAULT_PASSWORD = os.getenv("ENDACE_VAULT_PASSWORD", "").strip()
ENDACE_VAULT_TIMEOUT = float(os.getenv("ENDACE_VAULT_TIMEOUT", "30").strip())
ENDACE_VAULT_VERIFY_TLS = os.getenv("ENDACE_VAULT_VERIFY_TLS", "false").strip().lower() in {"1", "true", "yes", "on"}
MCP_ENDACE_VAULT_PORT = int(os.getenv("MCP_ENDACE_VAULT_PORT", "8003").strip())
MCP_ENDACE_VAULT_PATH = os.getenv("MCP_ENDACE_VAULT_PATH", "/mcp/").strip() or "/mcp/"


client = EndaceVaultClient(
    username=ENDACE_VAULT_USERNAME,
    password=ENDACE_VAULT_PASSWORD,
    base_url=ENDACE_VAULT_BASE_URL,
    http_timeout=ENDACE_VAULT_TIMEOUT,
    verify_tls=ENDACE_VAULT_VERIFY_TLS,
)


mcp = FastMCP(
    name="Endace Vault MCP",
    instructions=(
        "Packet-capture lifecycle tools for Endace Vault. "
        "Use these tools whenever a prompt asks to create a packet capture, "
        "list Vault requests, check Vault request status, retrieve a PCAP download URL, "
        "or cancel/delete a Vault request. "
        "Do not claim that binary PCAP content was retrieved inline. "
        "Prefer the returned request metadata and download URL over model memory."
    ),
)


def _ensure_configured() -> None:
    if not ENDACE_VAULT_USERNAME or not ENDACE_VAULT_PASSWORD:
        raise ToolError(
            "Endace Vault credentials are not configured. Set ENDACE_VAULT_USERNAME and ENDACE_VAULT_PASSWORD."
        )


def _tool_error(exc: EndaceVaultClientError) -> ToolError:
    return ToolError(str(exc))


def _normalize_request_response(raw_payload: Any) -> dict[str, Any]:
    payload = extract_request_payload(raw_payload)
    return normalize_vault_entry(payload)


def _validate_pcap_time_args(*, start: int | None, end: int | None, reltime: str | None) -> None:
    if reltime and (start is not None or end is not None):
        raise ToolError("Provide either reltime or start/end, not both.")
    if reltime:
        return
    if start is None or end is None:
        raise ToolError("Provide both start and end, or provide reltime.")


@mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def healthz(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


@mcp.tool
async def endace_list_vault_requests(
    page: int = 1,
    search_string: str | None = None,
    type_filter: str | None = None,
    user_filter: str | None = None,
    sort_by: str | None = None,
    sort_direction: str | None = None,
) -> dict[str, Any]:
    """List Endace Vault requests when the user needs to find an existing capture request first.

    Use this tool when the prompt asks to search Vault history, list packet capture
    requests, or locate the right Vault request before checking status or download info.
    Prefer this tool before the other Endace tools when the user does not yet know the
    exact request ID.
    """
    _ensure_configured()
    try:
        raw_payload = await client.list_requests(
            page=page,
            search_string=search_string,
            type_filter=type_filter,
            user_filter=user_filter,
            sort_by=sort_by,
            sort_direction=sort_direction,
            tool_name="endace_list_vault_requests",
        )
    except EndaceVaultClientError as exc:
        raise _tool_error(exc) from exc

    entries = [normalize_vault_entry(item) for item in extract_vault_entries(raw_payload)]
    total_available = extract_filtered_count(raw_payload) or len(entries)
    envelope = ToolEnvelope(
        summary_text=summarize_vault_request_list(entries),
        data={
            "requests": entries,
            "normalized": entries,
            "raw_data": raw_payload,
            "filters": compact(
                {
                    "page": max(page, 1),
                    "search_string": search_string,
                    "type_filter": type_filter,
                    "user_filter": user_filter,
                    "sort_by": sort_by,
                    "sort_direction": sort_direction,
                }
            ),
        },
        returned_count=len(entries),
        total_available=total_available,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def endace_create_pcap_request(
    datasources: str,
    title: str,
    start: int | None = None,
    end: int | None = None,
    reltime: str | None = None,
    ip: str | None = None,
    sip: str | None = None,
    dip: str | None = None,
    ipp: str | None = None,
    port: str | None = None,
    sport: str | None = None,
    dport: str | None = None,
    app: str | None = None,
) -> dict[str, Any]:
    """Create a new packets/pcap Endace Vault request for incident analysis.

    Use this tool when the user asks to create a packet capture for a time range,
    a relative time window, or common packet filters such as IP, protocol, or port.
    Do not claim that the PCAP was downloaded inline. This tool creates the request
    and returns the request metadata so follow-up tools can poll or retrieve the
    download URL.
    """
    _ensure_configured()
    _validate_pcap_time_args(start=start, end=end, reltime=reltime)

    params = compact(
        {
            "datasources": datasources,
            "title": title,
            "start": start,
            "end": end,
            "reltime": reltime,
            "ip": ip,
            "sip": sip,
            "dip": dip,
            "ipp": ipp,
            "port": port,
            "sport": sport,
            "dport": dport,
            "app": app,
        }
    )

    try:
        raw_payload = await client.create_request(
            request_type="packets",
            request_format="pcap",
            params=params,
            tool_name="endace_create_pcap_request",
        )
    except EndaceVaultClientError as exc:
        raise _tool_error(exc) from exc

    normalized = _normalize_request_response(raw_payload)
    envelope = ToolEnvelope(
        summary_text=summarize_vault_request(normalized),
        data={
            "request_id": normalized.get("request_id"),
            "status": normalized.get("status"),
            "download_url": normalized.get("download_url"),
            "view_url": normalized.get("view_url"),
            "bytes": normalized.get("bytes"),
            "created": normalized.get("created"),
            "vault_request": normalized.get("vault_request"),
            "normalized": normalized,
            "raw_data": raw_payload,
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def endace_get_vault_request(request_id: str) -> dict[str, Any]:
    """Get the current status and metadata for a known Endace Vault request ID.

    Use this tool when the prompt asks for progress, status, metadata, or current
    state of an existing Vault request. Prefer this tool over the download tool
    when the user wants to know whether a request is still pending or complete.
    """
    _ensure_configured()
    try:
        raw_payload = await client.get_request(request_id, tool_name="endace_get_vault_request")
    except EndaceVaultClientError as exc:
        raise _tool_error(exc) from exc

    normalized = _normalize_request_response(raw_payload)
    envelope = ToolEnvelope(
        summary_text=summarize_vault_request(normalized),
        data={
            "request_id": normalized.get("request_id"),
            "status": normalized.get("status"),
            "download_url": normalized.get("download_url"),
            "view_url": normalized.get("view_url"),
            "bytes": normalized.get("bytes"),
            "created": normalized.get("created"),
            "vault_request": normalized.get("vault_request"),
            "normalized": normalized,
            "raw_data": raw_payload,
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def endace_get_pcap_download(request_id: str) -> dict[str, Any]:
    """Get PCAP download metadata and URL for a completed Endace Vault request.

    Use this tool when the user asks for the PCAP download URL or wants to know
    whether a packet-capture request is ready to download. Do not claim that the
    binary capture was retrieved inline. Use the returned download_url as the
    authoritative download location when the status is Done.
    """
    _ensure_configured()
    try:
        raw_payload = await client.get_request(request_id, tool_name="endace_get_pcap_download")
    except EndaceVaultClientError as exc:
        raise _tool_error(exc) from exc

    normalized = _normalize_request_response(raw_payload)
    request_type = str(normalized.get("type", "")).lower()
    request_format = str(normalized.get("format", "")).lower()
    if request_type and request_type != "packets":
        raise ToolError(f"Vault request {request_id} is type '{request_type}', not a packets request.")
    if request_format and request_format != "pcap":
        raise ToolError(f"Vault request {request_id} is format '{request_format}', not pcap.")

    envelope = ToolEnvelope(
        summary_text=summarize_download(normalized),
        data={
            "request_id": normalized.get("request_id"),
            "status": normalized.get("status"),
            "download_url": normalized.get("download_url"),
            "view_url": normalized.get("view_url"),
            "bytes": normalized.get("bytes"),
            "created": normalized.get("created"),
            "vault_request": normalized.get("vault_request"),
            "normalized": normalized,
            "raw_data": raw_payload,
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def endace_delete_vault_request(request_id: str) -> dict[str, Any]:
    """Cancel or delete an Endace Vault request by request ID.

    Use this tool when the user explicitly asks to cancel, remove, or delete a
    Vault request. Prefer this tool only for destructive lifecycle actions, not
    for status checks or download retrieval.
    """
    _ensure_configured()
    try:
        raw_payload = await client.delete_request(request_id, tool_name="endace_delete_vault_request")
    except EndaceVaultClientError as exc:
        raise _tool_error(exc) from exc

    normalized = _normalize_request_response(raw_payload)
    envelope = ToolEnvelope(
        summary_text=f"Endace Vault request {request_id} was deleted or cancelled.",
        data={
            "request_id": request_id,
            "normalized": normalized,
            "raw_data": raw_payload,
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=MCP_ENDACE_VAULT_PORT,
        path=MCP_ENDACE_VAULT_PATH,
    )
