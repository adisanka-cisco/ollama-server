from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from client import CiscoXDRClient, XDRClientError
from formatters import (
    summarize_context,
    summarize_detections,
    summarize_incident,
    summarize_incident_list,
    summarize_incident_summary,
    summarize_storyboard,
)
from models import (
    ToolEnvelope,
    compact,
    extract_collection,
    normalize_context,
    normalize_event,
    normalize_export,
    normalize_incident,
    normalize_report,
    normalize_storyboard,
)


XDR_CLIENT_ID = os.getenv("XDR_CLIENT_ID", "").strip()
XDR_CLIENT_SECRET = os.getenv("XDR_CLIENT_SECRET", "").strip()
XDR_TOKEN_URL = os.getenv("XDR_TOKEN_URL", "https://visibility.amp.cisco.com/iroh/oauth2/token").strip()
XDR_CONURE_BASE_URL = os.getenv("XDR_CONURE_BASE_URL", "https://conure.us.security.cisco.com").strip()
XDR_HTTP_TIMEOUT = float(os.getenv("XDR_HTTP_TIMEOUT", "30").strip())
XDR_VERIFY_TLS = os.getenv("XDR_VERIFY_TLS", "true").strip().lower() in {"1", "true", "yes", "on"}
XDR_TOKEN_REFRESH_SKEW_SECONDS = int(os.getenv("XDR_TOKEN_REFRESH_SKEW_SECONDS", "60").strip())
MCP_XDR_PORT = int(os.getenv("MCP_XDR_PORT", "8002").strip())
MCP_XDR_PATH = os.getenv("MCP_XDR_PATH", "/mcp/").strip() or "/mcp/"


client = CiscoXDRClient(
    client_id=XDR_CLIENT_ID,
    client_secret=XDR_CLIENT_SECRET,
    token_url=XDR_TOKEN_URL,
    conure_base_url=XDR_CONURE_BASE_URL,
    http_timeout=XDR_HTTP_TIMEOUT,
    verify_tls=XDR_VERIFY_TLS,
    refresh_skew_seconds=XDR_TOKEN_REFRESH_SKEW_SECONDS,
)


mcp = FastMCP(
    name="Cisco XDR Conure MCP",
    instructions=(
        "Read-only Cisco XDR incident and investigation tools. "
        "Prefer these tools for incident lookup, summary, detections, and context."
    ),
)


def _ensure_configured() -> None:
    if not XDR_CLIENT_ID or not XDR_CLIENT_SECRET:
        raise ToolError("Cisco XDR credentials are not configured. Set XDR_CLIENT_ID and XDR_CLIENT_SECRET.")


def _tool_error(exc: XDRClientError) -> ToolError:
    return ToolError(str(exc))


@mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def healthz(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


@mcp.tool
async def xdr_list_incidents(
    status: str | None = None,
    priority: str | None = None,
    assignee: str | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """List Cisco XDR incidents using Conure incident search and compact filtering."""
    _ensure_configured()
    try:
        raw_payload = await client.list_incidents(limit=max(limit * 4, limit))
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    incidents = [normalize_incident(item) for item in extract_collection(raw_payload, preferred_keys=["incidents", "items", "results"])]

    def matches(item: dict[str, Any]) -> bool:
        if status and str(item.get("status", "")).lower() != status.lower():
            return False
        if priority and str(item.get("priority", "")).lower() != priority.lower():
            return False
        if assignee and assignee.lower() not in str(item.get("assignee", "")).lower():
            return False
        return True

    filtered = [item for item in incidents if matches(item)]
    capped = filtered[: max(1, min(limit, 100))]
    truncated = len(filtered) > len(capped)
    notes = ["Results were filtered client-side after incident search."] if any([status, priority, assignee]) else []
    if truncated:
        notes.append("Additional matching incidents were omitted because of the requested limit.")

    envelope = ToolEnvelope(
        summary_text=summarize_incident_list(capped),
        data={
            "normalized": capped,
            "raw_data": raw_payload,
            "filters": compact({"status": status, "priority": priority, "assignee": assignee}),
        },
        truncated=truncated,
        returned_count=len(capped),
        total_available=len(filtered),
        truncation_notes=notes,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def xdr_get_incident(incident_id: str) -> dict[str, Any]:
    """Get the core Cisco XDR incident object with high-fidelity raw data."""
    _ensure_configured()
    try:
        raw_payload = await client.get_incident(incident_id)
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    incident_object = raw_payload if isinstance(raw_payload, dict) else {"value": raw_payload}
    normalized = normalize_incident(incident_object)
    envelope = ToolEnvelope(
        summary_text=summarize_incident(normalized),
        data={
            "incident_id": incident_id,
            "incident": normalized,
            "normalized": normalized,
            "raw_data": raw_payload,
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def xdr_get_incident_summary(incident_id: str) -> dict[str, Any]:
    """Get the full incident summary and report with high-fidelity Cisco sections preserved."""
    _ensure_configured()
    try:
        incident_payload = await client.get_incident(incident_id)
        export_payload = await client.get_incident_export(incident_id)
        report_payload = await client.get_incident_report(incident_id)
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    normalized_incident = normalize_incident(incident_payload if isinstance(incident_payload, dict) else {})
    normalized_export = normalize_export(export_payload if isinstance(export_payload, dict) else {})
    normalized_report = normalize_report(report_payload if isinstance(report_payload, dict) else {})

    envelope = ToolEnvelope(
        summary_text=summarize_incident_summary(
            normalized_incident,
            normalized_export,
            normalized_report,
        ),
        data={
            "incident_id": incident_id,
            "incident": normalized_incident,
            "export": normalized_export,
            "report": normalized_report,
            "normalized": {
                "incident": normalized_incident,
                "export": normalized_export,
                "report": normalized_report,
            },
            "raw_data": {
                "incident": incident_payload,
                "export": export_payload,
                "report": report_payload,
            },
        },
        returned_count=1,
        total_available=1,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def xdr_get_incident_detections(incident_id: str, limit: int = 100) -> dict[str, Any]:
    """Get linked Cisco XDR detections/events for an incident with rich event detail preserved."""
    _ensure_configured()
    try:
        raw_payload = await client.get_incident_events(incident_id, limit=limit)
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    event_items = extract_collection(raw_payload, preferred_keys=["events", "items", "results"])
    normalized_events = [normalize_event(event) for event in event_items]
    capped_events = normalized_events[: max(1, min(limit, 500))]
    truncated = len(normalized_events) > len(capped_events)
    notes = ["Additional linked events were omitted because of the requested limit."] if truncated else []

    envelope = ToolEnvelope(
        summary_text=summarize_detections(capped_events),
        data={
            "incident_id": incident_id,
            "detections": capped_events,
            "normalized": capped_events,
            "raw_data": {"events": event_items},
        },
        truncated=truncated,
        returned_count=len(capped_events),
        total_available=len(normalized_events),
        truncation_notes=notes,
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def xdr_get_incident_context(incident_id: str) -> dict[str, Any]:
    """Get linked Cisco XDR incident context including entities and observables."""
    _ensure_configured()
    try:
        entity_payload = await client.get_incident_entities(incident_id)
        observable_payload = await client.get_incident_observables(incident_id)
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    entities = extract_collection(entity_payload, preferred_keys=["entities", "items", "results"])
    observables = extract_collection(observable_payload, preferred_keys=["observables", "items", "results"])
    context = normalize_context(entities, observables)

    envelope = ToolEnvelope(
        summary_text=summarize_context(context),
        data={
            "incident_id": incident_id,
            "context": context,
            "normalized": context,
            "raw_data": {"entities": entity_payload, "observables": observable_payload},
        },
        returned_count=len(entities) + len(observables),
        total_available=len(entities) + len(observables),
    )
    return envelope.model_dump(mode="json")


@mcp.tool
async def xdr_get_incident_storyboard(incident_id: str) -> dict[str, Any]:
    """Get the Cisco XDR incident storyboard with high-fidelity chronology and context preserved."""
    _ensure_configured()
    try:
        storyboard_payload = await client.get_incident_storyboard(incident_id)
    except XDRClientError as exc:
        raise _tool_error(exc) from exc

    storyboard_object = storyboard_payload if isinstance(storyboard_payload, dict) else {"value": storyboard_payload}
    normalized = normalize_storyboard(storyboard_object)
    entry_count = 0
    counts = normalized.get("counts")
    if isinstance(counts, dict):
        entry_count = sum(
            int(value)
            for key, value in counts.items()
            if key in {"detection_analysis", "observables", "device_analysis", "user_analysis"} and isinstance(value, int)
        )

    envelope = ToolEnvelope(
        summary_text=summarize_storyboard(normalized),
        data={
            "incident_id": incident_id,
            "storyboard": normalized,
            "normalized": normalized,
            "raw_data": storyboard_payload,
        },
        returned_count=entry_count or 1,
        total_available=entry_count or 1,
    )
    return envelope.model_dump(mode="json")


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=MCP_XDR_PORT,
        path=MCP_XDR_PATH,
    )
