from __future__ import annotations

from typing import Any


def _clip(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def summarize_incident_list(incidents: list[dict[str, Any]]) -> str:
    if not incidents:
        return "No incidents matched the current filters."

    lines = ["Incident search results:"]
    for incident in incidents:
        line = " - ".join(
            str(part)
            for part in (
                incident.get("id"),
                incident.get("title"),
                incident.get("status"),
                incident.get("severity"),
            )
            if part
        )
        lines.append(line)
    return "\n".join(lines[:21])


def summarize_incident(incident: dict[str, Any]) -> str:
    parts = []
    if incident.get("title"):
        parts.append(str(incident["title"]))
    metadata = [
        incident.get("status"),
        incident.get("severity"),
        incident.get("priority"),
        incident.get("assignee"),
    ]
    meta = ", ".join(str(item) for item in metadata if item)
    if meta:
        parts.append(f"Status and ownership: {meta}.")
    if incident.get("description"):
        parts.append(_clip(str(incident["description"]), limit=420))
    return "\n".join(parts) if parts else "Incident details retrieved."


def summarize_incident_summary(
    incident: dict[str, Any],
    export_data: dict[str, Any],
    report_data: dict[str, Any],
) -> str:
    lines = []
    title = incident.get("title") or report_data.get("title")
    if title:
        lines.append(str(title))

    executive = report_data.get("executive_summary")
    if isinstance(executive, str) and executive.strip():
        lines.append(_clip(executive, limit=700))

    timeline = report_data.get("timeline") or export_data.get("timeline")
    if isinstance(timeline, list):
        lines.append(f"Timeline entries available: {len(timeline)}")

    events = export_data.get("events")
    if isinstance(events, list):
        lines.append(f"Linked events available: {len(events)}")

    entities = export_data.get("entities")
    if isinstance(entities, list):
        lines.append(f"Linked entities available: {len(entities)}")

    return "\n".join(lines) if lines else "Incident summary retrieved."


def summarize_detections(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No detections or linked events were returned for this incident."

    lines = [f"Returned {len(events)} linked detections/events."]
    for event in events[:10]:
        line = " - ".join(
            str(part)
            for part in (
                event.get("timestamp"),
                event.get("title"),
                event.get("severity"),
                event.get("source_product"),
            )
            if part
        )
        lines.append(line)
    return "\n".join(lines)


def summarize_context(context: dict[str, Any]) -> str:
    counts = {
        "hosts": len(context.get("hosts", [])),
        "users": len(context.get("users", [])),
        "IPs": len(context.get("ips", [])),
        "domains": len(context.get("domains", [])),
        "hashes": len(context.get("hashes", [])),
        "URLs": len(context.get("urls", [])),
    }
    present = [f"{label}: {count}" for label, count in counts.items() if count]
    if not present:
        return "No linked incident context was returned."
    return "Incident context counts: " + ", ".join(present)
