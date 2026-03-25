"""Small summaries for Endace Vault lifecycle tools."""

from __future__ import annotations

from typing import Any


def _clip(text: str, limit: int = 240) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def summarize_vault_request_list(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "No Endace Vault requests matched the current filters."

    lines = ["Vault request search results:"]
    for entry in entries[:20]:
        line = " | ".join(
            str(part)
            for part in (
                entry.get("request_id"),
                entry.get("title"),
                entry.get("type"),
                entry.get("format"),
                entry.get("status"),
            )
            if part not in (None, "")
        )
        if line:
            lines.append(line)
    return "\n".join(lines)


def summarize_vault_request(entry: dict[str, Any]) -> str:
    if not entry:
        return "No Endace Vault request details were returned."

    parts = []
    if entry.get("title"):
        parts.append(str(entry["title"]))
    meta = [
        entry.get("request_id"),
        entry.get("type"),
        entry.get("format"),
        entry.get("status"),
    ]
    meta_line = ", ".join(str(item) for item in meta if item)
    if meta_line:
        parts.append(f"Request metadata: {meta_line}.")
    if entry.get("datasources"):
        parts.append(f"Datasources: {entry['datasources']}.")
    if entry.get("reltime"):
        parts.append(f"Relative time: {entry['reltime']}.")
    elif entry.get("start") and entry.get("end"):
        parts.append(f"Time window: {entry['start']} -> {entry['end']}.")
    return "\n".join(parts) if parts else "Endace Vault request details retrieved."


def summarize_download(entry: dict[str, Any]) -> str:
    if not entry:
        return "No Endace Vault request details were returned."

    status = str(entry.get("status", "unknown"))
    if status.lower() != "done" or not entry.get("download_url"):
        return (
            f"Vault request {entry.get('request_id', 'unknown')} is not ready for download yet. "
            f"Current status: {status}."
        )

    lines = [
        (
            f"Vault request {entry.get('request_id')} is ready for PCAP download. "
            "Use data.download_url as the authoritative download location."
        )
    ]
    if entry.get("title"):
        lines.append(str(entry["title"]))
    if entry.get("bytes") is not None:
        lines.append(f"Bytes: {entry['bytes']}")
    if entry.get("view_url"):
        lines.append(f"View URL: {_clip(str(entry['view_url']), limit=500)}")
    return "\n".join(lines)
