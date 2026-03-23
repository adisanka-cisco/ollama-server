from __future__ import annotations

from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field


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


def extract_collection(payload: Any, preferred_keys: list[str] | None = None) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    keys = preferred_keys or []
    candidate_keys = keys + [
        "items",
        "data",
        "results",
        "incidents",
        "events",
        "entities",
        "observables",
    ]

    for key in candidate_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = extract_collection(value)
            if nested:
                return nested

    return []


def normalize_incident(incident: dict[str, Any]) -> dict[str, Any]:
    assignee = first_present(
        incident,
        "assignee.name",
        "owner",
        "owner.name",
        "assigned_to",
        "assigned_to.name",
        "incident_owner",
        "assignee",
    )

    normalized = {
        "id": first_present(incident, "id", "incident_id", "incident-id"),
        "short_id": first_present(incident, "short_id", "short-id"),
        "title": first_present(incident, "title", "name", "incident.title"),
        "description": first_present(incident, "description", "summary", "incident.description"),
        "status": first_present(incident, "status", "state", "incident.status"),
        "priority": first_present(incident, "priority", "incident.priority"),
        "severity": first_present(incident, "severity", "risk.severity", "incident.severity"),
        "confidence": first_present(incident, "confidence", "risk.confidence", "incident.confidence"),
        "verdict": first_present(incident, "verdict", "disposition", "incident.verdict"),
        "assignee": assignee,
        "opened_at": first_present(
            incident,
            "opened_at",
            "created_at",
            "created",
            "timestamp",
            "incident_time.start_time",
        ),
        "updated_at": first_present(
            incident,
            "updated_at",
            "modified_at",
            "updated",
            "last_updated",
        ),
        "closed_at": first_present(incident, "closed_at", "resolved_at", "closed"),
        "source": first_present(incident, "source", "source_product", "source_module"),
        "schema_version": first_present(incident, "schema_version", "revision"),
        "labels": first_present(incident, "labels", "tags"),
        "tlp": first_present(incident, "tlp", "classification.tlp"),
        "confidence_label": first_present(incident, "confidence_label"),
        "severity_label": first_present(incident, "severity_label"),
    }
    return compact(normalized)


def _event_actor(event: dict[str, Any], role: str) -> list[str]:
    values: list[str] = []
    for path in (
        f"{role}",
        f"{role}.name",
        f"{role}.hostname",
        f"{role}.user",
        f"{role}.username",
        f"{role}.email",
    ):
        value = first_present(event, path)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value if item)
    return sorted(set(values))


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    mitre = first_present(
        event,
        "mitre_attack",
        "mitre",
        "attack",
        "attack_details",
        "tactics_techniques",
    )
    normalized = {
        "id": first_present(event, "id", "event_id"),
        "timestamp": first_present(event, "timestamp", "created_at", "observed_time", "time"),
        "title": first_present(event, "title", "name", "event_type"),
        "description": first_present(event, "description", "summary", "reason"),
        "severity": first_present(event, "severity", "risk.severity"),
        "confidence": first_present(event, "confidence", "risk.confidence"),
        "source_product": first_present(
            event,
            "source",
            "source_product",
            "module",
            "module_name",
            "device_type",
        ),
        "user": _event_actor(event, "user") or _event_actor(event, "target_user"),
        "host": _event_actor(event, "host")
        or _event_actor(event, "device")
        or _event_actor(event, "target_host"),
        "mitre_attack": mitre,
        "raw_refs": compact(
            {
                "observable": first_present(event, "observable"),
                "targets": first_present(event, "targets"),
                "sensor": first_present(event, "sensor"),
            }
        ),
    }
    return compact(normalized)


def normalize_report(report: dict[str, Any]) -> dict[str, Any]:
    sections = extract_collection(report, preferred_keys=["sections", "report"])
    timeline = first_present(report, "timeline", "incident.timeline")
    normalized = {
        "title": first_present(report, "title", "incident.title"),
        "executive_summary": first_present(report, "executive", "executive_summary"),
        "timeline": timeline,
        "sections": sections or None,
    }
    return compact(normalized)


def normalize_export(export_data: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "incident": first_present(export_data, "incident"),
        "timeline": first_present(export_data, "timeline"),
        "events": extract_collection(export_data, preferred_keys=["events"]),
        "entities": extract_collection(export_data, preferred_keys=["entities"]),
        "observables": extract_collection(export_data, preferred_keys=["observables"]),
    }
    return compact(normalized)


def normalize_context(
    entities: list[dict[str, Any]],
    observables: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped_entities: dict[str, list[dict[str, Any]]] = defaultdict(list)
    grouped_observables: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for entity in entities:
        entity_type = str(first_present(entity, "type", "schema_type", "entity_type") or "other").lower()
        grouped_entities[entity_type].append(
            compact(
                {
                    "id": first_present(entity, "id"),
                    "name": first_present(entity, "name", "title"),
                    "description": first_present(entity, "description"),
                    "value": first_present(entity, "value"),
                    "raw_type": entity_type,
                }
            )
        )

    for observable in observables:
        observable_type = str(first_present(observable, "type", "observable_type") or "other").lower()
        grouped_observables[observable_type].append(
            compact(
                {
                    "id": first_present(observable, "id"),
                    "value": first_present(observable, "value", "observable"),
                    "description": first_present(observable, "description"),
                    "raw_type": observable_type,
                }
            )
        )

    return compact(
        {
            "hosts": grouped_entities.get("host", []) + grouped_entities.get("asset", []),
            "users": grouped_entities.get("user", []) + grouped_entities.get("identity", []),
            "ips": grouped_observables.get("ip", []) + grouped_observables.get("ip_address", []),
            "domains": grouped_observables.get("domain", []),
            "hashes": grouped_observables.get("sha256", [])
            + grouped_observables.get("sha1", [])
            + grouped_observables.get("md5", []),
            "urls": grouped_observables.get("url", []),
            "entities_by_type": dict(grouped_entities),
            "observables_by_type": dict(grouped_observables),
        }
    )
