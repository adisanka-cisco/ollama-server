"""Normalization helpers for turning raw Conure responses into tool-friendly shapes.

The goal here is not to heavily summarize Cisco data. Instead, these helpers
preserve the high-value incident fields while removing repetitive wrappers and
normalizing common variants in Conure payloads.
"""

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
    # Conure payloads vary a bit across endpoints, so the MCP layer looks for a
    # field in several likely locations before giving up.
    for path in paths:
        value = _get_path(data, path)
        if value not in (None, "", [], {}):
            return value
    return None


def compact(value: Any) -> Any:
    # Compact nested payloads after normalization so the model gets signal-heavy
    # JSON without null-heavy wrappers.
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


def _stringify(value: Any) -> str | None:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _collect_scalar_values(*values: Any) -> list[str]:
    items: list[str] = []
    for value in values:
        for item in _as_list(value):
            stringified = _stringify(item)
            if stringified:
                items.append(stringified)
    return sorted(set(items))


def _normalize_observable_item(item: dict[str, Any]) -> dict[str, Any]:
    return compact(
        {
            "type": first_present(item, "type", "observableType"),
            "value": first_present(item, "value", "title", "name"),
            "title": first_present(item, "title", "name"),
            "disposition": first_present(item, "disposition"),
            "is_asset": first_present(item, "is_asset"),
        }
    )


def _normalize_target_item(item: dict[str, Any]) -> dict[str, Any]:
    observables = [
        _normalize_observable_item(observable)
        for observable in _as_list(first_present(item, "observables"))
        if isinstance(observable, dict)
    ]
    return compact(
        {
            "type": first_present(item, "type", "observableType"),
            "value": first_present(item, "value", "asset_value", "title", "name"),
            "is_asset": first_present(item, "is_asset"),
            "observables": observables,
        }
    )


def _normalize_relation_item(item: dict[str, Any]) -> dict[str, Any]:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    related = item.get("related") if isinstance(item.get("related"), dict) else {}
    relation_info = item.get("relation_info") if isinstance(item.get("relation_info"), dict) else {}
    actions = []
    for action in _as_list(relation_info.get("actions")):
        if isinstance(action, dict):
            actions.append(
                compact(
                    {
                        "type": first_present(action, "type"),
                        "status": first_present(action, "status"),
                        "source": first_present(action, "source"),
                        "started_at": first_present(action, "started_at"),
                    }
                )
            )

    return compact(
        {
            "relation": first_present(item, "relation"),
            "origin": first_present(item, "origin"),
            "source": _normalize_target_item(source),
            "related": _normalize_target_item(related),
            "actions": actions,
        }
    )


def _extract_application(description: Any) -> str | None:
    if not isinstance(description, str):
        return None
    marker = "**Application** :"
    if marker not in description:
        return None
    after = description.split(marker, 1)[1].strip()
    line = after.splitlines()[0].strip()
    return line or None


def _extract_action(description: Any) -> str | None:
    if not isinstance(description, str):
        return None
    marker = "Action:"
    if marker not in description:
        return None
    after = description.split(marker, 1)[1].strip()
    return after.splitlines()[0].strip(" .") or None


def _normalize_mitre_items(value: Any) -> list[dict[str, Any]] | None:
    items = []
    for item in _as_list(value):
        if isinstance(item, dict):
            items.append(
                compact(
                    {
                        "id": first_present(item, "id"),
                        "title": first_present(item, "title", "name"),
                        "mitre_type": first_present(item, "mitre_type", "type"),
                        "score": first_present(item, "score"),
                    }
                )
            )
    return items or None


def extract_collection(payload: Any, preferred_keys: list[str] | None = None) -> list[dict[str, Any]]:
    # Different Conure endpoints wrap collections differently. This helper lets
    # each tool ask for the likely keys while still falling back safely.
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
    # Detection events can arrive with rich nested targets/relations. Normalize
    # them once so the LLM sees a stable schema across vendors and modules.
    description = first_present(event, "description", "summary", "reason", "short_description")
    mitre = first_present(
        event,
        "mitre_attack",
        "mitre",
        "attack",
        "tactics_techniques",
        "tactics_and_techniques",
        "mitre_data",
    )
    observables = [
        _normalize_observable_item(observable)
        for observable in _as_list(first_present(event, "observables"))
        if isinstance(observable, dict)
    ]
    targets = [
        _normalize_target_item(target)
        for target in _as_list(first_present(event, "targets"))
        if isinstance(target, dict)
    ]
    indicators = [
        compact(
            {
                "id": first_present(indicator, "id"),
                "title": first_present(indicator, "title", "name"),
                "value": first_present(indicator, "value"),
                "description": first_present(indicator, "description", "short_description"),
            }
        )
        for indicator in _as_list(first_present(event, "indicators"))
        if isinstance(indicator, dict)
    ]
    relations = [
        _normalize_relation_item(relation)
        for relation in _as_list(first_present(event, "relations"))
        if isinstance(relation, dict)
    ]
    normalized = {
        "id": first_present(event, "id", "event_id"),
        "timestamp": first_present(
            event,
            "timestamp",
            "detection_interval.start_time",
            "observed_time.start_time",
            "activity_interval.start_time",
            "created_at",
            "time",
        ),
        "title": first_present(event, "title", "name", "event_type"),
        "description": description,
        "short_description": first_present(event, "short_description"),
        "severity": first_present(event, "severity", "risk.severity"),
        "confidence": first_present(event, "confidence", "risk.confidence"),
        "source_product": first_present(
            event,
            "source",
            "source_product",
            "module_data.module",
            "module",
            "module_name",
            "device_type",
        ),
        "module": first_present(event, "module", "module_data.module"),
        "sensor": first_present(event, "sensor"),
        "type": first_present(event, "type"),
        "count": first_present(event, "count"),
        "severity_label": first_present(event, "severity_label"),
        "confidence_label": first_present(event, "confidence_label"),
        "tlp": first_present(event, "tlp"),
        "notable": first_present(event, "notable"),
        "application": _extract_application(description),
        "action": _extract_action(description)
        or first_present(event, "action", "disposition"),
        "user": _event_actor(event, "user") or _event_actor(event, "target_user"),
        "host": _event_actor(event, "host")
        or _event_actor(event, "device")
        or _event_actor(event, "target_host")
        or _collect_scalar_values([target.get("value") for target in targets if target.get("type") == "endpoint"]),
        "indicator_titles": _collect_scalar_values([indicator.get("title") for indicator in indicators]),
        "indicator_values": _collect_scalar_values([indicator.get("value") for indicator in indicators]),
        "targets": targets,
        "observables": observables,
        "relations": relations,
        "mitre_attack": _normalize_mitre_items(mitre),
        "raw_refs": compact(
            {
                "observable": first_present(event, "observable"),
                "sensor": first_present(event, "sensor"),
                "external_ids": first_present(event, "external_ids"),
                "source_refs": first_present(event, "external_references"),
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


def _normalize_storyboard_confidence_factors(value: Any) -> list[dict[str, Any]] | None:
    items = []
    for item in _as_list(value):
        if isinstance(item, dict):
            items.append(
                compact(
                    {
                        "label": first_present(item, "label", "title", "name"),
                        "description": first_present(item, "description", "reason", "summary"),
                        "score": first_present(item, "score", "confidence"),
                    }
                )
            )
        else:
            stringified = _stringify(item)
            if stringified:
                items.append({"label": stringified})
    return items or None


def _normalize_storyboard_observable(item: dict[str, Any]) -> dict[str, Any]:
    reputations = []
    for reputation in _as_list(first_present(item, "reputations")):
        if isinstance(reputation, dict):
            reputations.append(
                compact(
                    {
                        "source": first_present(reputation, "source", "name"),
                        "disposition": first_present(reputation, "disposition", "verdict"),
                        "score": first_present(reputation, "score"),
                    }
                )
            )

    return compact(
        {
            "uid": first_present(item, "uid", "id"),
            "type": first_present(item, "entity_type", "type", "observable_type"),
            "value": first_present(item, "value", "ip", "domain", "url", "hostname", "user"),
            "title": first_present(item, "title", "name"),
            "first_observed": first_present(item, "first_observed", "first_seen"),
            "last_observed": first_present(item, "last_observed", "last_seen"),
            "asn": first_present(item, "asn"),
            "country": first_present(item, "country"),
            "reputations": reputations or None,
        }
    )


def _normalize_storyboard_analysis_item(item: dict[str, Any]) -> dict[str, Any]:
    entity_investigations = []
    for entity in _as_list(first_present(item, "entity_investigations")):
        if isinstance(entity, dict):
            entity_investigations.append(
                compact(
                    {
                        "uid": first_present(entity, "uid", "id"),
                        "entity_type": first_present(entity, "entity_type", "type"),
                        "value": first_present(entity, "value", "name", "title", "ip", "url", "hostname", "user"),
                        "title": first_present(entity, "title", "name"),
                    }
                )
            )

    detection_title_by_uid = first_present(item, "detection_title_by_uid")
    titles = []
    if isinstance(detection_title_by_uid, dict):
        for uid, title in detection_title_by_uid.items():
            title_string = _stringify(title)
            if title_string:
                titles.append(compact({"uid": uid, "title": title_string}))

    return compact(
        {
            "uid": first_present(item, "uid", "id"),
            "time": first_present(item, "time", "timestamp"),
            "title": first_present(item, "detection_title", "title", "name"),
            "description": first_present(item, "detection_desc", "description", "summary"),
            "confidence_factors": _normalize_storyboard_confidence_factors(
                first_present(item, "confidence_factors")
            ),
            "detection_titles_by_uid": titles or None,
            "aggregated_detection_uids": _as_list(first_present(item, "aggregated_detection_uids")) or None,
            "entity_investigations": entity_investigations or None,
        }
    )


def _normalize_storyboard_analysis_section(value: Any) -> list[dict[str, Any]] | None:
    items = []
    for item in _as_list(value):
        if isinstance(item, dict):
            items.append(
                compact(
                    {
                        "uid": first_present(item, "uid", "id"),
                        "type": first_present(item, "entity_type", "type"),
                        "value": first_present(item, "value", "name", "title", "ip", "url", "hostname", "user"),
                        "title": first_present(item, "title", "name"),
                        "description": first_present(item, "description", "summary"),
                        "confidence_factors": _normalize_storyboard_confidence_factors(
                            first_present(item, "confidence_factors")
                        ),
                    }
                )
            )
    return items or None


def normalize_storyboard(storyboard: dict[str, Any]) -> dict[str, Any]:
    # Storyboard is already one of the most assembled XDR views, so this helper
    # keeps most of the original structure and only normalizes the nested
    # sections the model is most likely to reason over directly.
    observables = [
        _normalize_storyboard_observable(item)
        for item in _as_list(first_present(storyboard, "observables"))
        if isinstance(item, dict)
    ]
    detection_analysis = [
        _normalize_storyboard_analysis_item(item)
        for item in _as_list(first_present(storyboard, "detection_analysis"))
        if isinstance(item, dict)
    ]
    summary_structured = storyboard.get("summary_structured") if isinstance(storyboard.get("summary_structured"), dict) else {}
    classification = storyboard.get("classification") if isinstance(storyboard.get("classification"), dict) else {}

    normalized = {
        "title": first_present(storyboard, "title"),
        "headline": first_present(storyboard, "headline"),
        "summary": first_present(storyboard, "summary"),
        "time": first_present(storyboard, "time"),
        "product_names": _as_list(first_present(storyboard, "product_names")) or None,
        "classification": compact(
            {
                "classification": first_present(classification, "classification"),
                "confidence": first_present(classification, "confidence"),
                "confidence_factors": _normalize_storyboard_confidence_factors(
                    first_present(classification, "confidence_factors")
                ),
            }
        ),
        "summary_structured": compact(
            {
                "statement": first_present(summary_structured, "statement"),
                "evidence": first_present(summary_structured, "evidence"),
                "reasoning": first_present(summary_structured, "reasoning"),
                "detection_investigation_uids": _as_list(
                    first_present(summary_structured, "detection_investigation_uids")
                )
                or None,
            }
        ),
        "observables": observables or None,
        "detection_analysis": detection_analysis or None,
        "device_analysis": _normalize_storyboard_analysis_section(first_present(storyboard, "device_analysis")),
        "user_analysis": _normalize_storyboard_analysis_section(first_present(storyboard, "user_analysis")),
        "counts": compact(
            {
                "observables": len(observables) or None,
                "detection_analysis": len(detection_analysis) or None,
                "device_analysis": len(_as_list(first_present(storyboard, "device_analysis"))) or None,
                "user_analysis": len(_as_list(first_present(storyboard, "user_analysis"))) or None,
                "products": len(_as_list(first_present(storyboard, "product_names"))) or None,
            }
        ),
    }
    return compact(normalized)


def normalize_context(
    entities: list[dict[str, Any]],
    observables: list[dict[str, Any]],
) -> dict[str, Any]:
    # Context is grouped by the entity/observable types users usually ask about
    # directly: hosts, users, IPs, domains, hashes, and URLs.
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
