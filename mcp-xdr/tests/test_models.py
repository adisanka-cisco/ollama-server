"""Regression tests for the normalization layer that shapes Cisco payloads."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, file_name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / file_name)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


models = _load_module("mcp_xdr_models", "models.py")


def test_normalize_incident_preserves_key_metadata() -> None:
    # Incident normalization should keep the user-facing metadata that drives
    # summaries and follow-up lookups.
    incident = {
        "id": "INC-001",
        "title": "Suspicious PowerShell Activity",
        "status": "open",
        "priority": "high",
        "severity": "critical",
        "confidence": "high",
        "assignee": {"name": "SOC Analyst"},
        "created_at": "2026-03-23T12:00:00Z",
        "updated_at": "2026-03-23T12:30:00Z",
    }

    normalized = models.normalize_incident(incident)

    assert normalized["id"] == "INC-001"
    assert normalized["title"] == "Suspicious PowerShell Activity"
    assert normalized["assignee"] == "SOC Analyst"
    assert normalized["severity"] == "critical"


def test_normalize_context_groups_entities_and_observables() -> None:
    # Context is grouped into the categories users most often ask for directly.
    entities = [
        {"type": "host", "id": "host-1", "name": "srv-1"},
        {"type": "user", "id": "user-1", "name": "alice@example.com"},
    ]
    observables = [
        {"type": "ip", "value": "10.0.0.5"},
        {"type": "domain", "value": "example.org"},
    ]

    context = models.normalize_context(entities, observables)

    assert context["hosts"][0]["name"] == "srv-1"
    assert context["users"][0]["name"] == "alice@example.com"
    assert context["ips"][0]["value"] == "10.0.0.5"
    assert context["domains"][0]["value"] == "example.org"


def test_normalize_event_preserves_targets_and_indicators() -> None:
    # Event shaping should preserve the detection fields the model needs for a
    # useful narrative without losing nested target/indicator data.
    event = {
        "id": "evt-1",
        "title": "THREAT url malware",
        "description": "Palo Alto Threat detection : THREAT url malware. Action: blocked\n\n**Application** : ssl",
        "source": "Palo Alto Networks Firewall via Splunk",
        "targets": [
            {
                "type": "endpoint",
                "value": "10.63.15.72",
                "observables": [{"type": "ip", "value": "10.63.15.72"}],
                "is_asset": True,
            }
        ],
        "observables": [{"type": "hostname", "value": "pass.nazarene.org"}],
        "indicators": [{"title": "THREAT url malware", "value": "THREAT url malware"}],
        "tactics_and_techniques": [{"id": "T1189", "title": "Drive-by Compromise"}],
        "detection_interval": {"start_time": "2026-03-24T00:10:03.000Z"},
    }

    normalized = models.normalize_event(event)

    assert normalized["action"] == "blocked"
    assert normalized["application"] == "ssl"
    assert normalized["targets"][0]["value"] == "10.63.15.72"
    assert normalized["observables"][0]["value"] == "pass.nazarene.org"
    assert normalized["indicator_titles"] == ["THREAT url malware"]
    assert normalized["mitre_attack"][0]["id"] == "T1189"


def test_normalize_storyboard_preserves_summary_and_observables() -> None:
    # Storyboard normalization should keep the assembled incident narrative plus
    # the key observable and detection-analysis sections.
    storyboard = {
        "title": "Suspicious Malware Storyboard",
        "headline": "Malware blocked after outbound SSL traffic",
        "summary": "A firewall blocked a known-malicious URL request.",
        "time": "2026-03-24T00:10:03.000Z",
        "product_names": ["Palo Alto Networks Firewall via Splunk"],
        "classification": {
            "classification": "malicious",
            "confidence": "high",
            "confidence_factors": [{"label": "Blocked by policy", "description": "The request was blocked."}],
        },
        "summary_structured": {
            "statement": "The incident consists of blocked malware URL activity.",
            "evidence": "Multiple THREAT url malware detections occurred.",
            "reasoning": "Repeated blocked events align with a malicious outbound request pattern.",
            "detection_investigation_uids": ["det-1", "det-2"],
        },
        "observables": [
            {"entity_type": "ip", "ip": "10.63.15.72", "uid": "obs-1"},
            {"entity_type": "url", "url": "pass.nazarene.org", "uid": "obs-2"},
        ],
        "detection_analysis": [
            {
                "uid": "det-1",
                "time": "2026-03-24T00:10:03.000Z",
                "detection_title": "THREAT url malware",
                "detection_desc": "Blocked malware URL request over SSL.",
                "aggregated_detection_uids": ["agg-1"],
                "detection_title_by_uid": {"agg-1": "THREAT url malware"},
                "entity_investigations": [{"uid": "entity-1", "entity_type": "host", "value": "10.63.15.72"}],
            }
        ],
    }

    normalized = models.normalize_storyboard(storyboard)

    assert normalized["title"] == "Suspicious Malware Storyboard"
    assert normalized["classification"]["classification"] == "malicious"
    assert normalized["summary_structured"]["statement"] == "The incident consists of blocked malware URL activity."
    assert normalized["observables"][0]["value"] == "10.63.15.72"
    assert normalized["observables"][1]["value"] == "pass.nazarene.org"
    assert normalized["detection_analysis"][0]["title"] == "THREAT url malware"
    assert normalized["counts"]["observables"] == 2
