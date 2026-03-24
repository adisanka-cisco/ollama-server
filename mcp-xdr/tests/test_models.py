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
