"""Regression tests for Endace Vault payload normalization."""

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


models = _load_module("mcp_endace_models", "models.py")


def test_normalize_vault_entry_preserves_request_metadata() -> None:
    entry = {
        "viewUrl": "https://vault.local/vision2/vault?search=Example",
        "downloadUrl": "https://vault.local/api/v5/vault/request-1/download",
        "status": "Done",
        "created": "2026-03-21T23:50:55.714Z",
        "bytes": 13528881,
        "vaultRequest": {
            "vaultRequestFormat": "pcap",
            "datasources": "tag:rotation-file",
            "ip": "10.63.5.179",
            "start": 1774135195000,
            "end": 1774136995000,
            "id": "request-1",
            "title": "XDR (incident-123)",
            "tools": "conversations_by_ipaddress",
            "reltime": "30m",
            "vaultRequestType": "packets",
            "username": "api",
        },
    }

    normalized = models.normalize_vault_entry(entry)

    assert normalized["request_id"] == "request-1"
    assert normalized["status"] == "Done"
    assert normalized["download_url"].endswith("/request-1/download")
    assert normalized["type"] == "packets"
    assert normalized["format"] == "pcap"
    assert normalized["vault_request"]["ip"] == "10.63.5.179"
    assert normalized["vault_request"]["packet_filters"]["ip"] == "10.63.5.179"


def test_extract_vault_entries_and_filtered_count_from_list_payload() -> None:
    payload = {
        "payload": {
            "filteredVaultEntries": 168,
            "vaultEntries": [
                {"status": "Done", "vaultRequest": {"id": "one"}},
                {"status": "Downloading", "vaultRequest": {"id": "two"}},
            ],
        },
        "meta": {"error": False},
    }

    entries = models.extract_vault_entries(payload)
    filtered_count = models.extract_filtered_count(payload)

    assert len(entries) == 2
    assert filtered_count == 168
