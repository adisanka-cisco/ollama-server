# ollama-server

This repository contains a production-oriented Open WebUI deployment for an existing host-installed Ollama server, plus a FastAPI proxy that integrates Cisco AI Defense between Open WebUI and Ollama, and FastMCP sidecars for Cisco XDR Conure incident access and Endace Vault packet-capture workflows.

## Contents

- `open-webui/docker-compose.yml`
  - Docker Compose stack for Open WebUI and the AI Defense proxy
- `open-webui/.env`
  - Environment template with configurable values and placeholder secrets
- `open-webui/README.md`
  - Detailed deployment, operations, validation, and troubleshooting guide
- `open-webui/aidefense-proxy/`
  - FastAPI proxy that inspects prompts and responses with Cisco AI Defense before forwarding to Ollama
- `open-webui/open-webui-custom/`
  - Minimal custom Open WebUI image patch that marks internal helper-task requests so the proxy can skip inspecting them
- `mcp-xdr/`
  - FastMCP server for Cisco XDR Conure incidents, summaries, detections, and context over Streamable HTTP
- `mcp-endace-vault/`
  - FastMCP server for Endace Vault packet-capture request lifecycle operations over Streamable HTTP

## Purpose

The deployment is designed for a setup where:

- Ollama runs directly on the Ubuntu host
- Open WebUI runs in Docker on the same host
- Cisco AI Defense sits in the request path between Open WebUI and Ollama
- Only real user prompts and model responses are inspected
- Open WebUI internal helper tasks remain enabled but are excluded from inspection

## Getting Started

Quick startup from the repo root:

```bash
cd open-webui
cp .env .env.local  # optional: keep a host-specific copy before editing
docker compose build aidefense-proxy mcp-xdr mcp-endace-vault open-webui
docker compose up -d
docker compose ps
```

Useful follow-up commands:

```bash
cd open-webui
docker compose logs -f
docker compose restart nginx aidefense-proxy mcp-xdr mcp-endace-vault open-webui
docker compose down
```

Use the detailed guide here:

- [open-webui/README.md](./open-webui/README.md)

That document includes:

- Docker installation
- environment configuration
- startup and restart commands
- Ollama connectivity checks
- Open WebUI validation
- Cisco AI Defense proxy behavior and troubleshooting
