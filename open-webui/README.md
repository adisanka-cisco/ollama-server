# Open WebUI with Cisco AI Defense and MCP sidecars

This deployment runs on one Ubuntu host:

- Ollama runs on the host OS
- `nginx` runs in Docker as the HTTPS reverse proxy
- `aidefense-proxy` runs in Docker as a FastAPI sidecar
- `mcp-xdr` runs in Docker as an internal MCP sidecar for Cisco XDR incident access
- `mcp-xdr-community` runs in Docker as an internal OpenAPI sidecar for the community Cortex XDR server
- `mcp-endace-vault` runs in Docker as an internal MCP sidecar for Endace Vault workflows
- `mcp-cortex` runs in Docker as an internal MCP sidecar for Palo Alto Cortex
- Open WebUI runs in Docker and talks to the AI Defense proxy instead of talking to Ollama directly

Traffic path:

```text
Browser -> nginx -> Open WebUI -> aidefense-proxy -> Cisco AI Defense inspect -> Ollama
Browser <- nginx <- Open WebUI <- aidefense-proxy <- Cisco AI Defense inspect <- Ollama
```

Internal tool path:

```text
Open WebUI -> mcp-xdr -> Cisco XDR Conure API
Open WebUI -> mcp-xdr-community -> Cortex community server
Open WebUI -> mcp-endace-vault -> Endace Vault API
Open WebUI -> mcp-cortex -> Palo Alto Cortex API
Open WebUI -> remote MCP servers defined in TOOL_SERVER_CONNECTIONS
```

## Folder structure

```text
open-webui/
├── .env.example
├── docker-compose.yml
├── README.md
├── ../mcp-xdr/
├── ../mcp-xdr-community/
├── ../mcp-endace-vault/
├── ../mcp-cortex/
├── nginx/
│   ├── certs/
│   └── default.conf.template
├── open-webui-custom/
│   ├── Dockerfile
│   ├── backend/open_webui/routers/ollama.py
│   ├── backend/open_webui/utils/tools.py
│   ├── backend/open_webui/utils/middleware.py
│   ├── backend/open_webui/utils/mcp/client.py
│   └── scripts/patch_main.py
└── aidefense-proxy/
    ├── app.py
    ├── Dockerfile
    └── requirements.txt
```

## Services

- `nginx`
  - public entrypoint on host ports `80` and `443`
  - terminates TLS with a self-signed certificate
  - proxies to Open WebUI on the internal Docker network
- `open-webui`
  - built locally from `./open-webui-custom` on top of `ghcr.io/open-webui/open-webui:main`
  - internal-only on Docker port `8080`
  - includes local patches for MCP tool exposure and MCP session lifecycle handling
- `aidefense-proxy`
  - built locally from `./aidefense-proxy`
  - internal-only on Docker port `8001`
  - adds Cisco AI Defense inspection before and after Ollama calls
  - skips Cisco inspection when Open WebUI sends `X-OpenWebUI-Task` for internal helper tasks
- `mcp-xdr`
  - built locally from `../mcp-xdr`
  - internal-only on Docker port `8002`
  - exposes Cisco XDR Conure tools over MCP Streamable HTTP
- `mcp-xdr-community`
  - built locally from `../mcp-xdr-community`
  - internal-only on Docker port `8004`
  - exposes the community Cortex XDR integration as an OpenAPI tool server
- `mcp-endace-vault`
  - built locally from `../mcp-endace-vault`
  - internal-only on Docker port `8003`
  - exposes Endace Vault tools over MCP Streamable HTTP
- `mcp-cortex`
  - built locally from `../mcp-cortex`
  - internal-only on Docker port `8080`
  - exposes Palo Alto Cortex tools over MCP Streamable HTTP

## Environment file

The repository tracks `open-webui/.env.example`, not the live host `.env`.

Create the runtime file on the host:

```bash
cd ~/open-webui
cp .env.example .env
```

Then populate only the live host `.env` with your real secrets.

Notes:

- Keep API keys, bearer tokens, SCIM tokens, and OAuth secrets out of Git.
- `TOOL_SERVER_CONNECTIONS` is a JSON string consumed directly by Open WebUI.
- Sidecar services such as `mcp-cortex` are configured in Compose and then referenced from `TOOL_SERVER_CONNECTIONS`.
- Direct remote MCP servers such as Splunk or ThousandEyes can also be defined in `TOOL_SERVER_CONNECTIONS`.

Example `TOOL_SERVER_CONNECTIONS` value:

```json
[
  {
    "name": "cortex-mcp",
    "url": "http://mcp-cortex:8080/api/v1/stream/mcp",
    "path": "/api/v1/stream/mcp",
    "type": "mcp",
    "auth_type": "none",
    "config": {
      "enable": true
    },
    "info": {
      "id": "cortex-mcp",
      "name": "Cortex MCP Server"
    }
  },
  {
    "name": "thousandeyes-mcp",
    "url": "https://api.thousandeyes.com/mcp",
    "type": "mcp",
    "auth_type": "bearer",
    "key": "replace-with-thousandeyes-token",
    "config": {
      "enable": true
    },
    "info": {
      "id": "thousandeyes-mcp",
      "name": "ThousandEyes MCP Server"
    }
  }
]
```

## Deployment

From the host:

```bash
cd ~/open-webui
cp .env.example .env
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout nginx/certs/openwebui.key \
  -out nginx/certs/openwebui.crt \
  -days 365 \
  -subj "/CN=<PUBLIC_HOST>" \
  -addext "subjectAltName=DNS:<PUBLIC_HOST>,IP:<PUBLIC_IP_IF_USING_IP>"
docker compose build aidefense-proxy mcp-xdr mcp-xdr-community mcp-endace-vault mcp-cortex open-webui
docker compose up -d
docker compose ps
```

Useful commands:

```bash
docker compose logs -f nginx
docker compose logs -f aidefense-proxy
docker compose logs -f mcp-xdr
docker compose logs -f mcp-xdr-community
docker compose logs -f mcp-endace-vault
docker compose logs -f mcp-cortex
docker compose logs -f open-webui
docker compose restart nginx aidefense-proxy mcp-xdr mcp-xdr-community mcp-endace-vault mcp-cortex open-webui
```

## Validation

### 1. HTTPS and reverse proxy

```bash
curl -I http://127.0.0.1
curl -k https://127.0.0.1/
curl -k https://127.0.0.1/api/config
docker compose ps
```

Expected:

- HTTP redirects to HTTPS
- `nginx` is healthy
- `open-webui` is healthy
- the UI returns `200`

### 2. Proxy-to-Ollama connectivity

```bash
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  curlimages/curl:8.12.1 \
  -fsS http://host.docker.internal:11434/api/tags
```

### 3. Sidecar health

```bash
docker compose ps
docker compose logs --tail=100 mcp-xdr
docker compose logs --tail=100 mcp-xdr-community
docker compose logs --tail=100 mcp-endace-vault
docker compose logs --tail=100 mcp-cortex
```

### 4. MCP discovery inside Open WebUI

```bash
docker exec open-webui python - <<'PY'
import asyncio
from open_webui.main import app
from open_webui.utils.tools import get_mcp_server_connection

async def main():
    for server_id in ["cortex-mcp"]:
        connection = get_mcp_server_connection(type("Req", (), {"app": app})(), server_id)
        print(server_id, bool(connection))

asyncio.run(main())
PY
```

### 5. Browser flow

Open:

```text
https://PUBLIC_HOST
```

Verify:

- Open WebUI loads
- models appear in the dropdown
- a normal chat succeeds
- selected MCP integrations can be called from chat

## Why the custom overlay exists

The custom Open WebUI overlay currently carries two kinds of changes:

- `routers/ollama.py`
  - existing proxy-specific Ollama routing behavior
- `utils/tools.py`, `utils/middleware.py`, `utils/mcp/client.py`, and `scripts/patch_main.py`
  - MCP integration patches so `type: "mcp"` tool servers are exposed to models
  - MCP session lifecycle fixes so connect and disconnect happen in the same async context

These files should be reviewed whenever the base `ghcr.io/open-webui/open-webui:main` image is updated upstream.
