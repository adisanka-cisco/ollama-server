# Open WebUI with Cisco AI Defense proxy

This deployment runs on one Ubuntu host:

- Ollama runs on the host OS
- `aidefense-proxy` runs in Docker as a FastAPI sidecar
- Open WebUI runs in Docker and talks to the proxy instead of talking to Ollama directly

Traffic path:

```text
Open WebUI -> aidefense-proxy -> Cisco AI Defense inspect -> Ollama
Open WebUI <- aidefense-proxy <- Cisco AI Defense inspect <- Ollama
```

## Folder structure

```text
open-webui/
├── .env
├── docker-compose.yml
├── README.md
├── open-webui-custom/
│   ├── Dockerfile
│   └── backend/open_webui/routers/ollama.py
└── aidefense-proxy/
    ├── app.py
    ├── Dockerfile
    └── requirements.txt
```

## Services

- `open-webui`
  - built locally from `./open-webui-custom` on top of `ghcr.io/open-webui/open-webui:main`
  - exposed on host port `3000`
- `aidefense-proxy`
  - built locally from `./aidefense-proxy`
  - internal-only on Docker port `8001`
  - adds Cisco AI Defense inspection before and after Ollama calls
  - skips Cisco inspection when Open WebUI sends `X-OpenWebUI-Task` for internal helper tasks

## Environment variables

Set these in `.env`:

```dotenv
OPEN_WEBUI_IMAGE=ghcr.io/open-webui/open-webui:main
OPEN_WEBUI_CONTAINER_NAME=open-webui
OPEN_WEBUI_HOST_PORT=3000
OPEN_WEBUI_CONTAINER_PORT=8080
OLLAMA_BASE_URL=http://host.docker.internal:11434
AIDEFENSE_PROXY_PORT=8001
AIDEFENSE_BASE_URL=https://us.api.inspect.aidefense.security.cisco.com
AIDEFENSE_API_KEY=replace-on-host-only
WEBUI_SECRET_KEY=replace-with-a-long-random-secret
```

Notes:

- `OLLAMA_BASE_URL` is used by the proxy to reach host Ollama.
- Open WebUI itself is wired in Compose to `http://aidefense-proxy:8001`.
- Keep the real `AIDEFENSE_API_KEY` only on the host copy of `.env`.
- The Cisco API key is injected into `aidefense-proxy` only, not into `open-webui`.

## Proxy behavior

- Intercepts `POST /api/chat`
- Intercepts `POST /api/generate`
- Passes through other Ollama-compatible `/api/*` routes unchanged
- Skips Cisco inspection for Open WebUI internal helper tasks when Open WebUI sends `X-OpenWebUI-Task`
- Forces upstream Ollama requests to `stream=false`
- If Cisco blocks a prompt or response, returns HTTP `200` with an Ollama-compatible assistant block message
- If Cisco is unreachable, times out, or returns `408/429/5xx`, the proxy fails open and forwards to Ollama

## Deployment

From the host:

```bash
cd ~/open-webui
docker compose build aidefense-proxy
docker compose up -d
docker compose ps
```

Useful commands:

```bash
docker compose logs -f aidefense-proxy
docker compose logs -f open-webui
docker compose restart aidefense-proxy open-webui
docker compose down
docker compose up -d
```

## Validation

### 1. Open WebUI health

```bash
curl -I http://127.0.0.1:3000
curl -fsS http://127.0.0.1:3000/api/config
docker compose ps
```

Expected:

- `open-webui` is healthy
- the UI returns `200`

### 2. Proxy-to-Ollama connectivity

```bash
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  curlimages/curl:8.12.1 \
  -fsS http://host.docker.internal:11434/api/tags
```

Expected:

- the model list includes the Ollama models already on the host

### 3. Proxy pass-through

```bash
curl -fsS http://127.0.0.1:3000/ollama/api/tags
```

Expected:

- Open WebUI can still fetch models through the proxy path

### 4. Safe chat flow

Send a normal prompt in Open WebUI and verify:

- the prompt succeeds
- `aidefense-proxy` logs a shared `client_transaction_id`
- logs show one ingress inspection and one egress inspection

### 5. Browser flow

Open:

```text
http://HOST_IP:3000
```

Verify:

- Open WebUI loads
- models appear in the dropdown
- a normal chat succeeds

## Troubleshooting

### Open WebUI loads but models do not appear

Check:

```bash
docker compose logs --tail=200 aidefense-proxy
curl -fsS http://127.0.0.1:11434/api/tags
curl -fsS http://127.0.0.1:3000/ollama/api/tags
```

### Cisco inspection is failing

Check:

```bash
docker compose logs --tail=200 aidefense-proxy
```

Look for:

- `inspection_result`
- `inspection_fail_open`
- `client_transaction_id`
- Cisco `event_id`

Common causes:

- invalid `AIDEFENSE_API_KEY`
- incorrect `AIDEFENSE_BASE_URL`
- outbound network or DNS failure from the proxy container

### Blocked requests are not readable in the UI

Check:

```bash
docker compose logs --tail=200 aidefense-proxy
```

Blocked content is returned as an Ollama-compatible success response, not as HTTP `403`.

### Proxy container is unhealthy

Check:

```bash
docker compose ps
docker compose logs --tail=200 aidefense-proxy
curl -fsS http://127.0.0.1:8001/healthz
```

### Streaming looks delayed

This is expected in v1. The proxy buffers the full Ollama reply, inspects it with Cisco AI Defense, and only then returns it to Open WebUI.
