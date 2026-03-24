# Open WebUI with Cisco AI Defense proxy

This deployment runs on one Ubuntu host:

- Ollama runs on the host OS
- `nginx` runs in Docker as the HTTPS reverse proxy
- `aidefense-proxy` runs in Docker as a FastAPI sidecar
- `mcp-xdr` runs in Docker as an internal FastMCP sidecar for Cisco XDR incident access
- Open WebUI runs in Docker and talks to the proxy instead of talking to Ollama directly

Traffic path:

```text
Browser -> nginx -> Open WebUI -> aidefense-proxy -> Cisco AI Defense inspect -> Ollama
Browser <- nginx <- Open WebUI <- aidefense-proxy <- Cisco AI Defense inspect <- Ollama
```

Optional internal MCP path:

```text
Open WebUI -> mcp-xdr -> Cisco XDR Conure API
```

## Folder structure

```text
open-webui/
├── .env
├── docker-compose.yml
├── README.md
├── ../mcp-xdr/
│   ├── Dockerfile
│   ├── client.py
│   ├── formatters.py
│   ├── models.py
│   ├── requirements.txt
│   ├── server.py
│   └── tests/
├── nginx/
│   ├── certs/
│   └── default.conf.template
├── open-webui-custom/
│   ├── Dockerfile
│   └── backend/open_webui/routers/ollama.py
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
- `aidefense-proxy`
  - built locally from `./aidefense-proxy`
  - internal-only on Docker port `8001`
  - adds Cisco AI Defense inspection before and after Ollama calls
  - skips Cisco inspection when Open WebUI sends `X-OpenWebUI-Task` for internal helper tasks
- `mcp-xdr`
  - built locally from `../mcp-xdr`
  - internal-only on Docker port `8002`
  - exposes Cisco XDR Conure incident tools over FastMCP Streamable HTTP
  - uses OAuth2 client credentials and in-memory token caching only

## Environment variables

Set these in `.env`:

```dotenv
OPEN_WEBUI_IMAGE=ghcr.io/open-webui/open-webui:main
OPEN_WEBUI_CONTAINER_NAME=open-webui
NGINX_CONTAINER_NAME=open-webui-nginx
PUBLIC_HOST=replace-with-public-host
WEBUI_URL=https://replace-with-public-host
NGINX_HTTP_PORT=80
NGINX_HTTPS_PORT=443
OPEN_WEBUI_CONTAINER_PORT=8080
OLLAMA_BASE_URL=http://host.docker.internal:11434
AIDEFENSE_PROXY_PORT=8001
MCP_XDR_PORT=8002
MCP_XDR_PATH=/mcp/
XDR_TOKEN_URL=https://visibility.amp.cisco.com/iroh/oauth2/token
XDR_CONURE_BASE_URL=https://conure.us.security.cisco.com
XDR_CLIENT_ID=
XDR_CLIENT_SECRET=
XDR_HTTP_TIMEOUT=30
XDR_VERIFY_TLS=true
XDR_TOKEN_REFRESH_SKEW_SECONDS=60
AIDEFENSE_BASE_URL=https://us.api.inspect.aidefense.security.cisco.com
AIDEFENSE_API_KEY=replace-on-host-only
AIDEFENSE_ENFORCEMENT_MODE=monitor
WEBUI_SECRET_KEY=replace-with-a-long-random-secret
SCIM_ENABLED=true
SCIM_TOKEN=replace-with-a-random-scim-token
SCIM_AUTH_PROVIDER=oidc
ENABLE_OAUTH_SIGNUP=false
ENABLE_OAUTH_PERSISTENT_CONFIG=false
OAUTH_PROVIDER_NAME=Duo
OPENID_PROVIDER_URL=
OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=
OAUTH_SCOPES=openid email profile
OPENID_REDIRECT_URI=https://replace-with-public-host/oauth/oidc/callback
```

Notes:

- `OLLAMA_BASE_URL` is used by the proxy to reach host Ollama.
- Open WebUI itself is wired in Compose to `http://aidefense-proxy:8001`.
- `mcp-xdr` is exposed only on the internal Docker network at `http://mcp-xdr:8002/mcp/`.
- `XDR_CLIENT_ID` and `XDR_CLIENT_SECRET` are read only by `mcp-xdr`.
- The XDR sidecar uses OAuth2 client credentials and keeps access tokens only in memory.
- Keep the real `AIDEFENSE_API_KEY` only on the host copy of `.env`.
- The Cisco API key is injected into `aidefense-proxy` only, not into `open-webui`.
- `AIDEFENSE_ENFORCEMENT_MODE=monitor` means the proxy inspects but never blocks.
- Set `AIDEFENSE_ENFORCEMENT_MODE=enforce` only if you want the proxy to replace unsafe prompts or responses with the block message.
- `ENABLE_OAUTH_SIGNUP` should remain `false` until you have the Duo OIDC `well-known` URL, client ID, and client secret.
- SCIM is exposed from Open WebUI at `/api/v1/scim/v2/` once `SCIM_ENABLED=true`.

## Proxy behavior

- Intercepts `POST /api/chat`
- Intercepts `POST /api/generate`
- Passes through other Ollama-compatible `/api/*` routes unchanged
- Skips Cisco inspection for Open WebUI internal helper tasks when Open WebUI sends `X-OpenWebUI-Task`
- Forces upstream Ollama requests to `stream=false`
- In `monitor` mode, Cisco results are logged but never block the request
- In `enforce` mode, unsafe prompt or response paths return HTTP `200` with an Ollama-compatible assistant block message
- If Cisco is unreachable, times out, or returns `408/429/5xx`, the proxy fails open and forwards to Ollama

## Deployment

From the host:

```bash
cd ~/open-webui
mkdir -p nginx/certs
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout nginx/certs/openwebui.key \
  -out nginx/certs/openwebui.crt \
  -days 365 \
  -subj "/CN=<PUBLIC_HOST>" \
  -addext "subjectAltName=DNS:<PUBLIC_HOST>,IP:<PUBLIC_IP_IF_USING_IP>"
docker compose build aidefense-proxy mcp-xdr open-webui
docker compose up -d
docker compose ps
```

Useful commands:

```bash
docker compose logs -f nginx
docker compose logs -f aidefense-proxy
docker compose logs -f mcp-xdr
docker compose logs -f open-webui
docker compose restart nginx aidefense-proxy mcp-xdr open-webui
docker compose down
docker compose up -d
```

## Validation

### 1. HTTPS and reverse proxy

```bash
curl -I http://127.0.0.1
curl -k -I https://127.0.0.1
curl -k -fsS https://127.0.0.1/api/config
docker compose ps
```

Expected:

- HTTP redirects to HTTPS
- `nginx` is healthy/running
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
curl -k -fsS https://127.0.0.1/ollama/api/tags
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
https://PUBLIC_HOST
```

Verify:

- Open WebUI loads
- browser accepts the self-signed certificate after trust/override
- models appear in the dropdown
- a normal chat succeeds

### 6. SCIM endpoint

```bash
curl -k -H "Authorization: Bearer $SCIM_TOKEN" \
  https://PUBLIC_HOST/api/v1/scim/v2/Users
```

Expected:

- Open WebUI responds from the SCIM endpoint
- Duo can use this same base URL for provisioning

### 7. Cisco XDR MCP sidecar

```bash
docker compose exec mcp-xdr python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8002/healthz').read().decode())"
docker compose logs --tail=200 mcp-xdr
```

Expected:

- the MCP sidecar responds with `{"status":"ok"}`
- no OAuth token or bearer token appears in logs

To register it in Open WebUI, add an MCP server using the internal URL:

```text
http://mcp-xdr:8002/mcp/
```

The initial tool set is:

- `xdr_list_incidents`
- `xdr_get_incident`
- `xdr_get_incident_summary`
- `xdr_get_incident_detections`
- `xdr_get_incident_context`
- `xdr_get_incident_storyboard`

## Troubleshooting

### Open WebUI loads but models do not appear

Check:

```bash
docker compose logs --tail=200 aidefense-proxy
curl -fsS http://127.0.0.1:11434/api/tags
curl -k -fsS https://127.0.0.1/ollama/api/tags
```

### HTTPS is not reachable

Check:

```bash
docker compose ps
docker compose logs --tail=200 nginx
openssl x509 -in nginx/certs/openwebui.crt -text -noout | sed -n '1,80p'
```

Common causes:

- AWS security group does not allow `80/tcp` and `443/tcp`
- certificate SAN does not match the host users browse to
- Nginx cert files are missing from `nginx/certs/`

### Duo OIDC login does not appear

Check:

```bash
docker compose logs --tail=200 open-webui
```

Common causes:

- `ENABLE_OAUTH_SIGNUP` is still `false`
- missing `OPENID_PROVIDER_URL`
- missing `OAUTH_CLIENT_ID` or `OAUTH_CLIENT_SECRET`
- `WEBUI_URL` and `OPENID_REDIRECT_URI` do not exactly match the Duo app redirect URI

### Cisco XDR MCP tools fail

Check:

```bash
docker compose logs --tail=200 mcp-xdr
```

Common causes:

- `XDR_CLIENT_ID` or `XDR_CLIENT_SECRET` is missing or invalid
- the OAuth client lacks Conure read scope and Cisco returns `403`
- `XDR_TOKEN_URL` or `XDR_CONURE_BASE_URL` is wrong
- the incident ID does not exist and Cisco returns `404`
- upstream rate limiting or a temporary Conure outage

### SCIM provisioning fails

Check:

```bash
docker compose logs --tail=200 open-webui
curl -k -H "Authorization: Bearer <scim-token>" \
  https://PUBLIC_HOST/api/v1/scim/v2/Users
```

Common causes:

- invalid `SCIM_TOKEN`
- `SCIM_AUTH_PROVIDER` is not `oidc`
- Duo tenant/app does not support outbound SCIM provisioning for the chosen OIDC app

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
- `AIDEFENSE_ENFORCEMENT_MODE=enforce` when you expected monitor-only behavior

### Blocked requests are not readable in the UI

Check:

```bash
docker compose logs --tail=200 aidefense-proxy
```

Blocked content is returned as an Ollama-compatible success response, not as HTTP `403`.

### Prompts are being blocked even though Cisco policy is monitor-only

Check:

```bash
grep '^AIDEFENSE_ENFORCEMENT_MODE=' .env
docker compose logs --tail=200 aidefense-proxy
```

If the proxy is set to `enforce`, it will still block even when the Cisco-side policy is only monitoring.
Set `AIDEFENSE_ENFORCEMENT_MODE=monitor` and restart the stack.

### Proxy container is unhealthy

Check:

```bash
docker compose ps
docker compose logs --tail=200 aidefense-proxy
curl -fsS http://127.0.0.1:8001/healthz
```

### Streaming looks delayed

This is expected in v1. The proxy buffers the full Ollama reply, inspects it with Cisco AI Defense, and only then returns it to Open WebUI.
