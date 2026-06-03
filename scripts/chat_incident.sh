#!/usr/bin/env bash
# Launch the SOC agent in INTERACTIVE chat mode, inside the open-webui container.
#
# Use this when the model needs to ask you questions (which two IPs? what time
# window?) and you need to answer back. Unlike run_incident_capture.sh (one-shot,
# writes to files), this gives you a live "you>" prompt to type into.
#
# It runs inside the open-webui container because mcp-xdr:8002 is only reachable
# on the docker network. The Endace MCP (172.16.0.70:8080) is reachable too.
#
# Usage (just run it):
#   bash scripts/chat_incident.sh
#
# Optional overrides via environment variables:
#   MODEL        (default: qwen2.5:32b)
#   ENDACE_URL / XDR_URL / SPLUNK_URL / OLLAMA_URL
#   CONTAINER    (default: open-webui)
#
# Splunk MCP is included ONLY if you export its bearer token first, e.g.:
#   export MCP_TOKEN_SPLUNK='<your-splunk-token>'
#   bash scripts/chat_incident.sh
# Without that token, the script runs with just XDR + Endace.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$REPO/scripts"
COMPOSE_DIR="$REPO/open-webui"

MODEL="${MODEL:-qwen2.5:32b}"
ENDACE_URL="${ENDACE_URL:-https://172.16.0.70:8080/mcp}"
XDR_URL="${XDR_URL:-http://mcp-xdr:8002/mcp/}"
SPLUNK_URL="${SPLUNK_URL:-https://es.cisco-sec-event.splunkcloud.com:8089/services/mcp}"
OLLAMA_URL="${OLLAMA_URL:-http://host.docker.internal:11434}"
CONTAINER="${CONTAINER:-open-webui}"

# Build the --mcp argument list. XDR and Endace are always on.
MCP_ARGS=(--mcp "xdr=$XDR_URL" --mcp "endace=$ENDACE_URL")

# Add Splunk only if its token is present, and pass the token into the container.
DOCKER_ENV_ARGS=()
if [ -n "${MCP_TOKEN_SPLUNK:-}" ]; then
  MCP_ARGS+=(--mcp "splunk=$SPLUNK_URL")
  DOCKER_ENV_ARGS=(-e "MCP_TOKEN_SPLUNK=$MCP_TOKEN_SPLUNK")
  SPLUNK_STATUS="$SPLUNK_URL (token set)"
else
  SPLUNK_STATUS="(disabled - export MCP_TOKEN_SPLUNK to enable)"
fi

echo "Model:    $MODEL"
echo "XDR:      $XDR_URL"
echo "Endace:   $ENDACE_URL"
echo "Splunk:   $SPLUNK_STATUS"
echo "Container:$CONTAINER"
echo

# Copy the latest agent script into the container.
sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" cp \
  "$HERE/soc_agent_cli.py" "$CONTAINER:/tmp/agent.py"

# Run interactively. No -T (so the TTY is kept) and NO --prompt (so it enters
# the chat loop and shows a "you>" prompt you can type into).
sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec \
  "${DOCKER_ENV_ARGS[@]}" "$CONTAINER" \
  python3 /tmp/agent.py \
    --model "$MODEL" \
    --ollama "$OLLAMA_URL" \
    "${MCP_ARGS[@]}" --insecure