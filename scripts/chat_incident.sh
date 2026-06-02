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
#   ENDACE_URL / XDR_URL / OLLAMA_URL
#   CONTAINER    (default: open-webui)

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$REPO/scripts"
COMPOSE_DIR="$REPO/open-webui"

MODEL="${MODEL:-qwen2.5:32b}"
ENDACE_URL="${ENDACE_URL:-https://172.16.0.70:8080/mcp}"
XDR_URL="${XDR_URL:-http://mcp-xdr:8002/mcp/}"
OLLAMA_URL="${OLLAMA_URL:-http://host.docker.internal:11434}"
CONTAINER="${CONTAINER:-open-webui}"

echo "Model:    $MODEL"
echo "XDR:      $XDR_URL"
echo "Endace:   $ENDACE_URL"
echo "Container:$CONTAINER"
echo

# Copy the latest agent script into the container.
sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" cp \
  "$HERE/soc_agent_cli.py" "$CONTAINER:/tmp/agent.py"

# Run interactively. No -T (so the TTY is kept) and NO --prompt (so it enters
# the chat loop and shows a "you>" prompt you can type into).
sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec "$CONTAINER" \
  python3 /tmp/agent.py \
    --model "$MODEL" \
    --ollama "$OLLAMA_URL" \
    --mcp "xdr=$XDR_URL" \
    --mcp "endace=$ENDACE_URL" --insecure