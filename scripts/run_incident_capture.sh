#!/usr/bin/env bash
# Full end-to-end incident -> assets -> packet-capture run, entirely from the CLI.
#
# Why this exists: on a shell-only host where you cannot copy commands or output
# in/out of the terminal, this single script does everything and writes all
# results to scripts/test-output/ so they can be committed and pushed for review.
#
# It runs the agent INSIDE the open-webui container because mcp-xdr:8002 is only
# resolvable on the Docker network (it is not published to the host). The Endace
# MCP (172.16.0.70:8080) is reachable from there too.
#
# Usage (just run it; no arguments to type):
#   bash scripts/run_incident_capture.sh
#   git add scripts/test-output && git commit -m "incident run" && git push
#
# Optional overrides via environment variables:
#   INCIDENT_ID  (default below)
#   START_UTC / END_UTC  capture window (default: a 2-minute window)
#   ENDACE_URL / XDR_URL / OLLAMA_URL / MODEL
#   CONTAINER    name/service of the container on the docker network (default: open-webui)

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$REPO/scripts"
OUT="$HERE/test-output"
mkdir -p "$OUT"

INCIDENT_ID="${INCIDENT_ID:-incident-35f0c1e7-d9e2-4219-bdc7-2d3ba0dea4cf}"
START_UTC="${START_UTC:-2026-05-30T00:02:01Z}"
END_UTC="${END_UTC:-2026-05-30T00:04:01Z}"   # 2 minutes after START_UTC
ENDACE_URL="${ENDACE_URL:-https://172.16.0.70:8080/mcp}"
XDR_URL="${XDR_URL:-http://mcp-xdr:8002/mcp/}"
OLLAMA_URL="${OLLAMA_URL:-http://host.docker.internal:11434}"
MODEL="${MODEL:-llama3.1:8b}"
CONTAINER="${CONTAINER:-open-webui}"

# docker compose is invoked from the open-webui project dir.
COMPOSE_DIR="$REPO/open-webui"

PROMPT="For Cisco XDR incident ${INCIDENT_ID}, call the XDR context tool to get \
the incident context and list every IP address involved. Identify the two main \
IPs (source and destination). Then call the packet-capture tool to capture the \
conversation between those two IPs for the window ${START_UTC} to ${END_UTC} \
(UTC, a 2-minute window). Report the capture request id and status. Use the \
tools; do not answer from memory."

echo "Repo:        $REPO"
echo "Container:   $CONTAINER"
echo "Incident:    $INCIDENT_ID"
echo "Window:      $START_UTC -> $END_UTC (UTC)"
echo "Endace:      $ENDACE_URL"
echo "XDR:         $XDR_URL"
echo "Output dir:  $OUT"
echo

# 1. Copy the agent script into the container (path on the docker network).
echo "==> Copying agent script into container..."
sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" cp \
  "$HERE/soc_agent_cli.py" "$CONTAINER:/tmp/agent.py"

run_in_container() {
  # run_in_container <outfile> <description> <args-to-agent...>
  local outfile="$1"; shift
  local desc="$1"; shift
  echo "==> $desc"
  {
    echo "### $desc"
    echo "### incident: $INCIDENT_ID"
    echo "### window:   $START_UTC -> $END_UTC"
    echo "### date:     $(date -u 2>/dev/null)"
    echo "----------------------------------------"
    sudo docker compose -f "$COMPOSE_DIR/docker-compose.yml" exec -T "$CONTAINER" \
      python3 /tmp/agent.py "$@"
    echo
    echo "### exit code: $?"
  } > "$OUT/$outfile" 2>&1
}

# 2. Discover tools on both servers (confirms reachability + real tool names).
run_in_container "10-list-tools.txt" "Discover XDR + Endace tools" \
  --list-tools \
  --mcp "endace=$ENDACE_URL" --mcp "xdr=$XDR_URL" --insecure

# 3. Full incident -> assets -> capture, one-shot (logged).
run_in_container "11-incident-capture.txt" "Incident -> assets -> capture" \
  --model "$MODEL" --ollama "$OLLAMA_URL" \
  --mcp "endace=$ENDACE_URL" --mcp "xdr=$XDR_URL" --insecure \
  --prompt "$PROMPT"

echo
echo "Done. Results written to: $OUT"
echo "  - 10-list-tools.txt       (tool discovery)"
echo "  - 11-incident-capture.txt (full incident -> capture run)"
echo
echo "Now push the results so they can be reviewed:"
echo "  cd $REPO && git add scripts/test-output && git commit -m 'incident run output' && git push"