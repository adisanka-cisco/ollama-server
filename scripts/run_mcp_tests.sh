#!/usr/bin/env bash
# Run the MCP / Ollama connectivity tests and save all output to scripts/test-output/.
#
# Why this exists: on a shell-only host where you cannot copy text out of the
# terminal (e.g. a remote console), this captures every test result to files so
# they can be committed and pushed for review.
#
# Usage:
#   bash scripts/run_mcp_tests.sh
#   git add scripts/test-output && git commit -m "mcp test output" && git push
#
# Optional overrides via environment variables:
#   ENDACE_URL   (default: https://172.16.0.70:8080/mcp)
#   XDR_URL      (default: http://mcp-xdr:8002/mcp/)
#   OLLAMA_URL   (default: http://127.0.0.1:11434)
#   MODEL        (default: llama3.1:8b)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/test-output"
mkdir -p "$OUT"

ENDACE_URL="${ENDACE_URL:-https://172.16.0.70:8080/mcp}"
XDR_URL="${XDR_URL:-http://mcp-xdr:8002/mcp/}"
OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
MODEL="${MODEL:-llama3.1:8b}"

echo "Writing results to: $OUT"
echo "ENDACE_URL=$ENDACE_URL  XDR_URL=$XDR_URL  OLLAMA_URL=$OLLAMA_URL  MODEL=$MODEL"

run() {
  # run <outfile> <description> <command...>
  local outfile="$1"; shift
  local desc="$1"; shift
  echo "==> $desc"
  {
    echo "### $desc"
    echo "### command: $*"
    echo "### date: $(date -u 2>/dev/null)"
    echo "----------------------------------------"
    "$@"
    echo
    echo "### exit code: $?"
  } > "$OUT/$outfile" 2>&1
}

# 1. Ollama model list
run "01-ollama-tags.txt" "Ollama model list" \
  curl -s "$OLLAMA_URL/api/tags"

# 2. Endace MCP tools (the key one)
run "02-endace-tools.txt" "Endace MCP tools/list" \
  python3 "$HERE/mcp_probe.py" --url "$ENDACE_URL" --insecure list

# 3. Both servers' tools via the agent script (also checks XDR reachability)
run "03-list-tools-both.txt" "Discover tools across XDR + Endace" \
  python3 "$HERE/soc_agent_cli.py" --list-tools \
    --mcp "endace=$ENDACE_URL" --mcp "xdr=$XDR_URL" --insecure

# 4. One-shot: does the model actually call the Endace tool?
run "04-oneshot-endace.txt" "One-shot Endace capture prompt" \
  python3 "$HERE/soc_agent_cli.py" --model "$MODEL" \
    --ollama "$OLLAMA_URL" --mcp "endace=$ENDACE_URL" --insecure \
    --prompt "List your packet-capture tools, then capture traffic between 10.1.1.5 and 10.1.1.9 for the last 15 minutes."

echo
echo "Done. Now commit and push the results:"
echo "  git add scripts/test-output && git commit -m 'mcp test output' && git push"
