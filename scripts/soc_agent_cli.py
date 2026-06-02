#!/usr/bin/env python3
"""CLI agent loop: Ollama + MCP tool servers (XDR + Endace), no UI required.

This replicates what Open WebUI does internally so the incident-driven
packet-capture flow can be tested from a shell-only environment:

  1. Connect to one or more MCP Streamable HTTP servers and discover their tools.
  2. Expose those tools to a local Ollama model using Ollama's tool-calling API.
  3. Run a chat loop: when the model calls a tool, execute it against the right
     MCP server, feed the result back, and repeat until the model answers.

The intended end-to-end test:
  "For XDR incident <id>, pull the involved assets, then capture the packet
   conversation between two of them."
The model uses the XDR tools to fetch assets and the Endace tool to request the
capture, with you confirming the two IPs and the time window in the chat.

Dependency-free: standard library only (talks to Ollama and MCP over HTTP).

Examples:
  # interactive chat with both servers wired in
  python3 scripts/soc_agent_cli.py \
    --ollama http://127.0.0.1:11434 --model llama3.1:8b \
    --mcp xdr=http://mcp-xdr:8002/mcp/ \
    --mcp endace=https://172.16.0.70:8080/mcp --insecure

  # one-shot prompt (non-interactive)
  python3 scripts/soc_agent_cli.py --model llama3.1:8b \
    --mcp endace=https://172.16.0.70:8080/mcp --insecure \
    --prompt "List the available packet-capture tools and their parameters."

  # just discover tools and exit (no model needed)
  python3 scripts/soc_agent_cli.py --list-tools \
    --mcp endace=https://172.16.0.70:8080/mcp --insecure
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2024-11-05"


# --------------------------------------------------------------------------- #
# MCP client (Streamable HTTP)                                                 #
# --------------------------------------------------------------------------- #
def _ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse_jsonrpc(raw: str):
    """Handle both plain JSON and SSE-framed ('data: {...}') responses."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    for line in reversed(raw.splitlines()):
        if line.startswith("data:"):
            try:
                return json.loads(line[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
    return None


class MCPClient:
    def __init__(self, name: str, url: str, insecure: bool = False, timeout: float = 30.0):
        self.name = name
        self.url = url
        self.timeout = timeout
        self.context = _ssl_context(insecure)
        self.session_id: str | None = None

    def _post(self, method: str, params: dict, request_id):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(self.url, data=body, headers=headers)
        try:
            resp = urllib.request.urlopen(req, context=self.context, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"[{self.name}] HTTP {exc.code}: {exc.read().decode(errors='replace')}"
            ) from exc
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        return _parse_jsonrpc(resp.read().decode())

    def initialize(self) -> None:
        self._post(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "soc-agent-cli", "version": "1.0"},
            },
            request_id=1,
        )
        try:
            self._post("notifications/initialized", {}, request_id=0)
        except Exception:
            pass

    def list_tools(self) -> list[dict]:
        payload = self._post("tools/list", {}, request_id=2)
        if not isinstance(payload, dict):
            return []
        return payload.get("result", {}).get("tools", []) or []

    def call_tool(self, name: str, arguments: dict):
        payload = self._post(
            "tools/call", {"name": name, "arguments": arguments}, request_id=3
        )
        if isinstance(payload, dict):
            if "error" in payload:
                return json.dumps(payload["error"])
            result = payload.get("result", {})
            # MCP tool results are a list of content blocks; pull text out.
            content = result.get("content")
            if isinstance(content, list):
                texts = [c.get("text", "") for c in content if isinstance(c, dict)]
                return "\n".join(t for t in texts if t) or json.dumps(result)
            return json.dumps(result)
        return json.dumps(payload)


# --------------------------------------------------------------------------- #
# Ollama chat with tool calling                                               #
# --------------------------------------------------------------------------- #
def ollama_chat(base_url: str, model: str, messages: list[dict], tools: list[dict], timeout: float = 300.0):
    url = base_url.rstrip("/") + "/api/chat"
    body = json.dumps(
        {"model": model, "messages": messages, "tools": tools, "stream": False}
    ).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(resp.read().decode())


def mcp_tools_to_ollama(tools: list[dict]) -> list[dict]:
    out = []
    for t in tools:
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "parameters": t.get("inputSchema", {"type": "object", "properties": {}}),
                },
            }
        )
    return out


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #
DEFAULT_SYSTEM_PROMPT = (
    "You are a Tier-1 SOC triage assistant. You are connected to MCP tool servers "
    "and can see all of their tools. Always prefer calling a tool over answering "
    "from memory, and fill arguments exactly as each tool's schema requires.\n"
    "\n"
    "Incident-driven packet capture workflow:\n"
    "1. Call xdr_get_incident_context with {\"incident_id\": \"<id>\"} to get the "
    "hosts/IPs tied to the incident.\n"
    "2. List the distinct IPs found, numbered.\n"
    "3. Ask the analyst which TWO IPs (source and destination) to capture between; "
    "do not choose the pair yourself.\n"
    "4. Propose a window from the incident timing and ask the analyst to confirm "
    "the start, end, and a maximum duration (time limit). Do not invent the limit.\n"
    "5. Call the Packet_Decode tool to start the capture, using EXACTLY:\n"
    "   - ip_conv: the two IPs as one string 'SRC & DST', e.g. '10.1.1.5 & 10.1.1.9'\n"
    "   - either start+end as RFC3339 UTC strings (e.g. '2026-05-30T00:02:01Z'),\n"
    "     OR reltime (e.g. '2m'), never both.\n"
    "   - do NOT use sip/dip/ip_sip or any other parameter names.\n"
    "Never invent tool results or pass placeholder values; if a tool errors, show "
    "the error and stop."
)


def build_registry(specs: list[str], insecure: bool):
    """specs like ['xdr=http://...','endace=https://...'] -> clients + tool map."""
    clients: dict[str, MCPClient] = {}
    tool_to_client: dict[str, MCPClient] = {}
    all_tools: list[dict] = []
    for spec in specs:
        if "=" not in spec:
            raise SystemExit(f"--mcp must be name=url, got: {spec}")
        name, url = spec.split("=", 1)
        client = MCPClient(name.strip(), url.strip(), insecure=insecure)
        client.initialize()
        tools = client.list_tools()
        clients[name] = client
        for t in tools:
            tname = t.get("name")
            if not tname:
                continue
            if tname in tool_to_client:
                print(f"WARNING: duplicate tool name '{tname}' across servers; last wins.", file=sys.stderr)
            tool_to_client[tname] = client
            all_tools.append(t)
        print(f"[{name}] {url} -> {len(tools)} tools: {', '.join(t.get('name','?') for t in tools) or '(none)'}", file=sys.stderr)
    return clients, tool_to_client, all_tools


def run_turn(base_url, model, messages, ollama_tools, tool_to_client, max_tool_rounds=8):
    for _ in range(max_tool_rounds):
        data = ollama_chat(base_url, model, messages, ollama_tools)
        msg = data.get("message", {})
        messages.append(msg)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            return msg.get("content", "")
        for call in tool_calls:
            fn = call.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            client = tool_to_client.get(name)
            print(f"  -> tool call: {name}({json.dumps(args)})", file=sys.stderr)
            if client is None:
                result = f"ERROR: unknown tool '{name}'"
            else:
                try:
                    result = client.call_tool(name, args)
                except Exception as exc:  # noqa: BLE001 - surface to the model
                    result = f"ERROR calling {name}: {exc}"
            print(f"  <- result ({len(str(result))} chars)", file=sys.stderr)
            messages.append({"role": "tool", "content": str(result)})
    return "(stopped: reached max tool-call rounds)"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="CLI agent loop: Ollama + MCP tool servers.")
    p.add_argument("--ollama", default="http://127.0.0.1:11434", help="Ollama base URL")
    p.add_argument("--model", default="llama3.1:8b", help="Ollama model name")
    p.add_argument("--mcp", action="append", default=[], metavar="name=url",
                   help="MCP server, repeatable, e.g. endace=https://172.16.0.70:8080/mcp")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification for MCP servers")
    p.add_argument("--system", default=DEFAULT_SYSTEM_PROMPT, help="system prompt")
    p.add_argument("--prompt", default=None, help="one-shot user prompt (non-interactive)")
    p.add_argument("--list-tools", action="store_true", help="discover tools and exit")
    ns = p.parse_args(argv)

    if not ns.mcp:
        p.error("at least one --mcp name=url is required")

    _clients, tool_to_client, all_tools = build_registry(ns.mcp, ns.insecure)

    if ns.list_tools:
        print(json.dumps(all_tools, indent=2))
        return 0

    ollama_tools = mcp_tools_to_ollama(all_tools)
    messages = [{"role": "system", "content": ns.system}]

    if ns.prompt is not None:
        messages.append({"role": "user", "content": ns.prompt})
        answer = run_turn(ns.ollama, ns.model, messages, ollama_tools, tool_to_client)
        print("\n=== assistant ===")
        print(answer)
        return 0

    print("Interactive SOC agent. Type your message; Ctrl-D or 'exit' to quit.\n")
    while True:
        try:
            user = input("you> ").strip()
        except EOFError:
            print()
            break
        if user.lower() in {"exit", "quit"}:
            break
        if not user:
            continue
        messages.append({"role": "user", "content": user})
        answer = run_turn(ns.ollama, ns.model, messages, ollama_tools, tool_to_client)
        print(f"\nassistant> {answer}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
