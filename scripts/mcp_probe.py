#!/usr/bin/env python3
"""Probe an MCP Streamable HTTP server: list tools and optionally call one.

This is a small, dependency-free diagnostic for the external packet-capture MCP
server (and any other MCP Streamable HTTP server). It performs the required
MCP handshake (initialize -> notifications/initialized) to obtain a session id,
then issues tools/list or tools/call.

Why this exists:
- Open WebUI's "Manage Tool Servers" page speaks OpenAPI, not raw MCP, so it
  cannot enumerate a pure MCP server's tools. This script talks MCP directly so
  you can confirm reachability and discover the real tool names + parameters
  before wiring anything up (e.g. via an mcpo bridge).

Usage:
  # list tools
  python3 scripts/mcp_probe.py --url https://172.16.0.70:8080/mcp list

  # call a tool with JSON arguments
  python3 scripts/mcp_probe.py --url https://172.16.0.70:8080/mcp \
      call <tool_name> --args '{"sip": "10.1.1.5", "dip": "10.1.1.9", "reltime": "15m"}'

Notes:
- Use --insecure to skip TLS certificate verification (self-signed certs).
- The server may answer in SSE framing ("data: {...}" lines); this script
  extracts and pretty-prints the JSON-RPC payload either way.
- No third-party packages required; uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "https://172.16.0.70:8080/mcp"
PROTOCOL_VERSION = "2024-11-05"


def build_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def parse_payload(raw: str) -> dict | list | None:
    """Return the JSON-RPC body from either plain JSON or SSE-framed output."""
    raw = raw.strip()
    if not raw:
        return None
    # Plain JSON.
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # SSE framing: collect the last non-empty "data:" line.
    data_lines = [
        line[len("data:"):].strip()
        for line in raw.splitlines()
        if line.startswith("data:")
    ]
    for chunk in reversed(data_lines):
        try:
            return json.loads(chunk)
        except json.JSONDecodeError:
            continue
    return None


class MCPClient:
    def __init__(self, url: str, insecure: bool = False, timeout: float = 20.0,
                 token: str | None = None) -> None:
        self.url = url
        self.timeout = timeout
        self.context = build_context(insecure)
        self.session_id: str | None = None
        self.token = token

    def _post(self, method: str, params: dict, request_id: int | str) -> tuple[str, str | None]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        ).encode()
        req = urllib.request.Request(self.url, data=body, headers=headers)
        try:
            resp = urllib.request.urlopen(req, context=self.context, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            # Surface the server's error body (e.g. "Missing session id").
            return f"HTTP {exc.code}: {exc.read().decode(errors='replace')}", None
        return resp.read().decode(), resp.headers.get("Mcp-Session-Id")

    def initialize(self) -> dict | list | None:
        raw, sid = self._post(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-probe", "version": "1.0"},
            },
            request_id=1,
        )
        if sid:
            self.session_id = sid
        payload = parse_payload(raw)
        # Best-effort: the spec requires an initialized notification before use.
        try:
            self._post("notifications/initialized", {}, request_id=0)
        except Exception:
            pass
        return payload

    def list_tools(self) -> dict | list | None:
        raw, _ = self._post("tools/list", {}, request_id=2)
        return parse_payload(raw)

    def call_tool(self, name: str, arguments: dict) -> dict | list | None:
        raw, _ = self._post(
            "tools/call", {"name": name, "arguments": arguments}, request_id=3
        )
        return parse_payload(raw)


def cmd_list(client: MCPClient) -> int:
    init = client.initialize()
    print("=== initialize ===")
    print(json.dumps(init, indent=2))
    print("SESSION ID:", client.session_id)
    tools = client.list_tools()
    print("=== tools/list ===")
    print(json.dumps(tools, indent=2))
    return 0


def cmd_call(client: MCPClient, name: str, args_json: str) -> int:
    try:
        arguments = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as exc:
        print(f"--args is not valid JSON: {exc}", file=sys.stderr)
        return 2
    client.initialize()
    print(f"=== tools/call {name} ===")
    result = client.call_tool(name, arguments)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Probe an MCP Streamable HTTP server.")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"MCP endpoint URL (default: {DEFAULT_URL})")
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    parser.add_argument("--timeout", type=float, default=20.0, help="request timeout in seconds")
    parser.add_argument("--token", default=None,
                        help="bearer token; if omitted, read from env var MCP_TOKEN")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list available tools")
    call_parser = sub.add_parser("call", help="call a tool")
    call_parser.add_argument("name", help="tool name")
    call_parser.add_argument("--args", default="{}", help="tool arguments as a JSON object string")

    ns = parser.parse_args(argv)
    token = ns.token or os.environ.get("MCP_TOKEN") or None
    client = MCPClient(ns.url, insecure=ns.insecure, timeout=ns.timeout, token=token)

    if ns.command == "list":
        return cmd_list(client)
    if ns.command == "call":
        return cmd_call(client, ns.name, ns.args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
