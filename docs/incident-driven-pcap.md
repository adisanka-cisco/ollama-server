# Incident-driven packet capture

This runbook describes the SOC workflow where an analyst gives the chatbot a
Cisco XDR incident ID, the model pulls the incident's assets from the **Cisco
XDR Conure MCP**, and then triggers a packet capture between two of those assets
on an **external packet-capture MCP server**.

It is **prompt-driven orchestration**: there is no new server code in this repo.
The model is given a system prompt (the playbook below) and access to two MCP
tool servers, and it walks the analyst through the chain.

## Components

| Component | Where it runs | How it is wired |
| --- | --- | --- |
| Cisco XDR Conure MCP (`mcp-xdr`) | Compose sidecar, internal `http://mcp-xdr:8002/mcp/` | Already in this repo |
| External packet-capture MCP | External host `http://172.16.0.70:8080/mcp` | Registered in the Open WebUI admin UI (no auth) |
| Open WebUI + model | Compose stack on the GPU host | Runs the playbook system prompt |

The in-repo `mcp-endace-vault` sidecar has been removed; packet capture is
handled entirely by the external MCP server above.

## One-time setup

### 1. Register the packet-capture MCP in Open WebUI

1. Sign in to Open WebUI as an admin.
2. Go to **Admin Settings -> Tools / Manage Tool Servers**.
3. Add a new MCP server:
   - **URL:** `http://172.16.0.70:8080/mcp`
   - **Auth:** None
4. Save and confirm the server's tools are discovered.

Verify reachability from the Open WebUI host first:

```bash
curl -i http://172.16.0.70:8080/mcp
```

An empty body to a plain GET is normal — MCP Streamable HTTP expects a session
POST, so a reachable server is enough confirmation here.

> Adjust the exact tool/argument names in the playbook below to match the tools
> the packet-capture MCP actually exposes once they are discovered in the UI.

### 2. Apply the playbook system prompt

Apply the system prompt below to the model used for SOC triage. In Open WebUI
this can be set as the model's **System Prompt** (Workspace -> Models) or as a
reusable **Prompt** preset the analyst selects before starting.

## The workflow (what the analyst sees)

1. Analyst gives an **incident ID** (for example `incident-<uuid>`).
2. Model calls XDR tools to fetch the incident and its assets.
3. Model lists the discovered IPs/assets and **asks which two** to capture
   between. It never guesses the pair on its own.
4. Model proposes a capture **time window** derived from the incident, and asks
   the analyst to confirm the window **and** the time limit (maximum duration).
   The analyst supplies the time limit; the model does not invent one.
5. Model calls the packet-capture MCP with the chosen source IP, destination IP,
   and confirmed window, then reports the request result/ID back.

## System prompt (playbook)

Paste the following as the SOC model's system prompt:

```text
You are a Tier-1 SOC triage assistant for a Cisco Live SOC. You are connected to
MCP tool servers and can see all of their tools. Always prefer calling a tool
over answering from memory. Discover and use whatever tools are available; the
sections below give exact usage rules for the current key tools, but new tools
may appear and you should use them when relevant.

== Incident-driven packet capture workflow ==
When the analyst gives you a Cisco XDR incident ID, follow these steps in order:

STEP 1 — Pull incident context.
Call the tool `xdr_get_incident_context` with {"incident_id": "<the id>"}. This
returns the hosts, IPs, and observables tied to the incident. Use live results.

STEP 2 — Present the assets.
List the distinct IP addresses found in the context, numbered, with any hostname
or role you have for each.

STEP 3 — Ask which two assets to capture between.
Ask the analyst to choose exactly two IPs — a source and a destination. Do NOT
choose the pair yourself. Wait for their answer.

STEP 4 — Confirm the time window and time limit.
Propose a capture window from the incident timing, then ask the analyst to
confirm or change the start, the end, and the maximum duration (time limit). The
analyst supplies the time limit; do not invent one. Do not proceed until both the
window and the limit are confirmed and the window does not exceed the limit.

STEP 5 — Trigger the capture with the `Packet_Decode` tool.
Call `Packet_Decode` with EXACTLY these argument rules:
  - "ip_conv": the two IPs as a single string "SRC & DST", for example
    "192.168.0.5 & 10.1.2.9". This is the required IP-conversation filter.
  - For an explicit window, pass "start" and "end" as RFC3339 UTC strings,
    e.g. "start": "2026-05-30T00:02:01Z", "end": "2026-05-30T00:04:01Z".
  - Use EITHER start+end OR "reltime" (e.g. "reltime": "2m"), NEVER both.
    reltime format: up to two digits followed by s, m, h, or d.
  - Do not use any other parameter names. There is no "sip"/"dip"/"ip_sip".
Then report the capture request result (request id, status, any URL) in plain
language.

== General tool rules (apply to every tool) ==
- Read each tool's description and input schema and fill arguments exactly as the
  schema requires; never invent parameter names or pass placeholder values like
  "source ip & destination ip".
- Never start a capture without an explicit two-IP selection (STEP 3) and a
  confirmed window + time limit (STEP 4).
- Never claim a PCAP was downloaded inline; report the request metadata returned.
- If a tool returns an error, show the analyst the error and stop; do not retry
  blindly or fabricate a result.
- Keep responses concise and oriented to a junior analyst.

== Extending this (for future maintainers) ==
To add a new capability, register its MCP server in Open WebUI and, if it needs
specific argument conventions, add a short rules block here describing the tool
name and its exact arguments. The model already sees all registered tools; this
section only encodes non-obvious usage rules.
```

## Testing from the CLI (no UI required)

When the Open WebUI front end is not reachable (for example you only have shell
access to the host), two dependency-free scripts under `scripts/` let you
discover MCP tools and drive the full Ollama + MCP flow directly. Both use only
the Python standard library, so they run on a locked-down host.

### 1. Discover the MCP tools

`scripts/mcp_probe.py` performs the MCP handshake (initialize ->
notifications/initialized -> tools/list) and prints the server's real tool names
and parameter schemas. The capture MCP is HTTPS and may use a self-signed
certificate, so pass `--insecure`.

```bash
cd ~/ollama-server
# list the packet-capture MCP's tools
python3 scripts/mcp_probe.py --url https://172.16.0.70:8080/mcp --insecure list

# call one tool directly (args are a JSON object; field names come from the spec)
python3 scripts/mcp_probe.py --url https://172.16.0.70:8080/mcp --insecure \
  call <tool_name> --args '{"sip":"10.1.1.5","dip":"10.1.1.9","reltime":"15m"}'
```

### 2. Run the Ollama + MCP agent loop

`scripts/soc_agent_cli.py` replicates what Open WebUI does internally: it
discovers tools from one or more MCP servers, exposes them to a local Ollama
model via Ollama's tool-calling API, and executes any tool the model calls.

```bash
# just discover tools across both servers and exit (no model needed)
python3 scripts/soc_agent_cli.py --list-tools \
  --mcp endace=https://172.16.0.70:8080/mcp \
  --mcp xdr=http://mcp-xdr:8002/mcp/ --insecure

# one-shot prompt against the capture MCP
python3 scripts/soc_agent_cli.py --model llama3.1:8b \
  --mcp endace=https://172.16.0.70:8080/mcp --insecure \
  --prompt "List your packet-capture tools, then capture traffic between 10.1.1.5 and 10.1.1.9 for the last 15 minutes."

# interactive end-to-end flow (XDR incident -> assets -> capture)
python3 scripts/soc_agent_cli.py --model llama3.1:8b \
  --mcp xdr=http://mcp-xdr:8002/mcp/ \
  --mcp endace=https://172.16.0.70:8080/mcp --insecure
# then type: For XDR incident incident-<id>, pull the assets and capture between two of them.
```

Tool-call activity is logged to stderr (`-> tool call: ...` / `<- result ...`)
so you can confirm the model actually invoked the MCP servers rather than
answering from memory.

Notes:
- `mcp-xdr:8002` is a Docker-internal hostname. It resolves from inside the
  `open-webui` container but not necessarily from the host shell; if the host
  cannot reach it, run the script from inside the container or use the address
  the sidecar is published on.
- `llama3.1:8b` tool-calling reliability is limited. `--list-tools` validates
  connectivity independently of the model, which is the most reliable check.

## Notes for deployment on the other network

- This document and the repo changes (removing the in-repo Endace sidecar) come
  down with the branch clone. The packet-capture MCP registration is **not** in
  the repo — it must be added in the Open WebUI admin UI on each deployment.
- Confirm the deployment host can route to `172.16.0.70:8080` before relying on
  the workflow.
- After discovering the packet-capture MCP's tools in the UI, update the tool
  and argument names referenced in the playbook prompt to match exactly.
