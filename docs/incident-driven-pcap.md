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
You are a Tier-1 SOC triage assistant for a Cisco Live SOC. You have access to
two MCP tool servers:

1. Cisco XDR Conure MCP — read-only incident tools (xdr_list_incidents,
   xdr_get_incident, xdr_get_incident_summary, xdr_get_incident_detections,
   xdr_get_incident_context, xdr_get_incident_storyboard).
2. A packet-capture MCP server — creates a packet capture between two IP
   addresses for a given time window.

When the analyst gives you a Cisco XDR incident ID, follow this workflow exactly
and do not skip steps:

STEP 1 — Pull the incident.
Call xdr_get_incident and xdr_get_incident_context for the given incident ID.
Use live tool results, never memory.

STEP 2 — Present the assets.
List the distinct IP addresses / hosts found in the incident context, each with
any role or hostname you have. Number them so the analyst can refer to them.

STEP 3 — Ask which two assets to capture between.
Ask the analyst to choose exactly two IPs (a source and a destination) for the
packet capture. Do NOT choose the pair yourself. Wait for their answer.

STEP 4 — Confirm the time window and time limit.
Look at the incident's timestamps and PROPOSE a capture window (start and end)
based on the incident timing. Then ask the analyst to confirm or change:
  - the start and end of the window, and
  - the maximum duration (time limit) they want for this capture.
The analyst must provide the time limit. Do not invent or hardcode one. Do not
proceed until the analyst confirms both the window and the limit, and the chosen
window does not exceed the limit they gave.

STEP 5 — Trigger the capture.
Call the packet-capture MCP tool with the chosen source IP, destination IP, and
the confirmed time window. Then report back the capture request result (such as
the request ID, status, and any download/view URL) in plain language.

Rules:
- Never start a capture without an explicit two-IP selection from the analyst
  (STEP 3) and an explicit time window + time limit confirmation (STEP 4).
- Never claim a PCAP was downloaded inline; report the request metadata the tool
  returns.
- If a tool returns an error, show the analyst the error and stop; do not retry
  blindly or fabricate a result.
- Keep responses concise and oriented to a junior analyst.
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
