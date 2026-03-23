import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(message)s",
)
LOGGER = logging.getLogger("aidefense_proxy")

app = FastAPI()

AIDEFENSE_API_KEY = os.environ["AIDEFENSE_API_KEY"]
AIDEFENSE_BASE_URL = os.getenv(
    "AIDEFENSE_BASE_URL",
    "https://us.api.inspect.aidefense.security.cisco.com",
).rstrip("/")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
PROXY_PORT = int(os.getenv("AIDEFENSE_PROXY_PORT", "8001"))
REQUEST_TIMEOUT = httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=30.0)
FAIL_OPEN_ERROR_CODES = {408, 429, 500, 502, 503, 504}
SAFE_BLOCK_MESSAGE = "This request was blocked by Cisco AI Defense policy. Reference: {ref}"
OPEN_WEBUI_TASK_HEADER = "x-openwebui-task"


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "port": str(PROXY_PORT)}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_event(stage: str, transaction_id: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"stage": stage, "client_transaction_id": transaction_id}
    payload.update(fields)
    LOGGER.info(json.dumps(payload, sort_keys=True))


def request_headers_for_forward(request: Request) -> dict[str, str]:
    excluded = {
        "host",
        "content-length",
        "connection",
        "accept-encoding",
        OPEN_WEBUI_TASK_HEADER,
    }
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in excluded
    }


def response_headers_for_client(headers: httpx.Headers) -> dict[str, str]:
    excluded = {"content-length", "connection", "content-encoding", "transfer-encoding"}
    return {key: value for key, value in headers.items() if key.lower() not in excluded}


def usable_user_id(headers: Any) -> str | None:
    for header_name in (
        "x-user-id",
        "x-forwarded-user",
        "x-auth-request-user",
        "remote-user",
    ):
        value = headers.get(header_name)
        if value:
            return value
    return None


def normalize_messages(raw_messages: Any) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    if not isinstance(raw_messages, list):
        return normalized
    for item in raw_messages:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "")).strip()
        content = item.get("content")
        if not role:
            continue
        if content is None:
            content = ""
        normalized.append({"role": role, "content": str(content)})
    return normalized


def messages_for_generate(payload: dict[str, Any]) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    prompt = payload.get("prompt")
    if prompt is not None:
        messages.append({"role": "user", "content": str(prompt)})
    return messages


def prompt_messages(endpoint: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    if endpoint == "chat":
        return normalize_messages(payload.get("messages"))
    return messages_for_generate(payload)


def internal_task_name(request: Request) -> str | None:
    task = request.headers.get(OPEN_WEBUI_TASK_HEADER)
    if task is None:
        return None
    task_str = str(task).strip()
    return task_str or None


def latest_user_message(messages: list[dict[str, str]]) -> list[dict[str, str]]:
    for message in reversed(messages):
        if message.get("role") == "user":
            return [{"role": "user", "content": message.get("content", "")}]
    return []


def ingress_messages_for_inspection(endpoint: str, payload: dict[str, Any]) -> list[dict[str, str]]:
    if endpoint == "chat":
        return latest_user_message(prompt_messages(endpoint, payload))
    return prompt_messages(endpoint, payload)


def assistant_text(endpoint: str, payload: dict[str, Any]) -> str:
    if endpoint == "chat":
        message = payload.get("message") or {}
        if isinstance(message, dict):
            return str(message.get("content", ""))
        return ""
    return str(payload.get("response", ""))


def ollama_chat_block_payload(model: str, message: str) -> dict[str, Any]:
    return {
        "model": model,
        "created_at": utc_now(),
        "message": {"role": "assistant", "content": message},
        "done": True,
        "done_reason": "stop",
        "total_duration": 0,
        "load_duration": 0,
        "prompt_eval_count": 0,
        "prompt_eval_duration": 0,
        "eval_count": 0,
        "eval_duration": 0,
    }


def ollama_generate_block_payload(model: str, message: str) -> dict[str, Any]:
    return {
        "model": model,
        "created_at": utc_now(),
        "response": message,
        "done": True,
        "done_reason": "stop",
        "total_duration": 0,
        "load_duration": 0,
        "prompt_eval_count": 0,
        "prompt_eval_duration": 0,
        "eval_count": 0,
        "eval_duration": 0,
        "context": [],
    }


def ndjson_bytes(items: list[dict[str, Any]]) -> bytes:
    return b"".join(json.dumps(item).encode("utf-8") + b"\n" for item in items)


def stream_chat_payload(data: dict[str, Any]) -> list[dict[str, Any]]:
    first = {
        "model": data.get("model"),
        "created_at": data.get("created_at", utc_now()),
        "message": data.get("message", {"role": "assistant", "content": ""}),
        "done": False,
    }
    final = {
        "model": data.get("model"),
        "created_at": data.get("created_at", utc_now()),
        "message": {"role": "assistant", "content": ""},
        "done": True,
        "done_reason": data.get("done_reason", "stop"),
        "total_duration": data.get("total_duration", 0),
        "load_duration": data.get("load_duration", 0),
        "prompt_eval_count": data.get("prompt_eval_count", 0),
        "prompt_eval_duration": data.get("prompt_eval_duration", 0),
        "eval_count": data.get("eval_count", 0),
        "eval_duration": data.get("eval_duration", 0),
    }
    return [first, final]


def stream_generate_payload(data: dict[str, Any]) -> list[dict[str, Any]]:
    first = {
        "model": data.get("model"),
        "created_at": data.get("created_at", utc_now()),
        "response": data.get("response", ""),
        "done": False,
    }
    final = {
        "model": data.get("model"),
        "created_at": data.get("created_at", utc_now()),
        "response": "",
        "done": True,
        "done_reason": data.get("done_reason", "stop"),
        "context": data.get("context", []),
        "total_duration": data.get("total_duration", 0),
        "load_duration": data.get("load_duration", 0),
        "prompt_eval_count": data.get("prompt_eval_count", 0),
        "prompt_eval_duration": data.get("prompt_eval_duration", 0),
        "eval_count": data.get("eval_count", 0),
        "eval_duration": data.get("eval_duration", 0),
    }
    return [first, final]


def stream_response_for(endpoint: str, data: dict[str, Any]) -> StreamingResponse:
    events = stream_chat_payload(data) if endpoint == "chat" else stream_generate_payload(data)
    return StreamingResponse(iter([ndjson_bytes(events)]), media_type="application/x-ndjson")


async def inspect_chat(
    messages: list[dict[str, str]],
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    payload = {"messages": messages, "metadata": metadata, "config": {}}
    headers = {
        "X-Cisco-AI-Defense-API-Key": AIDEFENSE_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    url = f"{AIDEFENSE_BASE_URL}/api/v1/inspect/chat"
    transaction_id = metadata["client_transaction_id"]
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        log_event("inspection_fail_open", transaction_id, reason=str(exc), src_app=metadata.get("src_app"), dst_app=metadata.get("dst_app"))
        return None

    if response.status_code == 200:
        body = response.json()
        log_event(
            "inspection_result",
            transaction_id,
            src_app=metadata.get("src_app"),
            dst_app=metadata.get("dst_app"),
            is_safe=body.get("is_safe"),
            severity=body.get("severity"),
            event_id=body.get("event_id"),
            rules=[rule.get("rule_name") for rule in body.get("rules", []) if isinstance(rule, dict)],
        )
        return body

    if response.status_code in FAIL_OPEN_ERROR_CODES:
        log_event(
            "inspection_fail_open",
            transaction_id,
            status_code=response.status_code,
            src_app=metadata.get("src_app"),
            dst_app=metadata.get("dst_app"),
        )
        return None

    raise HTTPException(
        status_code=502,
        detail=f"Cisco AI Defense request failed with status {response.status_code}",
    )


async def forward_to_ollama(
    method: str,
    path: str,
    *,
    headers: dict[str, str],
    json_body: dict[str, Any] | None = None,
    raw_body: bytes | None = None,
) -> httpx.Response:
    url = f"{OLLAMA_BASE_URL}{path}"
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        return await client.request(method, url, headers=headers, json=json_body, content=raw_body)


async def passthrough(request: Request, path: str) -> Response:
    body = await request.body()
    response = await forward_to_ollama(
        request.method,
        path,
        headers=request_headers_for_forward(request),
        raw_body=body,
    )
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=response_headers_for_client(response.headers),
        media_type=response.headers.get("content-type"),
    )


async def protected_ollama_call(endpoint: str, request: Request) -> Response:
    original_payload = await request.json()
    if not isinstance(original_payload, dict):
        raise HTTPException(status_code=400, detail="Expected a JSON object request body")

    transaction_id = str(uuid4())
    user_id = usable_user_id(request.headers)
    model = str(original_payload.get("model", "unknown"))
    requested_stream = bool(original_payload.get("stream", False))
    task_name = internal_task_name(request)
    if task_name:
        log_event(
            "inspection_skipped",
            transaction_id,
            endpoint=endpoint,
            model=model,
            reason="open_webui_internal_task",
            task=task_name,
        )
        ollama_response = await forward_to_ollama(
            "POST",
            f"/api/{endpoint}",
            headers=request_headers_for_forward(request),
            json_body=original_payload,
        )
        return Response(
            content=ollama_response.content,
            status_code=ollama_response.status_code,
            headers=response_headers_for_client(ollama_response.headers),
            media_type=ollama_response.headers.get("content-type"),
        )
    ingress_messages = ingress_messages_for_inspection(endpoint, original_payload)
    if not ingress_messages:
        raise HTTPException(status_code=400, detail="No inspectable messages were found in the request")

    ingress_metadata = {
        "src_app": "open-webui",
        "dst_app": "ollama",
        "client_transaction_id": transaction_id,
    }
    if user_id:
        ingress_metadata["user"] = user_id

    ingress_result = await inspect_chat(ingress_messages, ingress_metadata)
    if ingress_result is not None and ingress_result.get("is_safe") is False:
        log_event("request_blocked", transaction_id, endpoint=endpoint, direction="ingress", model=model)
        block_message = SAFE_BLOCK_MESSAGE.format(ref=transaction_id)
        blocked_payload = (
            ollama_chat_block_payload(model, block_message)
            if endpoint == "chat"
            else ollama_generate_block_payload(model, block_message)
        )
        return (
            stream_response_for(endpoint, blocked_payload)
            if requested_stream
            else JSONResponse(blocked_payload)
        )

    forwarded_payload = dict(original_payload)
    forwarded_payload["stream"] = False
    log_event("ollama_forward", transaction_id, endpoint=endpoint, model=model)
    ollama_response = await forward_to_ollama(
        "POST",
        f"/api/{endpoint}",
        headers=request_headers_for_forward(request),
        json_body=forwarded_payload,
    )
    log_event("ollama_response", transaction_id, endpoint=endpoint, model=model, status_code=ollama_response.status_code)
    if ollama_response.status_code >= 400:
        return Response(
            content=ollama_response.content,
            status_code=ollama_response.status_code,
            headers=response_headers_for_client(ollama_response.headers),
            media_type=ollama_response.headers.get("content-type"),
        )

    response_json = ollama_response.json()
    egress_messages = list(ingress_messages)
    egress_messages.append({"role": "assistant", "content": assistant_text(endpoint, response_json)})

    egress_metadata = {
        "src_app": "ollama",
        "dst_app": "open-webui",
        "client_transaction_id": transaction_id,
    }
    if user_id:
        egress_metadata["user"] = user_id

    egress_result = await inspect_chat(egress_messages, egress_metadata)
    if egress_result is not None and egress_result.get("is_safe") is False:
        log_event("request_blocked", transaction_id, endpoint=endpoint, direction="egress", model=model)
        block_message = SAFE_BLOCK_MESSAGE.format(ref=transaction_id)
        blocked_payload = (
            ollama_chat_block_payload(model, block_message)
            if endpoint == "chat"
            else ollama_generate_block_payload(model, block_message)
        )
        return (
            stream_response_for(endpoint, blocked_payload)
            if requested_stream
            else JSONResponse(blocked_payload)
        )

    return (
        stream_response_for(endpoint, response_json)
        if requested_stream
        else JSONResponse(response_json)
    )


@app.post("/api/chat")
async def chat(request: Request) -> Response:
    return await protected_ollama_call("chat", request)


@app.post("/api/generate")
async def generate(request: Request) -> Response:
    return await protected_ollama_call("generate", request)


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def generic_api(path: str, request: Request) -> Response:
    return await passthrough(request, f"/api/{path}")
