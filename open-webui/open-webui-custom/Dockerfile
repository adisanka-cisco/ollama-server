ARG OPEN_WEBUI_BASE_IMAGE=ghcr.io/open-webui/open-webui:main
FROM ${OPEN_WEBUI_BASE_IMAGE}

COPY backend/open_webui/routers/ollama.py /app/backend/open_webui/routers/ollama.py
COPY backend/open_webui/utils/tools.py /app/backend/open_webui/utils/tools.py
COPY backend/open_webui/utils/middleware.py /app/backend/open_webui/utils/middleware.py
COPY backend/open_webui/utils/mcp/client.py /app/backend/open_webui/utils/mcp/client.py
COPY scripts/patch_main.py /tmp/patch_main.py
RUN python /tmp/patch_main.py /app/backend/open_webui/main.py && rm /tmp/patch_main.py
