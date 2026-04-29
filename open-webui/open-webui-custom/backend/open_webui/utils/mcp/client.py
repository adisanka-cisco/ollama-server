import asyncio
import logging
from contextlib import AsyncExitStack
from typing import Optional

import anyio
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from open_webui.env import AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL


log = logging.getLogger(__name__)


def create_httpx_client(headers=None, timeout=None, auth=None, verify=True):
    """Create an httpx AsyncClient with the requested SSL and header settings."""
    kwargs = {
        "follow_redirects": True,
        "verify": verify,
    }
    if timeout is not None:
        kwargs["timeout"] = timeout
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


class MCPClient:
    def __init__(self):
        self.session: Optional[ClientSession] = None
        self.exit_stack: Optional[AsyncExitStack] = None
        self._disconnect_lock = asyncio.Lock()

    async def connect(self, url: str, headers: Optional[dict] = None):
        if self.session is not None and self.exit_stack is not None:
            return

        exit_stack = AsyncExitStack()

        try:
            http_client = create_httpx_client(
                headers=headers,
                verify=AIOHTTP_CLIENT_SESSION_TOOL_SERVER_SSL,
            )
            self._streams_context = streamable_http_client(
                url,
                http_client=http_client,
            )

            transport = await exit_stack.enter_async_context(self._streams_context)
            read_stream, write_stream, _ = transport

            self._session_context = ClientSession(read_stream, write_stream)
            self.session = await exit_stack.enter_async_context(self._session_context)
            with anyio.fail_after(10):
                await self.session.initialize()

            self.exit_stack = exit_stack
        except Exception:
            self.session = None
            self.exit_stack = None
            try:
                await exit_stack.aclose()
            except Exception as cleanup_error:
                log.debug(f"Error cleaning up failed MCP connect: {cleanup_error}")
            raise

    async def list_tool_specs(self) -> Optional[dict]:
        if not self.session:
            raise RuntimeError("MCP client is not connected.")

        result = await self.session.list_tools()
        tools = result.tools

        tool_specs = []
        for tool in tools:
            name = tool.name
            description = tool.description
            input_schema = tool.inputSchema

            tool_specs.append(
                {
                    "name": name,
                    "description": description,
                    "parameters": input_schema,
                }
            )

        return tool_specs

    async def call_tool(
        self, function_name: str, function_args: dict
    ) -> Optional[dict]:
        if not self.session:
            raise RuntimeError("MCP client is not connected.")

        result = await self.session.call_tool(function_name, function_args)
        if not result:
            raise Exception("No result returned from MCP tool call.")

        result_dict = result.model_dump(mode="json")
        result_content = result_dict.get("content", {})

        if result.isError:
            raise Exception(result_content)

        return result_content

    async def list_resources(self, cursor: Optional[str] = None) -> Optional[dict]:
        if not self.session:
            raise RuntimeError("MCP client is not connected.")

        result = await self.session.list_resources(cursor=cursor)
        if not result:
            raise Exception("No result returned from MCP list_resources call.")

        result_dict = result.model_dump()
        return result_dict.get("resources", [])

    async def read_resource(self, uri: str) -> Optional[dict]:
        if not self.session:
            raise RuntimeError("MCP client is not connected.")

        result = await self.session.read_resource(uri)
        if not result:
            raise Exception("No result returned from MCP read_resource call.")

        return result.model_dump()

    async def disconnect(self):
        async with self._disconnect_lock:
            exit_stack = self.exit_stack
            self.exit_stack = None
            self.session = None

            if exit_stack is None:
                return

            try:
                await exit_stack.aclose()
            except Exception as e:
                log.debug(f"Error disconnecting MCP client: {e}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.disconnect()
