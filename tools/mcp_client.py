import os
import json
import asyncio
import logging
from typing import Any, Optional
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

KUBECONFIG = os.getenv("KUBECONFIG", "")


async def _run_call(tool_name: str, args: dict):
    """
    Opens a fresh kubernetes-mcp-server subprocess via stdio, makes one call,
    and cleanly closes everything within the same event loop.
    This avoids cross-event-loop cleanup errors that occur when trying to
    persist a stdio session across separate asyncio.run() calls.
    """
    from mcp.client.stdio import stdio_client, StdioServerParameters
    from mcp.client.session import ClientSession

    if not KUBECONFIG or not os.path.exists(KUBECONFIG):
        raise RuntimeError(
            f"KUBECONFIG not found at: {KUBECONFIG}. "
            f"Set KUBECONFIG in .env to a valid kubeconfig file path."
        )

    server_params = StdioServerParameters(
        command="npx",
        args=["-y", "kubernetes-mcp-server@latest"],
        env={**os.environ, "KUBECONFIG": KUBECONFIG}
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            if tool_name == "__list_tools__":
                result = await session.list_tools()
                return [{"name": t.name, "description": t.description}
                        for t in result.tools]
            else:
                result = await session.call_tool(tool_name, args)
                return result.content[0].text


# ── Public sync interface ──────────────────────────────────────────────────────

def list_tools() -> list:
    """Returns the full list of tools kubernetes-mcp-server exposes."""
    logger.info("[MCP] Listing tools via kubernetes-mcp-server (stdio)")
    return asyncio.run(_run_call("__list_tools__", {}))


def call(tool_name: str, args: Optional[dict] = None) -> Any:
    """Calls any tool kubernetes-mcp-server exposes. Opens a clean session per call."""
    if args is None:
        args = {}
    logger.info(f"[MCP] Calling {tool_name} with {args}")
    return asyncio.run(_run_call(tool_name, args))


def call_json(tool_name: str, args: Optional[dict] = None) -> Any:
    """Same as call(), but parses the response as JSON automatically."""
    raw = call(tool_name, args)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw