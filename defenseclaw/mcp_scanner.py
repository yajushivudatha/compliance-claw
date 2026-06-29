import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, TypedDict

logger = logging.getLogger(__name__)

# ── Known-good tool whitelist ─────────────────────────────────────────────────
# These are the exact tools the Criterion kubernetes-mcp-server should expose.
# Any tool NOT in this list is flagged as unexpected.

KNOWN_GOOD_TOOLS = {
    "configuration_view",
    "events_list",
    "namespaces_list",
    "nodes_log",
    "nodes_stats_summary",
    "nodes_top",
    "pods_delete",
    "pods_exec",
    "pods_get",
    "pods_list",
    "pods_list_in_namespace",
    "pods_log",
    "pods_run",
    "pods_top",
    "resources_create_or_update",
    "resources_delete",
    "resources_get",
    "resources_list",
    "resources_scale",
}

MINIMUM_EXPECTED_TOOLS = 15   # flag if server suddenly exposes fewer
MAXIMUM_EXPECTED_TOOLS = 30   # flag if server exposes far more than expected

class MCPIssue(TypedDict):
    severity:    str
    rule:        str
    description: str

class MCPScanResult(TypedDict):
    endpoint:         str
    status:           str    # PASS / FAIL / WARN
    tool_count:       int
    expected_count:   int
    unexpected_tools: List[str]
    missing_tools:    List[str]
    issues:           List[MCPIssue]
    timestamp:        str

# ── Scanner ───────────────────────────────────────────────────────────────────

async def _scan_mcp_async(mcp_url: str,
                          timeout: float = 5.0) -> MCPScanResult:
    """
    Connects to the MCP server with a timeout and verifies its tool manifest.
    Flags unexpected tools, missing tools, and connection failures.
    """
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession

    issues: List[MCPIssue] = []
    tool_names: List[str]  = []

    try:
        async with asyncio.timeout(timeout):
            async with sse_client(mcp_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools_response = await session.list_tools()
                    tool_names = [t.name for t in tools_response.tools]

        # Check tool count
        if len(tool_names) < MINIMUM_EXPECTED_TOOLS:
            issues.append(MCPIssue(
                severity="HIGH", rule="TOO_FEW_TOOLS",
                description=f"MCP server returned only {len(tool_names)} tools — "
                            f"expected at least {MINIMUM_EXPECTED_TOOLS}. "
                            f"Possible server compromise or misconfiguration."
            ))

        if len(tool_names) > MAXIMUM_EXPECTED_TOOLS:
            issues.append(MCPIssue(
                severity="MEDIUM", rule="TOO_MANY_TOOLS",
                description=f"MCP server returned {len(tool_names)} tools — "
                            f"exceeds expected maximum of {MAXIMUM_EXPECTED_TOOLS}. "
                            f"Unexpected tools may indicate supply chain attack."
            ))

        # Check for unexpected tools (not in whitelist)
        unexpected = [t for t in tool_names if t not in KNOWN_GOOD_TOOLS]
        if unexpected:
            issues.append(MCPIssue(
                severity="HIGH", rule="UNEXPECTED_TOOLS",
                description=f"Tools not in known-good whitelist: {unexpected}. "
                            f"Verify these are legitimate before proceeding."
            ))

        # Check for missing critical tools
        critical_tools = {"pods_list", "resources_get", "resources_list",
                          "namespaces_list"}
        missing = [t for t in critical_tools if t not in tool_names]
        if missing:
            issues.append(MCPIssue(
                severity="HIGH", rule="MISSING_CRITICAL_TOOLS",
                description=f"Critical tools missing from server: {missing}. "
                            f"CIS checks cannot run without these."
            ))

        # Check tool descriptions for prompt injection patterns
        prompt_injection_keywords = [
            "ignore previous", "disregard", "jailbreak",
            "override instructions", "forget your"
        ]
        for tool in tools_response.tools:
            desc_lower = (tool.description or "").lower()
            for keyword in prompt_injection_keywords:
                if keyword in desc_lower:
                    issues.append(MCPIssue(
                        severity="CRITICAL", rule="PROMPT_INJECTION",
                        description=f"Tool '{tool.name}' description contains "
                                    f"potential prompt injection: '{keyword}'"
                    ))

        # Determine status
        critical_issues = [i for i in issues if i["severity"] == "CRITICAL"]
        high_issues     = [i for i in issues if i["severity"] == "HIGH"]

        status = "FAIL" if (critical_issues or high_issues) else \
                 "WARN" if issues else "PASS"

        return MCPScanResult(
            endpoint=mcp_url,
            status=status,
            tool_count=len(tool_names),
            expected_count=len(KNOWN_GOOD_TOOLS),
            unexpected_tools=unexpected,
            missing_tools=missing,
            issues=issues,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    except asyncio.TimeoutError:
        return MCPScanResult(
            endpoint=mcp_url,
            status="FAIL",
            tool_count=0,
            expected_count=len(KNOWN_GOOD_TOOLS),
            unexpected_tools=[],
            missing_tools=list(KNOWN_GOOD_TOOLS),
            issues=[MCPIssue(
                severity="CRITICAL", rule="CONNECTION_TIMEOUT",
                description=f"MCP server did not respond within {timeout}s. "
                            f"Server may be down, unreachable, or blocking connections."
            )],
            timestamp=datetime.now(timezone.utc).isoformat()
        )
    except Exception as e:
        return MCPScanResult(
            endpoint=mcp_url,
            status="FAIL",
            tool_count=0,
            expected_count=len(KNOWN_GOOD_TOOLS),
            unexpected_tools=[],
            missing_tools=[],
            issues=[MCPIssue(
                severity="CRITICAL", rule="CONNECTION_ERROR",
                description=f"Failed to connect to MCP server: {str(e)}"
            )],
            timestamp=datetime.now(timezone.utc).isoformat()
        )


def scan_mcp(mcp_url: str = None, timeout: float = 5.0) -> MCPScanResult:
    if mcp_url is None:
        mcp_url = os.getenv("K8S_MCP_URL", "")

    # In test/mock mode, skip MCP scan — cluster not reachable from CI
    if os.getenv("USE_MOCK_DATA", "true").lower() == "true":
        return MCPScanResult(
            endpoint=mcp_url,
            status="PASS",
            tool_count=19,
            expected_count=len(KNOWN_GOOD_TOOLS),
            unexpected_tools=[],
            missing_tools=[],
            issues=[],
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    logger.info(f"[DefenseClaw] MCP Scanner scanning: {mcp_url}")
    result = asyncio.run(_scan_mcp_async(mcp_url, timeout))
    logger.info(f"[DefenseClaw] MCP Scan: {result['status']} — "
                f"{result['tool_count']} tools, "
                f"{len(result['unexpected_tools'])} unexpected")
    return result