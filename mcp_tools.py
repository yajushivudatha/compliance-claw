import asyncio
from mcp.client.sse import sse_client
from mcp.client.session import ClientSession

MCP_URL = "http://ab21e8af68-cn.pods.criterionnetworks.com:20743/sse"

async def explore_cluster():
    async with sse_client(MCP_URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("✅ Connected to kubernetes-mcp-server")

            # List all available tools
            tools = await session.list_tools()
            print(f"\n📦 Available tools: {len(tools.tools)}")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description}")

            # Get namespaces
            print("\n🔍 Namespaces in cluster:")
            result = await session.call_tool("namespaces_list", {})
            print(result.content[0].text)

            # Get nodes
            print("\n🖥️  Nodes in cluster:")
            result = await session.call_tool("nodes_list", {})
            print(result.content[0].text)

            # Get pods across all namespaces
            print("\n📦 Pods (all namespaces):")
            result = await session.call_tool("pods_list", {})
            print(result.content[0].text)

            # Get warnings
            print("\n⚠️  Warning events:")
            result = await session.call_tool("events_list", {"warnings_only": True})
            print(result.content[0].text)

asyncio.run(explore_cluster())