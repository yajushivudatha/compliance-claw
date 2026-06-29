from dotenv import load_dotenv
import os

load_dotenv()

groq_key = os.getenv("GROQ_API_KEY")
if groq_key:
    print(f"✅ Groq key found: {groq_key[:8]}...")
else:
    print("❌ Groq key NOT found — check your .env file")

langsmith_key = os.getenv("LANGCHAIN_API_KEY")
if langsmith_key:
    print(f"✅ LangSmith key found: {langsmith_key[:8]}...")
else:
    print("❌ LangSmith key NOT found — check your .env file")

project = os.getenv("LANGCHAIN_PROJECT")
tracing = os.getenv("LANGCHAIN_TRACING_V2")
mock = os.getenv("USE_MOCK_DATA")
mcp_url = os.getenv("K8S_MCP_URL")

print(f"✅ LangSmith project: {project}")
print(f"✅ Tracing enabled: {tracing}")
print(f"✅ Mock data mode: {mock}")
print(f"✅ MCP URL configured: {'Yes' if mcp_url else 'NO — add K8S_MCP_URL to .env'}")