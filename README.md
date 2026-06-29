# Workload Security Compliance Agent
**Cisco Live — ReadyOps Platform — Agent #20**

An agentic AI system that validates CIS Kubernetes Benchmark v2.0.0 compliance
across enterprise workload security platforms and generates signed compliance
certificate reports automatically.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    READYOPS PLATFORM                             │
│                  POST /scan (HTTP Request)                       │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                     FASTAPI SERVER                               │
│                      main.py :8000                               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  LANGGRAPH AGENT                                 │
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────────────┐    │
│  │   Node 1    │───▶│   Node 2    │───▶│     Node 3       │    │
│  │  Security   │    │  RAG Query  │    │  AI Summary      │    │
│  │  Checks     │    │  (ChromaDB) │    │  (Groq LLM)      │    │
│  └──────┬──────┘    └─────────────┘    └──────────────────┘    │
│         │                                                        │
└─────────┼────────────────────────────────────────────────────── ┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  4 TOOL FUNCTIONS (MCP)                          │
│                                                                  │
│  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────────┐  │
│  │ API Server │  │    etcd    │  │   RBAC   │  │    Pod     │  │
│  │  CIS 1.2   │  │  CIS 2.x   │  │ CIS 5.1  │  │  Security  │  │
│  │  6 checks  │  │  6 checks  │  │ 6 checks │  │  CIS 5.2   │  │
│  └────────────┘  └────────────┘  └──────────┘  └────────────┘  │
│                         │                                        │
│                         ▼                                        │
│              Kubernetes Cluster (MCP Server)                     │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  RAG PIPELINE                                     │
│                                                                  │
│  ┌─────────────────┐   ┌────────────────┐   ┌───────────────┐  │
│  │ CIS K8s v2.0.0  │   │  NIST 800-53   │   │  NSA / CISA   │  │
│  │   1233 chunks   │   │  ~3400 chunks  │   │  ~800 chunks  │  │
│  └─────────────────┘   └────────────────┘   └───────────────┘  │
│                    ChromaDB Vector Store                         │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  OUTPUT                                          │
│                                                                  │
│   JSON Response ──────────────────────────▶ ReadyOps Platform   │
│   PDF Certificate ────────────────────────▶ ServiceNow Filing   │
│   LangSmith Traces ───────────────────────▶ Observability       │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│               DEPLOYMENT                                         │
│         Docker Container → Cloudflare Tunnel → Public URL        │
└─────────────────────────────────────────────────────────────────┘
```
---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent Framework | LangGraph StateGraph |
| LLM | Groq (llama-3.3-70b-versatile) |
| RAG / Vector DB | ChromaDB + HuggingFace Embeddings |
| Observability | LangSmith |
| Cluster Access | MCP Server (kubernetes-mcp-server) |
| API | FastAPI + Uvicorn |
| Deployment | Docker + Cloudflare Tunnel |
| Report | ReportLab PDF |

---

## Standards Covered

- CIS Kubernetes Benchmark v2.0.0
- Sections: 1.2 API Server · 2.x etcd · 5.1 RBAC · 5.2 Pod Security

---

## Project Structure

```
compliance-agent/
├── agents/
│   └── compliance_agent.py      # LangGraph StateGraph — 3 nodes
├── tools/
│   └── kubernetes_tools.py      # 4 @tool functions via MCP
├── rag/
│   ├── ingest.py                # PDF → ChromaDB ingestion (CIS + NIST + NSA)
│   └── retriever.py             # Semantic search over compliance standards
├── reports/
│   └── pdf_generator.py         # ReportLab PDF certificate generator
├── data/
│   ├── cis_k8s.pdf              # CIS Kubernetes Benchmark v2.0.0
│   ├── nist_800_53.pdf          # NIST SP 800-53 Rev 5
│   └── nsa_k8s.pdf              # NSA/CISA K8s Hardening Guide
├── main.py                      # FastAPI server — POST /scan, GET /report
├── mcp_tools.py                 # MCP cluster connection test
├── Dockerfile                   # Container definition
├── docker-compose.yml           # Service orchestration
├── requirements.txt             # Python dependencies
└── .env                         # API keys (never committed to Git)
```

---

## Setup Instructions

### 1. Clone the repo
```bash
git clone https://your-bitbucket-url/criterion-compliance-agent.git
cd criterion-compliance-agent
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
Create a `.env` file:
```bash
GROQ_API_KEY=your_groq_key
LANGCHAIN_API_KEY=your_langsmith_key
LANGCHAIN_TRACING_V2=true
LANGCHAIN_PROJECT=compliance-agent
K8S_MCP_URL=http://your-mcp-server/sse
```


### 5. Ingest CIS Benchmark into ChromaDB
```bash
python rag/ingest.py
```

### 6. Run the agent directly
```bash
python agents/compliance_agent.py
```

### 7. Run the FastAPI server
```bash
uvicorn main:app --reload --port 8000
```

### 8. Run via Docker
```bash
docker compose up --build
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Service info |
| GET | `/health` | Health check |
| POST | `/scan` | Trigger compliance scan |
| GET | `/report/{scan_id}/pdf` | Download PDF certificate |
| GET | `/scans` | List all scans |

### Example scan request
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"cluster_name": "criterion-k8s", "triggered_by": "readyops"}'
```

### Example response
```json
{
  "scan_id": "SCAN-20260523-094724",
  "status": "NON-COMPLIANT",
  "total_passed": 11,
  "total_failed": 14,
  "compliance_score": 44,
  "cluster_name": "criterion-k8s",
  "pdf_download_url": "/report/SCAN-20260523-094724/pdf"
}
```

---

## Connecting to Real Kubernetes Cluster

This agent connects to a live Kubernetes cluster via MCP server.
Set `K8S_MCP_URL` in your `.env` to the MCP server endpoint.

To test connectivity:
```bash
python mcp_tools.py
```

When connected, the agent checks real cluster configurations instead of mock data.
Switch `tools/kubernetes_tools.py` from mock to real MCP calls.

---

## ReadyOps Integration

This agent is designed as Agent #20 in the Criterion Networks ReadyOps platform.

**Integration endpoint:**
POST https://your-cloudflare-url.trycloudflare.com/scan

**Request body:**
```json
{
  "cluster_name": "production-cluster",
  "triggered_by": "readyops-platform"
}
```

**The agent returns** a full JSON compliance report plus a PDF download URL
that can be filed automatically into ServiceNow.

---

## LangSmith Observability

All agent runs are traced in LangSmith under the `compliance-agent` project.
Every node execution, tool call, RAG query, and LLM prompt is recorded with
timing and full input/output data.

---

## Built By

Yajushi Vudatha — Summer Intern
