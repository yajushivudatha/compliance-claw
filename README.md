# 🦅 Compliance Claw

<p align="center">
  <img src="https://img.shields.io/badge/Cisco_Live-2026_Demo-blue?style=for-the-badge&logo=cisco&logoColor=white" alt="Cisco Live Banner">
  <img src="https://img.shields.io/badge/Agent_ID-%2320-orange?style=for-the-badge" alt="Agent 20">
  <img src="https://img.shields.io/badge/Framework-LangGraph-green?style=for-the-badge" alt="LangGraph">
  <img src="https://img.shields.io/badge/Security-CIS_Hardened-red?style=for-the-badge" alt="CIS Hardened">
</p>

> **Cisco Live Demo • Agent #20 • ReadyOps Platform Integration**

An enterprise-grade autonomous security compliance agent engineered for the **Criterion Networks ReadyOps Platform**. **Compliance Claw** automatically audits Kubernetes clusters, maps findings against leading security frameworks using a high-performance **ChromaDB RAG pipeline**, generates AI-powered remediation guidance, and produces executive-ready compliance reports.

---

## 🎪 Cisco Live Showcase Overview

This repository serves as the official integration blueprint for **Agent #20** within the Criterion Networks ecosystem. It demonstrates how autonomous AI agents bridge cloud-native infrastructure engineering and enterprise security governance during live platform demonstrations.

---

## 🎮 Live Demo Workflow

```mermaid
sequenceDiagram
    autonumber
    participant RO as ReadyOps Platform
    participant API as FastAPI
    participant LG as LangGraph
    participant MCP as Kubernetes MCP
    participant RAG as ChromaDB
    participant SN as ServiceNow

    RO->>API: POST /scan
    API-->>RO: 202 Accepted
    Note over API,LG: Background task starts
    API->>LG: Invoke workflow
    LG->>MCP: Run Kubernetes security checks
    MCP-->>LG: Cluster findings
    LG->>RAG: Retrieve compliance context
    RAG-->>LG: CIS / NIST / NSA guidance
    LG->>LG: Generate AI summary
    Note over LG: Human-in-the-loop approval
    API->>MCP: Apply approved remediation
    API->>SN: Upload signed PDF report
```

---

## 🏗️ System Architecture

```mermaid
graph TD

A[ReadyOps Platform] --> B[FastAPI Gateway]

B --> C[LangGraph State Machine]

subgraph Workflow
C --> D[Security Checks]
D --> E[RAG Retrieval]
E --> F[AI Summary]
end

D <--> G[Kubernetes MCP]
E <--> H[(ChromaDB)]
F --> I[Groq Llama 3.3]

F --> J[JSON Response]
F --> K[Executive PDF]
C --> L[LangSmith Trace]
```

---

## 💻 Technical Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Agent Framework | LangGraph | Workflow orchestration |
| LLM | Groq Llama 3.3 70B | AI reasoning |
| Vector Database | ChromaDB | Semantic retrieval |
| Embeddings | sentence-transformers | Document embeddings |
| Cluster Access | Kubernetes MCP | Secure Kubernetes access |
| API | FastAPI + Uvicorn | Backend service |
| Observability | LangSmith | Execution tracing |
| Reports | ReportLab | PDF generation |

---

## 📂 Project Structure

```text
compliance-agent/
├── .github/
│   └── workflows/
│       └── ci.yml
├── agents/
│   └── compliance_agent.py
├── tools/
│   └── kubernetes_tools.py
├── rag/
│   ├── ingest.py
│   └── retriever.py
├── reports/
│   └── pdf_generator.py
├── data/
│   ├── cis_k8s.pdf
│   ├── nist_800_53.pdf
│   └── nsa_k8s.pdf
├── main.py
├── mcp_tools.py
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🛠️ Installation

### Clone Repository

```bash
git clone https://github.com/yajushivudatha/compliance-agent.git
cd compliance-agent
```

### Create Virtual Environment

```bash
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

Create a `.env` file:

```env
GROQ_API_KEY=

LANGCHAIN_API_KEY=
LANGCHAIN_TRACING_V2=true
LANGCHAIN_PROJECT=compliance-agent

USE_MOCK_DATA=false
K8S_MCP_URL=http://localhost:8080/sse
READYOPS_TOKEN=
```

### Build Vector Database

```bash
python rag/ingest.py
```

### Test the Agent

```bash
python agents/compliance_agent.py
```

### Run the API

```bash
uvicorn main:app --reload --port 8000
```

---

## 🐳 Docker

```bash
docker compose up -d --build
```

The container runs as a non-root user and includes health checks for production deployment.

---

## 📡 API Reference

| Method | Endpoint | Authentication | Description |
|---------|----------|----------------|-------------|
| GET | `/` | Public | API information |
| GET | `/health` | Public | Health check |
| POST | `/scan` | `X-ReadyOps-Token` | Start a compliance scan |
| GET | `/scans` | `X-ReadyOps-Token` | List scan history |
| GET | `/report/{scan_id}/pdf` | `X-ReadyOps-Token` | Download report |

### Trigger a Scan

```bash
curl -X POST http://localhost:8000/scan \
-H "Content-Type: application/json" \
-H "X-ReadyOps-Token: your-platform-secret-token" \
-d '{
  "cluster_name":"criterion-k8s",
  "triggered_by":"readyops-platform"
}'
```

### Sample Response

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

## 📸 Presentation Visuals

| ReadyOps Dashboard | LangSmith Trace | Executive PDF |
|--------------------|-----------------|---------------|
| *(Add screenshot)* | *(Add screenshot)* | *(Add screenshot)* |

---

## 📚 Compliance Standards

- CIS Kubernetes Benchmark v2.0.0
- NIST SP 800-53 Revision 5
- NSA/CISA Kubernetes Hardening Guide

---

## 👨‍💻 Project Ownership

**Developer:** Yajushi Vudatha

**Role:** Summer Intern

**Organization:** Criterion Networks

**Assignment:** Agent #20 — ReadyOps Platform Integration Suite (Cisco Live Production Build)
