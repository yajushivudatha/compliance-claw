import os
import sys
import logging
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from agents.remediation_engine import run_remediation

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.compliance_agent import build_agent, ComplianceState
from reports.pdf_generator import generate_report

# Compile agent once at startup — not on every scan
agent = build_agent()

load_dotenv()
from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    cluster_name: str = Field(
        default="criterion-k8s-cluster",
        max_length=100,
        pattern=r'^[a-zA-Z0-9\-_]+$'
    )
    triggered_by: str = Field(
        default="readyops-platform",
        max_length=100
    )

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "msg": "%(message)s"}'
)
logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Workload Security Compliance Agent",
    description="Criterion Networks ReadyOps Platform — CIS Kubernetes Benchmark v2.0.0",
    version="1.0.0"
)

# ── CORS — lock to ReadyOps origin in production ──────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── API key auth ──────────────────────────────────────────────────────────────
READYOPS_TOKEN = os.getenv("READYOPS_TOKEN", "")

def verify_token(x_readyops_token: Optional[str] = Header(default=None)):
    if not READYOPS_TOKEN:
        return  # No token configured — open access (dev mode)
    if x_readyops_token != READYOPS_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing X-ReadyOps-Token header")

# ── SQLite persistence ────────────────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "scans.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id            TEXT PRIMARY KEY,
            status             TEXT,
            total_passed       INTEGER,
            total_failed       INTEGER,
            compliance_score   INTEGER,
            cluster_name       TEXT,
            triggered_by       TEXT,
            timestamp          TEXT,
            pdf_path           TEXT,
            summary            TEXT,
            job_status         TEXT DEFAULT 'pending',
            full_findings_json TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"SQLite DB ready at {DB_PATH}")

def save_scan(data: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO scans
        (scan_id, status, total_passed, total_failed, compliance_score,
         cluster_name, triggered_by, timestamp, pdf_path, summary,
         job_status, full_findings_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["scan_id"], data.get("status", "PENDING"),
        data.get("total_passed", 0), data.get("total_failed", 0),
        data.get("compliance_score", 0), data.get("cluster_name", ""),
        data.get("triggered_by", ""), data.get("timestamp", ""),
        data.get("pdf_path", ""), data.get("summary", ""),
        data.get("job_status", "pending"),
        data.get("full_findings_json", "{}")
    ))
    conn.commit()
    conn.close()

def get_scan(scan_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def list_scans_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    init_db()
    logger.info("Compliance Agent API started")
    yield

app = FastAPI(
    title="Workload Security Compliance Agent",
    description="Criterion Networks ReadyOps Platform — CIS Kubernetes Benchmark v2.0.0",
    version="1.0.0",
    lifespan=lifespan
)

# ── Models ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    cluster_name: str = Field(
        default="criterion-k8s-cluster",
        max_length=100,
        pattern=r'^[a-zA-Z0-9\-_]+$'
    )
    triggered_by: str = Field(
        default="readyops-platform",
        max_length=100
    )

class ScanAccepted(BaseModel):
    scan_id: str
    job_status: str
    message: str
    poll_url: str

# ── Background scan runner ────────────────────────────────────────────────────
def run_scan_background(scan_id: str, cluster_name: str, triggered_by: str):
    logger.info(f"[{scan_id}] Background scan started")
    try:
        # agent already compiled at module level
        initial_state = ComplianceState(
    scan_id=scan_id,
    start_time=datetime.now(timezone.utc).isoformat(),
    api_server_findings={}, etcd_findings={},
    rbac_findings={}, pod_security_findings={},
    network_policy_findings={}, hipaa_evidence={},
    workload_presence={},
    mitre_findings={},          # ← ADD
    hipaa_pci_findings={},      # ← ADD
    cis_context=[], summary="",
    total_passed=0, total_failed=0,
    status="PENDING",
    preflight_report={}
)

        result = agent.invoke(initial_state)
        pdf_path = generate_report(result)

        total = result["total_passed"] + result["total_failed"]
        score = int((result["total_passed"] / total * 100)) if total > 0 else 0

        save_scan({
            "scan_id":            scan_id,
            "status":             result["status"],
            "total_passed":       result["total_passed"],
            "total_failed":       result["total_failed"],
            "compliance_score":   score,
            "cluster_name":       cluster_name,
            "triggered_by":       triggered_by,
            "timestamp":          result["start_time"],
            "pdf_path":           str(pdf_path),
            "summary":            result["summary"],
            "job_status":         "complete",
            "full_findings_json": json.dumps({
                "api_server_findings":   result.get("api_server_findings", {}),
                "etcd_findings":         result.get("etcd_findings", {}),
                "rbac_findings":         result.get("rbac_findings", {}),
                "pod_security_findings": result.get("pod_security_findings", {}),
                "csw_findings":          result.get("csw_findings", {}),
                "hypershield_findings":  result.get("hypershield_findings", {}),
            }),
        })
        logger.info(f"[{scan_id}] Scan complete — {result['status']}")

    except Exception as e:
        logger.exception(f"[{scan_id}] Scan failed: {e}")
        save_scan({
            "scan_id":            scan_id,
            "status":             "ERROR",
            "total_passed":       0,
            "total_failed":       0,
            "compliance_score":   0,
            "cluster_name":       cluster_name,
            "triggered_by":       triggered_by,
            "timestamp":          datetime.now(timezone.utc).isoformat(),
            "pdf_path":           "",
            "summary":            f"Scan failed: {str(e)}",
            "job_status":         "failed",
            "full_findings_json": json.dumps({}),
        })

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "Workload Security Compliance Agent",
        "platform": "Criterion Networks ReadyOps",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.post("/scan", response_model=ScanAccepted, status_code=202,
          dependencies=[Depends(verify_token)])
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Triggers a compliance scan. Returns 202 immediately with scan_id.
    Poll GET /scans/{scan_id} to check status and get results.
    """
    scan_id = f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    # Save immediately as pending so polling works right away
    save_scan({
        "scan_id": scan_id, "status": "PENDING",
        "total_passed": 0, "total_failed": 0,
        "compliance_score": 0,
        "cluster_name": request.cluster_name,
        "triggered_by": request.triggered_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pdf_path": "", "summary": "",
        "job_status": "running"
    })

    background_tasks.add_task(
        run_scan_background, scan_id,
        request.cluster_name, request.triggered_by
    )

    logger.info(f"[{scan_id}] Scan queued by {request.triggered_by}")

    return ScanAccepted(
        scan_id=scan_id,
        job_status="running",
        message="Scan started. Poll the status URL every 5 seconds.",
        poll_url=f"/scans/{scan_id}"
    )

@app.get("/scans/{scan_id}")
def get_scan_result(scan_id: str):
    """
    Poll this endpoint after POST /scan to check status.
    job_status = running | complete | failed
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    result = dict(scan)
    if result["job_status"] == "complete":
        result["pdf_download_url"] = f"/report/{scan_id}/pdf"
    return result

@app.get("/report/{scan_id}/pdf",
         dependencies=[Depends(verify_token)])
def download_pdf(scan_id: str):
    """Downloads the PDF compliance certificate for a completed scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan["job_status"] != "complete":
        raise HTTPException(status_code=425, detail="Scan not complete yet. Poll /scans/{scan_id} first.")
    pdf_path = scan["pdf_path"]
    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(status_code=404, detail="PDF not found on disk")
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"{scan_id}-compliance-report.pdf"
    )

@app.get("/scans")
def list_scans():
    """Lists all scans — persisted across restarts."""
    scans = list_scans_db()
    return {"total_scans": len(scans), "scans": scans}

# ── Remediation models ────────────────────────────────────────────────────────
class RemediationRequest(BaseModel):
    control_ids: List[str] = Field(
        description="List of control IDs to remediate e.g. ['1.2.6', '5.1.1', 'HS-1.1']",
        min_length=1
    )
    confirm: bool = Field(
        default=False,
        description="Must be set to true to confirm you want to apply changes to the cluster"
    )

class RemediationResponse(BaseModel):
    scan_id:          str
    remediation_time: str
    requested:        int
    remediated:       int
    failed:           int
    skipped:          int
    results:          list


# ── Remediation endpoint ──────────────────────────────────────────────────────
@app.post("/remediate/{scan_id}",
          response_model=RemediationResponse,
          dependencies=[Depends(verify_token)])
def remediate_scan(
    scan_id: str,
    request: RemediationRequest
):
    """
    Applies automated remediation for specific controls from a completed scan.

    IMPORTANT: This makes real changes to your cluster.
    - Set confirm=true to proceed.
    - Only the control_ids you specify are remediated — nothing else is touched.
    - Each remediation is logged to LangSmith for audit.

    Example request body:
    {
        "control_ids": ["1.2.6", "5.1.1", "5.2.2"],
        "confirm": true
    }
    """
    if not request.confirm:
        raise HTTPException(
            status_code=400,
            detail="Set confirm=true to apply remediation. "
                   "This will make real changes to your cluster."
        )

    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if scan["job_status"] != "complete":
        raise HTTPException(
            status_code=425,
            detail=f"Scan {scan_id} is not complete yet (status: {scan['job_status']})"
        )

    logger.info(f"[{scan_id}] Remediation requested for: {request.control_ids}")

    # Reconstruct full scan result from SQLite
    # The agent state is stored as individual columns — we rebuild findings from the PDF path
    # For now pass the scan row as the result (findings are in the PDF)
    # In production you would store full JSON — for now we pass what we have
    scan_result = dict(scan)
    scan_result["scan_id"] = scan_id

    # Run remediation
    remediation_result = run_remediation(scan_result, request.control_ids)

    logger.info(
        f"[{scan_id}] Remediation complete — "
        f"{remediation_result['remediated']} remediated, "
        f"{remediation_result['failed']} failed"
    )

    return RemediationResponse(**remediation_result)