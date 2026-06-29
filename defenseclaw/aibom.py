import os
import sys
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

def _get_package_version(package_name: str) -> str:
    """Safely get installed package version."""
    try:
        import importlib.metadata
        return importlib.metadata.version(package_name)
    except Exception:
        return "unknown"

def generate_aibom(scan_id: str,
                   mcp_tool_count: int = 0) -> Dict[str, Any]:
    """
    Generates an AI Bill of Materials — a complete snapshot of everything
    this agent depends on at the moment a scan is triggered.
    Stored in ComplianceState and included in every PDF report.
    """
    logger.info(f"[DefenseClaw] Generating AIBOM for scan {scan_id}")

    project_root = Path(__file__).parent.parent

    # ── RAG data sources ──────────────────────────────────────────────────────
    data_dir = project_root / "data"
    rag_sources = []
    if data_dir.exists():
        for pdf in data_dir.glob("*.pdf"):
            try:
                size_mb = round(pdf.stat().st_size / (1024 * 1024), 2)
                rag_sources.append({
                    "filename":   pdf.name,
                    "size_mb":    size_mb,
                    "path":       str(pdf),
                })
            except Exception:
                pass

    # ── Skills inventory ──────────────────────────────────────────────────────
    skills_file = project_root / "tools" / "kubernetes_tools.py"
    skills = []
    if skills_file.exists():
        import ast
        try:
            tree = ast.parse(skills_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if any(
                        (isinstance(d, ast.Name) and d.id == "tool") or
                        (isinstance(d, ast.Attribute) and d.attr == "tool")
                        for d in node.decorator_list
                    ):
                        docstring = (
                            node.body[0].value.s
                            if node.body and
                            isinstance(node.body[0], ast.Expr) and
                            isinstance(node.body[0].value, ast.Constant)
                            else "No docstring"
                        )
                        skills.append({
                            "name":        node.name,
                            "source_file": str(skills_file),
                            "line":        node.lineno,
                            "docstring":   docstring[:100] + "..."
                                           if len(docstring) > 100
                                           else docstring
                        })
        except Exception as e:
            logger.warning(f"Could not parse skills file: {e}")

    # ── Key package versions ──────────────────────────────────────────────────
    packages = {
        "langgraph":         _get_package_version("langgraph"),
        "langchain":         _get_package_version("langchain"),
        "langchain-groq":    _get_package_version("langchain-groq"),
        "chromadb":          _get_package_version("chromadb"),
        "mcp":               _get_package_version("mcp"),
        "fastapi":           _get_package_version("fastapi"),
        "reportlab":         _get_package_version("reportlab"),
        "sentence-transformers": _get_package_version("sentence-transformers"),
    }

    # ── ChromaDB info ─────────────────────────────────────────────────────────
    chroma_db_path = project_root / "chroma_db"
    chroma_info = {
        "path":    str(chroma_db_path),
        "exists":  chroma_db_path.exists(),
        "size_mb": round(
            sum(f.stat().st_size for f in chroma_db_path.rglob("*")
                if f.is_file()) / (1024 * 1024), 2
        ) if chroma_db_path.exists() else 0
    }

    aibom = {
        "aibom_version":  "1.0",
        "scan_id":        scan_id,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "agent": {
            "name":     "Workload Security Compliance Agent",
            "version":  "2.0",
            "platform": "Criterion Networks ReadyOps",
        },
        "llm": {
            "provider":    "Groq",
            "model":       os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            "temperature": 0,
            "key_configured": bool(os.getenv("GROQ_API_KEY")),
        },
        "mcp_server": {
            "endpoint":   os.getenv("K8S_MCP_URL", "not configured"),
            "tool_count": mcp_tool_count,
            "mock_mode":  os.getenv("USE_MOCK_DATA", "true").lower() == "true",
        },
        "skills": {
            "count":      len(skills),
            "source_file": str(skills_file),
            "functions":  skills,
        },
        "rag_pipeline": {
            "vector_db":     "ChromaDB",
            "embedding_model": "all-MiniLM-L6-v2",
            "chroma_db":     chroma_info,
            "data_sources":  rag_sources,
            "total_sources": len(rag_sources),
        },
        "observability": {
            "langsmith_configured": bool(os.getenv("LANGCHAIN_API_KEY")),
            "langsmith_project":    os.getenv("LANGCHAIN_PROJECT", "not set"),
            "tracing_enabled":      os.getenv("LANGCHAIN_TRACING_V2", "false"),
        },
        "python": {
            "version":  sys.version,
            "packages": packages,
        }
    }

    logger.info(f"[DefenseClaw] AIBOM generated — "
                f"{len(skills)} skills, "
                f"{len(rag_sources)} RAG sources, "
                f"{len(packages)} packages inventoried")
    return aibom