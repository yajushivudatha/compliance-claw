import os
import logging
from datetime import datetime, timezone
from typing import TypedDict

from defenseclaw.skill_scanner import scan_skills, ScanResult
from defenseclaw.mcp_scanner  import scan_mcp,    MCPScanResult
from defenseclaw.aibom        import generate_aibom

logger = logging.getLogger(__name__)

class PreflightReport(TypedDict):
    gate_decision:    str    # APPROVED or BLOCKED
    skill_scan:       ScanResult
    mcp_scan:         MCPScanResult
    aibom:            dict
    preflight_time:   str
    preflight_passed: bool
    block_reason:     str    # empty string if APPROVED

def run_preflight_checks(scan_id: str = "PREFLIGHT") -> PreflightReport:
    """
    Runs all DefenseClaw scanners and makes the gate decision.

    Gate logic:
      BLOCKED if skill_scan status == FAIL
      BLOCKED if mcp_scan status == FAIL
      APPROVED if both are PASS or WARN

    WARN means issues were found but none are critical/high severity.
    The scan proceeds with a warning in the report.
    """
    logger.info(f"[DefenseClaw] Pre-flight checks starting for {scan_id}...")
    start = datetime.now(timezone.utc)

    # ── Run all three scanners ────────────────────────────────────────────────
    print("\n" + "═"*60)
    print("  DEFENSECLAW PRE-FLIGHT SECURITY SCAN")
    print("  Cisco Secure Agent Framework — RSA Conference 2026")
    print("═"*60)

    # Skill scan
    print("\n[1/3] Skill Scanner — analysing kubernetes_tools.py...")
    skill_result = scan_skills()
    skill_icon   = "✅" if skill_result["status"] == "PASS" else \
                   "⚠️ " if skill_result["status"] == "WARN" else "❌"
    print(f"      {skill_icon} {skill_result['status']} — "
          f"{len(skill_result['issues'])} issues found")
    for issue in skill_result["issues"]:
        print(f"         [{issue['severity']}] Line {issue['line']}: "
              f"{issue['description']}")

    # MCP scan
    print("\n[2/3] MCP Scanner — verifying kubernetes-mcp-server...")
    mcp_result = scan_mcp()
    mcp_icon   = "✅" if mcp_result["status"] == "PASS" else \
                 "⚠️ " if mcp_result["status"] == "WARN" else "❌"
    print(f"      {mcp_icon} {mcp_result['status']} — "
          f"{mcp_result['tool_count']} tools verified")
    for issue in mcp_result["issues"]:
        print(f"         [{issue['severity']}] {issue['description']}")

    # AIBOM
    print("\n[3/3] AIBOM — generating AI Bill of Materials...")
    aibom = generate_aibom(
        scan_id=scan_id,
        mcp_tool_count=mcp_result["tool_count"]
    )
    print(f"      ✅ AIBOM generated — "
          f"{aibom['skills']['count']} skills, "
          f"{aibom['rag_pipeline']['total_sources']} RAG sources, "
          f"LLM: {aibom['llm']['model']}")

    # ── Gate decision ─────────────────────────────────────────────────────────
    block_reasons = []
    if skill_result["status"] == "FAIL":
        critical = [i for i in skill_result["issues"]
                    if i["severity"] in ("CRITICAL", "HIGH")]
        for i in critical:
            block_reasons.append(
                f"Skill Scanner FAIL: [{i['severity']}] Line {i['line']}: "
                f"{i['description']}"
            )

    if mcp_result["status"] == "FAIL":
        critical = [i for i in mcp_result["issues"]
                    if i["severity"] in ("CRITICAL", "HIGH")]
        for i in critical:
            block_reasons.append(f"MCP Scanner FAIL: {i['description']}")

    gate_decision    = "BLOCKED" if block_reasons else "APPROVED"
    preflight_passed = gate_decision == "APPROVED"

    # ── Console summary ───────────────────────────────────────────────────────
    print("\n" + "─"*60)
    if preflight_passed:
        print("  ✅ GATE DECISION: APPROVED")
        print("  All security checks passed — agent may proceed")
    else:
        print("  ❌ GATE DECISION: BLOCKED")
        print("  Security issues detected — agent will NOT run against cluster")
        for reason in block_reasons:
            print(f"  • {reason}")
    print("─"*60 + "\n")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    logger.info(f"[DefenseClaw] Pre-flight complete in {elapsed:.1f}s — "
                f"gate: {gate_decision}")

    return PreflightReport(
        gate_decision=gate_decision,
        skill_scan=skill_result,
        mcp_scan=mcp_result,
        aibom=aibom,
        preflight_time=start.isoformat(),
        preflight_passed=preflight_passed,
        block_reason="\n".join(block_reasons) if block_reasons else ""
    )