import pytest
from unittest.mock import patch, MagicMock
from agents.compliance_agent import (
    build_agent, ComplianceState,
    run_security_checks, fetch_cis_context, generate_summary
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def base_state():
    return ComplianceState(
        scan_id="SCAN-TEST-001",
        start_time="2026-05-23T00:00:00+00:00",
        api_server_findings={}, etcd_findings={},
        rbac_findings={}, pod_security_findings={},
        cis_context=[], summary="",
        total_passed=0, total_failed=0, status="PENDING"
    )

@pytest.fixture
def mock_findings():
    return {
        "section": "1.2 API Server",
        "total_checks": 2, "passed": 1, "failed": 1,
        "findings": [
            {"control_id": "1.2.1", "control_name": "Test control",
             "status": "PASS", "severity": "HIGH", "evidence": "Found"},
            {"control_id": "1.2.6", "control_name": "Auth mode check",
             "status": "FAIL", "severity": "CRITICAL", "evidence": "AlwaysAllow found"},
        ]
    }

# ── Tests ─────────────────────────────────────────────────────────────────────

def test_state_has_required_fields(base_state):
    """ComplianceState must have all required fields."""
    assert "scan_id" in base_state
    assert "total_passed" in base_state
    assert "total_failed" in base_state
    assert "status" in base_state
    assert base_state["status"] == "PENDING"

def test_run_security_checks_updates_state(base_state, mock_findings):
    """Node 1 should populate all 4 finding sections."""
    with patch("agents.compliance_agent.check_api_server_configuration") as m1, \
         patch("agents.compliance_agent.check_etcd_configuration") as m2, \
         patch("agents.compliance_agent.check_rbac_configuration") as m3, \
         patch("agents.compliance_agent.check_pod_security_configuration") as m4:

        for m in [m1, m2, m3, m4]:
            m.invoke.return_value = mock_findings

        result = run_security_checks(base_state)

        assert result["total_passed"] == 4   # 1 pass × 4 tools
        assert result["total_failed"] == 4   # 1 fail × 4 tools
        assert result["api_server_findings"] == mock_findings
        assert result["etcd_findings"] == mock_findings

def test_fetch_cis_context_queries_all_failures(base_state, mock_findings):
    """Node 2 should fetch RAG context for every failed control."""
    state_with_findings = {
        **base_state,
        "api_server_findings": mock_findings,
        "etcd_findings": {"findings": []},
        "rbac_findings": {"findings": []},
        "pod_security_findings": {"findings": []},
    }

    mock_doc = MagicMock()
    mock_doc.page_content = "CIS guidance text here"

    with patch("agents.compliance_agent.search_cis", return_value=[mock_doc]) as mock_rag:
        result = fetch_cis_context(state_with_findings)
        # Should query once for the 1 failed control
        assert mock_rag.call_count == 1
        assert len(result["cis_context"]) == 1

def test_generate_summary_sets_status(base_state, mock_findings):
    """Node 3 should set status to NON-COMPLIANT when failures exist."""
    state_with_findings = {
        **base_state,
        "api_server_findings": mock_findings,
        "etcd_findings": {"findings": []},
        "rbac_findings": {"findings": []},
        "pod_security_findings": {"findings": []},
        "cis_context": ["Some CIS guidance"],
        "total_passed": 1, "total_failed": 1,
    }

    mock_response = MagicMock()
    mock_response.content = "The cluster is NON-COMPLIANT."

    with patch("agents.compliance_agent.llm") as mock_llm:
        mock_llm.invoke.return_value = mock_response
        result = generate_summary(state_with_findings)
        assert result["status"] == "NON-COMPLIANT"
        assert result["summary"] == "The cluster is NON-COMPLIANT."

def test_compliant_status_when_no_failures(base_state):
    """Status should be COMPLIANT when all checks pass."""
    passing_findings = {
        "findings": [
            {"control_id": "1.2.1", "control_name": "Test", "status": "PASS",
             "severity": "HIGH", "evidence": "OK"}
        ]
    }
    state = {
        **base_state,
        "api_server_findings": passing_findings,
        "etcd_findings": {"findings": []},
        "rbac_findings": {"findings": []},
        "pod_security_findings": {"findings": []},
        "cis_context": [],
        "total_passed": 1, "total_failed": 0,
    }
    mock_response = MagicMock()
    mock_response.content = "The cluster is COMPLIANT."
    with patch("agents.compliance_agent.llm") as mock_llm:
        mock_llm.invoke.return_value = mock_response
        result = generate_summary(state)
        assert result["status"] == "COMPLIANT"

def test_agent_graph_builds():
    """LangGraph StateGraph should compile without errors."""
    agent = build_agent()
    assert agent is not None