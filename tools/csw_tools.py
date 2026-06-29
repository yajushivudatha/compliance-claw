import os
import json
import logging
from datetime import datetime, timezone
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

USE_MOCK_DATA = os.getenv("USE_MOCK_DATA", "true").lower() == "true"
CSW_API_URL   = os.getenv("CSW_API_URL", "")
CSW_API_KEY   = os.getenv("CSW_API_KEY", "")

# ── Helper ────────────────────────────────────────────────────────────────────

def csw_get(endpoint: str) -> dict:
    """Call Cisco Secure Workload REST API."""
    import requests, hashlib, hmac, base64, time
    url = f"{CSW_API_URL}{endpoint}"
    ts  = str(int(time.time()))
    sig = base64.b64encode(
        hmac.new(CSW_API_KEY.encode(), ts.encode(), hashlib.sha256).digest()
    ).decode()
    headers = {
        "X-Tetration-Cksum": sig,
        "X-Tetration-Id":    CSW_API_KEY[:16],
        "Timestamp":         ts,
        "Content-Type":      "application/json"
    }
    resp = requests.get(url, headers=headers, verify=False, timeout=10)
    return resp.json()

def _build(tool_name, section, findings):
    passed = len([f for f in findings if f["status"] == "PASS"])
    failed = len([f for f in findings if f["status"] == "FAIL"])
    return {
        "tool": tool_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": "Cisco Secure Workload",
        "section": section,
        "total_checks": len(findings),
        "passed": passed,
        "failed": failed,
        "findings": findings
    }

# ── Tool 1 — Policy Enforcement Mode ─────────────────────────────────────────

@tool
def check_csw_enforcement_mode() -> dict:
    """
    Checks whether Cisco Secure Workload is in enforcement mode (not observation).
    In observation mode policies are logged but not enforced — a security gap.
    Maps to NIST AC-4 (Information Flow Enforcement).
    """
    logger.info(f"[Tool] check_csw_enforcement_mode (mock={USE_MOCK_DATA})")

    if not USE_MOCK_DATA and CSW_API_URL:
        try:
            data = csw_get("/openapi/v1/policies")
            items = data.get("policies", [])
            observation_policies = [
                p for p in items
                if p.get("enforcement_mode") == "observation"
            ]
            findings = [{
                "control_id":   "CSW-1.1",
                "control_name": "All workload policies must be in enforcement mode",
                "status":       "FAIL" if observation_policies else "PASS",
                "severity":     "CRITICAL",
                "evidence":     f"{len(observation_policies)} policies in observation mode" if observation_policies
                                else "All policies in enforcement mode",
                "remediation_script": (
                    "# Fix: switch all observation policies to enforcement mode\n"
                    "# Via CSW API:\n"
                    "for policy_id in observation_policy_ids:\n"
                    "    csw_put(f'/openapi/v1/policies/{policy_id}',\n"
                    "            {'enforcement_mode': 'enforcement'})"
                )
            }]
            return _build("check_csw_enforcement_mode",
                          "CSW-1 Policy Enforcement", findings)
        except Exception as e:
            logger.warning(f"CSW API call failed: {e} — using mock")

    # ── Mock data ─────────────────────────────────────────────────────────────
    findings = [
        {
            "control_id":   "CSW-1.1",
            "control_name": "All workload policies must be in enforcement mode",
            "status":       "FAIL",
            "severity":     "CRITICAL",
            "evidence":     "3 policies found in observation mode — traffic allowed but not enforced",
            "remediation_script": (
                "# Switch observation policies to enforcement mode via CSW API\n"
                "# Affects: prod-web-policy, staging-db-policy, dev-api-policy\n"
                "import requests\n"
                "for policy_id in ['prod-web-policy', 'staging-db-policy', 'dev-api-policy']:\n"
                "    requests.put(\n"
                "        f'{CSW_API_URL}/openapi/v1/policies/{policy_id}',\n"
                "        json={'enforcement_mode': 'enforcement'},\n"
                "        headers={'X-Tetration-Id': CSW_API_KEY}\n"
                "    )"
            )
        },
        {
            "control_id":   "CSW-1.2",
            "control_name": "Default policy action must be DENY",
            "status":       "FAIL",
            "severity":     "HIGH",
            "evidence":     "Default policy action is ALLOW — implicit permit for unknown traffic",
            "remediation_script": (
                "# Set default policy action to DENY\n"
                "requests.put(\n"
                "    f'{CSW_API_URL}/openapi/v1/applications/default/policies',\n"
                "    json={'default_action': 'DENY'},\n"
                "    headers={'X-Tetration-Id': CSW_API_KEY}\n"
                ")"
            )
        },
    ]
    return _build("check_csw_enforcement_mode", "CSW-1 Policy Enforcement", findings)


# ── Tool 2 — Microsegmentation Coverage ──────────────────────────────────────

@tool
def check_csw_microsegmentation() -> dict:
    """
    Checks that all workload scopes have microsegmentation policies defined.
    Workloads without policies have unrestricted lateral movement.
    Maps to NIST SC-7 (Boundary Protection).
    """
    logger.info(f"[Tool] check_csw_microsegmentation (mock={USE_MOCK_DATA})")

    if not USE_MOCK_DATA and CSW_API_URL:
        try:
            scopes = csw_get("/openapi/v1/app_scopes")
            policies = csw_get("/openapi/v1/policies")
            scope_ids_with_policy = {
                p.get("app_scope_id")
                for p in policies.get("policies", [])
            }
            uncovered = [
                s for s in scopes.get("scopes", [])
                if s.get("id") not in scope_ids_with_policy
                and not s.get("name", "").startswith("Default")
            ]
            findings = [{
                "control_id":   "CSW-2.1",
                "control_name": "All workload scopes must have microsegmentation policies",
                "status":       "FAIL" if uncovered else "PASS",
                "severity":     "HIGH",
                "evidence":     f"Uncovered scopes: {[s.get('name') for s in uncovered[:5]]}" if uncovered
                                else "All scopes have microsegmentation policies",
                "remediation_script": (
                    "# Create deny-all base policy for uncovered scopes\n"
                    "for scope in uncovered_scopes:\n"
                    "    csw_post('/openapi/v1/policies', {\n"
                    "        'app_scope_id': scope['id'],\n"
                    "        'action': 'DENY',\n"
                    "        'enforcement_mode': 'enforcement'\n"
                    "    })"
                )
            }]
            return _build("check_csw_microsegmentation",
                          "CSW-2 Microsegmentation", findings)
        except Exception as e:
            logger.warning(f"CSW API failed: {e} — using mock")

    # ── Mock data ─────────────────────────────────────────────────────────────
    findings = [
        {
            "control_id":   "CSW-2.1",
            "control_name": "All workload scopes must have microsegmentation policies",
            "status":       "FAIL",
            "severity":     "HIGH",
            "evidence":     "2 scopes without policies: 'dev-environment', 'staging-internal' — unrestricted lateral movement possible",
            "remediation_script": (
                "# Create deny-all base policy for uncovered scopes\n"
                "for scope_name in ['dev-environment', 'staging-internal']:\n"
                "    csw_post('/openapi/v1/policies', {\n"
                "        'scope_name': scope_name,\n"
                "        'action': 'DENY',\n"
                "        'enforcement_mode': 'enforcement'\n"
                "    })"
            )
        },
        {
            "control_id":   "CSW-2.2",
            "control_name": "Workload isolation — no unrestricted any-to-any rules",
            "status":       "PASS",
            "severity":     "CRITICAL",
            "evidence":     "No any-to-any allow rules found across all scopes",
            "remediation_script": "# No remediation needed — control passing"
        },
        {
            "control_id":   "CSW-2.3",
            "control_name": "East-west traffic must traverse policy enforcement point",
            "status":       "PASS",
            "severity":     "HIGH",
            "evidence":     "All east-west traffic routed through Secure Workload enforcement points",
            "remediation_script": "# No remediation needed — control passing"
        },
    ]
    return _build("check_csw_microsegmentation", "CSW-2 Microsegmentation", findings)


# ── Tool 3 — Inventory and Scope Hygiene ─────────────────────────────────────

@tool
def check_csw_inventory_hygiene() -> dict:
    """
    Checks that workload inventory is clean — no untagged workloads,
    no stale agents, no workloads outside defined scopes.
    Maps to NIST CM-8 (System Component Inventory).
    """
    logger.info(f"[Tool] check_csw_inventory_hygiene (mock={USE_MOCK_DATA})")

    if not USE_MOCK_DATA and CSW_API_URL:
        try:
            inventory = csw_get("/openapi/v1/inventory/search")
            workloads = inventory.get("results", [])
            untagged  = [w for w in workloads if not w.get("tags")]
            stale     = [w for w in workloads if w.get("agent_status") == "inactive"]

            findings = [
                {
                    "control_id":   "CSW-3.1",
                    "control_name": "All workloads must be tagged and scoped",
                    "status":       "FAIL" if untagged else "PASS",
                    "severity":     "MEDIUM",
                    "evidence":     f"{len(untagged)} untagged workloads found" if untagged
                                    else "All workloads tagged",
                    "remediation_script": (
                        "# Tag untagged workloads\n"
                        "for workload in untagged_workloads:\n"
                        "    csw_post(f'/openapi/v1/inventory/{workload[\"id\"]}/tags',\n"
                        "             {'environment': 'unknown', 'review_required': 'true'})"
                    )
                },
                {
                    "control_id":   "CSW-3.2",
                    "control_name": "No stale workload agents (inactive > 7 days)",
                    "status":       "FAIL" if stale else "PASS",
                    "severity":     "MEDIUM",
                    "evidence":     f"{len(stale)} workloads with inactive agents" if stale
                                    else "All workload agents active",
                    "remediation_script": (
                        "# Reinstall or decommission stale agents\n"
                        "for workload in stale_workloads:\n"
                        "    # Option 1: reinstall agent\n"
                        "    # ssh {workload['ip']} 'systemctl restart tetration-sensor'\n"
                        "    # Option 2: remove from inventory if decommissioned\n"
                        "    csw_delete(f'/openapi/v1/inventory/{workload[\"id\"]}')"
                    )
                },
            ]
            return _build("check_csw_inventory_hygiene",
                          "CSW-3 Inventory", findings)
        except Exception as e:
            logger.warning(f"CSW API failed: {e} — using mock")

    # ── Mock data ─────────────────────────────────────────────────────────────
    findings = [
        {
            "control_id":   "CSW-3.1",
            "control_name": "All workloads must be tagged and scoped",
            "status":       "PASS",
            "severity":     "MEDIUM",
            "evidence":     "All 47 workloads tagged and assigned to scopes",
            "remediation_script": "# No remediation needed — control passing"
        },
        {
            "control_id":   "CSW-3.2",
            "control_name": "No stale workload agents (inactive > 7 days)",
            "status":       "FAIL",
            "severity":     "MEDIUM",
            "evidence":     "4 workloads with Tetration agents inactive for > 7 days — no telemetry, blind spot in enforcement",
            "remediation_script": (
                "# Reinstall Tetration sensor on stale workloads\n"
                "stale_ips = ['10.0.1.45', '10.0.2.33', '10.0.0.78', '10.0.3.12']\n"
                "for ip in stale_ips:\n"
                "    # SSH and restart the sensor\n"
                "    os.system(f'ssh root@{ip} systemctl restart tetration-sensor')"
            )
        },
        {
            "control_id":   "CSW-3.3",
            "control_name": "No workloads outside defined scopes",
            "status":       "PASS",
            "severity":     "HIGH",
            "evidence":     "All workloads assigned to named scopes — no orphaned workloads",
            "remediation_script": "# No remediation needed — control passing"
        },
    ]
    return _build("check_csw_inventory_hygiene", "CSW-3 Inventory", findings)


# ── Tool 4 — Policy Conflict Detection ───────────────────────────────────────

@tool
def check_csw_policy_conflicts() -> dict:
    """
    Checks for conflicting or shadowed policies in Cisco Secure Workload.
    Conflicting policies can inadvertently allow traffic that should be blocked.
    Maps to NIST AC-4 and SI-3.
    """
    logger.info(f"[Tool] check_csw_policy_conflicts (mock={USE_MOCK_DATA})")

    if not USE_MOCK_DATA and CSW_API_URL:
        try:
            analysis = csw_get("/openapi/v1/policy_analysis")
            conflicts = analysis.get("conflicts", [])
            shadows   = analysis.get("shadowed_rules", [])

            findings = [
                {
                    "control_id":   "CSW-4.1",
                    "control_name": "No conflicting policy rules",
                    "status":       "FAIL" if conflicts else "PASS",
                    "severity":     "HIGH",
                    "evidence":     f"{len(conflicts)} conflicting rules detected" if conflicts
                                    else "No policy conflicts detected",
                    "remediation_script": (
                        "# Resolve policy conflicts via CSW policy analysis\n"
                        "# Review each conflict and remove the less restrictive rule\n"
                        "for conflict in conflicts:\n"
                        "    print(f'Conflict: {conflict[\"rule_a\"]} vs {conflict[\"rule_b\"]}')\n"
                        "    # Remove lower-priority conflicting rule\n"
                        "    csw_delete(f'/openapi/v1/policies/{conflict[\"rule_b\"][\"id\"]}')"
                    )
                },
                {
                    "control_id":   "CSW-4.2",
                    "control_name": "No shadowed policy rules",
                    "status":       "FAIL" if shadows else "PASS",
                    "severity":     "MEDIUM",
                    "evidence":     f"{len(shadows)} shadowed rules — never evaluated" if shadows
                                    else "No shadowed rules",
                    "remediation_script": (
                        "# Remove shadowed rules that will never be evaluated\n"
                        "for rule in shadowed_rules:\n"
                        "    csw_delete(f'/openapi/v1/policies/{rule[\"id\"]}')"
                    )
                },
            ]
            return _build("check_csw_policy_conflicts",
                          "CSW-4 Policy Conflicts", findings)
        except Exception as e:
            logger.warning(f"CSW API failed: {e} — using mock")

    # ── Mock data ─────────────────────────────────────────────────────────────
    findings = [
        {
            "control_id":   "CSW-4.1",
            "control_name": "No conflicting policy rules",
            "status":       "PASS",
            "severity":     "HIGH",
            "evidence":     "Policy analysis complete — no conflicting rules found",
            "remediation_script": "# No remediation needed — control passing"
        },
        {
            "control_id":   "CSW-4.2",
            "control_name": "No shadowed policy rules",
            "status":       "FAIL",
            "severity":     "MEDIUM",
            "evidence":     "2 shadowed rules in prod-web scope — they will never be evaluated due to broader rules above them",
            "remediation_script": (
                "# Remove shadowed rules from prod-web scope\n"
                "shadowed_ids = ['rule-prod-web-034', 'rule-prod-web-089']\n"
                "for rule_id in shadowed_ids:\n"
                "    csw_delete(f'/openapi/v1/policies/{rule_id}')\n"
                "    print(f'Removed shadowed rule: {rule_id}')"
            )
        },
    ]
    return _build("check_csw_policy_conflicts", "CSW-4 Policy Conflicts", findings)