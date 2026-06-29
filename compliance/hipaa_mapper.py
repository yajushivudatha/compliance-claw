def _find(scan_result: dict, section: str, control_id: str):
    """Find a specific finding by control_id within a section."""
    for f in scan_result.get(section, {}).get("findings", []):
        if f["control_id"] == control_id:
            return f
    return None

def _all_pass(scan_result: dict, section: str, control_ids: list) -> bool:
    """True only if every listed control_id in that section passed."""
    for cid in control_ids:
        f = _find(scan_result, section, cid)
        if not f or f["status"] != "PASS":
            return False
    return True


def build_hipaa_assessment(scan_result: dict) -> dict:
    """
    Maps existing CIS/RBAC/Network/HIPAA-evidence findings to the
    HIPAA Security Rule structure: §164.308, §164.310, §164.312.
    """
    rbac_pass   = _all_pass(scan_result, "rbac_findings", ["5.1.1", "5.1.3"])
    audit_pass  = (_find(scan_result, "api_server_findings", "1.2.16") or {}).get("status") == "PASS"
    hipaa_audit = (_find(scan_result, "hipaa_evidence", "HIPAA-164.312(b)") or {}).get("status") == "PASS"
    pods_pass   = _all_pass(scan_result, "pod_security_findings",
                            ["5.2.2", "5.2.7", "5.2.10"])
    netpol_pass = _all_pass(scan_result, "network_policy_findings",
                            ["5.3.1", "5.3.2", "5.3.3"])
    etcd_pass   = _all_pass(scan_result, "etcd_findings",
                            ["2.1", "2.2", "2.4", "2.5"])

    return {
        "164.308": {
            "title": "Administrative Safeguards",
            "items": [
                {"name": "Access control policies", "passed": rbac_pass},
                {"name": "Audit controls",            "passed": audit_pass and hipaa_audit},
            ]
        },
        "164.310": {
            "title": "Physical Safeguards",
            "items": [
                {"name": "Workstation security", "passed": pods_pass},
            ]
        },
        "164.312": {
            "title": "Technical Safeguards",
            "items": [
                {"name": "Access control", "passed": rbac_pass and netpol_pass},
                {"name": "Encryption",     "passed": etcd_pass},
                {"name": "Audit logs",     "passed": audit_pass and hipaa_audit},
            ]
        }
    }