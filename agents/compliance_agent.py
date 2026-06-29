import os
import sys
import time
import logging
from datetime import datetime, timezone
from rag.retriever import search_cis, search_mitre
from typing import TypedDict, List, Dict
from dotenv import load_dotenv
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.kubernetes_tools import (
    check_api_server_configuration,
    check_etcd_configuration,
    check_rbac_configuration,
    check_pod_security_configuration,
    check_node_resource_pressure,
    check_namespace_isolation,
    check_cluster_events,
    check_pod_logs_audit,
    check_network_policies,
    check_hipaa_evidence,
    check_workload_presence,
    check_workload_namespaces,
    check_mitre_attack_mapping,
    check_hipaa_pci_workloads,
)
from rag.retriever import search_cis
CORRECT_ATTACK_NAMES = {
    "T1611":     "Escape to Host",
    "T1552.007": "Unsecured Credentials: Container API",
    "T1098.006": "Account Manipulation: Additional Container Cluster Roles",
    "T1613":     "Container and Resource Discovery",
    "T1610":     "Deploy Container",
    "T1609":     "Container Administration Command",
    "T1496":     "Resource Hijacking",
    "T1190":     "Exploit Public-Facing Application",
    "T1046":     "Network Service Discovery",
}

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)
logger = logging.getLogger(__name__)

# ── LLM singleton ─────────────────────────────────────────────────────────────
llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0
)

# ── State ─────────────────────────────────────────────────────────────────────
class ComplianceState(TypedDict):
    scan_id:                 str
    start_time:              str
    api_server_findings:     Dict
    node_health_findings:    Dict
    namespace_findings:      Dict
    event_findings:          Dict
    pod_log_findings:        Dict
    etcd_findings:           Dict
    rbac_findings:           Dict
    pod_security_findings:   Dict
    network_policy_findings: Dict
    hipaa_evidence:          Dict
    mitre_findings:          Dict
    hipaa_pci_findings:      Dict
    has_workloads:           bool
    has_healthcare:          bool
    has_pci:                 bool
    workload_list:           List[str]
    workload_namespaces:     List[str]
    workload_message:        str
    cis_context:             List[str]
    summary:                 str
    total_passed:            int
    total_failed:            int
    status:                  str
    preflight_report:        Dict


# ── Node 0 — DefenseClaw pre-flight security gate ─────────────────────────────
def run_preflight(state: ComplianceState) -> ComplianceState:
    from defenseclaw.preflight import run_preflight_checks
    logger.info(f"[{state['scan_id']}] Node 0: DefenseClaw pre-flight scan...")
    report = run_preflight_checks(scan_id=state["scan_id"])

    if not report["preflight_passed"]:
        logger.warning(f"[{state['scan_id']}] Pre-flight BLOCKED: {report['block_reason']}")
        return {
            **state,
            "preflight_report": dict(report),
            "status": "BLOCKED",
            "summary": f"Scan blocked by DefenseClaw: {report['block_reason']}"
        }
    return {**state, "preflight_report": dict(report)}


# ── Node 1 — Workload detection ───────────────────────────────────────────────
def detect_workloads(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 1: Workload detection...")

    presence   = check_workload_presence.invoke({})
    namespaces = check_workload_namespaces.invoke({})

    workload_list = (
        presence.get("workloads", []) or
        [f"{ns}/pod" for ns in namespaces.get("workload_ns", [])]
    )
    workload_ns   = namespaces.get("workload_ns", [])
    pod_count     = len(workload_list)

    has_workloads  = pod_count > 0 or namespaces.get("has_workloads", False)
    has_healthcare = namespaces.get("has_healthcare", False)
    has_pci        = namespaces.get("has_pci", False)

    if has_workloads:
        message = (
            f"{pod_count} application pod(s) detected across "
            f"{len(workload_ns)} namespace(s): {', '.join(workload_ns)}. "
            f"Pods: {', '.join(workload_list)}."
        )
    else:
        message = "No application workloads detected — infrastructure only."

    logger.info(f"[{state['scan_id']}] Workloads={has_workloads} "
                f"Healthcare={has_healthcare} PCI={has_pci}")

    return {
        **state,
        "has_workloads":       has_workloads,
        "has_healthcare":      has_healthcare,
        "has_pci":             has_pci,
        "workload_list":       workload_list,
        "workload_namespaces": workload_ns,
        "workload_message":    message,
    }


# ── Node 2 — Infrastructure + conditional app-level checks ───────────────────
def run_security_checks(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 2: Running security checks "
                f"(workloads={state['has_workloads']})...")

    # Infrastructure — always run
    api          = check_api_server_configuration.invoke({})
    etcd         = check_etcd_configuration.invoke({})
    rbac         = check_rbac_configuration.invoke({})
    node_health  = check_node_resource_pressure.invoke({})
    ns_isolation = check_namespace_isolation.invoke({})
    events       = check_cluster_events.invoke({})
    pod_logs     = check_pod_logs_audit.invoke({})

    # Application — only when workloads detected
    if state["has_workloads"]:
        pods   = check_pod_security_configuration.invoke({})
        netpol = check_network_policies.invoke({})
        hipaa  = check_hipaa_evidence.invoke({}) if state["has_healthcare"] else \
                 {"section": "HIPAA Security Rule Evidence",
                  "findings": [], "passed": 0, "failed": 0}
    else:
        logger.info(f"[{state['scan_id']}] No workloads — skipping app-level checks")
        pods   = {"section": "5.2 Pod Security Standards",
                  "findings": [], "passed": 0, "failed": 0}
        netpol = {"section": "5.3 Network Policies",
                  "findings": [], "passed": 0, "failed": 0}
        hipaa  = {"section": "HIPAA Security Rule Evidence",
                  "findings": [], "passed": 0, "failed": 0}

    passed = (api["passed"] + etcd["passed"] + rbac["passed"] +
              pods["passed"] + netpol["passed"] + hipaa["passed"] +
              node_health["passed"] + ns_isolation["passed"] +
              events["passed"] + pod_logs["passed"])
    failed = (api["failed"] + etcd["failed"] + rbac["failed"] +
              pods["failed"] + netpol["failed"] + hipaa["failed"] +
              node_health["failed"] + ns_isolation["failed"] +
              events["failed"] + pod_logs["failed"])

    return {
        **state,
        "api_server_findings":     api,
        "etcd_findings":           etcd,
        "rbac_findings":           rbac,
        "pod_security_findings":   pods,
        "network_policy_findings": netpol,
        "hipaa_evidence":          hipaa,
        "node_health_findings":    node_health,
        "namespace_findings":      ns_isolation,
        "event_findings":          events,
        "pod_log_findings":        pod_logs,
        "total_passed":            passed,
        "total_failed":            failed,
    }


# ── Node 3 — MITRE ATT&CK mapping ────────────────────────────────────────────
def run_mitre_mapping_node(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 3: MITRE ATT&CK mapping...")
    mitre = check_mitre_attack_mapping.invoke({})
    return {
        **state,
        "mitre_findings": mitre,
        "total_passed":   state["total_passed"] + mitre.get("passed", 0),
        "total_failed":   state["total_failed"] + mitre.get("failed", 0),
    }


# ── Node 4 — HIPAA + PCI-DSS workload checks ─────────────────────────────────
def run_hipaa_pci_node(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 4: HIPAA & PCI-DSS checks "
                f"(healthcare={state['has_healthcare']} pci={state['has_pci']})...")

    if not state["has_workloads"]:
        logger.info(f"[{state['scan_id']}] No workloads — skipping HIPAA/PCI node")
        return {
            **state,
            "hipaa_pci_findings": {
                "section": "HIPAA & PCI-DSS Workload Checks",
                "findings": [], "passed": 0, "failed": 0
            }
        }

    hipaa_pci = check_hipaa_pci_workloads.invoke({})
    return {
        **state,
        "hipaa_pci_findings": hipaa_pci,
        "total_passed": state["total_passed"] + hipaa_pci.get("passed", 0),
        "total_failed": state["total_failed"] + hipaa_pci.get("failed", 0),
    }


# ── Node 5 — RAG context ──────────────────────────────────────────────────────
def fetch_cis_context(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 5: Fetching RAG context...")

    all_sections = [
        "api_server_findings", "etcd_findings", "rbac_findings",
        "pod_security_findings", "network_policy_findings", "hipaa_evidence",
        "node_health_findings", "namespace_findings", "event_findings",
        "pod_log_findings", "mitre_findings", "hipaa_pci_findings",
    ]

    queries = []
    for section in all_sections:
        for f in state.get(section, {}).get("findings", []):
            if f["status"] == "FAIL":
                queries.append(f["control_name"])

    cis_context = []
    for query in queries:
        for r in search_cis(query, k=4):
            src = r.metadata.get("source", "unknown").upper()
            cis_context.append(f"[{src}] {r.page_content}")

    mitre_queries = [
        "container escape privilege escalation kubernetes",
        "RBAC cluster admin privilege escalation additional roles",
        "root container ePHI patient database escape to host",
        "audit logging disabled kubernetes credential access",
        "network policy bypass lateral movement container",
    ]
    for query in mitre_queries:
        for r in search_mitre(query, k=4):
            cis_context.append(f"[MITRE_ATTACK] {r.page_content}")

    seen, unique = set(), []
    for c in cis_context:
        key = c[:120]
        if key not in seen:
            seen.add(key)
            unique.append(c)

    logger.info(f"[{state['scan_id']}] Retrieved {len(unique)} context chunks")
    return {**state, "cis_context": unique[:25]}
# ── Correct cross-framework mapping per control ID ────────────────────────────
# This is the single source of truth. The LLM never invents these.
CROSS_FRAMEWORK_MAP = {
    # CIS infrastructure
    "1.2.1":  {"cis": "CIS 1.2.1", "hipaa": None,                  "pci": "Req 10.2",   "attack": "T1552.007"},
    "1.2.2":  {"cis": "CIS 1.2.2", "hipaa": None,                  "pci": "Req 10.2",   "attack": "T1552.007"},
    "1.2.6":  {"cis": "CIS 1.2.6", "hipaa": None,                  "pci": "Req 7.1",    "attack": "T1098.006"},
    "1.2.16": {"cis": "CIS 1.2.16","hipaa": "§164.312(b)",         "pci": "Req 10.2",   "attack": "T1552.007"},
    "2.1":    {"cis": "CIS 2.1",   "hipaa": None,                  "pci": "Req 2.2",    "attack": "T1552.007"},
    "2.2":    {"cis": "CIS 2.2",   "hipaa": None,                  "pci": "Req 2.2",    "attack": "T1552.007"},
    "2.4":    {"cis": "CIS 2.4",   "hipaa": None,                  "pci": "Req 2.2",    "attack": "T1552.007"},
    "2.5":    {"cis": "CIS 2.5",   "hipaa": None,                  "pci": None,         "attack": "T1552.007",
               "risk_note": "Single-node cluster — peer URLs localhost only. Exploitability LOW. "
                            "Verify peer TLS certs exist before enabling or etcd crashes. "
                            "Fix: edit /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml "
                            "and add --peer-client-cert-auth=true"},
    # RBAC
    "5.1.1":  {"cis": "CIS 5.1.1", "hipaa": "§164.312(a)(1)",     "pci": "Req 7.1",    "attack": "T1098.006"},
    "5.1.3":  {"cis": "CIS 5.1.3", "hipaa": "§164.312(a)(1)",     "pci": "Req 7.1",    "attack": "T1098.006"},
    # Pod security
    "5.2.2":  {"cis": "CIS 5.2.2", "hipaa": None,                  "pci": "Req 2.2 (simulation namespaces only — healthcare clean)", "attack": "T1611"},
    "5.2.7":  {"cis": "CIS 5.2.7", "hipaa": "§164.308(a)(3)",     "pci": None,         "attack": "T1609",
               "fix_override": "kubectl patch deployment patient-db -n healthcare --patch "
                               "'{\"spec\":{\"template\":{\"spec\":{\"securityContext\":"
                               "{\"runAsNonRoot\":true,\"runAsUser\":999}}}}}'"},
    "5.2.10": {"cis": "CIS 5.2.10","hipaa": "§164.308(a)(3)",     "pci": None,         "attack": "T1609",
               "fix_override": "kubectl patch deployment patient-db -n healthcare --patch "
                               "'{\"spec\":{\"template\":{\"spec\":{\"securityContext\":"
                               "{\"runAsNonRoot\":true,\"runAsUser\":999}}}}}'"},
    # Network
    "5.3.1":  {"cis": "CIS 5.3.1", "hipaa": "§164.312(e)(1)",     "pci": "Req 1.3",    "attack": "T1610"},
    "5.3.2":  {"cis": "CIS 5.3.2", "hipaa": "§164.312(e)(1)",     "pci": None,         "attack": "T1610"},
    "5.3.3":  {"cis": "CIS 5.3.3", "hipaa": "§164.312(e)(1)",     "pci": None,         "attack": "T1610"},
    # HIPAA-specific
    "HIPAA-164.308(a)(3)": {"cis": "CIS 5.2.10", "hipaa": "§164.308(a)(3)", "pci": None, "attack": "T1609",
                             "fix_override": "kubectl patch deployment patient-db -n healthcare --patch "
                                             "'{\"spec\":{\"template\":{\"spec\":{\"securityContext\":"
                                             "{\"runAsNonRoot\":true,\"runAsUser\":999}}}}}'"},
    "HIPAA-164.312(b)":    {"cis": "CIS 1.2.16","hipaa": "§164.312(b)",     "pci": "Req 10.2",   "attack": "T1552.007"},
    "HIPAA-164.312(b)-LIVE":{"cis": None,        "hipaa": "§164.312(b)",     "pci": "Req 10.2",   "attack": "T1552.007"},
    "HIPAA-164.312(a)(1)": {"cis": "CIS 5.1.1", "hipaa": "§164.312(a)(1)", "pci": "Req 7.1",    "attack": "T1098.006"},
    "HIPAA-164.312(e)(1)": {"cis": "CIS 5.3.x", "hipaa": "§164.312(e)(1)", "pci": "Req 1.3",    "attack": "T1610"},
    # PCI
    "PCI-DSS-Req7.1":  {"cis": "CIS 5.1.3", "hipaa": None,                  "pci": "Req 7.1",    "attack": "T1552.007"},
    "PCI-DSS-Req10.2": {"cis": "CIS 1.2.16","hipaa": "§164.312(b)",         "pci": "Req 10.2",   "attack": "T1552.007"},
    "PCI-DSS-Req2.2":  {"cis": "CIS 5.2.2", "hipaa": None,                  "pci": "Req 2.2",    "attack": "T1611",
                         "scope_note": "Scoped to MITRE simulation namespaces only — healthcare namespace is clean"},
    # MITRE
    "T1611":     {"cis": None,        "hipaa": None,                  "pci": None,         "attack": "T1611",
                  "scope_note": "Simulation namespace only — healthcare segmented at L4"},
    "T1552.007": {"cis": "CIS 1.2.16","hipaa": None,                  "pci": "Req 10.2",   "attack": "T1552.007"},
    "T1098.006": {"cis": "CIS 5.1.3", "hipaa": "§164.312(a)(1)",     "pci": "Req 7.1",    "attack": "T1098.006"},
    "T1613":     {"cis": "CIS 5.1.x", "hipaa": None,                  "pci": "Req 7.1",    "attack": "T1613"},
    "T1610":     {"cis": "CIS 5.1.1", "hipaa": None,                  "pci": "Req 7.1",    "attack": "T1610"},
    "T1609":     {"cis": "CIS 5.2.10","hipaa": "§164.308(a)(3)",     "pci": None,         "attack": "T1609"},
    # Node / NS / Events
    "EVT-1.2":   {"cis": "CIS 5.1.6","hipaa": "§164.312(b)",         "pci": "Req 10.2",   "attack": "T1552.007"},
    "NS-1.1":    {"cis": "CIS 5.7",  "hipaa": None,                  "pci": "Req 2.2",    "attack": "T1610"},
    "NS-1.2":    {"cis": "CIS 5.3.1","hipaa": "§164.312(e)(1)",      "pci": "Req 1.3",    "attack": "T1610"},
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def build_section6(state: ComplianceState, remediations_dict: dict) -> str:
    """
    Pre-computes Section 6 entirely in Python using CROSS_FRAMEWORK_MAP.
    The LLM receives this as a pre-built string and is told not to modify it.
    This eliminates all cross-framework hallucinations in Section 6.
    """
    all_sections = [
        "api_server_findings", "etcd_findings", "rbac_findings",
        "pod_security_findings", "network_policy_findings", "hipaa_evidence",
        "node_health_findings", "namespace_findings", "event_findings",
        "pod_log_findings", "mitre_findings", "hipaa_pci_findings",
    ]

    # Collect all failures, deduplicate by control_id, sort by severity
    seen_ids = set()
    failures = []
    for section in all_sections:
        for f in state.get(section, {}).get("findings", []):
            if f["status"] == "FAIL" and f["control_id"] not in seen_ids:
                seen_ids.add(f["control_id"])
                failures.append(f)

    failures.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    lines = ["SECTION 6 — PRIORITY REMEDIATION PLAN", ""]
    count = 0
    for f in failures:
        if count >= 3:
            break
        cid  = f["control_id"]
        m    = CROSS_FRAMEWORK_MAP.get(cid, {})
        fix  = m.get("fix_override") or remediations_dict.get(cid,
               "See detailed findings section for remediation guidance.")
        note = m.get("risk_note", "") or m.get("scope_note", "")

        # Build framework citation — only include frameworks that actually apply
        frameworks = []
        if m.get("cis"):   frameworks.append(m["cis"])
        if m.get("hipaa"): frameworks.append(f"HIPAA {m['hipaa']}")
        if m.get("pci"):   frameworks.append(f"PCI-DSS {m['pci']}")
        if m.get("attack"):frameworks.append(f"Mitigates {m['attack']} "
                                              f"({CORRECT_ATTACK_NAMES.get(m['attack'], '')})")
        fw_str = " | ".join(frameworks) if frameworks else "Infrastructure finding"

        count += 1
        lines.append(f"Action {count} [{f['severity']}] — {f['control_name']}")
        lines.append(f"Frameworks: {fw_str}")
        lines.append(f"Fix: {fix}")
        if note:
            lines.append(f"Note: {note}")
        lines.append("")

    return "\n".join(lines)



# ── Node 6 — AI summary ───────────────────────────────────────────────────────
def generate_summary(state: ComplianceState) -> ComplianceState:
    logger.info(f"[{state['scan_id']}] Node 6: Generating AI summary "
                f"(has_workloads={state['has_workloads']} "
                f"has_healthcare={state['has_healthcare']})...")

    # Read from authoritative flat keys — no ambiguity
    has_workloads  = state["has_workloads"]
    has_healthcare = state["has_healthcare"]
    workload_list  = state["workload_list"]
    workload_msg   = state["workload_message"]

    all_sections = [
        "api_server_findings", "etcd_findings", "rbac_findings",
        "pod_security_findings", "network_policy_findings", "hipaa_evidence",
        "node_health_findings", "namespace_findings", "event_findings",
        "pod_log_findings", "mitre_findings", "hipaa_pci_findings",
    ]

    failed_controls = []
    for section in all_sections:
        for f in state.get(section, {}).get("findings", []):
            if f["status"] == "FAIL":
                failed_controls.append(
                    f"- [{f['control_id']}] {f['control_name']} "
                    f"(Severity: {f['severity']})\n"
                    f"  Evidence: {f['evidence']}"
                )
    # ── Pre-build Section 6 in Python — LLM copies verbatim, cannot hallucinate ──
    from reports.pdf_generator import REMEDIATIONS as _REMEDIATIONS
    prebuilt_section6 = build_section6(state, _REMEDIATIONS)

    intelligence_sources = """INTELLIGENCE SOURCES LOADED (all 9 checked where applicable):
  [1] cis_k8s.pdf           — CIS Kubernetes Benchmark v2.0.0
  [2] nist_800_53.pdf       — NIST 800-53 Rev 5
  [3] nsa_k8s.pdf           — NSA/CISA K8s Hardening Guide v1.0
  [4] nsa_k8s_v1_2.pdf      — NSA/CISA K8s Hardening Guide v1.2
  [5] hipaa_security.pdf    — HIPAA Security Rule (45 CFR §164)
  [6] hipaa_privacy.pdf     — HIPAA Privacy Rule
  [7] nist_hipaa.pdf        — NIST HIPAA Security Rule Toolkit
  [8] pci_dss_v4.pdf        — PCI-DSS v4.0.1
  [9] enterprise-attack.json — MITRE ATT&CK Enterprise (Container/K8s techniques)"""

    # ── Kubectl patch command extracted to avoid f-string quote collision ──────
    patient_db_patch_cmd = (
        "kubectl patch deployment patient-db -n healthcare --patch "
        "'{\"spec\":{\"template\":{\"spec\":{\"securityContext\":"
        "{\"runAsNonRoot\":true,\"runAsUser\":999}}}}}'"
    )

    # ── Anti-hallucination rules injected into every prompt ───────────────────
    anti_hallucination = f"""
CRITICAL RULES — READ BEFORE WRITING. VIOLATIONS CAUSE CUSTOMER ESCALATION:

RULE 1 — ONLY cite findings that appear in the FAILED CONTROLS list above.
  If a control is not in that list it PASSED. Do not reference passed controls as failures.

RULE 2 — CIS 5.2.2 (privileged containers) PASSED for the healthcare namespace.
  Do NOT cite it as a PCI-DSS or HIPAA violation.

RULE 3 — ops-role DOES NOT EXIST in this cluster. Do not reference it.
  Real wildcard roles are: pci-wildcard-role and nist-ac-wildcard-role (cluster-scoped).
  Real binding evidence: pci-wildcard-binding → pci-wildcard-role → card-processor-sa.

RULE 4 — etcd peer auth (CIS 2.5) fix: edit the etcd manifest ONLY.
  Correct path: /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml
  Add flag: --peer-client-cert-auth=true
  NEVER suggest: kubectl patch deployment kube-apiserver for etcd flags.
  Add risk note: Single-node cluster — peer URLs are localhost only.
  Exploitability is LOW despite FAIL. Verify peer TLS cert files exist before
  enabling or etcd will crash on restart.

RULE 5 — patient-db root execution fix (HIPAA-164.308(a)(3)):
  The ONLY correct command is:
  {patient_db_patch_cmd}
  NEVER suggest kubectl set env or environment variables for this finding.
  Credentials are a separate concern handled via Kubernetes Secrets.

RULE 6 — HIPAA 164.312(a)(1) is PASS. Evidence: Cilium L4 NetworkPolicy (api-to-db)
  restricts patient-db ingress to patient-api on TCP/5432. It is L4 not L7.
  Do not describe this as an L7 policy.

RULE 7 — CIS 5.3.2 FAIL evidence: CiliumNetworkPolicy api-to-db exists at L4.
  No L7/HTTP policy found. Fails CIS 5.3.2 if L7 enforcement is required.

RULE 8 — Do NOT conflate root execution with network path controls.
  patient-db root execution maps to: CIS 5.2.10 + HIPAA-164.308(a)(3) + T1609.
  CIS 5.3.3 is about the frontend-to-db network path — completely separate finding.
  PCI-DSS Req 2.2 for root execution must note it is scoped to MITRE simulation
  namespaces — healthcare is clean for privileged containers.

RULE 9 — kubectl patch target for patient-db is a DEPLOYMENT not a StatefulSet.
  Pod name patient-db-54db48969c-m26z8 (two random suffixes) confirms Deployment.
  StatefulSet pods have only one random suffix (patient-db-0, patient-db-1).
  Always use: kubectl patch deployment patient-db -n healthcare ...
  Never use: kubectl patch statefulset patient-db ...

RULE 10 — EVT-1.2 (Forbidden events) is a runtime detection, not a config issue.
  Do not group it with configuration remediations.
  Flag it as: investigate immediately — possible active reconnaissance (T1552.007).
  Remediation: kubectl get events -A --field-selector reason=Forbidden | grep secrets.

CLUSTER SCOPE NOTE (include this verbatim in Section 1):
This cluster contains purpose-built compliance demonstration namespaces
(pci-cde-pass, pci-cde-fail, nist-hardened, nist-*-fail, mitre-detect,
mitre-runtime). Findings scoped to the healthcare namespace reflect production
workload posture. Cluster-wide findings include simulation namespaces and should
be interpreted accordingly.
"""

    if not has_workloads:
        prompt = f"""You are a Kubernetes security expert.

{intelligence_sources}

{anti_hallucination}

WORKLOAD STATUS: {workload_msg}
No application workloads detected. Only infrastructure-level checks were performed.

SCAN: {state['total_passed'] + state['total_failed']} controls | \
{state['total_passed']} passed | {state['total_failed']} failed

FAILED CONTROLS (infrastructure only):
{chr(10).join(failed_controls) if failed_controls else 'None — all infrastructure controls passed.'}

RAG CONTEXT:
{chr(10).join(state['cis_context'])}

Write exactly these sections:

SECTION 1 — OVERALL STATUS
State COMPLIANT or NON-COMPLIANT. State no application workloads detected.
Include the cluster scope note verbatim.

SECTION 2 — INTELLIGENCE AVAILABLE
List all 9 intelligence sources. State they will be applied when workloads deploy.

SECTION 3 — INFRASTRUCTURE FINDINGS (CIS / NIST / NSA)
Top 3 infrastructure failures: Control ID | evidence | exact remediation command.

SECTION 4 — WHAT WILL BE CHECKED WHEN WORKLOADS DEPLOY
List: CIS 5.2.x Pod Security | CIS 5.3.x Network Policies |
HIPAA §164.308/310/312 (if healthcare namespace) |
PCI-DSS Req 2/7/10/12 | MITRE ATT&CK container techniques.

SECTION 5 — MITRE ATT&CK INFRASTRUCTURE THREAT MAP
Map each infrastructure failure to its T-number and technique name.

SECTION 6 — PRIORITY REMEDIATION
Top 3 actions with exact commands. Follow all rules above.

500 words max. No markdown bold (**). No bullet symbols."""

    else:
        hipaa_note = (
            "HIPAA-RELEVANT WORKLOADS DETECTED: healthcare namespace with "
            f"{', '.join(workload_list)}. "
            "HIPAA §164.308/310/312 checks were executed against these workloads."
            if has_healthcare else
            "No healthcare namespace detected. "
            "HIPAA checks were not applicable to this scan."
        )

        # ── Rule 5 command also referenced inline in the workload prompt ──────
        rule5_inline = (
            f"the ONLY correct fix is: {patient_db_patch_cmd}"
            " — do NOT suggest kubectl set env or environment variables."
        )

        prompt = f"""You are a Kubernetes security and adversarial threat expert.

{intelligence_sources}

{anti_hallucination}

WORKLOAD STATUS: {workload_msg}
Running workloads: {', '.join(workload_list)}

{hipaa_note}

SCAN: {state['total_passed'] + state['total_failed']} controls | \
{state['total_passed']} passed | {state['total_failed']} failed

FAILED CONTROLS (only cite these — nothing else):
{chr(10).join(failed_controls)}

RAG CONTEXT (all 9 sources):
{chr(10).join(state['cis_context'])}

CRITICAL ANTI-HALLUCINATION RULES — VIOLATIONS WILL CAUSE CUSTOMER ESCALATION:
1. You may ONLY cite findings that appear in the FAILED CONTROLS list above. If a control is not in that list, it PASSED — do not reference it as a failure.
2. CIS 5.2.2 (privileged containers) PASSED for the healthcare namespace — do not cite it as a PCI-DSS violation.
3. CIS 5.1.3 PASSED — ops-role does NOT exist. Do not reference ops-role. The real wildcard roles are pci-wildcard-role and nist-ac-wildcard-role found at cluster scope.
4. For etcd peer auth (CIS 2.5): the correct fix edits /var/lib/rancher/rke2/agent/pod-manifests/etcd.yaml — NOT kube-apiserver. Never suggest kubectl patch deployment kube-apiserver for etcd flags. Add this risk note: "Single-node cluster — peer URLs are localhost only, exploitability is LOW despite FAIL. Verify peer TLS cert files exist before enabling --peer-client-cert-auth=true or etcd will crash on restart."
5. For patient-db root execution (HIPAA-164.308(a)(3)): {rule5_inline}

Write exactly these 6 sections. Every section is mandatory.
SECTION 1 — OVERALL STATUS
COMPLIANT or NON-COMPLIANT. One sentence why.
List all 9 intelligence sources checked.
State workloads found: {', '.join(workload_list)}.
Include the cluster scope note verbatim.
{'State healthcare namespace was assessed for HIPAA.' if has_healthcare else 'State no healthcare namespace detected — HIPAA not applicable.'}

SECTION 2 — CIS KUBERNETES (CIS Benchmark v2.0.0 + NSA Guide v1.0/v1.2)
Top 3 CIS failures from the FAILED CONTROLS list only.
Format: Control ID | Severity | Evidence | Exact fix.
For CIS 2.5 etcd: follow RULE 4 exactly.

SECTION 3 — HIPAA ASSESSMENT (HIPAA Security Rule + Privacy Rule + NIST HIPAA Toolkit)
{'Map each ePHI failure to exact paragraph §164.308/310/312. State whether patient data is at immediate risk. For patient-db root execution use RULE 5 command only. For 164.312(a)(1) use RULE 6 evidence.' if has_healthcare else 'State clearly: No healthcare namespace detected. HIPAA checks not applicable. HIPAA will run automatically when healthcare workloads are deployed.'}

SECTION 4 — PCI-DSS ASSESSMENT (PCI-DSS v4.0.1)
Map failures from FAILED CONTROLS list to Req 2, 7, 10, 12.
Use RULE 3 for wildcard RBAC evidence — cite pci-wildcard-binding not ops-role.
If a requirement has no matching failed control, state that explicitly.

SECTION 5 — MITRE ATT&CK THREAT MAP (MITRE ATT&CK Enterprise)
For every CRITICAL and HIGH finding, cite the ATT&CK technique.
Format: [T-number] Technique Name — how this finding enables the attack.
Minimum 4 mappings. Use: T1611, T1552.007, T1098.006, T1613, T1610, T1609.
For T1552.007: cite pci-wildcard-binding evidence (RULE 3).
For T1098.006: cite mitre-runtime/t1612-image-build docker:dind evidence.
For T1611: add scope note — healthcare namespace IS segmented via L4 policy.
            Active evidence is mitre-detect/t1611-escape-to-host simulation pod.
T1613 is MANDATORY: cite t1613-discovery-binding wildcard ClusterRole +
mitre-network/t1046-network-scan actively running.

THE FOLLOWING IS SECTION 6. COPY IT EXACTLY AS WRITTEN. DO NOT REPHRASE, REORDER, OR ADD CONTROL IDs:

{prebuilt_section6}

600 words max. No markdown bold (**). No bullet symbols. Plain text with newlines."""

    summary = "AI summary unavailable — manual review required."
    for attempt in range(3):
        try:
            summary = llm.invoke(prompt).content
            break
        except Exception as e:
            if attempt == 2:
                logger.error(f"[{state['scan_id']}] LLM failed after 3 attempts: {e}")
            else:
                wait = 2 ** attempt
                logger.warning(
                    f"[{state['scan_id']}] LLM attempt {attempt+1} failed, "
                    f"retrying in {wait}s"
                )
                time.sleep(wait)

    status = "NON-COMPLIANT" if state["total_failed"] > 0 else "COMPLIANT"
    return {**state, "summary": summary, "status": status}


# ── Build graph ───────────────────────────────────────────────────────────────
def build_agent():
    graph = StateGraph(ComplianceState)

    graph.add_node("run_preflight",       run_preflight)
    graph.add_node("detect_workloads",    detect_workloads)
    graph.add_node("run_security_checks", run_security_checks)
    graph.add_node("run_mitre_mapping",   run_mitre_mapping_node)
    graph.add_node("run_hipaa_pci",       run_hipaa_pci_node)
    graph.add_node("fetch_cis_context",   fetch_cis_context)
    graph.add_node("generate_summary",    generate_summary)

    graph.set_entry_point("run_preflight")

    graph.add_conditional_edges(
        "run_preflight",
        lambda s: "blocked" if s.get("status") == "BLOCKED" else "continue",
        {"blocked": END, "continue": "detect_workloads"}
    )

    graph.add_edge("detect_workloads",    "run_security_checks")
    graph.add_edge("run_security_checks", "run_mitre_mapping")
    graph.add_edge("run_mitre_mapping",   "run_hipaa_pci")
    graph.add_edge("run_hipaa_pci",       "fetch_cis_context")
    graph.add_edge("fetch_cis_context",   "generate_summary")
    graph.add_edge("generate_summary",    END)

    return graph.compile()


# ── Standalone run ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from reports.pdf_generator import generate_report

    agent   = build_agent()
    scan_id = f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    result = agent.invoke(ComplianceState(
        scan_id=scan_id,
        start_time=datetime.now(timezone.utc).isoformat(),
        api_server_findings={},     etcd_findings={},
        rbac_findings={},           pod_security_findings={},
        network_policy_findings={}, hipaa_evidence={},
        node_health_findings={},    namespace_findings={},
        event_findings={},          pod_log_findings={},
        mitre_findings={},          hipaa_pci_findings={},
        has_workloads=False,
        has_healthcare=False,
        has_pci=False,
        workload_list=[],
        workload_namespaces=[],
        workload_message="",
        cis_context=[],
        summary="",
        total_passed=0,
        total_failed=0,
        status="PENDING",
        preflight_report={},
    ))

    print(f"\nStatus       : {result['status']}")
    print(f"Passed       : {result['total_passed']}")
    print(f"Failed       : {result['total_failed']}")
    print(f"Has Workloads: {result['has_workloads']}")
    print(f"Healthcare   : {result['has_healthcare']}")
    print(f"\nSummary:\n{result['summary']}")
    pdf = generate_report(result)
    print(f"\nPDF: {pdf}")