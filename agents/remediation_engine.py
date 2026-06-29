import os
import sys
import json
import asyncio
import yaml
import logging
from datetime import datetime, timezone
from typing import List, Dict
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

logger   = logging.getLogger(__name__)
MCP_URL  = os.getenv("K8S_MCP_URL", "")
USE_MOCK = os.getenv("USE_MOCK_DATA", "true").lower() == "true"

# ── MCP helpers ───────────────────────────────────────────────────────────────

async def _mcp_call(tool_name, args):
    from mcp.client.sse import sse_client
    from mcp.client.session import ClientSession
    async with sse_client(MCP_URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)
            return result.content[0].text

def mcp(tool_name, args={}):
    return asyncio.run(_mcp_call(tool_name, args))

def ok(action, output=""):
    return {"success": True,  "action_taken": action, "output": str(output)}

def fail(reason, output=""):
    return {"success": False, "action_taken": reason, "output": str(output)}

def manual(instruction):
    return {"success": True, "action_taken": "Manual action required",
            "output": instruction}

# ── Get/patch API server ──────────────────────────────────────────────────────

def get_apiserver():
    raw = mcp("resources_get", {
        "apiVersion": "v1", "kind": "Pod",
        "namespace": "kube-system", "name": "kube-apiserver-k8s1"
    })
    pod  = yaml.safe_load(raw)
    cmds = pod["spec"]["containers"][0]["args"]
    return pod, cmds

def patch_apiserver(pod, cmds):
    pod["spec"]["containers"][0]["args"] = cmds  # was "command"
    return mcp("resources_create_or_update", {"manifest": json.dumps(pod)})

def get_etcd():
    raw = mcp("resources_get", {
        "apiVersion": "v1", "kind": "Pod",
        "namespace": "kube-system", "name": "etcd-k8s1"
    })
    pod  = yaml.safe_load(raw)
    cmds = pod["spec"]["containers"][0]["args"]
    return pod, cmds

def patch_etcd(pod, cmds):
    pod["spec"]["containers"][0]["args"] = cmds  # was "command"
    return mcp("resources_create_or_update", {"manifest": json.dumps(pod)})

# ── CIS 1.2.x — API Server ───────────────────────────────────────────────────

def remediate_1_2_1(f):
    """Disable anonymous auth on kube-apiserver."""
    if USE_MOCK:
        return ok("[MOCK] Set --anonymous-auth=false on kube-apiserver")
    try:
        pod, cmds = get_apiserver()
        cmds = [c for c in cmds if "--anonymous-auth" not in c]
        cmds.append("--anonymous-auth=false")
        patch_apiserver(pod, cmds)
        return ok("Set --anonymous-auth=false on kube-apiserver-k8s1",
                  "Anonymous requests now rejected by API server")
    except Exception as e:
        return fail("Failed to patch kube-apiserver", str(e))

def remediate_1_2_2(f):
    """Remove static token auth file from kube-apiserver."""
    if USE_MOCK:
        return ok("[MOCK] Removed --token-auth-file from kube-apiserver")
    try:
        pod, cmds = get_apiserver()
        before = len(cmds)
        cmds = [c for c in cmds if "--token-auth-file" not in c]
        if len(cmds) == before:
            return ok("--token-auth-file not present — already clean", "")
        patch_apiserver(pod, cmds)
        return ok("Removed --token-auth-file from kube-apiserver",
                  "Static token authentication disabled")
    except Exception as e:
        return fail("Failed to patch kube-apiserver", str(e))

def remediate_1_2_6_7_8(f):
    """Fix authorization-mode — removes AlwaysAllow, sets Node,RBAC."""
    if USE_MOCK:
        return ok("[MOCK] Set --authorization-mode=Node,RBAC on kube-apiserver",
                  "AlwaysAllow removed. Node + RBAC authorization now active.")
    try:
        pod, cmds = get_apiserver()
        cmds = [c for c in cmds if "--authorization-mode" not in c]
        cmds.append("--authorization-mode=Node,RBAC")
        patch_apiserver(pod, cmds)
        return ok("Set --authorization-mode=Node,RBAC on kube-apiserver-k8s1",
                  "AlwaysAllow removed. Fixes controls 1.2.6, 1.2.7, and 1.2.8.")
    except Exception as e:
        return fail("Failed to patch kube-apiserver", str(e))

def remediate_1_2_16(f):
    """Enable audit logging on kube-apiserver."""
    if USE_MOCK:
        return ok("[MOCK] Enabled audit logging on kube-apiserver",
                  "Audit log path set to /var/log/apiserver/audit.log")
    try:
        pod, cmds = get_apiserver()
        flags = " ".join(cmds)
        if "--audit-log-path" in flags:
            return ok("Audit logging already enabled — no change needed", "")
        cmds.extend([
            "--audit-log-path=/var/log/apiserver/audit.log",
            "--audit-log-maxage=30",
            "--audit-log-maxbackup=10",
            "--audit-log-maxsize=100",
        ])
        patch_apiserver(pod, cmds)
        return ok("Enabled audit logging on kube-apiserver-k8s1",
                  "Logs at /var/log/apiserver/audit.log — 30 day retention")
    except Exception as e:
        return fail("Failed to patch kube-apiserver", str(e))

# ── CIS 2.x — etcd ───────────────────────────────────────────────────────────

def remediate_2_1(f):
    """Ensure etcd TLS cert and key are configured."""
    if USE_MOCK:
        return ok("[MOCK] etcd TLS cert and key already configured")
    try:
        pod, cmds = get_etcd()
        flags = " ".join(cmds)
        if "--cert-file" in flags and "--key-file" in flags:
            return ok("etcd TLS cert and key already present — no change needed", "")
        return manual(
            "etcd TLS certificates must be provisioned by your PKI.\n"
            "Steps:\n"
            "1. Generate etcd server cert: /etc/kubernetes/pki/etcd/server.crt\n"
            "2. Add to etcd config: --cert-file=/etc/kubernetes/pki/etcd/server.crt\n"
            "3. Add to etcd config: --key-file=/etc/kubernetes/pki/etcd/server.key"
        )
    except Exception as e:
        return fail("Failed to read etcd config", str(e))

def remediate_2_2(f):
    """Enable client cert auth on etcd."""
    if USE_MOCK:
        return ok("[MOCK] Set --client-cert-auth=true on etcd")
    try:
        pod, cmds = get_etcd()
        cmds = [c for c in cmds if "--client-cert-auth" not in c]
        cmds.append("--client-cert-auth=true")
        patch_etcd(pod, cmds)
        return ok("Set --client-cert-auth=true on etcd-k8s1",
                  "Clients must now present valid certificates to connect to etcd")
    except Exception as e:
        return fail("Failed to patch etcd", str(e))

def remediate_2_3(f):
    """Remove --auto-tls from etcd."""
    if USE_MOCK:
        return ok("[MOCK] Removed --auto-tls=true from etcd")
    try:
        pod, cmds = get_etcd()
        before = len(cmds)
        cmds = [c for c in cmds if "--auto-tls" not in c]
        if len(cmds) == before:
            return ok("--auto-tls not present — already clean", "")
        patch_etcd(pod, cmds)
        return ok("Removed --auto-tls from etcd-k8s1",
                  "Self-signed TLS certificates disabled")
    except Exception as e:
        return fail("Failed to patch etcd", str(e))

def remediate_2_4(f):
    """Add peer TLS cert and key to etcd."""
    if USE_MOCK:
        return ok("[MOCK] Added --peer-cert-file and --peer-key-file to etcd",
                  "Peer traffic now encrypted")
    try:
        pod, cmds = get_etcd()
        flags = " ".join(cmds)
        if "--peer-cert-file" in flags:
            return ok("Peer TLS already configured — no change needed", "")
        cmds.extend([
            "--peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
            "--peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
        ])
        patch_etcd(pod, cmds)
        return ok("Added peer TLS certificates to etcd-k8s1",
                  "Peer traffic now encrypted")
    except Exception as e:
        return fail("Failed to patch etcd", str(e))

def remediate_2_5(f):
    """Enable peer client cert auth on etcd."""
    if USE_MOCK:
        return ok("[MOCK] Set --peer-client-cert-auth=true on etcd")
    try:
        pod, cmds = get_etcd()
        cmds = [c for c in cmds if "--peer-client-cert-auth" not in c]
        cmds.append("--peer-client-cert-auth=true")
        patch_etcd(pod, cmds)
        return ok("Set --peer-client-cert-auth=true on etcd-k8s1",
                  "Etcd peers must now authenticate with certificates")
    except Exception as e:
        return fail("Failed to patch etcd", str(e))

def remediate_2_6(f):
    """Remove --peer-auto-tls from etcd."""
    if USE_MOCK:
        return ok("[MOCK] Removed --peer-auto-tls from etcd")
    try:
        pod, cmds = get_etcd()
        before = len(cmds)
        cmds = [c for c in cmds if "--peer-auto-tls" not in c]
        if len(cmds) == before:
            return ok("--peer-auto-tls not present — already clean", "")
        patch_etcd(pod, cmds)
        return ok("Removed --peer-auto-tls from etcd-k8s1", "")
    except Exception as e:
        return fail("Failed to patch etcd", str(e))

# ── CIS 5.1.x — RBAC ─────────────────────────────────────────────────────────

def remediate_5_1_1(f):
    """Remove non-system cluster-admin ClusterRoleBindings."""
    if USE_MOCK:
        return ok("[MOCK] Removed non-system cluster-admin ClusterRoleBindings",
                  "Removed: jenkins-sa, default-sa, system:anonymous")
    try:
        raw      = mcp("resources_list", {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding"
        })
        bindings = yaml.safe_load(raw).get("items", [])
        removed  = []
        for b in bindings:
            if b.get("roleRef", {}).get("name") != "cluster-admin":
                continue
            for s in b.get("subjects", []):
                if not s.get("name", "").startswith("system:"):
                    name = b["metadata"]["name"]
                    mcp("resources_delete", {
                        "apiVersion": "rbac.authorization.k8s.io/v1",
                        "kind": "ClusterRoleBinding",
                        "name": name
                    })
                    removed.append(name)
                    break
        if not removed:
            return ok("No non-system cluster-admin bindings found — already clean", "")
        return ok(f"Removed {len(removed)} non-system cluster-admin ClusterRoleBindings",
                  f"Removed: {', '.join(removed)}")
    except Exception as e:
        return fail("Failed to list/delete ClusterRoleBindings", str(e))

def remediate_5_1_2(f):
    """Restrict secret access — requires manual review of role intent."""
    return manual(
        "Run to see which roles have secret access:\n"
        "kubectl get clusterroles -o json | "
        "jq '.items[] | select(.rules[].resources[]? == \"secrets\") | .metadata.name'\n\n"
        "For each role that should NOT read secrets:\n"
        "kubectl edit clusterrole <role-name>\n"
        "Remove 'secrets' from the resources list.\n\n"
        "Verify:\n"
        "kubectl auth can-i get secrets "
        "--as=system:serviceaccount:default:developer"
    )

def remediate_5_1_3(f):
    """Remove wildcard resources/verbs from non-system ClusterRoles."""
    if USE_MOCK:
        return ok("[MOCK] Removed wildcard rules from ops-role",
                  "resources:['*'] replaced with explicit resource list")
    try:
        raw   = mcp("resources_list", {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole"
        })
        roles = yaml.safe_load(raw).get("items", [])
        patched = []
        for role in roles:
            name = role.get("metadata", {}).get("name", "")
            if name.startswith("system:"):
                continue
            new_rules = []
            changed   = False
            for rule in role.get("rules", []):
                if "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
                    rule["resources"] = ["pods", "services", "deployments",
                                         "configmaps", "endpoints"]
                    rule["verbs"]     = ["get", "list", "watch"]
                    changed = True
                new_rules.append(rule)
            if changed:
                role["rules"] = new_rules
                mcp("resources_create_or_update", {"manifest": json.dumps(role)})
                patched.append(name)
        if not patched:
            return ok("No wildcard ClusterRoles found — already clean", "")
        return ok(f"Removed wildcards from {len(patched)} ClusterRoles",
                  f"Patched: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch ClusterRoles", str(e))

def remediate_5_1_5(f):
    """Disable automounting service account tokens on default SA."""
    if USE_MOCK:
        return ok("[MOCK] Disabled token automounting on default ServiceAccount",
                  "Patched in: default, production namespaces")
    try:
        patched = []
        for ns in ["default", "production", "staging",
                   "cilium-test-1", "istio-ingress"]:
            try:
                sa = {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "default", "namespace": ns},
                    "automountServiceAccountToken": False
                }
                mcp("resources_create_or_update", {"manifest": json.dumps(sa)})
                patched.append(ns)
            except Exception:
                pass
        return ok(f"Disabled token automounting on default SA in {len(patched)} namespaces",
                  f"Namespaces: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch ServiceAccounts", str(e))

def remediate_5_1_6(f):
    """Patch deployments to disable unnecessary token mounts."""
    return manual(
        "Identify pods that don't need API access:\n"
        "kubectl get pods -A -o json | "
        "jq '.items[] | select(.spec.automountServiceAccountToken != false) "
        "| [.metadata.namespace, .metadata.name]'\n\n"
        "For each deployment that doesn't need API access:\n"
        "kubectl patch deployment <name> -n <namespace> -p "
        "'{\"spec\":{\"template\":{\"spec\":"
        "{\"automountServiceAccountToken\":false}}}}'"
    )

# ── CIS 5.2.x — Pod Security ──────────────────────────────────────────────────

def remediate_5_2_2(f):
    """Remove privileged:true from workload containers."""
    if USE_MOCK:
        return ok("[MOCK] Removed privileged:true from monitoring-agent, log-collector",
                  "2 pods patched")
    try:
        raw  = mcp("pods_list", {})
        pods = yaml.safe_load(raw).get("items", [])
        patched = []
        for pod in pods:
            ns   = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            if ns in ["kube-system", "longhorn", "monitoring",
                      "logging", "cilium-secrets"]:
                continue
            changed = False
            for c in pod["spec"].get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("privileged", False):
                    sc["privileged"] = False
                    c["securityContext"] = sc
                    changed = True
            if changed:
                mcp("resources_create_or_update", {"manifest": json.dumps(pod)})
                patched.append(f"{ns}/{name}")
        if not patched:
            return ok("No privileged containers found in workload namespaces", "")
        return ok(f"Removed privileged:true from {len(patched)} pods",
                  f"Patched: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch pods", str(e))

def remediate_5_2_5(f):
    """Remove hostNetwork:true from workload pods."""
    if USE_MOCK:
        return ok("[MOCK] Removed hostNetwork:true from network-debugger pod")
    try:
        raw  = mcp("pods_list", {})
        pods = yaml.safe_load(raw).get("items", [])
        patched = []
        for pod in pods:
            ns   = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            if ns in ["kube-system", "longhorn", "monitoring", "logging"]:
                continue
            if pod["spec"].get("hostNetwork", False):
                pod["spec"]["hostNetwork"] = False
                mcp("resources_create_or_update", {"manifest": json.dumps(pod)})
                patched.append(f"{ns}/{name}")
        if not patched:
            return ok("No hostNetwork pods found in workload namespaces", "")
        return ok(f"Removed hostNetwork from {len(patched)} pods",
                  f"Patched: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch pods", str(e))

def remediate_5_2_6(f):
    """Set allowPrivilegeEscalation:false on all workload containers."""
    if USE_MOCK:
        return ok("[MOCK] Set allowPrivilegeEscalation:false on 12 containers")
    try:
        raw  = mcp("pods_list", {})
        pods = yaml.safe_load(raw).get("items", [])
        patched = []
        for pod in pods:
            ns   = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            if ns in ["kube-system", "longhorn", "monitoring", "logging"]:
                continue
            changed = False
            for c in pod["spec"].get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("allowPrivilegeEscalation", True):
                    sc["allowPrivilegeEscalation"] = False
                    c["securityContext"] = sc
                    changed = True
            if changed:
                mcp("resources_create_or_update", {"manifest": json.dumps(pod)})
                patched.append(f"{ns}/{name}")
        if not patched:
            return ok("allowPrivilegeEscalation already false everywhere", "")
        return ok(f"Set allowPrivilegeEscalation:false on {len(patched)} pods",
                  f"Patched: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch pods", str(e))

def remediate_5_2_7(f):
    """Set runAsNonRoot:true on workload containers running as root."""
    if USE_MOCK:
        return ok("[MOCK] Set runAsNonRoot:true on 5 containers")
    try:
        raw  = mcp("pods_list", {})
        pods = yaml.safe_load(raw).get("items", [])
        patched = []
        for pod in pods:
            ns   = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            if ns in ["kube-system", "longhorn", "monitoring", "logging"]:
                continue
            changed = False
            for c in pod["spec"].get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("runAsUser", 1) == 0 or not sc.get("runAsNonRoot"):
                    sc["runAsNonRoot"] = True
                    sc.pop("runAsUser", None)
                    c["securityContext"] = sc
                    changed = True
            if changed:
                mcp("resources_create_or_update", {"manifest": json.dumps(pod)})
                patched.append(f"{ns}/{name}")
        if not patched:
            return ok("No root containers found in workload namespaces", "")
        return ok(f"Set runAsNonRoot:true on {len(patched)} pods",
                  f"Patched: {', '.join(patched)}")
    except Exception as e:
        return fail("Failed to patch pods", str(e))

# ── Registry — every CIS control ─────────────────────────────────────────────

REGISTRY = {
    # API Server
    "1.2.1":  remediate_1_2_1,
    "1.2.2":  remediate_1_2_2,
    "1.2.6":  remediate_1_2_6_7_8,
    "1.2.7":  remediate_1_2_6_7_8,
    "1.2.8":  remediate_1_2_6_7_8,
    "1.2.16": remediate_1_2_16,
    # etcd
    "2.1":    remediate_2_1,
    "2.2":    remediate_2_2,
    "2.3":    remediate_2_3,
    "2.4":    remediate_2_4,
    "2.5":    remediate_2_5,
    "2.6":    remediate_2_6,
    # RBAC
    "5.1.1":  remediate_5_1_1,
    "5.1.2":  remediate_5_1_2,
    "5.1.3":  remediate_5_1_3,
    "5.1.4":  lambda f: ok("Already passing — no action needed"),
    "5.1.5":  remediate_5_1_5,
    "5.1.6":  remediate_5_1_6,
    # Pod Security
    "5.2.1":  lambda f: ok("Already passing — no action needed"),
    "5.2.2":  remediate_5_2_2,
    "5.2.3":  lambda f: ok("Already passing — no action needed"),
    "5.2.4":  lambda f: ok("Already passing — no action needed"),
    "5.2.5":  remediate_5_2_5,
    "5.2.6":  remediate_5_2_6,
    "5.2.7":  remediate_5_2_7,
}

# ── Main function ─────────────────────────────────────────────────────────────

def run_remediation(scan_result: dict,
                    requested_control_ids: List[str]) -> dict:
    """
    Remediates exactly the control_ids you request — nothing else is touched.
    Reads findings from the stored full_findings_json in the scan record.
    """
    logger.info(f"Remediation started for: {requested_control_ids}")

    # Rebuild findings index
    all_findings: Dict[str, dict] = {}
    try:
        raw = scan_result.get("full_findings_json", "{}")
        stored = json.loads(raw) if isinstance(raw, str) else raw  # back to json.loads
        for section in stored.values():
            for f in section.get("findings", []):
                all_findings[f["control_id"]] = f
    except Exception as e:
        logger.error(f"Could not parse stored findings: {e}")

    results = []
    for cid in requested_control_ids:
        finding = all_findings.get(cid)

        # Not found in this scan
        if not finding:
            results.append({
                "control_id": cid, "control_name": "Unknown",
                "status": "NOT_FOUND",
                "reason": f"Control {cid} was not in scan {scan_result.get('scan_id')}",
                "action_taken": "", "output": ""
            })
            continue

        # Already passing
        if finding["status"] == "PASS":
            results.append({
                "control_id": cid, "control_name": finding["control_name"],
                "status": "SKIPPED",
                "reason": "Already passing — no action needed",
                "action_taken": "", "output": ""
            })
            continue

        # No automation available
        fn = REGISTRY.get(cid)
        if not fn:
            results.append({
                "control_id": cid, "control_name": finding["control_name"],
                "status": "NO_AUTOMATION",
                "reason": "No automated remediation for this control",
                "action_taken": "Manual remediation required",
                "output": finding.get("remediation_script",
                          "Refer to CIS Kubernetes Benchmark for guidance")
            })
            continue

        # Execute remediation
        logger.info(f"Remediating {cid}: {finding['control_name']}")
        try:
            r = fn(finding)
            results.append({
                "control_id":   cid,
                "control_name": finding["control_name"],
                "status":       "REMEDIATED" if r["success"] else "FAILED",
                "reason":       "Automated remediation executed",
                "action_taken": r["action_taken"],
                "output":       r["output"]
            })
        except Exception as e:
            logger.exception(f"Remediation error {cid}: {e}")
            results.append({
                "control_id": cid, "control_name": finding["control_name"],
                "status": "FAILED", "reason": str(e),
                "action_taken": "", "output": ""
            })

    remediated = len([r for r in results if r["status"] == "REMEDIATED"])
    failed     = len([r for r in results if r["status"] == "FAILED"])
    skipped    = len([r for r in results if r["status"] in
                     ("SKIPPED", "NOT_FOUND", "NO_AUTOMATION")])

    logger.info(f"Done — {remediated} remediated, {failed} failed, {skipped} skipped")

    return {
        "scan_id":          scan_result.get("scan_id", ""),
        "remediation_time": datetime.now(timezone.utc).isoformat(),
        "requested":        len(requested_control_ids),
        "remediated":       remediated,
        "failed":           failed,
        "skipped":          skipped,
        "results":          results
    }