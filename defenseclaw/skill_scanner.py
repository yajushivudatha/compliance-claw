import ast
import os
import sys
import inspect
import importlib.util
import logging
from datetime import datetime, timezone
from typing import List, TypedDict

logger = logging.getLogger(__name__)

# ── Return types ──────────────────────────────────────────────────────────────

class SkillIssue(TypedDict):
    severity:    str   # CRITICAL / HIGH / MEDIUM / LOW
    rule:        str   # rule ID
    description: str
    line:        int

class ScanResult(TypedDict):
    skill_name:  str
    status:      str   # PASS / FAIL / WARN
    issues:      List[SkillIssue]
    timestamp:   str

# ── Dangerous patterns to detect ─────────────────────────────────────────────

DANGEROUS_CALLS = {
    "eval":       ("CRITICAL", "Dynamic code execution via eval() — arbitrary code risk"),
    "exec":       ("CRITICAL", "Dynamic code execution via exec() — arbitrary code risk"),
    "os.system":  ("CRITICAL", "Shell execution via os.system() — command injection risk"),
    "__import__": ("HIGH",     "Dynamic import via __import__() — supply chain risk"),
    "compile":    ("HIGH",     "Code compilation via compile() — code injection risk"),
}

DANGEROUS_MODULES = {
    "subprocess": ("CRITICAL", "subprocess module imported — shell execution possible"),
    "pickle":     ("HIGH",     "pickle module imported — deserialization attack possible"),
    "marshal":    ("HIGH",     "marshal module imported — code execution possible"),
}

EXPECTED_MCP_HOST = os.getenv("K8S_MCP_URL", "").split("/")[2].split(":")[0] if os.getenv("K8S_MCP_URL") else ""

EXPECTED_RETURN_KEYS = {
    "tool", "timestamp", "platform", "section",
    "findings", "passed", "failed", "total_checks"
}

# ── AST visitor ───────────────────────────────────────────────────────────────

class DangerousPatternVisitor(ast.NodeVisitor):
    """Walks AST and collects dangerous patterns."""

    def __init__(self):
        self.issues:        List[SkillIssue] = []
        self.tool_functions: List[str]       = []
        self.imports:        List[str]       = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
            if alias.name in DANGEROUS_MODULES:
                sev, desc = DANGEROUS_MODULES[alias.name]
                self.issues.append(SkillIssue(
                    severity=sev, rule="DANGEROUS_IMPORT",
                    description=desc, line=node.lineno
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.module in DANGEROUS_MODULES:
            sev, desc = DANGEROUS_MODULES[node.module]
            self.issues.append(SkillIssue(
                severity=sev, rule="DANGEROUS_IMPORT",
                description=desc, line=node.lineno
            ))
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for eval(), exec(), etc.
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = f"{getattr(node.func.value, 'id', '')}." \
                        f"{node.func.attr}"

        if func_name in DANGEROUS_CALLS:
            sev, desc = DANGEROUS_CALLS[func_name]
            self.issues.append(SkillIssue(
                severity=sev, rule="DANGEROUS_CALL",
                description=f"{func_name}() detected — {desc}",
                line=node.lineno
            ))

        # Check for unexpected outbound HTTP calls
        if func_name in ("requests.get", "requests.post",
                         "requests.put", "requests.delete",
                         "httpx.get", "httpx.post"):
            # Check if URL argument contains unexpected host
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    url = arg.value
                    if EXPECTED_MCP_HOST and EXPECTED_MCP_HOST not in url:
                        self.issues.append(SkillIssue(
                            severity="HIGH", rule="UNEXPECTED_NETWORK",
                            description=f"HTTP call to unexpected host: {url}",
                            line=node.lineno
                        ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # Check if this is a @tool decorated function
        is_tool = any(
            (isinstance(d, ast.Name) and d.id == "tool") or
            (isinstance(d, ast.Attribute) and d.attr == "tool")
            for d in node.decorator_list
        )
        if is_tool:
            self.tool_functions.append(node.name)

            # Check for docstring
            has_docstring = (
                node.body and
                isinstance(node.body[0], ast.Expr) and
                isinstance(node.body[0].value, ast.Constant) and
                isinstance(node.body[0].value.value, str)
            )
            if not has_docstring:
                self.issues.append(SkillIssue(
                    severity="MEDIUM", rule="MISSING_DOCSTRING",
                    description=f"@tool function '{node.name}' has no docstring — "
                                f"security governance requires all skills to be documented",
                    line=node.lineno
                ))

        self.generic_visit(node)


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan_skills(skills_file_path: str = None) -> ScanResult:
    """
    Statically analyses kubernetes_tools.py using AST.
    Does NOT execute the code — reads and analyses source only.
    Returns a ScanResult with all issues found.
    """
    if skills_file_path is None:
        skills_file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tools", "kubernetes_tools.py"
        )

    logger.info(f"[DefenseClaw] Skill Scanner scanning: {skills_file_path}")

    # File existence check
    if not os.path.exists(skills_file_path):
        return ScanResult(
            skill_name="kubernetes_tools",
            status="FAIL",
            issues=[SkillIssue(
                severity="CRITICAL", rule="FILE_NOT_FOUND",
                description=f"Skills file not found: {skills_file_path}",
                line=0
            )],
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    # Read source
    with open(skills_file_path, "r", encoding="utf-8") as f:
        source = f.read()

    # Parse AST
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return ScanResult(
            skill_name="kubernetes_tools",
            status="FAIL",
            issues=[SkillIssue(
                severity="CRITICAL", rule="SYNTAX_ERROR",
                description=f"Syntax error in skills file: {e}",
                line=e.lineno or 0
            )],
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    # Run visitor
    visitor = DangerousPatternVisitor()
    visitor.visit(tree)

    # Check expected @tool functions exist
    expected_tools = {
        "check_api_server_configuration",
        "check_etcd_configuration",
        "check_rbac_configuration",
        "check_pod_security_configuration",
    }
    missing = expected_tools - set(visitor.tool_functions)
    for fn in missing:
        visitor.issues.append(SkillIssue(
            severity="HIGH", rule="MISSING_SKILL",
            description=f"Expected @tool function '{fn}' not found in skills file",
            line=0
        ))

    # Determine status
    critical_or_high = [
        i for i in visitor.issues
        if i["severity"] in ("CRITICAL", "HIGH")
    ]
    status = "FAIL" if critical_or_high else \
             "WARN" if visitor.issues else "PASS"

    result = ScanResult(
        skill_name="kubernetes_tools",
        status=status,
        issues=visitor.issues,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

    logger.info(
        f"[DefenseClaw] Skill Scan: {status} — "
        f"{len(visitor.tool_functions)} tools found, "
        f"{len(visitor.issues)} issues"
    )
    return result