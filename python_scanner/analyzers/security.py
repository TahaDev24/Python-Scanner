import ast
import re
from pathlib import Path

from python_scanner.core.models import Finding


SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
)


class SecurityAnalyzer:
    name = "security"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (
                func.attr if isinstance(func, ast.Attribute) else ""
            )
            if name in {"eval", "exec"}:
                findings.append(Finding(
                    "SEC001", "Dynamic code execution",
                    f"Call to '{name}' can execute dynamically supplied code.",
                    "high", "security", relative_path, node.lineno,
                    suggestion="Avoid dynamic execution; use an explicit parser or constrained dispatch.",
                ))
            if name == "load" and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "pickle":
                    findings.append(Finding(
                        "SEC002", "Unsafe deserialization signal",
                        "pickle.load can be unsafe when the input is untrusted.",
                        "high", "security", relative_path, node.lineno,
                        suggestion="Do not load pickle data from untrusted sources; prefer a safe data format.",
                    ))
            if name == "run" and isinstance(func, ast.Attribute):
                shell_true = any(
                    keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if shell_true:
                    findings.append(Finding(
                        "SEC003", "Shell execution enabled",
                        "subprocess.run is called with shell=True.",
                        "medium", "security", relative_path, node.lineno,
                        suggestion="Prefer an argument list with shell=False and validate external input.",
                    ))
        for lineno, line in enumerate(source.splitlines(), 1):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                findings.append(Finding(
                    "SEC004", "Possible hard-coded credential",
                    "This line resembles an embedded credential; its value is intentionally omitted.",
                    "high", "security", relative_path, lineno,
                    suggestion="Load secrets from a secure environment or secret manager and rotate exposed credentials.",
                ))
        return findings
