import ast
from pathlib import Path

from python_scanner.core.models import Finding


class QualityAnalyzer:
    name = "quality"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(Finding(
                    "QLT001", "Bare except clause",
                    "A bare except catches nearly every exception and can hide unexpected failures.",
                    "medium", "quality", relative_path, node.lineno,
                    suggestion="Catch the specific exception types the code can handle.",
                ))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defaults = node.args.defaults + [item for item in node.args.kw_defaults if item is not None]
                if any(isinstance(item, (ast.List, ast.Dict, ast.Set)) for item in defaults):
                    findings.append(Finding(
                        "QLT002", "Mutable default argument",
                        f"Function '{node.name}' uses a mutable default argument.",
                        "high", "quality", relative_path, node.lineno,
                        suggestion="Use None as the default and create the mutable value inside the function.",
                    ))
                end = getattr(node, "end_lineno", node.lineno)
                if end - node.lineno + 1 > 60:
                    findings.append(Finding(
                        "QLT003", "Long function",
                        f"Function '{node.name}' spans {end - node.lineno + 1} lines.",
                        "low", "maintainability", relative_path, node.lineno,
                        suggestion="Consider extracting cohesive blocks into smaller functions.",
                    ))
                if not node.name.startswith("_") and not node.name.islower():
                    findings.append(Finding(
                        "QLT004", "Function naming convention",
                        f"Function '{node.name}' does not follow the usual snake_case convention.",
                        "info", "standards", relative_path, node.lineno,
                        suggestion="Use lowercase words separated by underscores for function names.",
                    ))
        for lineno, line in enumerate(source.splitlines(), 1):
            if "TODO" in line or "FIXME" in line:
                findings.append(Finding(
                    "QLT005", "Pending work marker",
                    "This line contains a TODO or FIXME marker.",
                    "info", "quality", relative_path, lineno,
                    suggestion="Track remaining work or remove the marker when resolved.",
                ))
        return findings
