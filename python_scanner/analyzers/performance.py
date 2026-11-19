import ast
from pathlib import Path

from python_scanner.core.models import Finding


class PerformanceAnalyzer:
    name = "performance"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "sum"
                and node.args
                and isinstance(node.args[0], ast.ListComp)
            ):
                findings.append(Finding(
                    "PERF001", "Unnecessary list materialization",
                    "sum() receives a list comprehension and may allocate a temporary list.",
                    "low", "performance", relative_path, node.lineno,
                    suggestion="Use a generator expression when values only need to be iterated once.",
                ))
        return findings
