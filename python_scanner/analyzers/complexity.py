import ast
from pathlib import Path

from python_scanner.core.models import Finding


class ComplexityAnalyzer:
    name = "complexity"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                      ast.ExceptHandler, ast.IfExp, ast.Assert)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += max(0, len(child.values) - 1)
                elif isinstance(child, ast.comprehension):
                    complexity += len(child.ifs)
            if complexity >= 7:
                severity = "high" if complexity >= 15 else "medium" if complexity >= 10 else "low"
                findings.append(Finding(
                    "CPL001", "High cyclomatic complexity",
                    f"Function '{node.name}' has an estimated complexity of {complexity}.",
                    severity, "complexity", relative_path, node.lineno,
                    suggestion="Reduce branching or split the function into smaller, focused units.",
                ))
        return findings
