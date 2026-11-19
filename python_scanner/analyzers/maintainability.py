import ast
from pathlib import Path

from python_scanner.core.models import Finding


class MaintainabilityAnalyzer:
    name = "maintainability"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            end = getattr(node, "end_lineno", node.lineno)
            line_count = end - node.lineno + 1
            if line_count > 60:
                findings.append(Finding(
                    "MAN001", "Long function",
                    f"Function '{node.name}' spans {line_count} lines.",
                    "low", "maintainability", relative_path, node.lineno,
                    suggestion="Extract cohesive blocks into smaller, focused functions.",
                ))
            depth = _maximum_nesting(node.body)
            if depth >= 5:
                findings.append(Finding(
                    "MAN002", "Deeply nested function",
                    f"Function '{node.name}' reaches a nesting depth of {depth}.",
                    "medium" if depth >= 7 else "low",
                    "maintainability", relative_path, node.lineno,
                    suggestion="Use guard clauses or extract nested logic into helper functions.",
                ))
        return findings


def _maximum_nesting(statements: list[ast.stmt], depth: int = 0) -> int:
    maximum = depth
    nested_types = (
        ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
        ast.AsyncWith, ast.Try, ast.ExceptHandler,
    )
    for statement in statements:
        if isinstance(statement, nested_types):
            children: list[list[ast.stmt]] = []
            for field_name in ("body", "orelse", "finalbody", "handlers"):
                value = getattr(statement, field_name, [])
                if isinstance(value, list):
                    children.extend(
                        item.body if isinstance(item, ast.ExceptHandler) else [item]
                        for item in value
                    )
            flattened = [item for group in children for item in group]
            maximum = max(maximum, _maximum_nesting(flattened, depth + 1))
        else:
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.stmt):
                    maximum = max(maximum, _maximum_nesting([child], depth))
    return maximum
