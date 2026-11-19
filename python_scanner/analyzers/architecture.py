import ast
from pathlib import Path

from python_scanner.core.models import Finding


class ArchitectureAnalyzer:
    name = "architecture"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        return []

    def analyze_project(self, root: Path, python_files: list[Path]) -> list[Finding]:
        module_paths: dict[str, Path] = {}
        for file_path in python_files:
            relative = file_path.relative_to(root).with_suffix("")
            parts = list(relative.parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            if parts:
                module_paths[".".join(parts)] = file_path

        graph: dict[str, set[str]] = {name: set() for name in module_paths}
        for module, file_path in module_paths.items():
            try:
                tree = ast.parse(file_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, SyntaxError):
                continue
            for node in ast.walk(tree):
                imported = []
                if isinstance(node, ast.Import):
                    imported = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported = [node.module]
                for name in imported:
                    match = name if name in module_paths else None
                    if match is None:
                        match = next(
                            (candidate for candidate in module_paths
                             if name.startswith(candidate + ".")),
                            None,
                        )
                    if match:
                        graph[module].add(match)

        findings: list[Finding] = []
        visited: set[str] = set()
        active: list[str] = []
        recorded: set[tuple[str, ...]] = set()

        def visit(module: str) -> None:
            if module in active:
                cycle = active[active.index(module):]
                canonical = tuple(sorted(cycle))
                if canonical not in recorded:
                    recorded.add(canonical)
                    source_file = module_paths[module]
                    findings.append(Finding(
                        "ARC001", "Circular local imports",
                        "The local import graph contains a cycle: " + " → ".join(cycle + [module]),
                        "medium", "architecture",
                        source_file.relative_to(root).as_posix(),
                        suggestion="Move shared contracts to a lower-level module or invert the dependency.",
                    ))
                return
            if module in visited:
                return
            active.append(module)
            for dependency in sorted(graph[module]):
                visit(dependency)
            active.pop()
            visited.add(module)

        for module in sorted(graph):
            visit(module)
        return findings
