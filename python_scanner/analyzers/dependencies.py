import ast
import re
from pathlib import Path

from python_scanner.core.models import Finding


STANDARD_LIBRARY = {
    "__future__", "abc", "argparse", "array", "ast", "asyncio", "base64", "collections",
    "concurrent", "contextlib", "copy", "csv", "dataclasses", "datetime", "decimal",
    "email", "enum", "fnmatch", "functools", "glob", "hashlib", "heapq", "html", "http",
    "importlib", "inspect", "io", "itertools", "json", "logging", "math", "multiprocessing",
    "operator", "os", "pathlib", "pickle", "platform", "queue", "random", "re", "shutil",
    "signal", "socket", "sqlite3", "statistics", "string", "subprocess", "sys", "tempfile",
    "threading", "time", "tomllib", "traceback", "types", "typing", "unittest", "urllib",
    "uuid", "warnings", "weakref", "xml", "zipfile",
}


def _distribution_name(line: str) -> str | None:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", line)
    return match.group(1).lower().replace("_", "-") if match else None


class DependencyAnalyzer:
    name = "dependencies"

    def analyze_project(self, root: Path, python_files: list[Path]) -> list[Finding]:
        declared: set[str] = set()
        for manifest in (root / "requirements.txt", root / "requirements-dev.txt"):
            if manifest.is_file():
                try:
                    for line in manifest.read_text(encoding="utf-8").splitlines():
                        if line.strip() and not line.lstrip().startswith(("#", "-")):
                            name = _distribution_name(line)
                            if name:
                                declared.add(name)
                except (OSError, UnicodeError):
                    continue
        imported: dict[str, set[str]] = {}
        for file in python_files:
            try:
                tree = ast.parse(file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, SyntaxError):
                continue
            for node in ast.walk(tree):
                module = node.name if isinstance(node, ast.Import) else (
                    node.module if isinstance(node, ast.ImportFrom) else None
                )
                if module:
                    top = module.split(".")[0]
                    if top not in STANDARD_LIBRARY:
                        imported.setdefault(top.lower().replace("_", "-"), set()).add(
                            file.relative_to(root).as_posix()
                        )
        findings: list[Finding] = []
        for module, locations in sorted(imported.items()):
            if module not in declared and module not in {"kivy", "pytest", "ruff", "bandit"}:
                findings.append(Finding(
                    "DEP001", "Import not found in requirements files",
                    f"Import '{module}' was not found in supported requirements manifests.",
                    "info", "dependencies", sorted(locations)[0],
                    suggestion="If this is external, declare it in the project's dependency manifest.",
                ))
        return findings

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        return []
