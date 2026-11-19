import ast
from pathlib import Path

from python_scanner.core.models import Finding


class SyntaxAnalyzer:
    name = "syntax"

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        try:
            ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            return [Finding(
                rule_id="SYN001", title="Python syntax error",
                message=exc.msg, severity="high", category="syntax",
                path=relative_path, line=exc.lineno, column=exc.offset,
                suggestion="Fix the syntax error before running or packaging this file.",
            )]
        return []
