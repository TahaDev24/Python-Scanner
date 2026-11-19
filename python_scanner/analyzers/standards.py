from pathlib import Path

from python_scanner.core.models import Finding


class StandardsAnalyzer:
    name = "standards"

    def __init__(self, max_line_length: int = 100) -> None:
        self.max_line_length = max_line_length

    def analyze(self, path: Path, source: str, relative_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), 1):
            if line.endswith((" ", "\t")):
                findings.append(Finding(
                    "STD001", "Trailing whitespace", "The line ends with whitespace characters.",
                    "info", "standards", relative_path, lineno,
                    suggestion="Remove trailing whitespace.",
                ))
            if "\t" in line[:len(line) - len(line.lstrip())]:
                findings.append(Finding(
                    "STD002", "Tab indentation", "Indentation contains tab characters.",
                    "low", "standards", relative_path, lineno,
                    suggestion="Use spaces consistently for indentation.",
                ))
            if len(line) > self.max_line_length:
                findings.append(Finding(
                    "STD003", "Line exceeds configured length",
                    f"Line is {len(line)} characters; configured limit is {self.max_line_length}.",
                    "info", "standards", relative_path, lineno,
                    suggestion="Wrap the expression or adjust max_line_length in configuration.",
                ))
        return findings
