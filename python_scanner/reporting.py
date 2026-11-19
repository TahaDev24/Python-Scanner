from __future__ import annotations

import json
from pathlib import Path

from python_scanner.core.models import ScanResult


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=indent)


def write_json(result: ScanResult, destination: str | Path) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_json(result) + "\n", encoding="utf-8")
    return path


def to_text(result: ScanResult) -> str:
    lines = [
        f"Python Scanner — {result.target}",
        "=" * 72,
        f"Score: {result.score}/100",
        f"Files scanned: {result.scanned_files} | skipped: {result.skipped_files}",
        f"Findings: {len(result.findings)} | Duration: {result.duration_seconds:.2f}s",
        "",
        "Category scores:",
    ]
    lines.extend(f"  {name:18} {score:3}/100" for name, score in result.category_scores.items())
    lines.append("")
    if not result.findings:
        lines.append("No findings from the enabled built-in rules.")
    for item in result.findings:
        location = f"{item.path}:{item.line}" if item.line else item.path
        lines.append(f"[{item.severity.upper():8}] {item.rule_id} {location} — {item.title}")
        lines.append(f"           {item.message}")
        if item.suggestion:
            lines.append(f"           Suggestion: {item.suggestion}")
    if result.errors:
        lines.extend(["", "Scan warnings:"])
        lines.extend(f"  - {error}" for error in result.errors)
    return "\n".join(lines)
