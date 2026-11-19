from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: str
    category: str
    path: str
    line: int | None = None
    column: int | None = None
    suggestion: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported severity: {self.severity}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target: str
    scanned_files: int
    skipped_files: int
    findings: list[Finding] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    duration_seconds: float = 0.0
    score: int = 100
    category_scores: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def finalize(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "target": self.target,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "score": self.score,
            "category_scores": self.category_scores,
            "summary": {
                severity: sum(f.severity == severity for f in self.findings)
                for severity in SEVERITY_ORDER
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }
