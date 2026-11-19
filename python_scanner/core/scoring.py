from __future__ import annotations

from collections import defaultdict

from python_scanner.core.models import Finding


PENALTIES = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


def calculate_scores(findings: list[Finding]) -> tuple[int, dict[str, int]]:
    overall = max(0, min(100, 100 - sum(PENALTIES[item.severity] for item in findings)))
    categories: dict[str, list[int]] = defaultdict(list)
    for item in findings:
        categories[item.category].append(PENALTIES[item.severity])
    category_scores = {
        category: max(0, 100 - sum(values))
        for category, values in sorted(categories.items())
    }
    for category in ("syntax", "quality", "complexity", "maintainability",
                     "standards", "security", "dependencies"):
        category_scores.setdefault(category, 100)
    return overall, category_scores
