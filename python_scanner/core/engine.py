from __future__ import annotations

import time
from pathlib import Path

from python_scanner.analyzers.architecture import ArchitectureAnalyzer
from python_scanner.analyzers.complexity import ComplexityAnalyzer
from python_scanner.analyzers.dependencies import DependencyAnalyzer
from python_scanner.analyzers.maintainability import MaintainabilityAnalyzer
from python_scanner.analyzers.performance import PerformanceAnalyzer
from python_scanner.analyzers.quality import QualityAnalyzer
from python_scanner.analyzers.security import SecurityAnalyzer
from python_scanner.analyzers.standards import StandardsAnalyzer
from python_scanner.analyzers.syntax import SyntaxAnalyzer
from python_scanner.core.config import ScannerConfig
from python_scanner.core.discovery import discover_python_files
from python_scanner.core.models import ScanResult
from python_scanner.core.scoring import calculate_scores


class Scanner:
    """Coordinate built-in analyzers without importing or executing target code."""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self.analyzers = [
            SyntaxAnalyzer(), QualityAnalyzer(), ComplexityAnalyzer(),
            MaintainabilityAnalyzer(), PerformanceAnalyzer(),
            StandardsAnalyzer(self.config.max_line_length), SecurityAnalyzer(),
        ]
        self.dependency_analyzer = DependencyAnalyzer()
        self.architecture_analyzer = ArchitectureAnalyzer()

    def scan(self, target: str | Path) -> ScanResult:
        started = time.perf_counter()
        path = Path(target).expanduser().resolve()
        files, skipped = discover_python_files(path, self.config)
        result = ScanResult(str(path), scanned_files=0, skipped_files=skipped)
        for file_path in files:
            relative = file_path.relative_to(path).as_posix() if path.is_dir() else file_path.name
            try:
                source = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                result.skipped_files += 1
                result.errors.append(f"{relative}: file is not valid UTF-8")
                continue
            except OSError as exc:
                result.skipped_files += 1
                result.errors.append(f"{relative}: {exc}")
                continue
            result.scanned_files += 1
            for analyzer in self.analyzers:
                try:
                    result.findings.extend(analyzer.analyze(file_path, source, relative))
                except Exception as exc:
                    result.errors.append(f"{relative} [{analyzer.name}]: {exc}")
        if path.is_dir():
            result.findings.extend(self.dependency_analyzer.analyze_project(path, files))
            result.findings.extend(self.architecture_analyzer.analyze_project(path, files))
        result.findings.sort(key=lambda item: (
            item.path, item.line or 0, item.rule_id, item.message
        ))
        result.score, result.category_scores = calculate_scores(result.findings)
        result.duration_seconds = time.perf_counter() - started
        result.finalize()
        return result
