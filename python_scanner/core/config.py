from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


DEFAULT_EXCLUDES = [
    ".git/**", ".venv/**", "venv/**", "__pycache__/**",
    "build/**", "dist/**", ".tox/**", ".mypy_cache/**",
]


@dataclass(slots=True)
class ScannerConfig:
    max_files: int = 5000
    max_file_size: int = 1_000_000
    max_line_length: int = 100
    exclude: list[str] = field(default_factory=lambda: DEFAULT_EXCLUDES.copy())

    def is_excluded(self, relative_path: str) -> bool:
        normalized = relative_path.replace("\\", "/").lstrip("./")
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in self.exclude)

    @classmethod
    def from_file(cls, path: Path) -> "ScannerConfig":
        if not path.exists():
            return cls()
        with path.open("rb") as stream:
            raw: dict[str, Any] = tomllib.load(stream)
        values = raw.get("scanner", {})
        if not isinstance(values, dict):
            raise ValueError("The [scanner] configuration section must be a table.")
        defaults = cls()
        return cls(
            max_files=_positive_int(values.get("max_files", defaults.max_files), "max_files"),
            max_file_size=_positive_int(values.get("max_file_size", defaults.max_file_size), "max_file_size"),
            max_line_length=_positive_int(values.get("max_line_length", defaults.max_line_length), "max_line_length"),
            exclude=_string_list(values.get("exclude", defaults.exclude), "exclude"),
        )


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer.")
    return value


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings.")
    return value
