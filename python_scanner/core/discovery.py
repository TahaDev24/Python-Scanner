from __future__ import annotations

from pathlib import Path

from python_scanner.core.config import ScannerConfig


def discover_python_files(target: Path, config: ScannerConfig) -> tuple[list[Path], int]:
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    if target.is_file():
        if target.suffix != ".py":
            raise ValueError("The target file must have a .py extension.")
        if target.stat().st_size > config.max_file_size:
            return [], 1
        return [target], 0
    if not target.is_dir():
        raise ValueError("Target must be a Python file or a directory.")

    files: list[Path] = []
    skipped = 0
    for path in sorted(target.rglob("*.py")):
        try:
            if path.is_symlink():
                skipped += 1
                continue
            relative = path.relative_to(target).as_posix()
            if config.is_excluded(relative) or path.stat().st_size > config.max_file_size:
                skipped += 1
                continue
            files.append(path)
            if len(files) >= config.max_files:
                break
        except OSError:
            skipped += 1
    return files, skipped
