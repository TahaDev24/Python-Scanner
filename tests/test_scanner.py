from pathlib import Path

from python_scanner.core.config import ScannerConfig
from python_scanner.core.engine import Scanner
from python_scanner.core.models import Finding
from python_scanner.core.scoring import calculate_scores


def test_scans_python_file_and_reports_mutable_default(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("def collect(items=[]):\n    return items\n", encoding="utf-8")
    result = Scanner().scan(source)
    assert result.scanned_files == 1
    assert any(item.rule_id == "QLT002" for item in result.findings)
    assert result.score < 100


def test_syntax_error_is_reported(tmp_path: Path):
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n    pass\n", encoding="utf-8")
    result = Scanner().scan(source)
    assert any(item.rule_id == "SYN001" for item in result.findings)


def test_excluded_directory_is_skipped(tmp_path: Path):
    hidden = tmp_path / ".venv" / "lib.py"
    hidden.parent.mkdir()
    hidden.write_text("x = 1\n", encoding="utf-8")
    result = Scanner().scan(tmp_path)
    assert result.scanned_files == 0
    assert result.skipped_files == 1


def test_score_is_bounded():
    items = [
        Finding("X", "Example", "Message", "high", "quality", "x.py"),
        Finding("Y", "Example", "Message", "low", "security", "y.py"),
    ]
    overall, categories = calculate_scores(items)
    assert overall == 86
    assert categories["quality"] == 88
    assert categories["security"] == 98


def test_invalid_config_value_is_rejected(tmp_path: Path):
    config_file = tmp_path / ".python-scanner.toml"
    config_file.write_text("[scanner]\nmax_files = 0\n", encoding="utf-8")
    try:
        ScannerConfig.from_file(config_file)
    except ValueError as exc:
        assert "positive integer" in str(exc)
    else:
        raise AssertionError("Invalid config should fail")
