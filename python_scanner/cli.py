from __future__ import annotations

import argparse
import sys
from pathlib import Path

from python_scanner import __version__
from python_scanner.core.config import ScannerConfig
from python_scanner.core.engine import Scanner
from python_scanner.reporting import to_json, to_text, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python-scanner",
        description="Analyze Python code quality, complexity, maintainability, and security signals.",
    )
    parser.add_argument("target", nargs="?", default=".", help="Python file or project directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    parser.add_argument("--output", help="Write the report to this path")
    parser.add_argument("--config", help="Path to a .python-scanner.toml configuration file")
    parser.add_argument("--max-files", type=int, help="Maximum number of Python files to inspect")
    parser.add_argument("--max-file-size", type=int, help="Maximum source file size in bytes")
    parser.add_argument("--max-line-length", type=int, help="Configured line length threshold")
    parser.add_argument("--fail-under", type=int, help="Exit with status 1 when score is below this value")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.fail_under is not None and not 0 <= args.fail_under <= 100:
        parser.error("--fail-under must be between 0 and 100")
    config_path = Path(args.config) if args.config else Path(args.target).expanduser()
    if config_path.is_dir():
        config_path = config_path / ".python-scanner.toml"
    elif config_path.is_file() and config_path.name != ".python-scanner.toml":
        config_path = config_path.parent / ".python-scanner.toml"
    try:
        config = ScannerConfig.from_file(config_path)
        for key in ("max_files", "max_file_size", "max_line_length"):
            value = getattr(args, key)
            if value is not None:
                if value < 1:
                    parser.error(f"--{key.replace('_', '-')} must be positive")
                setattr(config, key, value)
        scanner = Scanner(config)
        if args.max_line_length is not None:
            scanner.analyzers = [
                analyzer if analyzer.name != "standards" else
                __import__("python_scanner.analyzers.standards", fromlist=["StandardsAnalyzer"])
                .StandardsAnalyzer(config.max_line_length)
                for analyzer in scanner.analyzers
            ]
        result = scanner.scan(args.target)
    except (OSError, ValueError) as exc:
        print(f"python-scanner: error: {exc}", file=sys.stderr)
        return 2
    output = to_json(result) if args.output_format == "json" else to_text(result)
    if args.output:
        if args.output_format == "json":
            write_json(result, args.output)
        else:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)
    return 1 if args.fail_under is not None and result.score < args.fail_under else 0


if __name__ == "__main__":
    raise SystemExit(main())
