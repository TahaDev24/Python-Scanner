# Python Scanner

<p align="center">
  <strong>A practical code-quality analysis platform for Python projects.</strong><br>
  Inspect quality, complexity, maintainability, dependencies, and security signals — locally.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Cross--platform-64748b">
  <img alt="Analysis" src="https://img.shields.io/badge/Analysis-Static-0f766e">
  <img alt="Status" src="https://img.shields.io/badge/Status-Early%20development-orange">
</p>

<p align="center">
  <a href="https://github.com/TahaDev24/Python-Scanner/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/TahaDev24/Python-Scanner/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/TahaDev24/Python-Scanner/issues"><img alt="Issues" src="https://img.shields.io/github/issues/TahaDev24/Python-Scanner"></a>
  <a href="https://github.com/TahaDev24/Python-Scanner/stargazers"><img alt="Stars" src="https://img.shields.io/github/stars/TahaDev24/Python-Scanner"></a>
</p>

Python Scanner is a local-first static analysis tool for understanding the health of Python codebases. It combines a reusable analysis engine with two interfaces:

- **CLI** for automation, scripts, and terminal workflows.
- **Desktop UI** built with Kivy for interactive local scans.

Every reported issue includes a rule identifier, severity, location, and actionable message. Scores help prioritize review; they are not a certification of correctness or security.

## Highlights

- Analyze a single Python file or an entire project directory.
- Parse source with Python's AST without importing or executing the target project.
- Inspect syntax, maintainability, complexity, coding conventions, common security-sensitive patterns, and declared dependencies.
- Produce deterministic JSON reports for CI and tooling.
- Use the same engine from the CLI and optional Kivy desktop interface.
- Configure exclusions and file-size limits.
- Run offline; no source code is uploaded.

## Quick start

Python 3.10 or newer is required.

~~~bash
git clone https://github.com/TahaDev24/Python-Scanner.git
cd Python-Scanner
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
~~~

Scan a project:

~~~bash
python -m python_scanner ./path/to/project
~~~

Export a JSON report:

~~~bash
python -m python_scanner ./path/to/project --format json --output report.json
~~~

Show all options:

~~~bash
python -m python_scanner --help
~~~

## Desktop interface

The desktop interface is an optional extra:

~~~bash
python -m pip install -e ".[desktop]"
python -m python_scanner.desktop
~~~

Kivy availability depends on your operating system and Python environment. On Android, use a compatible Kivy/Pydroid setup; desktop installation instructions may not apply directly.

## Analysis coverage

| Area | Built-in checks |
|---|---|
| Syntax | Parse errors with file and line information |
| Quality | Mutable defaults, bare except, TODO markers, oversized functions, basic naming signals |
| Complexity | Approximate cyclomatic complexity per function |
| Maintainability | Long functions and complexity-oriented signals |
| Standards | Trailing whitespace, tabs, configurable line-length checks |
| Security | Risky calls such as eval / exec, unsafe deserialization signals, shell execution, credential-like literals |
| Dependencies | Declared packages and imports discovered in source files |

The built-in checks are conservative and do not implement every Python style or security rule. Optional tools such as Ruff and Bandit can add further coverage in future integrations.

## Quality score

The overall score is a weighted heuristic derived from findings. Higher-severity findings have a larger impact. Category scores are also provided so a single number does not hide the source of problems.

A score is **not** proof that code is correct, performant, maintainable, or secure. Always review findings in context.

## Configuration

Create a .python-scanner.toml file at the project root:

~~~toml
[scanner]
max_files = 5000
max_file_size = 1000000
max_line_length = 100
exclude = [".git/**", ".venv/**", "venv/**", "build/**", "dist/**"]
~~~

See docs/configuration.md for all settings.

## Architecture

~~~text
python_scanner/
├── analyzers/       # Independent static analyzers
├── core/            # Discovery, models, scoring, orchestration
├── cli.py           # Command-line interface
└── desktop.py       # Optional Kivy interface
tests/               # Automated tests
docs/                # User and contributor documentation
~~~

The core does not import Kivy. Both interfaces call the same scan API.

## Safety and privacy

- The scanner reads source files as text and parses Python syntax.
- It does not import, run, or execute the project being scanned.
- It does not upload source code or reports.
- Secret-like values are not copied into finding messages.
- Reports may contain local file paths and should be reviewed before sharing.
- Only scan projects you own or are authorized to inspect.

Static analysis can produce false positives and false negatives. A clean report is not a security guarantee. For security-sensitive software, combine static analysis with tests, dependency auditing, code review, and runtime controls.

## Development

~~~bash
python -m pip install -e ".[dev]"
pytest
ruff check .
~~~

See CONTRIBUTING.md, docs/architecture.md, docs/scoring.md, and docs/rules.md.

## Project status

Python Scanner is in early development. The analysis engine and CLI are the primary supported surfaces. The desktop interface is optional and may have platform-specific limitations.

## License

No license has been selected for this repository. Until one is added, the default copyright rules apply; do not assume permission to reuse or redistribute this project.
