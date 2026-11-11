# Python Scanner

**Python Scanner** is a Kivy-based static analysis application for reviewing Python files and project folders. It combines syntax inspection, dependency analysis, and security-oriented checks in a mobile-friendly interface, with Android/Pydroid 3 as an important target environment.

> **Safety by design:** the scanner reads and analyzes source files; it does not import or execute the project being inspected.

## Features

| Area | What it does |
|---|---|
| Project discovery | Scans selected Python files or folders and applies limits and ignore rules during discovery. |
| Syntax analysis | Uses Python's `ast` parser to identify syntax errors and inspect code structure. |
| Secret detection | Searches for credential-like patterns using regular expressions and entropy heuristics; masks detected values in findings. |
| Dependency analysis | Reads `requirements.txt` and `pyproject.toml`, and compares declared packages with imports found in source files. |
| Ruff integration | Optionally runs Ruff for additional linting and code-quality findings. |
| Bandit integration | Optionally runs Bandit for additional security-oriented checks. |
| Background scanning | Runs analysis work off the UI thread and communicates progress/results through a queue. |
| Reports | Displays findings in the app and supports exporting scan results as JSON. |

Ruff and Bandit are optional. If they are unavailable, the built-in analysis components can still run.

## Screenshots

*Screenshots can be added here as the interface stabilizes.*

## Requirements

- Python 3.9+
- Kivy 2.2+
- Android with Pydroid 3 is a primary target; desktop environments with a working Kivy installation may also be used.

Optional external analyzers:

```bash
pip install ruff bandit
```

The availability of Kivy and its Android dependencies depends on the runtime environment. On Android, use a Pydroid 3 setup that supports Kivy rather than assuming a standard desktop installation command will work.

## Run

From the repository directory:

```bash
python main.py
```

The legacy launcher is retained for compatibility:

```bash
python python_scanner.py
```

Both commands start the same application.

## Project structure

```text
Python-Scanner/
├── core/
│   ├── __init__.py
│   └── engine.py       # Discovery, analyzers, scan engine, and JSON reporting
├── interface/
│   ├── __init__.py
│   └── app.py          # Kivy interface and application lifecycle
├── main.py             # Canonical application entry point
├── python_scanner.py   # Backward-compatible launcher and API re-export
└── README.md
```

The code is intentionally divided along two main responsibilities:

- **Core** contains scanning and analysis logic and does not depend on the Kivy interface.
- **Interface** contains the Kivy application and imports the core engine.

This keeps the module structure small while making the analysis engine easier to maintain and test independently.

## How a scan works

1. Select a Python file or project folder in the application.
2. The discovery layer collects supported source and dependency files, subject to configured limits and exclusions.
3. The built-in analyzers inspect syntax, source structure, possible secrets, and dependency information.
4. If installed and available, Ruff and Bandit can contribute additional findings.
5. Results are presented in the interface and can be exported as JSON.

## Understanding findings

Static analysis can identify suspicious patterns, syntax problems, and useful review signals, but it cannot prove that a program is secure or detect every runtime issue.

- A possible secret match may be a false positive.
- High entropy is a heuristic, not proof that a string is a credential.
- A detected pattern does not automatically mean an exploitable vulnerability exists.
- Dependency extraction is not a full vulnerability audit and does not guarantee that packages are current or safe.
- Optional-tool findings depend on the installed tool version and its execution environment.

Review findings in context before making changes. Do not treat a clean scan as a security guarantee.

## Privacy and safe use

- The project being scanned is analyzed as source input; it is not intentionally executed by the scanner.
- Detected secret values are masked in findings to reduce accidental exposure.
- Scan reports may contain file paths, code locations, package names, and finding details. Review a report before sharing it.
- Only scan code and folders you own or are authorized to inspect.

## Current scope

Python Scanner focuses on static inspection of Python projects and common dependency declaration files. It is not a replacement for runtime testing, code review, a dedicated software-composition analysis service, or a complete security audit.

## Contributing

Issues and focused pull requests are welcome. When reporting a problem, include:

- Your operating system and Python version
- Kivy version and runtime (for example, Pydroid 3)
- The steps needed to reproduce the issue
- Relevant error output, with tokens, passwords, and other secrets removed

## License

No license is specified in this repository yet. Until a license is added, the default copyright rules apply; please do not assume the code is licensed for reuse or redistribution.
