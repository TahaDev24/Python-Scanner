# Contributing

Thanks for your interest in Python Scanner.

## Before opening an issue

- Search existing issues to avoid duplicates.
- Include your operating system and Python version.
- Provide a minimal reproducible example.
- Remove passwords, tokens, private paths, and other sensitive data from logs.

## Development setup

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
ruff check .
~~~

## Pull requests

1. Keep changes focused and explain the problem they solve.
2. Add or update tests for behavior changes.
3. Update documentation when commands, rules, or configuration change.
4. Give every finding a stable rule ID and actionable explanation.
5. Never import or execute scanned project code.
6. Avoid network access in the core analysis path.

Analyzers should be deterministic, local, and independently testable. Return Finding objects and avoid printing directly.
