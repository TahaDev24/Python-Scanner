# Architecture

Python Scanner has one analysis engine and multiple presentation layers.

## Components

- **Discovery** walks a target directory, applies exclusions, and enforces file-count and file-size limits.
- **Analyzers** inspect source text or its AST and return structured findings.
- **Scoring** converts findings into transparent heuristic scores.
- **Reporting** renders text and JSON output.
- **CLI** parses arguments and invokes the engine.
- **Desktop** is an optional Kivy client that invokes the same engine.

## Analysis modules

| Analyzer | Responsibility |
|---|---|
| Syntax | Parser diagnostics |
| Quality | Common correctness and maintainability signals |
| Complexity | Approximate cyclomatic complexity |
| Architecture | Local import-cycle detection |
| Maintainability | Function length and nesting depth |
| Performance | Selected allocation-related code patterns |
| Standards | Whitespace, indentation, and line length |
| Security | Common risky API patterns and credential-like strings |
| Dependencies | Compare imports with supported requirements manifests |

## Design constraints

1. Core modules must not depend on Kivy.
2. Scanned project modules are never imported or executed.
3. Findings should be deterministic for the same source and configuration.
4. Analyzer errors are recorded rather than silently discarded.
5. JSON reports carry a schema version for future compatibility.

## Adding an analyzer

Implement an object with a name and an analyze(path, source, relative_path) method. Return a list of Finding instances. Register it in Scanner and add tests for normal and malformed input.
