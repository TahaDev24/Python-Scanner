# Architecture

Python Scanner has one analysis engine and multiple presentation layers.

## Components

- **Discovery** walks a target directory, applies exclusions, and enforces file-count and file-size limits.
- **Analyzers** inspect source text or its AST and return structured findings.
- **Scoring** converts findings into transparent heuristic scores.
- **Reporting** renders text and JSON output.
- **CLI** parses arguments and invokes the engine.
- **Desktop** is an optional Kivy client that invokes the same engine.

## Design constraints

1. Core modules must not depend on Kivy.
2. Scanned project modules are never imported or executed.
3. Findings should be deterministic for the same source and configuration.
4. Analyzer errors are recorded rather than silently discarded.
5. JSON reports carry a schema version for future compatibility.

## Adding an analyzer

Implement an object with a name and an analyze(path, source, relative_path) method. Return a list of Finding instances. Register it in Scanner and add tests for normal and malformed input.
