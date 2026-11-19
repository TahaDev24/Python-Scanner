# Built-in rule catalog

This catalog documents the initial rule set. Rules are heuristic signals and should be reviewed in context.

| Rule ID | Category | Default severity | Description |
|---|---|---|---|
| SYN001 | Syntax | High | Python parser reported a syntax error |
| QLT001 | Quality | Medium | Bare except handler |
| QLT002 | Quality | High | Mutable list, dict, or set used as a function default |
| QLT004 | Standards | Info | Public function name is not lowercase snake_case |
| QLT005 | Quality | Info | TODO or FIXME marker |
| CPL001 | Complexity | Low–High | Estimated cyclomatic complexity is at least 7 |
| ARC001 | Architecture | Medium | Cycle detected in the local absolute-import graph |
| MAN001 | Maintainability | Low | Function spans more than 60 source lines |
| MAN002 | Maintainability | Low–Medium | Function reaches a nesting depth of at least 5 |
| PERF001 | Performance | Low | sum() receives a list comprehension |
| STD001 | Standards | Info | Trailing whitespace |
| STD002 | Standards | Low | Tab-based indentation |
| STD003 | Standards | Info | Line exceeds configured length |
| SEC001 | Security | High | Dynamic eval or exec call |
| SEC002 | Security | High | pickle.load call |
| SEC003 | Security | Medium | subprocess.run uses shell=True |
| SEC004 | Security | High | Line resembles a hard-coded credential |
| DEP001 | Dependencies | Info | Imported module not found in supported requirements files |

The dependency check is intentionally limited to requirements.txt and requirements-dev.txt in this first iteration. Architecture analysis currently checks cycles in absolute local imports; relative imports and namespace-package edge cases are not fully resolved.
