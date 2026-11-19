# Scoring model

Scores range from 0 to 100. The initial implementation subtracts a fixed penalty for each finding:

| Severity | Penalty |
|---|---:|
| Critical | 25 |
| High | 12 |
| Medium | 5 |
| Low | 2 |
| Info | 0 |

The score is clamped to the 0–100 range. Category scores use the same penalties, applied only to findings in that category. Categories without findings start at 100.

## Interpretation

- This is a prioritization heuristic, not a statistical quality metric.
- Multiple findings can refer to related root causes.
- The score is not normalized by project size in this initial release.
- A high score does not prove that a project is safe or correct.
- Scoring weights may change as the rule set matures.
