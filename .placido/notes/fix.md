# Fixing Goiabada

Follow `.placido/notes/implement.md`: the same commands, the same regeneration
checklist, and the same rule on standards.

- **A red CI run:** CI runs the data and integration tiers on all four engines, plus
  the lint tier. Reproduce on the engine that failed (`data mssql`,
  `integration postgres`, ...), not only on SQLite, and run it again after the fix.
- **A failing e2e gate:** the gate's log has the Playwright output, and
  `e2e/playwright/test-results/` the traces and screenshots of each failure. Unlike
  the other steps, you may run `e2e` here, narrowed to the failing area
  (`tests/oauth`, a file, or `--grep`). It rebuilds the shared environment from
  your changes and takes minutes, so run it to confirm a fix, not to explore.
