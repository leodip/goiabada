# Fixing Goiabada

Follow `.placido/notes/implement.md`: the same commands, the same regeneration
checklist, and the same rule on standards.

- **A red CI run:** CI runs the data and integration tiers on all four engines, plus
  the lint tier. Reproduce on the engine that failed (`data mssql`,
  `integration postgres`, ...), not only on SQLite, and run it again after the fix.
- **A failing e2e gate:** the gate's log has the Playwright output, and
  `e2e/playwright/test-results/` the traces and screenshots of each failure. Do not
  run `e2e` yourself: placido runs it on your result, and each run rebuilds the
  environment on the VPS, about ten minutes. The gate left that environment running
  this branch, so to check a change to the specs alone, run `e2e/test.sh` against
  it, narrowed to the failing area (`tests/oauth`, a file, or `--grep`). A change
  under `src/` needs the rebuild, which placido's run on your result does.
