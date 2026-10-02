# Fixing Goiabada

Follow `.placido/notes/implement.md`: the same commands, the same regeneration
checklist, and the same rule on standards.

- **A red CI run:** CI runs the data and integration tiers on all four engines, plus
  the lint tier. Reproduce on the engine that failed (`data mssql`,
  `integration postgres`, ...), not only on SQLite, and run it again after the fix.
