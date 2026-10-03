# Implementing a slice of Goiabada

- **Run everything through the commands in your prompt.** They run inside this
  issue's own Docker stack, in the devcontainer, with the environment it needs.
  Never run `go test` on the host: without that environment the integration tier
  times out with zero tests.
- **Iterate fast, then widen.** `--run '<regex>'` narrows the data and integration
  tiers only; the unit tiers ignore it. For one unit test, use `exec` with `go test
  -count=1 -run '<regex>'` on its package. Run the data and integration tiers on
  SQLite while you work (`data-sqlite`, `integration-sqlite`). When the slice touches SQL that differs between engines, run
  the changed tier on MySQL, PostgreSQL, and SQL Server too (`data mysql`, and so on)
  before you write your result: CI runs all four.
- **Before you write your result, regenerate what your change affects,** and leave
  the regenerated files in the worktree. Each one turns CI red when forgotten:
  - a migration added or changed: `schema` (the four `schema.golden` files);
  - a core symbol added or moved: `ownership`;
  - an interface changed: `mocks` (never mockery by hand);
  - Tailwind classes added: the CSS, which `lint` checks.
- **Mutations:** give `placido mutate` the narrowest test command that covers the
  code, such as `.placido/stack.sh exec 'go test -count=1 -run TestName
  ./internal/oauth/...'`, or `.placido/stack.sh run --type integration --db sqlite
  --run 'TestName'`, never the whole suite.
- **Standards:** before building behavior that a published standard defines (see
  "Standards" in AGENTS.md), read the section the agreement cites, or find it, and
  follow its MUST and SHOULD requirements. Tests assert what the standard requires,
  not only what the code happens to do.
