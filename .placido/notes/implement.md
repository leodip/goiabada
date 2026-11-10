# Implementing a slice of Goiabada

- **Run Go checks through the commands in your prompt.** They run inside this
  issue's own Docker stack, in the devcontainer, with the environment it needs.
  Never run `go test` on the host: without that environment the integration tier
  times out with zero tests.
- **Iterate fast, then widen.** Narrow any tier with `--run '<regex>'`, and the unit
  tiers by module with `--type internal|core|adminconsole`; a pattern that matches no
  test fails the run. Run the data and integration tiers on SQLite while you work
  (`data-sqlite`, `integration-sqlite`). When the slice touches SQL that differs between engines, run
  the changed tier on MySQL, PostgreSQL, and SQL Server too (`data mysql`, and so on)
  before you write your result: CI runs all four.
- **Before you write your result, regenerate what your change affects,** and leave
  the regenerated files in the worktree. Each one turns CI red when forgotten:
  - a migration added or changed: `schema` (the four `schema.golden` files);
  - a core symbol added or moved: `ownership`;
  - an interface changed: `mocks` (never mockery by hand);
  - Tailwind classes added: the CSS, which `lint` checks.
- **Mutations:** give `placido mutate` the narrowest test command that covers the
  code, such as `.placido/stack.sh run --type internal --no-build --run 'TestName'`
  or `.placido/stack.sh run --type integration --db sqlite --run 'TestName'`, never
  the whole suite.
- **Standards:** before building behavior that a published standard defines (see
  "Standards" in AGENTS.md), read the section the agreement cites, or find it, and
  follow its MUST and SHOULD requirements. Tests assert what the standard requires,
  not only what the code happens to do.
- **Documentation:** update affected pages under `site/src/content/docs/` in the
  same slice as reader-facing changes. For Admin or Account API operation facts,
  edit `src/authserver/web/openapi.yaml`, which generates their reference pages.
  Read `site/STYLE.md` and its linked glossary before writing. The docs describe
  the latest version in the present tense; put breaking changes and migration
  steps in release notes. For docs or OpenAPI changes, build the site from `site/`
  on the host as `site/README.md` describes; the devcontainer has no Node.js.
- **Look at the pages you change.** When the slice changes how a page of the auth
  server or the admin console looks, regenerate the CSS, then run
  `.placido/stack.sh serve`: it starts both from this worktree, with an empty
  database, and prints their addresses and the admin's sign-in. Open the pages with
  the Playwright MCP tools, starting with the ones the agreement names, in light and
  dark (`browser_emulate_media`) and at a phone width (`browser_resize` to 375
  pixels wide), and look at each screenshot: text hard to read, overlaps, overflow, a
  control out of place. After switching the color scheme or the theme, wait a second
  before the screenshot: the page fades between colors, and a screenshot taken
  mid-fade shows faded text that is not there. Measure a doubtful contrast from the
  computed colors (`browser_evaluate`), not from the picture. `serve` runs what the
  worktree held when it started, so run it again after a change; `serve stop` ends it.
- **Browser tests:** the Playwright suite under `e2e/` runs against one shared
  environment on a VPS, and placido runs it whole as the last gate, after the
  review. Do not run `e2e` or the scripts under `e2e/` yourself. Look at
  `e2e/playwright/tests/` and add or update specs as the change needs, starting with
  the ones the agreement names. Follow `e2e/README.md`, and check the types on the
  host with `cd e2e/playwright && npm ci && npm run typecheck`.
