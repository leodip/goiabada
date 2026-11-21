# Specifying a Goiabada issue

- **Settle early what costs most when found late:** which database engines the change
  affects, and whether it needs a migration; whether it changes an API route, a
  response, or the admin console; and its security effects (who can do what, and what
  goes into tokens).
- **Standards:** for each decision that touches behavior a published standard defines
  (see "Standards" in AGENTS.md), read the section and cite it in the agreement, such
  as "RFC 6749 §4.1.2.1". A decision that departs from a MUST is a question for the
  user, never an assumption.
- **Seams that fit this codebase:** HTTP handler tests for endpoints, the data tier
  for storage, the integration tier for whole OAuth2 and OpenID Connect flows.
- **Gates:** give a slice that changes storage the `data-sqlite` gate, and one that
  changes a flow end to end the `integration-sqlite` gate.
- **Regeneration, per slice:** name in each slice's deliverables the committed files
  it regenerates before its gates. The unit and lint gates check the ownership table,
  the mocks and the CSS in every slice, so a slice that leaves its regeneration to a
  later one fails its own gates. `ownership`: when the slice adds, moves or removes a
  core exported symbol, and also when it only adds or removes a reference to one, a
  test's included. A row holds the strongest justification its references give, with
  no declaration changed: a first production reference from another core package
  makes it `kernel`, and losing references can move it to a weaker one. A symbol that
  only tests name has no computed justification, so `ownershipdump` refuses to write
  until the slice gives it a `test-support` row with a note by hand. A `test-support`
  row fails the unit gate once no test and no code of its own package names the
  symbol, and regenerating keeps it (`src/core/OWNERSHIP.md`, "The justifications").
  `mocks`: when the slice renames or changes a mocked interface; a rename also changes
  the key that names it in its module's `.mockery.yaml`, in the same slice. `schema`:
  in the slice that adds or changes a migration. The CSS: in the slice that adds
  Tailwind classes.
- **Documentation:** decide whether a change to reader-facing behavior, configuration,
  an API, deployment, or the admin console needs an update under
  `site/src/content/docs/`. Name the affected pages in the agreement and include
  the updates in a slice. API operation descriptions live in
  `src/authserver/web/openapi.yaml`. Use `site/STYLE.md` and its linked glossary
  for wording; breaking changes and migration steps belong in release notes.
- **Pages to look at:** when the change alters how a page of the auth server or the
  admin console looks, name in the agreement the pages and states to look at, such as
  the brand editor in light and dark and at a phone width. The implementer and the
  reviewer open them in a browser, through `.placido/stack.sh serve`.
- **Browser tests:** `e2e/` holds a Playwright suite that runs against a real
  deployment on a VPS (see `e2e/README.md`). Placido runs it whole as the last gate,
  after the review; no agent runs it. In every interview, look at
  `e2e/playwright/tests/`, decide which specs to add or update for this change, and
  name them in the agreement, in the slices that change that behavior.
