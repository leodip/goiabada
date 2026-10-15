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
- **Documentation:** decide whether a change to reader-facing behavior, configuration,
  an API, deployment, or the admin console needs an update under
  `site/src/content/docs/`. Name the affected pages in the agreement and include
  the updates in a slice. API operation descriptions live in
  `src/authserver/web/openapi.yaml`. Use `site/STYLE.md` and its linked glossary
  for wording; breaking changes and migration steps belong in release notes.
- **Browser tests:** `e2e/` holds a Playwright suite that runs against a real
  deployment on a VPS (see `e2e/README.md`). Placido runs it whole as the last gate,
  after the review; no agent runs it. In every interview, look at
  `e2e/playwright/tests/`, decide which specs to add or update for this change, and
  name them in the agreement, in the slices that change that behavior.
