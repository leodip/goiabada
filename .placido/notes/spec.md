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
  deployment on a VPS (see `e2e/README.md`): the admin console's pages
  (`admin-console/`), the test app's flows (`testapp/`), and the protocol, with
  conformance suites for RFC 6749 and RFC 9700 (`rfc6749/`, `rfc9700/`, `oauth/`).
  Placido runs it whole as the last gate, after the review, against an environment
  rebuilt from the branch; no agent runs it. In every interview, before sealing,
  settle the e2e work and name it in the agreement, in the slices that change the
  behavior:
  - **Gaps this issue closes:** search `e2e/playwright/tests/` for `#<this issue>`.
    A known gap is a test marked `test.fail()`, with a comment naming its issue and
    item. The slice that closes the gap removes the marker; left in, the test
    passes and the suite fails.
  - **Specs the change breaks:** search the suite for what the change alters
    (routes, status codes, response parameters, discovery keys, messages, page
    text, settings), and name each spec to update.
  - **Coverage to add:** where the change adds or fixes behavior that a real
    deployment shows better than the integration tier (a page in the browser, a
    redirect across sites, a sign-in through the test app, mail, a protocol
    response over HTTPS, a requirement of an RFC the suites cover), propose the
    cases to add, and name the ones agreed.
