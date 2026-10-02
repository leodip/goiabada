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
