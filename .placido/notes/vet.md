# Checking a Goiabada agreement

- **Standards:** where a decision cites an RFC or OpenID Connect section, read that
  section and check it says what the decision says. A decision that departs from a
  MUST, and that the user didn't decide explicitly, is a finding.
- **Conventions with their own docs:** API errors follow
  `site/src/content/docs/reference/api/errors.mdx`, with message keys in
  `src/core/i18n/error_codes.go`. API operations are described in
  `src/authserver/web/openapi.yaml`. Check that every error code, route and field
  the agreement names follows them.
- **Four database engines:** a claim about storage must hold on SQLite, MySQL,
  PostgreSQL and SQL Server. Check each engine where the agreement describes the
  schema or a query.
- **What the agreement names must exist:** the docs pages under
  `site/src/content/docs/`, the specs under `e2e/playwright/tests/`, and the
  settings or features a decision copies.
