# Reviewing a contributor's pull request to Goiabada

- **What this is:** an outside contributor's change to Goiabada, its owner's
  open-source OAuth 2.0 and OpenID Connect authorization server, reviewed for the owner
  before they decide whether to merge it. A flaw merged here becomes a flaw in every
  application that relies on Goiabada: treat security findings with the highest care,
  each shown with a test through the commands in your prompt.
- **What is normal here, for the scan:** the tests talk to MySQL, PostgreSQL, SQL
  Server, and Mailpit in this pull request's own Docker stack, by service name; the
  integration tier starts the server on local ports. Anything reaching beyond those,
  or touching `src/.devcontainer/`, `.placido/`, `.github/`, the Dockerfiles, or the
  scripts under `src/`, is worth a line.
- **Standards:** CLAUDE.md's "Standards" section lists the RFCs and OpenID specs
  Goiabada implements. Read the section the change touches in the official text
  (rfc-editor.org, openid.net) and quote it.
- **The issue is the spec.** Most contributions close an issue written by the owner,
  with a "Done when" or a list of options; check the change against it literally, and
  when the contributor chose between the issue's options, say which and whether the
  choice holds, as a decision for the owner when it is a judgment call.
- **The gates placido ran** cover vet, the unit tiers, lint (golangci-lint, unparam,
  and the committed Tailwind CSS, mocks, and core ownership table), the setup wizard,
  and the data and integration tiers on SQLite. A change to SQL that differs between
  engines needs the data tier on MySQL, PostgreSQL, and SQL Server too (`data mysql`,
  and so on): run it. CI runs every engine, but GitHub holds a first-time
  contributor's CI until the owner approves it, so CI may not have run at all.
- **Generated files must be current:** the four `schema.golden` files after a
  migration, `src/core/OWNERSHIP.md` after a core symbol moves, the mocks after an
  interface changes, the CSS after a template class changes. A stale one turns CI red:
  blocking.
- **Weakened guards are findings:** the repository holds itself to many tests that walk
  the tree (CLAUDE.md, "Testing"). A new exemption, allowlist entry, row in
  `ARCHITECTURE.md`'s exception tables, `//nolint`, or a loosened assertion needs a
  reason the owner would accept.
- **Beside the code:** reader-facing changes need their pages under
  `site/src/content/docs/`; Admin and Account API facts live in
  `src/authserver/web/openapi.yaml`; user-facing text needs both catalogs,
  `src/core/i18n/catalogs/active.en.toml` and `active.pt-BR.toml`.
- **Do not run** `e2e` or the scripts under `e2e/`: they rebuild a shared environment.
- **The comment and the squash message:** the history's squash subjects are a sentence
  in the imperative ending with the pull request's number, such as
  `Refuse the password grant for a mandatory level 2 client (#602)`; the body says
  what changed and why, in prose.
