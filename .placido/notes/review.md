# Reviewing Goiabada

- **What this is:** Goiabada is its owner's open-source OAuth 2.0 and OpenID
  Connect authorization server, and you review a change to it at the owner's
  request, before they merge it. It is defensive work: its issues name the
  weaknesses being closed (privilege escalation, token misuse, and so on) so they
  can be fixed and tested, and the stack you run against is this issue's own,
  isolated, with throwaway data.
- **Goiabada is a security product:** a flaw here becomes a flaw in every
  application that relies on it. Treat security findings with the highest care, and
  show each with a test through the commands in your prompt: a request the server
  must refuse, a check a path skips.
- **Standards:** on the Spec axis, also check the change against the published
  standards it touches (see "Standards" in AGENTS.md), reading the sections rather
  than recalling them. Breaking a MUST is a blocking finding; ignoring a SHOULD
  without a recorded reason is a significant one. Quote the section in the finding.
- **Data changes must hold on all four engines.** Look for SQL that differs between
  engines without a case for each, and run the changed data tier on at least one
  real engine besides SQLite (`data postgres`, for example).
- **Generated files must be current:** the schema goldens, the core ownership table,
  the mocks, and the CSS. A stale one is a blocking finding, since it turns CI red.
- **Documentation:** check that reader-facing changes have matching updates under
  `site/src/content/docs/`, and that Admin or Account API operation facts agree
  with `src/authserver/web/openapi.yaml`. Review changed docs against
  `site/STYLE.md` and its linked glossary. The docs describe the latest version;
  breaking changes and migration steps belong in release notes. For docs or
  OpenAPI changes, build the site on the host as `site/README.md` describes.
- **Look at the pages the change touches.** Reading the CSS does not show how a page
  looks. When the change alters a page of the auth server or the admin console, run
  `.placido/stack.sh serve`, which starts both from this worktree and prints their
  addresses and the admin's sign-in, and open the pages with the Playwright MCP
  tools: the ones the agreement names first, in light and dark
  (`browser_emulate_media`), at a phone width (`browser_resize` to 375 pixels wide),
  and in each theme or state the change adds. Text hard to read, overlaps, overflow
  or a control out of place is a finding like any other; say which page, scheme and
  width show it. After switching the color scheme or the theme, wait a second before
  the screenshot: a screenshot taken mid-fade shows faded text that is not there.
  Measure contrast from the computed colors (`browser_evaluate`), not from the
  picture. Run `serve` again after each fix round, since it runs the code it started
  with.
- **Browser tests:** the Playwright suite under `e2e/` runs against one shared
  environment on a VPS, and placido runs it whole as the last gate, after the
  review. Do not run `e2e` or the scripts under `e2e/` yourself, and do not count a
  spec that has not run yet as missing evidence. Check that the change adds or
  updates the specs under `e2e/playwright/tests/` it needs, the ones the agreement
  names among them, that they follow `e2e/README.md`, and that their types check on
  the host (`cd e2e/playwright && npm ci && npm run typecheck`).
