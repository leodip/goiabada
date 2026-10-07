# Docs style guide

Every page under `src/content/docs` follows this guide, and every docs change does too.

## Voice

- Friendly and direct. Address the reader as "you", keep sentences short, and cut filler.
- A light touch of personality: contractions, the odd friendly line, and a one-line "why" where it
  helps. Never cute.
- Use real OAuth/OIDC terms, but explain each one in plain English the first time it appears on a
  page, and link to its concept page.

## Vocabulary

- Each concept has one name, the one the admin console uses: client, user, group, resource,
  permission, scope, auth server. The [glossary](src/content/docs/concepts/glossary.mdx) defines
  them, and the docs never use a synonym. The glossary also decides pairs like "sign in" versus
  "log in".
- "Your app" is allowed, but only for the software the reader is building, which they register as
  a client.

## Structure

- The sidebar is organized by task (see below).
- Pages are short, with one topic each. When a page covers two topics, split it.
- Every page has the same shape:
  1. One sentence on what the page helps you do.
  2. The common path, using Starlight's `<Steps>` for any procedure.
  3. A "How it works" section with the precise rules.
  4. Next steps cards.

## Formatting

- Short paragraphs first. Use lists and tables only for real lists, steps and comparisons.
- Code examples use HTTP and curl only. That covers examples of calling Goiabada: deploy pages
  keep the YAML, shell commands and configuration files they need.
- Security warnings are emphatic: danger boxes and a bold "never". Keep them for real risks so
  they don't lose their force.

## Versions

- The docs describe only the latest version, in the present tense. Breaking changes and migration
  steps go in the release notes, not the docs.

## Example

The client "Consent required" setting, written in this style:

```mdx
## Consent required

Turn this on when users should approve what a client can access before it gets a token.

You usually don't need it for your own clients. Turn it on for third-party ones, so users can see who's asking for their data.

Clients you create in the admin console start with consent off. Clients that register themselves (DCR) start with it on, since nobody has reviewed them yet.
```

## Sidebar

The sidebar is in `astro.config.mjs`, and a page's URL is its group's path followed by its own
label, so the two read alike: Deploy > Monitoring is `/deploy/monitoring/`. The groups, in order:

```
Get started      Introduction, quickstart, setup wizard, first sign-in
Guides           One task end to end: add sign-in to an app, protect an API, ...
Concepts         What each thing is and how it behaves, and the glossary
Deploy           Running Goiabada in production
Reference        Endpoints, the API, environment variables, security
Troubleshooting  One short page per problem
Legacy flows     Implicit, ROPC
About            Contributing, contact, license
```

A group appears in the sidebar once it has a page.
