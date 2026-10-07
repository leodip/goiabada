# Goiabada docs site

The source of [goiabada.dev](https://goiabada.dev), built with [Astro](https://astro.build) and
[Starlight](https://starlight.astro.build). Pages are Markdown and MDX files in
`src/content/docs/`; a file's path there is its URL. The sidebar is in `astro.config.mjs`.

## Build and preview

Build the site on your own machine, with Node.js 22 or later. The devcontainer has no Node.js.

```sh
cd site
npm ci
npm run dev       # live preview at http://localhost:4321
npm run build     # the published site, in dist/, with every check below
npm run preview   # serves dist/ as built
npm test          # the tests of the site's own checks
```

## What fails the build

`npm run build` fails, and so does the docs image's build, when:

- **An internal link is broken:** a link to a page that does not exist, or to a fragment no
  heading on its page produces. `starlight-links-validator` checks this. Links to
  `http://localhost` are examples of a local install and are not checked.
- **A link in shipped code names nothing:** every `https://goiabada.dev` link under the
  repository's `src/` (server messages, the setup wizard's generated files, templates) must name
  a page the build published, and a fragment on it must name a heading on that page. When you move
  a page or reword a heading, update those links in the same change. This check is ours, in
  `checks/shipped-links.mjs`, run from `checks/build-checks.mjs` once the pages are written.
- **The llms files disagree with the pages:** the build writes `/llms.txt`, the
  [llmstxt.org](https://llmstxt.org) index of every page with its title, URL and description,
  and `/llms-full.txt`, every page's content as Markdown headed by its title and URL, from the
  pages it has just written, the 404 page left out. It then reads them back and fails when a page
  is missing from either file, an entry names no page, or an entry lacks text its page renders.
  This step is ours, in `checks/llms.mjs`. The project title and summary that head `llms.txt`
  are in `astro.config.mjs`, and its sections follow the sidebar.

`npm test` runs the checks' tests on small fixtures with Node's built-in test runner.

## The docs image

The image serves the built site with nginx. It is built from the repository root, because the
build reads `src/`:

```sh
docker build -f site/Dockerfile -t goiabada-docs .
site/checks/docs-image.sh goiabada-docs
```

`checks/docs-image.sh` starts the image and asserts nginx's answers: 200 for a page, 404 with the
site's 404 page for any other path, a 301 to the relative path with the slash for a page asked
without it, and `charset=utf-8` on text. The 404 page's text is `src/content/docs/404.md`.

CI's Check workflow runs the checks' tests, the build and the image's answers on every pull
request. The Docs workflow builds and pushes the image when `site/` or
`src/authserver/web/openapi.yaml` changes on `main`, and on every release.
