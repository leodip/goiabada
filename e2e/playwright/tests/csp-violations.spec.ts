// The suite's Content-Security-Policy watcher (lib/csp-violations.ts), against pages of its own: a
// server on this machine that sends the servers' policy, started twice so it answers on two origins,
// one watched and one not, as the auth server's is and the test app's is not. Needs no environment.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { CspViolationWatcher, expect, test as watched } from "../lib/csp-violations";

const policy = "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

// Each element on a line of its own, so the line a violation names is known.
const pages: Record<string, { type: string; body: string }> = {
  "/clean": {
    type: "text/html",
    body: [
      "<!DOCTYPE html>",
      "<title>Clean</title>",
      '<script type="application/json" id="data">{"a": 1}</script>',
      '<script src="/clean.js"></script>',
      "<h1>Clean</h1>",
    ].join("\n"),
  },
  "/clean.js": { type: "text/javascript", body: "document.body;" },
  "/dirty": {
    type: "text/html",
    body: [
      "<!DOCTYPE html>",
      "<title>Dirty</title>",
      "<script>document.title = 'Ran';</script>",
      '<button onclick="1">Button</button>',
      '<script src="/eval.js"></script>',
      "<h1>Dirty</h1>",
    ].join("\n"),
  },
  "/eval.js": { type: "text/javascript", body: "try { eval('1'); } catch {}" },
};

async function serve(): Promise<{ port: number; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const page = pages[req.url ?? ""];
    res.setHeader("Content-Security-Policy", policy);
    if (!page) {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader("Content-Type", page.type);
    res.end(page.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const test = watched.extend<object, { watchedOrigin: string; otherPort: number }>({
  watchedOrigin: [
    async ({}, use) => {
      const server = await serve();
      await use(`http://127.0.0.1:${server.port}`);
      await server.close();
    },
    { scope: "worker" },
  ],
  // Answers as http://127.0.0.1:<port> and as http://localhost:<port>, two origins neither watched.
  otherPort: [
    async ({}, use) => {
      const server = await serve();
      await use(server.port);
      await server.close();
    },
    { scope: "worker" },
  ],
  cspWatchedOrigins: [async ({ watchedOrigin }, use) => use([watchedOrigin]), { scope: "worker" }],
});

test("a page of a watched origin whose scripts are files, and whose data is a JSON block, passes", async ({ page, watchedOrigin }) => {
  await page.goto(`${watchedOrigin}/clean`);
  await expect(page.getByRole("heading", { name: "Clean" })).toBeVisible();
});

test("a page of a watched origin that runs inline code fails the test", async ({ page, watchedOrigin }) => {
  test.fail();
  await page.goto(`${watchedOrigin}/dirty`);
  await expect(page.getByRole("heading", { name: "Dirty" })).toBeVisible();
});

test("a page of a watched origin in a context the test made fails the test", async ({ browser, watchedOrigin }) => {
  test.fail();
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${watchedOrigin}/dirty`);
  await expect(page.getByRole("heading", { name: "Dirty" })).toBeVisible();
  await context.close();
});

test("a page of an origin not watched may run inline code", async ({ page, browser, otherPort }) => {
  await page.goto(`http://127.0.0.1:${otherPort}/dirty`);
  await expect(page.getByRole("heading", { name: "Dirty" })).toBeVisible();
  const context = await browser.newContext();
  const other = await context.newPage();
  await other.goto(`http://localhost:${otherPort}/dirty`);
  await expect(other.getByRole("heading", { name: "Dirty" })).toBeVisible();
  await context.close();
});

test("the watcher names the page, the directive and what was blocked, on its origins only", async ({ browser, otherPort }) => {
  const origin = `http://127.0.0.1:${otherPort}`;
  const watcher = new CspViolationWatcher([origin]);
  const context = await browser.newContext();
  await watcher.watch(context);
  const page = await context.newPage();

  await page.goto(`${origin}/clean`);
  await expect(page.getByRole("heading", { name: "Clean" })).toBeVisible();
  // Every page of the context is watched, the second as well as the first, and after a navigation.
  const second = await context.newPage();
  await second.goto(`http://localhost:${otherPort}/dirty`);
  await expect(second.getByRole("heading", { name: "Dirty" })).toBeVisible();
  await page.goto(`${origin}/dirty`);
  await expect(page.getByRole("heading", { name: "Dirty" })).toBeVisible();

  const expected = [
    `${origin}/dirty: script-src blocked eval, at ${origin}/eval.js:1`,
    // Chromium gives no place for an attribute's code.
    `${origin}/dirty: script-src-attr blocked inline`,
    `${origin}/dirty: script-src-elem blocked inline, at ${origin}/dirty:3`,
  ];
  await expect.poll(() => [...watcher.violations()].sort()).toEqual(expected);
  // The failure lists them.
  let failure = "";
  try {
    watcher.expectNone();
  } catch (error) {
    failure = String(error);
  }
  for (const line of expected) expect(failure).toContain(line);
  await context.close();
});
