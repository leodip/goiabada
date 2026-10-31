// A Content-Security-Policy violation on a page of the auth server or the admin console fails the
// test. Both servers send script-src 'self' (with object-src and base-uri 'none'), so a page that
// carried an inline script, an on… attribute, a javascript: URL or an eval would have that code
// refused by the browser, and the page would break, perhaps in no way a test asserts.
//
// The watcher listens for the securitypolicyviolation event in every page of a browser context, not
// for console messages: a caught eval fires the event and logs nothing. Pages of other origins, the
// test app's and Mailpit's, are not under the servers' policy and are not watched.
//
// lib/fixtures.ts names the two origins. The test object here watches the test's own context and
// every context made with browser.newContext() during the test, by a test or by a helper.
import { randomBytes } from "node:crypto";
import { test as base, expect, type Browser, type BrowserContext } from "@playwright/test";

// What the page's event says, as the page hands it over.
interface Report {
  documentURI: string;
  effectiveDirective: string;
  blockedURI: string;
  sourceFile: string;
  lineNumber: number;
}

export class CspViolationWatcher {
  private readonly origins: ReadonlySet<string>;
  // A name of its own, so two watchers can watch one context.
  private readonly binding = `__cspViolation_${randomBytes(6).toString("hex")}`;
  private readonly watched = new Set<BrowserContext>();
  private readonly found: string[] = [];

  // origins: such as https://e2e-auth.goiabada.dev, as URL.origin spells them.
  constructor(origins: readonly string[]) {
    this.origins = new Set(origins);
  }

  // Watches every page the context has from now on, in every frame, across navigations.
  async watch(context: BrowserContext): Promise<void> {
    if (this.watched.has(context)) return;
    this.watched.add(context);
    context.on("close", () => this.watched.delete(context));
    await context.exposeBinding(this.binding, (_source, report: Report) => this.record(report));
    await context.addInitScript((binding: string) => {
      document.addEventListener("securitypolicyviolation", (event) => {
        const report = (window as unknown as Record<string, (report: unknown) => void>)[binding];
        void report({
          documentURI: event.documentURI,
          effectiveDirective: event.effectiveDirective,
          blockedURI: event.blockedURI,
          sourceFile: event.sourceFile,
          lineNumber: event.lineNumber,
        });
      });
    }, this.binding);
  }

  private record(report: Report): void {
    let origin: string;
    try {
      origin = new URL(report.documentURI).origin;
    } catch {
      return;
    }
    if (!this.origins.has(origin)) return;
    const where = report.sourceFile ? `, at ${report.sourceFile}:${report.lineNumber}` : "";
    this.found.push(`${report.documentURI}: ${report.effectiveDirective} blocked ${report.blockedURI}${where}`);
  }

  // One line per violation on a watched origin: the page, the directive and what it blocked (inline,
  // eval, or the address of what was refused), then where the code was.
  violations(): readonly string[] {
    return this.found;
  }

  // Lets each open page of the contexts still watched run what it has queued, so a violation its
  // page has fired but not yet handed over is counted.
  async settle(): Promise<void> {
    const pages = [...this.watched].flatMap((context) => context.pages());
    await Promise.all(
      pages.map((page) => page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 0))).catch(() => undefined)),
    );
  }

  expectNone(): void {
    expect(this.found, "pages of the auth server or the admin console reported Content-Security-Policy violations").toEqual([]);
  }
}

// Watches each context browser.newContext() makes until the returned function is called. Playwright's
// own context fixture makes the test's context through it as well.
function watchNewContexts(browser: Browser, watcher: CspViolationWatcher): () => void {
  const newContext = browser.newContext;
  browser.newContext = async (options) => {
    const context = await newContext.call(browser, options);
    await watcher.watch(context);
    return context;
  };
  return () => {
    browser.newContext = newContext;
  };
}

export const test = base.extend<{ cspWatcher: CspViolationWatcher }, { cspWatchedOrigins: string[] }>({
  // The origins whose pages must report no violation: none unless a test object says.
  cspWatchedOrigins: [[], { option: true, scope: "worker" }],
  cspWatcher: [
    async ({ browser, cspWatchedOrigins }, use) => {
      const watcher = new CspViolationWatcher(cspWatchedOrigins);
      const stop = watchNewContexts(browser, watcher);
      try {
        await use(watcher);
      } finally {
        stop();
      }
      // The contexts a test made and left open.
      await watcher.settle();
      watcher.expectNone();
    },
    { auto: true },
  ],
  // The test's own context: Playwright makes it through browser.newContext(), which the watcher
  // already watches; watched here as well, whatever order the two fixtures are set up in.
  context: async ({ context, cspWatcher }, use) => {
    await cspWatcher.watch(context);
    await use(context);
    await cspWatcher.settle();
  },
});

export { expect };
