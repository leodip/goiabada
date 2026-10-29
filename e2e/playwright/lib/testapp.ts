// The test app (e2e/testapp) as e2e/infra/testapp.sh deploys it: one container per test app host, and
// the clients and API it signs in with, set up by provision/testapp.provision.ts. Tests drive its
// pages in a browser as its user would, and read what it shows.
import { expect, type Browser, type Page } from "@playwright/test";
import { submitPassword } from "./browser-sign-in";
import { env } from "./environment";

export const testapp = {
  // The first host serves the web app, the SPA, the service and the API; the second the second web
  // app, so single sign-on is tried across two sites.
  web: { clientId: "testapp-web", url: `${env.webtest1Url}/web` },
  web2: { clientId: "testapp-web2", url: `${env.webtest2Url}/web2` },
  spa: { clientId: "testapp-spa", url: `${env.webtest1Url}/spa`, origin: env.webtest1Url },
  service: { clientId: "testapp-service", url: `${env.webtest1Url}/service` },
  api: {
    resource: "product-api",
    permissions: ["read", "write"],
    scope: "product-api:read",
    url: `${env.webtest1Url}/api/products`,
    // The API's own client, which introspects every token it is sent.
    clientId: "testapp-api",
  },
};

export type WebApp = typeof testapp.web;

// A browser of the user's own, with nothing in it: inside a test, browser.newContext() starts from the
// test's options, which carry the administrator's signed-in state. The caller closes it.
export async function userBrowser(browser: Browser) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  return { context, page: await context.newPage() };
}

// Signs in to a web app from its page with these authorization parameters (the app's own sign-in form
// sends scope, prompt, acr_values, max_age and id_token_hint), entering the password when the auth
// server asks for it, and returns once the browser is back on the app's page. Whether the password was
// asked is returned, for the single sign-on tests.
export async function signInToWebApp(
  page: Page,
  app: WebApp,
  user: { email: string; password: string },
  params: Record<string, string> = {},
): Promise<{ askedForPassword: boolean }> {
  await page.goto(`${app.url}/login?${new URLSearchParams(params)}`);
  await page.waitForURL((url) => url.href === app.url || url.pathname === "/auth/pwd" || url.pathname === "/auth/consent");
  const askedForPassword = new URL(page.url()).pathname === "/auth/pwd";
  if (askedForPassword) await submitPassword(page, user.email, user.password);
  await page.waitForURL((url) => url.href === app.url || url.pathname === "/auth/consent" || url.pathname === "/auth/otp");
  return { askedForPassword };
}

// The outcome box the app shows after each action: its title, and the JSON under it.
export async function expectResult(page: Page, title: string | RegExp) {
  await expect(page.locator("section > h2").first()).toHaveText(title);
}

export async function resultBody(page: Page): Promise<Record<string, unknown>> {
  return JSON.parse(await page.locator("section > pre").first().innerText());
}

// The claims the web app shows under a heading ("ID token claims", "Access token claims").
export async function shownClaims(page: Page, heading: "ID token claims" | "Access token claims"): Promise<Record<string, unknown>> {
  return JSON.parse(await page.locator(`h3:text-is("${heading}") + pre`).innerText());
}
