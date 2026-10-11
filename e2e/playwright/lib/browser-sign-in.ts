// A user signing in to a client application through the browser: the authorization code flow, the
// way a real application starts it. The tests use it where only a browser sign-in leaves a trace, a
// session or a consent, which the password grant does not.
import { createHash, randomBytes } from "node:crypto";
import type { Browser, BrowserContext, Page } from "@playwright/test";
import { env } from "./environment";
import { userAgentFor } from "./devices";

// The redirect URI the tests register on their clients. Nothing answers there (nginx says 404), which
// is all a test needs: the code arrives in the address.
export const testRedirectUri = `${env.webtest1Url}/callback`;

export interface BrowserSignIn {
  // The browser the user signed in with, holding the auth server's session cookie.
  context: BrowserContext;
  code: string;
  codeVerifier: string;
}

// Starts a sign-in through the client in a browser of its own, and leaves the page at the auth
// server's password form. The caller closes the context.
export async function openSignIn(browser: Browser, options: { clientId: string; scope: string; device: string }) {
  // An explicit empty state: inside a test, browser.newContext() starts from the test's options, which
  // here carry the administrator's signed-in state, and the sign-in would be the administrator's.
  const context = await browser.newContext({
    userAgent: userAgentFor(options.device),
    storageState: { cookies: [], origins: [] },
  });
  const page = await context.newPage();
  const codeVerifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({
    client_id: options.clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: options.scope,
    state: randomBytes(8).toString("hex"),
    code_challenge: createHash("sha256").update(codeVerifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  await page.goto(`${env.authUrl}/auth/authorize?${query}`);
  return { context, page, codeVerifier };
}

export async function submitPassword(page: Page, email: string, password: string) {
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

// Signs the user in through the client in a browser of their own, approving the consent screen if one
// shows, and returns once the browser is back at the redirect URI with a code. The caller closes the
// context.
export async function signInThroughClient(
  browser: Browser,
  options: { clientId: string; email: string; password: string; scope: string; device: string },
): Promise<BrowserSignIn> {
  const { context, page, codeVerifier } = await openSignIn(browser, options);
  await submitPassword(page, options.email, options.password);

  await page.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/consent");
  if (new URL(page.url()).pathname === "/auth/consent") await page.getByRole("button", { name: "Give consent" }).click();
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));

  const code = new URL(page.url()).searchParams.get("code");
  if (!code) throw new Error(`no code in ${page.url()}`);
  await page.close();
  return { context, code, codeVerifier };
}
