// A user signing in to a client application through the browser: the authorization code flow, the
// way a real application starts it. The tests use it where only a browser sign-in leaves a trace, a
// session or a consent, which the password grant does not.
import { createHash, randomBytes } from "node:crypto";
import { expect, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { env } from "./environment";

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
// server's password form. Any other authorization parameters, such as ui_locales, are added to the
// request. The caller closes the context.
export async function openSignIn(browser: Browser, options: { clientId: string; scope: string; params?: Record<string, string> }) {
  // An explicit empty state: inside a test, browser.newContext() starts from the test's options, which
  // here carry the administrator's signed-in state, and the sign-in would be the administrator's.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
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
    ...options.params,
  });
  await page.goto(`${env.authUrl}/auth/authorize?${query}`);
  return { context, page, codeVerifier };
}

// Fills and submits the auth server's password form.
export async function submitPassword(page: Page, email: string, password: string) {
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForLoadState();
}

// After the code that set up an authenticator during a sign-in, the page that shows the ten recovery
// codes the authenticator came with, once (#257): checks that it lists them, clicks Continue, and
// returns them, as shown.
export async function continuePastRecoveryCodes(page: Page): Promise<string[]> {
  await page.waitForURL((url) => url.pathname === "/auth/recovery-codes");
  await expect(page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  const recoveryCodes = (await page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts())
    .map((code) => code.trim());
  expect(recoveryCodes).toHaveLength(10);
  await page.getByRole("button", { name: "Continue" }).click();
  return recoveryCodes;
}

// Signs the user in through the client in a browser of their own, approving the consent screen if one
// shows, and returns once the browser is back at the redirect URI with a code. The caller closes the
// context.
export async function signInThroughClient(
  browser: Browser,
  options: { clientId: string; email: string; password: string; scope: string },
): Promise<BrowserSignIn> {
  const { context, page, codeVerifier } = await openSignIn(browser, options);
  await submitPassword(page, options.email, options.password);

  await page.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/consent");
  if (new URL(page.url()).pathname === "/auth/consent") await page.getByRole("button", { name: "Allow", exact: true }).click();
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));

  const code = new URL(page.url()).searchParams.get("code");
  if (!code) throw new Error(`no code in ${page.url()}`);
  await page.close();
  return { context, code, codeVerifier };
}

// Sends a browser to the authorization endpoint with exactly these parameters (redirect_uri is the
// tests' own), signs the user in if the auth server asks, and returns the address the browser lands
// on back at the redirect URI: query or fragment, code or error.
export async function authorizeAndLand(
  browser: Browser,
  params: Record<string, string>,
  user: { email: string; password: string },
): Promise<URL> {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();
  try {
    await page.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams({ redirect_uri: testRedirectUri, ...params })}`);
    if (new URL(page.url()).pathname === "/auth/pwd") await submitPassword(page, user.email, user.password);
    await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
    return new URL(page.url());
  } finally {
    await context.close();
  }
}

// The parameters of a redirect back to the client, from the query or, for the implicit flow, the
// fragment.
export function redirectParams(url: URL): URLSearchParams {
  return url.hash.length > 1 ? new URLSearchParams(url.hash.slice(1)) : url.searchParams;
}
