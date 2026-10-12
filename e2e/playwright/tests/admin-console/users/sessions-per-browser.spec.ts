// A browser is one device to the auth server through its device cookie, not its user agent or address
// (#564): a sign-in replaces the earlier session of the browser it happens in and no other, and every
// session that ends says why in the audit log.
import type { BrowserContext } from "@playwright/test";
import { signInThroughClient, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { authorizeAgain, expectSessionDeleted, sessionIds } from "../../../lib/sessions";
import { browserSignInClient } from "../../../lib/test-clients";

// On https the cookie carries the __Host- prefix: secure, host-only, path /.
const deviceCookie = "__Host-authserver_device";

async function deviceCookieOf(context: BrowserContext) {
  return (await context.cookies(env.authUrl)).find((cookie) => cookie.name === deviceCookie);
}

// Signs the user in again through the client in this browser, which has no session to sign them in.
async function signInAgain(context: BrowserContext, clientId: string, user: { email: string; password: string }) {
  const { page, landed } = await authorizeAgain(context, clientId);
  expect(landed).toBe("password");
  await submitPassword(page, user.email, user.password);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await page.close();
}

test("a browser keeps its device cookie, and signing in again in it replaces its earlier session", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const device = await deviceCookieOf(signIn.context);
  expect(device, `no ${deviceCookie} cookie`).toBeDefined();
  expect(device).toMatchObject({ domain: new URL(env.authUrl).hostname, path: "/", httpOnly: true, secure: true, sameSite: "Lax" });
  // Kept for 400 days, the longest a browser keeps a cookie.
  expect(device!.expires * 1000).toBeGreaterThan(Date.now() + 399 * 86_400_000);
  expect(device!.expires * 1000).toBeLessThan(Date.now() + 401 * 86_400_000);
  const [first] = await sessionIds(page, user.id);
  expect(first).toBeDefined();

  // The session cookie gone and the device cookie kept: the same browser after its session cookie
  // expired. The sign-in asks for the password, and its session replaces the browser's earlier one.
  await signIn.context.clearCookies({ name: new RegExp(`^(?!${deviceCookie}$)`) });
  await signInAgain(signIn.context, client.identifier, user);
  const after = await sessionIds(page, user.id);
  expect(after).toHaveLength(1);
  expect(after[0]).not.toBe(first);
  expect((await deviceCookieOf(signIn.context))?.value).toBe(device!.value);
  await expectSessionDeleted(page, first, "same_device");
  await signIn.context.close();
});

test("a sign-out keeps the device cookie, and each session that ends says why", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const device = (await deviceCookieOf(signIn.context))!.value;
  const [signedOut] = await sessionIds(page, user.id);

  const logout = await signIn.context.newPage();
  await logout.goto(`${env.authUrl}/auth/logout`);
  await logout.getByRole("button", { name: "Yes" }).click();
  await expect(logout.getByRole("heading", { name: "Signed out" })).toBeVisible();
  expect((await deviceCookieOf(signIn.context))?.value).toBe(device);
  expect(await sessionIds(page, user.id)).toEqual([]);
  await expectSessionDeleted(page, signedOut, "signed_out");

  await signInAgain(signIn.context, client.identifier, user);
  const [ended] = await sessionIds(page, user.id);
  await page.locator("table tbody tr").first().getByRole("button", { name: "End session" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByText("No sessions found.")).toBeVisible();
  await expectSessionDeleted(page, ended, "ended_by_administrator");
  await signIn.context.close();
});
