// RFC 9700 section 4.13, a TLS-terminating reverse proxy. Headers the proxy passes on, such as the
// client's address, are only as good as the proxy's handling of what the client sent: a client
// could otherwise name any address and slip past limits counted by address. The proxy's part is the
// deployment's (here nginx appends to X-Forwarded-For and sets X-Real-IP, as the docs' reverse proxy
// page shows); the server's is to read the hop the proxy added, not one the client wrote. The
// address shows on the user's sessions in the admin console.
import type { Browser, Page } from "@playwright/test";
import { userUrl } from "../../lib/admin-console";
import { submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { authorizeEndpoint, codeRequest } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

const forged = { "X-Forwarded-For": "203.0.113.7", "X-Real-IP": "203.0.113.8", "True-Client-IP": "203.0.113.9", Forwarded: "for=203.0.113.10" };

// Signs the user in through the client in a browser sending these headers on every request.
async function signIn(browser: Browser, clientId: string, user: { email: string; password: string }, extraHTTPHeaders: Record<string, string> = {}) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders });
  const tab = await context.newPage();
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(clientId).params)}`);
  await submitPassword(tab, user.email, user.password);
  await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));
  await context.close();
}

// The address of the user's one session, from the IP address column of Users -> Sessions.
async function sessionAddress(page: Page, userId: number): Promise<string> {
  await page.goto(userUrl(userId, "sessions"));
  const column = (await page.locator("table thead th").allInnerTexts()).findIndex((text) => text.trim() === "IP address");
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(1);
  return (await rows.first().locator("td").nth(column).innerText()).trim();
}

test("an address the client writes in a forwarding header is not taken as its own (section 4.13)", async ({ page, browser, clients, users }) => {
  const plain = await users.create();
  const forging = await users.create();
  const { client } = await browserSignInClient(page, clients);

  await signIn(browser, client.identifier, plain);
  await signIn(browser, client.identifier, forging, forged);

  const real = await sessionAddress(page, plain.id);
  expect(real, "the plain sign-in's address").toMatch(/^[0-9a-f.:]+$/i);
  expect(await sessionAddress(page, forging.id)).toBe(real);
});
