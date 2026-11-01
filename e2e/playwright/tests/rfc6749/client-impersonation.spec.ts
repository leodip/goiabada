// RFC 6749 section 10.2 and RFC 8252 section 8.6, client impersonation: a public client has no
// secret, so nothing proves an authorization request comes from it rather than from another app
// sending its client_id. The server SHOULD NOT process repeated authorization requests automatically
// unless the client's identity can be proven, and SHOULD process them as if no previous request had
// been approved. So a public client with Remember consent off, as every public client starts, shows
// the consent screen every time it asks for consent, and prompt=none from it is refused; a
// confidential client, which proves itself with its secret, skips the screen once approved.
import type { Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { signInThroughClient } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { codeRequest, expectAuthorizeError, followAuthorize, responseParams } from "../../lib/rfc6749";
import { browserSignInClient, publicSignInClient } from "../../lib/test-clients";

// Turns Ask users for consent on for the client, on its Settings tab.
async function askUsersForConsent(page: Page, clientId: number) {
  await page.goto(clientUrl(clientId, "settings"));
  await page.locator('input[name="consentRequired"]').check();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Settings saved.")).toBeVisible();
}

test("a public client asking for consent shows the screen again after the user approved every scope", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  await askUsersForConsent(page, client.id);

  // The first sign-in approves the screen, which ticks every scope asked for.
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  // Section 10.2 SHOULD: processed as if no previous request had been approved.
  const { pageUrl, page: shown, redirect } = await followAuthorize(signIn.context.request, codeRequest(client.identifier).params);
  expect(redirect, "no code is sent without the screen").toBeUndefined();
  expect(new URL(pageUrl!).pathname).toBe("/auth/consent");
  expect(shown!.status).toBe(200);
  expect(shown!.text).toContain("Allow");
  await signIn.context.close();
});

test("prompt=none from a public client asking for consent is answered consent_required", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  await askUsersForConsent(page, client.id);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  // OIDC Core 1.0 section 3.1.2.6: consent_required when the request cannot be completed without a
  // consent screen, which an earlier approval cannot stand in for here.
  const silent = codeRequest(client.identifier, { prompt: "none" });
  const { redirect } = await followAuthorize(signIn.context.request, silent.params);
  expectAuthorizeError(redirect!, "consent_required", silent.params.state);
  expect(responseParams(redirect!).get("error_description")).toBe("User consent is required for every request from this client");
  await signIn.context.close();
});

test("a confidential client asking for consent skips the screen once the user approved it", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const again = codeRequest(client.identifier);
  const { redirect } = await followAuthorize(signIn.context.request, again.params);
  expect(redirect?.searchParams.get("state")).toBe(again.params.state);
  expect(redirect?.searchParams.get("code")).toBeTruthy();

  const silent = codeRequest(client.identifier, { prompt: "none" });
  const { redirect: silentRedirect } = await followAuthorize(signIn.context.request, silent.params);
  expect(silentRedirect?.searchParams.get("code"), silentRedirect?.href).toBeTruthy();
  await signIn.context.close();
});
