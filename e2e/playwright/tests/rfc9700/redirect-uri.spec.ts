// RFC 9700 sections 2.1, 4.1 and 2.6 on redirect URIs. A requested redirect URI is compared with the
// registered ones by simple string comparison (RFC 3986 section 6.2.1), with no patterns, and the only
// exception is the port of a loopback redirect URI (RFC 8252 section 7.3). And an http redirect URI
// added on a host other than loopback is refused; one stored before that rule keeps working, and the
// list holding it stays saveable (#575). A redirect URI the client stops registering while a user
// signs in is checked again before anything is sent to it. The near misses
// ../rfc6749/redirect-uri.spec.ts tries are not repeated here; dynamic registration is in
// client-registration.system.ts.
import type { Page } from "@playwright/test";
import { addRedirectUri, clientUrl } from "../../lib/admin-console";
import { signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken } from "../../lib/oauth";
import { authorizeEndpoint, codeRequest, emptyBrowser, expectRefusedOnPage, followAuthorize, getAuthorize } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

const notRegistered = /The application does not have this redirect URI registered/;
const host = new URL(testRedirectUri).host;

// Adds uri on the client's Redirect URIs tab and saves: true when the console saved it, false when it
// refused it, at the field (no URL) or in the tab's status region (the admin API's refusal).
async function tryAddRedirectUri(page: Page, id: number, uri: string): Promise<boolean> {
  await page.goto(clientUrl(id, "redirect-uris"));
  await page.locator("#redirectURI").fill(uri);
  await page.locator("#addURIBtn").click();
  if (await page.locator("#redirectURI-error").isVisible()) return false;
  await page.locator("#btnSave").click();
  const saved = page.getByText("Redirect URIs saved.");
  const refused = page.locator("#uriListStatus .notice-danger");
  await expect(saved.or(refused)).toBeVisible();
  return saved.isVisible();
}

test("a redirect URI equal to the registered one only after normalisation is refused (section 4.1.3: simple string comparison)", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  for (const nearMiss of [
    `HTTPS://${host}/callback`,
    `https://${host}/c%61llback`,
    `https://${host}/x/../callback`,
    `https://user@${host}/callback`,
    `https://${host}.evil.example/callback`,
    `${testRedirectUri}/x`,
    `${testRedirectUri}x`,
  ]) {
    await test.step(nearMiss, async () => {
      const answer = await getAuthorize(anonymous.request, codeRequest(client.identifier, { redirect_uri: nearMiss }).params);
      expectRefusedOnPage(answer, notRegistered);
    });
  }
  await anonymous.close();
});

test("a registered redirect URI with a wildcard is no pattern: a URI it would match is refused (section 4.1)", async ({ page, browser, clients }) => {
  const client = await clients.create();
  const parentDomain = host.split(".").slice(1).join(".");
  const anonymous = await emptyBrowser(browser);

  for (const pattern of [`https://*.${parentDomain}/callback`, `${env.webtest1Url}/*`]) {
    await test.step(pattern, async () => {
      // Refusing it at registration is as good as storing it literally.
      if (!(await tryAddRedirectUri(page, client.id, pattern))) return;
      const answer = await getAuthorize(anonymous.request, codeRequest(client.identifier, { redirect_uri: testRedirectUri }).params);
      expectRefusedOnPage(answer, notRegistered);
    });
  }
  await anonymous.close();
});

test("only a loopback redirect URI takes any port: [::1] and localhost as 127.0.0.1 does (section 4.1.3, RFC 8252 section 7.3)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await addRedirectUri(page, client.id, "http://[::1]/callback");
  await addRedirectUri(page, client.id, "http://localhost/callback");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  for (const loopback of ["http://[::1]:53682/callback", "http://localhost:53682/callback"]) {
    await test.step(loopback, async () => {
      const { params, verifier } = codeRequest(client.identifier, { redirect_uri: loopback });
      const { redirect } = await followAuthorize(signIn.context.request, params);
      expect(redirect?.href.startsWith(`${loopback}?`), redirect?.href).toBe(true);
      const redeemed = await codeToken(request, client.identifier, secret, redirect!.searchParams.get("code")!, verifier, loopback);
      expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
    });
  }

  // The exception is loopback's alone: on any other host, another port is another redirect URI.
  const answer = await getAuthorize(signIn.context.request, codeRequest(client.identifier, { redirect_uri: `https://${host}:8443/callback` }).params);
  expectRefusedOnPage(answer, notRegistered);
  await signIn.context.close();
});

test("an http redirect URI on a host other than loopback is refused at registration (section 2.6 MUST NOT)", async ({ page, clients }) => {
  const client = await clients.create();
  const plainHttp = `http://${host}/callback`;

  expect(await tryAddRedirectUri(page, client.id, plainHttp), "refused").toBe(false);
  await expect(page.locator("#uriListStatus")).toContainText("must not use plain http on a host other than the loopback interface");
  await page.reload();
  await expect(page.locator("#redirectURIsTable")).not.toContainText(plainHttp);
});

// The client is checked again at issuance: a redirect URI removed while the user was on the consent
// screen receives nothing, and the page says where the application asked to send the user (#241).
test("a redirect URI the client stops registering during the sign-in is sent nothing: the page says the request stopped (section 4.1)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const context = await emptyBrowser(browser);
  const tab = await context.newPage();
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier).params)}`);
  await submitPassword(tab, user.email, user.password);
  await expect(tab).toHaveURL(/\/auth\/consent/);

  await page.goto(clientUrl(client.id, "redirect-uris"));
  await page.getByRole("button", { name: `Remove ${testRedirectUri}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Redirect URIs saved.")).toBeVisible();

  const sentThere: string[] = [];
  context.on("request", (r) => {
    if (r.url().startsWith(testRedirectUri)) sentThere.push(r.url());
  });
  await tab.getByRole("button", { name: "Allow", exact: true }).click();
  await expect(tab.getByRole("heading", { name: "You have not been sent anywhere" })).toBeVisible();
  await expect(tab).toHaveTitle(/^Authorization stopped – /);
  await expect(tab.getByText(client.identifier, { exact: true })).toBeVisible();
  await expect(tab.getByText("This application asked to send you to:")).toBeVisible();
  await expect(tab.getByText(host, { exact: true })).toBeVisible();
  expect(new URL(tab.url()).origin).toBe(env.authUrl);
  expect(sentThere).toEqual([]);
  await context.close();
});
