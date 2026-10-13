// RFC 9700 on what the browser sees. 4.16: the auth server MUST prevent clickjacking on the
// authorization endpoint, its login and consent pages and its error pages, with X-Frame-Options and
// CSP frame-ancestors. 4.2.4: those pages SHOULD NOT load third-party resources, and a Referrer-Policy
// keeps their addresses from other sites. 2.6: CORS MUST NOT be supported at the authorization
// endpoint, which the browser navigates to rather than fetches; the token endpoint MAY. 4.3.2: an
// access token never travels in a URI query. 4.2.4 and 4.3 name form_post as the response mode that
// keeps the code out of the address, and 4.17 governs in-browser responses, which this server does
// not offer.
import type { Request, Response } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken } from "../../lib/oauth";
import { authorizeEndpoint, codeRequest, emptyBrowser, expectRefusedOnPage, followAuthorize, getAuthorize, tokenEndpoint } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";

const authOrigin = new URL(env.authUrl).origin;

test("every page of the sign-in, its error pages included, refuses framing and loads nothing from another site (sections 4.16, 4.2.4)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('select[name="defaultAcrLevel"]').selectOption("urn:goiabada:level2_mandatory");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client settings saved successfully")).toBeVisible();

  // Every page the auth server renders in this browser, and every request those pages make elsewhere.
  const context = await emptyBrowser(browser);
  const pages = new Map<string, Record<string, string>>();
  const elsewhere: string[] = [];
  context.on("response", (response: Response) => {
    const url = new URL(response.url());
    const rendered = response.status() < 300 || response.status() >= 400;
    if (response.request().resourceType() === "document" && url.origin === authOrigin && rendered) pages.set(url.pathname, response.headers());
  });
  context.on("request", (request: Request) => {
    const url = new URL(request.url());
    const from = request.frame().url();
    if (request.resourceType() !== "document" && url.protocol.startsWith("http") && from.startsWith(authOrigin) && url.origin !== authOrigin) {
      elsewhere.push(`${request.url()} from ${from}`);
    }
  });
  const tab = await context.newPage();

  // The refusal page, at the authorization endpoint itself.
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier, { redirect_uri: "https://attacker.example/cb" }).params)}`);
  // Password, enrolment of a one-time code, consent, and the form_post page.
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier, { response_mode: "form_post" }).params)}`);
  await submitPassword(tab, user.email, user.password);
  await expect(tab).toHaveURL(/\/auth\/otp/);
  await tab.locator('input[name="otp"]').fill(await freshTotp((await tab.locator("pre").innerText()).trim()));
  await tab.getByRole("button", { name: "Verify" }).click();
  await expect(tab).toHaveURL(/\/auth\/consent/);
  await tab.getByRole("button", { name: "Give consent" }).click();
  await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));
  // The "no longer active" page: a step named with another sign-in's ceremony.
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier, { prompt: "login" }).params)}`);
  await expect(tab).toHaveURL(/\/auth\/pwd/);
  await tab.goto(`${env.authUrl}/auth/level1completed?ceremony=another-sign-in`);
  // Signing out, asked first, and the page after.
  await tab.goto(`${env.authUrl}/auth/logout`);
  await tab.getByRole("button", { name: "Yes" }).click();
  await expect(tab.getByRole("heading", { name: "Signed out" })).toBeVisible();
  // Forgot password, and the not found page.
  await tab.goto(`${env.authUrl}/forgot-password`);
  await tab.goto(`${env.authUrl}/no-such-page`);
  await context.close();

  expect([...pages.keys()].sort()).toEqual(
    ["/auth/authorize", "/auth/pwd", "/auth/otp", "/auth/consent", "/auth/issue", "/auth/level1completed", "/auth/logout", "/forgot-password", "/no-such-page"].sort(),
  );
  for (const [path, headers] of pages) {
    await test.step(path, async () => {
      expect(headers["x-frame-options"]).toBe("DENY");
      expect(headers["content-security-policy"]).toMatch(/frame-ancestors 'none'/);
      // Either keeps the page's address from every other site.
      expect(["same-origin", "no-referrer"]).toContain(headers["referrer-policy"]);
    });
  }
  expect(elsewhere, "requests to other sites").toEqual([]);
});

test("the authorization endpoint answers no CORS request, from a registered web origin either; the token endpoint answers only that origin (section 2.6)", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create();
  const registered = `https://${client.identifier}.example.com`;
  await page.goto(clientUrl(client.id, "web-origins"));
  await page.locator("#webOrigin").fill(registered);
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved successfully")).toBeVisible();
  const allowedOrigin = async (url: string, method: "GET" | "OPTIONS", origin: string, requestMethod: string) => {
    const headers: Record<string, string> = { Origin: origin };
    if (method === "OPTIONS") headers["Access-Control-Request-Method"] = requestMethod;
    const response = await request.fetch(url, { method, headers, failOnStatusCode: false, maxRedirects: 0 });
    return response.headers()["access-control-allow-origin"];
  };
  const authorize = `${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier).params)}`;

  for (const origin of [registered, "https://elsewhere.example"]) {
    await test.step(`authorize, ${origin}`, async () => {
      expect(await allowedOrigin(authorize, "GET", origin, "GET")).toBeUndefined();
      expect(await allowedOrigin(authorize, "OPTIONS", origin, "GET")).toBeUndefined();
    });
  }
  expect(await allowedOrigin(tokenEndpoint, "OPTIONS", registered, "POST")).toBe(registered);
  expect(await allowedOrigin(tokenEndpoint, "OPTIONS", "https://elsewhere.example", "POST")).toBeUndefined();
});

test("/userinfo takes the access token from the Authorization header or the body, never from the query (section 4.3.2)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid email" });
  await signIn.context.close();
  const accessToken = (await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri)).body.access_token as string;
  const userinfo = `${env.authUrl}/userinfo`;

  const header = await request.get(userinfo, { headers: { Authorization: `Bearer ${accessToken}` }, failOnStatusCode: false });
  expect(header.status()).toBe(200);
  expect((await header.json()).email).toBe(user.email);
  const body = await request.post(userinfo, { form: { access_token: accessToken }, failOnStatusCode: false });
  expect(body.status()).toBe(200);

  const query = await request.get(`${userinfo}?${new URLSearchParams({ access_token: accessToken })}`, { failOnStatusCode: false });
  expect(query.status()).toBe(401);
  expect(await query.text()).not.toContain(user.email);
});

test("form_post is offered, and posts the response to the redirect URI; an in-browser response mode is refused on the page (sections 4.2.4, 4.3, 4.17)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const metadata = await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json();
  expect(metadata.response_modes_supported).toContain("form_post");
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { params } = codeRequest(client.identifier, { response_mode: "form_post" });
  const { redirect, page: form } = await followAuthorize(signIn.context.request, params);
  expect(redirect, "no redirect: the response is in the page").toBeUndefined();
  expect(form!.status).toBe(200);
  expect(form!.text).toContain(`<form method="post" action="${testRedirectUri}">`);
  expect(form!.text).toMatch(/<input type="hidden" name="code" value="[^"]+"/);
  expect(form!.text).toContain(`<input type="hidden" name="state" value="${params.state}"`);

  const inBrowser = await getAuthorize(signIn.context.request, codeRequest(client.identifier, { response_mode: "web_message" }).params);
  expect(inBrowser.status).toBe(400);
  expectRefusedOnPage(inBrowser, /Invalid response_mode parameter/);
  await signIn.context.close();
});
