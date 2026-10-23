// RFC 9700 on what the browser sees. 4.16: the auth server MUST prevent clickjacking on the
// authorization endpoint, its login and consent pages and its error pages, with X-Frame-Options and
// CSP frame-ancestors. 4.2.4: those pages SHOULD NOT load third-party resources, and a Referrer-Policy
// keeps their addresses from other sites. 2.6: CORS MUST NOT be supported at the authorization
// endpoint, which the browser navigates to rather than fetches; the token endpoint MAY. 4.3.2: an
// access token never travels in a URI query. 4.2.4 and 4.3 name form_post as the response mode that
// keeps the code out of the address, and 4.17 governs in-browser responses, which this server does
// not offer.
import type { Request, Response } from "@playwright/test";
import { addRedirectUri, clientUrl, setImplicitGrant } from "../../lib/admin-console";
import { openSignIn, signInThroughClient, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken } from "../../lib/oauth";
import {
  authorizeEndpoint,
  codeRequest,
  emptyBrowser,
  expectAuthorizeError,
  expectRefusedOnPage,
  followAuthorize,
  getAuthorize,
  readAnswer,
  responseParams,
  type RawAnswer,
  tokenEndpoint,
} from "../../lib/rfc6749";
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
  await expect(page.getByText("Settings saved.")).toBeVisible();

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
  await tab.locator('input[name="otp"]').fill(await freshTotp((await tab.locator("#otp-secret").innerText()).trim()));
  await tab.getByRole("button", { name: "Verify" }).click();
  await expect(tab).toHaveURL(/\/auth\/consent/);
  await tab.getByRole("button", { name: "Allow", exact: true }).click();
  await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));
  // The "no longer active" page: a step named with another sign-in's ceremony.
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier, { prompt: "login" }).params)}`);
  await expect(tab).toHaveURL(/\/auth\/pwd/);
  await tab.goto(`${env.authUrl}/auth/level1completed?ceremony=another-sign-in`);
  // Signing out, asked first, and the page after.
  await tab.goto(`${env.authUrl}/auth/logout`);
  await tab.getByRole("button", { name: "Sign out", exact: true }).click();
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
  await page.locator("#addOriginBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved.")).toBeVisible();
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
  // A form the page's script submits as soon as it is parsed (data-auto-submit).
  expect(form!.text).toContain(`method="post" action="${testRedirectUri}" data-auto-submit>`);
  expect(form!.text).toMatch(/<input type="hidden" name="code" value="[^"]+"/);
  expect(form!.text).toContain(`<input type="hidden" name="state" value="${params.state}"`);

  const inBrowser = await getAuthorize(signIn.context.request, codeRequest(client.identifier, { response_mode: "web_message" }).params);
  expect(inBrowser.status).toBe(400);
  expectRefusedOnPage(inBrowser, /Invalid response_mode parameter/);
  await signIn.context.close();
});

// With no script to submit it, the form_post page says what it is doing and offers the button that
// sends the response on.
test("without JavaScript, the form_post page says it is returning the user, and Continue posts the response to the redirect URI (section 4.2.4)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  // The same browser's session, in a context that runs no script.
  const noScript = await browser.newContext({ storageState: await signIn.context.storageState(), javaScriptEnabled: false });
  await signIn.context.close();
  const tab = await noScript.newPage();

  const { params } = codeRequest(client.identifier, { response_mode: "form_post" });
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
  await expect(tab.getByRole("heading", { name: "Returning you to the application" })).toBeVisible();
  await expect(tab.getByText("If nothing happens, select Continue.")).toBeVisible();
  const [posted] = await Promise.all([
    tab.waitForRequest((r) => r.url() === testRedirectUri && r.method() === "POST"),
    tab.getByRole("button", { name: "Continue" }).click(),
  ]);
  const fields = new URLSearchParams(posted.postData() ?? "");
  expect(fields.get("code")).toBeTruthy();
  expect(fields.get("state")).toBe(params.state);
  await noScript.close();
});

// form_post answers through a form whose action is the redirect URI, which no form can post to when
// its scheme is a custom one: html/template rewrote it to #ZgotmplZ, so the code, or an error, was
// posted back to the auth server and never reached the app. The request is refused on the page with
// no error parameters, as an unsupported mode is (OIDC Core 1.0 section 3.1.2.6), whether or not the
// browser is signed in, and the page names the modes the request may use instead (#121).
test("form_post to a custom-scheme redirect URI is refused on the page, signed in or not (#121, OIDC Core 3.1.2.6)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const customUris = ["myapp://callback", "com.example.app:/oauth2redirect/example-provider"];
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  for (const uri of customUris) await addRedirectUri(page, client.id, uri);

  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const signedOut = await emptyBrowser(browser);

  const codeAdvice = "Use response_mode=query or response_mode=fragment instead.";
  const implicitAdvice = "Use response_mode=fragment instead.";
  const requests = customUris.flatMap((uri) => [
    { name: `code to ${uri}`, advice: codeAdvice, params: codeRequest(client.identifier, { response_mode: "form_post", redirect_uri: uri }).params },
    {
      name: `token to ${uri}`,
      advice: implicitAdvice,
      params: codeRequest(client.identifier, {
        response_mode: "form_post",
        redirect_uri: uri,
        response_type: "token",
        code_challenge: undefined,
        code_challenge_method: undefined,
      }).params,
    },
  ]);

  const expectRefusal = (answer: RawAnswer, advice: string, label: string) => {
    expect(answer.status, label).toBe(400);
    expectRefusedOnPage(answer, advice);
    expect(answer.text, `${label}: no form to post anything anywhere`).not.toContain("<form");
    expect(answer.text, label).not.toContain("ZgotmplZ");
  };
  for (const [state, context] of [
    ["signed in", signIn.context],
    ["signed out", signedOut],
  ] as const) {
    for (const { name, advice, params } of requests) {
      expectRefusal(await getAuthorize(context.request, params), advice, `GET ${name}, ${state}`);
      const posted = await context.request.post(authorizeEndpoint, { form: params, failOnStatusCode: false, maxRedirects: 0 });
      expectRefusal(await readAnswer(posted), advice, `POST ${name}, ${state}`);
    }
  }

  // In the browser itself: the page stays on the authorization endpoint and says why.
  const tab = await signedOut.newPage();
  const shown = await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(requests[0].params)}`);
  expect(shown?.status()).toBe(400);
  await expect(tab.getByRole("heading", { name: "Unable to authorize" })).toBeVisible();
  await expect(tab.locator("#errorMsg")).toContainText(codeAdvice);
  expect(new URL(tab.url()).pathname).toBe("/auth/authorize");

  // The control: the query reaches a custom scheme, so only form_post is refused there.
  const viaQuery = codeRequest(client.identifier, { response_mode: "query", redirect_uri: customUris[0] }).params;
  const { redirect } = await followAuthorize(signIn.context.request, viaQuery);
  expect(redirect?.protocol, "redirected to the app's custom scheme").toBe("myapp:");
  expect(responseParams(redirect!).get("code")).toBeTruthy();
  expect(responseParams(redirect!).get("state")).toBe(viaQuery.state);

  await signedOut.close();
  await signIn.context.close();
});

// Any page the user has open, of any site, can send the browser to the authorization endpoint, and
// the browser sends its session cookie with that navigation. A request the auth server answers at
// once with an error stores nothing and removes nothing, so it cannot end the sign-in the user is
// in the middle of: here a prompt=none request from another tab, answered login_required at its
// redirect URI, while the first tab shows the password form (#246).
test("a sign-in in progress finishes after a prompt=none request in another tab of the same browser is answered with login_required (#246)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const { context, page: signingIn, codeVerifier } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signingIn).toHaveURL(/\/auth\/pwd/);

  const other = await context.newPage();
  const silent = codeRequest(client.identifier, { prompt: "none" });
  await other.goto(`${authorizeEndpoint}?${new URLSearchParams(silent.params)}`);
  await other.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expectAuthorizeError(new URL(other.url()), "login_required", silent.params.state);

  await submitPassword(signingIn, user.email, user.password);
  await signingIn.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const code = new URL(signingIn.url()).searchParams.get("code");
  expect(code, "the first tab's sign-in reached its client with a code").toBeTruthy();
  const tokens = await codeToken(request, client.identifier, secret, code!, codeVerifier, testRedirectUri);
  expect(tokens.status, "and the code is the first tab's own").toBe(200);
  await context.close();
});

// The same with a valid authorization request: a link from any site, or a page sending the browser
// to sign in, starts a sign-in of its own, held beside the one in progress, and ends none. Here the
// other tab's request reaches its own password form while the first tab shows the password form,
// and both finish, each with its own code (#246).
test("a sign-in in progress finishes after a valid authorization request in another tab of the same browser (#246)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const { context, page: signingIn, codeVerifier } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signingIn).toHaveURL(/\/auth\/pwd/);

  const other = await context.newPage();
  const another = codeRequest(client.identifier);
  await other.goto(`${authorizeEndpoint}?${new URLSearchParams(another.params)}`);
  await expect(other).toHaveURL(/\/auth\/pwd/);

  await submitPassword(signingIn, user.email, user.password);
  await signingIn.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const code = new URL(signingIn.url()).searchParams.get("code");
  expect(code, "the first tab's sign-in reached its client with a code").toBeTruthy();
  const tokens = await codeToken(request, client.identifier, secret, code!, codeVerifier, testRedirectUri);
  expect(tokens.status, "and the code is the first tab's own").toBe(200);

  await submitPassword(other, user.email, user.password);
  await other.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const answer = new URL(other.url()).searchParams;
  expect(answer.get("state"), "the other tab's sign-in answers its own request").toBe(another.params.state);
  const otherTokens = await codeToken(request, client.identifier, secret, answer.get("code")!, another.verifier, testRedirectUri);
  expect(otherTokens.status, "with a code of its own").toBe(200);
  await context.close();
});
