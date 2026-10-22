// RFC 6749 sections 3.1 and 3.1.1, how the authorization endpoint reads a request: GET and POST
// (3.1), parameters sent empty, unknown or twice (3.1 and erratum 5708), response_type (3.1.1), and
// the client_id it must know before anything is redirected (4.1.2.1). Requests that should reach the
// client go through a browser already signed in, so their answers come back at once.
import { clientUrl, confirmDialog, setImplicitGrant } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
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
  followFrom,
  getAuthorize,
} from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

test("a GET and a POST to the authorization endpoint both issue a code, the POST through a redirect that works once", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const viaGet = codeRequest(client.identifier);
  const { redirect: gotten } = await followAuthorize(signIn.context.request, viaGet.params);
  expect(gotten?.searchParams.get("state")).toBe(viaGet.params.state);
  const fromGet = await codeToken(request, client.identifier, secret, gotten!.searchParams.get("code")!, viaGet.verifier, testRedirectUri);
  expect(fromGet.status, JSON.stringify(fromGet.body)).toBe(200);

  // Section 3.1 MAY: the same parameters as a form body.
  const viaPost = codeRequest(client.identifier);
  const posted = await signIn.context.request.post(authorizeEndpoint, { form: viaPost.params, failOnStatusCode: false, maxRedirects: 0 });
  expect(posted.status()).toBeGreaterThanOrEqual(300);
  expect(posted.status()).toBeLessThan(400);
  const parked = new URL(posted.headers()["location"], authorizeEndpoint);
  const { redirect: fromPost } = await followFrom(signIn.context.request, parked.href);
  expect(fromPost?.searchParams.get("state")).toBe(viaPost.params.state);
  const fromPostTokens = await codeToken(request, client.identifier, secret, fromPost!.searchParams.get("code")!, viaPost.verifier, testRedirectUri);
  expect(fromPostTokens.status, JSON.stringify(fromPostTokens.body)).toBe(200);
  // The request is parked under a one-time handle the redirect carries: followed again, it is refused.
  expectRefusedOnPage(await getAuthorize(signIn.context.request, [...parked.searchParams]), /This sign-in link is no longer valid/);
  await signIn.context.close();
});

test("no step of the sign-in can be skipped: nothing reaches the client before the password", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);

  // Section 3.1 MUST: the resource owner is authenticated first.
  const { pageUrl } = await followAuthorize(anonymous.request, codeRequest(client.identifier).params);
  expect(pageUrl).toMatch(/\/auth\/pwd\?/);
  const ceremony = new URL(pageUrl!).searchParams.get("ceremony")!;
  for (const step of ["/auth/level1completed", "/auth/completed", "/auth/consent", "/auth/issue"]) {
    await test.step(step, async () => {
      const response = await anonymous.request.get(`${env.authUrl}${step}?ceremony=${ceremony}`, { failOnStatusCode: false, maxRedirects: 0 });
      expect(response.headers()["location"] ?? "", `${step} answered ${response.status()}`).not.toContain(new URL(testRedirectUri).host);
      expect(response.status()).toBe(400);
      expect(await response.text()).toContain("This step is no longer available");
    });
  }
  await anonymous.close();
});

test("an unknown parameter is ignored, sent once or twice", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  // Section 3.1 MUST ignore unrecognized parameters; erratum 5708 keeps the repetition rule to the
  // RFC's own, so an unknown one sent twice is ignored as well.
  for (const extra of [[["foo", "bar"]], [["foo", "1"], ["foo", "2"]]] as [string, string][][]) {
    await test.step(new URLSearchParams(extra).toString(), async () => {
      const { params } = codeRequest(client.identifier);
      const { redirect } = await followAuthorize(signIn.context.request, [...Object.entries(params), ...extra]);
      expect(redirect?.searchParams.get("code"), redirect?.href).toBeTruthy();
      expect(redirect!.searchParams.has("foo")).toBe(false);
    });
  }
  await signIn.context.close();
});

test("a parameter of the RFC sent twice is refused: on the page when it says where the answer goes, else at the redirect URI", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const twice = (name: string) => {
    const { params } = codeRequest(client.identifier);
    return { params, pairs: [...Object.entries(params), [name, params[name]]] as [string, string][] };
  };

  // client_id, redirect_uri, response_type: sent twice, the request does not say where the answer
  // goes or how, so it goes nowhere (sections 3.1 and 4.1.2.1).
  for (const name of ["client_id", "redirect_uri", "response_type"]) {
    await test.step(name, async () => {
      expectRefusedOnPage(await getAuthorize(signIn.context.request, twice(name).pairs), /was included more than once/);
    });
  }

  // scope: invalid_request at the redirect URI (section 4.1.2.1: "includes a parameter more than once").
  const scope = twice("scope");
  const { redirect: scopeAnswer } = await followAuthorize(signIn.context.request, scope.pairs);
  expectAuthorizeError(scopeAnswer!, "invalid_request", scope.params.state);
  // state: the same, without a state, since no one exact value was received.
  const state = twice("state");
  const { redirect: stateAnswer } = await followAuthorize(signIn.context.request, state.pairs);
  expectAuthorizeError(stateAnswer!, "invalid_request", undefined);
  await signIn.context.close();
});

test("a parameter sent without a value is treated as omitted", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const api = signIn.context.request;

  // state: a code, and no state in the answer.
  const { redirect: noState } = await followAuthorize(api, codeRequest(client.identifier, { state: "" }).params);
  expect(noState?.searchParams.get("code")).toBeTruthy();
  expect(noState!.searchParams.has("state")).toBe(false);

  // scope and response_type: the same error whether empty or absent. Section 3.3 MUST: with no scope,
  // a default or invalid_scope.
  for (const [name, error] of [["scope", "invalid_scope"], ["response_type", "invalid_request"]] as const) {
    await test.step(name, async () => {
      for (const value of ["", undefined]) {
        const { params } = codeRequest(client.identifier, { [name]: value });
        const { redirect } = await followAuthorize(api, params);
        expect(redirect, `${name}=${value ?? "(absent)"} answered at the redirect URI`).toBeDefined();
        expectAuthorizeError(redirect!, error, params.state);
      }
    });
  }

  // redirect_uri: refused as missing, on the page, either way.
  for (const value of ["", undefined]) {
    expectRefusedOnPage(await getAuthorize(api, codeRequest(client.identifier, { redirect_uri: value }).params), /The redirect_uri parameter is missing/);
  }
  await signIn.context.close();
});

test("a response_type the server does not know, in part or in its case, is unsupported_response_type", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  // Section 1.9: values are case-sensitive, so CODE is not code.
  for (const responseType of ["foo", "code foo", "CODE"]) {
    await test.step(responseType, async () => {
      const { params } = codeRequest(client.identifier, { response_type: responseType });
      const { redirect } = await followAuthorize(signIn.context.request, params);
      expect(redirect, "answered at the redirect URI").toBeDefined();
      expectAuthorizeError(redirect!, "unsupported_response_type", params.state);
    });
  }
  await signIn.context.close();
});

test("a response_type of several values is a set: token id_token is id_token token (sections 3.1.1, 8.4)", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  for (const responseType of ["id_token token", "token id_token"]) {
    await test.step(responseType, async () => {
      const { params } = codeRequest(client.identifier, {
        response_type: responseType,
        nonce: `n-${Date.now()}`,
        code_challenge: undefined,
        code_challenge_method: undefined,
      });
      const { redirect } = await followAuthorize(signIn.context.request, params);
      const fragment = new URLSearchParams(redirect?.hash.slice(1));
      expect(fragment.get("access_token"), redirect?.href).toBeTruthy();
      expect(fragment.get("id_token")).toBeTruthy();
    });
  }
  await signIn.context.close();
});

test("a missing or unknown client_id is refused on the page, never redirected", async ({ browser }) => {
  const anonymous = await emptyBrowser(browser);

  expectRefusedOnPage(await getAuthorize(anonymous.request, codeRequest("unused", { client_id: undefined }).params), /The client_id parameter is missing/);
  expectRefusedOnPage(await getAuthorize(anonymous.request, codeRequest("e2e-no-such-client").params), /The application does not exist/);
  await anonymous.close();
});

test("a disabled client is refused on the page, never redirected to its registered redirect URI", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator("#enabledDisabled").uncheck();
  // Disabling asks first.
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're disabling the client");
  await expect(page.getByText("Settings saved.")).toBeVisible();
  const anonymous = await emptyBrowser(browser);

  // Section 4.1.2.1: a client identifier that is invalid MUST NOT be redirected to.
  expectRefusedOnPage(await getAuthorize(anonymous.request, codeRequest(client.identifier).params), /The application is disabled/);
  await anonymous.close();
});
