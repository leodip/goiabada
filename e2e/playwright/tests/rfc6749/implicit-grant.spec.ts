// RFC 6749 section 4.2, the implicit grant (deprecated by RFC 9700, and off unless enabled): the access
// token comes back in the redirect URI's fragment (4.2.2), never with a refresh token, and an error
// comes back in the fragment too (4.2.2.1). Each client here enables it for itself, so no global
// setting changes.
import type { Browser, Page } from "@playwright/test";
import { addRedirectUri, grantUserPermission, setImplicitGrant } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { userinfo } from "../../lib/oauth";
import {
  codeRequest,
  emptyBrowser,
  expectAuthorizeError,
  expectNoStore,
  expectRefusedOnPage,
  followAuthorize,
  getAuthorize,
} from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

interface ClientsFixture {
  create(): Promise<{ id: number; identifier: string; markDeleted(): void }>;
}

// A client with the tests' redirect URI and the implicit grant on, and a user signed in through it, so
// an implicit request through the returned browser's .request needs no password.
async function implicitClientAndSession(page: Page, browser: Browser, clients: ClientsFixture, user: { email: string; password: string }) {
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  return { client, context: signIn.context };
}

// An implicit request: response_type token, the tests' redirect URI, a fresh state, no PKCE.
const tokenRequest = (clientId: string, overrides: Record<string, string | undefined> = {}) =>
  codeRequest(clientId, { response_type: "token", code_challenge: undefined, code_challenge_method: undefined, ...overrides }).params;

test("the access token comes back in the fragment, with its type, lifetime and the state, the registered query kept", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, context } = await implicitClientAndSession(page, browser, clients, user);
  const withQuery = `${testRedirectUri}?tenant=a`;
  await addRedirectUri(page, client.id, withQuery);

  const params = tokenRequest(client.identifier, { redirect_uri: withQuery });
  const { redirect } = await followAuthorize(context.request, params);
  expect(redirect, "redirected to the client").toBeDefined();
  // Section 3.1.2: the registered query is kept, and the response goes in the fragment, not in it.
  expect(redirect!.search).toBe("?tenant=a");
  const fragment = new URLSearchParams(redirect!.hash.slice(1));
  expect(fragment.get("access_token")).toBeTruthy();
  expect(fragment.get("token_type")?.toLowerCase()).toBe("bearer");
  expect(fragment.get("expires_in")).toMatch(/^\d+$/);
  expect(fragment.get("state")).toBe(params.state);
  expect((await userinfo(request, fragment.get("access_token")!)).status).toBe(200);
  await context.close();
});

test("an authorization response carrying a token or a code is never cached (section 5.1)", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client, context } = await implicitClientAndSession(page, browser, clients, user);
  const code = (overrides: Record<string, string> = {}) => codeRequest(client.identifier, overrides).params;

  // response_mode=form_post: a page carrying the token or the code.
  const tokenPage = await followAuthorize(context.request, tokenRequest(client.identifier, { response_mode: "form_post" }));
  expect(tokenPage.page?.text).toContain('name="access_token"');
  expectNoStore(tokenPage.page!);
  const codePage = await followAuthorize(context.request, code({ response_mode: "form_post" }));
  expect(codePage.page?.text).toContain('name="code"');
  expectNoStore(codePage.page!);

  // Section 5.1 MUST: "any response containing tokens, credentials, or other sensitive information",
  // which a redirect whose Location carries the token, or the code, is.
  const tokenRedirect = await followAuthorize(context.request, tokenRequest(client.identifier));
  expect(tokenRedirect.redirect?.hash).toContain("access_token=");
  expectNoStore({ status: 302, headers: tokenRedirect.redirectHeaders!, body: {}, text: "" });
  const codeRedirect = await followAuthorize(context.request, code());
  expect(codeRedirect.redirect?.searchParams.get("code")).toBeTruthy();
  expectNoStore({ status: 302, headers: codeRedirect.redirectHeaders!, body: {}, text: "" });
  await context.close();
});

test("no refresh token is issued, and a scope other than the one asked for is named in the fragment", async ({
  page,
  browser,
  clients,
  resources,
  users,
}) => {
  const user = await users.create();
  const resource = await resources.create({ permissions: ["read", "write"] });
  await grantUserPermission(page, user.id, resource.identifier, "read");
  const { client, context } = await implicitClientAndSession(page, browser, clients, user);

  // Section 4.2.2 MUST NOT: no refresh token, offline_access or not.
  const offline = await followAuthorize(context.request, tokenRequest(client.identifier, { scope: "openid offline_access" }));
  const offlineFragment = new URLSearchParams(offline.redirect!.hash.slice(1));
  expect(offlineFragment.get("access_token")).toBeTruthy();
  expect(offlineFragment.has("refresh_token")).toBe(false);

  // Section 4.2.2: scope is REQUIRED when it differs from the scope asked for.
  const asked = `openid ${resource.identifier}:read ${resource.identifier}:write`;
  const partial = await followAuthorize(context.request, tokenRequest(client.identifier, { scope: asked }));
  const partialFragment = new URLSearchParams(partial.redirect!.hash.slice(1));
  expect(partialFragment.get("access_token")).toBeTruthy();
  expect(partialFragment.get("scope")?.split(" ").sort()).toEqual(["openid", `${resource.identifier}:read`].sort());
  await context.close();
});

test("an error comes back in the fragment with the state, and a redirect URI not registered is refused on the page", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, context } = await implicitClientAndSession(page, browser, clients, user);

  const params = tokenRequest(client.identifier, { scope: "openid no-such-resource:read" });
  const { redirect } = await followAuthorize(context.request, params);
  expect(redirect, "redirected to the client").toBeDefined();
  expect(redirect!.search, "nothing in the query").toBe("");
  expectAuthorizeError(redirect!, "invalid_scope", params.state);

  // Section 4.2.1 MUST: the redirect URI the token would go to is checked against registration.
  const anonymous = await emptyBrowser(browser);
  expectRefusedOnPage(
    await getAuthorize(anonymous.request, tokenRequest(client.identifier, { redirect_uri: `${testRedirectUri}/` })),
    /The client does not have this redirect URI registered/,
  );
  await anonymous.close();
  await context.close();
});

test("a client without the implicit grant is answered unauthorized_client, in the fragment", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client, context } = await implicitClientAndSession(page, browser, clients, user);
  await setImplicitGrant(page, client.id, "off");

  const params = tokenRequest(client.identifier);
  const { redirect, page: refusal } = await followAuthorize(context.request, params);
  expect(redirect, `redirected to the client, not answered on ${refusal ? "a page" : "nothing"}`).toBeDefined();
  expect(redirect!.search).toBe("");
  expect(redirect!.hash).not.toContain("access_token");
  expectAuthorizeError(redirect!, "unauthorized_client", params.state);
  await context.close();
});
