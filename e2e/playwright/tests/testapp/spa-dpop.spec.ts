// Add sign-in to a SPA or mobile app, "Bind the tokens to a key with DPoP", through the test app's
// SPA with DPoP: a public client set to require DPoP for token requests, doing everything in the
// browser from its own origin. It makes an ES256 key, binds the code to it with dpop_jkt beside PKCE,
// and sends a proof by it with every token request, to /userinfo and to the API. Every token request
// needs a nonce, so the sign-in succeeds only because script on the SPA's origin read DPoP-Nonce
// from a cross-origin answer and retried with it (RFC 9449 section 8).
import { createHash } from "node:crypto";
import type { Response } from "@playwright/test";
import { grantUserPermission } from "../../lib/admin-console";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { postToken } from "../../lib/rfc6749";
import { expectResult, resultBody, shownClaims, testapp, userBrowser } from "../../lib/testapp";

const tokenEndpoint = `${env.authUrl}/auth/token`;

test("the SPA with DPoP signs in with dpop_jkt, gets bound tokens, refreshes, calls /userinfo and the API with proofs, and signs out", async ({ page, browser, users }) => {
  const user = await users.create();
  await grantUserPermission(page, user.id, testapp.api.resource, "read");
  const { context, page: spa } = await userBrowser(browser);
  const tokenAnswers: Response[] = [];
  spa.on("response", (response) => {
    if (response.url() === tokenEndpoint && response.request().method() === "POST") tokenAnswers.push(response);
  });

  await spa.goto(testapp.spaDpop.url);
  const [authorize] = await Promise.all([
    spa.waitForRequest((request) => new URL(request.url()).pathname === "/auth/authorize"),
    spa.getByRole("button", { name: "Sign in" }).click(),
  ]);
  const parameters = new URL(authorize.url()).searchParams;
  expect(parameters.get("code_challenge_method")).toBe("S256");
  const dpopJkt = parameters.get("dpop_jkt");
  expect(dpopJkt).toMatch(/^[A-Za-z0-9_-]{43}$/);

  await expect(spa).toHaveURL(/\/auth\/pwd/);
  await submitPassword(spa, user.email, user.password);
  await spa.waitForURL(testapp.spaDpop.url);
  await expectResult(spa, "Signed in");
  const signedIn = await resultBody(spa);
  // openid-client reports token_type lower-cased; the auth server's own answer is checked below.
  expect(signedIn.token_type).toBe("dpop");
  expect(String(signedIn.scope).split(" ")).toContain(testapp.api.scope);
  await expect(spa.getByText("Refresh token: yes.")).toBeVisible();

  await test.step("the key the page shows is the one the code and the access token are bound to", async () => {
    const jwk = JSON.parse(await spa.locator('h3:text-is("DPoP public key") + pre').innerText());
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    // RFC 7638 section 3, worked out here from the public key the page shows.
    const thumbprint = createHash("sha256").update(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`).digest("base64url");
    expect(dpopJkt).toBe(thumbprint);
    expect((await shownClaims(spa, "Access token claims")).cnf).toEqual({ jkt: thumbprint });
  });

  await test.step("the first token request was asked for a nonce, which script on the SPA's origin could read", async () => {
    expect(tokenAnswers.length).toBeGreaterThanOrEqual(2);
    const [asked, answered] = tokenAnswers;
    expect(asked.status()).toBe(400);
    expect((await asked.json()).error).toBe("use_dpop_nonce");
    for (const answer of [asked, answered]) {
      const headers = answer.headers();
      expect(headers["dpop-nonce"]).toBeTruthy();
      expect(headers["access-control-allow-origin"]).toBe(testapp.spaDpop.origin);
      expect(headers["access-control-expose-headers"]?.toLowerCase().split(/\s*,\s*/)).toContain("dpop-nonce");
    }
    expect(answered.status()).toBe(200);
    expect((await answered.json()).token_type).toBe("DPoP");
    expect(answered.request().headers()["dpop"]).toBeTruthy();
  });

  const [refreshed] = await Promise.all([
    spa.waitForResponse((response) => response.url() === tokenEndpoint && response.status() === 200),
    spa.getByRole("button", { name: "Refresh the tokens" }).click(),
  ]);
  await expectResult(spa, "Refreshed");
  expect((await refreshed.json()).token_type).toBe("DPoP");
  expect(refreshed.request().postData()).toContain("grant_type=refresh_token");
  expect((await shownClaims(spa, "Access token claims")).cnf).toEqual({ jkt: dpopJkt });

  const [userinfoCall] = await Promise.all([
    spa.waitForRequest((request) => request.url() === `${env.authUrl}/userinfo` && request.method() === "GET"),
    spa.getByRole("button", { name: "Call /userinfo" }).click(),
  ]);
  await expectResult(spa, "/userinfo answered");
  expect((await resultBody(spa)).email).toBe(user.email);
  expect(userinfoCall.headers()["authorization"]).toMatch(/^DPoP /);
  expect(userinfoCall.headers()["dpop"]).toBeTruthy();

  await spa.getByRole("button", { name: "Call the API", exact: true }).click();
  await expectResult(spa, "The API answered 200");
  const api = await resultBody(spa);
  expect(api.scheme).toBe("DPoP");
  expect(api.binding).toEqual({ token_cnf: { jkt: dpopJkt }, introspection: { token_type: "DPoP", cnf: { jkt: dpopJkt } } });

  await test.step("the same token sent as Bearer, with no proof, is refused", async () => {
    await spa.getByRole("button", { name: "Call the API as Bearer (should be refused)" }).click();
    await expectResult(spa, "The API answered 401");
    const refused = await resultBody(spa);
    expect(refused.www_authenticate).toMatch(/^Bearer realm="product-api", error="invalid_token"/);
    expect((refused.body as Record<string, unknown>).error).toBe("invalid_token");
  });

  const [revocation] = await Promise.all([
    spa.waitForResponse((response) => response.url() === `${env.authUrl}/auth/revoke`),
    spa.getByRole("button", { name: "Sign out" }).click(),
  ]);
  expect(revocation.status()).toBe(200);
  await spa.waitForURL(testapp.spaDpop.url);
  await expectResult(spa, "Signed out");
  await context.close();
});

// The client requires DPoP, so the token endpoint refuses any of its token requests without a proof,
// before it looks at the grant.
test("the SPA with DPoP's client gets nothing from the token endpoint without a proof", async ({ request }) => {
  const refused = await postToken(request, {
    grant_type: "authorization_code",
    client_id: testapp.spaDpop.clientId,
    code: "SplxlOBeZQQYbYS6WxSbIA",
    redirect_uri: testapp.spaDpop.url,
    code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  });
  expect(refused.status, refused.text).toBe(400);
  expect(refused.body.error).toBe("invalid_dpop_proof");
  expect(refused.body.error_description).toBe("This client requires a DPoP proof with every token request.");
});
