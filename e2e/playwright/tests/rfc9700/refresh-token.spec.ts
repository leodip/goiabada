// RFC 9700 sections 2.2.2 and 4.14, refresh token protection. A public client's refresh token must be
// sender-constrained or rotated, and rotation must detect a replay: the old token presented again
// revokes the live one. A refresh token stays bound to the scope the resource owner consented to, so
// withdrawing the consent or the permission ends it. It should expire when unused for a while, and
// may be revoked at logout or a password change. A confidential client's rotation and replay, and a
// refresh token presented by another client, are in ../oauth/refresh-tokens.spec.ts.
import type { APIRequestContext, Browser } from "@playwright/test";
import { clientUrl, confirmDialog, grantUserPermission, rowWithCell, userUrl } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, expectTokenError, expectTokenResponse, postToken, type RawAnswer } from "../../lib/rfc6749";
import { browserSignInClient, publicSignInClient } from "../../lib/test-clients";

interface Client {
  identifier: string;
  secret?: string;
}

// The token endpoint as the client: client_secret_basic with a secret, client_id alone without one.
function asClient(request: APIRequestContext, client: Client) {
  return (form: Record<string, string>): Promise<RawAnswer> =>
    client.secret
      ? postToken(request, form, { headers: { Authorization: basicAuth(client.identifier, client.secret) } })
      : postToken(request, { ...form, client_id: client.identifier });
}

// A user's tokens through the authorization code flow, with the browser they signed in with, which
// holds their session. The caller closes it.
async function signInForTokens(browser: Browser, request: APIRequestContext, client: Client, user: { email: string; password: string }, scope = "openid") {
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope });
  const answer = await asClient(request, client)({ grant_type: "authorization_code", code: signIn.code, code_verifier: signIn.codeVerifier, redirect_uri: testRedirectUri });
  expectTokenResponse(answer);
  expect(answer.body.refresh_token, "a refresh token was issued").toBeTruthy();
  return { context: signIn.context, tokens: answer.body };
}

test("a public client's refresh token rotates, and a rotated one presented again revokes the one that replaced it (section 4.14.2 MUST)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const client = await publicSignInClient(page, clients);
  const token = asClient(request, client);
  const { context, tokens } = await signInForTokens(browser, request, client, user);
  await context.close();
  const first = tokens.refresh_token as string;

  const rotated = await token({ grant_type: "refresh_token", refresh_token: first });
  expectTokenResponse(rotated);
  const second = rotated.body.refresh_token as string;
  expect(second, "a new refresh token with every refresh").toBeTruthy();
  expect(second).not.toBe(first);

  // The thief, or the client, presents the old one: refused, and the family goes with it.
  expectTokenError(await token({ grant_type: "refresh_token", refresh_token: first }), "invalid_grant");
  expectTokenError(await token({ grant_type: "refresh_token", refresh_token: second }), "invalid_grant");
});

test("a refresh token ends when the user's consent to the client, or the user's permission, is withdrawn (section 4.14.2 MUST)", async ({
  page,
  browser,
  clients,
  resources,
  users,
  request,
}) => {
  const resource = await resources.create({ permissions: ["read"] });
  const user = await users.create();
  await grantUserPermission(page, user.id, resource.identifier, "read");
  const { client, secret } = await browserSignInClient(page, clients, { consentRequired: true });
  const token = asClient(request, { identifier: client.identifier, secret });

  await test.step("consent revoked", async () => {
    // A client of its own, whose Ask users for consent is turned off once the user has approved the
    // screen: a refresh then consults no stored consent, so only the withdrawal's revocation can end
    // the grant (#622). The step's shared client keeps consent required for the step after.
    const consentClient = await browserSignInClient(page, clients, { consentRequired: true });
    const consentToken = asClient(request, { identifier: consentClient.client.identifier, secret: consentClient.secret });
    const { context, tokens } = await signInForTokens(browser, request, { identifier: consentClient.client.identifier, secret: consentClient.secret }, user, "openid profile");
    await context.close();
    await page.goto(clientUrl(consentClient.client.id, "settings"));
    await page.locator('input[name="consentRequired"]').uncheck();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Settings saved.")).toBeVisible();
    // Refreshes while the consent stands; the token it issues is the live one.
    const refreshed = await consentToken({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string });
    expectTokenResponse(refreshed);
    await page.goto(userUrl(user.id, "consents"));
    const row = rowWithCell(page, consentClient.client.identifier);
    await row.getByRole("button", { name: `Revoke ${consentClient.client.identifier}`, exact: true }).click();
    await confirmDialog(page, `Revoke the consent the user gave ${consentClient.client.identifier}?`);
    await expect(row.getByText("Revoked", { exact: true })).toBeVisible();
    const refused = await consentToken({ grant_type: "refresh_token", refresh_token: refreshed.body.refresh_token as string });
    expectTokenError(refused, "invalid_grant");
    expect(refused.body.error_description).toBe("This refresh token has been revoked.");
  });

  await test.step("permission removed", async () => {
    const { context, tokens } = await signInForTokens(browser, request, { identifier: client.identifier, secret }, user, `openid ${resource.identifier}:read`);
    await context.close();
    await page.goto(userUrl(user.id, "permissions"));
    await page.locator("#permissionsTable").getByRole("button", { name: `Remove ${resource.identifier}:read`, exact: true }).click();
    await page.locator("#btnSave").click();
    await expect(page.getByText("Permissions saved.")).toBeVisible();
    expectTokenError(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string }), "invalid_grant");
  });
});

test("an offline refresh token unused for longer than the client's idle timeout is refused (section 4.14.2 SHOULD)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  test.setTimeout(120_000);
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#refreshTokenOfflineIdleTimeoutInSeconds").fill("20");
  await page.locator("#refreshTokenOfflineMaxLifetimeInSeconds").fill("3600");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Token settings saved.")).toBeVisible();
  const token = asClient(request, { identifier: client.identifier, secret });

  const { context, tokens } = await signInForTokens(browser, request, { identifier: client.identifier, secret }, user, "openid offline_access");
  await context.close();
  // Used within the timeout, it refreshes, and the new one starts the clock again.
  const used = await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string });
  expectTokenResponse(used);

  await new Promise((resolve) => setTimeout(resolve, 25_000));
  // Its exp is the idle timeout, so it is refused as expired.
  const idle = await token({ grant_type: "refresh_token", refresh_token: used.body.refresh_token as string });
  expectTokenError(idle, "invalid_grant");
  expect(idle.body.error_description).toBe("The refresh token is invalid because it has expired.");
});

test("signing out at the auth server, or a new password, ends the user's refresh tokens (section 4.14.2 MAY)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const token = asClient(request, { identifier: client.identifier, secret });

  await test.step("signed out", async () => {
    const { context, tokens } = await signInForTokens(browser, request, { identifier: client.identifier, secret }, user);
    const tab = await context.newPage();
    await tab.goto(`${env.authUrl}/auth/logout?${new URLSearchParams({ id_token_hint: tokens.id_token as string })}`);
    await expect(tab.getByRole("heading", { name: "Signed out" })).toBeVisible();
    await context.close();
    expectTokenError(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string }), "invalid_grant");
  });

  await test.step("password changed", async () => {
    const { context, tokens } = await signInForTokens(browser, request, { identifier: client.identifier, secret }, user);
    await context.close();
    await page.goto(userUrl(user.id, "authentication"));
    await page.locator('input[name="newPassword"]').fill("a-brand-new-password");
    await page.locator("#btnSave").click();
    await expect(page.getByText("Changes saved.")).toBeVisible();
    expectTokenError(await token({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string }), "invalid_grant");
  });
});
