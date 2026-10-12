// Add sign-in to a web app, and Protect an API, through the test app's confidential web app: what the
// guides tell a developer to build, working against the real auth server.
import { grantUserPermission } from "../../lib/admin-console";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, shownClaims, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

test("a user signs in to the web app, which reads their claims, calls /userinfo and calls the API", async ({ page, browser, users }) => {
  const user = await users.create();
  await grantUserPermission(page, user.id, testapp.api.resource, "read");
  const { context, page: app } = await userBrowser(browser);

  await app.goto(testapp.web.url);
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();
  await app.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(app).toHaveURL(/\/auth\/pwd/);
  await submitPassword(app, user.email, user.password);
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed in");
  const signedIn = await resultBody(app);
  expect(String(signedIn.scope).split(" ")).toEqual(expect.arrayContaining(["openid", "email", "profile", testapp.api.scope]));
  expect(signedIn.refresh_token).toBe("received");

  // openid-client checked the ID token's signature, issuer, audience and nonce before the app kept it.
  const id = await shownClaims(app, "ID token claims");
  expect(id.email).toBe(user.email);
  expect(id.aud).toBe(testapp.web.clientId);
  // A new client's level is 2 optional, as the guide's example ID token shows: a user with no
  // authenticator signs in with the password alone.
  expect(id.acr).toBe("urn:goiabada:level2_optional");
  expect(id.amr).toEqual(["pwd"]);
  await expect(app.getByText("Entered a one-time code: no")).toBeVisible();
  const access = await shownClaims(app, "Access token claims");
  expect(access.sub).toBe(id.sub);
  expect(access.aud).toContain(testapp.api.resource);
  await expect(app.getByText(`As ${id.sub} (${user.email}).`)).toBeVisible();

  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo answered");
  const info = await resultBody(app);
  expect(info.sub).toBe(id.sub);
  expect(info.email).toBe(user.email);
  expect(info.given_name).toBe("Playwright");
  // profile is the page where the user manages their profile, the admin console's, in both places.
  const profilePage = `${env.adminUrl}/account/profile`;
  expect(id.profile).toBe(profilePage);
  expect(info.profile).toBe(profilePage);

  await app.getByRole("button", { name: "Call the API" }).click();
  await expectResult(app, "The API answered 200");
  const api = await resultBody(app);
  expect((api.body as Record<string, unknown>).caller).toBe(id.sub);

  // And it opens: the user's session signs them in to the admin console, at their own profile.
  await app.goto(profilePage);
  await app.waitForURL(profilePage);
  await expect(app.locator('input[name="givenName"]')).toHaveValue("Playwright");
  await context.close();
});

test("without the API's permission the user still signs in, but the token isn't for the API and the API refuses it", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);

  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  expect(String((await resultBody(app)).scope).split(" ")).not.toContain(testapp.api.scope);
  const access = await shownClaims(app, "Access token claims");
  expect([access.aud].flat()).not.toContain(testapp.api.resource);
  expect(String(access.scope).split(" ")).not.toContain(testapp.api.scope);

  await app.getByRole("button", { name: "Call the API" }).click();
  await expectResult(app, /^The API answered 40[13]$/);
  await context.close();
});

test("the web app refreshes its tokens, and each refresh hands back a new refresh token", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  const before = await shownClaims(app, "Access token claims");

  for (let i = 0; i < 2; i++) {
    await app.getByRole("button", { name: "Refresh the tokens" }).click();
    await expectResult(app, "Refreshed");
    expect((await resultBody(app)).new_refresh_token).toBe("received");
  }
  const after = await shownClaims(app, "Access token claims");
  expect(after.sub).toBe(before.sub);
  expect(after.jti).not.toBe(before.jti);
  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo answered");
  await context.close();
});
