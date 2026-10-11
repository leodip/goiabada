// Sign users out, through the test app's web app: RP-initiated logout with and without the ID token,
// and the difference between ending the app's session and ending the auth server's.
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

test("signing out with the ID token returns to the app with its state, and the next sign-in asks for the password", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser, `testapp-signout-${user.id}`);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed out");
  const body = await resultBody(app);
  expect(body.state).toBe("matches the one sent");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  await context.close();
});

test("signing out with no ID token asks first, then ends the session", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser, `testapp-signout-nohint-${user.id}`);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  await expect(app.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  expect(new URL(app.url()).origin).toBe(env.authUrl);
  await app.getByRole("button", { name: "Yes" }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed out");
  expect((await resultBody(app)).state).toBe("matches the one sent");

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});

test("forgetting only the app's session leaves the auth server's: signing in again asks for nothing", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser, `testapp-forget-${user.id}`);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Forget this app's session only" }).click();
  await expectResult(app, "Forgot this app's session");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");
  await context.close();
});

// Logout, "Where the user lands": with no hint, the post-logout redirect URI is honoured only beside the
// client_id it is registered on. Without one the sign-out still happens.
test("signing out with no ID token and no client_id signs out, but leaves the user on the auth server's page", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser, `testapp-signout-noclient-${user.id}`);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");

  await app.goto(`${env.authUrl}/auth/logout?${new URLSearchParams({ post_logout_redirect_uri: `${testapp.web.url}/signed-out`, state: "s" })}`);
  await app.getByRole("button", { name: "Yes" }).click();
  await expect(app.getByRole("heading", { name: "Signed out" })).toBeVisible();
  await expect(app.getByText("We could not return you to the application that signed you out.")).toBeVisible();
  expect(new URL(app.url()).origin).toBe(env.authUrl);

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});
