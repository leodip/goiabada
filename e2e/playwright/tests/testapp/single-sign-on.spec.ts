// Single sign-on across clients, with the test app's two web apps on two sites: e2e-webtest1 and
// e2e-webtest2, each a confidential client of its own.
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, shownClaims, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

test("signed in on the first site, the user signs in to the second without the password, as the same user", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);

  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  const first = await shownClaims(app, "ID token claims");

  expect((await signInToWebApp(app, testapp.web2, user)).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");
  const second = await shownClaims(app, "ID token claims");
  expect(second.sub).toBe(first.sub);
  expect(second.aud).toBe(testapp.web2.clientId);
  expect(second.sid).toBe(first.sid);
  // The second site's token says how the user authenticated, which was at the first sign-in.
  expect(second.auth_time).toBe(first.auth_time);
  expect(second.amr).toEqual(first.amr);
  await context.close();
});

test("prompt=none signs in silently over a session, and answers login_required with none", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);

  await signInToWebApp(app, testapp.web2, user, { prompt: "none" });
  await expectResult(app, "Sign-in failed");
  expect((await resultBody(app)).error).toBe("login_required");

  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web2, user, { prompt: "none" })).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");
  await context.close();
});

// Sign users out, "What a sign-out ends": with the ID token as its hint, a sign-out ends the app's part
// of the session, and the session goes on for the other apps that share it.
test("signing out on one site with the ID token leaves the other site signed in, though this browser signs in afresh", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web2.url);
  await expectResult(app, "Signed out");

  // The first site's tokens still come from a live session.
  await app.goto(testapp.web.url);
  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo answered");
  await app.getByRole("button", { name: "Refresh the tokens" }).click();
  await expectResult(app, "Refreshed");
  // The browser's session cookie was cleared all the same.
  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});

// With no hint, the user is asked, and the whole session ends, every app's part of it: /userinfo
// refuses the tokens it handed out, and their refresh tokens stop working.
test("signing out on one site with no ID token ends the other site's part too", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");

  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  // The auth server's confirmation, whose Sign out shares its name with the app's own button.
  await expect(app.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web2.url);
  await expectResult(app, "Signed out");

  await app.goto(testapp.web.url);
  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo failed");
  await app.getByRole("button", { name: "Refresh the tokens" }).click();
  await expectResult(app, "Refresh failed");
  expect((await resultBody(app)).error).toBe("invalid_grant");
  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(true);
  await context.close();
});
