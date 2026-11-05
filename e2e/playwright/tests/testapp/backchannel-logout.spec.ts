// OpenID Connect Back-Channel Logout 1.0, through the test app's two web apps. Each registered its
// /<app>/backchannel-logout route as its back-channel logout URI, as Sign users out, "Get told when a
// session ends", says, and the route checks each logout token as the guide says, ends the app's own
// sessions the token names and answers 200. Each test drives a real end of the user's session and
// watches the app sign the user out, from the tokens it shows it accepted for this browser's user.
import { confirmDialog, userUrl } from "../../lib/admin-console";
import { signInToConsole } from "../../lib/console-user";
import { expect, test } from "../../lib/fixtures";
import {
  expectResult,
  receivedLogoutTokens,
  shownClaims,
  signInToWebApp,
  testapp,
  userBrowser,
  waitForLogoutTokens,
  type WebApp,
} from "../../lib/testapp";

// Two sign-ins and a delivery the auth server may retry 15 seconds later take longer than the
// default.
test.describe.configure({ timeout: 120_000 });

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";

// A logout token to app about the user and, when session is "named", the session the ID token came
// from (Back-Channel Logout 1.0 section 2.4, #784 decisions 3 and 4).
function expectLogoutToken(token: Record<string, unknown>, app: WebApp, idToken: Record<string, unknown>, session: "named" | "none") {
  expect(token.iss).toBe(idToken.iss);
  expect(token.aud).toBe(app.clientId);
  expect(token.sub).toBe(idToken.sub);
  if (session === "named") expect(token.sid).toBe(idToken.sid);
  else expect(token).not.toHaveProperty("sid");
  expect(token.events).toEqual({ [logoutEvent]: {} });
  expect(token).not.toHaveProperty("nonce");
  expect(typeof token.jti).toBe("string");
  expect(Number(token.exp) - Number(token.iat)).toBe(120);
}

test("ending the session under Account tells the app, which signs the user out", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  const idToken = await shownClaims(app, "ID token claims");

  // The user ends the app's session from another device's Account, Sessions.
  const own = await signInToConsole(browser, user, "/account/sessions");
  const otherRow = own.page.locator("table tbody tr").filter({ hasNotText: "This device" });
  await otherRow.getByRole("button", { name: /^End session/ }).click();
  await confirmDialog(own.page, "including ones that keep working in the background, will need you to sign in again");
  await expect(own.page.locator("#sessions-status")).toHaveText("Session ended.");
  await own.context.close();

  const [token] = await waitForLogoutTokens(app, testapp.web, 1);
  expectLogoutToken(token, testapp.web, idToken, "named");
  await expectResult(app, "Signed out by the auth server");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();
  await context.close();
});

test("signing out with no ID token tells both apps on the session, and the other one signs the user out", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  const webIdToken = await shownClaims(app, "ID token claims");
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");
  const web2IdToken = await shownClaims(app, "ID token claims");

  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  await expect(app.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web2.url);
  await expectResult(app, "Signed out");

  // The app that signed out is told too, though it had already ended its own session.
  const [web2Token] = await waitForLogoutTokens(app, testapp.web2, 1);
  expectLogoutToken(web2Token, testapp.web2, web2IdToken, "named");

  const [webToken] = await waitForLogoutTokens(app, testapp.web, 1);
  expectLogoutToken(webToken, testapp.web, webIdToken, "named");
  await expectResult(app, "Signed out by the auth server");
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();
  await context.close();
});

test("disabling the user tells both apps with a token naming no session, and both sign the user out", async ({ page, browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  const webIdToken = await shownClaims(app, "ID token claims");
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");
  const web2IdToken = await shownClaims(app, "ID token claims");

  await page.goto(userUrl(user.id, "details"));
  await page.locator("#enabledDisabled").uncheck();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're disabling the user, so they won't be able to sign in");
  await expect(page.getByText("Changes saved.")).toBeVisible();

  for (const [web, idToken] of [[testapp.web, webIdToken], [testapp.web2, web2IdToken]] as const) {
    const [token] = await waitForLogoutTokens(app, web, 1);
    expectLogoutToken(token, web, idToken, "none");
    await expectResult(app, "Signed out by the auth server");
    await expect(app.getByText("Not signed in to this app.")).toBeVisible();
  }
  await context.close();
});

test("signing out of one app with its ID token tells that app alone, and the other stays signed in", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await expectResult(app, "Signed in");
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");
  const web2IdToken = await shownClaims(app, "ID token claims");

  await app.getByRole("button", { name: "Sign out", exact: true }).click();
  await app.waitForURL(testapp.web2.url);
  await expectResult(app, "Signed out");

  // Once the app that signed out has been told, the other one would have been too.
  const [token] = await waitForLogoutTokens(app, testapp.web2, 1);
  expectLogoutToken(token, testapp.web2, web2IdToken, "named");

  expect(await receivedLogoutTokens(app, testapp.web)).toEqual([]);
  await expectResult(app, "Signed in");
  await expect(app.getByText("Not signed in to this app.")).toHaveCount(0);
  // Its part of the session is still there.
  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo answered");
  await context.close();
});
