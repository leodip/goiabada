// Refresh tokens that outlive the session: the offline_access scope, which always asks the user, and
// which ending the session doesn't reach (Ending sessions, "What it doesn't reach").
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

test("offline_access asks for consent, and its refresh token keeps working after the whole session ends", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser, `testapp-offline-${user.id}`);
  await signInToWebApp(app, testapp.web, user, { scope: "openid email offline_access" });
  await expect(app).toHaveURL(/\/auth\/consent/);
  await expect(app.getByText(/offline/i).first()).toBeVisible();
  await app.getByRole("button", { name: "Give consent" }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed in");
  expect(String((await resultBody(app)).scope).split(" ")).toContain("offline_access");

  // The second site ends the whole session: no hint, confirmed.
  await signInToWebApp(app, testapp.web2, user);
  await expectResult(app, "Signed in");
  await app.getByRole("button", { name: "Sign out with no id_token_hint" }).click();
  await app.getByRole("button", { name: "Yes" }).click();
  await app.waitForURL(testapp.web2.url);
  await expectResult(app, "Signed out");

  await app.goto(testapp.web.url);
  await app.getByRole("button", { name: "Refresh the tokens" }).click();
  await expectResult(app, "Refreshed");
  // The refreshed access token names no session, so /userinfo goes on accepting it.
  await app.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(app, "/userinfo answered");
  // Consent for offline access is asked every time.
  await signInToWebApp(app, testapp.web, user, { scope: "openid email offline_access" });
  await expect(app).toHaveURL(/\/auth\/consent/);
  await context.close();
});
