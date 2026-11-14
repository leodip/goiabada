// The authorization parameters a client sends to ask for more than single sign-on gives by default,
// from the test app's web app sign-in form: prompt, max_age, id_token_hint and acr_values (Require
// two-factor authentication). The consent screen prompt=consent shows is answered every way a user
// can: allowed, not allowed, and allowed with a scope unticked. Last, Goiabada's own
// goiabada_safe_mode on a test client's sign-in, which the test app's form does not send.
import type { Page } from "@playwright/test";
import { setClientBrand } from "../../lib/admin-console";
import { pageToken, saveCustomCss, warmBasicPalette, withCustomBrand } from "../../lib/brands";
import { continuePastRecoveryCodes, openSignIn, submitPassword } from "../../lib/browser-sign-in";
import { enterRecoveryCode, turnOnTwoFactor } from "../../lib/console-user";
import { expect, test } from "../../lib/fixtures";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";
import { expectResult, resultBody, shownClaims, signInToWebApp, testapp, userBrowser } from "../../lib/testapp";

const second = () => new Promise((resolve) => setTimeout(resolve, 1_100));

test("prompt=login asks for the password over a session, and the new tokens say when", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  const first = await shownClaims(app, "ID token claims");
  await second();

  expect((await signInToWebApp(app, testapp.web, user, { prompt: "login" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  const again = await shownClaims(app, "ID token claims");
  expect(again.sub).toBe(first.sub);
  expect(Number(again.auth_time)).toBeGreaterThan(Number(first.auth_time));
  await context.close();
});

test("max_age asks for the password again once the sign-in is older than it", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user);
  await second();

  expect((await signInToWebApp(app, testapp.web, user, { max_age: "3600" })).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web, user, { max_age: "1" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  await context.close();
});

test("prompt=consent shows the consent screen even when the client doesn't require it", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user, { prompt: "consent" });
  await expect(app).toHaveURL(/\/auth\/consent/);
  await app.getByRole("button", { name: "Allow", exact: true }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed in");
  await context.close();
});

test("Don't allow on the consent screen sends the user back to the app with access_denied, signed in to nothing", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user, { prompt: "consent" });
  await expect(app).toHaveURL(/\/auth\/consent/);
  await app.getByRole("button", { name: "Don't allow" }).click();
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Sign-in failed");
  expect(await resultBody(app)).toMatchObject({ error: "access_denied", error_description: "The user did not provide consent" });
  await expect(app.getByText("Not signed in to this app.")).toBeVisible();
  await context.close();
});

test("an id_token_hint naming the signed-in user signs in silently; naming someone else asks for the password", async ({ browser, users }) => {
  const alice = await users.create();
  const bob = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web3, alice);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web3, alice, { id_token_hint: "yes" })).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");

  // Bob signs in on the second site in the same browser, so the browser's session is now his, while
  // the first site still holds Alice's ID token: it's the web app with no back-channel logout URI, so
  // it isn't told her session ended.
  expect((await signInToWebApp(app, testapp.web2, bob, { prompt: "login" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web3, alice, { id_token_hint: "yes" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  expect((await shownClaims(app, "ID token claims")).email).toBe(alice.email);
  await context.close();
});

test("a sign-in by someone other than the id_token_hint's user is refused with no consent screen, and ends the session the browser held", async ({ browser, users }) => {
  const alice = await users.create();
  const bob = await users.create();
  const { context, page: app } = await userBrowser(browser);
  // The third web app, which registered no back-channel logout URI. Ending Alice's session would send
  // the first web app a logout token, which can land between the refused callback and the page after
  // it, and replace the outcome the test reads with "Signed out by the auth server".
  await signInToWebApp(app, testapp.web3, alice);
  await expectResult(app, "Signed in");

  // With prompt=login the hint naming Alice asks for a password over her session, and Bob enters his.
  const visited: string[] = [];
  app.on("framenavigated", (frame) => {
    if (frame === app.mainFrame()) visited.push(new URL(frame.url()).pathname);
  });
  expect((await signInToWebApp(app, testapp.web3, bob, { id_token_hint: "yes", prompt: "login" })).askedForPassword).toBe(true);
  await expectResult(app, "Sign-in failed");
  const refusal = await resultBody(app);
  expect(refusal.error).toBe("login_required");
  expect(refusal.error_description).toBe("The authenticated user does not match the id_token_hint");
  expect(visited).not.toContain("/auth/consent");

  // The browser changed hands, so Alice's session is gone and Bob was given none: the second site
  // asks for a password rather than signing anyone in as Alice.
  expect((await signInToWebApp(app, testapp.web2, bob)).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  expect((await shownClaims(app, "ID token claims")).email).toBe(bob.email);
  await context.close();
});

test("acr_values level 2 mandatory makes a user enrol an authenticator, and the tokens say a code was entered", async ({ browser, users }) => {
  const user = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user, { acr_values: "urn:goiabada:level2_mandatory" });
  // The enrolment page: a QR code and its key, then a code from it, then the page showing the new
  // authenticator's recovery codes, whose Continue goes on to the app.
  await expect(app).toHaveURL(/\/auth\/otp/);
  const secret = (await app.locator("#otp-secret").innerText()).trim();
  await app.locator('input[name="otp"]').fill(await freshTotp(secret));
  await app.getByRole("button", { name: "Verify" }).click();
  await continuePastRecoveryCodes(app);
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed in");
  const id = await shownClaims(app, "ID token claims");
  expect(id.acr).toBe("urn:goiabada:level2_mandatory");
  expect(id.amr).toEqual(["pwd", "otp"]);
  await expect(app.getByText("Entered a one-time code: yes")).toBeVisible();

  // Signing in again over the session keeps the level it reached, without asking for anything.
  expect((await signInToWebApp(app, testapp.web, user)).askedForPassword).toBe(false);
  expect((await shownClaims(app, "ID token claims")).acr).toBe("urn:goiabada:level2_mandatory");

  // A new sign-in at the client's level, now the user has an authenticator, asks for its code.
  await signInToWebApp(app, testapp.web, user, { prompt: "login" });
  await expect(app).toHaveURL(/\/auth\/otp/);
  await app.locator('input[name="otp"]').fill(await freshTotp(secret));
  await app.getByRole("button", { name: "Verify" }).click();
  await app.waitForURL(testapp.web.url);
  const stepped = await shownClaims(app, "ID token claims");
  expect(stepped.acr).toBe("urn:goiabada:level2_optional");
  expect(stepped.amr).toEqual(["pwd", "otp"]);
  await context.close();
});

test("a level 2 mandatory sign-in with a recovery code says so in amr, at the level a code reaches", async ({ browser, users }) => {
  const user = await users.create();
  const { recoveryCodes } = await turnOnTwoFactor(browser, user);
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, user, { acr_values: "urn:goiabada:level2_mandatory" });
  await enterRecoveryCode(app, recoveryCodes[3]);
  await app.waitForURL(testapp.web.url);
  await expectResult(app, "Signed in");
  for (const heading of ["ID token claims", "Access token claims"] as const) {
    const claims = await shownClaims(app, heading);
    expect(claims.acr).toBe("urn:goiabada:level2_mandatory");
    expect(claims.amr).toEqual(["pwd", "recovery_code"]);
  }
  await context.close();
});

// goiabada_safe_mode=true draws a sign-in without what an administrator authors freely (#816): the
// brand's custom CSS is not drawn and Blueberry's colors take its custom palette's place, on every
// page of that sign-in, the password page answering a wrong password included. The same client's
// sign-in without it is drawn in the brand as saved.
test("goiabada_safe_mode=true draws a sign-in without the brand's custom CSS and custom palette, and no other sign-in", async ({
  page,
  browser,
  clients,
}) => {
  const outlined = "rgb(18, 52, 86)";
  const cardOutline = (signIn: Page) =>
    signIn.locator(".auth-card").first().evaluate((card) => getComputedStyle(card).outlineColor);
  const { client } = await browserSignInClient(page, clients);
  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await saveCustomCss(page, brand.id, `.auth-card {\n  outline: 6px solid ${outlined};\n}\n`);
    await setClientBrand(page, client.id, brand);

    const safe = await openSignIn(browser, { clientId: client.identifier, scope: "openid", params: { goiabada_safe_mode: "true" } });
    try {
      await expect(safe.page).toHaveURL(/\/auth\/pwd/);
      await expect(safe.page.locator('link[rel="stylesheet"][href*="/safe-stylesheet.css"]')).toHaveCount(1);
      expect(await cardOutline(safe.page)).not.toBe(outlined);
      expect(await pageToken(safe.page, "canvas"), "Blueberry's canvas").toBe("#f4f5f7");

      await submitPassword(safe.page, "nobody@example.com", "not-the-password");
      await expect(safe.page).toHaveURL(/\/auth\/pwd/);
      await expect(safe.page.locator('link[rel="stylesheet"][href*="/safe-stylesheet.css"]')).toHaveCount(1);
      expect(await cardOutline(safe.page)).not.toBe(outlined);
    } finally {
      await safe.context.close();
    }

    const usual = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      await expect(usual.page).toHaveURL(/\/auth\/pwd/);
      await expect(usual.page.locator('link[rel="stylesheet"][href*="/safe-stylesheet.css"]')).toHaveCount(0);
      expect(await cardOutline(usual.page)).toBe(outlined);
      expect(await pageToken(usual.page, "canvas")).toBe(warmBasicPalette.light.canvas);
    } finally {
      await usual.context.close();
    }
  });
});
