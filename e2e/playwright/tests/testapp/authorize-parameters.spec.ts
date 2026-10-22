// The authorization parameters a client sends to ask for more than single sign-on gives by default,
// from the test app's web app sign-in form: prompt, max_age, id_token_hint and acr_values (Require
// two-factor authentication). The consent screen prompt=consent shows is answered every way a user
// can: allowed, not allowed, and allowed with a scope unticked.
import { expect, test } from "../../lib/fixtures";
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
  await signInToWebApp(app, testapp.web, alice);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web, alice, { id_token_hint: "yes" })).askedForPassword).toBe(false);
  await expectResult(app, "Signed in");

  // Bob signs in on the second site in the same browser, so the browser's session is now his, while
  // the first site still holds Alice's ID token.
  expect((await signInToWebApp(app, testapp.web2, bob, { prompt: "login" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  expect((await signInToWebApp(app, testapp.web, alice, { id_token_hint: "yes" })).askedForPassword).toBe(true);
  await expectResult(app, "Signed in");
  expect((await shownClaims(app, "ID token claims")).email).toBe(alice.email);
  await context.close();
});

test("a sign-in by someone other than the id_token_hint's user is refused with no consent screen, and ends the session the browser held", async ({ browser, users }) => {
  const alice = await users.create();
  const bob = await users.create();
  const { context, page: app } = await userBrowser(browser);
  await signInToWebApp(app, testapp.web, alice);
  await expectResult(app, "Signed in");

  // With prompt=login the hint naming Alice asks for a password over her session, and Bob enters his.
  const visited: string[] = [];
  app.on("framenavigated", (frame) => {
    if (frame === app.mainFrame()) visited.push(new URL(frame.url()).pathname);
  });
  expect((await signInToWebApp(app, testapp.web, bob, { id_token_hint: "yes", prompt: "login" })).askedForPassword).toBe(true);
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
  // The enrolment page: a QR code and its key, then a code from it.
  await expect(app).toHaveURL(/\/auth\/otp/);
  const secret = (await app.locator("#otp-secret").innerText()).trim();
  await app.locator('input[name="otp"]').fill(await freshTotp(secret));
  await app.getByRole("button", { name: "Verify" }).click();
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
