// A client's settings followed into real sign-ins: its own flow switches over the global ones, what
// the consent screen shows of it, the ACR level it asks for, and the administrative scopes allowance.
import { createHash, randomBytes } from "node:crypto";
import type { Page } from "@playwright/test";
import { clientUrl, confirmDialog, enablePasswordGrant, readClientSecret, saveAndExpectSaved, userUrl } from "../../../lib/admin-console";
import { authorizeAndLand, openSignIn, redirectParams, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { codeToken, jwtClaims, passwordToken } from "../../../lib/oauth";
import { browserSignInClient } from "../../../lib/test-clients";
import { freshTotp } from "../../../lib/totp";

async function setFlow(page: Page, clientId: number, name: "ropcEnabled" | "implicitGrantEnabled" | "pkceRequired", value: "on" | "off" | "global") {
  await page.goto(clientUrl(clientId, "oauth2-flows"));
  await page.locator(`input[name="${name}"][value="${value}"]`).check();
  await saveAndExpectSaved(page, "OAuth2 flows saved.");
}

// Saves the client's settings after edit, whose changes the page saves without asking first.
async function saveClientSettings(page: Page, clientId: number, edit: () => Promise<void>) {
  await page.goto(clientUrl(clientId, "settings"));
  await edit();
  await saveAndExpectSaved(page, "Settings saved.");
}

test("the client's own password grant switch wins over the global one, both ways", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
  const grant = () => passwordToken(request, client.identifier, secret, user.email, user.password, "openid");

  await setFlow(page, client.id, "ropcEnabled", "on");
  expect((await grant()).status).toBe(200);
  await setFlow(page, client.id, "ropcEnabled", "off");
  expect((await grant()).body.error).toBe("unauthorized_client");
});

test("the client's own implicit switch turns the implicit flow on for it alone", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const implicit = () =>
    authorizeAndLand(browser, { client_id: client.identifier, response_type: "token", scope: "openid", state: "s" }, user);

  await setFlow(page, client.id, "implicitGrantEnabled", "on");
  const params = redirectParams(await implicit());
  expect(params.get("access_token"), params.toString()).toBeTruthy();
  expect(params.get("state")).toBe("s");

  await setFlow(page, client.id, "implicitGrantEnabled", "off");
  expect(redirectParams(await implicit()).get("error")).toBe("unauthorized_client");
});

test("the client's own PKCE switch lets it leave PKCE out while the global setting requires it", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await setFlow(page, client.id, "pkceRequired", "off");
  const params = redirectParams(
    await authorizeAndLand(browser, { client_id: client.identifier, response_type: "code", scope: "openid", state: "s" }, user),
  );
  const code = params.get("code");
  expect(code, params.toString()).toBeTruthy();
  // Redeemed with no verifier at all.
  const basic = Buffer.from(`${client.identifier}:${secret}`).toString("base64");
  const response = await request.post(`${env.authUrl}/auth/token`, {
    form: { grant_type: "authorization_code", code: code!, redirect_uri: testRedirectUri },
    headers: { Authorization: `Basic ${basic}` },
    failOnStatusCode: false,
  });
  expect(response.status(), await response.text()).toBe(200);
});

test("the consent screen shows the client's logo, name, description and website only where told to", async ({ page, browser, clients, users }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const consentPage = async () => {
    const attempt = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    await submitPassword(attempt.page, user.email, user.password);
    await expect(attempt.page).toHaveURL(/\/auth\/consent/);
    return attempt;
  };
  const shown = ["showLogo", "showDisplayName", "showDescription", "showWebsiteUrl"];

  // A logo to show, uploaded on the Logo tab.
  await page.goto(clientUrl(client.id, "logo"));
  await page.locator("#imageUploadInput").setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: solidPng(64, 64, [30, 120, 200]) });
  await page.getByRole("button", { name: "Save logo" }).click();
  await expect(page.locator("#imageUploadStatus")).toContainText("Logo saved.");

  await saveClientSettings(page, client.id, async () => {
    await page.locator('input[name="displayName"]').fill("Acme Reports");
    await page.locator('input[name="description"]').fill("Monthly sales reports");
    await page.locator('input[name="websiteUrl"]').fill("https://reports.example.com");
    for (const name of shown) await page.locator(`input[name="${name}"]`).check();
  });
  let attempt = await consentPage();
  await expect(attempt.page.locator("img.auth-client-logo")).toBeVisible();
  await expect(attempt.page.getByText("Acme Reports")).toBeVisible();
  await expect(attempt.page.getByText("Monthly sales reports")).toBeVisible();
  await expect(attempt.page.getByRole("link", { name: "https://reports.example.com" })).toBeVisible();
  await attempt.context.close();

  await saveClientSettings(page, client.id, async () => {
    for (const name of shown) await page.locator(`input[name="${name}"]`).uncheck();
  });
  attempt = await consentPage();
  await expect(attempt.page.locator("img.auth-client-logo")).toHaveCount(0);
  await expect(attempt.page.getByText("Acme Reports")).toHaveCount(0);
  await expect(attempt.page.getByText("Monthly sales reports")).toHaveCount(0);
  await expect(attempt.page.getByRole("link", { name: "https://reports.example.com" })).toHaveCount(0);
  await attempt.context.close();
});

test("a client requiring ACR level 2 mandatory makes a user without an authenticator enrol one, and shows its recovery codes once", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  await saveClientSettings(page, client.id, async () => {
    await page.locator('select[name="defaultAcrLevel"]').selectOption("urn:goiabada:level2_mandatory");
  });

  const verifier = randomBytes(32).toString("base64url");
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const signIn = await context.newPage();
  await signIn.goto(
    `${env.authUrl}/auth/authorize?${new URLSearchParams({
      client_id: client.identifier,
      redirect_uri: testRedirectUri,
      response_type: "code",
      scope: "openid",
      state: "s",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256",
    })}`,
  );
  await submitPassword(signIn, user.email, user.password);
  // The enrolment page: a QR code and the secret, then a code from it.
  await expect(signIn).toHaveURL(/\/auth\/otp/);
  const secretKey = (await signIn.locator("#otp-secret").innerText()).trim();
  await signIn.locator('input[name="otp"]').fill(await freshTotp(secretKey));
  await signIn.getByRole("button", { name: "Verify" }).click();
  // The page after the code shows the ten recovery codes the authenticator came with, once: a reload
  // says they were already shown, with the same Continue (#257 decision 14).
  await expect(signIn).toHaveURL(/\/auth\/recovery-codes/);
  const codes = signIn.getByRole("list", { name: "Recovery codes" }).getByRole("listitem");
  await expect(codes).toHaveCount(10);
  const shown = (await codes.allInnerTexts()).map((c) => c.trim());
  for (const c of shown) expect(c).toMatch(/^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$/);
  await signIn.reload();
  await expect(signIn.getByRole("heading", { name: "Your recovery codes were already shown" })).toBeVisible();
  await expect(signIn.getByRole("list", { name: "Recovery codes" })).toHaveCount(0);
  for (const c of shown) await expect(signIn.getByText(c)).toHaveCount(0);
  await signIn.getByRole("button", { name: "Continue" }).click();
  await signIn.waitForURL((url) => url.href.startsWith(testRedirectUri));
  const code = new URL(signIn.url()).searchParams.get("code")!;
  await context.close();

  const tokens = await codeToken(request, client.identifier, secret, code, verifier, testRedirectUri);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  const id = jwtClaims(tokens.body.id_token as string);
  expect(id.acr).toBe("urn:goiabada:level2_mandatory");
  expect(id.amr).toEqual(["pwd", "otp"]);

  // The administrator sees the authenticator the user just enrolled.
  await page.goto(userUrl(user.id, "authentication"));
  await expect(page.locator('input[name="otpEnabled"]')).toBeChecked();
});

test("allowing the administrative scopes asks first, and lets the client take them for an administrator", async ({
  page,
  request,
  clients,
}) => {
  const client = await clients.create();
  await enablePasswordGrant(page, client.id);
  const secret = await readClientSecret(page, client.id);
  const adminGrant = () => passwordToken(request, client.identifier, secret, env.adminEmail, env.adminPassword, "openid authserver:manage");

  let answer = await adminGrant();
  expect(answer.body.error, JSON.stringify(answer.body)).toBe("invalid_scope");

  await page.goto(clientUrl(client.id, "settings"));
  await page.locator("#administrativeScopesAllowed").check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're allowing the client to request the administrative scopes");
  await expect(page.getByText("Settings saved.")).toBeVisible();
  await expect(page.locator("#administrativeScopesAllowed")).toBeChecked();

  answer = await adminGrant();
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  expect(String(jwtClaims(answer.body.access_token as string).scope).split(" ")).toContain("authserver:manage");
});
