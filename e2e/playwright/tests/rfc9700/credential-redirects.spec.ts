// RFC 9700 section 4.12. A browser follows a 307 with the same method and body, so a POST carrying the
// user's password, redirected with 307, hands the password to wherever the redirect points. The auth
// server MUST NOT redirect such a POST with 307, and SHOULD use 303, the one status that requires the
// browser to follow with a GET. These record the status of each POST of the sign-in: the password,
// the one-time code (at enrolment, which is the same handler as at verification), the consent screen,
// which answers the client itself on a cancel, and a password reset.
import type { APIRequestContext, Browser, Page } from "@playwright/test";
import { clientUrl } from "../../lib/admin-console";
import { submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, type TestClient, type TestUser, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { authorizeEndpoint, codeRequest, emptyBrowser } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";

// The status of the POST to path that submit sends from tab, before any redirect is followed.
async function postStatus(tab: Page, path: string, submit: () => Promise<unknown>): Promise<number> {
  const [response] = await Promise.all([
    tab.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === path),
    submit(),
  ]);
  return response.status();
}

// Signs a new user in through a client requiring consent, made to require a one-time code too, so the
// user enrols one, approves the consent screen, then cancels it on a second request, and resets their
// password. Returns the status each POST was answered with.
async function signInPostStatuses(page: Page, browser: Browser, request: APIRequestContext, client: TestClient, user: TestUser) {
  await page.goto(clientUrl(client.id, "settings"));
  await page.locator('select[name="defaultAcrLevel"]').selectOption("urn:goiabada:level2_mandatory");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client settings saved successfully")).toBeVisible();

  const statuses: Record<string, number> = {};
  const context = await emptyBrowser(browser);
  const tab = await context.newPage();
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier).params)}`);
  statuses.password = await postStatus(tab, "/auth/pwd", () => submitPassword(tab, user.email, user.password));

  await expect(tab).toHaveURL(/\/auth\/otp/);
  await tab.locator('input[name="otp"]').fill(await freshTotp((await tab.locator("pre").innerText()).trim()));
  statuses.otp = await postStatus(tab, "/auth/otp", () => tab.getByRole("button", { name: "Verify" }).click());

  await expect(tab).toHaveURL(/\/auth\/consent/);
  statuses.consentGiven = await postStatus(tab, "/auth/consent", () => tab.getByRole("button", { name: "Give consent" }).click());
  await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));

  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier, { prompt: "consent" }).params)}`);
  await expect(tab).toHaveURL(/\/auth\/consent/);
  statuses.consentCancelled = await postStatus(tab, "/auth/consent", () => tab.getByRole("button", { name: "Cancel consent" }).click());
  await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));

  await context.close();

  // A browser with no session, as someone who forgot their password has.
  const signedOut = await emptyBrowser(browser);
  const reset = await signedOut.newPage();
  await reset.goto(`${env.authUrl}/forgot-password`);
  await reset.locator('input[name="email"]').fill(user.email);
  await reset.getByRole("button", { name: "Send password reset link" }).click();
  await expect(reset.getByText("If you're a registered user, a password reset link has been sent")).toBeVisible();
  const link = linksIn(await waitForMail(request, user.email)).find((l) => l.startsWith(env.authUrl))!;
  await reset.goto(link);
  await reset.locator('input[name="password"]').fill("a-reset-password");
  await reset.locator('input[name="passwordConfirmation"]').fill("a-reset-password");
  statuses.passwordReset = await postStatus(reset, new URL(link).pathname, () => reset.getByRole("button", { name: "Set my password" }).click());
  await expect(reset.getByText("Your password has been successfully set.")).toBeVisible();
  await signedOut.close();

  return statuses;
}

test("no POST of the sign-in is redirected with 307 or 308, so no password is sent on (section 4.12 MUST NOT)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create({ emailVerified: true });
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  const statuses = await signInPostStatuses(page, browser, request, client, user);
  for (const [post, status] of Object.entries(statuses)) {
    expect([307, 308], `${post} answered ${status}`).not.toContain(status);
  }
});

test("every POST of the sign-in, the password, the one-time code and the consent approved or cancelled, is redirected with 303 (section 4.12 SHOULD)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const user = await users.create({ emailVerified: true });
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });
  // The password reset answers its page itself, redirecting nowhere. The cancelled consent answers the
  // client itself, with access_denied, and carries no credential; it is a 303 all the same, since one
  // rule, a POST is answered with 303, is what the docs state.
  const { password, otp, consentGiven, consentCancelled } = await signInPostStatuses(page, browser, request, client, user);
  expect({ password, otp, consentGiven, consentCancelled }).toEqual({ password: 303, otp: 303, consentGiven: 303, consentCancelled: 303 });
});
