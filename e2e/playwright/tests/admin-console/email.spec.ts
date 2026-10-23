// What the auth server mails, as the environment's Mailpit catches it (lib/mailpit.ts), followed
// through the links and codes in each message. SMTP pointing at Mailpit is part of the baseline the
// setup step restores, and none of these tests changes it.
import type { APIRequestContext, Page } from "@playwright/test";
import { deleteUser } from "../../lib/admin-console";
import { signInToConsole } from "../../lib/console-user";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, mailTo, waitForMail } from "../../lib/mailpit";
import { passwordToken } from "../../lib/oauth";
import { passwordGrantClient } from "../../lib/test-clients";
import { uniqueIdentifier } from "../../lib/unique";

const sendTest = `${env.adminUrl}/admin/settings/email/send-test-email`;
const forgotPassword = `${env.authUrl}/forgot-password`;

// The page every well-formed forgot-password request is answered with, whatever the address leads
// to, so it tells nobody whether the address has an account.
async function expectLinkSent(page: Page, address: string) {
  await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  await expect(page.getByText("If an account uses this address, we've sent it a link to reset your password:")).toBeVisible();
  await expect(page.locator("code.auth-address")).toHaveText(address);
}

// Asks for a password reset link on the forgot password page and returns the link mailed for it.
async function mailedResetLink(page: Page, request: APIRequestContext, address: string): Promise<string> {
  await page.goto(forgotPassword);
  await page.locator("#email").fill(address);
  await page.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expectLinkSent(page, address);
  const mail = await waitForMail(request, address);
  return linksIn(mail).find((l) => l.startsWith(env.authUrl))!;
}

// Sets a password on the form a mailed link opened, which names the account it is for. A link is
// followed once: the form is what it opens.
async function setPasswordOnForm(page: Page, address: string, password: string) {
  await expect(page.getByRole("heading", { name: "Set your password" })).toBeVisible();
  await expect(page.locator("code.auth-address")).toHaveText(address);
  await page.locator("#password").fill(password);
  await page.locator("#passwordConfirmation").fill(password);
  await page.getByRole("button", { name: "Set password", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Password set" })).toBeVisible();
  await expect(page.locator("code.auth-address")).toHaveText(address);
  await expect(page.getByRole("link", { name: "Sign in to your account" })).toHaveAttribute("href", `${env.adminUrl}/account/profile`);
}

test("a test email from Settings - Email arrives", async ({ page, request }) => {
  const to = `${uniqueIdentifier("m")}@example.com`;
  await page.goto(sendTest);
  await expect(page).toHaveTitle(/^Send test email – Email settings – /);
  const tabs = page.getByRole("navigation", { name: "Sections", exact: true });
  await expect(tabs.getByRole("link", { name: "Send test email", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(tabs.getByRole("link", { name: "Configuration", exact: true })).toHaveAttribute("href", "/admin/settings/email");
  await page.locator("#destinationEmail").fill(to);
  await page.getByRole("button", { name: "Send test email", exact: true }).click();
  await expect(page.getByText(`Test email sent to ${to}.`, { exact: true })).toBeVisible();
  const mail = await waitForMail(request, to);
  expect(mail.subject).toBeTruthy();
});

test("a test email to a missing or malformed address is refused at the field, which keeps the address", async ({ page }) => {
  for (const { address, message } of [
    { address: "", message: "Enter the address to send the test email to." },
    { address: "not-an-email", message: "Please enter a valid email address." },
  ]) {
    await page.goto(sendTest);
    await page.locator("#destinationEmail").fill(address);
    await page.locator("#btnSend").click();
    await expect(page).toHaveURL(sendTest);
    await expect(page.locator("#sendtest-error")).toHaveText(message);
    await expect(page.locator("#destinationEmail")).toHaveAttribute("aria-invalid", "true");
    await expect(page.locator("#destinationEmail")).toHaveValue(address);
    await expect(page.getByText(/^Test email sent to/)).toHaveCount(0);
  }
});

test("a user created with an emailed link sets their password through it, and signs in", async ({
  page,
  browser,
  request,
  clients,
}) => {
  // Created by hand, not by the users fixture, to choose the emailed link; deleted below.
  const email = `${uniqueIdentifier("u")}@example.com`;
  await page.goto(`${env.adminUrl}/admin/users/new`);
  await page.locator("#email").fill(email);
  await page.locator("#givenName").fill("Linked");
  await page.locator("#familyName").fill("User");
  await page.locator("#setPasswordTypeEmail").check();
  // No password is set here, so its field goes.
  await expect(page.locator("#password")).toBeHidden();
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
  await expect(page.getByText("User created.", { exact: true })).toBeVisible();
  const id = Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]);

  try {
    const mail = await waitForMail(request, email);
    const link = linksIn(mail).find((l) => l.startsWith(env.authUrl));
    expect(link, mail.text).toBeTruthy();

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const setPassword = await context.newPage();
    await setPassword.goto(link!);
    await setPasswordOnForm(setPassword, email, "a-chosen-password");

    // A link is good once, and the page says how to get another.
    await setPassword.goto(link!);
    await expect(setPassword.getByRole("heading", { name: "This link can't be used" })).toBeVisible();
    await expect(setPassword.getByRole("link", { name: "Request a new link" })).toHaveAttribute("href", "/forgot-password");
    await context.close();

    const { client, secret } = await passwordGrantClient(page, clients);
    expect((await passwordToken(request, client.identifier, secret, email, "a-chosen-password", "openid")).status).toBe(200);
  } finally {
    await deleteUser(page, id);
  }
});

test("forgot password: the emailed link sets a new password, and the old one stops working", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  // A reset link is only ever mailed to a verified address.
  const user = await users.create({ emailVerified: true });
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(`${env.adminUrl}/account/profile`);
  await forgot.getByRole("link", { name: "Forgot your password?" }).click();
  await expect(forgot.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await forgot.locator("#email").fill(user.email);
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expectLinkSent(forgot, user.email);

  const mail = await waitForMail(request, user.email);
  const link = linksIn(mail).find((l) => l.startsWith(env.authUrl))!;
  await forgot.goto(link);
  // The password's rules, under the seeded policy, are said under its field.
  await expect(forgot.locator("#password-rules")).toHaveText(
    "At least 15 characters. A few unrelated words make a long password that's easy to remember. Common passwords, and the account's email address or the app's name, are refused.",
  );
  await setPasswordOnForm(forgot, user.email, "a-reset-password");
  await context.close();

  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await passwordToken(request, client.identifier, secret, user.email, "a-reset-password", "openid")).status).toBe(200);
  expect((await passwordToken(request, client.identifier, secret, user.email, user.password, "openid")).body.error).toBe("invalid_grant");
});

test("the reset form refuses a password too short or not confirmed, and the link still sets one after", async ({
  browser,
  request,
  users,
}) => {
  const user = await users.create({ emailVerified: true });
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const reset = await context.newPage();
  const link = await mailedResetLink(reset, request, user.email);
  await reset.goto(link);
  for (const { password, confirmation, field, message } of [
    { password: "abc", confirmation: "abc", field: "password", message: "Use at least 15 characters for the password." },
    { password: "a-reset-password", confirmation: "another-password", field: "passwordConfirmation", message: "The passwords don't match." },
  ]) {
    await reset.locator("#password").fill(password);
    await reset.locator("#passwordConfirmation").fill(confirmation);
    await reset.getByRole("button", { name: "Set password", exact: true }).click();
    await expect(reset.locator("#reset-error")).toHaveText(message);
    await expect(reset.locator(`#${field}`)).toHaveAttribute("aria-invalid", "true");
  }
  // A refusal costs the link nothing.
  await reset.locator("#password").fill("a-reset-password");
  await reset.locator("#passwordConfirmation").fill("a-reset-password");
  await reset.getByRole("button", { name: "Set password", exact: true }).click();
  await expect(reset.getByRole("heading", { name: "Password set" })).toBeVisible();
  await context.close();
});

test("forgot password refuses a malformed address on the form, which keeps it", async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(forgotPassword);
  await forgot.locator("#email").fill("not-an-email");
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(forgot.locator("#forgot-error")).toHaveText("Please enter a valid email address.");
  await expect(forgot.locator("#email")).toHaveAttribute("aria-invalid", "true");
  await expect(forgot.locator("#email")).toHaveValue("not-an-email");
  await expect(forgot.getByRole("heading", { name: "Check your email" })).toHaveCount(0);
  await context.close();
});

test("forgot password for an address nobody has answers the same, and sends nothing", async ({ browser, request }) => {
  const email = `${uniqueIdentifier("u")}@example.com`;
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(forgotPassword);
  await forgot.locator("#email").fill(email);
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expectLinkSent(forgot, email);
  await context.close();
  // The answer does not tell; neither does the mailbox, after giving the mail time to arrive.
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  expect(await mailTo(request, email)).toHaveLength(0);
});

test("the user verifies their email with the mailed code, and the administrator sees it verified", async ({
  page,
  browser,
  request,
  users,
}) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email-verification");
  await expect(own.page.getByText("Not verified", { exact: true })).toBeVisible();
  // The code is sent from the page, which says so in place.
  await own.page.getByRole("button", { name: "Send code", exact: true }).click();
  await expect(own.page.locator("#verification-status")).toHaveText(`We sent a code to ${user.email}. Check your inbox and spam folder.`);

  const mail = await waitForMail(request, user.email);
  const code = mail.html.match(/verification code:<\/p>\s*<p>\s*([^<\s]+)\s*<\/p>/)?.[1];
  expect(code, mail.html).toBeTruthy();
  await own.page.locator("#verificationCode").fill(code!);
  await own.page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(own.page.getByText("Email address verified.", { exact: true })).toBeVisible();
  await expect(own.page.getByText("Verified", { exact: true })).toBeVisible();
  await own.context.close();

  await page.goto(`${env.adminUrl}/admin/users/${user.id}/email`);
  await expect(page.locator("#emailVerified")).toBeChecked();
});

test("a wrong verification code is refused at its field", async ({ browser, request, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email-verification");
  await own.page.getByRole("button", { name: "Send code", exact: true }).click();
  await expect(own.page.locator("#verification-status")).toContainText("We sent a code to");
  await waitForMail(request, user.email);
  await own.page.locator("#verificationCode").fill("WRONG1");
  await own.page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(own.page.locator("#verification-error")).toHaveText("That code isn't right, or it has expired. Send a new one if you need to.");
  await expect(own.page.locator("#verificationCode")).toHaveAttribute("aria-invalid", "true");
  await expect(own.page.getByText("Email address verified.")).toHaveCount(0);
  await own.context.close();
});

test("forgot password for an unverified address sends nothing", async ({ browser, request, users }) => {
  const user = await users.create();
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(forgotPassword);
  await forgot.locator("#email").fill(user.email);
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  // The same answer as for any address.
  await expectLinkSent(forgot, user.email);
  await context.close();
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  expect(await mailTo(request, user.email)).toHaveLength(0);
});

test("changing a verified email sends a notice to the previous address, which does not name the new one", async ({
  browser,
  request,
  users,
}) => {
  const user = await users.create({ emailVerified: true });
  const newEmail = `${uniqueIdentifier("u")}@example.com`;
  const own = await signInToConsole(browser, user, "/account/email");
  await own.page.locator("#email").fill(newEmail);
  await own.page.locator("#emailConfirmation").fill(newEmail);
  await own.page.locator("#currentPassword").fill(user.password);
  await own.page.getByRole("button", { name: "Change email", exact: true }).click();
  await expect(own.page.getByText("Email changed.", { exact: true })).toBeVisible();
  await own.context.close();

  const notice = await waitForMail(request, user.email);
  expect(notice.subject).toBeTruthy();
  // Whoever reads the old mailbox has no business learning the new address.
  expect(notice.text + notice.html).not.toContain(newEmail);
});

test("the sign-in page's register link appears only while self-registration is on", async ({ browser }) => {
  // Off, as in the baseline.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const signIn = await context.newPage();
  await signIn.goto(`${env.adminUrl}/account/profile`);
  await expect(signIn.locator('input[name="password"]')).toBeVisible();
  await expect(signIn.getByRole("link", { name: "Create an account" })).toHaveCount(0);
  await context.close();
});
