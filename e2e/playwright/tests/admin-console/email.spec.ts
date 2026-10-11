// What the auth server mails, as the environment's Mailpit catches it (lib/mailpit.ts), followed
// through the links and codes in each message. SMTP pointing at Mailpit is part of the baseline the
// setup step restores, and none of these tests changes it.
import { userUrl } from "../../lib/admin-console";
import { signInToConsole } from "../../lib/console-user";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, mailTo, waitForMail } from "../../lib/mailpit";
import { passwordToken } from "../../lib/oauth";
import { passwordGrantClient } from "../../lib/test-clients";
import { uniqueIdentifier } from "../../lib/unique";

test("a test email from Settings - Email arrives", async ({ page, request }) => {
  const to = `${uniqueIdentifier("m")}@example.com`;
  await page.goto(`${env.adminUrl}/admin/settings/email/send-test-email`);
  await page.locator('input[name="destinationEmail"]').fill(to);
  await page.locator("#btnSend").click();
  await expect(page.getByText("Email sent successfully")).toBeVisible();
  const mail = await waitForMail(request, to);
  expect(mail.subject).toBeTruthy();
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
  await expect(page.locator("#password")).toBeDisabled();
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
  const id = Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]);

  try {
    const mail = await waitForMail(request, email);
    const link = linksIn(mail).find((l) => l.startsWith(env.authUrl));
    expect(link, mail.text).toBeTruthy();

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const setPassword = await context.newPage();
    await setPassword.goto(link!);
    await setPassword.locator('input[name="password"]').fill("a-chosen-password");
    await setPassword.locator('input[name="passwordConfirmation"]').fill("a-chosen-password");
    await setPassword.getByRole("button", { name: "Set my password" }).click();
    await expect(setPassword.getByText("Your password has been successfully set.")).toBeVisible();

    // A link is good once.
    await setPassword.goto(link!);
    await expect(setPassword.getByText(/invalid or expired|no longer/i).first()).toBeVisible();
    await context.close();

    const { client, secret } = await passwordGrantClient(page, clients);
    expect((await passwordToken(request, client.identifier, secret, email, "a-chosen-password", "openid")).status).toBe(200);
  } finally {
    await page.goto(userUrl(id, "delete"));
    await page.getByRole("button", { name: "Delete user" }).click();
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
  await forgot.getByRole("link", { name: "Forgot password?" }).click();
  await forgot.locator('input[name="email"]').fill(user.email);
  await forgot.getByRole("button", { name: "Send password reset link" }).click();
  await expect(forgot.getByText("If you're a registered user, a password reset link has been sent")).toBeVisible();

  const mail = await waitForMail(request, user.email);
  const link = linksIn(mail).find((l) => l.startsWith(env.authUrl))!;
  await forgot.goto(link);
  await forgot.locator('input[name="password"]').fill("a-reset-password");
  await forgot.locator('input[name="passwordConfirmation"]').fill("a-reset-password");
  await forgot.getByRole("button", { name: "Set my password" }).click();
  await expect(forgot.getByText("Your password has been successfully set.")).toBeVisible();
  await context.close();

  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await passwordToken(request, client.identifier, secret, user.email, "a-reset-password", "openid")).status).toBe(200);
  expect((await passwordToken(request, client.identifier, secret, user.email, user.password, "openid")).body.error).toBe("invalid_grant");
});

test("forgot password for an address nobody has answers the same, and sends nothing", async ({ browser, request }) => {
  const email = `${uniqueIdentifier("u")}@example.com`;
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(`${env.authUrl}/forgot-password`);
  await forgot.locator('input[name="email"]').fill(email);
  await forgot.getByRole("button", { name: "Send password reset link" }).click();
  await expect(forgot.getByText("If you're a registered user, a password reset link has been sent")).toBeVisible();
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
  await expect(own.page.getByText("isn't verified")).toBeVisible();
  await own.page.getByRole("button", { name: "Send verification code" }).click();
  const dialog = own.page.locator("dialog[open]");
  await expect(dialog).toContainText("A verification code has been sent to");
  await dialog.getByRole("button", { name: "Close" }).click();

  const mail = await waitForMail(request, user.email);
  const code = mail.html.match(/verification code:<\/p>\s*<p>\s*([^<\s]+)\s*<\/p>/)?.[1];
  expect(code, mail.html).toBeTruthy();
  await own.page.locator('input[name="verificationCode"]').fill(code!);
  await own.page.getByRole("button", { name: "Verify email" }).click();
  await expect(own.page.getByText("Email verified successfully")).toBeVisible();
  await own.context.close();

  await page.goto(userUrl(user.id, "email"));
  await expect(page.locator('input[name="emailVerified"]')).toBeChecked();
});

test("a wrong verification code is refused", async ({ browser, request, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email-verification");
  await own.page.getByRole("button", { name: "Send verification code" }).click();
  await own.page.locator("dialog[open]").getByRole("button", { name: "Close" }).click();
  await waitForMail(request, user.email);
  await own.page.locator('input[name="verificationCode"]').fill("WRONG1");
  await own.page.getByRole("button", { name: "Verify email" }).click();
  await expect(own.page.locator(".text-error, dialog[open]").first()).toBeVisible();
  await expect(own.page.getByText("Email verified successfully")).toHaveCount(0);
  await own.context.close();
});

test("forgot password for an unverified address sends nothing", async ({ browser, request, users }) => {
  const user = await users.create();
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const forgot = await context.newPage();
  await forgot.goto(`${env.authUrl}/forgot-password`);
  await forgot.locator('input[name="email"]').fill(user.email);
  await forgot.getByRole("button", { name: "Send password reset link" }).click();
  // The same answer as for any address.
  await expect(forgot.getByText("If you're a registered user, a password reset link has been sent")).toBeVisible();
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
  await own.page.locator('input[name="email"]').fill(newEmail);
  await own.page.locator('input[name="emailConfirmation"]').fill(newEmail);
  await own.page.locator('input[name="currentPassword"]').fill(user.password);
  await own.page.getByRole("button", { name: "Update email" }).click();
  await expect(own.page.getByText("Email updated successfully")).toBeVisible();
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
  await expect(signIn.getByRole("link", { name: /register/i })).toHaveCount(0);
  await context.close();
});
