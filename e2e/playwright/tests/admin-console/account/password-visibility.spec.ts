// Every password field in the console has a Show button beside it (#722). Pressing it shows the
// text, the button then reads Hide, and a status region says "Shown" or "Hidden", which every
// screen reader speaks. Each button names the field it shows. The field goes back to dots when its
// form is sent and when the browser brings the page back.
import type { Locator, Page } from "@playwright/test";
import { userUrl } from "../../../lib/admin-console";
import { signInToConsole, turnOnTwoFactor } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { watchPasswordFieldsAsSent } from "../../../lib/submission";

// The status region the script adds beside the field, right after the field's row.
function statusOf(page: Page, fieldId: string): Locator {
  return page.locator(`.input-row:has(#${fieldId}) + [role="status"]`);
}

// The button named name is shown, reads Show, and controls the field with id fieldId.
async function expectShowButton(page: Page, name: string, fieldId: string) {
  const button = page.getByRole("button", { name, exact: true });
  await expect(button).toBeVisible();
  await expect(button).toHaveText("Show");
  await expect(button).toHaveAttribute("aria-controls", fieldId);
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("type", "password");
}

test("Change password: each field's button is named after it, and Enter and Space toggle it, the focus kept on the button", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const page = own.page;
  await expectShowButton(page, "Show current password", "currentPassword");
  await expectShowButton(page, "Show new password", "newPassword");
  await expectShowButton(page, "Show new password confirmation", "newPasswordConfirmation");

  const field = page.locator("#newPassword");
  await field.fill("a-new-passphrase");
  const status = statusOf(page, "newPassword");
  await expect(status).toHaveText("");

  const show = page.getByRole("button", { name: "Show new password", exact: true });
  await show.focus();
  await page.keyboard.press("Enter");
  await expect(field).toHaveAttribute("type", "text");
  const hide = page.getByRole("button", { name: "Hide new password", exact: true });
  await expect(hide).toHaveText("Hide");
  await expect(status).toHaveText("Shown");
  await expect(hide).toBeFocused();
  await expect(field).toHaveValue("a-new-passphrase");

  await page.keyboard.press("Space");
  await expect(field).toHaveAttribute("type", "password");
  await expect(show).toHaveText("Show");
  await expect(status).toHaveText("Hidden");
  await expect(show).toBeFocused();
  // The other fields' buttons are untouched.
  await expect(page.locator("#currentPassword")).toHaveAttribute("type", "password");
  await expect(statusOf(page, "currentPassword")).toHaveText("");
  await own.context.close();
});

test("Change password: a pointer press keeps the focus, the caret and the selection in the field", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const page = own.page;
  const field = page.locator("#newPassword");
  await field.fill("a-new-passphrase");
  await field.focus();
  await field.evaluate((input: HTMLInputElement) => input.setSelectionRange(2, 5));

  await page.getByRole("button", { name: "Show new password", exact: true }).click();
  await expect(field).toHaveAttribute("type", "text");
  await expect(field).toBeFocused();
  expect(await field.evaluate((input: HTMLInputElement) => [input.selectionStart, input.selectionEnd])).toEqual([2, 5]);

  await page.getByRole("button", { name: "Hide new password", exact: true }).click();
  await expect(field).toHaveAttribute("type", "password");
  await expect(field).toBeFocused();
  expect(await field.evaluate((input: HTMLInputElement) => [input.selectionStart, input.selectionEnd])).toEqual([2, 5]);
  await own.context.close();
});

test("Change password: sending the form puts every shown field back to dots before the page leaves", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const page = own.page;
  const fields = ["currentPassword", "newPassword", "newPasswordConfirmation"];
  for (const id of fields) {
    await page.locator(`#${id}`).fill("not-the-password");
  }
  for (const name of ["Show current password", "Show new password", "Show new password confirmation"]) {
    await page.getByRole("button", { name, exact: true }).click();
  }
  for (const id of fields) {
    await expect(page.locator(`#${id}`)).toHaveAttribute("type", "text");
  }

  // The submission is held at the network, so the page it leaves is still there to read; it is
  // then dropped, so nothing is changed.
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  await page.route(`${env.adminUrl}/account/change-password`, async (route) => {
    if (route.request().method() !== "POST") {
      return route.continue();
    }
    await held;
    return route.abort();
  });
  const sent = page.waitForRequest((request) => request.method() === "POST" && request.url() === `${env.adminUrl}/account/change-password`);
  // Playwright reads no page while its navigation is held, so the page reports its own fields.
  const asSent = await watchPasswordFieldsAsSent(page, fields);
  try {
    // The click does not wait for the navigation it starts, which the route holds until release.
    await page.getByRole("button", { name: "Change password" }).click({ noWaitAfter: true });
    await sent;
    expect(await asSent.state).toEqual({
      currentPassword: { type: "password", buttonText: "Show", buttonName: "Show current password" },
      newPassword: { type: "password", buttonText: "Show", buttonName: "Show new password" },
      newPasswordConfirmation: { type: "password", buttonText: "Show", buttonName: "Show new password confirmation" },
    });
    const dropped = page.waitForEvent("requestfailed");
    release();
    await dropped;
  } finally {
    // A failed assertion still lets the held request go.
    release();
  }
  await own.context.close();
});

test("Change password: the browser bringing the page back puts a shown field back to dots", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/change-password");
  const page = own.page;
  const field = page.locator("#newPassword");
  await field.fill("a-new-passphrase");
  await page.getByRole("button", { name: "Show new password", exact: true }).click();
  await expect(field).toHaveAttribute("type", "text");

  // The suite's Chromium runs without the back/forward cache, so the persisted pageshow a page
  // restored from it fires is dispatched here.
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
  await expect(field).toHaveAttribute("type", "password");
  await expect(page.getByRole("button", { name: "Show new password", exact: true })).toHaveText("Show");
  await expect(statusOf(page, "newPassword")).toHaveText("Hidden");
  await own.context.close();
});

test("the email change and the three two-factor forms name their buttons", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/email");
  await expectShowButton(own.page, "Show current password", "currentPassword");

  // Turning two-factor authentication on asks for the password.
  await own.page.goto(`${env.adminUrl}/account/otp`);
  await expectShowButton(own.page, "Show password", "password");
  await own.context.close();

  // Once it is on, turning it off asks for it, and so does a new set of recovery codes.
  const { secret } = await turnOnTwoFactor(browser, user);
  const enrolled = await signInToConsole(browser, { ...user, otpSecret: secret }, "/account/otp");
  const buttons = enrolled.page.getByRole("button", { name: "Show password", exact: true });
  await expect(buttons).toHaveCount(2);
  await expect(buttons.nth(0)).toHaveAttribute("aria-controls", "password");
  await expect(buttons.nth(1)).toHaveAttribute("aria-controls", "recovery-codes-password");
  for (const button of await buttons.all()) {
    await expect(button).toBeVisible();
    await expect(button).toHaveText("Show");
  }
  await enrolled.context.close();
});

test("the administrator's password fields name their buttons: new user, set password, SMTP and Turnstile", async ({ page, users }) => {
  await page.goto(`${env.adminUrl}/admin/users/new`);
  // With email on, the password is set here only when the administrator chooses to.
  const setNow = page.locator("#setPasswordTypeNow");
  if ((await setNow.count()) > 0) {
    await setNow.check();
  }
  await expectShowButton(page, "Show password", "password");

  const user = await users.create();
  await page.goto(userUrl(user.id, "authentication"));
  await expectShowButton(page, "Show new password", "newPassword");

  await page.goto(`${env.adminUrl}/admin/settings/email`);
  await expectShowButton(page, "Show password", "password");

  await page.goto(`${env.adminUrl}/admin/settings/turnstile`);
  await expectShowButton(page, "Show secret key", "turnstileSecretKey");
  const secretKey = page.locator("#turnstileSecretKey");
  await page.getByRole("button", { name: "Show secret key", exact: true }).click();
  await expect(secretKey).toHaveAttribute("type", "text");
  await expect(page.getByRole("button", { name: "Hide secret key", exact: true })).toHaveText("Hide");
  await expect(statusOf(page, "turnstileSecretKey")).toHaveText("Shown");
});
