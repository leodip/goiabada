import { expect, test, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";

// These tests are about signing in, so each starts with no session, not the suite's saved one.
test.use({ storageState: { cookies: [], origins: [] } });

// A protected admin console page sends a visitor with no session to the auth server's password page.
async function startSignIn(page: Page) {
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(page).toHaveTitle(/^Sign in – /);
}

async function expectSignedIn(page: Page) {
  // Back on the admin console, on the page asked for, signed in.
  await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
  await expect(page).toHaveTitle(/^Clients – /);
  // The user menu, in the header, names who is signed in.
  await expect(page.locator("[data-user-menu-button]")).toContainText(env.adminEmail);
}

async function expectRefused(page: Page, message: string) {
  // The password page again, with the message above the fields, and still no session at the admin
  // console.
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(page.locator("#pwd-error")).toHaveText(message);
  await expect(page.locator("#password")).toHaveValue("");
}

// The field a refusal is about: marked invalid, described by the message, and focused.
async function expectFieldRefused(page: Page, fieldId: string) {
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("aria-invalid", "true");
  await expect(page.locator(`#${fieldId}`)).toHaveAttribute("aria-describedby", "pwd-error");
  await expect(page.locator(`#${fieldId}`)).toBeFocused();
}

test("the administrator signs in to the admin console through the auth server", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expectSignedIn(page);

  // The list comes from the auth server's admin API with the administrator's token: the admin
  // console's own client, which the first start seeded, is in it.
  await expect(page.locator("#clientsTable").getByRole("link", { name: "admin-console-client", exact: true })).toBeVisible();
});

// No negative test here uses a wrong password for the administrator: every one counts against the
// account's failure budget (10 per 15 minutes from one address, held in memory until the next
// reset), so a few runs in a row would lock the administrator out and fail every test after them.
// A wrong password for a real account waits for throwaway users.

test("an address that names no account is refused, and the same sign-in then succeeds", async ({ page }) => {
  await startSignIn(page);
  // A fresh address each run, so its failure budget is never shared with another run's.
  const nobody = `nobody-${randomUUID()}@example.com`;
  await page.locator('input[name="email"]').fill(nobody);
  await page.locator('input[name="password"]').fill("not-a-password-anyone-has");

  // Hold the form on this page while its real submit handler runs twice. A persisted pageshow
  // then restores it without depending on whether this browser caches the navigation (#581).
  const submissions = await page.locator("form").evaluate((form: HTMLFormElement) => {
    const accepted: boolean[] = [];
    const stayHere = (event: Event) => {
      accepted.push(!event.defaultPrevented);
      event.preventDefault();
    };
    form.addEventListener("submit", stayHere);
    try {
      form.requestSubmit();
      form.requestSubmit();
      const disabled = Array.from(form.querySelectorAll("button")).every((button) => button.disabled);
      window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
      const restored = Array.from(form.querySelectorAll("button")).every((button) => !button.disabled);
      return { accepted, disabled, restored };
    } finally {
      form.removeEventListener("submit", stayHere);
    }
  });
  expect(submissions.accepted).toEqual([true, false]);
  expect(submissions.disabled).toBe(true);
  expect(submissions.restored).toBe(true);

  await submitPassword(page, nobody, "not-a-password-anyone-has");

  await expectRefused(page, "Authentication failed.");
  // The address typed stays in the form for the retry. A refusal of the pair names neither field, and
  // the focus is where typing starts again, the password.
  await expect(page.locator("#email")).toHaveValue(nobody);
  await expect(page.locator("#email")).not.toHaveAttribute("aria-invalid");
  await expect(page.locator("#password")).not.toHaveAttribute("aria-invalid");
  await expect(page.locator("#password")).toBeFocused();

  // A mistake does not end the sign-in: the re-rendered form carries it on.
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await expectSignedIn(page);
});

test("an empty email is refused before any password is checked", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, "", "anything");
  await expectRefused(page, "Email is required.");
  await expectFieldRefused(page, "email");
});

test("an empty password is refused before it is checked", async ({ page }) => {
  await startSignIn(page);
  await submitPassword(page, env.adminEmail, "");
  await expectRefused(page, "Password is required.");
  await expectFieldRefused(page, "password");
  await expect(page.locator("#email")).toHaveValue(env.adminEmail);
});

test("without signing in, the admin console's pages stay out of reach", async ({ page }) => {
  for (const path of ["/admin/clients", "/admin/users", "/admin/settings/general"]) {
    await page.goto(`${env.adminUrl}${path}`);
    await expect(page, `${path} should send the visitor to sign in`).toHaveURL(
      new RegExp(`^${env.authUrl}/auth/pwd\\?`),
    );
  }
});

// The console's callback takes the auth server's form_post, so a browser that opens its address on
// its own, from a bookmark or the history, carries no answer to a sign-in. It gets the sign-in error
// page at 405, naming POST as the one method the address takes, and Start again leads back to the
// console's home, from where a sign-in starts as it always does (#632 item 3).
test("the callback's address opened on its own explains itself, and Start again leads to a sign-in", async ({ page }) => {
  const response = await page.goto(`${env.adminUrl}/auth/callback`);
  expect(response?.status()).toBe(405);
  expect(response?.headers()["allow"]).toBe("POST");
  await expect(page.getByRole("heading", { level: 1, name: "This sign-in can't be finished", exact: true })).toBeVisible();
  await expect(
    page.getByText("This address receives the auth server's answer to a sign-in, posted to it, so it cannot be opened on its own."),
  ).toBeVisible();

  await page.getByRole("link", { name: "Start again", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}/`);
  await expect(page.getByRole("heading", { level: 1, name: "Admin console", exact: true })).toBeVisible();

  await page.getByRole("link", { name: /^Administration/ }).click();
  await expect(page).toHaveURL(new RegExp(`^${env.authUrl}/auth/pwd\\?`));
  await expect(page).toHaveTitle(/^Sign in – /);
});
