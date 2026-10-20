// axe-core over the states only a change to the settings reaches (axe-check.ts): each settings page
// saved and refused, the confirmations their saves ask, the audit log while no event is stored, and
// self-registration's pages. Runs alone, and each test puts back what it changes (lib/settings.ts).
import { randomBytes } from "node:crypto";
import { deleteUser, idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";
import { asks, checkStates, refused, saved, titled, type State } from "../../lib/axe";

test.describe.configure({ timeout: 300_000 });

const settings = (path: string) => `${env.adminUrl}/admin/settings/${path}`;

// Every page is saved as it stands, which changes nothing; a refused save writes nothing, and a
// confirmation is answered with Cancel. The settings are put back all the same, should one not be.
test("the settings pages saved, refused, and asking first", async ({ page }) => {
  const save = () => page.locator("#btnSave").click();
  const savedAsItStands = (path: string, name: string) =>
    saved(page, name, async () => {
      await page.goto(settings(path));
      await save();
    });
  const refusedAt = (path: string, name: string, field: string, value: string) =>
    refused(page, name, field, async () => {
      await page.goto(settings(path));
      await page.locator(`#${field}`).fill(value);
      await save();
    });

  const pages: { path: string; states: State[] }[] = [
    {
      path: "general",
      states: [
        savedAsItStands("general", "general settings saved"),
        refusedAt("general", "general settings, the app name refused", "appName", "x".repeat(100)),
        asks(page, "general settings, an issuer change asking first", async () => {
          await page.goto(settings("general"));
          const issuer = page.locator("#issuer");
          await issuer.fill(`${await issuer.inputValue()}/changed`);
          await save();
        }),
      ],
    },
    { path: "ui-theme", states: [savedAsItStands("ui-theme", "theme settings saved")] },
    {
      path: "sessions",
      states: [
        savedAsItStands("sessions", "session settings saved"),
        refusedAt("sessions", "session settings, the idle timeout refused", "userSessionIdleTimeoutInSeconds", "ten"),
      ],
    },
    {
      path: "tokens",
      states: [
        savedAsItStands("tokens", "token settings saved"),
        refusedAt("tokens", "token settings, the token lifetime refused", "tokenExpirationInSeconds", "five"),
      ],
    },
    {
      path: "email",
      states: [
        savedAsItStands("email", "email settings saved"),
        refusedAt("email", "email settings, the port refused", "port", "twenty-five"),
        asks(page, "email settings, turning email off asking first", async () => {
          await page.goto(settings("email"));
          await page.locator("#smtpEnabled").setChecked(false);
          await save();
        }),
      ],
    },
    {
      path: "audit-logs",
      states: [
        savedAsItStands("audit-logs", "audit logging settings saved"),
        refusedAt("audit-logs", "audit logging settings, the retention refused", "auditLogRetentionDays", "ninety"),
      ],
    },
  ];
  for (const { path, states } of pages) {
    await withSettingsRestored(page, `/admin/settings/${path}`, () => checkStates(page, states));
  }

  // Revoking the previous key, which a freshly built environment has none of, is checked in
  // keys.system.ts, once its rotation has made one.
  await page.goto(settings("keys"));
  await checkStates(page, [asks(page, "signing keys, a rotation asking first", () => page.locator("#btnRotate").click())]);
});

test("the audit log while no event is stored", async ({ page }) => {
  await withSettingsRestored(page, "/admin/settings/audit-logs", async () => {
    await fillSettingsForm(page, { auditLogsInDatabaseEnabled: false });
    await saveSettings(page);
    await checkStates(page, [
      {
        name: "the audit log, nothing stored",
        reach: async () => {
          await page.goto(settings("audit-log-viewer"));
          await expect(page.locator(".notice-note")).toBeVisible();
        },
      },
    ]);
  });
});

// Registration with the emailed link, as the baseline's email verification has it, then with a
// password chosen on the form. The accounts it creates are deleted afterwards.
test("self-registration's pages", async ({ page, browser, request }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const own = await context.newPage();
  const register = `${env.authUrl}/account/register`;
  const createAccount = own.getByRole("button", { name: "Create account", exact: true });
  const password = `${randomBytes(12).toString("base64url")}-Aa1`;
  const withLink = `${uniqueIdentifier("u")}@example.com`;
  const withPassword = `${uniqueIdentifier("u")}@example.com`;
  const created: string[] = [];
  const choosePassword = async (confirmation: string) => {
    await own.locator("#password").fill(password);
    await own.locator("#passwordConfirmation").fill(confirmation);
    await createAccount.click();
  };

  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      await fillSettingsForm(page, { selfRegistrationEnabled: true, selfRegistrationRequiresEmailVerification: true });
      await saveSettings(page);
      await checkStates(own, [
        {
          name: "sign-in, offering to create an account",
          reach: async () => {
            await own.goto(`${env.adminUrl}/account/profile`);
            await expect(own.getByRole("link", { name: "Create an account" })).toBeVisible();
          },
        },
        titled(own, "creating an account", "Create an account", () => own.goto(register)),
        refused(own, "creating an account, the address refused", "email", async () => {
          await own.locator("#email").fill("not-an-address");
          await createAccount.click();
        }),
        titled(own, "creating an account, the link sent", "Check your email", async () => {
          await own.locator("#email").fill(withLink);
          await createAccount.click();
        }),
        titled(own, "choosing the new account's password", "Choose your password", async () => {
          const mail = await waitForMail(request, withLink);
          await own.goto(linksIn(mail).find((link) => link.includes("/account/activate"))!);
        }),
        refused(own, "choosing the new account's password, the passwords not matching", "passwordConfirmation", () =>
          choosePassword(`${password}-not`),
        ),
        {
          name: "the new account activated",
          reach: async () => {
            await choosePassword(password);
            await expect(own.getByRole("heading", { level: 1, name: "Account activated" })).toBeVisible();
            created.push(withLink);
          },
        },
        titled(own, "an activation link that can't be used", "This link can't be used", () =>
          own.goto(`${env.authUrl}/account/activate?code=not-a-code`),
        ),
      ]);

      await fillSettingsForm(page, { selfRegistrationRequiresEmailVerification: false });
      await saveSettings(page);
      await checkStates(own, [
        {
          name: "creating an account with a password",
          reach: async () => {
            await own.goto(register);
            await expect(own.locator("#password")).toBeVisible();
          },
        },
        refused(own, "creating an account, the passwords not matching", "passwordConfirmation", async () => {
          await own.locator("#email").fill(withPassword);
          await choosePassword(`${password}-not`);
        }),
        {
          name: "the account created",
          reach: async () => {
            await own.locator("#email").fill(withPassword);
            await choosePassword(password);
            await expect(own.getByRole("heading", { level: 1, name: "Account created" })).toBeVisible();
            created.push(withPassword);
          },
        },
      ]);
    });
  } finally {
    await context.close();
    for (const email of created) {
      await deleteUser(page, await idFromListLink(page, `${env.adminUrl}/admin/users?${new URLSearchParams({ query: email })}`, email));
    }
  }
});
