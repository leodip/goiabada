// axe-core over the states only a change to the settings reaches (axe-check.ts): each settings page
// saved and refused, the Branding pages among them, the confirmations their saves ask, the audit log while no event is stored, and
// self-registration's pages, and the console drawn in a brand with a logo (#813): its header and its
// cards, with the app name shown and hidden. Runs alone, and each test puts back what it changes
// (lib/settings.ts).
import { randomBytes } from "node:crypto";
import { clientIdFromList, deleteUser, idFromListLink, publishLegalDocument, setClientBrand, setLegalDocumentApps } from "../../lib/admin-console";
import { openSignIn, submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { linksIn, waitForMail } from "../../lib/mailpit";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";
import { uniqueIdentifier } from "../../lib/unique";
import { asks, at, checkStates, refused, saved, titled, withBrandPreview, type State } from "../../lib/axe";
import {
  brandKitToken,
  brandUrl,
  brandingUrl,
  createBrand,
  defaultBrand,
  deleteBrand,
  newBrandUrl,
  saveBrand,
  setBrandKit,
  uploadBrandAsset,
  withBrand,
  withDefaultBrandRestored,
} from "../../lib/brands";
import { solidPng } from "../../lib/images";
import { browserSignInClient } from "../../lib/test-clients";

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

  // A brand's page saved and refused, Make default asking first, and the delete page refusing a
  // name, on a brand of the test's own; the default brand is saved as it stands.
  await withDefaultBrandRestored(page, async () => {
    const seeded = await defaultBrand(page);
    const name = uniqueIdentifier("brand");
    const id = await createBrand(page, { name, appearance: "dark", theme: "plum" });
    try {
      await checkStates(page, [
        withBrandPreview(
          page,
          saved(page, "branding, the default brand saved", async () => {
            await page.goto(brandUrl(seeded.id, "edit"));
            await save();
          }),
        ),
        withBrandPreview(
          page,
          refused(page, "branding, a new brand's name refused", "name", async () => {
            await page.goto(newBrandUrl);
            await page.locator("#btnCreate").click();
          }),
        ),
        // Drawn again with a theme the auth server does not know, previewed in the first listed one.
        withBrandPreview(
          page,
          refused(page, "branding, a brand's theme refused", "theme-blueberry", async () => {
            await page.goto(brandUrl(id, "edit"));
            await page.locator('input[name="theme"]:checked').evaluate((radio) => ((radio as HTMLInputElement).value = "sepia"));
            await save();
          }),
        ),
        asks(page, "branding, Make default asking first", async () => {
          await page.goto(brandUrl(id, "edit"));
          await page.locator("#btnMakeDefault").click();
        }),
        refused(page, "branding, a deletion's name refused", "name", async () => {
          await page.goto(brandUrl(id, "delete"));
          await page.locator("#name").fill("not its name");
          await page.locator("#btnDelete").click();
        }),
      ]);
    } finally {
      await deleteBrand(page, id);
    }
  });

  // Revoking the previous key, which a freshly built environment has none of, is checked in
  // keys.system.ts, once its rotation has made one.
  await page.goto(settings("keys"));
  await checkStates(page, [asks(page, "signing keys, a rotation asking first", () => page.locator("#btnRotate").click())]);
});

// The console's own client given an automatic brand with a logo and a dark logo: an admin page's and
// an Account page's header, and home's card, with the logo beside the app name and in its place. The
// client is put back on the default brand.
test("the console's header and cards with its brand's logo", async ({ page, request, clients }) => {
  const token = await brandKitToken(page, request, clients);
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const sidebarLogo = page.locator("a.sidebar-brand img");
  const cardLogo = page.locator(".auth-card .auth-logo img");

  await withBrand(page, { appearance: "auto", theme: "blueberry" }, async (brand) => {
    const logo = await uploadBrandAsset(request, token, "logo", solidPng(200, 50, [30, 60, 160]));
    const darkLogo = await uploadBrandAsset(request, token, "logo", solidPng(200, 50, [220, 230, 250]));
    await setBrandKit(request, token, brand.id, { logo, darkLogo });
    try {
      await setClientBrand(page, consoleClient, brand);
      const withLogo = (name: string, url: string, image: typeof cardLogo) => ({
        name,
        reach: async () => {
          await page.goto(url);
          await expect(image).toBeVisible();
        },
      });
      await checkStates(page, [
        withLogo("an admin page's header with the brand's logo", brandingUrl, sidebarLogo),
        withLogo("an Account page's header with the brand's logo", `${env.adminUrl}/account/profile`, sidebarLogo),
        withLogo("the console's home card with the brand's logo", `${env.adminUrl}/`, cardLogo),
      ]);

      // The name hidden, saved as it stands in the editor so every console page is drawn again.
      await setBrandKit(request, token, brand.id, { logo, darkLogo, hideAppName: true });
      await saveBrand(page, brand.id, {});
      await checkStates(page, [
        withLogo("an admin page's header with the logo in the name's place", brandingUrl, sidebarLogo),
        withLogo("an Account page's header with the logo in the name's place", `${env.adminUrl}/account/profile`, sidebarLogo),
        withLogo("the console's home card with the logo in the name's place", `${env.adminUrl}/`, cardLogo),
      ]);

      // A logo short and wide, as the logo's rules allow, in the name's place: each link to home is
      // still a target of at least 24 by 24 pixels, the phone's header link and the desktop's sidebar
      // link, and the pages pass.
      const wide = await uploadBrandAsset(request, token, "logo", solidPng(512, 10, [30, 60, 160]));
      await setBrandKit(request, token, brand.id, { logo: wide, hideAppName: true });
      await saveBrand(page, brand.id, {});
      const viewport = page.viewportSize();
      try {
        for (const [width, link] of [
          [375, "a.app-header-brand"],
          [1440, "a.sidebar-brand"],
        ] as const) {
          await page.setViewportSize({ width, height: 900 });
          await page.goto(`${env.adminUrl}/account/profile`);
          await expect(page.locator(`${link} img`)).toBeVisible();
          const box = await page.locator(link).boundingBox();
          expect(box, `${link} at ${width}px`).not.toBeNull();
          expect(box!.width, `${link}'s width at ${width}px`).toBeGreaterThanOrEqual(24);
          expect(box!.height, `${link}'s height at ${width}px`).toBeGreaterThanOrEqual(24);
        }
        await checkStates(page, [
          withLogo("an Account page's header with a short, wide logo in the name's place", `${env.adminUrl}/account/profile`, page.locator("a.sidebar-brand img")),
        ]);
      } finally {
        if (viewport) await page.setViewportSize(viewport);
      }
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }
  });
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
// password chosen on the form. The emailed link is also opened in a browser that does not hold the
// sign-in the registration started from, the console's, whose page sends the person back to the app.
// The accounts it creates are deleted afterwards.
test("self-registration's pages", async ({ page, browser, request }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const own = await context.newPage();
  const register = `${env.authUrl}/account/register`;
  const createAccount = own.getByRole("button", { name: "Create account", exact: true });
  const password = `${randomBytes(12).toString("base64url")}-Aa1`;
  const withLink = `${uniqueIdentifier("u")}@example.com`;
  const withPassword = `${uniqueIdentifier("u")}@example.com`;
  const fromSignIn = `${uniqueIdentifier("u")}@example.com`;
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

      await own.goto(`${env.adminUrl}/account/profile`);
      await own.getByRole("link", { name: "Create an account" }).click();
      await own.locator("#email").fill(fromSignIn);
      await createAccount.click();
      await expect(own.getByRole("heading", { level: 1, name: "Check your email" })).toBeVisible();
      const fromSignInLink = linksIn(await waitForMail(request, fromSignIn)).find((link) => link.includes("/account/activate"))!;
      const elsewhere = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      try {
        const other = await elsewhere.newPage();
        await checkStates(other, [
          {
            name: "the new account activated in another browser, sending the person back to the app",
            reach: async () => {
              await other.goto(fromSignInLink);
              await other.locator("#password").fill(password);
              await other.locator("#passwordConfirmation").fill(password);
              await other.getByRole("button", { name: "Create account", exact: true }).click();
              await expect(other.getByRole("heading", { level: 1, name: "Account activated" })).toBeVisible();
              created.push(fromSignIn);
              await expect(other.getByText("Go back to the application you were signing in to")).toBeVisible();
            },
          },
        ]);
      } finally {
        await elsewhere.close();
      }

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

// The acceptance step and a legal document's public page (#622): the step as first shown and with its
// box left unticked, and the page the step links. The document is set to the test's own client
// before it is published, so no other sign-in owes it, and the fixtures retire it and delete the
// client.
test("the acceptance step and a legal document's page", async ({ page, browser, clients, users, legalDocuments }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "## Using the app\n\nBe nice to **everyone**." });
  await setLegalDocumentApps(page, doc.id, [client.identifier]);
  await publishLegalDocument(page, doc.id);

  const { context, page: own } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  try {
    await checkStates(own, [
      titled(own, "the acceptance step", "Accept the terms", async () => {
        await submitPassword(own, user.email, user.password);
        await own.waitForURL((url) => url.pathname === "/auth/legal-acceptance");
      }),
      refused(own, "the acceptance step, the box left unticked", "legalDocument0", () =>
        own.getByRole("button", { name: "Accept", exact: true }).click(),
      ),
      at(own, "a legal document's public page", `${env.authUrl}/legal/${doc.shortName}`),
    ]);
  } finally {
    await context.close();
  }
});
