// An email drawn in the brand of the sign-in it was asked from (#817), read from the environment's
// Mailpit, for brands of the test's own: emails.system.ts holds the ones that change the default
// brand or the console's own client. A Dark brand's email is drawn in its dark palette, with its dark
// logo, which stands in for the app name while the brand's switch hides it; the reset link it carries,
// opened in the browser that asked for it, draws the reset page in the client's brand, and anywhere
// else in the default brand (#812 decision 4). A sign-in started in safe mode sends its emails in
// Blueberry's colors in place of the brand's custom palette (#816 decision 6), and one started
// without it in the palette's.
//
// The brands and the clients are the test's own, so no other page changes, and this is an ordinary
// parallel spec.
import type { APIRequestContext, Browser, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  blueberryLightMail,
  brandKitToken,
  defaultBrand,
  expectDrawnInPlumDark,
  expectDrawnInSeededDefault,
  mailLook,
  plumDarkMail,
  setBrandKit,
  uploadBrandAsset,
  warmBasicPalette,
  withBrand,
  withCustomBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { linksIn, type Mail, waitForMail } from "../../../lib/mailpit";
import { browserSignInClient } from "../../../lib/test-clients";

// The app name the instance signs its emails with, as Settings - General holds it.
async function appName(page: Page): Promise<string> {
  await page.goto(`${env.adminUrl}/admin/settings/general`);
  return page.locator("#appName").inputValue();
}

// Asks for a password reset for address from the client's sign-in, through its Forgot your password?
// link, with params added to the authorization request, and answers the browser that asked, open.
async function resetFromSignIn(browser: Browser, client: TestClient, address: string, params: Record<string, string> = {}) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid", params });
  await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
  await signIn.page.getByRole("link", { name: "Forgot your password?" }).click();
  await signIn.page.locator("#email").fill(address);
  await signIn.page.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(signIn.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  return signIn;
}

// The reset link a password reset carries.
function resetLink(mail: Mail): string {
  const link = linksIn(mail).find((found) => found.startsWith(`${env.authUrl}/reset-password?`));
  expect(link, mail.text).toBeTruthy();
  return link!;
}

async function resetMail(request: APIRequestContext, address: string): Promise<Mail> {
  const mail = await waitForMail(request, address);
  expect(mail.subject).toBe("Password reset");
  return mail;
}

test("a Dark brand's email is drawn in its dark palette and dark logo, and its reset link draws the reset page in the brand in the browser that asked", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const name = await appName(page);
  const token = await brandKitToken(page, request, clients);
  const { client } = await browserSignInClient(page, clients);
  const seeded = await defaultBrand(page);
  const user = await users.create({ emailVerified: true });

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    const logo = await uploadBrandAsset(request, token, "logo", solidPng(240, 80, [36, 86, 196]));
    const darkLogo = await uploadBrandAsset(request, token, "logo", solidPng(240, 80, [250, 200, 60]));
    await setBrandKit(request, token, brand.id, { logo, darkLogo, hideAppName: true });
    await setClientBrand(page, client.id, brand);

    const signIn = await resetFromSignIn(browser, client, user.email);
    try {
      const mail = await resetMail(request, user.email);
      // The dark palette and the dark logo, by its absolute URL, whose alt is the app name it stands
      // in for: the name is not written beside it.
      expect(mailLook(mail.html)).toEqual({ canvas: plumDarkMail.canvas, colorScheme: "dark", logo: { src: darkLogo.url, alt: name } });
      expect(mail.html).not.toContain(logo.url);
      expect(mail.html).not.toContain(`text-align: center;">${name}</p>`);
      expect(mail.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${plumDarkMail.brand}"`));

      // The link, opened in the browser that asked for it, which holds the sign-in.
      const link = resetLink(mail);
      expect(new URL(link).searchParams.get("ceremony"), "the link names the sign-in").toBeTruthy();
      await signIn.page.goto(link);
      await expect(signIn.page.getByRole("heading", { name: "Set your password" })).toBeVisible();
      await expect(signIn.page.locator("body")).toHaveAttribute("data-page", "reset-password");
      await expectDrawnInPlumDark(signIn.page, brand.id);

      // And in another browser, which holds no sign-in.
      const elsewhere = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const other = await elsewhere.newPage();
      await other.goto(link);
      await expect(other.getByRole("heading", { name: "Set your password" })).toBeVisible();
      await expectDrawnInSeededDefault(other, seeded.id);
      await elsewhere.close();
    } finally {
      await signIn.context.close();
    }
  });
});

test("a sign-in started in safe mode sends its emails in Blueberry's colors, and one without it in the brand's custom palette", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const safe = await users.create({ emailVerified: true });
  const usual = await users.create({ emailVerified: true });

  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await setClientBrand(page, client.id, brand);

    const safeSignIn = await resetFromSignIn(browser, client, safe.email, { goiabada_safe_mode: "true" });
    await safeSignIn.context.close();
    const safeMail = await resetMail(request, safe.email);
    expect(mailLook(safeMail.html), "safe mode: Blueberry's light colors").toMatchObject({ canvas: blueberryLightMail.canvas, colorScheme: "light" });
    expect(safeMail.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${blueberryLightMail.brand}"`));
    expect(safeMail.html).not.toContain(warmBasicPalette.light.brand);

    const usualSignIn = await resetFromSignIn(browser, client, usual.email);
    await usualSignIn.context.close();
    const usualMail = await resetMail(request, usual.email);
    expect(mailLook(usualMail.html), "the palette's light colors").toMatchObject({ canvas: warmBasicPalette.light.canvas, colorScheme: "light" });
    expect(usualMail.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${warmBasicPalette.light.brand}"`));
  });
});
