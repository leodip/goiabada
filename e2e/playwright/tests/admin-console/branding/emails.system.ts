// An email is drawn in the brand of the page it was sent from (#817), read from the environment's
// Mailpit. A client is given a light Avocado brand with a logo, a footer link and a support
// contact: a password reset asked for from that client's sign-in arrives with the brand's logo by
// its absolute URL, its card and button in Avocado's colors, its footer, and a plain-text part that
// holds the reset link once and the footer written out. One asked for from the forgot password
// page naming no sign-in arrives in the default brand, the seeded Blueberry, which is given a
// support contact of its own for the run so the email shows it is the default's. Runs alone, since
// the default brand's footer is under every page that has no brand of its own, and puts it back.
import type { APIRequestContext, Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import {
  type BrandFooter,
  brandKitToken,
  defaultBrand,
  setBrandFooter,
  setBrandKit,
  uploadBrandAsset,
  withBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { solidPng } from "../../../lib/images";
import { linksIn, type Mail, waitForMail } from "../../../lib/mailpit";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// The colors an email in each brand is drawn in, as the themes' light palettes hold them: the area
// behind the card, and the brand's color the button and the links take.
const avocadoLight = { canvas: "#f3f6f4", brand: "#1f6b43" } as const;
const blueberryLight = { canvas: "#f4f5f7", brand: "#2456c4" } as const;

// The app name the instance signs its emails with, as Settings - General holds it.
async function appName(page: Page): Promise<string> {
  await page.goto(`${env.adminUrl}/admin/settings/general`);
  return page.locator("#appName").inputValue();
}

// A brand's footer links and support contact as the Admin API answers them, to put back after.
async function readBrandFooter(request: APIRequestContext, token: string, brandId: number): Promise<BrandFooter> {
  const response = await request.get(`${env.authUrl}/api/v1/admin/brands/${brandId}`, {
    headers: { Authorization: `Bearer ${token}` },
    failOnStatusCode: false,
  });
  expect(response.status(), await response.text()).toBe(200);
  const { brand } = await response.json();
  return {
    footerLinks: brand.footerLinks ?? [],
    supportEmail: brand.supportEmail ?? "",
    supportUrl: brand.supportUrl ?? "",
    supportPhone: brand.supportPhone ?? "",
  };
}

// Asks for a password reset for address on the forgot password page the browser is on.
async function askForReset(forgot: Page, address: string) {
  await expect(forgot.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await forgot.locator("#email").fill(address);
  await forgot.getByRole("button", { name: "Send reset link", exact: true }).click();
  await expect(forgot.getByRole("heading", { name: "Check your email" })).toBeVisible();
}

// The reset link a password reset carries, the first link of its text.
function resetLink(mail: Mail): string {
  const link = linksIn(mail)[0];
  expect(link, mail.text).toMatch(new RegExp(`^${env.authUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/reset-password\\?`));
  return link;
}

// An email's plain-text part, its line endings as written here, and the reset link it holds named
// <link>, since its code is new on each reset.
function textWithLink(mail: Mail, link: string): string {
  return mail.text.replace(/\r\n/g, "\n").split(link).join("<link>").trim();
}

test("a password reset is drawn in the brand of the sign-in it was asked from, with its text, and one asked from no sign-in in the default brand", async ({
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
  const seededFooter = await readBrandFooter(request, token, seeded.id);
  const defaultSupport = `${uniqueIdentifier("help")}@example.com`;

  await withBrand(page, { appearance: "light", theme: "avocado" }, async (brand) => {
    const logo = await uploadBrandAsset(request, token, "logo", solidPng(240, 80, [36, 86, 196]));
    await setBrandKit(request, token, brand.id, { logo });
    await setBrandFooter(request, token, brand.id, {
      footerLinks: [{ url: "https://example.com/privacy", label: "Privacy" }],
      supportEmail: "help@example.com",
    });
    await setClientBrand(page, client.id, brand);
    await setBrandFooter(request, token, seeded.id, { supportEmail: defaultSupport });

    try {
      // From the client's sign-in: its Forgot your password? link leads to the page naming it.
      const branded = await users.create({ emailVerified: true });
      const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
      await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
      await signIn.page.getByRole("link", { name: "Forgot your password?" }).click();
      await askForReset(signIn.page, branded.email);
      await signIn.context.close();

      const mail = await waitForMail(request, branded.email);
      expect(mail.subject).toBe("Password reset");
      // The logo by its absolute URL, above the app name, which shows, so the logo's alt is empty.
      expect(logo.url).toMatch(/^https:\/\//);
      expect(mail.html).toContain(`<img src="${logo.url}" alt=""`);
      expect(mail.html).toContain(`text-align: center;">${name}</p>`);
      // The card on Avocado's canvas, and the button in Avocado's brand color, labelled.
      expect(mail.html).toMatch(new RegExp(`<body style="[^"]*background-color: ${avocadoLight.canvas};`));
      expect(mail.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${avocadoLight.brand}"`));
      expect(mail.html).toMatch(/data-email-button[\s\S]*?>Reset password<\/a>/);
      // The brand's footer under the card, its link in the brand's color, and none of the default's.
      expect(mail.html).toContain(`<a href="https://example.com/privacy" style="color: ${avocadoLight.brand}; text-decoration: underline;">Privacy</a>`);
      expect(mail.html).toContain('<a href="mailto:help@example.com"');
      expect(mail.html).not.toContain(defaultSupport);
      expect(mail.html).not.toContain(blueberryLight.brand);

      // The text part: the reset link once, the button not repeated, then the footer written out,
      // and nothing of the logo.
      const link = resetLink(mail);
      expect(new URL(link).searchParams.get("ceremony"), "the link names the sign-in").toBeTruthy();
      expect(mail.text).not.toContain(logo.url);
      expect(textWithLink(mail, link)).toBe(
        [
          "Hello Playwright Tester,",
          "",
          "You can reset your password by clicking the link below:",
          "",
          "<link>",
          "",
          "If you have trouble clicking the link, you can copy and paste it into your web browser.",
          "",
          "In case you didn't request a password reset, kindly disregard this email.",
          "",
          "Best regards,",
          name,
          "",
          "Privacy <https://example.com/privacy>",
          "",
          "Need help? help@example.com",
        ].join("\n"),
      );

      // From the forgot password page naming no sign-in, in a browser holding none: the default
      // brand, with its own support contact, and nothing of the client's brand.
      const plain = await users.create({ emailVerified: true });
      const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const forgot = await context.newPage();
      await forgot.goto(`${env.authUrl}/forgot-password`);
      await askForReset(forgot, plain.email);
      await context.close();

      const unbranded = await waitForMail(request, plain.email);
      expect(unbranded.html).toMatch(new RegExp(`<body style="[^"]*background-color: ${blueberryLight.canvas};`));
      expect(unbranded.html).toMatch(new RegExp(`data-email-button[^>]*>\\s*<tr>\\s*<td align="center" bgcolor="${blueberryLight.brand}"`));
      expect(unbranded.html).toContain(`<a href="mailto:${defaultSupport}"`);
      expect(unbranded.html).not.toContain(logo.url);
      expect(unbranded.html).not.toContain("https://example.com/privacy");
      expect(unbranded.html).not.toContain(avocadoLight.brand);
      const unbrandedLink = resetLink(unbranded);
      expect(new URL(unbrandedLink).searchParams.get("ceremony"), "the link names no sign-in").toBeNull();
      expect(textWithLink(unbranded, unbrandedLink)).toMatch(new RegExp(`\\n\\nNeed help\\? ${defaultSupport.replace(/\./g, "\\.")}$`));
    } finally {
      await setBrandFooter(request, token, seeded.id, seededFooter);
    }
  });
});
