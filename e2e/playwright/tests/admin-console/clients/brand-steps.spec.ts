// The steps of a client's sign-in past the password, each drawn in the client's brand (#812): setting
// up an authenticator, the recovery codes it comes with, consent and the form_post page that hands
// the app its answer, then, at the next sign-in, the one-time code and a recovery code in its place.
// The brand's custom CSS reaches each step by the page's data-page name (#816), and its footer is
// under each card (#814). The emails these steps send, the authenticator set up and a recovery code
// used, are drawn in the client's brand too, a Dark brand's in its dark palette (#817).
//
// The first sign-in runs in a browser that runs no script, so the form_post page stays on screen
// rather than posting at once. The brand, the client and the user are the test's own, so no other
// page changes, and this is an ordinary parallel spec.
import type { Page } from "@playwright/test";
import { enterRecoveryCode } from "../../../lib/console-user";
import { setClientBrand } from "../../../lib/admin-console";
import {
  brandUrl,
  customCssField,
  drawnFooter,
  expectDrawnInPlumDark,
  fillBrandFooter,
  mailLook,
  plumDarkMail,
  withBrand,
} from "../../../lib/brands";
import { continuePastRecoveryCodes, submitPassword, testRedirectUri } from "../../../lib/browser-sign-in";
import { expect, test } from "../../../lib/fixtures";
import { type Mail, waitForMail } from "../../../lib/mailpit";
import { authorizeEndpoint, codeRequest } from "../../../lib/rfc6749";
import { browserSignInClient } from "../../../lib/test-clients";
import { freshTotp } from "../../../lib/totp";

// The card's outline the brand's custom CSS draws on each step, by the page's data-page name.
const outlines: Record<string, string> = {
  "authenticator-setup": "rgb(11, 0, 0)",
  "new-recovery-codes": "rgb(12, 0, 0)",
  consent: "rgb(13, 0, 0)",
  "form-post": "rgb(14, 0, 0)",
  "one-time-code": "rgb(15, 0, 0)",
  "recovery-code": "rgb(16, 0, 0)",
};
const customCss = Object.entries(outlines)
  .map(([name, color]) => `body[data-page="${name}"] .auth-card {\n  outline: 4px solid ${color};\n}\n`)
  .join("");

// A step drawn in the client's brand: the page names itself, the brand's colors and its CSS's rule
// for the page are drawn, and the footer is under the card.
async function expectStepInBrand(page: Page, brandId: number, dataPage: string) {
  await expect(page.locator("body")).toHaveAttribute("data-page", dataPage);
  await expectDrawnInPlumDark(page, brandId);
  const outline = await page.locator(".auth-card").first().evaluate((card) => getComputedStyle(card).outlineColor);
  expect(outline, `${dataPage}: the brand's custom CSS for the page`).toBe(outlines[dataPage]);
  const footer = await drawnFooter(page);
  expect(footer?.links.map((link) => link.href), `${dataPage}: the brand's footer`).toEqual(["https://example.com/help"]);
}

// The email to the user whose subject is this one.
async function mailWithSubject(request: Parameters<typeof waitForMail>[0], address: string, subject: string, count: number): Promise<Mail> {
  const mail = await waitForMail(request, address, count);
  expect(mail.subject).toBe(subject);
  return mail;
}

test("a client's sign-in steps past the password, its consent and its form_post page are drawn in its brand, its CSS and its footer, and so are the emails they send", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const user = await users.create({ emailVerified: true });
  const { client } = await browserSignInClient(page, clients, { consentRequired: true });

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandFooter(page, { footerLinks: [{ label: "Help", url: "https://example.com/help" }] });
    await customCssField(page).fill(customCss);
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    await setClientBrand(page, client.id, brand);

    // The first sign-in asks for a second factor the user has not set up, and answers by form_post,
    // in a browser that runs no script.
    const first = await browser.newContext({ storageState: { cookies: [], origins: [] }, javaScriptEnabled: false });
    let recoveryCodes: string[];
    try {
      const tab = await first.newPage();
      const { params } = codeRequest(client.identifier, { acr_values: "urn:goiabada:level2_mandatory", response_mode: "form_post" });
      await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
      await expect(tab).toHaveURL(/\/auth\/pwd/);
      await submitPassword(tab, user.email, user.password);

      await expect(tab).toHaveURL(/\/auth\/otp/);
      await expectStepInBrand(tab, brand.id, "authenticator-setup");
      const secret = (await tab.locator("#otp-secret").innerText()).trim();
      await tab.locator('input[name="otp"]').fill(await freshTotp(secret));
      await tab.getByRole("button", { name: "Verify" }).click();

      await tab.waitForURL((url) => url.pathname === "/auth/recovery-codes");
      await expectStepInBrand(tab, brand.id, "new-recovery-codes");
      recoveryCodes = await continuePastRecoveryCodes(tab);

      await expect(tab).toHaveURL(/\/auth\/consent/);
      await expectStepInBrand(tab, brand.id, "consent");
      await tab.getByRole("button", { name: "Allow", exact: true }).click();

      await expect(tab.getByRole("heading", { name: "Returning you to the application" })).toBeVisible();
      await expectStepInBrand(tab, brand.id, "form-post");
      await expect(tab.locator("form")).toHaveAttribute("action", testRedirectUri);
    } finally {
      await first.close();
    }

    // The authenticator set up during the sign-in is said in the client's brand, a Dark brand's
    // email in its dark palette.
    const setUp = await mailWithSubject(request, user.email, "Two-factor authentication was set up", 1);
    expect(mailLook(setUp.html)).toMatchObject({ canvas: plumDarkMail.canvas, colorScheme: "dark" });
    expect(setUp.html).toContain('<a href="https://example.com/help" style="color: ' + plumDarkMail.brand);

    // The next sign-in asks for the code; a recovery code is used in its place.
    const second = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      const tab = await second.newPage();
      const { params } = codeRequest(client.identifier, { acr_values: "urn:goiabada:level2_optional" });
      await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
      await submitPassword(tab, user.email, user.password);
      await expect(tab).toHaveURL(/\/auth\/otp/);
      await expectStepInBrand(tab, brand.id, "one-time-code");

      await tab.getByRole("link", { name: "Use a recovery code instead" }).click();
      await expect(tab.locator('input[name="recoveryCode"]')).toBeVisible();
      await expectStepInBrand(tab, brand.id, "recovery-code");
      await enterRecoveryCode(tab, recoveryCodes[0]);
      await tab.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/consent");
      if (new URL(tab.url()).pathname === "/auth/consent") await tab.getByRole("button", { name: "Allow", exact: true }).click();
      await tab.waitForURL((url) => url.href.startsWith(testRedirectUri));
      expect(new URL(tab.url()).searchParams.get("code"), "the app gets its code").toBeTruthy();
    } finally {
      await second.close();
    }

    const used = await mailWithSubject(request, user.email, "A recovery code was used to sign in", 2);
    expect(mailLook(used.html)).toMatchObject({ canvas: plumDarkMail.canvas, colorScheme: "dark" });
  });
});
