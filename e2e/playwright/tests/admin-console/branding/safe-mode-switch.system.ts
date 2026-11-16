// The auth server's safe mode switch (#816 decision 2): GOIABADA_AUTHSERVER_BRAND_SAFE_MODE, set and the
// auth server restarted (e2e/infra/safe-mode.sh), draws every brand's pages without its custom CSS and
// with Blueberry's colors in place of its custom palette, the brand as stored left unchanged: a
// client's sign-in, with no parameter asking for it, and the emails it sends. The console's admin pages
// say the switch is on and how to leave it, and its Account pages draw the brand safe too. Unset and
// restarted, the pages are drawn in the brand as saved again.
//
// The switch changes every page of the instance, so this runs alone, and always switches it off again,
// pass or fail; e2e/test.sh switches it off before each run too, in case a run was killed with it on.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Browser, Page } from "@playwright/test";
import { clientIdFromList, safeModeNotice, safeModeSessionNotice, safeModeSwitchNotice, setClientBrand } from "../../../lib/admin-console";
import { blueberryLightMail, mailLook, pageToken, saveCustomCss, warmBasicPalette, withCustomBrand } from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { waitForMail } from "../../../lib/mailpit";
import { safeModeScript } from "../../../lib/paths";
import { browserSignInClient } from "../../../lib/test-clients";

const run = promisify(execFile);

// Switches safe mode on or off, the auth server restarted with it, and waits for the console to know:
// it reads the switch from the auth server's public settings, which it keeps half a minute.
async function switchSafeMode(page: Page, to: "on" | "off") {
  await run(safeModeScript, [to], { timeout: 180_000 });
  await expect
    .poll(
      async () => {
        await page.goto(`${env.adminUrl}/admin/clients`);
        return (await safeModeNotice(page).count()) > 0 && (await safeModeNotice(page).innerText()).trim() === safeModeSwitchNotice;
      },
      { message: `the console says the switch is ${to}`, timeout: 60_000, intervals: [2_000] },
    )
    .toBe(to === "on");
}

const outlined = "rgb(18, 52, 86)";

// The client's sign-in, with no parameter, as the brand draws it: the stylesheet it links, its custom
// CSS's outline on the card, and the page's canvas.
async function signInLook(browser: Browser, client: TestClient) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  try {
    await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
    return {
      stylesheets: await signIn.page.evaluate(() =>
        Array.from(document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]'))
          .map((link) => new URL(link.href).pathname.match(/^\/brand\/\d+\/([a-z-]+)\.css$/)?.[1])
          .filter((kind) => kind !== undefined),
      ),
      outline: await signIn.page.locator(".auth-card").first().evaluate((card) => getComputedStyle(card).outlineColor),
      canvas: await pageToken(signIn.page, "canvas"),
    };
  } finally {
    await signIn.context.close();
  }
}

// Asks for a password reset for address from the client's sign-in, with no parameter.
async function resetFromSignIn(browser: Browser, client: TestClient, address: string) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  try {
    await signIn.page.getByRole("link", { name: "Forgot your password?" }).click();
    await signIn.page.locator("#email").fill(address);
    await signIn.page.getByRole("button", { name: "Send reset link", exact: true }).click();
    await expect(signIn.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
  } finally {
    await signIn.context.close();
  }
}

test("GOIABADA_AUTHSERVER_BRAND_SAFE_MODE draws every page and email without the brand's custom CSS and palette, the console says so, and unset it is the brand again", async ({
  page,
  browser,
  request,
  clients,
  users,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const consoleClient = await clientIdFromList(page, "admin-console-client");
  const user = await users.create({ emailVerified: true });

  await withCustomBrand(page, "light", warmBasicPalette, async (brand) => {
    await saveCustomCss(page, brand.id, `.auth-card, .page-title {\n  outline: 6px solid ${outlined};\n}\n`);
    await setClientBrand(page, client.id, brand);
    try {
      // Off, the sign-in is drawn in the brand as saved.
      expect(await signInLook(browser, client)).toEqual({ stylesheets: ["stylesheet"], outline: outlined, canvas: warmBasicPalette.light.canvas });

      await switchSafeMode(page, "on");
      // The client's sign-in, asking for nothing, links the safe stylesheet: no custom CSS, and
      // Blueberry's colors in place of the palette.
      expect(await signInLook(browser, client), "the switch on").toEqual({
        stylesheets: ["safe-stylesheet"],
        outline: expect.not.stringMatching(/^rgb\(18, 52, 86\)$/),
        canvas: blueberryLightMail.canvas,
      });

      // Its emails are drawn in Blueberry's colors too.
      await resetFromSignIn(browser, client, user.email);
      const mail = await waitForMail(request, user.email);
      expect(mailLook(mail.html)).toMatchObject({ canvas: blueberryLightMail.canvas, colorScheme: "light" });
      expect(mail.html).not.toContain(warmBasicPalette.light.brand);

      // The console's admin pages say the switch is on, not a console session's safe mode, and its
      // Account pages, given the brand through the console's own client, draw it safe.
      await setClientBrand(page, consoleClient, brand);
      await page.goto(`${env.adminUrl}/admin/settings/branding`);
      await expect(safeModeNotice(page)).toHaveText(safeModeSwitchNotice);
      await expect(safeModeNotice(page)).not.toHaveText(safeModeSessionNotice);
      await page.goto(`${env.adminUrl}/account/profile`);
      await expect(safeModeNotice(page), "the notice is on admin pages alone").toHaveCount(0);
      expect(await page.locator(".page-title").first().evaluate((title) => getComputedStyle(title).outlineColor)).not.toBe(outlined);
      expect(await pageToken(page, "canvas")).toBe(blueberryLightMail.canvas);
      await setClientBrand(page, consoleClient, "default");

      // Nothing stored changed: the brand still holds its palette and its CSS.
      await page.goto(`${env.adminUrl}/admin/settings/branding/${brand.id}/edit`);
      await expect(page.locator("#theme-custom")).toBeChecked();
      await expect(page.locator("#customCss")).toHaveValue(/outline: 6px solid rgb\(18, 52, 86\)/);
    } finally {
      // The console's own client first, a save that cannot fail for the switch, then the switch.
      await setClientBrand(page, consoleClient, "default").catch(() => undefined);
      await switchSafeMode(page, "off");
    }

    // Off again, the sign-in is drawn in the brand as saved.
    expect(await signInLook(browser, client), "the switch off").toEqual({ stylesheets: ["stylesheet"], outline: outlined, canvas: warmBasicPalette.light.canvas });
  });
});
