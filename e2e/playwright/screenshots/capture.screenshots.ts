// The screenshots of the docs home page and the README, captured from the servers e2e/screenshots.sh
// started on a new database, into SCREENSHOTS_OUT, under the names images.json lists, which the script
// then writes over site/src/assets.
//
// A set-up session signs the administrator in and sets the instance up through the console's forms.
// The images come from a browser context of their own with no session, since a browser that has one
// never sees the password page: opening the console there lands on it, and it is captured before
// any credentials are submitted (#534 decision 8).
//
// Each image has a fixed width and a height measured from the page (decision 9): the sign-in page is
// 960 pixels wide, as tall as its card plus 86 pixels above and below, its corners transparent and
// rounded to 12 pixels; the card image is the same capture cropped to the card with 30 pixels around
// it, its corners square.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { signInAsAdmin } from "../lib/admin-console";
import { env } from "../lib/environment";
import { fillSettingsForm, saveSettings } from "../lib/settings";
import { crop, decodePng, encodePng, roundCorners, type Pixels } from "./png";

const signInWidth = 960;
const signInCardSpace = 86;
const cardMargin = 30;
const cornerRadius = 12;

// The images the command writes, by file name: the list e2e/screenshots.sh replaces the committed
// files from.
const listed: string[] = JSON.parse(readFileSync(new URL("./images.json", import.meta.url), "utf8"));

function outDir(): string {
  const out = process.env.SCREENSHOTS_OUT;
  if (!out) throw new Error("no SCREENSHOTS_OUT: run e2e/screenshots.sh");
  return out;
}

// Turns on what the sign-in page shows "Forgot your password?" and "Create an account" for: sending
// email, through the Mailpit beside the servers, and self-registration.
async function setUp(browser: Browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signInAsAdmin(page);
  await page.goto(`${env.adminUrl}/admin/settings/email`);
  await fillSettingsForm(page, {
    smtpEnabled: true,
    hostOrIP: "localhost",
    port: "1025",
    smtpEncryption: "none",
    username: "",
    fromName: "Goiabada",
    fromEmail: "noreply@example.com",
  });
  await saveSettings(page);
  await page.goto(`${env.adminUrl}/admin/settings/general`);
  await fillSettingsForm(page, { selfRegistrationEnabled: true });
  await saveSettings(page);
  await context.close();
}

// The page as one capture of the viewport, its pixels decoded, once its fonts have loaded.
async function capture(page: Page): Promise<Pixels> {
  await page.evaluate(() => document.fonts.ready);
  return decodePng(await page.screenshot({ animations: "disabled", caret: "hide" }));
}

// The auth server's password page the console sends a browser with no session to, captured whole
// and cropped to its card.
async function signInPage(page: Page): Promise<Map<string, Buffer>> {
  await page.goto(`${env.adminUrl}/admin/users`);
  await page.waitForURL((url) => url.origin === env.authUrl && url.pathname === "/auth/pwd");
  await expect(page.getByRole("link", { name: "Forgot your password?" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Create an account" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);

  const card = page.locator(".auth-card");
  const height = (await card.boundingBox())!.height;
  expect(Number.isInteger(height), `the card is ${height} pixels tall, not a whole number`).toBe(true);
  await page.setViewportSize({ width: signInWidth, height: height + 2 * signInCardSpace });
  const box = (await card.boundingBox())!;
  expect(box, `the card is not ${signInCardSpace} pixels from the top and the bottom`).toEqual({
    x: box.x,
    y: signInCardSpace,
    width: box.width,
    height,
  });

  const pixels = await capture(page);
  return new Map([
    ["screenshot-signin.png", encodePng(roundCorners(pixels, cornerRadius), { alpha: true })],
    [
      "screenshot-signin-card.png",
      encodePng(crop(pixels, box.x - cardMargin, box.y - cardMargin, box.width + 2 * cardMargin, box.height + 2 * cardMargin), {
        alpha: false,
      }),
    ],
  ]);
}

test("the screenshots", async ({ browser }) => {
  await setUp(browser);

  const context = await browser.newContext({ viewport: { width: signInWidth, height: 1000 } });
  const page = await context.newPage();
  const images = await signInPage(page);
  await context.close();

  expect([...images.keys()].sort(), "the images captured are not the ones images.json lists").toEqual([...listed].sort());
  for (const [name, png] of images) writeFileSync(path.join(outDir(), name), png);
});
