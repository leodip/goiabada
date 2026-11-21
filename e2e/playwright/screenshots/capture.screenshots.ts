// The screenshots of the docs home page and the README, captured from the servers e2e/screenshots.sh
// started on a new database, into SCREENSHOTS_OUT, under the names images.json lists, which the script
// then writes over site/src/assets.
//
// A set-up session signs the administrator in and sets the instance up through the console's forms:
// email sending and self-registration, the administrator's name, username and phone number, and the
// sample users (sample.ts). The images come from a browser context of their own with no session,
// since a browser that has one never sees the password page: opening the console there lands on it,
// and it is captured before any credentials are submitted. The same context then signs in, so the
// console's header draws the name the set-up session gave the administrator, and captures the users
// list and the account Phone page (#534 decision 8).
//
// Each image has a fixed width and a height measured from the page (decision 9): the sign-in page is
// 960 pixels wide, as tall as its card plus 86 pixels above and below; the card image is the same
// capture cropped to the card with 30 pixels around it, its corners square. The two console pages are
// 1440 pixels wide, as tall as the smallest viewport that shows the whole page with nothing
// scrolling. All but the card image have their corners transparent and rounded to 12 pixels.
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { choose, signInAsAdmin, submitNewUser } from "../lib/admin-console";
import { submitPassword } from "../lib/browser-sign-in";
import { env } from "../lib/environment";
import { fillSettingsForm, saveSettings } from "../lib/settings";
import { crop, decodePng, encodePng, roundCorners, type Pixels } from "./png";
import { administrator, sampleUsers } from "./sample";

const signInWidth = 960;
const signInCardSpace = 86;
const cardMargin = 30;
const consoleWidth = 1440;
const cornerRadius = 12;

// The images the command writes, by file name. The capture reads the list and hands it to
// e2e/screenshots.sh as images.txt beside the images, one name to a line, so the script replaces
// the committed files this parse names rather than reading the JSON a second way. A name is a plain
// file name, which a line can hold.
const listed: string[] = JSON.parse(readFileSync(new URL("./images.json", import.meta.url), "utf8"));
for (const name of listed) {
  if (!/^screenshot[A-Za-z0-9._-]*$/.test(name)) throw new Error(`images.json lists ${JSON.stringify(name)}, which is not a screenshot's file name`);
}

function outDir(): string {
  const out = process.env.SCREENSHOTS_OUT;
  if (!out) throw new Error("no SCREENSHOTS_OUT: run e2e/screenshots.sh");
  return out;
}

// Sets the instance up in a session of its own. Turns on what the sign-in page shows "Forgot your
// password?" and "Create an account" for: sending email, through the Mailpit beside the servers, and
// self-registration. Gives the administrator, which the auth server seeds with neither, a name and a
// username on their own Profile page, and a phone number on their Phone page. Creates the sample
// users, each with a password of this run alone, which nothing signs in with.
async function setUp(browser: Browser) {
  expect(env.adminEmail, "the administrator the servers seed is not the sample's").toBe(administrator.email);
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

  await page.goto(`${env.adminUrl}/account/profile`);
  await page.locator("#givenName").fill(administrator.givenName);
  await page.locator("#familyName").fill(administrator.familyName);
  await page.locator("#username").fill(administrator.username);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Profile saved.", { exact: true })).toBeVisible();

  await page.goto(`${env.adminUrl}/account/phone`);
  await choose(page, "phoneCountryUniqueId", administrator.phoneCountry, new RegExp(`${administrator.phoneCountry} \\(\\+\\d+\\)$`));
  await page.locator("#phoneNumber").fill(administrator.phoneNumber);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Phone number saved.", { exact: true })).toBeVisible();

  for (const user of sampleUsers) {
    await submitNewUser(page, {
      email: user.email,
      givenName: user.givenName,
      familyName: user.familyName,
      password: randomBytes(24).toString("hex"),
    });
    await expect(page.getByText("User created.", { exact: true })).toBeVisible();
  }
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

// Whether a console page, at the viewport it has, scrolls: its sidebar's menu, which is pinned to the
// viewport and scrolls inside itself, or the page.
function scrolls(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const nav = document.querySelector(".app-sidebar .sidebar-nav")!;
    return nav.scrollHeight > nav.clientHeight || document.documentElement.scrollHeight > window.innerHeight;
  });
}

// Sets a console page's viewport to its width and to the smallest height at which the whole page
// shows with nothing scrolling: the taller of the sidebar, its head, every link of its menu and its
// footer, and the page beside it, the header and the main column to the end of its bottom padding.
// Both are measured in a viewport shorter than either, where neither column is stretched to fill it.
// The height found is checked: one pixel less, something scrolls.
async function fitConsolePage(page: Page) {
  await page.setViewportSize({ width: consoleWidth, height: 100 });
  const { sidebar, body } = await page.evaluate(() => {
    const height = (selector: string) => document.querySelector(selector)!.getBoundingClientRect().height;
    return {
      sidebar: height(".app-sidebar .sidebar-head") + document.querySelector(".app-sidebar .sidebar-nav")!.scrollHeight + height(".app-sidebar .sidebar-foot"),
      body: height(".app-body"),
    };
  });
  const height = Math.ceil(Math.max(sidebar, body));
  await page.setViewportSize({ width: consoleWidth, height: height - 1 });
  expect(await scrolls(page), `the page still shows whole ${height - 1} pixels tall: the height measured is not the smallest`).toBe(true);
  await page.setViewportSize({ width: consoleWidth, height });
  expect(await scrolls(page), `the page scrolls ${height} pixels tall: the height measured hides part of it`).toBe(false);
  await expect(page.locator(".app-sidebar .sidebar-foot")).toBeInViewport({ ratio: 1 });
  // The pointer rests on a corner the rounding makes transparent, so nothing shows hovered.
  await page.mouse.move(consoleWidth - 1, height - 1);
}

// The console's header names the administrator, as the sign-in that opened the session claimed them.
async function expectHeaderNamesTheAdministrator(page: Page) {
  await expect(page.locator(".app-header .user-menu-button .user-menu-name")).toHaveText(
    `${administrator.givenName} ${administrator.familyName}`,
  );
}

// The first page of the users list, with its paginator, each Subject cell showing the stand-in the
// sample list fixes for the user of its row in place of the subject the auth server drew (decision
// 2). Only the Subject cells' text is replaced, and only once every row's user is one of the sample.
async function usersList(page: Page): Promise<Buffer> {
  await page.goto(`${env.adminUrl}/admin/users`);
  await expectHeaderNamesTheAdministrator(page);
  await expect(page.getByRole("navigation", { name: "Pagination" })).toBeVisible();

  const standIns = Object.fromEntries([administrator, ...sampleUsers].map((user) => [user.email, user.subject]));
  const table = page.locator("#usersTable");
  const unknown = await table.evaluate((element, standIns) => {
    const table = element as HTMLTableElement;
    const column = [...table.tHead!.rows[0].cells].findIndex((cell) => cell.textContent!.trim() === "Subject");
    if (column < 0) return ["(no Subject column)"];
    const rows = [...table.tBodies[0].rows].map((row) => ({
      email: row.cells[0].querySelector("a")?.textContent!.trim() ?? "",
      subject: row.cells[column],
    }));
    const unknown = rows.filter((row) => !(row.email in standIns) || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(row.subject.textContent!.trim()));
    if (unknown.length > 0) return unknown.map((row) => `${row.email}: ${row.subject.textContent!.trim()}`);
    for (const row of rows) row.subject.textContent = standIns[row.email];
    return [];
  }, standIns);
  expect(unknown, "rows of the users list that are not a sample user's with a subject").toEqual([]);

  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(10);
  for (const row of await rows.all()) {
    const email = (await row.locator("td").first().locator("a").innerText()).trim();
    await expect(row.locator("td.cell-mono")).toHaveText(standIns[email]);
  }

  await fitConsolePage(page);
  return encodePng(roundCorners(await capture(page), cornerRadius), { alpha: true });
}

// The administrator's own Phone page, with the number the set-up session saved.
async function accountPhone(page: Page): Promise<Buffer> {
  await page.goto(`${env.adminUrl}/account/phone`);
  await expectHeaderNamesTheAdministrator(page);
  await expect(page.getByRole("combobox", { name: "Country" })).toHaveValue(new RegExp(`${administrator.phoneCountry} \\(\\+\\d+\\)$`));
  await expect(page.locator("#phoneNumber")).toHaveValue(administrator.phoneNumber);

  await fitConsolePage(page);
  return encodePng(roundCorners(await capture(page), cornerRadius), { alpha: true });
}

test("the screenshots", async ({ browser }) => {
  await setUp(browser);

  const context = await browser.newContext({ viewport: { width: signInWidth, height: 1000 } });
  const page = await context.newPage();
  const images = await signInPage(page);
  await submitPassword(page, env.adminEmail, env.adminPassword);
  await page.waitForURL(`${env.adminUrl}/admin/users`);
  images.set("screenshot-users.png", await usersList(page));
  images.set("screenshot-account-phone.png", await accountPhone(page));
  await context.close();

  expect([...images.keys()].sort(), "the images captured are not the ones images.json lists").toEqual([...listed].sort());
  for (const [name, png] of images) writeFileSync(path.join(outDir(), name), png);
  writeFileSync(path.join(outDir(), "images.txt"), listed.map((name) => `${name}\n`).join(""));
});
