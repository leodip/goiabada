// Settings - Turnstile: the Cloudflare Turnstile challenge's switch and widget keys (#642 decision
// 11). The keys are Cloudflare's public test keys, which work on any host name. Runs alone, and every
// test starts and ends with the challenge off and no keys stored, as the baseline has it
// (lib/settings.ts).
import type { Page } from "@playwright/test";
import { cancelDialog, confirmDialog, expectRefusal } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, readSettingsForm, saveSettings } from "../../../lib/settings";

const turnstile = "/admin/settings/turnstile";
const siteKey = "1x00000000000000000000AA";
const otherSiteKey = "2x00000000000000000000AB";
const secretKey = "1x0000000000000000000000000000000AA";

// The question asked before the challenge is turned on names the way back from it.
const turnOnQuestion = /recover --disable-turnstile/;

// Turns the challenge off and removes both keys, which a save does only with the removal ticked.
async function clearTurnstile(page: Page) {
  await page.goto(`${env.adminUrl}${turnstile}`);
  const hasSecretKey = (await page.locator("#clearTurnstileSecretKey").count()) > 0;
  const enabled = await page.locator("#turnstileEnabled").isChecked();
  const storedSiteKey = await page.locator("#turnstileSiteKey").inputValue();
  if (!hasSecretKey && !enabled && storedSiteKey === "") return;
  await fillSettingsForm(page, {
    turnstileEnabled: false,
    turnstileSiteKey: "",
    ...(hasSecretKey ? { clearTurnstileSecretKey: true } : {}),
  });
  await saveSettings(page);
  // A fresh page, with no notice left from this save for the next one to be mistaken for.
  await page.goto(`${env.adminUrl}${turnstile}`);
}

// Clicks Save, answers the question asked before the challenge is turned on when the case expects
// it, and waits for the page the save answers with: the one it was clicked on already says "Settings
// saved." after an earlier save.
async function save(page: Page, { asks = false }: { asks?: boolean } = {}) {
  const answered = page.waitForEvent("load");
  await page.locator("#btnSave").click();
  if (asks) await confirmDialog(page, turnOnQuestion);
  await answered;
}

// The secret key's label carries the Saved or Not set tag.
function secretKeyTag(page: Page) {
  return page.locator('label[for="turnstileSecretKey"] .tag');
}

test.beforeEach(async ({ page }) => {
  await clearTurnstile(page);
});

test.afterEach(async ({ page }) => {
  await clearTurnstile(page);
});

test("the page sits beside Email, and the secret key is write-only: saved, kept when left empty, removed only by its box", async ({ page }) => {
  await page.goto(`${env.adminUrl}/admin/settings/email`);
  await page.getByRole("link", { name: "Turnstile", exact: true }).click();
  await expect(page).toHaveURL(`${env.adminUrl}${turnstile}`);
  await expect(page.getByRole("link", { name: "Turnstile", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Turnstile");

  // Nothing stored: no secret key, so nothing to remove.
  await expect(secretKeyTag(page)).toHaveText("Not set");
  await expect(page.locator("#clearTurnstileSecretKey")).toHaveCount(0);
  await expect(page.locator("#turnstileSecretKey")).not.toHaveAttribute("placeholder", /.*/);

  // The keys are saved with the challenge off, which asks nothing.
  await fillSettingsForm(page, { turnstileSiteKey: siteKey, turnstileSecretKey: secretKey });
  await save(page);
  await expect(page.getByText("Settings saved.", { exact: true })).toBeVisible();
  await expect(secretKeyTag(page)).toHaveText("Saved");
  await expect(page.locator("#turnstileSecretKey")).toHaveValue("");
  await expect(page.locator("#turnstileSecretKey")).toHaveAttribute("placeholder", "Leave empty to keep the saved secret key");
  await expect(page.locator("#turnstileSiteKey")).toHaveValue(siteKey);
  await expect(page.locator("#turnstileEnabled")).not.toBeChecked();

  // Turning the challenge on asks first, and the empty box keeps the saved secret key.
  await page.locator("#turnstileEnabled").check();
  await save(page, { asks: true });
  await expect(page.getByText("Settings saved.", { exact: true })).toBeVisible();
  await expect(page.locator("#turnstileEnabled")).toBeChecked();
  await expect(secretKeyTag(page)).toHaveText("Saved");

  // A save that keeps it on asks nothing: a question would leave the save unsent, and the wait
  // for its page unanswered.
  await save(page);
  await expect(page.getByText("Settings saved.", { exact: true })).toBeVisible();
  await expect(page.locator("#turnstileEnabled")).toBeChecked();

  // Ticking the removal disables the box and says what the save will do; turned off, it is removed,
  // and the site key stays.
  await page.locator("#turnstileEnabled").uncheck();
  await page.locator("#clearTurnstileSecretKey").check();
  await expect(page.locator("#turnstileSecretKey")).toBeDisabled();
  await expect(page.getByText("The saved secret key will be deleted when you save.")).toBeVisible();
  await page.locator("#clearTurnstileSecretKey").uncheck();
  await expect(page.locator("#turnstileSecretKey")).toBeEnabled();
  await expect(page.getByText("The saved secret key will be deleted when you save.")).toBeHidden();
  await page.locator("#clearTurnstileSecretKey").check();
  await save(page);
  await expect(page.getByText("Settings saved.", { exact: true })).toBeVisible();
  await expect(secretKeyTag(page)).toHaveText("Not set");
  await expect(page.locator("#clearTurnstileSecretKey")).toHaveCount(0);
  await expect(page.locator("#turnstileEnabled")).not.toBeChecked();
  await expect(page.locator("#turnstileSiteKey")).toHaveValue(siteKey);
});

test("Cancel on turning the challenge on keeps it off", async ({ page }) => {
  await fillSettingsForm(page, { turnstileSiteKey: siteKey, turnstileSecretKey: secretKey });
  await save(page);
  const before = await readSettingsForm(page, turnstile);

  await page.locator("#turnstileEnabled").check();
  await page.locator("#btnSave").click();
  await cancelDialog(page, turnOnQuestion);

  expect(await readSettingsForm(page, turnstile)).toEqual(before);
  await expect(page.locator("#turnstileEnabled")).not.toBeChecked();
});

test("the auth server's refusals are shown at their fields, and nothing refused is saved", async ({ page }) => {
  // Turned on without a site key: the typed secret key comes back in its box.
  await fillSettingsForm(page, { turnstileEnabled: true, turnstileSecretKey: secretKey });
  await save(page, { asks: true });
  await expectRefusal(page, "turnstile-error", "turnstileSiteKey", "Enter the site key to turn the Turnstile challenge on.");
  await expect(page.locator("#turnstileSecretKey")).toHaveValue(secretKey);

  // Turned on without a secret key.
  await page.goto(`${env.adminUrl}${turnstile}`);
  await fillSettingsForm(page, { turnstileEnabled: true, turnstileSiteKey: siteKey });
  await save(page, { asks: true });
  await expectRefusal(page, "turnstile-error", "turnstileSecretKey", "Enter the secret key to turn the Turnstile challenge on.");

  // A site key longer than its column.
  await page.goto(`${env.adminUrl}${turnstile}`);
  await fillSettingsForm(page, { turnstileSiteKey: "x".repeat(129) });
  await page.locator("#btnSave").click();
  await expectRefusal(page, "turnstile-error", "turnstileSiteKey", "The site key can't be longer than 128 characters.");

  // Nothing refused was saved.
  await page.goto(`${env.adminUrl}${turnstile}`);
  await expect(page.locator("#turnstileEnabled")).not.toBeChecked();
  await expect(page.locator("#turnstileSiteKey")).toHaveValue("");
  await expect(secretKeyTag(page)).toHaveText("Not set");

  // With both keys saved and the challenge on, the site key is not changed without its secret key,
  // and the secret key is not removed.
  await fillSettingsForm(page, { turnstileEnabled: true, turnstileSiteKey: siteKey, turnstileSecretKey: secretKey });
  await save(page, { asks: true });
  await expect(page.getByText("Settings saved.", { exact: true })).toBeVisible();
  await fillSettingsForm(page, { turnstileSiteKey: otherSiteKey });
  await page.locator("#btnSave").click();
  await expectRefusal(page, "turnstile-error", "turnstileSecretKey", "The site key has changed: enter the secret key again, or remove it.");
  await expect(page.locator("#turnstileSiteKey")).toHaveValue(otherSiteKey);

  await page.goto(`${env.adminUrl}${turnstile}`);
  await fillSettingsForm(page, { clearTurnstileSecretKey: true });
  await page.locator("#btnSave").click();
  await expectRefusal(page, "turnstile-error", "clearTurnstileSecretKey", "The secret key can't be removed while the Turnstile challenge is on.");
  await expect(page.locator("#clearTurnstileSecretKey")).toBeChecked();
  await expect(page.locator("#turnstileSecretKey")).toBeDisabled();

  await page.goto(`${env.adminUrl}${turnstile}`);
  await expect(page.locator("#turnstileEnabled")).toBeChecked();
  await expect(page.locator("#turnstileSiteKey")).toHaveValue(siteKey);
  await expect(secretKeyTag(page)).toHaveText("Saved");
});
