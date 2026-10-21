// The admin console refreshing one administrator's tokens from two tabs at once (#621). The console
// refreshes on whichever request finds the access token within 30 seconds of its expiry, or within
// half its lifetime when that is shorter, and the auth server rotates refresh tokens strictly, so two
// requests of one session that both refreshed presented the same refresh token: the second was
// refused or read as a replay, and the administrator was signed out. The console runs one refresh per
// session at a time now, and a request that waited carries on with what the first stored, its own
// session included, so a page that saves the session after it, for a "saved" message, does not put
// the rotated-away refresh token back.
//
// With the global token lifetime at 20 seconds a token set is due in its last 10, so each round waits
// into the refresh window of the set the round before stored, then fires the two tabs' requests at
// once: every one of them finds the token due, and they overlap on purpose. A freshly rotated set is
// never due, so the requests that waited carry the one answer rather than rotating it again. Whether
// they meet inside one refresh is not up to a browser, so a few rounds; the unit tier holds the
// orderings themselves (middleware_jwt_refresh_serialization_test.go). Runs alone, since it changes
// the lifetime every client without one of its own uses, and puts it back.
import type { Page } from "@playwright/test";
import { groupUrl, saveAndExpectSaved, signInAsAdmin } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { auditRows } from "../../lib/sessions";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";

const tokens = "/admin/settings/tokens";
const lifetimeSeconds = 20;
const replays = `${env.adminUrl}/admin/settings/audit-log-viewer?auditEvent=refresh_token_replay_detected`;

// The text of the newest refresh_token_replay_detected row, or null when there is none: its token
// identifiers make it unique, so a replay audited later shows as another newest row.
async function newestReplay(page: Page): Promise<string | null> {
  await page.goto(replays);
  const rows = auditRows(page, {});
  if ((await rows.count()) === 0) return null;
  return rows.first().innerText();
}

// Waits until the token set the console stored at some moment between storedFrom and storedBy, both
// Date.now() readings, is due for its refresh, in the last half of its lifetime, and fails when that
// moment is past its expiry already: a round fired then would find an expired token, not a due one.
async function waitIntoRefreshWindow(page: Page, storedFrom: number, storedBy: number) {
  const opens = storedBy + (lifetimeSeconds / 2) * 1000 + 500;
  const closes = storedFrom + lifetimeSeconds * 1000;
  expect(Date.now(), "the round is ready before the token set is due").toBeLessThan(opens);
  expect(opens, "the refresh window is reachable before the token set expires").toBeLessThan(closes - 1_000);
  await page.waitForTimeout(opens - Date.now());
}

test("two tabs of one console session refreshing at once both stay signed in", async ({ page, browser, groups }) => {
  test.setTimeout(150_000);
  const group = await groups.create({ description: "round 0" });
  const replayBefore = await newestReplay(page);

  await withSettingsRestored(page, tokens, async () => {
    await page.goto(`${env.adminUrl}${tokens}`);
    await fillSettingsForm(page, { tokenExpirationInSeconds: String(lifetimeSeconds) });
    await saveSettings(page);

    // Signed in after the change, so the session's tokens last 20 seconds; a browser of its own, so its
    // refreshes are this test's alone.
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      const first = await context.newPage();
      // The set the latest refresh stored was stored between these two moments.
      let storedFrom = Date.now();
      await signInAsAdmin(first);
      let storedBy = Date.now();
      const second = await context.newPage();

      for (let round = 1; round <= 3; round++) {
        // Loaded before the set is due, so this request carries it and refreshes nothing.
        await first.goto(groupUrl(group.id, "settings"));
        await first.locator('input[name="description"]').fill(`round ${round}`);
        await waitIntoRefreshWindow(first, storedFrom, storedBy);

        // The save sets a flash and saves the session, while the other tab and two background requests
        // of the same session refresh beside it.
        storedFrom = Date.now();
        const [, , listed, account] = await Promise.all([
          saveAndExpectSaved(first, "Settings saved."),
          second.goto(`${env.adminUrl}/admin/users`),
          context.request.get(`${env.adminUrl}/admin/groups`),
          context.request.get(`${env.adminUrl}/account/profile`),
        ]);
        storedBy = Date.now();

        await expect(first, `round ${round}: the saving tab is still signed in`).toHaveURL(groupUrl(group.id, "settings"));
        await expect(second, `round ${round}: the other tab is still signed in`).toHaveURL(`${env.adminUrl}/admin/users`);
        for (const response of [listed, account]) {
          expect(response.url(), `round ${round}: a background request is still signed in`).toMatch(new RegExp(`^${env.adminUrl}/`));
          expect(response.status(), `round ${round}: ${response.url()}`).toBe(200);
        }
      }

      // One more request on each tab after the last round, in the window of the set it stored, renews
      // again from what the rounds stored: a refresh token put back by a save, or contained as a replay,
      // would sign the session out here.
      await waitIntoRefreshWindow(first, storedFrom, storedBy);
      await Promise.all([first.reload(), second.reload()]);
      await expect(first).toHaveURL(groupUrl(group.id, "settings"));
      await expect(first.locator('input[name="description"]')).toHaveValue("round 3");
      await expect(second).toHaveURL(`${env.adminUrl}/admin/users`);
    } finally {
      await context.close();
    }
  });

  expect(await newestReplay(page), "no refresh-token replay was audited").toBe(replayBefore);
});
