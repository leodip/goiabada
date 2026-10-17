// Settings - two administrators saving different settings pages at once. Each page's save writes its
// own settings onto the row as stored when it runs (#407), so neither puts back what the other just
// changed. Runs alone, and puts the settings back.
import { signInAsAdmin } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { fillSettingsForm, readSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";

const sessions = "/admin/settings/sessions";
const tokens = "/admin/settings/tokens";

test("two administrators saving different settings pages at once both keep their change", async ({ page, browser }) => {
  // The second administrator signs in from a browser of their own, so each save runs in its own console
  // session and their one-time messages and token refreshes never cross.
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const other = await context.newPage();
  try {
    await signInAsAdmin(other);
    await withSettingsRestored(page, sessions, () =>
      withSettingsRestored(page, tokens, async () => {
        // Whether the two saves overlap at the auth server is not up to a browser, so a few rounds,
        // each with values of its own: a save written back over reads as the round before's value.
        for (let round = 1; round <= 4; round++) {
          const idleTimeout = String(3000 + round);
          const tokenExpiration = String(600 + round);
          await Promise.all([page.goto(`${env.adminUrl}${sessions}`), other.goto(`${env.adminUrl}${tokens}`)]);
          await fillSettingsForm(page, { userSessionIdleTimeoutInSeconds: idleTimeout });
          await fillSettingsForm(other, { tokenExpirationInSeconds: tokenExpiration });
          await Promise.all([saveSettings(page), saveSettings(other)]);

          expect(await readSettingsForm(page, sessions), `round ${round}: the sessions save`).toMatchObject({
            userSessionIdleTimeoutInSeconds: idleTimeout,
          });
          expect(await readSettingsForm(page, tokens), `round ${round}: the tokens save`).toMatchObject({
            tokenExpirationInSeconds: tokenExpiration,
          });
        }
      }),
    );
  } finally {
    await context.close();
  }
});
