// The password page's Keep me signed in box, under the deployment's default, Let each user choose
// (#743 decisions 2 and 4): the page shows it unticked, with its note, and the answer decides whether
// the auth server's sign-in cookie outlives the browser. Nothing global changes: the setting is only
// read.
import { expect, test } from "../../lib/fixtures";
import { env } from "../../lib/environment";
import { openSignIn, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { readSettingsForm } from "../../lib/settings";
import { browserSignInClient } from "../../lib/test-clients";

const sessionsPath = "/admin/settings/sessions";

// On https the auth server's session cookie carries the __Host- prefix.
const signInCookie = "__Host-authserver";

test("the password page asks Keep me signed in with an unticked box and its note", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const { context, page: signIn } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  try {
    const box = signIn.getByRole("checkbox", { name: "Keep me signed in", exact: true });
    await expect(box).toBeVisible();
    await expect(box).not.toBeChecked();
    await expect(box).toHaveAccessibleDescription("Uses a cookie to keep you signed in after you close the browser.");
  } finally {
    await context.close();
  }
});

for (const tick of [true, false]) {
  test(`${tick ? "ticked" : "unticked"}, the sign-in cookie ${tick ? "has an expiry" : "is a session cookie"}`, async ({
    page,
    browser,
    clients,
    users,
  }) => {
    const user = await users.create();
    const { client } = await browserSignInClient(page, clients);
    const idleTimeout = Number((await readSettingsForm(page, sessionsPath)).userSessionIdleTimeoutInSeconds);
    expect(idleTimeout).toBeGreaterThan(0);

    const { context, page: signIn } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
    try {
      if (tick) await signIn.getByRole("checkbox", { name: "Keep me signed in", exact: true }).check();
      await submitPassword(signIn, user.email, user.password);
      await signIn.waitForURL((url) => url.href.startsWith(testRedirectUri));

      const cookie = (await context.cookies(env.authUrl)).find((c) => c.name === signInCookie);
      expect(cookie, `no ${signInCookie} cookie`).toBeDefined();
      if (tick) {
        expect(cookie!.expires * 1000, "an expiry, the idle timeout from now").toBeGreaterThan(Date.now() + (idleTimeout - 600) * 1000);
        expect(cookie!.expires * 1000).toBeLessThan(Date.now() + (idleTimeout + 60) * 1000);
      } else {
        expect(cookie!.expires, "a session cookie, which ends with the browser").toBe(-1);
      }
    } finally {
      await context.close();
    }
  });
}
