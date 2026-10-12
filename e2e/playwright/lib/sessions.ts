// A user's sessions as the admin console lists them, the audit row each one's end leaves, and a
// sign-in started again in a browser that may still hold one.
import { expect, type BrowserContext, type Page } from "@playwright/test";
import { userUrl } from "./admin-console";
import { testRedirectUri } from "./browser-sign-in";
import { env } from "./environment";

// The ids of the user's sessions, from the Users -> Sessions page.
export async function sessionIds(page: Page, userId: number): Promise<string[]> {
  await page.goto(userUrl(userId, "sessions"));
  return page.locator('table tbody span[id^="loadingIcon"]').evaluateAll((spans) => spans.map((s) => s.id.slice("loadingIcon".length)));
}

// Starts a sign-in through the client in a new tab of this browser and says where it lands: straight
// back at the client (a session signed the user in), or on the password form. The caller closes the tab.
export async function authorizeAgain(context: BrowserContext, clientId: string): Promise<{ page: Page; landed: "client" | "password" }> {
  const page = await context.newPage();
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: "openid",
    state: "again",
    // RFC 7636's example challenge: this sign-in's code is never redeemed.
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
  });
  await page.goto(`${env.authUrl}/auth/authorize?${query}`);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/pwd");
  return { page, landed: page.url().startsWith(testRedirectUri) ? "client" : "password" };
}

// Waits for the deleted_user_session row of this session with this reason, among the newest pages of
// that event: tests running beside this one add rows of their own.
export async function expectSessionDeleted(page: Page, sessionId: string, reason: string) {
  const details = `"reason":"${reason}","user_session_id":${sessionId}}`;
  await expect
    .poll(
      async () => {
        for (let n = 1; n <= 5; n++) {
          await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?auditEvent=deleted_user_session&page=${n}`);
          if ((await page.locator(`td.audit-details[data-details$='${details}']`).count()) > 0) return true;
        }
        return false;
      },
      { message: `deleted_user_session ${details}` },
    )
    .toBe(true);
}
