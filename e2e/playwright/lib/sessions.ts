// A user's sessions as the admin console lists them, the audit row each one's end leaves, and a
// sign-in started again in a browser that may still hold one.
import { expect, type BrowserContext, type Page } from "@playwright/test";
import { userUrl } from "./admin-console";
import { testRedirectUri } from "./browser-sign-in";
import { admitted, answerOf } from "./admission";
import { env } from "./environment";

// The ids of the user's sessions, from the Users -> Sessions page, each row's End session button
// carrying its session's.
export async function sessionIds(page: Page, userId: number): Promise<string[]> {
  await page.goto(userUrl(userId, "sessions"));
  return page.locator("#sessionsTable tbody button[data-end-session]").evaluateAll((buttons) => buttons.map((b) => (b as HTMLElement).dataset.endSession!));
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
  await admitted(() => page.goto(`${env.authUrl}/auth/authorize?${query}`), answerOf);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri) || url.pathname === "/auth/pwd");
  return { page, landed: page.url().startsWith(testRedirectUri) ? "client" : "password" };
}

// Waits for the deleted_user_session row of this session with this reason, among the newest pages of
// that event: tests running beside this one add rows of their own.
export async function expectSessionDeleted(page: Page, sessionId: string, reason: string) {
  await expect
    .poll(
      async () => {
        for (let n = 1; n <= 5; n++) {
          await page.goto(`${env.adminUrl}/admin/settings/audit-log-viewer?auditEvent=deleted_user_session&page=${n}`);
          if ((await auditRows(page, { reason, user_session_id: sessionId }).count()) > 0) return true;
        }
        return false;
      },
      { message: `deleted_user_session reason ${reason}, user_session_id ${sessionId}` },
    )
    .toBe(true);
}

// The audit log's rows whose details hold each of these keys with exactly this value: the page lists
// an event's details as a list of key and value.
export function auditRows(page: Page, details: Record<string, string>) {
  let rows = page.locator("#auditLogsTable tbody tr");
  for (const [key, value] of Object.entries(details)) {
    const pair = page
      .locator("dl > div")
      .filter({ has: page.locator("dt", { hasText: exactly(key) }) })
      .filter({ has: page.locator("dd", { hasText: exactly(value) }) });
    rows = rows.filter({ has: pair });
  }
  return rows;
}

function exactly(text: string): RegExp {
  return new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);
}
