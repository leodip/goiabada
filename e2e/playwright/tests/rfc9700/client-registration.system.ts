// RFC 9700 at dynamic client registration (RFC 7591). Section 2.6: no http redirect URI but on
// loopback, for any client. Section 4.15.1: a client does not choose its own client_id, which could
// pass for a user's subject in a client credentials token. Section 4.11.2: a client anyone could
// register is not where a declined authorization sends the user. A system test because registration
// is a global switch, put back afterwards; the clients it registers are deleted.
import { randomUUID } from "node:crypto";
import type { APIRequestContext, Page } from "@playwright/test";
import { clientIdFromList, deleteClient } from "../../lib/admin-console";
import { submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { authorizeEndpoint, codeRequest, emptyBrowser, readAnswer } from "../../lib/rfc6749";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";

async function register(request: APIRequestContext, metadata: Record<string, unknown>) {
  return readAnswer(await request.post(`${env.authUrl}/connect/register`, { data: { client_name: "e2e rfc9700", ...metadata }, failOnStatusCode: false }));
}

// Runs body with registration on, then deletes every client it registered and puts the setting back.
async function withRegistration(page: Page, body: (registered: string[]) => Promise<void>) {
  const registered: string[] = [];
  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      await fillSettingsForm(page, { dynamicClientRegistrationEnabled: true });
      await saveSettings(page);
      await body(registered);
    });
  } finally {
    for (const identifier of registered) await deleteClient(page, await clientIdFromList(page, identifier));
  }
}

test("an http redirect URI is registered only on loopback, for a confidential client and a public one (section 2.6 MUST NOT)", async ({
  page,
  request,
}) => {
  await withRegistration(page, async (registered) => {
    for (const method of ["client_secret_basic", "none"]) {
      await test.step(method, async () => {
        const refused = await register(request, { redirect_uris: ["http://app.example.com/callback"], token_endpoint_auth_method: method });
        expect(refused.status, refused.text).toBe(400);
        expect(refused.body.error).toBe("invalid_redirect_uri");
        expect(refused.body.client_id).toBeUndefined();

        const loopback = await register(request, { redirect_uris: ["http://127.0.0.1:8765/callback"], token_endpoint_auth_method: method });
        expect(loopback.status, loopback.text).toBe(201);
        registered.push(loopback.body.client_id as string);
      });
    }
  });
});

test("a registration cannot choose its client_id: the server assigns one (section 4.15.1 SHOULD NOT)", async ({ page, request }) => {
  await withRegistration(page, async (registered) => {
    // Shaped like a user's subject, which is what would make a chosen one dangerous.
    const chosen = randomUUID();
    const answer = await register(request, {
      client_id: chosen,
      redirect_uris: ["https://app.example.com/callback"],
      token_endpoint_auth_method: "client_secret_basic",
    });
    expect(answer.status, answer.text).toBe(201);
    registered.push(answer.body.client_id as string);
    expect(answer.body.client_id).not.toBe(chosen);
  });
});

// RFC 9700 4.11.2's second attack: a client registered to point at its own host gets a user to
// decline it, and the error redirect would deliver the browser there. The consent screen says the
// client registered itself, and declining it ends on the auth server's page. The client is
// confidential: one registered as public may not use an https redirect URI at all.
test("declining a client that registered itself sends the user nowhere: the page names where it asked to send them (section 4.11.2 MUST)", async ({
  page,
  browser,
  request,
  users,
}) => {
  const user = await users.create();
  await withRegistration(page, async (registered) => {
    const answer = await register(request, { redirect_uris: [testRedirectUri], token_endpoint_auth_method: "client_secret_basic" });
    expect(answer.status, answer.text).toBe(201);
    const clientId = answer.body.client_id as string;
    registered.push(clientId);

    const context = await emptyBrowser(browser);
    const tab = await context.newPage();
    await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(clientId).params)}`);
    await submitPassword(tab, user.email, user.password);
    await expect(tab).toHaveURL(/\/auth\/consent/);
    await expect(tab.getByText("This application registered itself and has not been verified.")).toBeVisible();
    await tab.getByRole("button", { name: "Don't allow" }).click();

    await expect(tab.getByRole("heading", { name: "You have not been sent anywhere" })).toBeVisible();
    await expect(tab.getByText("e2e rfc9700", { exact: true })).toBeVisible();
    await expect(tab.getByText(new URL(testRedirectUri).host, { exact: true })).toBeVisible();
    await expect(tab.getByText("It registered itself with this server, so nobody here has checked who it is or where it wants to send you.")).toBeVisible();
    expect(new URL(tab.url()).origin).toBe(env.authUrl);
    await context.close();
  });
});
