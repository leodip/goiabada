// RFC 9700 at dynamic client registration (RFC 7591). Section 2.6: no http redirect URI but on
// loopback, for any client. Section 4.15.1: a client does not choose its own client_id, which could
// pass for a user's subject in a client credentials token. A system test because registration is a
// global switch, put back afterwards; the clients it registers are deleted.
import { randomUUID } from "node:crypto";
import type { APIRequestContext, Page } from "@playwright/test";
import { idFromListLink } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { readAnswer } from "../../lib/rfc6749";
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
    for (const identifier of registered) {
      const id = await idFromListLink(page, `${env.adminUrl}/admin/clients`, identifier, "Manage");
      await page.goto(`${env.adminUrl}/admin/clients/${id}/delete`);
      await page.locator('input[name="clientIdentifier"]').fill(identifier);
      await page.getByRole("button", { name: "Delete", exact: true }).click();
      await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
    }
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
