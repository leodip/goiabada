// RFC 6749 sections 2, 3.1.2 and 10.1 at dynamic client registration (RFC 7591): a public client is
// issued no secret (10.1 MUST NOT), a confidential one a secret that cannot be guessed (10.10), in an
// answer never cached (5.1), and a redirect URI must be absolute with no fragment (3.1.2). A system test
// because registration is a global switch, put back afterwards. RFC 7591 section 5 too: a policy_uri
// or tos_uri is kept only on a redirect URI's scheme and host, and the answer carries what was kept. Clients made in the admin console are
// covered by ../admin-console/clients/: a duplicate identifier, a new secret, a switch to public.
import { clientIdFromList, clientUrl, deleteClient } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectNoStore, readAnswer } from "../../lib/rfc6749";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../lib/settings";

test("a public client is registered with no secret, a confidential one with a long secret never cached, and a bad redirect URI is refused", async ({
  page,
  request,
}) => {
  const register = async (metadata: Record<string, unknown>) =>
    readAnswer(await request.post(`${env.authUrl}/connect/register`, { data: { client_name: "e2e rfc6749", ...metadata }, failOnStatusCode: false }));
  const registered: string[] = [];

  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      await fillSettingsForm(page, { dynamicClientRegistrationEnabled: true });
      await saveSettings(page);

      const publicClient = await register({ redirect_uris: ["http://127.0.0.1:8765/callback"], token_endpoint_auth_method: "none" });
      expect(publicClient.status, publicClient.text).toBe(201);
      registered.push(publicClient.body.client_id as string);
      expect(publicClient.body.client_secret).toBeUndefined();

      const confidential = await register({ redirect_uris: ["https://app.example.com/callback"], token_endpoint_auth_method: "client_secret_basic" });
      expect(confidential.status, confidential.text).toBe(201);
      registered.push(confidential.body.client_id as string);
      // 128 bits take at least 22 characters of a 64-character alphabet; this server issues 60.
      expect(confidential.body.client_secret).toMatch(/^[\x21-\x7E]{22,}$/);
      expectNoStore(confidential);

      for (const uri of ["https://app.example.com/callback#section", "/callback"]) {
        await test.step(uri, async () => {
          const refused = await register({ redirect_uris: [uri], token_endpoint_auth_method: "client_secret_basic" });
          expect(refused.status, refused.text).toBe(400);
          expect(refused.body.error).toBe("invalid_redirect_uri");
          expect(refused.body.client_id).toBeUndefined();
        });
      }
    });
  } finally {
    for (const identifier of registered) await deleteClient(page, await clientIdFromList(page, identifier));
  }
});

test("a policy_uri on the redirect URI's host is kept, a tos_uri on another host is dropped, and the client is registered", async ({
  page,
  request,
}) => {
  const registered: string[] = [];
  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      await fillSettingsForm(page, { dynamicClientRegistrationEnabled: true });
      await saveSettings(page);

      const registration = await readAnswer(
        await request.post(`${env.authUrl}/connect/register`, {
          data: {
            client_name: "e2e rfc7591 documents",
            redirect_uris: ["https://app.example.com/callback"],
            policy_uri: "https://app.example.com/privacy",
            tos_uri: "https://elsewhere.example.org/terms",
          },
          failOnStatusCode: false,
        }),
      );
      expect(registration.status, registration.text).toBe(201);
      registered.push(registration.body.client_id as string);
      expect(registration.body.policy_uri).toBe("https://app.example.com/privacy");
      expect(registration.body).not.toHaveProperty("tos_uri");

      // What was stored is what the client's Settings tab shows.
      await page.goto(clientUrl(await clientIdFromList(page, registration.body.client_id as string), "settings"));
      await expect(page.locator('input[name="privacyPolicyUrl"]')).toHaveValue("https://app.example.com/privacy");
      await expect(page.locator('input[name="termsOfServiceUrl"]')).toHaveValue("");
    });
  } finally {
    for (const identifier of registered) await deleteClient(page, await clientIdFromList(page, identifier));
  }
});

