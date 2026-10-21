// RFC 6749 sections 2, 3.1.2 and 10.1 at dynamic client registration (RFC 7591): a public client is
// issued no secret (10.1 MUST NOT), a confidential one a secret that cannot be guessed (10.10), in an
// answer never cached (5.1), and a redirect URI must be absolute with no fragment (3.1.2). A system test
// because registration is a global switch, put back afterwards. Clients made in the admin console are
// covered by ../admin-console/clients/: a duplicate identifier, a new secret, a switch to public.
import { clientIdFromList, deleteClient } from "../../lib/admin-console";
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
