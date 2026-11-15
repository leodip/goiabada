// The Authentication tab of a client that registered itself as confidential names the
// token_endpoint_auth_method it is held to, and that a secret sent the other way is refused; a
// client not held to one method shows no such line, and the switch to public clears it (#708
// decision 5). A system test because registering a client needs dynamic client registration on, a
// global switch, put back afterwards. The rest of the tab is covered by authentication.spec.ts.
import { clientIdFromList, clientUrl, confirmDialog, deleteClient } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { readAnswer } from "../../../lib/rfc6749";
import { fillSettingsForm, saveSettings, withSettingsRestored } from "../../../lib/settings";

const heldToBasic =
  "This client registered itself for client_secret_basic, so it must send its secret in the Authorization header. A secret sent in the request body is refused.";
const heldToPost =
  "This client registered itself for client_secret_post, so it must send its secret in the request body. A secret sent in the Authorization header is refused.";

test("a self-registered confidential client's tab names its method, and the switch to public clears it", async ({
  page,
  request,
  clients,
}) => {
  const registered: string[] = [];
  const line = page.locator("#registered-method");
  try {
    await withSettingsRestored(page, "/admin/settings/general", async () => {
      await fillSettingsForm(page, { dynamicClientRegistrationEnabled: true });
      await saveSettings(page);

      const register = async (method: string) => {
        const answer = await readAnswer(
          await request.post(`${env.authUrl}/connect/register`, {
            data: { client_name: "e2e registered method tab", grant_types: ["client_credentials"], token_endpoint_auth_method: method },
            failOnStatusCode: false,
          }),
        );
        expect(answer.status, answer.text).toBe(201);
        const identifier = answer.body.client_id as string;
        registered.push(identifier);
        return clientIdFromList(page, identifier);
      };

      const basicId = await register("client_secret_basic");
      const postId = await register("client_secret_post");

      await test.step("held to client_secret_basic", async () => {
        await page.goto(clientUrl(basicId, "authentication"));
        await expect(line).toHaveText(heldToBasic);
      });

      await test.step("held to client_secret_post, until the switch to public", async () => {
        await page.goto(clientUrl(postId, "authentication"));
        await expect(line).toHaveText(heldToPost);

        await page.getByRole("radio", { name: "Public", exact: true }).check();
        // The line is in the confidential client's part of the tab, hidden with it.
        await expect(line).toBeHidden();
        await page.locator("#btnSave").click();
        await confirmDialog(page, "You're making the client public");
        await expect(page.getByText("Authentication saved.")).toBeVisible();
        await expect(line).toHaveCount(0);

        await page.getByRole("radio", { name: "Confidential", exact: true }).check();
        await expect(page.locator("#clientSecret")).not.toHaveValue("");
        await page.locator("#btnSave").click();
        await confirmDialog(page, "You're making the client confidential");
        await expect(page.getByText("Authentication saved.")).toBeVisible();
        // Switched back, it may use either method, so the tab names none.
        await expect(line).toHaveCount(0);
      });
    });
  } finally {
    for (const identifier of registered) await deleteClient(page, await clientIdFromList(page, identifier));
  }

  await test.step("a client an administrator created names no method", async () => {
    const created = await clients.create();
    await page.goto(clientUrl(created.id, "authentication"));
    await expect(page.locator("#clientSecret")).toBeAttached();
    await expect(line).toHaveCount(0);
  });
});
