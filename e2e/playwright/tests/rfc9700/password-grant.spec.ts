// RFC 9700 section 2.4: the resource owner password credentials grant MUST NOT be used. It exposes
// the user's password to the client, and cannot ask for a second factor. Goiabada keeps it for
// clients an administrator turns it on for; these check that nobody else gets it, and that a user
// with an authenticator never does, since the grant would sign them in on the password alone.
import { clientUrl, readClientSecret } from "../../lib/admin-console";
import { submitPassword } from "../../lib/browser-sign-in";
import { expect, test } from "../../lib/fixtures";
import { passwordToken } from "../../lib/oauth";
import { authorizeEndpoint, basicAuth, codeRequest, emptyBrowser, expectTokenError, postToken } from "../../lib/rfc6749";
import { browserSignInClient, passwordGrantClient } from "../../lib/test-clients";
import { freshTotp } from "../../lib/totp";

test("a client made with the defaults may not use the password grant (section 2.4)", async ({ page, clients, users, request }) => {
  const user = await users.create();
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);

  const answer = await postToken(
    request,
    { grant_type: "password", username: user.email, password: user.password, scope: "openid" },
    { headers: { Authorization: basicAuth(client.identifier, secret) } },
  );
  expectTokenError(answer, "unauthorized_client");
});

test("a user with an authenticator is refused the password grant, which cannot ask for the code (section 2.4)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const withAuthenticator = await users.create();
  const without = await users.create();

  // The user enrols an authenticator, at a client that requires one.
  const { client: strict } = await browserSignInClient(page, clients);
  await page.goto(clientUrl(strict.id, "settings"));
  await page.locator('select[name="defaultAcrLevel"]').selectOption("urn:goiabada:level2_mandatory");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Settings saved.")).toBeVisible();
  const context = await emptyBrowser(browser);
  const tab = await context.newPage();
  await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(strict.identifier).params)}`);
  await submitPassword(tab, withAuthenticator.email, withAuthenticator.password);
  await expect(tab).toHaveURL(/\/auth\/otp/);
  await tab.locator('input[name="otp"]').fill(await freshTotp((await tab.locator("#otp-secret").innerText()).trim()));
  await tab.getByRole("button", { name: "Verify" }).click();
  await tab.waitForURL((url) => url.searchParams.has("code"));
  await context.close();

  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await passwordToken(request, client.identifier, secret, without.email, without.password, "openid")).status).toBe(200);
  const refused = await passwordToken(request, client.identifier, secret, withAuthenticator.email, withAuthenticator.password, "openid");
  expect(refused.status).toBe(400);
  expect(refused.body.error).toBe("invalid_grant");
  expect(refused.body.error_description).toMatch(/two-factor/);
  expect(refused.body.access_token).toBeUndefined();
});
