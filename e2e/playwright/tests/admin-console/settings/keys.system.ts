// Settings - Keys: rotating and revoking the signing keys, followed to the tokens and the JWKS. Runs
// alone.
import type { APIRequestContext, Page } from "@playwright/test";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { userTokens, userinfo } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

const keysPage = `${env.adminUrl}/admin/settings/keys`;

async function keysByState(page: Page): Promise<Record<string, string>> {
  await page.goto(keysPage);
  const keys: Record<string, string> = {};
  for (const row of await page.locator("table tbody tr").all()) {
    const cells = row.getByRole("cell");
    keys[(await cells.nth(4).innerText()).trim().toLowerCase()] = (await cells.nth(2).innerText()).trim();
  }
  return keys;
}

async function jwksKids(request: APIRequestContext): Promise<string[]> {
  const jwks = (await (await request.get(`${env.authUrl}/certs`)).json()) as { keys: { kid: string }[] };
  return jwks.keys.map((k) => k.kid);
}

function kidOf(token: string): string {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString()).kid;
}

test("the keys page shows the current and next keys, as the JWKS publishes them", async ({ page, request }) => {
  const keys = await keysByState(page);
  expect(keys.current).toBeTruthy();
  expect(keys.next).toBeTruthy();
  const kids = await jwksKids(request);
  expect(kids).toEqual(expect.arrayContaining(Object.values(keys)));

  // The public key in JWK form names the same key.
  const current = page.getByRole("row").filter({ hasText: keys.current });
  await current.getByRole("link", { name: "JWK" }).click();
  await expect(page.locator("dialog[open]")).toContainText(keys.current);
  await page.locator("dialog[open]").getByRole("button", { name: "Close" }).click();
});

test("rotating signs new tokens with the next key; revoking the previous one refuses what it signed", async ({
  page,
  request,
  clients,
  users,
}) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const before = await keysByState(page);
  const oldToken = (await userTokens(request, client.identifier, secret, user, "openid")).body.access_token as string;
  expect(kidOf(oldToken)).toBe(before.current);

  // Rotate: next becomes current, current becomes previous, and a new next is made.
  await page.goto(keysPage);
  await page.getByRole("button", { name: "Rotate key" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.locator("dialog[open]")).toContainText("Key successfully rotated");
  await page.locator("dialog[open]").getByRole("button", { name: "Close" }).click();
  const rotated = await keysByState(page);
  expect(rotated.current).toBe(before.next);
  expect(rotated.previous).toBe(before.current);
  expect(rotated.next).not.toBe(before.next);
  expect(await jwksKids(request)).toEqual(expect.arrayContaining([rotated.previous, rotated.current, rotated.next]));

  const newToken = (await userTokens(request, client.identifier, secret, user, "openid")).body.access_token as string;
  expect(kidOf(newToken)).toBe(rotated.current);
  // A token the previous key signed is still good while that key is published.
  expect((await userinfo(request, oldToken)).status).toBe(200);

  // Revoke the previous key.
  await page.goto(keysPage);
  await page.getByRole("row").filter({ hasText: rotated.previous }).getByRole("link", { name: "Revoke" }).click();
  await page.locator("dialog[open]").getByRole("button", { name: "Yes" }).click();
  await expect(page.getByRole("row").filter({ hasText: rotated.previous })).toHaveCount(0);
  expect(await jwksKids(request)).not.toContain(rotated.previous);
  expect((await userinfo(request, oldToken)).status).toBe(401);
  expect((await userinfo(request, newToken)).status).toBe(200);

  // The administrator's console session holds an access token the revoked key signed. The auth server
  // refuses it now, and the console renews it behind the scenes: the next page just works.
  const next = await page.goto(keysPage);
  expect(next?.status()).toBe(200);
  await expect(page.getByRole("button", { name: "Rotate key" })).toBeVisible();
});
