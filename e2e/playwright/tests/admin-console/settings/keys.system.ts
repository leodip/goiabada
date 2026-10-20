// Settings - Signing keys: rotating and revoking the signing keys, followed to the tokens and the
// JWKS. Runs alone.
import type { APIRequestContext, Page } from "@playwright/test";
import { cancelDialog, confirmDialog } from "../../../lib/admin-console";
import { asks, checkStates } from "../../../lib/axe";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { userTokens, userinfo } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

const keysPage = `${env.adminUrl}/admin/settings/keys`;

// The key identifiers by state ("current", "next", "previous"), as the keys table lists them: the
// identifier in the first cell, the state's tag in the second.
async function keysByState(page: Page): Promise<Record<string, string>> {
  await page.goto(keysPage);
  const keys: Record<string, string> = {};
  for (const row of await page.locator("#keysTable tbody tr").all()) {
    const cells = row.getByRole("cell");
    keys[(await cells.nth(1).innerText()).trim().toLowerCase()] = (await cells.nth(0).innerText()).trim();
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

  // The public key in JWK form names the same key, and Copy puts it on the clipboard.
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: env.adminUrl });
  await page.getByRole("button", { name: `JWK ${keys.current}`, exact: true }).click();
  const dialog = page.locator("#publicKeyDialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Public key in JWK format" })).toBeVisible();
  await expect(dialog.locator("#publicKeyDialogKeyId")).toHaveText(keys.current);
  const jwk = JSON.parse(await dialog.locator("#publicKeyContent").innerText());
  expect(jwk.kid).toBe(keys.current);
  await dialog.getByRole("button", { name: "Copy", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
  expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))).toEqual(jwk);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();
});

test("a rotation cancelled changes no key", async ({ page }) => {
  const before = await keysByState(page);
  await page.getByRole("button", { name: "Rotate keys", exact: true }).click();
  await cancelDialog(page, "Rotate the signing keys?");
  expect(await keysByState(page)).toEqual(before);
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

  // Rotate: next becomes current, current becomes previous, and a new next is made. The page says so
  // when it is drawn again.
  await page.goto(keysPage);
  await page.getByRole("button", { name: "Rotate keys", exact: true }).click();
  await confirmDialog(page, "The next key will become the current key and sign every new token");
  await expect(page.getByText("Keys rotated: the next key is now the current key, and a new next key was created.")).toBeVisible();
  const rotated = await keysByState(page);
  expect(rotated.current).toBe(before.next);
  expect(rotated.previous).toBe(before.current);
  expect(rotated.next).not.toBe(before.next);
  expect(await jwksKids(request)).toEqual(expect.arrayContaining([rotated.previous, rotated.current, rotated.next]));

  const newToken = (await userTokens(request, client.identifier, secret, user, "openid")).body.access_token as string;
  expect(kidOf(newToken)).toBe(rotated.current);
  // A token the previous key signed is still good while that key is published.
  expect((await userinfo(request, oldToken)).status).toBe(200);

  // Revoke the previous key: Cancel keeps it; the dialog's Revoke key revokes it, and the row's button
  // gives way to a tag.
  await page.goto(keysPage);
  const previous = page.getByRole("row").filter({ hasText: rotated.previous });
  const revoke = previous.getByRole("button", { name: `Revoke ${rotated.previous}`, exact: true });
  // Its confirmation is checked by axe here, the one moment a previous key surely exists.
  await checkStates(page, [asks(page, "signing keys, revoking the previous key asking first", () => revoke.click())]);
  await revoke.click();
  await cancelDialog(page, "Revoke this key?");
  expect(await jwksKids(request)).toContain(rotated.previous);
  await revoke.click();
  await confirmDialog(page, "The key will be deleted, and the tokens it signed will stop verifying.");
  await expect(previous.getByText("Revoked", { exact: true })).toBeVisible();
  await expect(page.locator("#row-actions-status")).toHaveText("Key revoked.");
  expect(await jwksKids(request)).not.toContain(rotated.previous);
  expect((await userinfo(request, oldToken)).status).toBe(401);
  expect((await userinfo(request, newToken)).status).toBe(200);

  // With no previous key left, the next rotation's question no longer says it deletes one.
  await page.getByRole("button", { name: "Rotate keys", exact: true }).click();
  await expect(page.locator("dialog[open]")).not.toContainText("The existing previous key will be deleted");
  await cancelDialog(page, "Rotate the signing keys?");

  // The administrator's console session holds an ID token the revoked key signed, which can no longer
  // be verified, so the console signs that session out rather than refresh it (#427): the next page
  // is the home page, saying so. The auth server's own session is still good, so signing in again
  // asks for nothing, and the keys page no longer lists the revoked key.
  await page.goto(keysPage);
  await expect(page.getByText("Your sign-in has ended. Sign in again.")).toBeVisible();
  await page.goto(keysPage);
  await expect(page).toHaveURL(keysPage);
  await expect(page.getByRole("button", { name: "Rotate keys", exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: rotated.previous })).toHaveCount(0);
});
