import { userUrl } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken } from "../../../lib/oauth";
import { passwordGrantClient } from "../../../lib/test-clients";

test("a password set here replaces the old one", async ({ page, request, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const signIn = (password: string) => passwordToken(request, client.identifier, secret, user.email, password, "openid");

  await page.goto(userUrl(user.id, "authentication"));
  // A new user has no authenticator: the switch is off and cannot be turned on from here.
  await expect(page.getByText("Two-factor authentication is not enabled for this user")).toBeVisible();
  await page.locator('input[name="newPassword"]').fill("a-brand-new-password");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Saved successfully")).toBeVisible();
  // The field is never filled back in.
  await expect(page.locator('input[name="newPassword"]')).toHaveValue("");

  expect((await signIn("a-brand-new-password")).status).toBe(200);
  const old = await signIn(user.password);
  expect(old.body.error).toBe("invalid_grant");
});

test("a password under the policy is refused, and the old one still works", async ({ page, request, clients, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "authentication"));
  await page.locator('input[name="newPassword"]').fill("abc");
  await page.locator("#btnSave").click();
  await expect(page.getByText("The minimum length for the password is 6 characters")).toBeVisible();

  const { client, secret } = await passwordGrantClient(page, clients);
  expect((await passwordToken(request, client.identifier, secret, user.email, user.password, "openid")).status).toBe(200);
});
