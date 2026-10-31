// The user's recovery codes: the set of ten that comes with every new authenticator, each of which
// signs in once in place of an authenticator code.
import { signInToConsole } from "../../../lib/console-user";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { freshTotp } from "../../../lib/totp";

// 24 characters of Crockford's base32 alphabet, which leaves out i, l, o and u, in six groups of
// four.
const codeShape = /^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$/;

test("turning on two-factor authentication shows ten recovery codes, once", async ({ browser, users }) => {
  const user = await users.create();
  const own = await signInToConsole(browser, user, "/account/otp");
  const secret = (await own.page.locator("#otp-secret").innerText()).trim();
  await own.page.locator("#password").fill(user.password);
  await own.page.locator("#otp").fill(await freshTotp(secret));
  await own.page.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();

  await expect(own.page.getByRole("heading", { name: "Save your recovery codes" })).toBeVisible();
  await expect(own.page.getByText("They are not shown again.")).toBeVisible();
  const codes = (await own.page.getByRole("list", { name: "Recovery codes" }).getByRole("listitem").allInnerTexts())
    .map((code) => code.trim());
  expect(codes).toHaveLength(10);
  for (const code of codes) {
    expect(code).toMatch(codeShape);
  }
  expect(new Set(codes).size).toBe(10);

  // Copy codes copies the list, one code per line.
  await own.context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: env.adminUrl });
  await own.page.getByRole("button", { name: "Copy codes" }).click();
  await expect(own.page.getByRole("button", { name: "Codes copied" })).toBeVisible();
  expect((await own.page.evaluate(() => navigator.clipboard.readText())).split("\n")).toEqual(codes);

  // The page drawn again shows the account, and not the codes.
  await own.page.goto(`${env.adminUrl}/account/otp`);
  await expect(own.page.getByText("Two-factor authentication is on.")).toBeVisible();
  await expect(own.page.getByRole("heading", { name: "Save your recovery codes" })).toHaveCount(0);
  await expect(own.page.getByText(codes[0])).toHaveCount(0);
  await own.context.close();
});
