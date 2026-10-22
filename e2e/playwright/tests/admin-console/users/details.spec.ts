import { cancelDialog, confirmDialog, rowWithCell, userUrl } from "../../../lib/admin-console";
import { openSignIn, submitPassword } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { passwordToken } from "../../../lib/oauth";
import { browserSignInClient, passwordGrantClient } from "../../../lib/test-clients";

const saved = "Changes saved.";
const disableWarning = "You're disabling the user, so they won't be able to sign in";

test("a disabled user cannot sign in until enabled again", async ({ page, request, browser, clients, users }) => {
  const user = await users.create();
  const { client, secret } = await passwordGrantClient(page, clients);
  const signIn = () => passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect((await signIn()).status).toBe(200);

  // Disabling asks first.
  await page.goto(userUrl(user.id, "details"));
  await page.locator("#enabledDisabled").uncheck();
  await page.locator("#btnSave").click();
  await confirmDialog(page, disableWarning);
  await expect(page.getByText(saved)).toBeVisible();
  await expect(page.locator("#enabledDisabled")).not.toBeChecked();
  // The list tags the user.
  await page.goto(`${env.adminUrl}/admin/users?query=${encodeURIComponent(user.email)}`);
  await expect(rowWithCell(page, user.email).getByText("Disabled", { exact: true })).toBeVisible();

  const refused = await signIn();
  expect(refused.status, JSON.stringify(refused.body)).toBe(400);
  expect(refused.body.error).toBe("invalid_grant");

  // The browser sign-in refuses too, on the password page.
  const web = await browserSignInClient(page, clients);
  const signInPage = await openSignIn(browser, { clientId: web.client.identifier, scope: "openid" });
  await submitPassword(signInPage.page, user.email, user.password);
  await expect(signInPage.page.getByText("Your user account is disabled.")).toBeVisible();
  await signInPage.context.close();

  // Enabling asks nothing.
  await page.goto(userUrl(user.id, "details"));
  await page.locator("#enabledDisabled").check();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  expect((await signIn()).status).toBe(200);
});

test("disabling asks first, and Cancel leaves the user enabled", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "details"));
  await page.locator("#enabledDisabled").uncheck();
  await page.locator("#btnSave").click();
  await cancelDialog(page, disableWarning);
  // Opened afresh, so the browser restores nothing of the form.
  await page.goto(userUrl(user.id, "details"));
  await expect(page.locator("#enabledDisabled")).toBeChecked();
});
