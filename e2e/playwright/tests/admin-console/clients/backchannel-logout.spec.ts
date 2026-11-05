// A client's Back-channel logout tab: the URI the auth server POSTs a logout token to when a
// session the client was on ends, and whether the client requires the session identifier in every
// one (OpenID Connect Back-Channel Logout 1.0 section 2.2, #784 decisions 6 and 9).
import { clientUrl, confirmDialog } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

test("the tab follows Sign-out redirect URIs, and saves, shows and clears both settings", async ({ page, clients }) => {
  const client = await clients.create();
  const uri = page.locator("#backchannelLogoutUri");
  const sessionRequired = page.getByRole("checkbox", { name: "Require the session identifier" });

  await page.goto(clientUrl(client.id, "sign-out-redirect-uris"));
  const tabs = page.locator("nav.tab-bar a.tab-item");
  const names = await tabs.allInnerTexts();
  expect(names.indexOf("Back-channel logout")).toBe(names.indexOf("Sign-out redirect URIs") + 1);
  await tabs.getByText("Back-channel logout", { exact: true }).click();
  await expect(page).toHaveURL(clientUrl(client.id, "backchannel-logout"));
  await expect(page.locator('nav.tab-bar a[aria-current="page"]')).toHaveText("Back-channel logout");
  await expect(uri).toHaveValue("");
  await expect(sessionRequired).not.toBeChecked();

  // A query is kept exactly as entered.
  await uri.fill("https://app.example.com/backchannel-logout?tenant=a");
  await sessionRequired.check();
  await page.locator("#btnSave").click();
  await expect(page.getByRole("status").filter({ hasText: "Back-channel logout settings saved." })).toBeVisible();
  await page.reload();
  await expect(uri).toHaveValue("https://app.example.com/backchannel-logout?tenant=a");
  await expect(sessionRequired).toBeChecked();

  // A new client is confidential, so plain http on a private host is allowed.
  await uri.fill("http://app:3000/backchannel-logout");
  await sessionRequired.uncheck();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Back-channel logout settings saved.")).toBeVisible();
  await page.reload();
  await expect(uri).toHaveValue("http://app:3000/backchannel-logout");
  await expect(sessionRequired).not.toBeChecked();

  // Emptying the field clears the URI.
  await uri.fill("");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Back-channel logout settings saved.")).toBeVisible();
  await page.reload();
  await expect(uri).toHaveValue("");
});

test("a URI the auth server refuses is shown at its field, as typed, and nothing is saved", async ({ page, clients }) => {
  const client = await clients.create();
  const uri = page.locator("#backchannelLogoutUri");
  await page.goto(clientUrl(client.id, "backchannel-logout"));

  for (const [typed, refusal] of [
    ["ftp://app.example.com/backchannel-logout", "Back-channel logout URI must use https or http: ftp://app.example.com/backchannel-logout"],
    ["https://user:secret@app.example.com/backchannel-logout", "Back-channel logout URI must not carry a user name or password"],
    ["https://app.example.com/backchannel-logout#here", "Back-channel logout URI must be an absolute URI that names a host, with no fragment"],
  ] as const) {
    await uri.fill(typed);
    await page.locator("#btnSave").click();
    await expect(page.getByRole("alert")).toContainText(refusal);
    await expect(uri).toHaveAttribute("aria-invalid", "true");
    await expect(uri).toHaveAttribute("aria-describedby", /\bbackchannel-logout-error\b/);
    await expect(uri).toBeFocused();
    await expect(uri).toHaveValue(typed);
  }

  await page.goto(clientUrl(client.id, "backchannel-logout"));
  await expect(uri).toHaveValue("");
});

test("a public client is refused plain http, which a confidential one may use", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  await page.locator("#publicClientRadio").check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();

  const uri = page.locator("#backchannelLogoutUri");
  await page.goto(clientUrl(client.id, "backchannel-logout"));
  await uri.fill("http://app:3000/backchannel-logout");
  await page.locator("#btnSave").click();
  await expect(page.getByRole("alert")).toContainText("Back-channel logout URI must use https on a public client.");
  await expect(uri).toHaveAttribute("aria-invalid", "true");

  await uri.fill("https://app.example.com/backchannel-logout");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Back-channel logout settings saved.")).toBeVisible();
});

test("a client with no flow that signs users in shows the note instead of the form", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "backchannel-logout"));
  await expect(page.getByText(/^A back-channel logout URI is for the authorization code flow and the implicit flow\./)).toBeVisible();
  await expect(page.locator("#backchannelLogoutUri")).toHaveCount(0);
  await expect(page.locator("#btnSave")).toHaveCount(0);
});
