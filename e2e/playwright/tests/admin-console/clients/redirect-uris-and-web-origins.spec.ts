import { clientUrl, expectErrorDialog } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

test("redirect URIs are added, saved, and one is removed again", async ({ page, clients }) => {
  const client = await clients.create();
  const table = page.locator("#redirectURIsTable");
  await page.goto(clientUrl(client.id, "redirect-uris"));
  await expect(table).toContainText("(none yet)");

  for (const uri of ["https://app.example.com/callback", "https://app.example.com/signed-out"]) {
    await page.locator("#redirectURI").fill(uri);
    await page.getByRole("button", { name: "Add" }).click();
  }
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client redirect uris saved successfully")).toBeVisible();

  await page.reload();
  await expect(table).toContainText("https://app.example.com/callback");
  await expect(table).toContainText("https://app.example.com/signed-out");

  await table.getByRole("button", { name: "Remove redirect URI https://app.example.com/signed-out", exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Client redirect uris saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText("https://app.example.com/callback");
  await expect(table).not.toContainText("/signed-out");
});

test("a redirect URI that is not a URL, or is already listed, is refused", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "redirect-uris"));

  await page.locator("#redirectURI").fill("app.example.com/callback");
  await page.getByRole("button", { name: "Add" }).click();
  await expectErrorDialog(page, "The redirect URI is not a valid URL.");

  await page.locator("#redirectURI").fill("https://app.example.com/callback");
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#redirectURI").fill("https://app.example.com/callback");
  await page.getByRole("button", { name: "Add" }).click();
  await expectErrorDialog(page, "The redirect URI is already in the list.");
  await expect(page.locator("#redirectURIsTable").getByRole("row").filter({ hasText: "/callback" })).toHaveCount(1);
});

test("a client with only the client credentials flow has no redirect URIs to manage", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "redirect-uris"));
  await expect(page.getByText(/^Redirect URIs are used by the authorization code with PKCE flow/)).toBeVisible();
  await expect(page.locator("#redirectURI")).toBeHidden();
});

test("a web origin is added, saved, and removed again", async ({ page, clients }) => {
  const client = await clients.create();
  const origin = `https://${client.identifier}.example.com`;
  const table = page.locator("#webOriginsTable");
  await page.goto(clientUrl(client.id, "web-origins"));

  await page.locator("#webOrigin").fill(origin);
  await page.getByRole("button", { name: "Add" }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).toContainText(origin);
  // Origins are server-wide: it shows among the ones every client is permitted.
  await expect(page.locator("#effectiveWebOriginsTable")).toContainText(origin);

  await table.getByRole("button", { name: `Remove web origin ${origin}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved successfully")).toBeVisible();
  await page.reload();
  await expect(table).not.toContainText(origin);
});

test("a web origin that is not an origin is refused", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "web-origins"));
  await page.locator("#webOrigin").fill("not an origin");
  await page.getByRole("button", { name: "Add" }).click();
  await expectErrorDialog(page, "The web origin is not a valid URL.");
  await expect(page.locator("#webOriginsTable")).toContainText("(none yet)");
});
