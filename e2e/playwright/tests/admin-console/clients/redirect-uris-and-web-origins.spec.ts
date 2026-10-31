import { addRedirectUri, addSignOutRedirectUri, clientUrl, expectFieldError } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

test("redirect URIs are added, saved, and one is removed again", async ({ page, clients }) => {
  const client = await clients.create();
  const table = page.locator("#redirectURIsTable");
  await page.goto(clientUrl(client.id, "redirect-uris"));
  await expect(page.getByText("No redirect URIs yet.")).toBeVisible();
  await expect(table).toBeHidden();

  for (const uri of ["https://app.example.com/callback", "https://app.example.com/signed-out"]) {
    await page.locator("#redirectURI").fill(uri);
    await page.locator("#addURIBtn").click();
  }
  await page.locator("#btnSave").click();
  await expect(page.getByText("Redirect URIs saved.")).toBeVisible();

  await page.reload();
  await expect(table).toContainText("https://app.example.com/callback");
  await expect(table).toContainText("https://app.example.com/signed-out");

  await table.getByRole("button", { name: "Remove https://app.example.com/signed-out", exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Redirect URIs saved.")).toBeVisible();
  await page.reload();
  await expect(table).toContainText("https://app.example.com/callback");
  await expect(table).not.toContainText("/signed-out");
});

test("a redirect URI that is not a URL, or is already listed, is refused at its field", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "redirect-uris"));

  await page.locator("#redirectURI").fill("app.example.com/callback");
  await page.locator("#addURIBtn").click();
  await expectFieldError(page, "redirectURI", "That isn't a valid URL. Include the scheme, such as https://.");
  await expect(page.getByText("No redirect URIs yet.")).toBeVisible();

  await page.locator("#redirectURI").fill("https://app.example.com/callback");
  await page.locator("#addURIBtn").click();
  await page.locator("#redirectURI").fill("https://app.example.com/callback");
  await page.locator("#addURIBtn").click();
  await expectFieldError(page, "redirectURI", "That redirect URI is already in the list.");
  await expect(page.locator('#redirectURIsTable tr[data-value="https://app.example.com/callback"]')).toHaveCount(1);
});

test("a redirect URI the auth server refuses is said in the tab's status, and nothing is saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "redirect-uris"));
  // A URL to the page, but plain http on a host other than the loopback interface.
  await page.locator("#redirectURI").fill("http://app.example.com/callback");
  await page.locator("#addURIBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.locator("#uriListStatus")).toContainText("Redirect URI must not use plain http on a host other than the loopback interface");

  await page.reload();
  await expect(page.getByText("No redirect URIs yet.")).toBeVisible();
});

// Each save carries the list as its page loaded it, so a page left open while another save landed
// cannot undo that save.
test("a save from a page loaded before another save is refused, and leaves that save in place", async ({ page, context, clients }) => {
  const client = await clients.create();
  const stale = await context.newPage();
  await stale.goto(clientUrl(client.id, "redirect-uris"));
  await addRedirectUri(page, client.id, "https://app.example.com/first");

  await stale.locator("#redirectURI").fill("https://app.example.com/second");
  await stale.locator("#addURIBtn").click();
  await stale.locator("#btnSave").click();
  await expect(stale.locator("#uriListStatus")).toContainText("The list was changed by another save after it was loaded. Nothing was saved");
  await stale.close();

  await page.reload();
  await expect(page.locator('#redirectURIsTable tr[data-value="https://app.example.com/first"]')).toHaveCount(1);
  await expect(page.locator('#redirectURIsTable tr[data-value="https://app.example.com/second"]')).toHaveCount(0);
});

test("a client with only the client credentials flow has no redirect URIs to manage", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "redirect-uris"));
  await expect(page.getByText(/^Redirect URIs are for the authorization code flow and the implicit flow\./)).toBeVisible();
  await expect(page.locator("#redirectURI")).toHaveCount(0);
});

test("sign-out redirect URIs are added, saved, and one is removed again, apart from the redirect URIs", async ({ page, clients }) => {
  const client = await clients.create();
  const table = page.locator("#signOutRedirectURIsTable");
  await page.goto(clientUrl(client.id, "sign-out-redirect-uris"));
  await expect(page.getByText("No sign-out redirect URIs yet.")).toBeVisible();
  await expect(page.getByText("After signing out, the user is sent back only to an address listed here, matched exactly, port included. Redirect URIs aren't used for sign-out.")).toBeVisible();
  await expect(table).toBeHidden();

  // A custom scheme and a query carrying state are allowed.
  for (const uri of ["https://app.example.com/signed-out", "https://app.example.com/bye?state=fixed", "com.example.app:/signed-out"]) {
    await page.locator("#signOutRedirectURI").fill(uri);
    await page.locator("#addURIBtn").click();
  }
  await page.locator("#btnSave").click();
  await expect(page.getByText("Sign-out redirect URIs saved.")).toBeVisible();

  await page.reload();
  for (const uri of ["https://app.example.com/signed-out", "https://app.example.com/bye?state=fixed", "com.example.app:/signed-out"]) {
    await expect(table.locator(`tr[data-value="${uri}"]`)).toHaveCount(1);
  }

  await table.getByRole("button", { name: "Remove https://app.example.com/bye?state=fixed", exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Sign-out redirect URIs saved.")).toBeVisible();
  await page.reload();
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table).not.toContainText("state=fixed");

  // The two lists are kept apart: none of these is a redirect URI.
  await page.goto(clientUrl(client.id, "redirect-uris"));
  await expect(page.getByText("No redirect URIs yet.")).toBeVisible();
});

test("a sign-out redirect URI on plain http off loopback is said in the tab's status, and nothing is saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "sign-out-redirect-uris"));
  await page.locator("#signOutRedirectURI").fill("http://app.example.com/signed-out");
  await page.locator("#addURIBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.locator("#uriListStatus")).toContainText("Sign-out redirect URI must not use plain http on a host other than the loopback interface");

  await page.reload();
  await expect(page.getByText("No sign-out redirect URIs yet.")).toBeVisible();
});

test("a sign-out redirect URI save from a page loaded before another save is refused, and leaves that save in place", async ({ page, context, clients }) => {
  const client = await clients.create();
  const stale = await context.newPage();
  await stale.goto(clientUrl(client.id, "sign-out-redirect-uris"));
  await addSignOutRedirectUri(page, client.id, "https://app.example.com/first");

  await stale.locator("#signOutRedirectURI").fill("https://app.example.com/second");
  await stale.locator("#addURIBtn").click();
  await stale.locator("#btnSave").click();
  await expect(stale.locator("#uriListStatus")).toContainText("The list was changed by another save after it was loaded. Nothing was saved");
  await stale.close();

  await page.reload();
  await expect(page.locator('#signOutRedirectURIsTable tr[data-value="https://app.example.com/first"]')).toHaveCount(1);
  await expect(page.locator('#signOutRedirectURIsTable tr[data-value="https://app.example.com/second"]')).toHaveCount(0);
});

test("a client with only the client credentials flow has no sign-out redirect URIs to manage", async ({ page, clients }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await page.goto(clientUrl(client.id, "sign-out-redirect-uris"));
  await expect(page.getByText(/^Sign-out redirect URIs are for the authorization code flow and the implicit flow\./)).toBeVisible();
  await expect(page.locator("#signOutRedirectURI")).toHaveCount(0);
});

test("a web origin is added, saved, and removed again", async ({ page, clients }) => {
  const client = await clients.create();
  const origin = `https://${client.identifier}.example.com`;
  const table = page.locator("#webOriginsTable");
  await page.goto(clientUrl(client.id, "web-origins"));
  await expect(page.getByText("No web origins yet.")).toBeVisible();

  // Only the origin is kept of what is typed.
  await page.locator("#webOrigin").fill(`${origin}/callback?from=e2e`);
  await page.locator("#addOriginBtn").click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator(`tr[data-value="${origin}"]`)).toHaveCount(1);
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved.")).toBeVisible();
  await page.reload();
  await expect(table).toContainText(origin);
  // Origins are server-wide: it shows among the ones every client is permitted, beside its client.
  const effective = page.locator("#effectiveWebOriginsTable").getByRole("row").filter({ hasText: origin });
  await expect(effective.getByRole("cell", { name: client.identifier, exact: true })).toBeVisible();

  await table.getByRole("button", { name: `Remove ${origin}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved.")).toBeVisible();
  await page.reload();
  await expect(page.getByText("No web origins yet.")).toBeVisible();
});

test("a web origin that is not an origin is refused at its field", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "web-origins"));
  await page.locator("#webOrigin").fill("not an origin");
  await page.locator("#addOriginBtn").click();
  await expectFieldError(page, "webOrigin", "That isn't a valid origin. Include the scheme, such as https://.");
  await expect(page.getByText("No web origins yet.")).toBeVisible();
});
