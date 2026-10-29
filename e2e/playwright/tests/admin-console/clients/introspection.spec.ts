// A client's Introspection tab: the resources whose tokens a confidential client may introspect
// (#676 decision 14), edited in the page and saved whole, and absent for a public client.
import type { Page } from "@playwright/test";
import { addIntrospectionResource, clientUrl, confirmDialog, expectFieldError } from "../../../lib/admin-console";
import { expect, test } from "../../../lib/fixtures";

const saved = "Introspection resources saved.";
const none = "No introspection resources yet.";

// Makes the client public on its Authentication tab, which empties its introspection resources.
async function makePublic(page: Page, clientId: number) {
  await page.goto(clientUrl(clientId, "authentication"));
  await page.getByRole("radio", { name: "Public", exact: true }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();
}

test("a resource listed is saved, kept across a reload, and removed again", async ({ page, clients, resources }) => {
  const client = await clients.create();
  const first = await resources.create();
  const second = await resources.create();
  const table = page.locator("#introspectionResourcesTable");

  await page.goto(clientUrl(client.id, "introspection"));
  await expect(page.getByRole("link", { name: "Introspection", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.getByText(none)).toBeVisible();

  await addIntrospectionResource(page, first.identifier);
  await addIntrospectionResource(page, second.identifier);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(table.getByRole("link", { name: first.identifier, exact: true })).toHaveAttribute("href", `/admin/resources/${first.id}/settings`);
  await expect(table.getByRole("link", { name: second.identifier, exact: true })).toBeVisible();

  await table.getByRole("button", { name: `Remove ${first.identifier}`, exact: true }).click();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(table).not.toContainText(first.identifier);
  await expect(table).toContainText(second.identifier);

  await table.getByRole("button", { name: `Remove ${second.identifier}`, exact: true }).click();
  await expect(page.getByText(none)).toBeVisible();
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();
  await page.reload();
  await expect(page.getByText(none)).toBeVisible();
});

test("Add with no resource chosen, or one listed already, is refused at the field", async ({ page, clients, resources }) => {
  const client = await clients.create();
  const resource = await resources.create({ description: "The orders API" });

  await page.goto(clientUrl(client.id, "introspection"));
  await page.locator("#addIntrospectionResourceBtn").click();
  await expectFieldError(page, "introspectionResourcesSelect", "Choose a resource to add.");

  const select = page.locator("#introspectionResourcesSelect");
  await select.selectOption((await select.locator(`option[data-resource-identifier="${resource.identifier}"]`).getAttribute("value"))!);
  await expect(page.locator("#introspectionResourcesSelect-description")).toHaveText("The orders API");
  await page.locator("#addIntrospectionResourceBtn").click();
  await addIntrospectionResource(page, resource.identifier);
  await expectFieldError(page, "introspectionResourcesSelect", "The client already lists that resource.");
  await expect(page.locator("#introspectionResourcesTable").getByRole("row").filter({ hasText: resource.identifier })).toHaveCount(1);
});

test("a public client has no Introspection tab, and making a client public empties its list", async ({ page, clients, resources }) => {
  const client = await clients.create();
  const resource = await resources.create();

  await page.goto(clientUrl(client.id, "introspection"));
  await addIntrospectionResource(page, resource.identifier);
  await page.locator("#btnSave").click();
  await expect(page.getByText(saved)).toBeVisible();

  await makePublic(page, client.id);
  await page.goto(clientUrl(client.id, "settings"));
  await expect(page.getByRole("link", { name: "Permissions", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Introspection", exact: true })).toHaveCount(0);

  // Reached by its address, the tab says why and offers nothing to edit.
  await page.goto(clientUrl(client.id, "introspection"));
  await expect(page.getByText(/^A public client can't authenticate, so it can't introspect tokens\./)).toBeVisible();
  await expect(page.locator("#introspectionResourcesSelect")).toHaveCount(0);
  await expect(page.locator("#btnSave")).toHaveCount(0);

  // Made confidential again, the client starts with no introspection resources.
  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Confidential", exact: true }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client confidential");
  await expect(page.getByText("Authentication saved.")).toBeVisible();
  await page.goto(clientUrl(client.id, "introspection"));
  await expect(page.getByText(none)).toBeVisible();
});
