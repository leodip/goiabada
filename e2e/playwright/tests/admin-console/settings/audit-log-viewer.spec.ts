// The audit log viewer reads; it changes nothing, so it runs with the other parallel tests. Audit
// events are persisted to the database by default.
import type { Page } from "@playwright/test";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

const viewer = `${env.adminUrl}/admin/settings/audit-log-viewer`;

function rowFor(page: Page, text: string) {
  return page.locator("#auditLogsTable tbody tr").filter({ has: page.locator(`td.audit-details[data-details*="${text}"]`) });
}

test("an action is listed by its event, and found again by its request id", async ({ page, groups }) => {
  const group = await groups.create();

  await page.goto(viewer);
  await page.locator("#auditEventFilter").selectOption("created_group");
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(page).toHaveURL(/auditEvent=created_group/);
  const row = rowFor(page, group.identifier);
  await expect(row).toHaveCount(1);
  await expect(row.getByRole("cell").nth(1)).toHaveText("created_group");
  // Every listed row is of the event filtered on.
  for (const event of await page.locator("#auditLogsTable tbody tr td:nth-child(2)").allInnerTexts()) {
    expect(event.trim()).toBe("created_group");
  }

  const requestId = (await row.getByRole("cell").nth(2).innerText()).trim();
  expect(requestId).not.toBe("-");
  await page.goto(viewer);
  await page.locator("#requestIdFilter").fill(requestId);
  await page.getByRole("button", { name: "Filter" }).click();
  await expect(rowFor(page, group.identifier)).toHaveCount(1);

  await page.getByRole("link", { name: "Clear" }).click();
  await expect(page).toHaveURL(viewer);
});

test("a request id that matches nothing says so", async ({ page }) => {
  await page.goto(`${viewer}?requestId=no-such-request-e2e`);
  await expect(page.getByText("No audit logs found.")).toBeVisible();
});
