// The audit log viewer reads; it changes nothing, so it runs with the other parallel tests. Audit
// events are persisted to the database by default.
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { auditRows } from "../../../lib/sessions";

const viewer = `${env.adminUrl}/admin/settings/audit-log-viewer`;

test("an action is listed by its event, and found again by its request id", async ({ page, groups }) => {
  const group = await groups.create();

  // The event is chosen from a searchable list: type, then pick the option.
  await page.goto(viewer);
  await page.locator("#auditEventFilter").fill("created_group");
  await page.getByRole("option", { name: "created_group", exact: true }).click();
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page).toHaveURL(/auditEvent=created_group/);
  await expect(page.locator("#auditEventFilter")).toHaveValue("created_group");
  const row = auditRows(page, { group_identifier: group.identifier });
  await expect(row).toHaveCount(1);
  // Every listed row is of the event filtered on: the event is the first line of its cell.
  for (const event of await page.locator("#auditLogsTable tbody tr td:nth-child(2) > span:first-child").allInnerTexts()) {
    expect(event.trim()).toBe("created_group");
  }

  // The request id, under the event, links to every event of that request.
  const requestLink = row.getByRole("link");
  const requestId = new URL((await requestLink.getAttribute("href"))!, viewer).searchParams.get("requestId");
  expect(requestId).toBeTruthy();
  await requestLink.click();
  await expect(page).toHaveURL((url) => url.searchParams.get("requestId") === requestId);
  await expect(page.locator("#requestIdFilter")).toHaveValue(requestId!);
  await expect(auditRows(page, { group_identifier: group.identifier })).toHaveCount(1);

  await page.getByRole("link", { name: "Clear filters", exact: true }).click();
  await expect(page).toHaveURL(viewer);
  await expect(page.locator("#requestIdFilter")).toHaveValue("");
  await expect(page.getByRole("link", { name: "Clear filters", exact: true })).toHaveCount(0);
});

test("a request id that matches nothing says so", async ({ page }) => {
  await page.goto(viewer);
  await page.locator("#requestIdFilter").fill("no-such-request-e2e");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get("requestId") === "no-such-request-e2e");
  await expect(page.locator(".empty-state")).toHaveText("No audit events match these filters.");
  await expect(page.locator("#auditLogsTable")).toHaveCount(0);
});
