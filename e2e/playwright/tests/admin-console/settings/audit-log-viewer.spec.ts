// The audit log viewer reads; it changes nothing, so it runs with the other parallel tests. Audit
// events are persisted to the database by default.
import { expectFieldError, userUrl } from "../../../lib/admin-console";
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

  // The request id, under the event, links to every event of that request. The row names the
  // administrator who made the change too, by another link.
  const requestLink = row.locator('a[href*="requestId="]');
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

test("a user's page links to their audit events, and each row links to the users it names", async ({ page, users }) => {
  const user = await users.create();
  await page.goto(userUrl(user.id, "profile"));
  await page.locator('input[name="nickname"]').fill("audited");
  await page.locator("#btnSave").click();
  await expect(page.getByText("Profile saved.")).toBeVisible();

  // The user header, on every tab, links to the audit log filtered by the user's id.
  await page.getByRole("link", { name: "Show audit events", exact: true }).click();
  await expect(page).toHaveURL((url) => url.pathname === "/admin/settings/audit-log-viewer" && url.searchParams.get("userId") === String(user.id));
  await expect(page.locator("#userIdFilter")).toHaveValue(String(user.id));
  const change = auditRows(page, { user_id: String(user.id) }).filter({ hasText: "updated_user_profile" });
  await expect(change).toHaveCount(1);

  // Under the event, the row names the user it is about and the administrator who acted, each by id.
  const aboutLink = change.locator("span", { hasText: /^User:/ }).getByRole("link");
  const actedByLink = change.locator("span", { hasText: /^Acted by:/ }).getByRole("link");
  await expect(aboutLink).toHaveAttribute("href", `/admin/settings/audit-log-viewer?userId=${user.id}`);
  const adminId = new URL((await actedByLink.getAttribute("href"))!, viewer).searchParams.get("userId");
  expect(Number(adminId)).toBeGreaterThan(0);
  expect(adminId).not.toBe(String(user.id));

  // Following the administrator's id lists the administrator's events. Other tests change things as
  // the same administrator meanwhile, so the event narrows the page to find this change among them.
  await actedByLink.click();
  await expect(page).toHaveURL((url) => url.searchParams.get("userId") === adminId);
  await expect(page.locator("#userIdFilter")).toHaveValue(adminId!);
  await page.locator("#auditEventFilter").fill("updated_user_profile");
  await page.getByRole("option", { name: "updated_user_profile", exact: true }).click();
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get("userId") === adminId && url.searchParams.get("auditEvent") === "updated_user_profile");
  await expect(auditRows(page, { user_id: String(user.id) })).toHaveCount(1);

  // A user id that is not a number is the box's error, and nothing is listed under it.
  await page.locator("#userIdFilter").fill("not-a-number");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page).toHaveURL((url) => url.searchParams.get("userId") === "not-a-number");
  await expectFieldError(page, "userIdFilter", "Enter the user id as a whole number above 0.");
  await expect(page.locator("#userIdFilter")).toHaveValue("not-a-number");
  await expect(page.locator("#auditLogsTable")).toHaveCount(0);
  await expect(page.locator(".empty-state")).toHaveCount(0);
});
