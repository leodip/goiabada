// What branding leaves in the audit log, as the console's audit log viewer lists it (#810, #812,
// #813): a brand created, saved and deleted, a file uploaded for its kit, and a client given the brand,
// each found by its event and the brand, the file or the client it names. Making a brand the default
// changes every page, and is brands.system.ts's; an email's text is email-templates.system.ts's.
//
// The brand and the client are the test's own, and the viewer only reads, so this is an ordinary
// parallel spec.
import type { Page } from "@playwright/test";
import { setClientBrand } from "../../../lib/admin-console";
import { brandIdFromList, brandUrl, deleteBrand, fillBrandForm, kitFiles, newBrandUrl, slotHolds, uploadInEditor } from "../../../lib/brands";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { auditRows } from "../../../lib/sessions";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

const viewer = `${env.adminUrl}/admin/settings/audit-log-viewer`;

// Expects one event of this kind whose details hold these values, on the viewer filtered on the
// event. The viewer lists twenty a page, newest first, and other tests running beside this one save
// and upload too, so the first few pages are read.
async function expectEvent(page: Page, event: string, details: Record<string, string>, what = event) {
  let found = 0;
  for (let number = 1; number <= 5 && found === 0; number++) {
    await page.goto(`${viewer}?${new URLSearchParams({ auditEvent: event, page: String(number) })}`);
    await expect(page.locator("#auditEventFilter")).toHaveValue(event);
    found = await auditRows(page, details).count();
    if ((await page.locator("#auditLogsTable tbody tr").count()) < 20) break;
  }
  expect(found, `${what}: ${JSON.stringify(details)}`).toBe(1);
}

test("a brand created, saved with an uploaded logo, given to a client and deleted is each listed in the audit log", async ({ page, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const name = uniqueIdentifier("brand");

  await page.goto(newBrandUrl);
  await fillBrandForm(page, { name, appearance: "light", theme: "avocado" });
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(/\/admin\/settings\/branding$/);
  const id = await brandIdFromList(page, name);
  let deleted = false;
  try {
    await expectEvent(page, "created_brand", { brand_id: String(id), brand_name: name });

    // A logo uploaded in the editor is stored at once, before the brand is saved.
    await page.goto(brandUrl(id, "edit"));
    await uploadInEditor(page, "logo", kitFiles.logo);
    const logo = (await slotHolds(page, "logo")).id;
    await fillBrandForm(page, { theme: "plum", corners: "pill" });
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();
    await expectEvent(page, "uploaded_brand_asset", { brand_asset_id: logo, kind: "logo" });
    await expectEvent(page, "updated_brand", { brand_id: String(id), theme: "plum", corners: "pill", logo_asset_id: logo }, "the save names what the brand holds after it");

    await setClientBrand(page, client.id, { name });
    await expectEvent(page, "updated_client_brand", { client_identifier: client.identifier, brand_id: String(id), brand_name: name });

    // Deleted while the client uses it: the event counts the clients moved to the default brand.
    await deleteBrand(page, id);
    deleted = true;
    await expectEvent(page, "deleted_brand", { brand_id: String(id), brand_name: name, client_count: "1" });
  } finally {
    if (!deleted) await deleteBrand(page, id);
  }
});
