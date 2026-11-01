// Runs before every other test: sweeps what earlier runs that stopped half way may have left behind.
import type { Page } from "@playwright/test";
import {
  deleteClient,
  deleteGroup,
  deleteResource,
  deleteUser,
  idFromListLink,
  legalDocumentIdFrom,
  putAwayLegalDocument,
  signInAsAdmin,
} from "../lib/admin-console";
import { env } from "../lib/environment";
import { test as setup } from "../lib/fixtures";
import { restoreBaselineSettings } from "../lib/settings";
import { testPrefix } from "../lib/unique";

// The setup signs the administrator in for itself, from an empty browser, not with a worker's session.
setup.use({ storageState: { cookies: [], origins: [] } });

// The names a list page links to that the tests made: each row's identifier or email is a link.
async function leftoversOn(page: Page, listUrl: string): Promise<string[]> {
  await page.goto(listUrl);
  return (await page.getByRole("table").getByRole("link").allInnerTexts())
    .map((text) => text.trim())
    .filter((text) => text.startsWith(testPrefix));
}

setup("sweep what earlier runs left", async ({ page }, testInfo) => {
  await signInAsAdmin(page);
  // The settings tests put back what they change; one that failed while doing so is put right here,
  // and so is a new environment's missing SMTP set-up.
  const drifted = await restoreBaselineSettings(page);
  if (drifted.length > 0) {
    testInfo.annotations.push({ type: "settings restored", description: drifted.join("; ") });
    console.warn(`settings were not at their baseline, restored: ${drifted.join("; ")}`);
  }
  // Every test removes what it creates, so anything named with the test prefix at the start of a run
  // is what a run that crashed left. Assumes one run at a time against the environment.
  const clients = `${env.adminUrl}/admin/clients`;
  for (const identifier of await leftoversOn(page, clients)) {
    await deleteClient(page, await idFromListLink(page, clients, identifier));
  }
  const resources = `${env.adminUrl}/admin/resources`;
  for (const identifier of await leftoversOn(page, resources)) {
    await deleteResource(page, await idFromListLink(page, resources, identifier));
  }
  const groups = `${env.adminUrl}/admin/groups`;
  for (const identifier of await leftoversOn(page, groups)) {
    await deleteGroup(page, await idFromListLink(page, groups, identifier));
  }
  // A legal document is listed by its title, with its short name beneath, which is what the tests
  // name with the prefix. One never published is deleted and a published one retired; a retired one
  // stays as it is, since a published document is never deleted.
  await page.goto(`${env.adminUrl}/admin/legal-documents`);
  const legalDocumentIds = (
    await page
      .locator("#legalDocumentsTable tbody tr")
      .filter({ has: page.locator(".cell-secondary", { hasText: new RegExp(`^${testPrefix}`) }) })
      .filter({ hasNot: page.locator(".tag-caution") })
      .locator("td:first-child a")
      .evaluateAll((links) => links.map((link) => link.getAttribute("href") ?? ""))
  ).map(legalDocumentIdFrom);
  for (const id of legalDocumentIds) await putAwayLegalDocument(page, id);
  // The users list is paged; a search narrows it to the test users, a page at a time.
  const users = `${env.adminUrl}/admin/users?query=${testPrefix}`;
  for (let emails = await leftoversOn(page, users); emails.length > 0; emails = await leftoversOn(page, users)) {
    for (const email of emails) await deleteUser(page, await idFromListLink(page, users, email));
  }
});
