// Runs before every other test: sweeps what earlier runs that stopped half way may have left behind.
import { test as setup, type Page } from "@playwright/test";
import { userAgentFor } from "../lib/devices";
import {
  deleteClient,
  deleteGroup,
  deleteResource,
  deleteUser,
  idFromListLink,
  signInAsAdmin,
} from "../lib/admin-console";
import { env } from "../lib/environment";
import { restoreSeededSettings } from "../lib/settings";
import { testPrefix } from "../lib/unique";

setup.use({ userAgent: userAgentFor("setup") });

// The cells of a list page that hold a name the tests made.
async function leftoversOn(page: Page, listUrl: string): Promise<string[]> {
  await page.goto(listUrl);
  return (await page.getByRole("cell").allInnerTexts())
    .map((text) => text.trim())
    .filter((text) => text.startsWith(testPrefix));
}

setup("sweep what earlier runs left", async ({ page }, testInfo) => {
  await signInAsAdmin(page);
  // The settings tests put back what they change; one that failed while doing so is put right here.
  const drifted = await restoreSeededSettings(page);
  if (drifted.length > 0) {
    testInfo.annotations.push({ type: "settings restored", description: drifted.join("; ") });
    console.warn(`settings were not as seeded, restored: ${drifted.join("; ")}`);
  }
  // Every test removes what it creates, so anything named with the test prefix at the start of a run
  // is what a run that crashed left. Assumes one run at a time against the environment.
  const clients = `${env.adminUrl}/admin/clients`;
  for (const identifier of await leftoversOn(page, clients)) {
    await deleteClient(page, await idFromListLink(page, clients, identifier, "Manage"));
  }
  const resources = `${env.adminUrl}/admin/resources`;
  for (const identifier of await leftoversOn(page, resources)) {
    await deleteResource(page, await idFromListLink(page, resources, identifier, "Manage"));
  }
  const groups = `${env.adminUrl}/admin/groups`;
  for (const identifier of await leftoversOn(page, groups)) {
    await deleteGroup(page, await idFromListLink(page, groups, identifier, "Manage"));
  }
  // The users list is paged; a search narrows it to the test users, a page at a time.
  const users = `${env.adminUrl}/admin/users?query=${testPrefix}`;
  for (let emails = await leftoversOn(page, users); emails.length > 0; emails = await leftoversOn(page, users)) {
    for (const email of emails) await deleteUser(page, await idFromListLink(page, users, email, "Manage"));
  }
});
