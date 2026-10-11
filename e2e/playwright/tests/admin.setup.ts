// Runs before every other test: sweeps what earlier runs that stopped half way may have left behind.
import { test as setup } from "@playwright/test";
import { userAgentFor } from "../lib/devices";
import { clientIdFromList, deleteClient, signInAsAdmin } from "../lib/admin-console";
import { env } from "../lib/environment";
import { testPrefix } from "../lib/unique";

setup.use({ userAgent: userAgentFor("setup") });

setup("sweep what earlier runs left", async ({ page }) => {
  await signInAsAdmin(page);
  // Every test removes what it creates, so anything named with the test prefix at the start of a run
  // is what a run that crashed left. Assumes one run at a time against the environment.
  await page.goto(`${env.adminUrl}/admin/clients`);
  const leftovers = (await page.getByRole("cell").allInnerTexts())
    .map((text) => text.trim())
    .filter((text) => text.startsWith(testPrefix));
  for (const identifier of leftovers) {
    await deleteClient(page, await clientIdFromList(page, identifier));
  }
});
