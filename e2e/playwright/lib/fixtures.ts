// The suite's test object: Playwright's, plus fixtures that create what a test needs and remove it
// afterwards, pass or fail, so the shared environment stays as it was.
import { test as base, expect } from "@playwright/test";
import { clientIdFromList, deleteClient, signInAsAdmin, submitNewClient, type NewClient } from "./admin-console";
import { env } from "./environment";
import { userAgentFor } from "./devices";
import { adminStorageState } from "./paths";
import { uniqueIdentifier } from "./unique";

export interface TestClient {
  id: number;
  identifier: string;
  // Marks the client deleted by the test itself, so the fixture does not try again.
  markDeleted(): void;
}

interface Fixtures {
  clients: {
    // Creates a client through the admin console under a fresh identifier.
    create(options?: Omit<NewClient, "identifier">): Promise<TestClient>;
  };
}

interface WorkerFixtures {
  // The administrator's session for this worker: each worker signs in for itself, as a device of its
  // own, so parallel tests never share one session (whose one-time messages and token refreshes would
  // then cross) nor end each other's.
  adminSession: string;
  workerUserAgent: string;
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  workerUserAgent: [
    async ({}, use, workerInfo) => use(userAgentFor(`worker-${workerInfo.parallelIndex}`)),
    { scope: "worker" },
  ],
  adminSession: [
    async ({ browser, workerUserAgent }, use, workerInfo) => {
      const path = adminStorageState(workerInfo.parallelIndex);
      const context = await browser.newContext({ userAgent: workerUserAgent });
      await signInAsAdmin(await context.newPage());
      await context.storageState({ path });
      await context.close();
      await use(path);
    },
    { scope: "worker" },
  ],
  storageState: ({ adminSession }, use) => use(adminSession),
  userAgent: ({ workerUserAgent }, use) => use(workerUserAgent),

  clients: async ({ context }, use) => {
    const created: { id: number; identifier: string; deleted: boolean }[] = [];
    // Its own tab, so a test's page is left as the test left it.
    const page = await context.newPage();

    await use({
      async create(options = {}) {
        const identifier = uniqueIdentifier("c");
        await submitNewClient(page, { ...options, identifier });
        await expect(page).toHaveURL(`${env.adminUrl}/admin/clients`);
        const id = await clientIdFromList(page, identifier);
        const entry = { id, identifier, deleted: false };
        created.push(entry);
        return { id, identifier, markDeleted: () => (entry.deleted = true) };
      },
    });

    for (const client of created.filter((c) => !c.deleted)) {
      await deleteClient(page, client.id);
    }
    await page.close();
  },
});

export { expect };
