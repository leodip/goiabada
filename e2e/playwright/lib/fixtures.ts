// The suite's test object: Playwright's, plus fixtures that create what a test needs and remove it
// afterwards, pass or fail, so the shared environment stays as it was.
import { randomBytes } from "node:crypto";
import { test as base, expect } from "@playwright/test";
import {
  addResourcePermission,
  clientIdFromList,
  deleteClient,
  deleteGroup,
  deleteResource,
  deleteUser,
  idFromListLink,
  resourceUrl,
  saveResourcePermissions,
  signInAsAdmin,
  submitNewClient,
  submitNewGroup,
  submitNewResource,
  submitNewUser,
  type NewClient,
  type NewGroup,
} from "./admin-console";
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

export interface TestResource {
  id: number;
  identifier: string;
  // The resource's permissions, in the order given, by identifier.
  permissions: string[];
  markDeleted(): void;
}

export interface TestGroup {
  id: number;
  identifier: string;
  markDeleted(): void;
}

export interface TestUser {
  id: number;
  email: string;
  password: string;
  markDeleted(): void;
}

interface Fixtures {
  clients: {
    // Creates a client through the admin console under a fresh identifier.
    create(options?: Omit<NewClient, "identifier">): Promise<TestClient>;
  };
  resources: {
    // Creates a resource under a fresh identifier, with these permissions saved on it.
    create(options?: { description?: string; permissions?: string[] }): Promise<TestResource>;
  };
  groups: {
    // Creates a group under a fresh identifier; both include switches on unless said otherwise.
    create(options?: Omit<NewGroup, "identifier">): Promise<TestGroup>;
  };
  users: {
    // Creates a user with a password set, so no email is sent.
    create(): Promise<TestUser>;
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

  resources: async ({ context }, use) => {
    const created: { id: number; deleted: boolean }[] = [];
    const page = await context.newPage();

    await use({
      async create({ description = "", permissions = [] } = {}) {
        const identifier = uniqueIdentifier("r");
        await submitNewResource(page, identifier, description);
        await expect(page).toHaveURL(`${env.adminUrl}/admin/resources`);
        const id = await idFromListLink(page, `${env.adminUrl}/admin/resources`, identifier, "Manage");
        const entry = { id, deleted: false };
        created.push(entry);
        if (permissions.length > 0) {
          await page.goto(resourceUrl(id, "permissions"));
          for (const permission of permissions) await addResourcePermission(page, permission);
          await saveResourcePermissions(page);
        }
        return { id, identifier, permissions, markDeleted: () => (entry.deleted = true) };
      },
    });

    for (const resource of created.filter((r) => !r.deleted)) {
      await deleteResource(page, resource.id);
    }
    await page.close();
  },

  groups: async ({ context }, use) => {
    const created: { id: number; deleted: boolean }[] = [];
    const page = await context.newPage();

    await use({
      async create(options = {}) {
        const identifier = uniqueIdentifier("g");
        await submitNewGroup(page, { ...options, identifier });
        await expect(page).toHaveURL(`${env.adminUrl}/admin/groups`);
        const id = await idFromListLink(page, `${env.adminUrl}/admin/groups`, identifier, "Manage");
        const entry = { id, deleted: false };
        created.push(entry);
        return { id, identifier, markDeleted: () => (entry.deleted = true) };
      },
    });

    for (const group of created.filter((g) => !g.deleted)) await deleteGroup(page, group.id);
    await page.close();
  },

  users: async ({ context }, use) => {
    const created: { id: number; deleted: boolean }[] = [];
    const page = await context.newPage();

    await use({
      async create() {
        const email = `${uniqueIdentifier("u")}@example.com`;
        const password = randomBytes(18).toString("base64url");
        await submitNewUser(page, { email, givenName: "Playwright", familyName: "Tester", password });
        await expect(page).toHaveURL(/\/admin\/users\/\d+\/details/);
        const id = Number(page.url().match(/\/admin\/users\/(\d+)\/details/)![1]);
        const entry = { id, deleted: false };
        created.push(entry);
        return { id, email, password, markDeleted: () => (entry.deleted = true) };
      },
    });

    for (const user of created.filter((u) => !u.deleted)) await deleteUser(page, user.id);
    await page.close();
  },
});

export { expect };
