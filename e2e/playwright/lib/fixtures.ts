// The suite's test object: Playwright's, plus fixtures that create what a test needs and remove it
// afterwards, pass or fail, so the shared environment stays as it was. A test fails when a page of the
// auth server or the admin console reports a Content-Security-Policy violation, in any browser context
// it opens (lib/csp-violations.ts).
import { randomBytes } from "node:crypto";
import {
  addResourcePermission,
  clientIdFromList,
  deleteClient,
  deleteGroup,
  deleteResource,
  deleteUser,
  idFromListLink,
  legalDocumentIdFrom,
  publishLegalDocument,
  putAwayLegalDocument,
  resourceUrl,
  saveLegalDocumentDraft,
  saveResourcePermissions,
  signInAsAdmin,
  submitNewClient,
  submitNewGroup,
  submitNewLegalDocument,
  submitNewResource,
  submitNewUser,
  type LegalDocumentKind,
  type NewClient,
  type NewGroup,
} from "./admin-console";
import { CspViolationWatcher, expect, test as base } from "./csp-violations";
import { env } from "./environment";
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

export interface TestLegalDocument {
  id: number;
  shortName: string;
  title: string;
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
  legalDocuments: {
    // Creates a legal document under a fresh short name, a notice for information unless said
    // otherwise, holding this text as its saved draft, and published as version 1 when asked.
    create(options?: { kind?: LegalDocumentKind; markdown?: string; publish?: boolean }): Promise<TestLegalDocument>;
  };
  users: {
    // Creates a user with a password set now, so no link is mailed: a random one unless given; with the
    // email verified when asked, which mail such as a password reset is only ever sent to.
    create(options?: { emailVerified?: boolean; password?: string }): Promise<TestUser>;
  };
}

interface WorkerFixtures {
  // The administrator's session for this worker: each worker signs in for itself, in a browser of its
  // own, so parallel tests never share one session (whose one-time messages and token refreshes would
  // then cross) nor end each other's.
  adminSession: string;
}

export const test = base.extend<Fixtures, WorkerFixtures>({
  cspWatchedOrigins: [[new URL(env.authUrl).origin, new URL(env.adminUrl).origin], { scope: "worker" }],

  adminSession: [
    async ({ browser, cspWatchedOrigins }, use, workerInfo) => {
      const path = adminStorageState(workerInfo.parallelIndex);
      // Made before any test, so watched here rather than by the test's watcher.
      const watcher = new CspViolationWatcher(cspWatchedOrigins);
      const context = await browser.newContext();
      await watcher.watch(context);
      await signInAsAdmin(await context.newPage());
      await context.storageState({ path });
      await watcher.settle();
      await context.close();
      watcher.expectNone();
      await use(path);
    },
    { scope: "worker" },
  ],
  storageState: ({ adminSession }, use) => use(adminSession),

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
        const id = await idFromListLink(page, `${env.adminUrl}/admin/resources`, identifier);
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
        const id = await idFromListLink(page, `${env.adminUrl}/admin/groups`, identifier);
        const entry = { id, deleted: false };
        created.push(entry);
        return { id, identifier, markDeleted: () => (entry.deleted = true) };
      },
    });

    for (const group of created.filter((g) => !g.deleted)) await deleteGroup(page, group.id);
    await page.close();
  },

  // A published document is never deleted, so what a test published is retired afterwards and stays
  // in the list, retired; one never published is deleted (putAwayLegalDocument).
  legalDocuments: async ({ context }, use) => {
    const created: number[] = [];
    const page = await context.newPage();

    await use({
      async create({ kind = "for_information", markdown = "", publish = false } = {}) {
        const shortName = uniqueIdentifier("ld");
        const title = `${shortName} document`;
        await submitNewLegalDocument(page, { kind, title, shortName });
        await expect(page).toHaveURL(/\/admin\/legal-documents\/\d+\/draft$/);
        const id = legalDocumentIdFrom(page.url());
        created.push(id);
        if (markdown !== "") await saveLegalDocumentDraft(page, id, { markdown });
        if (publish) await publishLegalDocument(page, id);
        return { id, shortName, title };
      },
    });

    for (const id of created) await putAwayLegalDocument(page, id);
    await page.close();
  },

  users: async ({ context }, use) => {
    const created: { id: number; deleted: boolean }[] = [];
    const page = await context.newPage();

    await use({
      async create({ emailVerified = false, password = randomBytes(18).toString("base64url") } = {}) {
        const email = `${uniqueIdentifier("u")}@example.com`;
        await submitNewUser(page, { email, givenName: "Playwright", familyName: "Tester", password, emailVerified });
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
