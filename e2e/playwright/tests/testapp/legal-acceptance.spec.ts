// The acceptance step (#622): a sign-in to an app, once the user is authenticated and before consent,
// lists the must-accept documents the user owes for that app, each with an unticked box. Accept with
// a box unticked shows the step again; Accept records the versions shown and goes on to the app;
// Decline answers the app access_denied and the next sign-in asks again; a new version is asked again;
// a single sign-on is asked too; prompt=none is answered interaction_required; a retired document is
// asked of nobody until it is restored; and an app added to a published document asks its users at
// their next sign-in there, with no new version, but not a user who accepted it on another app.
//
// Every document here is set to selected apps, clients of the test's own, before it is published, so
// no other test's sign-in owes it. The clients fixture deletes the clients, and the legal documents
// fixture retires the documents.
import type { Browser, Page } from "@playwright/test";
import {
  type LegalDocumentKind,
  legalDocumentUrl,
  publishLegalDocument,
  restoreLegalDocument,
  retireLegalDocument,
  saveLegalDocumentDraft,
  setLegalDocumentApps,
} from "../../lib/admin-console";
import { openSignIn, redirectParams, submitPassword, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, type TestClient, type TestLegalDocument, test } from "../../lib/fixtures";
import { codeRequest } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

interface LegalDocumentsFixture {
  create(options?: { kind?: LegalDocumentKind; markdown?: string }): Promise<TestLegalDocument>;
}

// A must-accept document for the client alone, published.
async function termsFor(page: Page, legalDocuments: LegalDocumentsFixture, client: TestClient) {
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice to each other." });
  await setLegalDocumentApps(page, doc.id, [client.identifier]);
  await publishLegalDocument(page, doc.id);
  return doc;
}

// Signs in to the client with a password in a browser of its own, and returns the page where the
// sign-in stopped: the step, or back at the redirect URI.
async function signIn(browser: Browser, client: TestClient, user: { email: string; password: string }) {
  const { context, page } = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await submitPassword(page, user.email, user.password);
  await page.waitForURL((url) => url.pathname === "/auth/legal-acceptance" || url.href.startsWith(testRedirectUri));
  return { context, page };
}

// Sends a browser that holds a session to the client's authorization request, with any other
// parameters, and waits for where it stops.
async function authorizeAgain(page: Page, client: TestClient, params: Record<string, string> = {}) {
  const { params: request } = codeRequest(client.identifier, params);
  await page.goto(`${env.authUrl}/auth/authorize?${new URLSearchParams(request)}`);
  await page.waitForURL((url) => url.pathname === "/auth/legal-acceptance" || url.href.startsWith(testRedirectUri));
}

function backAtTheApp(page: Page) {
  return redirectParams(new URL(page.url()));
}

const accept = (page: Page) => page.getByRole("button", { name: "Accept", exact: true }).click();

// Ticks every box on the step, accepts, and waits to be back at the app.
async function acceptAll(page: Page) {
  for (const box of await page.getByRole("checkbox").all()) await box.check();
  await accept(page);
  await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
}

function isBackAtTheApp(page: Page) {
  return page.url().startsWith(testRedirectUri);
}

test("the step lists what is owed; an unticked box is refused; Accept goes on, and the next sign-in is not asked", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const doc = await termsFor(page, legalDocuments, client);

  const { context, page: own } = await signIn(browser, client, user);
  await expect(own).toHaveURL(/\/auth\/legal-acceptance/);
  await expect(own.getByRole("heading", { level: 1, name: "Accept the terms" })).toBeVisible();
  const box = own.getByRole("checkbox");
  await expect(box).toHaveCount(1);
  await expect(box).not.toBeChecked();
  await expect(own.locator("form").getByRole("link", { name: doc.title })).toHaveAttribute("href", `/legal/${doc.shortName}`);

  await accept(own);
  await expect(own.locator("#legal-acceptance-error")).toContainText("Tick the box beside every document");
  await expect(own.getByRole("checkbox")).toHaveAttribute("aria-invalid", "true");

  await own.getByRole("checkbox").check();
  await accept(own);
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expect(backAtTheApp(own).get("code"), "the app gets its code").toBeTruthy();

  await authorizeAgain(own, client);
  expect(own.url().startsWith(testRedirectUri), "accepted once, the next sign-in goes straight through").toBe(true);
  expect(backAtTheApp(own).get("code")).toBeTruthy();
  await context.close();
});

test("Decline answers the app access_denied, and the next sign-in asks again", async ({ page, browser, clients, users, legalDocuments }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await termsFor(page, legalDocuments, client);

  const { context, page: own } = await signIn(browser, client, user);
  await own.getByRole("button", { name: "Decline", exact: true }).click();
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));
  expect(backAtTheApp(own).get("error")).toBe("access_denied");
  expect(backAtTheApp(own).get("code")).toBeNull();

  // The session stays: no password is asked, and the step is.
  await authorizeAgain(own, client);
  await expect(own).toHaveURL(/\/auth\/legal-acceptance/);
  await context.close();
});

test("a new version is asked again", async ({ page, browser, clients, users, legalDocuments }) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const doc = await termsFor(page, legalDocuments, client);

  const { context, page: own } = await signIn(browser, client, user);
  await expect(own.getByText("Version 1", { exact: true })).toBeVisible();
  await own.getByRole("checkbox").check();
  await accept(own);
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));

  await saveLegalDocumentDraft(page, doc.id, { markdown: "Be even nicer to each other." });
  await publishLegalDocument(page, doc.id);
  await authorizeAgain(own, client);
  await expect(own).toHaveURL(/\/auth\/legal-acceptance/);
  await expect(own.getByText("Version 2", { exact: true })).toBeVisible();
  await context.close();
});

test("a single sign-on is asked too, and prompt=none is answered interaction_required", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const user = await users.create();
  const { client: other } = await browserSignInClient(page, clients);
  const { client } = await browserSignInClient(page, clients);
  await termsFor(page, legalDocuments, client);

  // Signed in to another app, which owes nothing.
  const { context, page: own } = await signIn(browser, other, user);
  expect(own.url().startsWith(testRedirectUri)).toBe(true);

  await authorizeAgain(own, client, { prompt: "none" });
  expect(backAtTheApp(own).get("error")).toBe("interaction_required");
  expect(backAtTheApp(own).get("error_description")).toBe("Acceptance of a legal document is required");

  await authorizeAgain(own, client);
  await expect(own, "no password is asked, and the step is").toHaveURL(/\/auth\/legal-acceptance/);
  await own.getByRole("checkbox").check();
  await accept(own);
  await own.waitForURL((url) => url.href.startsWith(testRedirectUri));

  await authorizeAgain(own, client, { prompt: "none" });
  expect(backAtTheApp(own).get("code"), "accepted, the silent request gets its code").toBeTruthy();
  await context.close();
});

test("a retired document is asked of nobody; restored, it is asked again of whoever has not accepted it", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const accepted = await users.create();
  const owing = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const doc = await termsFor(page, legalDocuments, client);

  // One user accepts version 1 before the document is retired.
  const first = await signIn(browser, client, accepted);
  await acceptAll(first.page);

  await retireLegalDocument(page, doc.id);
  const second = await signIn(browser, client, owing);
  expect(isBackAtTheApp(second.page), "a retired document is not asked").toBe(true);
  expect(backAtTheApp(second.page).get("code")).toBeTruthy();

  // Restored, it is in effect again at version 1: the user who never accepted it is asked at their
  // next sign-in, and the one who accepted version 1 is not.
  await restoreLegalDocument(page, doc.id);
  await authorizeAgain(second.page, client);
  await expect(second.page).toHaveURL(/\/auth\/legal-acceptance/);
  await expect(second.page.getByText("Version 1", { exact: true })).toBeVisible();
  await authorizeAgain(first.page, client);
  expect(isBackAtTheApp(first.page), "the version accepted before the retirement still counts").toBe(true);
  expect(backAtTheApp(first.page).get("code")).toBeTruthy();
  await first.context.close();
  await second.context.close();
});

test("an app added to a published document asks its users with no new version, but not a user who accepted it elsewhere", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const accepted = await users.create();
  const owing = await users.create();
  const { client: shop } = await browserSignInClient(page, clients);
  const { client: forum } = await browserSignInClient(page, clients);
  const doc = await termsFor(page, legalDocuments, shop);

  // One user accepts it on the shop; the forum asks the other user nothing yet.
  const first = await signIn(browser, shop, accepted);
  await acceptAll(first.page);
  const second = await signIn(browser, forum, owing);
  expect(isBackAtTheApp(second.page), "the forum owes nothing yet").toBe(true);

  // The forum is added, which publishes no new version.
  await setLegalDocumentApps(page, doc.id, [shop.identifier, forum.identifier]);
  await page.goto(legalDocumentUrl(doc.id, "versions"));
  await expect(page.locator("#versionsTable tbody tr")).toHaveCount(1);

  // The user who never accepted it is asked at their next sign-in to the forum, at version 1.
  await authorizeAgain(second.page, forum);
  await expect(second.page).toHaveURL(/\/auth\/legal-acceptance/);
  await expect(second.page.getByText("Version 1", { exact: true })).toBeVisible();

  // The user who accepted it on the shop is not asked on the forum: one acceptance counts on every
  // app the document covers.
  await authorizeAgain(first.page, forum);
  expect(isBackAtTheApp(first.page), "accepted on the shop, the forum does not ask").toBe(true);
  expect(backAtTheApp(first.page).get("code")).toBeTruthy();

  // The shop taken off, the document asks nothing there.
  await setLegalDocumentApps(page, doc.id, [forum.identifier]);
  await authorizeAgain(second.page, shop);
  expect(isBackAtTheApp(second.page), "an app the document no longer lists does not ask").toBe(true);
  expect(backAtTheApp(second.page).get("code")).toBeTruthy();
  await first.context.close();
  await second.context.close();
});
