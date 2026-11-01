// The acceptance step (#622): a sign-in to an app, once the user is authenticated and before consent,
// lists the must-accept documents the user owes for that app, each with an unticked box. Accept with
// a box unticked shows the step again; Accept records the versions shown and goes on to the app;
// Decline answers the app access_denied and the next sign-in asks again; a new version is asked again;
// a single sign-on is asked too; and prompt=none is answered interaction_required.
//
// Every document here is set to selected apps, clients of the test's own, before it is published, so
// no other test's sign-in owes it. The clients fixture deletes the clients, and the legal documents
// fixture retires the documents.
import type { Browser, Page } from "@playwright/test";
import { type LegalDocumentKind, publishLegalDocument, saveLegalDocumentDraft, setLegalDocumentApps } from "../../lib/admin-console";
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
