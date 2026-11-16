// A client's brand, chosen on its Settings tab under Sign-in and consent pages (#812): the client's
// sign-in, forgot-password and sign-out pages are drawn in it, while another client's sign-in keeps the
// default brand. Deleting the brand says how many clients use it, and moves them back to the default.
// The brand is not the default and the clients are the test's own, so no other page changes. The
// console's own pages, in the brand it is drawn in as the run finds it, link the brand's colors-only
// stylesheet on its admin pages and the full one on its end-user pages (#813); the kit drawn on them,
// which changes every console page, is brand.system.ts's. Pages that belong to no client are drawn in
// the default brand in a browser holding the client's sign-in, and a legal document its acceptance
// step links is drawn in its brand.
import type { Browser } from "@playwright/test";
import { clientBrandChoice, clientBrandSelect, setClientBrand } from "../../../lib/admin-console";
import {
  brandRow,
  brandUrl,
  brandingUrl,
  defaultBrand,
  deleteBrand,
  expectDrawnInPlumDark,
  expectDrawnInSeededDefault,
  goiabadaIcons,
  listBrands,
  pageBrandStylesheets,
  pageIcons,
  withBrand,
} from "../../../lib/brands";
import { openSignIn, submitPassword } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
import { authorizeEndpoint, codeRequest } from "../../../lib/rfc6749";
import { browserSignInClient } from "../../../lib/test-clients";
import { uniqueIdentifier } from "../../../lib/unique";

// The client's sign-in, opened in a browser of its own, at its password step.
async function openPasswordStep(browser: Browser, client: TestClient) {
  const signIn = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  await expect(signIn.page).toHaveURL(/\/auth\/pwd/);
  return signIn;
}

test("a client given a brand on its Settings tab has its sign-in, forgot-password and sign-out pages drawn in it, and another client's sign-in keeps the default", async ({
  page,
  browser,
  clients,
}) => {
  const { client: branded } = await browserSignInClient(page, clients);
  const { client: plain } = await browserSignInClient(page, clients);
  const seeded = await defaultBrand(page);
  const onDefault = `Default brand (${seeded.name})`;

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    // A new client starts on the default brand, the select's first choice, which names it.
    expect(await clientBrandChoice(page, branded.id)).toBe(onDefault);
    await expect(clientBrandSelect(page).locator("option").first()).toHaveAttribute("value", "");
    await expect(clientBrandSelect(page).locator("option", { hasText: brand.name })).toHaveAttribute("value", String(brand.id));

    await setClientBrand(page, branded.id, brand);
    await expect(clientBrandSelect(page)).toHaveValue(String(brand.id));
    expect(await clientBrandChoice(page, branded.id), "the brand is stored").toBe(brand.name);
    expect(await clientBrandChoice(page, plain.id), "the other client is untouched").toBe(onDefault);

    // The client's sign-in, and the forgot-password page its link leads to, under the form and once
    // the link is sent.
    const own = await openPasswordStep(browser, branded);
    await expectDrawnInPlumDark(own.page, brand.id);
    await own.page.getByRole("link", { name: "Forgot your password?" }).click();
    await expect(own.page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
    await expectDrawnInPlumDark(own.page, brand.id);
    await own.page.locator("#email").fill(`${uniqueIdentifier("u")}@example.com`);
    await own.page.getByRole("button", { name: "Send reset link", exact: true }).click();
    await expect(own.page.getByRole("heading", { name: "Check your email" })).toBeVisible();
    await expectDrawnInPlumDark(own.page, brand.id);
    // The same page naming no sign-in belongs to no client, and is drawn in the default.
    await own.page.goto(`${env.authUrl}/forgot-password`);
    await expect(own.page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
    await expectDrawnInSeededDefault(own.page, seeded.id);
    // Its sign-in link leads to the console's account page: a bare password step would be refused
    // as no longer active while this browser holds the client's sign-in.
    await expect(own.page.getByRole("link", { name: "Sign in to your account", exact: true })).toHaveAttribute("href", `${env.adminUrl}/account/profile`);
    await own.context.close();

    // Another client's sign-in keeps the default.
    const other = await openPasswordStep(browser, plain);
    await expectDrawnInSeededDefault(other.page, seeded.id);
    await other.context.close();

    // A sign-out naming the client by client_id: the question, the page its Stay signed in link
    // leads to (followed as a browser without script does), and the page after Sign out.
    const signOut = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const out = await signOut.newPage();
    const question = `${env.authUrl}/auth/logout?${new URLSearchParams({ client_id: branded.identifier })}`;
    await out.goto(question);
    await expect(out.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
    await expectDrawnInPlumDark(out, brand.id);
    const stay = await out.getByRole("link", { name: "Stay signed in", exact: true }).getAttribute("href");
    await out.goto(new URL(stay!, out.url()).href);
    await expect(out.getByRole("heading", { name: "Still signed in" })).toBeVisible();
    await expectDrawnInPlumDark(out, brand.id);
    await out.goto(question);
    await out.getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(out.getByRole("heading", { name: "Signed out" })).toBeVisible();
    await expectDrawnInPlumDark(out, brand.id);
    // A sign-out naming no client is drawn in the default.
    await out.goto(`${env.authUrl}/auth/logout`);
    await expect(out.getByRole("heading", { name: "Sign out", exact: true })).toBeVisible();
    await expectDrawnInSeededDefault(out, seeded.id);
    await signOut.close();
  });
});

test("deleting a brand a client uses says so, and puts the client back on the default brand", async ({ page, browser, clients }) => {
  const { client } = await browserSignInClient(page, clients);
  const seeded = await defaultBrand(page);

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    // Unused, its pages say no client uses it.
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator(".page-lead")).toHaveText(
      "Choose it on a client's Settings tab to draw that client's pages in it. No client uses this brand.",
    );

    await setClientBrand(page, client.id, brand);

    // The list's Clients column, the brand's page and its delete page say one client uses it, the
    // last naming the default brand it will move to.
    await page.goto(brandingUrl);
    await expect(brandRow(page, brand.name).locator('td[data-label="Clients"]')).toHaveText("1");
    await page.goto(brandUrl(brand.id, "edit"));
    await expect(page.locator(".page-lead")).toHaveText(
      "Choose it on a client's Settings tab to draw that client's pages in it. 1 client uses this brand.",
    );
    await page.goto(brandUrl(brand.id, "delete"));
    await expect(page.locator(".page-lead")).toHaveText(
      `The brand will be deleted. 1 client uses it. It will move to the default brand, ${seeded.name}.`,
    );

    await deleteBrand(page, brand.id);
    expect((await listBrands(page)).map((listed) => listed.id)).not.toContain(brand.id);

    // The client is back on the default brand, on its Settings tab and on its sign-in.
    expect(await clientBrandChoice(page, client.id)).toBe(`Default brand (${seeded.name})`);
    const signIn = await openPasswordStep(browser, client);
    await expectDrawnInSeededDefault(signIn.page, seeded.id);
    await signIn.context.close();
  });
});

test("the console's admin pages link its brand's colors-only stylesheet and Goiabada's icons, and its end-user pages the full stylesheet", async ({
  page,
}) => {
  // The console is drawn in the default brand, as the baseline leaves its own client, and the seeded
  // default has no favicon, so every page keeps Goiabada's icons.
  const seeded = await defaultBrand(page);
  const consoleIcons = goiabadaIcons(new URL(env.adminUrl).origin);

  // An admin page, one drawn with the admin menu: the brand's colors and nothing else of its kit.
  for (const path of ["/admin/clients", "/admin/settings/branding"]) {
    await page.goto(`${env.adminUrl}${path}`);
    await expect(page.getByRole("navigation", { name: "Admin", exact: true })).toBeVisible();
    expect(await pageBrandStylesheets(page), path).toEqual([{ brandId: seeded.id, kind: "colors" }]);
    expect(await pageIcons(page), path).toEqual(consoleIcons);
  }

  // The end-user pages: an Account page, home, and an error answered for an admin URL, a card page.
  await page.goto(`${env.adminUrl}/account/profile`);
  await expect(page.getByRole("navigation", { name: "Account", exact: true })).toBeVisible();
  expect(await pageBrandStylesheets(page), "an Account page").toEqual([{ brandId: seeded.id, kind: "full" }]);
  expect(await pageIcons(page), "an Account page").toEqual(consoleIcons);

  await page.goto(`${env.adminUrl}/`);
  await expect(page.locator(".auth-card")).toBeVisible();
  expect(await pageBrandStylesheets(page), "home").toEqual([{ brandId: seeded.id, kind: "full" }]);

  const missing = await page.goto(`${env.adminUrl}/admin/clients/999999999/settings`);
  expect(missing?.status()).toBe(404);
  await expect(page.locator(".auth-card")).toBeVisible();
  expect(await pageBrandStylesheets(page), "an error page at an admin URL").toEqual([{ brandId: seeded.id, kind: "full" }]);
  expect(await pageIcons(page), "an error page at an admin URL").toEqual(consoleIcons);
});

// Pages that belong to no client are drawn in the default brand, even in a browser holding a branded
// client's sign-in (#812 decision 2): an authorization request naming no client the auth server
// knows, the not found page, and a step the sign-in's URL does not name, which says the request is no
// longer active.
test("pages that belong to no client are drawn in the default brand, in a browser holding a branded client's sign-in", async ({
  page,
  browser,
  clients,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const seeded = await defaultBrand(page);
  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    await setClientBrand(page, client.id, brand);
    const signIn = await openPasswordStep(browser, client);
    try {
      await expectDrawnInPlumDark(signIn.page, brand.id);
      const tab = await signIn.context.newPage();

      const { params } = codeRequest("e2e-no-such-client");
      await tab.goto(`${authorizeEndpoint}?${new URLSearchParams(params)}`);
      await expect(tab.getByText(/The application does not exist/)).toBeVisible();
      await expectDrawnInSeededDefault(tab, seeded.id);

      const missing = await tab.goto(`${env.authUrl}/no-such-page`);
      expect(missing?.status()).toBe(404);
      await expect(tab.getByRole("heading", { name: "Page not found" })).toBeVisible();
      await expectDrawnInSeededDefault(tab, seeded.id);

      await tab.goto(`${env.authUrl}/auth/pwd`);
      await expect(tab.getByRole("heading", { name: "This request is no longer active" })).toBeVisible();
      await expectDrawnInSeededDefault(tab, seeded.id);
    } finally {
      await signIn.context.close();
    }
  });
});

// A legal document the acceptance step links is drawn in the client's brand in the browser holding
// the sign-in, and so is each version its page links; the same link anywhere else, or the document's
// own address, is drawn in the default brand (#812 decision 4).
test("a legal document opened from a client's acceptance step is drawn in its brand, and anywhere else in the default", async ({
  page,
  browser,
  clients,
  users,
  legalDocuments,
}) => {
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  const seeded = await defaultBrand(page);
  const doc = await legalDocuments.create({ kind: "must_accept", markdown: "Be nice to each other.", apps: [client.identifier], publish: true });

  await withBrand(page, { appearance: "dark", theme: "plum" }, async (brand) => {
    await setClientBrand(page, client.id, brand);
    const signIn = await openPasswordStep(browser, client);
    try {
      await submitPassword(signIn.page, user.email, user.password);
      await expect(signIn.page).toHaveURL(/\/auth\/legal-acceptance/);
      await expectDrawnInPlumDark(signIn.page, brand.id);

      // The link opens a tab of the same browser, which holds the sign-in.
      const link = signIn.page.locator("form").getByRole("link", { name: `${doc.title} (opens in a new tab)`, exact: true });
      const [reading] = await Promise.all([signIn.context.waitForEvent("page"), link.click()]);
      await reading.waitForLoadState();
      await expect(reading.getByRole("heading", { level: 1, name: `${doc.title}` })).toBeVisible();
      await expect(reading.locator("body")).toHaveAttribute("data-page", "legal-document");
      await expectDrawnInPlumDark(reading, brand.id);
      const linked = reading.url();
      expect(new URL(linked).searchParams.get("ceremony"), "the link names the sign-in").toBeTruthy();

      // Its version's link names the sign-in too, and the version's page keeps the brand.
      await reading.locator("#legal-document-versions").getByRole("link", { name: "Version 1", exact: true }).click();
      await expect(reading).toHaveURL(/\/versions\/1\?ceremony=/);
      await expectDrawnInPlumDark(reading, brand.id);

      // The document's own address, naming no sign-in, in the same browser.
      await reading.goto(`${env.authUrl}/legal/${doc.shortName}`);
      await expectDrawnInSeededDefault(reading, seeded.id);

      // The same link in another browser, which holds no sign-in.
      const elsewhere = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const other = await elsewhere.newPage();
      await other.goto(linked);
      await expect(other.getByRole("heading", { level: 1, name: `${doc.title}` })).toBeVisible();
      await expectDrawnInSeededDefault(other, seeded.id);
      await elsewhere.close();
    } finally {
      await signIn.context.close();
    }
  });
});
