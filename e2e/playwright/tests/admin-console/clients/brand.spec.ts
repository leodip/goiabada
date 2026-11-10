// A client's brand, chosen on its Settings tab under Sign-in and consent pages (#812): the client's
// sign-in, forgot-password and sign-out pages are drawn in it, while another client's sign-in keeps the
// default brand. Deleting the brand says how many clients use it, and moves them back to the default.
// The brand is not the default and the clients are the test's own, so no other page changes.
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
  listBrands,
  withBrand,
} from "../../../lib/brands";
import { openSignIn } from "../../../lib/browser-sign-in";
import { env } from "../../../lib/environment";
import { expect, type TestClient, test } from "../../../lib/fixtures";
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
