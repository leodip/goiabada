// A brand's footer links and support contact set in the brand editor (#814), seen on the console's own
// end-user pages: under home's card and after an Account page's content, each label in the page's
// language. The console's own client's brand is what every console page is drawn in, so this runs
// alone, and puts the client back on the default brand. footer.spec.ts covers the auth server's pages.
import { clientIdFromList, setClientBrand } from "../../../lib/admin-console";
import { brandUrl, drawnFooter, fillBrandFooter, withBrand } from "../../../lib/brands";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";

test("footer links and a support contact set in the editor are drawn on the console's home and an Account page", async ({ page, browser }) => {
  const consoleClient = await clientIdFromList(page, "admin-console-client");

  await withBrand(page, { appearance: "auto", theme: "avocado" }, async (brand) => {
    await page.goto(brandUrl(brand.id, "edit"));
    await fillBrandFooter(page, {
      footerLinks: [
        { label: "Terms", url: "https://example.com/terms", labels: { de: "Nutzungsbedingungen" } },
        { label: "Status", url: "https://status.example.com/" },
      ],
      supportEmail: "help@example.com",
      supportPhone: "+44 20 7946 0958",
    });
    await page.locator("#btnSave").click();
    await expect(page.getByText("Brand saved.", { exact: true })).toBeVisible();

    try {
      await setClientBrand(page, consoleClient, brand);
      const notice = "(opens in a new tab)";

      // Home: the footer under the card.
      await page.goto(`${env.adminUrl}/`);
      await expect(page.getByRole("contentinfo")).toBeVisible();
      const home = (await drawnFooter(page))!;
      expect(home.links.map((link) => [link.text, link.href])).toEqual([
        [`Terms ${notice}`, "https://example.com/terms"],
        [`Status ${notice}`, "https://status.example.com/"],
      ]);
      expect(home.contact).toBe("Need help? help@example.com +442079460958");
      expect(home.afterMain).toBe(true);

      // An Account page: the footer after the content, outside main.
      await page.goto(`${env.adminUrl}/account/profile`);
      await expect(page.getByRole("contentinfo")).toBeVisible();
      await expect(page.locator("main footer")).toHaveCount(0);
      const account = (await drawnFooter(page))!;
      expect(account.links.map((link) => link.href)).toEqual(["https://example.com/terms", "https://status.example.com/"]);
      expect(account.contact).toBe("Need help? help@example.com +442079460958");

      // Home in German takes the German label, and the fallback for the link with none.
      const context = await browser.newContext({ locale: "de-DE", storageState: { cookies: [], origins: [] } });
      const german = await context.newPage();
      await german.goto(`${env.adminUrl}/`);
      await expect(german.locator("html")).toHaveAttribute("lang", "de");
      const deNotice = "(öffnet sich in einem neuen Tab)";
      expect((await drawnFooter(german))!.links.map((link) => link.text)).toEqual([`Nutzungsbedingungen ${deNotice}`, `Status ${deNotice}`]);
      await context.close();
    } finally {
      await setClientBrand(page, consoleClient, "default");
    }
  });
});
