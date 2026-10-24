// Layout assertions shared by the Italian browser checks.
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

export async function fitsInItalian(page: Page) {
  await expect(page.locator("html")).toHaveAttribute("lang", "it");
  await expect(page.locator("h1")).toBeVisible();
  // Let tab-bar wrapping and searchable selects finish their initial layout.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  const overflow = await page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const problems: string[] = [];
    if (document.documentElement.scrollWidth > width) problems.push("page scrolls horizontally");
    for (const element of document.querySelectorAll<HTMLElement>("button, .tab-item, th, .page-title, dialog[open], [role=alert]")) {
      if (!element.checkVisibility() || element.closest(".table-scroll") || element.classList.contains("sr-only")) continue;
      const box = element.getBoundingClientRect();
      if (box.right <= 0 || box.width <= 1) continue;
      if (box.left < -1 || box.right > width + 1 || element.scrollWidth > element.clientWidth + 1) {
        problems.push(`${element.tagName}: ${element.textContent?.trim().slice(0, 90)}`);
      }
    }
    return problems;
  });
  expect(overflow, page.url()).toEqual([]);
  await expect(page.locator("body")).not.toContainText(/\b(?:adminconsole|validator|handler)\.[a-z_]+\./);
}
