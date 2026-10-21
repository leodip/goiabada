// axe-core over a page in each of its states, in the light and the dark scheme, against the WCAG 2.2
// A and AA rules. tests/accessibility walks every page through it, its states built from the shapes at
// the end of this file.
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { cancelDialog } from "./admin-console";
import { expect, test } from "./fixtures";

const wcagTags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

// A page in one state: reach brings the page there and waits for what shows it is there; leave, when
// given, closes what the state opened, such as a dialog, before the next state.
export interface State {
  name: string;
  reach: () => Promise<void>;
  leave?: () => Promise<void>;
}

// Every violation axe finds on the page as it stands, one line per element: the state, the scheme
// and the page's address, then the rule, the element and what the rule asks, so a red run says what
// to fix and where. The seeded theme is Automatic, which follows the device, so the emulated scheme
// is what draws the page light or dark.
export async function axeViolations(page: Page, state: string): Promise<string[]> {
  await page.waitForLoadState("load");
  // Scrolled by what the state did, a page can sit under the sticky header, which axe then reads as
  // covering the targets beneath it.
  await page.evaluate(() => window.scrollTo(0, 0));
  const address = new URL(page.url());
  const where = `${address.origin}${address.pathname}${address.search}`;
  expect.soft(await page.locator("html").getAttribute("data-theme"), `${state}: the stored theme is Automatic`).toBeNull();
  const found: string[] = [];
  for (const colorScheme of ["light", "dark"] as const) {
    // Reduced motion, so no transition is caught half way between the schemes' colours.
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    // Legacy mode runs axe in the page itself rather than gathering its results in a blank page of
    // its own, which no page here needs, having no frames.
    const { violations } = await new AxeBuilder({ page }).withTags(wcagTags).setLegacyMode(true).analyze();
    for (const violation of violations) {
      for (const node of violation.nodes) {
        const target = node.target.map((part) => (Array.isArray(part) ? part.join(" >>> ") : part)).join(" ");
        found.push(`${state}, ${colorScheme} (${where}): ${violation.id} at ${target}: ${violation.help}`);
      }
    }
  }
  return found;
}

// Brings the page to each state in turn and checks it, each a step of its own. A violation fails the
// test without stopping it, so one run lists every violation; a state that cannot be reached stops it.
export async function checkStates(page: Page, states: State[]) {
  for (const state of states) {
    await test.step(state.name, async () => {
      await state.reach();
      expect.soft(await axeViolations(page, state.name), `WCAG 2.2 A and AA violations on ${state.name}`).toEqual([]);
      await state.leave?.();
    });
  }
}

// The page at this address, answered there with this status.
export function at(page: Page, name: string, url: string, status = 200): State {
  return {
    name,
    reach: async () => {
      const response = await page.goto(url);
      expect(response?.status(), url).toBe(status);
      await expect(page).toHaveURL(url);
    },
  };
}

// A page whose heading says it is the one reached.
export function titled(page: Page, name: string, heading: string, act: () => Promise<unknown>): State {
  return {
    name,
    reach: async () => {
      await act();
      await expect(page.getByRole("heading", { level: 1, name: heading, exact: true })).toBeVisible();
    },
  };
}

// A submission refused at the field it is about, which the page marks invalid.
export function refused(page: Page, name: string, field: string, act: () => Promise<unknown>): State {
  return {
    name,
    reach: async () => {
      await act();
      await expect(page.locator(`#${field}`)).toHaveAttribute("aria-invalid", "true");
    },
  };
}

// A save answered with the page's notice that it worked.
export function saved(page: Page, name: string, act: () => Promise<unknown>): State {
  return {
    name,
    reach: async () => {
      await act();
      await expect(page.locator(".panel-body > .notice-positive")).toBeVisible();
    },
  };
}

// A notice a script writes in a status region, the answer to something done in the page.
export function says(page: Page, name: string, region: string, act: () => Promise<unknown>): State {
  return {
    name,
    reach: async () => {
      await act();
      await expect(page.locator(`#${region} .notice`)).toBeVisible();
    },
  };
}

// A confirmation open: a removal's or a save's. It is answered with Cancel once checked.
export function asks(page: Page, name: string, act: () => Promise<unknown>): State {
  return {
    name,
    reach: async () => {
      await act();
      await expect(page.locator("dialog[open]")).toBeVisible();
    },
    leave: () => cancelDialog(page),
  };
}
