// A page whose form-post.js submits its form as it loads, the auth server's form_post response and
// the console's sign-out on its way to the auth server, holds its card back for 2 seconds, so the
// card does not flash by while the next page loads (ui.css).
import { expect, type Page } from "@playwright/test";

// Checks the card on page is hidden through its first 2 seconds and shown after. The card's
// animation is started again and paused, then read at points of it, rather than raced against the
// clock: by the time a test looks, the 2 seconds may have passed.
export async function expectCardHeldBack(page: Page) {
  const visibility = await page.locator(".auth-card").evaluate((card: HTMLElement) => {
    card.style.animation = "none";
    void card.offsetWidth;
    card.style.animation = "";
    const [hold] = card.getAnimations();
    if (!hold) return "no animation";
    hold.pause();
    const at = (ms: number) => {
      hold.currentTime = ms;
      return getComputedStyle(card).visibility;
    };
    return { atLoad: at(0), justBefore2s: at(1900), justAfter2s: at(2100) };
  });
  expect(visibility).toEqual({ atLoad: "hidden", justBefore2s: "hidden", justAfter2s: "visible" });
}
