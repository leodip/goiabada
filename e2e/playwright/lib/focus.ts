// Where the keyboard's focus is, and whether a person can see it: the element has the focus, shows
// its ring, and is not hidden under the console's header, which stays pinned to the top of the page
// as it scrolls (WCAG 2.2 SC 2.4.11 Focus Not Obscured (Minimum)). Axe cannot check that, since it
// depends on where the page has scrolled to when the focus arrives.
import { expect, type Locator } from "@playwright/test";

// The focus ring ui.css draws, a 2px outline 2px outside the control, reaches this far past its box.
const focusRingReach = 4;

// What hides the element, or "" when it shows. Its visible part is its box within the window, less
// what lies under .app-header, unless the element is drawn above the header there: one inside it,
// such as the user menu, or the skip link, which ui.css lays over it. At a point of that part the page
// must show the element itself, or something inside it.
function obscured(element: Element): string {
  const describe = (node: Element | null) =>
    node ? `${node.tagName.toLowerCase()}${node.id ? `#${node.id}` : ""}${node.className && typeof node.className === "string" ? `.${node.className.trim().split(/\s+/).join(".")}` : ""}` : "nothing";
  const shows = (x: number, y: number) => {
    const hit = document.elementFromPoint(x, y);
    return hit !== null && element.contains(hit);
  };
  const box = element.getBoundingClientRect();
  const left = Math.max(box.left, 0);
  const right = Math.min(box.right, window.innerWidth);
  let top = Math.max(box.top, 0);
  const bottom = Math.min(box.bottom, window.innerHeight);
  if (right <= left || bottom <= top) return `it lies outside the window, at ${Math.round(box.top)} to ${Math.round(box.bottom)}`;

  const header = document.querySelector(".app-header");
  if (header && !header.contains(element)) {
    const headerBottom = header.getBoundingClientRect().bottom;
    const under = Math.min(bottom, headerBottom);
    if (top < under && !shows((left + right) / 2, (top + under) / 2)) {
      top = Math.max(top, headerBottom);
      if (bottom <= top) {
        return `it lies wholly under the header: it spans ${Math.round(box.top)} to ${Math.round(box.bottom)}, and the header ends at ${Math.round(headerBottom)}`;
      }
    }
  }
  const x = (left + right) / 2;
  const y = (top + bottom) / 2;
  if (!shows(x, y)) return `at (${Math.round(x)}, ${Math.round(y)}), in its visible part, the page shows ${describe(document.elementFromPoint(x, y))}`;
  return "";
}

// The element is not hidden: some of it shows, outside the console's header.
export async function expectNotObscured(element: Locator) {
  await expect.poll(() => element.evaluate(obscured), { message: `${element} shows` }).toBe("");
}

// The element has the focus, shows the ring that says so, and is not hidden under the header.
export async function expectFocused(element: Locator) {
  await expect(element).toBeFocused();
  await expect(element).toHaveCSS("outline-style", "solid");
  await expectNotObscured(element);
}

// The element and its focus ring lie wholly below the console's header and within the window: what
// the page's scroll-padding-top gives a field the focus scrolls to, beyond the minimum above.
export async function expectWhollyBelowHeader(element: Locator) {
  await expect
    .poll(
      () =>
        element.evaluate((element, reach) => {
          const box = element.getBoundingClientRect();
          const headerBottom = document.querySelector(".app-header")!.getBoundingClientRect().bottom;
          if (box.top - reach < headerBottom) {
            return `its ring begins at ${Math.round(box.top - reach)}, above the header's end at ${Math.round(headerBottom)}`;
          }
          if (box.bottom + reach > window.innerHeight) {
            return `its ring ends at ${Math.round(box.bottom + reach)}, below the window's ${window.innerHeight}`;
          }
          return "";
        }, focusRingReach),
      { message: `${element} lies wholly below the header` },
    )
    .toBe("");
}
