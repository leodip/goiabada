// What a page shows as its form is sent, read while the submission is held at the network. While
// the page's navigation is pending, Playwright reads nothing from it: every locator action waits
// for that navigation to finish, and an evaluation stalls. So the page reports on itself. A
// listener on the window, the last stop of the submit event, so after every handler the page has,
// reads each password field and the Show button that controls it. It passes them out through an
// exposed binding, which needs no evaluation in the page.
import type { Page } from "@playwright/test";

// A password field's type and its Show button's text and accessible name.
export type PasswordFieldState = { type: string | null; buttonText: string | null; buttonName: string | null };

const binding = "e2eReportSubmission";

// Watches the page's next form submission; call it before the submission. The state it returns
// resolves, with each field named by its id, once that submission's submit event has been dispatched.
export async function watchPasswordFieldsAsSent(page: Page, fieldIds: string[]): Promise<{ state: Promise<Record<string, PasswordFieldState>> }> {
  let report!: (state: Record<string, PasswordFieldState>) => void;
  const reported = new Promise<Record<string, PasswordFieldState>>((resolve) => (report = resolve));
  await page.exposeBinding(binding, (_source, state: Record<string, PasswordFieldState>) => report(state));
  await page.evaluate(
    ({ name, ids }) => {
      window.addEventListener(
        "submit",
        () => {
          const state: Record<string, PasswordFieldState> = {};
          for (const id of ids) {
            const button = document.querySelector(`button[data-password-toggle][aria-controls="${id}"]`);
            state[id] = {
              type: document.getElementById(id)?.getAttribute("type") ?? null,
              buttonText: button?.textContent ?? null,
              buttonName: button?.getAttribute("aria-label") ?? null,
            };
          }
          (window as unknown as Record<string, (state: Record<string, PasswordFieldState>) => void>)[name](state);
        },
        { once: true },
      );
    },
    { name: binding, ids: fieldIds },
  );
  return { state: reported };
}
