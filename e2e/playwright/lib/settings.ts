// The settings pages change what the whole instance shares, so a test changing one takes the form's
// values first and puts them back afterwards, pass or fail. Those tests live in *.system.ts files, which
// run alone (playwright.config.ts).
import { expect, type Page } from "@playwright/test";
import { confirmDialog } from "./admin-console";
import { env } from "./environment";

type FormValues = Record<string, string | boolean>;

// The values of a settings page's named fields: text and selects by value, checkboxes by state, a
// group of radios by the value chosen. Password and hidden fields are left out.
export async function readSettingsForm(page: Page, path: string): Promise<FormValues> {
  await page.goto(`${env.adminUrl}${path}`);
  return page.locator('form[method="post"]').first().evaluate((form) => {
    const values: Record<string, string | boolean> = {};
    for (const element of Array.from(form.querySelectorAll("input[name], select[name]"))) {
      const field = element as HTMLInputElement | HTMLSelectElement;
      if (field instanceof HTMLInputElement && ["hidden", "password", "file"].includes(field.type)) continue;
      if (field instanceof HTMLInputElement && field.type === "radio") {
        if (field.checked) values[field.name] = field.value;
        continue;
      }
      values[field.name] = field instanceof HTMLInputElement && field.type === "checkbox" ? field.checked : field.value;
    }
    return values;
  });
}

// Fills a settings page's fields with these values, leaving the others as they are. A switch can
// show or hide others (self-registration its email verification, sending email the server's fields),
// so the fields are set last to first, skipping one that is hidden or disabled, and again until each
// is set or none can be.
export async function fillSettingsForm(page: Page, values: FormValues) {
  let pending = Object.entries(values).reverse();
  while (pending.length > 0) {
    const skipped: typeof pending = [];
    for (const [name, value] of pending) {
      const named = page.locator(`form [name="${name}"]`);
      const isRadio = (await named.first().getAttribute("type")) === "radio";
      const field = isRadio ? page.locator(`form [name="${name}"][value="${value}"]`) : named.first();
      if (!(await field.isVisible()) || (await field.isDisabled())) {
        skipped.push([name, value]);
        continue;
      }
      if (isRadio) await field.check();
      else if (typeof value === "boolean") await field.setChecked(value);
      else if ((await field.evaluate((e) => e.tagName)) === "SELECT") await field.selectOption(value);
      else await field.fill(value);
    }
    if (skipped.length === pending.length) throw new Error(`fields that stay hidden or disabled: ${skipped.map(([n]) => n).join(", ")}`);
    pending = skipped;
  }
}

// Saves a settings page and waits for "Settings saved.", answering Save when the page first asks
// (an issuer change, email turned off).
export async function saveSettings(page: Page) {
  await page.locator("#btnSave").click();
  const saved = page.getByText("Settings saved.", { exact: true });
  const asked = page.locator("dialog[open]");
  await expect(saved.or(asked).first()).toBeVisible();
  if (await asked.isVisible()) await confirmDialog(page);
  await expect(saved).toBeVisible();
}

// Runs body, then puts the page's fields back as they were before it, whatever happened.
export async function withSettingsRestored(page: Page, path: string, body: () => Promise<void>) {
  const before = await readSettingsForm(page, path);
  try {
    await body();
  } finally {
    const now = await readSettingsForm(page, path);
    const changed = Object.fromEntries(Object.entries(before).filter(([name, value]) => now[name] !== value));
    if (Object.keys(changed).length > 0) {
      await fillSettingsForm(page, changed);
      await saveSettings(page);
    }
  }
}

// The settings every run starts from, page by page, for the fields the tests change: those the
// instance was seeded with (src/authserver/internal/bootstrap/seed.go), and email sent through the
// environment's Mailpit (e2e/infra/remote-prepare.sh), which the auth server reaches as mailpit:1025.
// The app name and the issuer are left alone: the tests restore what they change of those, and the
// issuer is the deployment's own.
const baseline: Record<string, FormValues> = {
  "/admin/settings/general": {
    passwordPolicy: "nist",
    selfRegistrationEnabled: false,
    selfRegistrationRequiresEmailVerification: true,
    dynamicClientRegistrationEnabled: false,
    pkceRequired: true,
    implicitFlowEnabled: false,
    ropcFlowEnabled: false,
  },
  "/admin/settings/ui-theme": { themeSelection: "" },
  "/admin/settings/sessions": { userSessionIdleTimeoutInSeconds: "7200", userSessionMaxLifetimeInSeconds: "86400", maxUserSessionsPerUser: "20" },
  "/admin/settings/tokens": {
    tokenExpirationInSeconds: "300",
    refreshTokenOfflineIdleTimeoutInSeconds: "2592000",
    refreshTokenOfflineMaxLifetimeInSeconds: "31536000",
    includeOpenIDConnectClaimsInAccessToken: false,
    includeOpenIDConnectClaimsInIdToken: true,
  },
  "/admin/settings/audit-logs": { auditLogsInConsoleEnabled: true, auditLogsInDatabaseEnabled: true, auditLogRetentionDays: "180" },
  "/admin/settings/email": {
    smtpEnabled: true,
    hostOrIP: "mailpit",
    port: "1025",
    smtpEncryption: "none",
    username: "",
    fromName: "Goiabada e2e",
    fromEmail: "noreply@goiabada.dev",
  },
};

// Puts every page's baseline values back where they differ, and returns what it had to change: a run
// whose restore failed half way would otherwise leave the next run testing against other settings. A
// freshly built environment has no SMTP set up, so the first run sets it up here.
export async function restoreBaselineSettings(page: Page): Promise<string[]> {
  const drifted: string[] = [];
  for (const [path, values] of Object.entries(baseline)) {
    const now = await readSettingsForm(page, path);
    const changed = Object.fromEntries(Object.entries(values).filter(([name, value]) => now[name] !== value));
    if (Object.keys(changed).length === 0) continue;
    drifted.push(...Object.keys(changed).map((name) => `${path}: ${name}`));
    await fillSettingsForm(page, changed);
    await saveSettings(page);
  }
  return drifted;
}
