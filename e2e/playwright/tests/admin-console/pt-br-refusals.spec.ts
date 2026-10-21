// A console page opened in Portuguese (Brazil) shows its refusals in Portuguese too, whichever
// server made them: one the auth server's API had translated before #559, which the console now
// asks for in the page's language; one the API translates since #559; and one the console makes
// itself. Each form has no action, so the POST keeps the page's ?ui_locales and the refusal is
// rendered in the language the page was. A page's own requests name its language too, so a refusal
// they bring back to its field is in Portuguese as well.
//
// These fail against releases before the one carrying #559, which answer all four in English.
import type { Page } from "@playwright/test";
import { expectFieldError, resourceUrl } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";

const ptBR = "ui_locales=pt-BR";

async function submitNewResourceInPortuguese(page: Page, identifier: string) {
  await page.goto(`${env.adminUrl}/admin/resources/new?${ptBR}`);
  await page.locator("#resourceIdentifier").fill(identifier);
  await page.locator("#btnCreate").click();
  await expect(page).toHaveURL(`${env.adminUrl}/admin/resources/new?${ptBR}`);
  await expect(page.locator("html")).toHaveAttribute("lang", "pt-BR");
}

test("the API's refusal of an identifier in an invalid format, translated before, reaches the page in Portuguese", async ({
  page,
}) => {
  await submitNewResourceInPortuguese(page, "abc-");
  await expect(page.locator("#resource-error")).toContainText("Formato de identificador inválido.");
  await expect(page.locator("#resourceIdentifier")).toHaveAttribute("aria-invalid", "true");
});

test("the API's refusal of an empty resource identifier, newly translated, reaches the page in Portuguese", async ({
  page,
}) => {
  await submitNewResourceInPortuguese(page, "");
  await expect(page.locator("#resource-error")).toContainText("O identificador do recurso é obrigatório");
  await expect(page.locator("#resourceIdentifier")).toHaveAttribute("aria-invalid", "true");
});

test("the console's own refusal of a delete whose identifier does not match is in Portuguese", async ({
  page,
  resources,
}) => {
  const resource = await resources.create();
  await page.goto(`${resourceUrl(resource.id, "delete")}?${ptBR}`);
  await page.locator("#resourceIdentifier").fill(`${resource.identifier}-wrong`);
  await page.locator("#btnDelete").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "pt-BR");
  await expect(page.locator("#delete-error")).toHaveText("Este não é o identificador deste recurso. Digite-o como aparece acima.");
  await expect(page.locator("#resourceIdentifier")).toHaveAttribute("aria-invalid", "true");
});

test("a refusal the page's own request brings back to its field is in Portuguese", async ({ page, resources }) => {
  const resource = await resources.create();
  await page.goto(`${resourceUrl(resource.id, "permissions")}?${ptBR}`);
  await expect(page.locator("html")).toHaveAttribute("lang", "pt-BR");
  await page.locator("#permissionIdentifier").fill("1abc");
  const validated = page.waitForResponse((r) => new URL(r.url()).pathname === "/admin/resources/validate-permission");
  await page.getByRole("button", { name: "Adicionar permissão", exact: true }).click();
  // The page names its language on the request, over the browser's English.
  expect(new URL((await validated).url()).searchParams.get("ui_locales")).toBe("pt-BR");

  await expectFieldError(page, "permissionIdentifier", "Formato de identificador inválido.");
  await expect(page.locator("#permissionsTable tbody tr[data-identifier]")).toHaveCount(0);
});
