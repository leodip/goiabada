import { clientRow, clientUrl, confirmDialog, readClientSecret } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

const saved = "Client authentication saved successfully";

test("a confidential client's secret is hidden until revealed", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  const secret = page.locator("#clientSecret");
  await expect(secret).toHaveAttribute("type", "password");
  await page.locator("#revealLink").click();
  await expect(secret).toHaveAttribute("type", "text");
  await page.locator("#hideLink").click();
  await expect(secret).toHaveAttribute("type", "password");
});

test("a new secret replaces the old one: the old is refused at the token endpoint, the new works", async ({
  page,
  clients,
  request,
}) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  const oldSecret = await readClientSecret(page, client.id);
  // A client holding no permission gets invalid_scope, not a token, but only after its secret passed.
  expect((await clientCredentialsToken(request, client.identifier, oldSecret)).body.error).toBe("invalid_scope");

  await page.goto(clientUrl(client.id, "authentication"));
  await page.locator("#generateNewSecretLink").click();
  await expect(page.locator("#clientSecret")).not.toHaveValue(oldSecret);
  const newSecret = await page.locator("#clientSecret").inputValue();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You are changing the client secret");
  await expect(page.getByText(saved)).toBeVisible();

  expect(await readClientSecret(page, client.id)).toBe(newSecret);
  const withOld = await clientCredentialsToken(request, client.identifier, oldSecret);
  expect(withOld.status).toBe(401);
  expect(withOld.body.error).toBe("invalid_client");
  expect((await clientCredentialsToken(request, client.identifier, newSecret)).body.error).toBe("invalid_scope");
});

test("generating a secret and leaving without saving keeps the old one", async ({ page, clients }) => {
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
  await page.goto(clientUrl(client.id, "authentication"));
  await page.locator("#generateNewSecretLink").click();
  await expect(page.locator("#clientSecret")).not.toHaveValue(secret);
  expect(await readClientSecret(page, client.id)).toBe(secret);
});

test("a client switched to public loses its secret, and switched back gets a new one", async ({ page, clients }) => {
  const client = await clients.create();
  const original = await readClientSecret(page, client.id);

  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Public client" }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You are switching from confidential to public client");
  await expect(page.getByText(saved)).toBeVisible();
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Public", exact: true })).toBeVisible();

  await page.goto(clientUrl(client.id, "authentication"));
  await expect(page.getByRole("radio", { name: "Public client" })).toBeChecked();
  await page.getByRole("radio", { name: "Confidential client" }).check();
  // Switching to confidential fills in a fresh secret.
  await expect(page.locator("#clientSecret")).not.toHaveValue("");
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You are switching from public to confidential client");
  await expect(page.getByText(saved)).toBeVisible();

  const restored = await readClientSecret(page, client.id);
  expect(restored).not.toBe(original);
});
