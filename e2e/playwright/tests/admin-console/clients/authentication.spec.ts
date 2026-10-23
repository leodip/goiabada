import { cancelDialog, clientRow, clientUrl, confirmDialog, readClientSecret } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

const saved = "Authentication saved.";

test("a confidential client's secret is hidden until shown", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "authentication"));
  const secret = page.locator("#clientSecret");
  await expect(secret).toHaveAttribute("type", "password");
  await page.getByRole("button", { name: "Show", exact: true }).click();
  await expect(secret).toHaveAttribute("type", "text");
  await page.getByRole("button", { name: "Hide", exact: true }).click();
  await expect(secret).toHaveAttribute("type", "password");
  await expect(page.getByRole("button", { name: "Show", exact: true })).toBeVisible();
});

test("Copy puts the secret on the clipboard", async ({ page, context, clients }) => {
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
  // The page may write to the clipboard, and the test read it back.
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: env.adminUrl });
  await page.getByRole("button", { name: "Copy", exact: true }).click();
  await expect(page.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret);
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
  await page.getByRole("button", { name: "Generate a new secret" }).click();
  await expect(page.locator("#secret-status")).toContainText("New secret generated. Save to start using it; until then the current one keeps working.");
  // The new secret is shown, to be copied before it is saved.
  await expect(page.locator("#clientSecret")).toHaveAttribute("type", "text");
  await expect(page.locator("#clientSecret")).not.toHaveValue(oldSecret);
  const newSecret = await page.locator("#clientSecret").inputValue();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're changing the client secret");
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
  await page.getByRole("button", { name: "Generate a new secret" }).click();
  await expect(page.locator("#clientSecret")).not.toHaveValue(secret);
  expect(await readClientSecret(page, client.id)).toBe(secret);
});

test("a client switched to public loses its secret, and switched back gets a new one", async ({ page, clients }) => {
  const client = await clients.create();
  const original = await readClientSecret(page, client.id);

  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Public", exact: true }).check();
  // A public client has no secret to show.
  await expect(page.locator("#clientSecret")).toBeHidden();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText(saved)).toBeVisible();
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Public", exact: true })).toBeVisible();

  await page.goto(clientUrl(client.id, "authentication"));
  await expect(page.getByRole("radio", { name: "Public", exact: true })).toBeChecked();
  await page.getByRole("radio", { name: "Confidential", exact: true }).check();
  // Switching to confidential fills in a fresh secret.
  await expect(page.locator("#clientSecret")).not.toHaveValue("");
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client confidential");
  await expect(page.getByText(saved)).toBeVisible();

  const restored = await readClientSecret(page, client.id);
  expect(restored).not.toBe(original);
});

test("making a client public asks first, and Cancel keeps it confidential with its secret", async ({ page, clients }) => {
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);
  await page.goto(clientUrl(client.id, "authentication"));
  await page.getByRole("radio", { name: "Public", exact: true }).check();
  await page.locator("#btnSave").click();
  await cancelDialog(page, "Its secret will be removed");
  await expect(page.getByText(saved)).toHaveCount(0);

  expect(await readClientSecret(page, client.id)).toBe(secret);
  await expect(page.getByRole("radio", { name: "Confidential", exact: true })).toBeChecked();
});

test("a save made by hand with a client type that is neither is refused, the client kept as it was", async ({ page, clients }) => {
  const client = await clients.create();
  const secret = await readClientSecret(page, client.id);

  // The page's radios always send public or confidential, so the form is posted by hand, past the
  // confirmation the page asks, with a type that is neither and a secret typed beside it.
  await page.locator("form.panel").evaluate((form: HTMLFormElement) => {
    for (const radio of form.querySelectorAll<HTMLInputElement>('input[name="publicConfidential"]')) radio.value = "neither";
    form.querySelector<HTMLInputElement>("#clientSecret")!.value = "a-secret-typed-by-hand";
    HTMLFormElement.prototype.submit.call(form);
  });
  await expect(page).toHaveURL(clientUrl(client.id, "authentication"));
  await expect(page.locator("#authentication-error")).toHaveText("Choose the client type: public or confidential.");
  await expect(page.locator("#authentication-error")).toHaveAttribute("role", "alert");
  await expect(page.getByText(saved)).toHaveCount(0);
  // The tab is drawn as stored, and the refusal marks no field.
  await expect(page.getByRole("radio", { name: "Confidential", exact: true })).toBeChecked();
  await expect(page.locator("#clientSecret")).toHaveValue(secret);
  await expect(page.locator('[aria-invalid="true"]')).toHaveCount(0);

  expect(await readClientSecret(page, client.id)).toBe(secret);
  await page.goto(`${env.adminUrl}/admin/clients`);
  await expect(clientRow(page, client.identifier).getByRole("cell", { name: "Confidential", exact: true })).toBeVisible();
});
