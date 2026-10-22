// Sets up the test app's clients and API through the admin console, each the way its guide tells a
// person to (see e2e/testapp/README.md), and writes their secrets to e2e/.state/testapp.env for
// e2e/infra/testapp.sh. Whatever an earlier run set up is removed first, so the result is always the
// same.
import { writeFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import {
  addRedirectUri,
  addResourcePermission,
  clientIdFromList,
  clientRow,
  clientUrl,
  confirmDialog,
  deleteClient,
  deleteResource,
  grantClientPermission,
  idFromListLink,
  readClientSecret,
  resourceUrl,
  rowWithCell,
  saveResourcePermissions,
  signInAsAdmin,
  submitNewClient,
  submitNewResource,
  type NewClient,
} from "../lib/admin-console";
import { env } from "../lib/environment";
import { testappEnvFile } from "../lib/paths";
import { testapp } from "../lib/testapp";

const clientsList = `${env.adminUrl}/admin/clients`;
const resourcesList = `${env.adminUrl}/admin/resources`;

async function createClient(page: Page, client: NewClient): Promise<number> {
  await submitNewClient(page, client);
  await expect(page).toHaveURL(clientsList);
  return clientIdFromList(page, client.identifier);
}

test("set up the test app's clients and API", async ({ page }) => {
  await signInAsAdmin(page);

  const clientIds = [testapp.web, testapp.web2, testapp.spa, testapp.service].map((c) => c.clientId);
  await page.goto(clientsList);
  for (const identifier of clientIds) {
    if ((await clientRow(page, identifier).count()) > 0) {
      await deleteClient(page, await clientIdFromList(page, identifier));
      await page.goto(clientsList);
    }
  }
  await page.goto(resourcesList);
  if ((await rowWithCell(page, testapp.api.resource).count()) > 0) {
    await deleteResource(page, await idFromListLink(page, resourcesList, testapp.api.resource));
  }

  // Protect an API, steps 1 and 2: the API's resource and its permissions.
  await submitNewResource(page, testapp.api.resource, "The test app's API");
  await expect(page).toHaveURL(resourcesList);
  const resourceId = await idFromListLink(page, resourcesList, testapp.api.resource);
  await page.goto(resourceUrl(resourceId, "permissions"));
  for (const permission of testapp.api.permissions) await addResourcePermission(page, permission);
  await saveResourcePermissions(page);

  // Add sign-in to a web app, steps 1 and 2, and Sign users out, step 2: a confidential client with the
  // authorization code flow, its callback and its signed-out page.
  const secrets: Record<string, string> = {};
  for (const [key, app] of [["WEB", testapp.web], ["WEB2", testapp.web2]] as const) {
    const id = await createClient(page, { identifier: app.clientId });
    await addRedirectUri(page, id, `${app.url}/callback`);
    await addRedirectUri(page, id, `${app.url}/signed-out`);
    secrets[`${key}_CLIENT_ID`] = app.clientId;
    secrets[`${key}_CLIENT_SECRET`] = await readClientSecret(page, id);
  }

  // Add sign-in to a SPA or mobile app, steps 1 to 4: a public client, the page as its redirect URI,
  // and its origin.
  const spaId = await createClient(page, { identifier: testapp.spa.clientId });
  await page.goto(clientUrl(spaId, "authentication"));
  await page.getByRole("radio", { name: "Public", exact: true }).check();
  await page.locator("#btnSave").click();
  await confirmDialog(page, "You're making the client public");
  await expect(page.getByText("Authentication saved.")).toBeVisible();
  await addRedirectUri(page, spaId, testapp.spa.url);
  await page.goto(clientUrl(spaId, "web-origins"));
  await page.locator("#webOrigin").fill(testapp.spa.origin);
  await page.locator("#addOriginBtn").click();
  await page.locator("#btnSave").click();
  await expect(page.getByText("Web origins saved.")).toBeVisible();
  secrets.SPA_CLIENT_ID = testapp.spa.clientId;

  // Protect an API, "Let a service call your API", steps 1 and 2: the client credentials flow alone,
  // and the API's read permission.
  const serviceId = await createClient(page, {
    identifier: testapp.service.clientId,
    authorizationCode: false,
    clientCredentials: true,
  });
  const [resource, permission] = testapp.api.scope.split(":");
  await grantClientPermission(page, serviceId, resource, permission);
  secrets.SERVICE_CLIENT_ID = testapp.service.clientId;
  secrets.SERVICE_CLIENT_SECRET = await readClientSecret(page, serviceId);

  secrets.API_RESOURCE = testapp.api.resource;
  secrets.API_SCOPE = testapp.api.scope;
  const lines = Object.entries(secrets).map(([name, value]) => `${name}=${value}`);
  writeFileSync(testappEnvFile, `${lines.join("\n")}\n`, { mode: 0o600 });
});
