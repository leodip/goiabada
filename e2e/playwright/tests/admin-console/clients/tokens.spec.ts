import { clientIdFromList, clientUrl, grantClientPermission, readClientSecret, saveAndExpectSaved } from "../../../lib/admin-console";
import { env } from "../../../lib/environment";
import { expect, test } from "../../../lib/fixtures";
import { clientCredentialsToken } from "../../../lib/oauth";

const saved = "Token settings saved.";

test("token durations and the OIDC claim options are saved", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#tokenExpirationInSeconds").fill("600");
  await page.locator("#refreshTokenOfflineIdleTimeoutInSeconds").fill("3600");
  await page.locator("#refreshTokenOfflineMaxLifetimeInSeconds").fill("86400");
  await page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]').check();
  await page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]').check();
  await saveAndExpectSaved(page, saved);

  await page.reload();
  await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("600");
  await expect(page.locator("#refreshTokenOfflineIdleTimeoutInSeconds")).toHaveValue("3600");
  await expect(page.locator("#refreshTokenOfflineMaxLifetimeInSeconds")).toHaveValue("86400");
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]')).toBeChecked();
});

test("a new client's Tokens tab shows an ID token choice, and saves as loaded", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  // Both three-way choices start on the global setting.
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="default"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
  await saveAndExpectSaved(page, saved);
});

// Under each duration the page says what was typed as a duration, and what 0 stands for.
test("each duration is read back in words as it is typed", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  const readout = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
  await expect(readout).toHaveText(/^Uses the global setting \(.+\)$/);
  await page.locator("#tokenExpirationInSeconds").fill("600");
  await expect(readout).toHaveText("10 minutes");
  await page.locator("#tokenExpirationInSeconds").fill("ten");
  await expect(readout).toHaveText("Enter a whole number of seconds.");
});

// A page in Portuguese (Brazil) says the duration in Portuguese too, as it says the sentence around it.
test("each duration is read back in Portuguese on a page in Portuguese", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(`${clientUrl(client.id, "tokens")}?ui_locales=pt-BR`);
  await expect(page.locator("html")).toHaveAttribute("data-catalog-lang", "pt-BR");
  const readout = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
  await expect(readout).toHaveText(/^Usa a configuração global \(\d[^()]* (segundo|minuto|hora|dia)s?\)$/);
  await page.locator("#tokenExpirationInSeconds").fill("600");
  await expect(readout).toHaveText("10 minutos");
  await page.locator("#tokenExpirationInSeconds").fill("5400");
  await expect(readout).toHaveText("1 hora e 30 minutos");
  await page.locator("#tokenExpirationInSeconds").fill("dez");
  await expect(readout).toHaveText("Informe um número inteiro de segundos.");
});

// Back may bring the page back with what was typed put back in the field, without an input event, or
// with the stored value: either way the readout says what the field then holds. Which one Chromium
// does is its own choice, so the restoration itself is then played as a browser plays it: a value put
// in the field with no input event, then pageshow. Only the readout's pageshow listener can say it.
for (const { locale, query, typed, global, restored } of [
  {
    locale: "English",
    query: "",
    typed: "10 minutes",
    global: /^Uses the global setting \(.+\)$/,
    restored: "1 hour, 30 minutes",
  },
  {
    locale: "Portuguese",
    query: "?ui_locales=pt-BR",
    typed: "10 minutos",
    global: /^Usa a configuração global \(.+\)$/,
    restored: "1 hora e 30 minutos",
  },
]) {
  test(`a duration the browser restores on Back is read back as the field holds it, in ${locale}`, async ({ page, clients }) => {
    const client = await clients.create();
    const tokens = `${clientUrl(client.id, "tokens")}${query}`;
    await page.goto(tokens);
    const field = page.locator("#tokenExpirationInSeconds");
    const readout = page.locator('[data-duration-for="tokenExpirationInSeconds"]');
    await field.fill("600");
    await expect(readout).toHaveText(typed);
    await page.goto(`${clientUrl(client.id, "settings")}${query}`);
    await page.goBack();
    await expect(page).toHaveURL(tokens);
    const value = await field.inputValue();
    expect(["600", "0"], "the field holds what was typed or what is stored").toContain(value);
    await expect(readout).toHaveText(value === "600" ? typed : global);
    await field.evaluate((input: HTMLInputElement) => {
      input.value = "5400";
      window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    });
    await expect(readout).toHaveText(restored);
  });
}

// The durations are written by the console's own script, so the page needs nothing from elsewhere,
// and nothing of the duration library it used to load (#645).
test("the page requests no script or stylesheet from another origin, nor the removed duration library", async ({ page, clients }) => {
  const client = await clients.create();
  const adminOrigin = new URL(env.adminUrl).origin;
  const foreign: string[] = [];
  const removed: string[] = [];
  page.on("request", (request) => {
    const kind = request.resourceType();
    if ((kind === "script" || kind === "stylesheet") && new URL(request.url()).origin !== adminOrigin) foreign.push(request.url());
    if (new URL(request.url()).pathname.includes("humanize-duration")) removed.push(request.url());
  });
  await page.goto(clientUrl(client.id, "tokens"), { waitUntil: "load" });
  await page.locator("#tokenExpirationInSeconds").fill("600");
  await expect(page.locator('[data-duration-for="tokenExpirationInSeconds"]')).toHaveText("10 minutes");
  expect(foreign).toEqual([]);
  expect(removed).toEqual([]);
});

test("the token expiration set here is the lifetime the token endpoint gives", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");

  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#tokenExpirationInSeconds").fill("123");
  await saveAndExpectSaved(page, saved);

  const secret = await readClientSecret(page, client.id);
  const answer = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  expect(answer.body.expires_in).toBe(123);
});

for (const { value, message } of [
  { value: "-5", message: "Token lifetime must be between 0 and 160000000 seconds." },
  { value: "abc", message: "Enter the token lifetime as a whole number of seconds." },
]) {
  test(`a token expiration of ${JSON.stringify(value)} is refused at its field`, async ({ page, clients }) => {
    const client = await clients.create();
    await page.goto(clientUrl(client.id, "tokens"));
    await page.locator("#tokenExpirationInSeconds").fill(value);
    await page.locator("#btnSave").click();
    await expect(page.locator("#tokens-error")).toContainText(message);
    await expect(page.locator("#tokenExpirationInSeconds")).toHaveAttribute("aria-invalid", "true");
    await page.goto(clientUrl(client.id, "tokens"));
    await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("0");
  });
}

test("an offline idle timeout longer than the offline maximum lifetime is refused at the idle timeout", async ({ page, clients }) => {
  const client = await clients.create();
  await page.goto(clientUrl(client.id, "tokens"));
  await page.locator("#refreshTokenOfflineIdleTimeoutInSeconds").fill("7200");
  await page.locator("#refreshTokenOfflineMaxLifetimeInSeconds").fill("3600");
  await page.locator("#btnSave").click();
  await expect(page.locator("#tokens-error")).toContainText("The offline idle timeout can't be longer than the offline maximum lifetime.");
  await expect(page.locator("#refreshTokenOfflineIdleTimeoutInSeconds")).toHaveAttribute("aria-invalid", "true");
});

test("a refused save keeps what was typed, both claim choices included", async ({ page, clients }) => {
  const client = await clients.create();
  const accessOff = page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="off"]');
  const idOn = page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="on"]');
  await page.goto(clientUrl(client.id, "tokens"));
  await accessOff.check();
  await idOn.check();
  await page.locator("#tokenExpirationInSeconds").fill("abc");
  await page.locator("#btnSave").click();
  await expect(page.locator("#tokens-error")).toContainText("Enter the token lifetime as a whole number of seconds.");
  await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("abc");
  await expect(accessOff).toBeChecked();
  await expect(idOn).toBeChecked();

  // Nothing was saved: the tab opens on the stored choices again.
  await page.goto(clientUrl(client.id, "tokens"));
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInAccessToken"][value="default"]')).toBeChecked();
  await expect(page.locator('input[name="includeOpenIDConnectClaimsInIdToken"][value="default"]')).toBeChecked();
});

// "Require DPoP for token requests" is a switch of the tab, saved by its one Save through the auth
// server's PUT /clients/{id}/dpop, with the implicit-flow restriction said beside it (#42 decisions
// 12 and 13). What it saves is what the token endpoint applies.
test("Require DPoP for token requests is saved, shown, and applied by the token endpoint", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const secret = await readClientSecret(page, client.id);
  const requireDPoP = page.getByRole("checkbox", { name: "Require DPoP for token requests" });

  await page.goto(clientUrl(client.id, "tokens"));
  await expect(requireDPoP).not.toBeChecked();
  await expect(requireDPoP).toHaveAccessibleDescription(
    /must carry a DPoP proof.*can't get access tokens through the implicit flow: the token and id_token token response types are refused/,
  );

  await test.step("switched on, a token request without a proof is refused", async () => {
    await requireDPoP.check();
    await saveAndExpectSaved(page, saved);
    await page.reload();
    await expect(requireDPoP).toBeChecked();
    const refused = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_dpop_proof");
    expect(refused.body.error_description).toBe("This client requires a DPoP proof with every token request.");
  });

  await test.step("saving the tab's other settings leaves it on", async () => {
    await page.locator("#tokenExpirationInSeconds").fill("600");
    await saveAndExpectSaved(page, saved);
    await page.reload();
    await expect(page.locator("#tokenExpirationInSeconds")).toHaveValue("600");
    await expect(requireDPoP).toBeChecked();
  });

  await test.step("switched off, a token request without a proof is answered again", async () => {
    await requireDPoP.uncheck();
    await saveAndExpectSaved(page, saved);
    await page.reload();
    await expect(requireDPoP).not.toBeChecked();
    const answered = await clientCredentialsToken(request, client.identifier, secret, "authserver:manage-account");
    expect(answered.status, JSON.stringify(answered.body)).toBe(200);
    expect(answered.body.token_type).toBe("Bearer");
  });
});

// The admin console calls the auth server with Bearer tokens, so its own client is not offered the
// requirement: its Tokens tab draws the rest and no switch (#42 decision 12).
test("the admin console's client is not offered Require DPoP for token requests", async ({ page }) => {
  await page.goto(clientUrl(await clientIdFromList(page, "admin-console-client"), "tokens"));
  await expect(page.locator("#tokenExpirationInSeconds")).toBeVisible();
  await expect(page.locator("#dpopBoundAccessTokens")).toHaveCount(0);
  await expect(page.getByText("Require DPoP for token requests")).toHaveCount(0);
});
