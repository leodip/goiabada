// Add sign-in to a SPA or mobile app, through the test app's SPA: a public client doing everything in
// the browser, from its own origin, so every call to the auth server is a cross-origin request.
import { grantUserPermission } from "../../lib/admin-console";
import { submitPassword } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { expectResult, resultBody, testapp, userBrowser } from "../../lib/testapp";

test("the SPA signs a user in, refreshes, calls /userinfo and the API, and signs out, all from the browser", async ({ page, browser, users }) => {
  const user = await users.create();
  await grantUserPermission(page, user.id, testapp.api.resource, "read");
  const { context, page: spa } = await userBrowser(browser);

  await spa.goto(testapp.spa.url);
  await spa.getByRole("button", { name: "Sign in" }).click();
  await expect(spa).toHaveURL(/\/auth\/pwd/);
  await submitPassword(spa, user.email, user.password);
  await spa.waitForURL(testapp.spa.url);
  await expectResult(spa, "Signed in");
  expect(String((await resultBody(spa)).scope).split(" ")).toContain(testapp.api.scope);
  await expect(spa.getByText("Refresh token: yes.")).toBeVisible();
  // The code came back in the address, and the page took it out again.
  expect(spa.url()).toBe(testapp.spa.url);

  await spa.getByRole("button", { name: "Refresh the tokens" }).click();
  await expectResult(spa, "Refreshed");
  await spa.getByRole("button", { name: "Call /userinfo" }).click();
  await expectResult(spa, "/userinfo answered");
  expect((await resultBody(spa)).email).toBe(user.email);
  await spa.getByRole("button", { name: "Call the API" }).click();
  await expectResult(spa, "The API answered 200");

  await spa.getByRole("button", { name: "Sign out" }).click();
  await spa.waitForURL(testapp.spa.url);
  await expectResult(spa, "Signed out");
  await spa.getByRole("button", { name: "Sign in" }).click();
  await expect(spa).toHaveURL(/\/auth\/pwd/);
  await context.close();
});

// Web origins are what lets a page call the token endpoint and /userinfo from the browser. The SPA's
// origin is registered; another one is not given the header that would let its page read the answer.
test("the token endpoint lets the SPA's origin read its answers, and not an origin nobody registered", async ({ request }) => {
  for (const [origin, allowed] of [
    [testapp.spa.origin, true],
    ["https://not-registered.example.com", false],
  ] as const) {
    const preflight = await request.fetch(`${env.authUrl}/auth/token`, {
      method: "OPTIONS",
      headers: { Origin: origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type" },
      failOnStatusCode: false,
    });
    const answer = preflight.headers()["access-control-allow-origin"];
    if (allowed) expect(answer, `preflight from ${origin}`).toBe(origin);
    else expect(answer, `preflight from ${origin}`).toBeUndefined();
  }
});
