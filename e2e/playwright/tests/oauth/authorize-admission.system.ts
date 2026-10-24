// The authorization endpoint's admission budget (#504): one client address may make 120 requests a
// minute to /auth/authorize, the GET and the POST together, every one counted, because each request
// that passes the first validation writes a row, a browser session on the GET and a parked request on
// the POST. Past it the browser gets the "Too many attempts" page with Retry-After, before anything in
// the request is read, so nothing reaches the redirect URI. A system test because the budget is the
// address's, which every other test signs in from: it runs alone, and records what it spent
// (lib/address-limits.ts), so whatever needs the budget next waits for the window to pass.
import type { Response } from "@playwright/test";
import { spent, untilCleared } from "../../lib/address-limits";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { authorizeEndpoint, codeRequest, emptyBrowser, followAuthorize } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

// The requests one address may make to the endpoint in a minute, GET and POST together.
const budget = 120;
// The limiter's window slides by weighing the previous minute's count, so requests other tests made
// in the two minutes before bring the refusal forward, and a minute rolling over during the burst
// pushes it back by a few.
const slack = 8;
// A page on another site, which posts the authorization request as a client's own page would.
const clientPage = "https://client.example/sign-in";

test.skip(!env.rateLimiter, "the environment was prepared with the rate limiter off (E2E_RATE_LIMITER)");
test.setTimeout(5 * 60_000);

test("the authorization endpoint refuses one address past 120 requests a minute, a GET and a cross-site POST alike", async ({
  page,
  browser,
  clients,
}) => {
  // Through the console, before the burst, so its own pages are not what the budget refuses.
  const { client } = await browserSignInClient(page, clients);
  const anonymous = await emptyBrowser(browser);
  await untilCleared("authorization endpoint");

  try {
    // Spent with requests naming no client, which the endpoint refuses on its page and writes nothing
    // for: the budget counts them all the same. Eight at a time, so the burst lands within the minute.
    let admitted = 0;
    let refused = false;
    while (!refused && admitted <= budget + slack) {
      const statuses = await Promise.all(
        Array.from({ length: 8 }, async () => {
          const answer = await anonymous.request.get(`${authorizeEndpoint}?response_type=code`, { failOnStatusCode: false, maxRedirects: 0 });
          return answer.status();
        }),
      );
      spent("authorization endpoint");
      expect(statuses.filter((status) => status >= 500), `statuses ${statuses}`).toEqual([]);
      admitted += statuses.filter((status) => status !== 429).length;
      refused = statuses.includes(429);
    }
    expect(refused, "the endpoint never refused the address").toBe(true);
    expect(admitted, "the burst itself was admitted until the budget ran out").toBeGreaterThan(0);
    expect(admitted).toBeLessThanOrEqual(budget + slack);

    // A refusal holds nothing: the limiter weighs the previous minute's count less every second, and
    // a refused request adds none, so a moment after the burst the address may be admitted again. Each
    // check below therefore spends requests naming no client until one is refused, then makes its own
    // at once, and starts over if that was admitted all the same.
    const spendUntilRefused = async () => {
      for (let sent = 0; sent <= budget + slack; sent++) {
        const answer = await anonymous.request.get(`${authorizeEndpoint}?response_type=code`, { failOnStatusCode: false, maxRedirects: 0 });
        spent("authorization endpoint");
        expect(answer.status(), "a request naming no client").toBeLessThan(500);
        if (answer.status() === 429) return;
      }
      throw new Error("the endpoint never refused the address");
    };

    // A browser sent to sign in, with a request that would otherwise start one.
    const signIn = await anonymous.newPage();
    let gotten = null as Response | null;
    await expect(async () => {
      await spendUntilRefused();
      gotten = await signIn.goto(`${authorizeEndpoint}?${new URLSearchParams(codeRequest(client.identifier).params)}`);
      spent("authorization endpoint");
      expect(gotten?.status()).toBe(429);
    }).toPass({ timeout: 20_000 });
    expect(gotten!.headers()["retry-after"]).toBe("60");
    expect(gotten!.headers()["location"]).toBeUndefined();
    await expect(signIn.getByRole("heading", { name: "Too many attempts" })).toBeVisible();
    expect(new URL(signIn.url()).pathname, "the browser stays on the endpoint").toBe("/auth/authorize");

    // The same request posted from the client's own page, on another site: refused before it is
    // parked, with no redirect to follow.
    const viaPost = codeRequest(client.identifier);
    const fields = Object.entries(viaPost.params)
      .map(([name, value]) => `<input type="hidden" name="${name}" value="${value}">`)
      .join("");
    await anonymous.route(clientPage, (route) =>
      route.fulfill({
        status: 200,
        contentType: "text/html",
        body: `<form method="post" action="${authorizeEndpoint}">${fields}<button type="submit">Sign in</button></form>`,
      }),
    );
    const own = await anonymous.newPage();
    let posted = null as Response | null;
    await expect(async () => {
      // The form is loaded before the requests that bring the address to its budget, so the click
      // follows the refusal at once. An attempt whose post was admitted left the page.
      if (own.url() !== clientPage) await own.goto(clientPage);
      await spendUntilRefused();
      const [answer] = await Promise.all([
        own.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/auth/authorize"),
        own.getByRole("button", { name: "Sign in" }).click(),
      ]);
      posted = answer;
      spent("authorization endpoint");
      expect(answer.status()).toBe(429);
    }).toPass({ timeout: 20_000 });
    expect(posted!.headers()["retry-after"]).toBe("60");
    expect(posted!.headers()["location"]).toBeUndefined();
    await expect(own.getByRole("heading", { name: "Too many attempts" })).toBeVisible();

    // The refusal lapses as the window slides: followAuthorize asks again while it is refused, and
    // once admitted the request proceeds to the password form.
    const { pageUrl } = await followAuthorize(anonymous.request, codeRequest(client.identifier).params);
    expect(pageUrl, "authorization proceeds to the password form once the address is admitted again").toMatch(/\/auth\/pwd\?/);
  } finally {
    await anonymous.close();
  }
});
