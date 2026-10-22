// The authorization endpoint's admission budget (#504): one client address may make 120 requests a
// minute to /auth/authorize, the GET and the POST together, every one counted, because each request
// that passes the first validation writes a row, a browser session on the GET and a parked request on
// the POST. Past it the browser gets the "Too many attempts" page with Retry-After, before anything in
// the request is read, so nothing reaches the redirect URI. A system test because the budget is the
// address's, which every other test signs in from: it runs alone, and waits the window out before it
// ends.
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

  let lastRequest = Date.now();
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
      lastRequest = Date.now();
      expect(statuses.filter((status) => status >= 500), `statuses ${statuses}`).toEqual([]);
      admitted += statuses.filter((status) => status !== 429).length;
      refused = statuses.includes(429);
    }
    expect(refused, "the endpoint never refused the address").toBe(true);
    expect(admitted, "the burst itself was admitted until the budget ran out").toBeGreaterThan(0);
    expect(admitted).toBeLessThanOrEqual(budget + slack);

    // A browser sent to sign in, with a request that would otherwise start one.
    const signIn = await anonymous.newPage();
    const viaGet = codeRequest(client.identifier);
    const gotten = await signIn.goto(`${authorizeEndpoint}?${new URLSearchParams(viaGet.params)}`);
    lastRequest = Date.now();
    expect(gotten?.status()).toBe(429);
    expect(gotten?.headers()["retry-after"]).toBe("60");
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
    await own.goto(clientPage);
    const [posted] = await Promise.all([
      own.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/auth/authorize"),
      own.getByRole("button", { name: "Sign in" }).click(),
    ]);
    lastRequest = Date.now();
    expect(posted.status()).toBe(429);
    expect(posted.headers()["retry-after"]).toBe("60");
    expect(posted.headers()["location"]).toBeUndefined();
    await expect(own.getByRole("heading", { name: "Too many attempts" })).toBeVisible();
  } finally {
    // A refused request spends nothing, so two minutes after the last admitted or refused one the
    // window holds none of this test's: the tests after it, and a run started right after this one,
    // start from an empty window.
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, lastRequest + 125_000 - Date.now())));
    const { pageUrl } = await followAuthorize(anonymous.request, codeRequest(client.identifier).params);
    expect(pageUrl, "authorization proceeds to the password form once the window has passed").toMatch(/\/auth\/pwd\?/);
    await anonymous.close();
  }
});
