// Many people signing in from one address: an office, a school or a carrier-grade NAT behind one
// router, and this suite (#564). The sign-in form and the password grant each limit one client address
// to 30 failed password checks a minute (the pwd_ip and ropc_ip tiers); a successful sign-in spends
// none of it. Each also has a ceiling of 120 checks a minute, every one counted (pwd_ip_requests and
// ropc_ip_requests), which the first test here reaches at the password grant and the others stay
// under: their successes and their failures.
import type { APIRequestContext, Browser, Page } from "@playwright/test";
import { openSignIn, submitPassword, testRedirectUri } from "../lib/browser-sign-in";
import { passwordToken } from "../lib/oauth";
import { expect, test, type TestUser } from "../lib/rate-limits";
import { browserSignInClient, passwordGrantClient } from "../lib/test-clients";

// The failed password checks one address may make in a minute, at either route.
const limit = 30;
// The password checks, right or wrong, one address may make in a minute, at either route.
const ceiling = 120;
// The limiter's window slides by weighing the previous minute's count, so a minute rolling over during
// the attempts pushes the refusal back by a few. Nothing brings it forward: each test starts with the
// budgets whole.
const slack = 8;
// More successes than the address could make in a minute when successes counted, slack included.
const successes = limit + slack + 2;
const maxFailures = limit + slack + 1;
// Each wrong password goes to the next of these throwaway accounts in turn, so none of them reaches
// the 10 failures an account may have from one address in 15 minutes (pwd_account_net) and the
// refusal is the address's.
const accounts = 5;

type Outcome = "signed in" | "wrong password" | "too many attempts";

// One sign-in at the auth server's password form, in a browser of its own.
async function signInAtForm(browser: Browser, clientId: string, user: { email: string; password: string }): Promise<Outcome> {
  const { context, page } = await openSignIn(browser, { clientId, scope: "openid" });
  try {
    return await submitAndRead(page, user.email, user.password);
  } finally {
    await context.close();
  }
}

// Submits the password form and reads the answer to the POST: a redirect on to the client, which
// answers a POST with 303 (RFC 9700 section 4.12), the form again with the failure, or the limiter's
// refusal.
async function submitAndRead(page: Page, email: string, password: string): Promise<Outcome> {
  const [answer] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === "/auth/pwd"),
    submitPassword(page, email, password),
  ]);
  if (answer.status() === 429) {
    await expect(page.getByRole("heading", { name: "Too many attempts" })).toBeVisible();
    return "too many attempts";
  }
  if (answer.status() === 303) {
    await page.waitForURL((url) => url.href.startsWith(testRedirectUri));
    return "signed in";
  }
  await expect(page.getByText("Authentication failed.", { exact: true })).toBeVisible();
  return "wrong password";
}

async function grantOutcome(
  request: APIRequestContext,
  client: { identifier: string; secret: string },
  user: { email: string; password: string },
): Promise<Outcome> {
  const answer = await passwordToken(request, client.identifier, client.secret, user.email, user.password, "openid");
  if (answer.status === 429) return "too many attempts";
  if (answer.status === 200) return "signed in";
  expect(answer.body.error, JSON.stringify(answer.body)).toBe("invalid_grant");
  return "wrong password";
}

async function createAccounts(users: { create(): Promise<TestUser> }): Promise<TestUser[]> {
  const created: TestUser[] = [];
  for (let i = 0; i < accounts; i++) created.push(await users.create());
  return created;
}

// Wrong passwords, one account after another, until the address is refused; how many were answered
// as wrong passwords before that, or null when none was refused.
async function failUntilRefused(attempt: (user: TestUser) => Promise<Outcome>, throwaway: TestUser[]): Promise<number | null> {
  for (let failures = 0; failures < maxFailures; failures++) {
    const user = throwaway[failures % throwaway.length];
    const outcome = await attempt({ ...user, password: `not-${user.password}` });
    if (outcome === "too many attempts") return failures;
    expect(outcome, `wrong password ${failures + 1}`).toBe("wrong password");
  }
  return null;
}

// The successful grants outlast the failure limit, and the ceiling stops them.
test("the password grant refuses one address past 120 grants a minute, its successful ones included", async ({
  page,
  request,
  clients,
  users,
}) => {
  const { client, secret } = await passwordGrantClient(page, clients);
  const user = await users.create();
  const grant = () => grantOutcome(request, { identifier: client.identifier, secret }, user);

  // Four at a time, so they all land within the minute however slow the round trip. The account's own
  // tier counts the checks in flight against its 10 failures, which four stay well under.
  let granted = 0;
  let refused = false;
  while (!refused && granted <= ceiling + slack) {
    const outcomes = await Promise.all(Array.from({ length: 4 }, grant));
    expect(outcomes).not.toContain("wrong password");
    granted += outcomes.filter((outcome) => outcome === "signed in").length;
    refused = outcomes.includes("too many attempts");
  }
  expect(refused, "the grant never refused the address").toBe(true);
  expect(granted).toBeGreaterThanOrEqual(ceiling);
  expect(granted).toBeLessThanOrEqual(ceiling + slack);
  // The refusal is the token endpoint's error, as RFC 6749 section 5.2 shapes it.
  const answer = await passwordToken(request, client.identifier, secret, user.email, user.password, "openid");
  expect(answer.status).toBe(429);
  expect(answer.body.error).toBe("invalid_request");
});

test("the sign-in form refuses one address's wrong passwords past the limit, and never its successful sign-ins", async ({
  page,
  browser,
  clients,
  users,
}) => {
  const { client } = await browserSignInClient(page, clients);
  const throwaway = await createAccounts(users);
  const signIn = (user: { email: string; password: string }) => signInAtForm(browser, client.identifier, user);

  for (let i = 1; i <= successes; i++) {
    expect(await signIn(throwaway[0]), `successful sign-in ${i}`).toBe("signed in");
  }

  // The failures from one form, submitted again as each answer renders it, so they land within
  // seconds of each other.
  const form = await openSignIn(browser, { clientId: client.identifier, scope: "openid" });
  try {
    const accepted = await failUntilRefused((user) => submitAndRead(form.page, user.email, user.password), throwaway);
    expect(accepted, "the form never refused the address's wrong passwords").not.toBeNull();
    expect(accepted!).toBeGreaterThanOrEqual(limit);
    // Refused for the address: this account has had far fewer failures than its own limit, and its
    // right password is refused too.
    expect(await signIn(throwaway[0])).toBe("too many attempts");
  } finally {
    await form.context.close();
  }
});

test("the password grant refuses one address's wrong passwords past the limit, and never its successful grants", async ({
  page,
  request,
  clients,
  users,
}) => {
  const { client, secret } = await passwordGrantClient(page, clients);
  const throwaway = await createAccounts(users);
  const grant = (user: { email: string; password: string }) => grantOutcome(request, { identifier: client.identifier, secret }, user);

  for (let i = 1; i <= successes; i++) {
    expect(await grant(throwaway[0]), `successful grant ${i}`).toBe("signed in");
  }

  const accepted = await failUntilRefused(grant, throwaway);
  expect(accepted, "the grant never refused the address's wrong passwords").not.toBeNull();
  expect(accepted!).toBeGreaterThanOrEqual(limit);
  expect(await grant(throwaway[0])).toBe("too many attempts");
});
