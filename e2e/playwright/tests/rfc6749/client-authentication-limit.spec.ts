// RFC 6749 section 2.3.1: the authorization server MUST protect every endpoint that takes a client
// password against brute force. A confidential client may fail its secret 200 times an hour, counted
// together at the token, revocation and introspection endpoints, whether or not the rate limiter is
// on; then it is refused 429 with Retry-After at all three, its right secret included, while another
// client is untouched. The count persists across runs within the hour, so the test spends the budget
// of fresh clients of its own and never sends a wrong secret for a client anything else uses. Every
// attempt is a request through the API, never a browser.
import type { APIRequestContext, Page } from "@playwright/test";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, readAnswer, tokenEndpoint, type RawAnswer } from "../../lib/rfc6749";

const revocationEndpoint = `${env.authUrl}/auth/revoke`;
const introspectionEndpoint = `${env.authUrl}/auth/introspect`;
const scope = "authserver:manage-account";

interface ClientsFixture {
  create(options?: { authorizationCode?: boolean; clientCredentials?: boolean }): Promise<{ id: number; identifier: string }>;
}

// A confidential client that may use the client credentials grant for one scope, and its secret.
async function confidentialClient(page: Page, clients: ClientsFixture) {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  return { id: client.identifier, secret: await readClientSecret(page, client.id) };
}

// The three endpoints, each with a request that reaches the client's secret check.
const endpoints: { name: string; url: string; form: Record<string, string> }[] = [
  { name: "token", url: tokenEndpoint, form: { grant_type: "client_credentials", scope } },
  { name: "revocation", url: revocationEndpoint, form: { token: "not-a-token" } },
  { name: "introspection", url: introspectionEndpoint, form: { token: "not-a-token" } },
];

// Posts the endpoint's request for the client, its secret in the Authorization header when basic is
// set and in the body otherwise.
async function post(
  request: APIRequestContext,
  endpoint: (typeof endpoints)[number],
  clientId: string,
  secret: string,
  basic: boolean,
): Promise<RawAnswer> {
  const form: Record<string, string> = basic ? { ...endpoint.form } : { ...endpoint.form, client_id: clientId, client_secret: secret };
  const response = await request.post(endpoint.url, {
    data: new URLSearchParams(form).toString(),
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...(basic ? { Authorization: basicAuth(clientId, secret) } : {}),
    },
    failOnStatusCode: false,
    maxRedirects: 0,
  });
  return readAnswer(response);
}

function expectOverTheLimit(answer: RawAnswer, what: string) {
  expect(answer.status, `${what}: ${answer.text}`).toBe(429);
  expect(answer.headers["retry-after"], `${what}: Retry-After`).toBe("3600");
  expect(answer.body, what).toEqual({ error: "invalid_request", error_description: "Too many requests. Please wait and try again later." });
}

test("200 wrong secrets across the token, revocation and introspection endpoints refuse the client 429 at all three, its right secret included", async ({
  page,
  clients,
  request,
}) => {
  test.setTimeout(180_000);
  const guessed = await confidentialClient(page, clients);
  const other = await confidentialClient(page, clients);

  // 200 failures, about 67 at each endpoint, so no one endpoint alone reaches the limit. Ten at a time.
  for (let batch = 0; batch < 20; batch++) {
    const answers = await Promise.all(
      Array.from({ length: 10 }, (_, i) => {
        const n = batch * 10 + i;
        return post(request, endpoints[n % 3], guessed.id, `wrong-${n}`, n % 2 === 0);
      }),
    );
    for (const answer of answers) {
      expect(answer.status, answer.text).toBe(401);
      expect(answer.body.error).toBe("invalid_client");
    }
  }

  for (const endpoint of endpoints) {
    for (const basic of [true, false]) {
      expectOverTheLimit(await post(request, endpoint, guessed.id, guessed.secret, basic), `the right secret at ${endpoint.name}, basic ${basic}`);
    }
  }

  // Another client's budget is its own.
  const [token, revocation, introspection] = endpoints;
  const issued = await post(request, token, other.id, other.secret, true);
  expect(issued.status, issued.text).toBe(200);
  expect(typeof issued.body.access_token).toBe("string");
  const revoked = await post(request, revocation, other.id, other.secret, true);
  expect(revoked.status, revoked.text).toBe(200);
  const introspected = await post(request, introspection, other.id, other.secret, false);
  expect(introspected.status, introspected.text).toBe(200);
  expect(introspected.body).toEqual({ active: false });
});
