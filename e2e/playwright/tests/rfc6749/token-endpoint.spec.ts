// RFC 6749 at the token endpoint, whatever the grant: how a request is read (sections 3.2 and
// Appendix B), how the client authenticates (2.3, 3.2.1), and the shape of the answer (5.1, 5.2).
// The client credentials grant carries most of it, being the one grant with no user in it.
import type { Page } from "@playwright/test";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { expect, test } from "../../lib/fixtures";
import {
  basicAuth,
  expectInvalidClient,
  expectTokenError,
  expectTokenResponse,
  postToken,
  readAnswer,
  tokenEndpoint,
} from "../../lib/rfc6749";
import { passwordGrantClient } from "../../lib/test-clients";

const scope = "authserver:manage-account";

interface ClientsFixture {
  create(options?: { authorizationCode?: boolean; clientCredentials?: boolean }): Promise<{ id: number; identifier: string }>;
}

// A confidential client that may use the client credentials grant for one scope, and its secret.
async function clientCredentialsClient(page: Page, clients: ClientsFixture) {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  return { id: client.identifier, secret: await readClientSecret(page, client.id) };
}

test("a client authenticates with client_secret_basic or client_secret_post, and gets the section 5.1 answer", async ({
  page,
  clients,
  request,
}) => {
  const client = await clientCredentialsClient(page, clients);

  expectTokenResponse(
    await postToken(request, { grant_type: "client_credentials", scope }, { headers: { Authorization: basicAuth(client.id, client.secret) } }),
  );
  expectTokenResponse(
    await postToken(request, { grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret }),
  );
});

test("a failed client authentication is invalid_client, with a Basic challenge when it came in the Authorization header", async ({
  page,
  clients,
  request,
}) => {
  const client = await clientCredentialsClient(page, clients);
  const body = { grant_type: "client_credentials", scope };

  const wrongBasic = await postToken(request, body, { headers: { Authorization: basicAuth(client.id, `${client.secret}x`) } });
  expectInvalidClient(wrongBasic, { viaBasic: true });
  const unknownBasic = await postToken(request, body, { headers: { Authorization: basicAuth(`${client.id}-unknown`, client.secret) } });
  expectInvalidClient(unknownBasic, { viaBasic: true });

  const wrongPost = await postToken(request, { ...body, client_id: client.id, client_secret: `${client.secret}x` });
  expectInvalidClient(wrongPost, { viaBasic: false });
  // Section 2.2: the identifier is no secret, and never authenticates a confidential client alone.
  const identifierAlone = await postToken(request, { ...body, client_id: client.id });
  expectInvalidClient(identifierAlone, { viaBasic: false });
});

test("the client's credentials are read from the body, never from the request URI", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const query = `?${new URLSearchParams({ client_id: client.id, client_secret: client.secret })}`;

  // Section 2.3.1: the two parameters MUST NOT be included in the request URI.
  const inQuery = await postToken(request, { grant_type: "client_credentials", scope }, { query });
  expectTokenError(inQuery, ["invalid_request", "invalid_client"], inQuery.status === 401 ? 401 : 400);

  expectTokenResponse(
    await postToken(request, { grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret }),
  );
});

test("Basic credentials are form-urlencoded before base64, as section 2.3.1 has the client send them", async ({
  page,
  clients,
  request,
}) => {
  const client = await clientCredentialsClient(page, clients);
  // A client that encodes every character it may, as some libraries do: e2e-c-… sent as e2e%2Dc%2D….
  const encodedId = client.id.replaceAll("-", "%2D");
  const header = `Basic ${Buffer.from(`${encodedId}:${client.secret}`).toString("base64")}`;

  expectTokenResponse(await postToken(request, { grant_type: "client_credentials", scope }, { headers: { Authorization: header } }));
});

// RFC 9110 section 11.4 puts one or more spaces between the scheme and its credentials. Sent through
// the proxy, so this also shows the header reaches the auth server as the client wrote it.
test("Basic followed by two spaces authenticates the client", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const header = basicAuth(client.id, client.secret).replace(/^Basic /, "Basic  ");

  expectTokenResponse(await postToken(request, { grant_type: "client_credentials", scope }, { headers: { Authorization: header } }));
});

// Section 5.2: a client that tried the Authorization header MUST get a 401 with the challenge of its
// scheme. Basic credentials that cannot be read are that failure, whatever the body holds.
test("a Basic header whose credentials cannot be read is invalid_client, with the Basic challenge", async ({
  page,
  clients,
  request,
}) => {
  const client = await clientCredentialsClient(page, clients);
  const body = { grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret };

  for (const header of ["Basic not-valid-base64!", `Basic ${Buffer.from(client.id).toString("base64")}`]) {
    const answer = await postToken(request, body, { headers: { Authorization: header } });
    expectTokenError(answer, "invalid_client", 401);
    expect(answer.headers["www-authenticate"], header).toBe('Basic realm="goiabada"');
    expect(answer.body.error_description, header).toBe(
      "Client authentication failed: the Basic credentials in the Authorization header could not be read.",
    );
  }
});

test("two client authentication methods in one request are refused as invalid_request", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);

  const both = await postToken(
    request,
    { grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret },
    { headers: { Authorization: basicAuth(client.id, client.secret) } },
  );
  expectTokenError(both, "invalid_request");
});

test("a parameter of the RFC sent twice is refused; an unknown one is ignored, once or twice", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const headers = { Authorization: basicAuth(client.id, client.secret) };
  const form = (pairs: [string, string][]) => new URLSearchParams(pairs).toString();

  // Section 3.2: request parameters MUST NOT be included more than once, copies that agree included.
  expectTokenError(
    await postToken(request, form([["grant_type", "client_credentials"], ["grant_type", "client_credentials"], ["scope", scope]]), { headers }),
    "invalid_request",
  );
  expectTokenError(
    await postToken(request, form([["grant_type", "client_credentials"], ["scope", scope], ["scope", scope]]), { headers }),
    "invalid_request",
  );
  expectTokenError(
    await postToken(
      request,
      form([
        ["grant_type", "client_credentials"],
        ["scope", scope],
        ["client_id", client.id],
        ["client_secret", client.secret],
        ["client_secret", client.secret],
      ]),
    ),
    "invalid_request",
  );

  // Section 3.2 MUST ignore unrecognized parameters; erratum 5708 limits the repetition rule to the
  // RFC's own, so an unknown one sent twice is ignored too.
  expectTokenResponse(await postToken(request, form([["grant_type", "client_credentials"], ["scope", scope], ["foo", "bar"]]), { headers }));
  expectTokenResponse(
    await postToken(request, form([["grant_type", "client_credentials"], ["scope", scope], ["foo", "1"], ["foo", "2"]]), { headers }),
  );
});

test("a parameter sent without a value is treated as omitted", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const headers = { Authorization: basicAuth(client.id, client.secret) };

  // An omitted scope is the client's default here, everything it holds; the answer names it, since it
  // differs from the (absent) scope asked for (section 3.3).
  const omitted = await postToken(request, "grant_type=client_credentials", { headers });
  expectTokenResponse(omitted);
  expect(omitted.body.scope).toBe(scope);
  const empty = await postToken(request, "grant_type=client_credentials&scope=", { headers });
  expectTokenResponse(empty);
  expect(empty.body.scope).toBe(scope);

  // An empty client_secret is no secret at all.
  const emptySecret = await postToken(request, `grant_type=client_credentials&scope=${encodeURIComponent(scope)}&client_id=${client.id}&client_secret=`);
  expectInvalidClient(emptySecret, { viaBasic: false });
});

test("an unknown or wrongly cased grant_type is unsupported_grant_type", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const headers = { Authorization: basicAuth(client.id, client.secret) };

  for (const grantType of ["foo", "Client_Credentials", "urn:example:params:oauth:grant-type:unknown"]) {
    expectTokenError(await postToken(request, { grant_type: grantType, scope }, { headers }), "unsupported_grant_type");
  }
});

test("a missing grant_type is invalid_request", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);

  // Section 5.2: a request missing a required parameter is invalid_request.
  expectTokenError(await postToken(request, { scope }, { headers: { Authorization: basicAuth(client.id, client.secret) } }), "invalid_request");
});

test("a GET to the token endpoint issues nothing", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);
  const query = new URLSearchParams({ grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret });

  const answer = await readAnswer(await request.get(`${tokenEndpoint}?${query}`, { failOnStatusCode: false, maxRedirects: 0 }));
  expect(answer.status, answer.text).toBeGreaterThanOrEqual(400);
  expect(answer.text).not.toContain("access_token");
});

test("a body that is not form-encoded is refused as invalid_request, not as a server error", async ({ page, clients, request }) => {
  const client = await clientCredentialsClient(page, clients);

  const json = await postToken(
    request,
    JSON.stringify({ grant_type: "client_credentials", scope, client_id: client.id, client_secret: client.secret }),
    { headers: { "Content-Type": "application/json" } },
  );
  expectTokenError(json, "invalid_request");
});

test("form values are decoded as UTF-8, and + as a space (Appendix B)", async ({ page, clients, users, request }) => {
  const user = await users.create({ password: `Pässwörd £€ ${Date.now()}` });
  const { client, secret } = await passwordGrantClient(page, clients);

  // URLSearchParams encodes as Appendix B does: UTF-8 octets percent-escaped, the space as +.
  const body = new URLSearchParams({ grant_type: "password", username: user.email, password: user.password, scope: "openid" }).toString();
  expect(body).toContain("P%C3%A4ssw%C3%B6rd+%C2%A3%E2%82%AC+");
  expectTokenResponse(await postToken(request, body, { headers: { Authorization: basicAuth(client.identifier, secret) } }));
});
