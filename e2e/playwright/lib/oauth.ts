// Calls to the auth server's token endpoint, as a client application makes them.
import { expect, test, type APIRequestContext } from "@playwright/test";
import { env } from "./environment";

export interface TokenAnswer {
  status: number;
  body: Record<string, unknown>;
}

// The client credentials grant, authenticating with client_secret_basic.
export async function clientCredentialsToken(
  request: APIRequestContext,
  clientId: string,
  clientSecret: string,
  scope?: string,
): Promise<TokenAnswer> {
  const form: Record<string, string> = { grant_type: "client_credentials" };
  if (scope) form.scope = scope;
  const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");
  const response = await request.post(`${env.authUrl}/auth/token`, {
    form,
    headers: { Authorization: `Basic ${basic}` },
    failOnStatusCode: false,
  });
  return { status: response.status(), body: await response.json() };
}

// The resource owner password credentials grant, authenticating the client with client_secret_basic:
// the shortest way for a test to get a user's tokens without driving a browser sign-in.
//
// The grant is limited to 30 requests a minute per client address (the ropc_ip tier), successes
// included, and the suite running four workers from one address can pass that. A 429 here is the
// limiter doing its job, not the test's subject, so the call waits and tries again, every few
// seconds as the sliding window frees room, extending the test's timeout by what it waits and
// noting it in the report.
export async function passwordToken(
  request: APIRequestContext,
  clientId: string,
  clientSecret: string,
  username: string,
  password: string,
  scope: string,
): Promise<TokenAnswer> {
  const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");
  const post = () =>
    request.post(`${env.authUrl}/auth/token`, {
      form: { grant_type: "password", username, password, scope },
      headers: { Authorization: `Basic ${basic}` },
      failOnStatusCode: false,
    });
  let response = await post();
  for (let waited = 0; response.status() === 429 && waited < 90_000; waited += 3_000) {
    if (waited === 0) test.info().annotations.push({ type: "rate-limited", description: "password grant answered 429; waited" });
    test.info().setTimeout(test.info().timeout + 3_000);
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    response = await post();
  }
  return { status: response.status(), body: await response.json() };
}

// Redeems an authorization code, authenticating the client with client_secret_basic.
export async function codeToken(
  request: APIRequestContext,
  clientId: string,
  clientSecret: string,
  code: string,
  codeVerifier: string,
  redirectUri: string,
): Promise<TokenAnswer> {
  const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64");
  const response = await request.post(`${env.authUrl}/auth/token`, {
    form: { grant_type: "authorization_code", code, code_verifier: codeVerifier, redirect_uri: redirectUri },
    headers: { Authorization: `Basic ${basic}` },
    failOnStatusCode: false,
  });
  return { status: response.status(), body: await response.json() };
}

// The userinfo endpoint, called with an access token as a bearer.
export async function userinfo(request: APIRequestContext, accessToken: string): Promise<TokenAnswer> {
  const response = await request.get(`${env.authUrl}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    failOnStatusCode: false,
  });
  return { status: response.status(), body: await response.json() };
}

// The claims of a JWT, unverified: the tests read what the server put in, they don't trust it.
export function jwtClaims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
}

// A user's tokens from the password grant, which must succeed, with both tokens decoded.
export async function userTokens(
  request: APIRequestContext,
  clientId: string,
  clientSecret: string,
  user: { email: string; password: string },
  scope: string,
) {
  const answer = await passwordToken(request, clientId, clientSecret, user.email, user.password, scope);
  expect(answer.status, JSON.stringify(answer.body)).toBe(200);
  return {
    body: answer.body,
    access: jwtClaims(answer.body.access_token as string),
    id: answer.body.id_token ? jwtClaims(answer.body.id_token as string) : {},
  };
}
