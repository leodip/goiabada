// Calls to the auth server's token endpoint, as a client application makes them.
import type { APIRequestContext } from "@playwright/test";
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

// The claims of a JWT, unverified: the tests read what the server put in, they don't trust it.
export function jwtClaims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
}
