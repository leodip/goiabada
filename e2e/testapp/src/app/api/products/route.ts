import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { apiClient, apiResource, apiScope, issuer } from "@/lib/config";

// Protect an API, step 6: check the access token on every request, on its own, with the auth
// server's public keys at /certs: the signature, the at+jwt header (RFC 9068 section 4), iss, exp,
// the resource among aud, and the permission in scope. 401 for a token that fails a check, 403 for one without the permission
// (RFC 6750 section 3.1). jose fetches the key set once, and again when a token names a kid it
// doesn't have.
//
// Then "Ask the auth server about a token": introspect it with the API's own client (RFC 7662), so a
// token cut off since it was issued, its session ended or its grant revoked, is refused at once.

// Made on the first request rather than at load, since the build loads this file with no
// configuration.
let keys: ReturnType<typeof createRemoteJWKSet> | undefined;

export async function GET(request: Request) {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return refuse(401, `Bearer realm="${apiResource}"`, { error: "no bearer token" });

  try {
    keys ??= createRemoteJWKSet(new URL(`${issuer}/certs`));
    const { payload } = await jwtVerify(token, keys, { issuer, audience: apiResource, typ: "at+jwt" });
    const introspection = await introspect(token);
    if (introspection.active !== true) {
      return refuse(401, `Bearer realm="${apiResource}", error="invalid_token"`, {
        error: "invalid_token",
        error_description: "The auth server says the token is no longer active.",
      });
    }
    const scopes = typeof payload.scope === "string" ? payload.scope.split(" ") : [];
    if (!scopes.includes(apiScope)) {
      return refuse(403, `Bearer realm="${apiResource}", error="insufficient_scope", scope="${apiScope}"`, {
        error: "insufficient_scope",
        needs: apiScope,
        token_scope: payload.scope,
      });
    }
    return Response.json({
      caller: payload.sub,
      acr: payload.acr,
      amr: payload.amr,
      scope: payload.scope,
      products: [
        { id: 1, name: "Guava paste" },
        { id: 2, name: "Guava juice" },
      ],
    });
  } catch (error) {
    const description = error instanceof errors.JOSEError ? `${error.code}: ${error.message}` : String(error);
    return refuse(401, `Bearer realm="${apiResource}", error="invalid_token"`, {
      error: "invalid_token",
      error_description: description,
    });
  }
}

// Asks the introspection endpoint about the token, as the API's client, with Basic credentials. A
// failure to ask throws, and the token is refused as one the API couldn't check.
async function introspect(token: string): Promise<Record<string, unknown>> {
  const credentials = Buffer.from(`${encodeURIComponent(apiClient.clientId)}:${encodeURIComponent(apiClient.clientSecret)}`).toString("base64");
  const response = await fetch(`${issuer}/auth/introspect`, {
    method: "POST",
    headers: { authorization: `Basic ${credentials}`, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`the introspection endpoint answered ${response.status}`);
  return (await response.json()) as Record<string, unknown>;
}

function refuse(status: number, challenge: string, body: object) {
  return Response.json(body, { status, headers: { "www-authenticate": challenge } });
}
