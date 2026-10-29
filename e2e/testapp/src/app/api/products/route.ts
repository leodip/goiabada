import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { apiResource, apiScope, issuer } from "@/lib/config";

// Protect an API, step 6: check the access token on every request, on its own, with the auth
// server's public keys at /certs: the signature, the at+jwt header (RFC 9068 section 4), iss, exp,
// the resource among aud, and the permission in scope. 401 for a token that fails a check, 403 for one without the permission
// (RFC 6750 section 3.1). jose fetches the key set once, and again when a token names a kid it
// doesn't have.

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

function refuse(status: number, challenge: string, body: object) {
  return Response.json(body, { status, headers: { "www-authenticate": challenge } });
}
