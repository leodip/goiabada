import { createRemoteJWKSet, errors, jwtVerify } from "jose";
import { apiClient, apiResource, apiScope, apiUrl, issuer } from "@/lib/config";
import { challenge, checkBinding, checkProof, readCredentials, Refusal, useOnce, type CheckedProof } from "@/lib/dpop";

// Protect an API, step 6: check the access token on every request, on its own, with the auth
// server's public keys at /certs: the signature, the at+jwt header (RFC 9068 section 4), iss, exp,
// the resource among aud, and the permission in scope. 401 for a token that fails a check, 403 for one without the permission
// (RFC 6750 section 3.1). jose fetches the key set once, and again when a token names a kid it
// doesn't have.
//
// Then "Ask the auth server about a token": introspect it with the API's own client (RFC 7662), so a
// token cut off since it was issued, its session ended or its grant revoked, is refused at once.
//
// And "Accept DPoP-bound tokens" (RFC 9449): a token bound to a key, its cnf.jkt read from the token
// and from introspection's answer, is accepted only with the DPoP scheme and a proof by that key for
// this request (src/lib/dpop.ts); a bound token sent as Bearer is refused. ?check=local checks the
// token on its own alone, and ?check=introspection asks the auth server alone, reading everything
// from its answer, so each way the guide describes is tried by itself; with neither, the API does
// both. The proof's htu is the API's public URL, whatever the query.

// Made on the first request rather than at load, since the build loads this file with no
// configuration.
let keys: ReturnType<typeof createRemoteJWKSet> | undefined;

// The proofs this API accepted, until each one's iat window has passed. The test app runs as one
// process; an API running several would keep them where every instance sees them.
const seenProofs = new Map<string, number>();

// What a check of the token found: who it names, its scope, the thumbprint of the key it's bound to,
// and the binding as each source reported it, for the answer.
type Checked = { sub?: unknown; acr?: unknown; amr?: unknown; scope?: string; jkt?: string; binding: Record<string, unknown> };

export async function GET(request: Request) {
  const credentials = readCredentials(request.headers.get("authorization"));
  if (!credentials) return refuse(401, challenge(apiResource), { error: "no access token" });
  const { scheme, token } = credentials;
  const check = new URL(request.url).searchParams.get("check");

  try {
    // A proof is read only with the DPoP scheme: beside a bearer token, a DPoP header means nothing.
    let proof: CheckedProof | undefined;
    if (scheme === "DPoP") {
      const proofs = request.headers.get("dpop")?.split(",").map((value) => value.trim()) ?? [];
      proof = await checkProof(proofs, { method: request.method, url: apiUrl, accessToken: token });
    }

    const checked = check === "introspection" ? await introspected(scheme, token) : await verified(scheme, token);
    if (!check) {
      const answer = await introspected(scheme, token);
      if (answer.jkt !== checked.jkt) {
        throw new Refusal(401, scheme, "invalid_token", "The token's cnf and the auth server's answer name different keys.");
      }
      checked.binding = { ...checked.binding, ...answer.binding };
    }
    checkBinding(scheme, checked.jkt, proof?.jkt);

    const scopes = checked.scope ? checked.scope.split(" ") : [];
    if (!scopes.includes(apiScope)) {
      const refusal = new Refusal(403, scheme, "insufficient_scope", `The token needs ${apiScope}.`, apiScope);
      return refuse(403, challenge(apiResource, refusal), { error: "insufficient_scope", needs: apiScope, token_scope: checked.scope });
    }
    if (proof) useOnce(seenProofs, proof);

    return Response.json({
      caller: checked.sub,
      acr: checked.acr,
      amr: checked.amr,
      scope: checked.scope,
      scheme,
      checked: check ?? "local and introspection",
      binding: checked.binding,
      products: [
        { id: 1, name: "Guava paste" },
        { id: 2, name: "Guava juice" },
      ],
    });
  } catch (error) {
    const refusal =
      error instanceof Refusal
        ? error
        : new Refusal(401, scheme, "invalid_token", error instanceof errors.JOSEError ? `${error.code}: ${error.message}` : String(error));
    return refuse(refusal.status, challenge(apiResource, refusal), { error: refusal.error, error_description: refusal.description });
  }
}

// Step 6, on the API's own: the token's signature, header, iss, exp and aud, and its cnf.jkt.
async function verified(scheme: "Bearer" | "DPoP", token: string): Promise<Checked> {
  keys ??= createRemoteJWKSet(new URL(`${issuer}/certs`));
  const { payload } = await jwtVerify(token, keys, { issuer, audience: apiResource, typ: "at+jwt" });
  const cnf = payload.cnf as { jkt?: unknown } | undefined;
  const jkt = typeof cnf?.jkt === "string" ? cnf.jkt : undefined;
  return {
    sub: payload.sub,
    acr: payload.acr,
    amr: payload.amr,
    scope: typeof payload.scope === "string" ? payload.scope : undefined,
    jkt,
    binding: { token_cnf: cnf ?? null },
  };
}

// "Ask the auth server about a token": active, and for a bound token token_type DPoP and cnf.jkt
// (RFC 9449 section 6.2), with the API's own client and Basic credentials. A failure to ask throws,
// and the token is refused as one the API couldn't check.
async function introspected(scheme: "Bearer" | "DPoP", token: string): Promise<Checked> {
  const credentials = Buffer.from(`${encodeURIComponent(apiClient.clientId)}:${encodeURIComponent(apiClient.clientSecret)}`).toString("base64");
  const response = await fetch(`${issuer}/auth/introspect`, {
    method: "POST",
    headers: { authorization: `Basic ${credentials}`, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }),
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`the introspection endpoint answered ${response.status}`);
  const answer = (await response.json()) as Record<string, unknown>;
  if (answer.active !== true) throw new Refusal(401, scheme, "invalid_token", "The auth server says the token is no longer active.");
  const cnf = answer.cnf as { jkt?: unknown } | undefined;
  const jkt = answer.token_type === "DPoP" && typeof cnf?.jkt === "string" ? cnf.jkt : undefined;
  return {
    sub: answer.sub,
    acr: answer.acr,
    amr: answer.amr,
    scope: typeof answer.scope === "string" ? answer.scope : undefined,
    jkt,
    binding: { introspection: { token_type: answer.token_type, cnf: cnf ?? null } },
  };
}

function refuse(status: number, wwwAuthenticate: string, body: object) {
  return Response.json(body, { status, headers: { "www-authenticate": wwwAuthenticate } });
}
