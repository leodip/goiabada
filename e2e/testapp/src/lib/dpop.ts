import { createHash } from "node:crypto";
import { calculateJwkThumbprint, EmbeddedJWK, errors, jwtVerify, type JWK } from "jose";

// Protect an API, "Accept DPoP-bound tokens": the checks RFC 9449 asks of a resource server that
// takes access tokens bound to a key, the proof's (section 4.3) and the binding's (sections 7.1 and
// 7.2), and the challenges it answers a refusal with. It imports nothing of the app's own, so its
// test (test/dpop.test.mjs) runs on Node alone.

// The algorithms the API accepts in a proof, as its DPoP challenge lists them: asymmetric only,
// never none or a shared-secret one (section 11.6).
export const algorithms = ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "Ed25519"];

// How far a proof's iat may lie from the API's clock, either side. The API hands out no nonce, so
// iat is what makes a proof fresh (section 11.1).
const iatWindowSeconds = 60;

export type Scheme = "Bearer" | "DPoP";

// A refused request: its status, the scheme whose challenge carries the error, the error code, and
// a description for the challenge and the body. scope is the permission a 403 names.
export class Refusal extends Error {
  status: number;
  scheme: Scheme;
  error: string;
  description: string;
  scope?: string;
  constructor(status: number, scheme: Scheme, error: string, description: string, scope?: string) {
    super(description);
    this.status = status;
    this.scheme = scheme;
    this.error = error;
    this.description = description;
    this.scope = scope;
  }
}

const invalidProof = (why: string) => new Refusal(401, "DPoP", "invalid_dpop_proof", `The DPoP proof is invalid: ${why}`);

// The access token and the scheme it came with, from the Authorization header. A header with
// another scheme, or none, carries no credentials the API reads.
export function readCredentials(header: string | null): { scheme: Scheme; token: string } | undefined {
  const match = /^(Bearer|DPoP) +(\S+)$/i.exec(header ?? "");
  if (!match) return undefined;
  return { scheme: match[1].toLowerCase() === "dpop" ? "DPoP" : "Bearer", token: match[2] };
}

// What a checked proof gives the API: its key's RFC 7638 thumbprint, to compare with the token's
// cnf.jkt, and what useOnce needs to accept it once.
export type CheckedProof = { jkt: string; replayKey: string; until: number };

// Checks the request's DPoP proofs, the values of its DPoP headers: exactly one, a dpop+jwt signed
// with an accepted algorithm by the public key in its own jwk header, naming this request's method
// in htm and its URL in htu, made within a minute of now, and carrying in ath the hash of the access
// token sent beside it. Throws a Refusal with invalid_dpop_proof otherwise.
export async function checkProof(
  proofs: string[],
  expected: { method: string; url: string; accessToken: string; now?: number },
): Promise<CheckedProof> {
  if (proofs.length === 0) throw invalidProof("the request carries no DPoP proof.");
  if (proofs.length > 1) throw invalidProof("send one DPoP proof, in one DPoP header.");
  const now = expected.now ?? Math.floor(Date.now() / 1000);

  let payload: Record<string, unknown>;
  let jwk: JWK;
  try {
    const verified = await jwtVerify(proofs[0], EmbeddedJWK, {
      typ: "dpop+jwt",
      algorithms,
      requiredClaims: ["jti", "htm", "htu", "iat"],
    });
    payload = verified.payload as Record<string, unknown>;
    jwk = verified.protectedHeader.jwk as JWK;
  } catch (error) {
    throw invalidProof(error instanceof errors.JOSEError ? error.message : String(error));
  }

  const { jti, htm, htu, iat, ath } = payload;
  if (typeof jti !== "string" || jti === "") throw invalidProof("its jti isn't a string.");
  if (htm !== expected.method) throw invalidProof(`its htm isn't ${expected.method}.`);
  if (typeof htu !== "string" || normalize(htu) !== normalize(expected.url)) throw invalidProof(`its htu isn't ${normalize(expected.url)}.`);
  if (typeof iat !== "number" || Math.abs(now - iat) > iatWindowSeconds) throw invalidProof("its iat is more than 60 seconds from now.");
  if (ath !== hash(expected.accessToken)) throw invalidProof("its ath isn't the hash of the access token.");

  return {
    jkt: await calculateJwkThumbprint(jwk, "sha256"),
    replayKey: hash(`${normalize(htu)} ${jti}`),
    until: iat + iatWindowSeconds,
  };
}

// A URL as section 4.3 compares it: without its query and fragment, its scheme and host lower-cased,
// a default port dropped and dot segments removed, which the URL parser does. One that doesn't parse
// matches nothing.
function normalize(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "";
  }
}

// Section 4.2's ath, and the hash a replay record keeps: base64url SHA-256, without padding.
function hash(value: string): string {
  return createHash("sha256").update(value, "ascii").digest("base64url");
}

// Section 11.1: accepts each proof once. seen maps a proof's replayKey to the end of its iat window,
// after which the proof is refused for its iat anyway, so its record is dropped. Call it last, once
// every other check on the request has passed, so a refused request spends no proof.
export function useOnce(seen: Map<string, number>, proof: Pick<CheckedProof, "replayKey" | "until">, now: number = Math.floor(Date.now() / 1000)) {
  for (const [replayKey, until] of seen) if (until < now) seen.delete(replayKey);
  if (seen.has(proof.replayKey)) throw invalidProof("it was already used.");
  seen.set(proof.replayKey, proof.until);
}

// Sections 7.1 and 7.2: a token bound to a key (tokenJkt, its cnf.jkt) is accepted only with the
// DPoP scheme and a proof by that key (proofJkt), and a token bound to none only as a bearer token.
export function checkBinding(scheme: Scheme, tokenJkt: string | undefined, proofJkt: string | undefined) {
  if (scheme === "Bearer") {
    if (tokenJkt) throw new Refusal(401, "Bearer", "invalid_token", "The access token is bound to a DPoP key and must be sent with the DPoP scheme.");
    return;
  }
  if (!tokenJkt) throw new Refusal(401, "DPoP", "invalid_token", "The access token is not bound to a DPoP key and must be sent with the Bearer scheme.");
  if (tokenJkt !== proofJkt) throw new Refusal(401, "DPoP", "invalid_token", "The DPoP proof is signed by another key than the one the access token is bound to.");
}

// The WWW-Authenticate value of a 401 or 403: a Bearer challenge, then a DPoP challenge listing the
// algorithms, the refusal's error in the challenge of the scheme the request used (section 7.2). With
// no refusal, as for a request with no token, neither carries an error (RFC 6750 section 3.1).
export function challenge(realm: string, refusal?: Refusal): string {
  const error = (scheme: Scheme) => {
    if (refusal?.scheme !== scheme) return "";
    const quoted = (value: string) => `"${value.replace(/["\\]/g, "'")}"`;
    let params = `, error=${quoted(refusal.error)}, error_description=${quoted(refusal.description)}`;
    if (refusal.scope) params += `, scope=${quoted(refusal.scope)}`;
    return params;
  };
  return `Bearer realm="${realm}"${error("Bearer")}, DPoP realm="${realm}", algs="${algorithms.join(" ")}"${error("DPoP")}`;
}
