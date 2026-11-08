// DPoP proofs (RFC 9449) built the way a client builds them, with Node's built-in crypto alone: an
// ES256 key of the test's own, and its RFC 7638 thumbprint worked out here, apart from the server,
// so a test comparing it with a token's cnf.jkt checks the server against an answer it did not
// compute.
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { expect, type APIRequestContext } from "@playwright/test";
import { expectNoStore, postToken, tokenEndpoint, type RawAnswer } from "./rfc6749";

export interface DPoPKey {
  privateKey: KeyObject;
  // The public key as a proof's jwk header member carries it.
  jwk: { kty: string; crv: string; x: string; y: string };
  // RFC 7638 section 3: SHA-256 over the required members in lexicographic order, base64url.
  thumbprint: string;
}

// A fresh P-256 key pair.
export function dpopKey(): DPoPKey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { kty, crv, x, y } = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string; y: string };
  const thumbprint = createHash("sha256").update(`{"crv":"${crv}","kty":"${kty}","x":"${x}","y":"${y}"}`).digest("base64url");
  return { privateKey, jwk: { kty, crv, x, y }, thumbprint };
}

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");

// Section 4.2: the ath of an access token, the base64url SHA-256 of its ASCII characters.
export function ath(accessToken: string): string {
  return createHash("sha256").update(accessToken, "ascii").digest("base64url");
}

// A proof by key for a request with method htm to htu: a dpop+jwt header naming ES256 and the key,
// and a fresh jti, iat now or iatOffsetSeconds from it, the nonce when there is one, and the ath of
// accessToken when there is one, as a proof to a resource carries (section 7).
export function dpopProof(
  key: DPoPKey,
  { htu = tokenEndpoint, htm = "POST", nonce, accessToken, iatOffsetSeconds = 0 }: { htu?: string; htm?: string; nonce?: string; accessToken?: string; iatOffsetSeconds?: number } = {},
): string {
  const header = b64({ typ: "dpop+jwt", alg: "ES256", jwk: key.jwk });
  const claims = b64({
    jti: randomUUID(),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000) + iatOffsetSeconds,
    ...(nonce ? { nonce } : {}),
    ...(accessToken ? { ath: ath(accessToken) } : {}),
  });
  const signature = sign("sha256", Buffer.from(`${header}.${claims}`), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return `${header}.${claims}.${signature.toString("base64url")}`;
}

// The one DPoP-Nonce an answer to a DPoP request carries.
export function nonceOf(answer: RawAnswer): string {
  const nonce = answer.headers["dpop-nonce"];
  expect(nonce, "the answer carries a DPoP-Nonce").toBeTruthy();
  expect(nonce, "one DPoP-Nonce, not several joined").not.toContain(",");
  return nonce;
}

// Section 8: a token request whose proof carries no nonce is answered use_dpop_nonce with a nonce,
// and the same request again, with a proof carrying it, is answered. Returns the second answer.
export async function postTokenWithDPoP(
  request: APIRequestContext,
  body: Record<string, string>,
  key: DPoPKey,
  { headers = {} }: { headers?: Record<string, string> } = {},
): Promise<RawAnswer> {
  const asked = await postToken(request, body, { headers: { ...headers, DPoP: dpopProof(key) } });
  expectUseDPoPNonce(asked);
  return postToken(request, body, { headers: { ...headers, DPoP: dpopProof(key, { nonce: nonceOf(asked) }) } });
}

// Section 8's refusal: 400 use_dpop_nonce, with a nonce to retry with, and nothing cached.
export function expectUseDPoPNonce(answer: RawAnswer) {
  expect(answer.status, answer.text).toBe(400);
  expect(answer.body.error, answer.text).toBe("use_dpop_nonce");
  expect(answer.body.access_token).toBeUndefined();
  nonceOf(answer);
  expectNoStore(answer);
}

// Section 5: a token response whose access token is bound to key: token_type DPoP and cnf.jkt the
// key's thumbprint (section 6.1), with a fresh nonce for the next request.
export function expectBoundTokenResponse(answer: RawAnswer, key: DPoPKey) {
  expect(answer.status, answer.text).toBe(200);
  expect(answer.body.token_type).toBe("DPoP");
  const claims = JSON.parse(Buffer.from(String(answer.body.access_token).split(".")[1], "base64url").toString("utf8"));
  expect(claims.cnf, "cnf.jkt is the proof key's thumbprint").toEqual({ jkt: key.thumbprint });
  nonceOf(answer);
  expectNoStore(answer);
}
