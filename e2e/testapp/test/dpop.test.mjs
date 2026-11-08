// The API's checks of a DPoP request (src/lib/dpop.ts), against proofs signed here, one broken per
// case: Protect an API, "Accept DPoP-bound tokens", lists each check, after RFC 9449 sections 4.3,
// 7.1 and 7.2. Run with npm test; the e2e suite's testapp/protect-an-api.spec.ts drives the API
// against the real auth server.
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { test } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { algorithms, challenge, checkBinding, checkProof, readCredentials, Refusal, useOnce } from "../src/lib/dpop.ts";

const url = "https://api.example.com/products";
const accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl";
const now = 1760000000;

const key = await generateKeyPair("ES256", { extractable: true });
const jwk = await exportJWK(key.publicKey);
const other = await generateKeyPair("ES256", { extractable: true });

// RFC 7638 section 3: the required members of an EC key, in lexicographic order, with no
// whitespace, hashed with SHA-256 and base64url-encoded. Worked out here, apart from the code.
const thumbprint = createHash("sha256").update(`{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`).digest("base64url");
// RFC 9449 section 4.2: the base64url SHA-256 of the access token's ASCII characters.
const ath = createHash("sha256").update(accessToken, "ascii").digest("base64url");

// A proof for GET url carrying accessToken, signed by key, with one part changed per case. A claim
// or header member set to undefined is left out.
async function proof({ claims = {}, header = {}, signWith = key.privateKey } = {}) {
  const payload = { jti: randomUUID(), htm: "GET", htu: url, iat: now, ath, ...claims };
  for (const [name, value] of Object.entries(payload)) if (value === undefined) delete payload[name];
  const protectedHeader = { typ: "dpop+jwt", alg: "ES256", jwk, ...header };
  for (const [name, value] of Object.entries(protectedHeader)) if (value === undefined) delete protectedHeader[name];
  return new SignJWT(payload).setProtectedHeader(protectedHeader).sign(signWith);
}

const expected = (overrides = {}) => ({ method: "GET", url, accessToken, now, ...overrides });

async function refused(proofs, why, overrides) {
  await assert.rejects(checkProof(proofs, expected(overrides)), (error) => {
    assert.ok(error instanceof Refusal, `a Refusal, not ${error}`);
    assert.equal(error.status, 401);
    assert.equal(error.error, "invalid_dpop_proof");
    assert.equal(error.scheme, "DPoP");
    if (why) assert.match(error.description, why);
    return true;
  });
}

test("a proof for this request by the token's key is accepted, and answers the key's RFC 7638 thumbprint", async () => {
  const checked = await checkProof([await proof()], expected());
  assert.equal(checked.jkt, thumbprint);
});

test("htu is compared without its query or fragment, after normalizing the scheme, host and port", async () => {
  for (const htu of [`${url}?page=2`, `${url}#top`, "HTTPS://API.Example.COM:443/products"]) {
    assert.equal((await checkProof([await proof({ claims: { htu } })], expected())).jkt, thumbprint, htu);
  }
  // The request's own query is ignored too.
  assert.equal((await checkProof([await proof()], expected({ url: `${url}?check=local` }))).jkt, thumbprint);
});

test("no proof, or two, is refused", async () => {
  await refused([], /no DPoP proof/);
  await refused([await proof(), await proof()], /one DPoP proof/);
});

test("a proof for another URL or another method is refused", async () => {
  await refused([await proof({ claims: { htu: "https://api.example.com/orders" } })], /htu/);
  await refused([await proof({ claims: { htu: "https://other.example.com/products" } })], /htu/);
  await refused([await proof({ claims: { htu: "http://api.example.com/products" } })], /htu/);
  await refused([await proof({ claims: { htm: "POST" } })], /htm/);
  // htm is the method exactly, not compared case-insensitively.
  await refused([await proof({ claims: { htm: "get" } })], /htm/);
});

test("a proof whose ath isn't this token's hash, or that has none, is refused", async () => {
  await refused([await proof({ claims: { ath: createHash("sha256").update("another token").digest("base64url") } })], /ath/);
  await refused([await proof({ claims: { ath: undefined } })], /ath/);
});

test("a proof made more than 60 seconds before or after now is refused; one within is accepted", async () => {
  for (const iat of [now - 60, now + 60]) {
    assert.equal((await checkProof([await proof({ claims: { iat } })], expected())).jkt, thumbprint, `iat ${iat - now}`);
  }
  await refused([await proof({ claims: { iat: now - 61 } })], /iat/);
  await refused([await proof({ claims: { iat: now + 61 } })], /iat/);
});

test("a proof missing jti, htm, htu or iat is refused", async () => {
  for (const claim of ["jti", "htm", "htu", "iat"]) {
    await refused([await proof({ claims: { [claim]: undefined } })]);
  }
});

test("a proof of another type, or no type, is refused; application/dpop+jwt is the same type", async () => {
  await refused([await proof({ header: { typ: "JWT" } })], /typ/);
  await refused([await proof({ header: { typ: undefined } })], /typ/);
  assert.equal((await checkProof([await proof({ header: { typ: "application/dpop+jwt" } })], expected())).jkt, thumbprint);
});

test("a proof signed by another key than its jwk, with a private jwk, or with no jwk is refused", async () => {
  await refused([await proof({ signWith: other.privateKey })]);
  await refused([await proof({ header: { jwk: await exportJWK(key.privateKey) } })], /public key/);
  await refused([await proof({ header: { jwk: undefined } })], /jwk/);
});

test("a proof with a symmetric algorithm, or one off the list, is refused", async () => {
  const secret = new TextEncoder().encode("a shared secret of at least thirty-two bytes");
  await refused([await proof({ header: { alg: "HS256", jwk: { kty: "oct", k: "c2VjcmV0" } }, signWith: secret })], /alg/);
  assert.ok(!algorithms.includes("none") && !algorithms.some((alg) => alg.startsWith("HS")));
});

test("a proof that isn't a JWT is refused", async () => {
  await refused(["not-a-jwt"]);
});

test("each proof is accepted once, until its iat window has passed", () => {
  const seen = new Map();
  assert.doesNotThrow(() => useOnce(seen, { replayKey: "a", until: now + 60 }, now));
  assert.throws(
    () => useOnce(seen, { replayKey: "a", until: now + 60 }, now + 30),
    (error) => error instanceof Refusal && error.error === "invalid_dpop_proof" && /already used/.test(error.description),
  );
  assert.doesNotThrow(() => useOnce(seen, { replayKey: "b", until: now + 60 }, now));
  // Past its window, the record is dropped: the proof would be refused for its iat anyway.
  useOnce(seen, { replayKey: "c", until: now + 200 }, now + 100);
  assert.ok(!seen.has("a"), "an expired record is swept");
});

test("two proofs with the same jti for different URLs are different proofs", async () => {
  const jti = randomUUID();
  const a = await checkProof([await proof({ claims: { jti } })], expected());
  const b = await checkProof([await proof({ claims: { jti, htu: "https://api.example.com/orders" } })], expected({ url: "https://api.example.com/orders" }));
  assert.notEqual(a.replayKey, b.replayKey);
  assert.equal(a.until, now + 60);
});

test("a bound token is accepted only with the DPoP scheme and a proof by its key (sections 7.1 and 7.2)", () => {
  assert.doesNotThrow(() => checkBinding("DPoP", thumbprint, thumbprint));
  assert.doesNotThrow(() => checkBinding("Bearer", undefined, undefined));
  for (const [scheme, tokenJkt, proofJkt, why, inChallenge] of [
    ["Bearer", thumbprint, undefined, /bound to a DPoP key/, "Bearer"],
    ["DPoP", undefined, thumbprint, /not bound/, "DPoP"],
    ["DPoP", thumbprint, "c29tZSBvdGhlciBrZXkncyB0aHVtYnByaW50IGhlcmU", /another key/, "DPoP"],
  ]) {
    assert.throws(
      () => checkBinding(scheme, tokenJkt, proofJkt),
      (error) => error instanceof Refusal && error.status === 401 && error.error === "invalid_token" && why.test(error.description) && error.scheme === inChallenge,
      `${scheme} ${tokenJkt ?? "unbound"} ${proofJkt ?? "no proof"}`,
    );
  }
});

test("the Authorization header names the Bearer or DPoP scheme, case-insensitively; anything else is no credentials", () => {
  assert.deepEqual(readCredentials(`Bearer ${accessToken}`), { scheme: "Bearer", token: accessToken });
  assert.deepEqual(readCredentials(`DPoP ${accessToken}`), { scheme: "DPoP", token: accessToken });
  assert.deepEqual(readCredentials(`dpop ${accessToken}`), { scheme: "DPoP", token: accessToken });
  for (const header of [null, "", "Basic dXNlcjpwYXNz", "DPoP", "Bearer "]) assert.equal(readCredentials(header), undefined, String(header));
});

test("every 401 names both schemes, Bearer first, with the error in the challenge of the scheme used", () => {
  const algs = `algs="${algorithms.join(" ")}"`;
  assert.equal(challenge("product-api"), `Bearer realm="product-api", DPoP realm="product-api", ${algs}`);
  assert.equal(
    challenge("product-api", new Refusal(401, "Bearer", "invalid_token", "Expired.")),
    `Bearer realm="product-api", error="invalid_token", error_description="Expired.", DPoP realm="product-api", ${algs}`,
  );
  assert.equal(
    challenge("product-api", new Refusal(401, "DPoP", "invalid_dpop_proof", "No proof.")),
    `Bearer realm="product-api", DPoP realm="product-api", ${algs}, error="invalid_dpop_proof", error_description="No proof."`,
  );
  assert.equal(
    challenge("product-api", new Refusal(403, "DPoP", "insufficient_scope", "Needs product-api:read.", "product-api:read")),
    `Bearer realm="product-api", DPoP realm="product-api", ${algs}, error="insufficient_scope", error_description="Needs product-api:read.", scope="product-api:read"`,
  );
});
