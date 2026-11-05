// The logout token checks of the back-channel logout route (src/lib/logout-token.ts), against tokens
// signed here, one broken per case: Back-Channel Logout 1.0 section 2.6 lists each check. Run with
// npm test; the e2e suite's testapp/backchannel-logout.spec.ts drives the route against the real auth
// server.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { LogoutTokenError, logoutEvent, validateLogoutToken } from "../src/lib/logout-token.ts";

const issuer = "https://auth.example.com";
const audience = "testapp-web";

const signing = await generateKeyPair("RS256");
const other = await generateKeyPair("RS256");
const jwk = { ...(await exportJWK(signing.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
const keys = createLocalJWKSet({ keys: [jwk] });

const now = () => Math.floor(Date.now() / 1000);

function claims(overrides = {}) {
  const iat = now();
  const base = {
    iss: issuer,
    aud: audience,
    iat,
    exp: iat + 120,
    jti: "0b6a8f7e-2d4c-4f8e-9b1a-3c5d7e9f1a2b",
    events: { [logoutEvent]: {} },
    sub: "c5b9b6a2-4b39-4b8e-9a8e-6f7f2b3a1d10",
    sid: "3f2a1b4c-5d6e-4f70-8192-a3b4c5d6e7f8",
  };
  const merged = { ...base, ...overrides };
  for (const [name, value] of Object.entries(merged)) if (value === undefined) delete merged[name];
  return merged;
}

// typ null leaves the header's typ out.
function sign(payload, { typ = "logout+jwt", key = signing.privateKey, kid = "k1" } = {}) {
  const header = { alg: "RS256", kid };
  if (typ !== null) header.typ = typ;
  return new SignJWT(payload).setProtectedHeader(header).sign(key);
}

async function refused(token, why) {
  await assert.rejects(validateLogoutToken(token, { issuer, audience, keys }), (error) => {
    assert.ok(error instanceof LogoutTokenError, `a LogoutTokenError, not ${error}`);
    if (why) assert.match(error.message, why);
    return true;
  });
}

test("a token the auth server would send is accepted, with its claims", async () => {
  const sent = claims();
  const got = await validateLogoutToken(await sign(sent), { issuer, audience, keys });
  assert.equal(got.sub, sent.sub);
  assert.equal(got.sid, sent.sid);
  assert.equal(got.jti, sent.jti);
});

test("a token naming the user alone, with no session, is accepted", async () => {
  const got = await validateLogoutToken(await sign(claims({ sid: undefined })), { issuer, audience, keys });
  assert.equal(got.sub, "c5b9b6a2-4b39-4b8e-9a8e-6f7f2b3a1d10");
  assert.equal(got.sid, undefined);
});

test("a token signed with another key is refused", async () => {
  await refused(await sign(claims(), { key: other.privateKey }));
});

test("a token not typed logout+jwt is refused, an ID token's JWT and no typ included", async () => {
  await refused(await sign(claims(), { typ: "JWT" }), /typ/);
  await refused(await sign(claims(), { typ: null }), /typ/);
});

test("a token from another issuer or for another client is refused", async () => {
  await refused(await sign(claims({ iss: "https://evil.example.com" })), /iss/);
  await refused(await sign(claims({ aud: "testapp-web2" })), /aud/);
});

test("an expired token, or one with no iat or jti, is refused", async () => {
  await refused(await sign(claims({ iat: now() - 300, exp: now() - 180 })), /exp/);
  await refused(await sign(claims({ iat: undefined })), /iat/);
  await refused(await sign(claims({ jti: undefined })), /jti/);
});

test("a token without the logout event is refused", async () => {
  await refused(await sign(claims({ events: undefined })), /events/);
  await refused(await sign(claims({ events: { "http://schemas.openid.net/event/other": {} } })), /events/);
  await refused(await sign(claims({ events: { [logoutEvent]: "yes" } })), /events/);
});

test("a token naming neither a user nor a session is refused", async () => {
  await refused(await sign(claims({ sub: undefined, sid: undefined })), /neither/);
});

test("a token with a nonce, as an ID token has, is refused", async () => {
  await refused(await sign(claims({ nonce: "n-0S6_WzA2Mj" })), /nonce/);
});
