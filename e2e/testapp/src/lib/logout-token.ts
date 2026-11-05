import { jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

// Sign users out, "Get told when a session ends", step 2: the checks OpenID Connect Back-Channel
// Logout 1.0 section 2.6 asks of a logout token. It imports nothing of the app's own, so its test
// (test/logout-token.test.mjs) runs on Node alone.

export const logoutEvent = "http://schemas.openid.net/event/backchannel-logout";

// A token the checks refused, with why, for the 400 the route answers.
export class LogoutTokenError extends Error {}

export type LogoutTokenClaims = JWTPayload & { sub?: string; sid?: string };

// Checks the token's signature against the auth server's keys, its type, algorithm, iss, aud, iat
// and exp as for an ID token, then the claims a logout token must and must not have, and answers its
// claims. Anything else throws a LogoutTokenError.
export async function validateLogoutToken(
  token: string,
  expected: { issuer: string; audience: string; keys: JWTVerifyGetKey },
): Promise<LogoutTokenClaims> {
  let claims: JWTPayload;
  try {
    ({ payload: claims } = await jwtVerify(token, expected.keys, {
      issuer: expected.issuer,
      audience: expected.audience,
      algorithms: ["RS256"],
      typ: "logout+jwt",
      requiredClaims: ["iat", "exp", "jti"],
    }));
  } catch (error) {
    throw new LogoutTokenError(error instanceof Error ? error.message : String(error));
  }

  const events = claims.events;
  if (!isObject(events) || !isObject(events[logoutEvent])) {
    throw new LogoutTokenError(`The token's events claim has no ${logoutEvent} member.`);
  }
  const { sub, sid } = claims;
  if (sub !== undefined && typeof sub !== "string") throw new LogoutTokenError("The token's sub claim isn't a string.");
  if (sid !== undefined && typeof sid !== "string") throw new LogoutTokenError("The token's sid claim isn't a string.");
  if (!sub && !sid) throw new LogoutTokenError("The token names neither a sub nor a sid.");
  if ("nonce" in claims) throw new LogoutTokenError("The token has a nonce claim, which a logout token never has.");
  return claims as LogoutTokenClaims;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
