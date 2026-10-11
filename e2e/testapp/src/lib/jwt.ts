import { decodeJwt } from "jose";

// A token's claims, for display only. Nothing here checks a signature: the code that trusts a
// token (openid-client for ID tokens, the API route for access tokens) checks it.
export function claims(token: string | undefined): Record<string, unknown> | null {
  if (!token) return null;
  try {
    return decodeJwt(token) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function shorten(token: string | undefined): string {
  if (!token) return "(none)";
  return token.length > 40 ? `${token.slice(0, 20)}…${token.slice(-12)}` : token;
}
