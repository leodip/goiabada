import type { NextRequest } from "next/server";
import * as client from "openid-client";
import { appUrl } from "@/lib/config";
import { describeError, webConfig } from "@/lib/oidc";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Steps 4 to 7 of Add sign-in to a web app: check state, redeem the code with the secret and the
// verifier, check the ID token (openid-client checks its signature, iss, exp, aud and nonce), and
// keep the tokens.
export async function GET(request: NextRequest, ctx: RouteContext<"/[client]/callback">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  const pending = state.pending;
  state.pending = undefined;
  if (!pending) {
    setResult(state, "Sign-in failed", false, { error: "No sign-in was in progress in this browser: start again." });
    return backTo(key);
  }

  // The URL the auth server sent the browser to. Built from APP_URL rather than the request,
  // which behind a proxy names the container, so the redirect_uri sent to the token endpoint is
  // the one registered.
  const currentUrl = new URL(`${appUrl}/${key}/callback${request.nextUrl.search}`);
  try {
    const config = await webConfig(key);
    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: pending.codeVerifier,
      expectedState: pending.state,
      expectedNonce: pending.nonce,
      idTokenExpected: true,
    });
    const expiresIn = tokens.expiresIn();
    state.signIn = {
      idToken: tokens.id_token!,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: expiresIn === undefined ? undefined : Date.now() + expiresIn * 1000,
      signedInAt: Date.now(),
    };
    setResult(state, "Signed in", true, {
      seconds_since_the_sign_in_started: Math.round((Date.now() - pending.startedAt) / 1000),
      token_type: tokens.token_type,
      expires_in: expiresIn,
      scope: tokens.scope,
      refresh_token: tokens.refresh_token ? "received" : "none",
    });
  } catch (error) {
    setResult(state, "Sign-in failed", false, describeError(error));
  }
  return backTo(key);
}
