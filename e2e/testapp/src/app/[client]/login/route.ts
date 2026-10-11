import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import * as client from "openid-client";
import { appUrl, defaultScope } from "@/lib/config";
import { describeError, webConfig } from "@/lib/oidc";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Step 3 of Add sign-in to a web app: make a state, a nonce and a PKCE verifier, keep them in the
// session, and send the browser to the auth server.
export async function GET(request: NextRequest, ctx: RouteContext<"/[client]/login">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  let config: client.Configuration;
  try {
    config = await webConfig(key);
  } catch (error) {
    setResult(state, "Discovery failed", false, describeError(error));
    return backTo(key);
  }

  const pending = {
    state: client.randomState(),
    nonce: client.randomNonce(),
    codeVerifier: client.randomPKCECodeVerifier(),
    startedAt: Date.now(),
  };
  const form = request.nextUrl.searchParams;
  const parameters: Record<string, string> = {
    redirect_uri: `${appUrl}/${key}/callback`,
    scope: form.get("scope") || defaultScope,
    code_challenge: await client.calculatePKCECodeChallenge(pending.codeVerifier),
    code_challenge_method: "S256",
    state: pending.state,
    nonce: pending.nonce,
  };
  for (const name of ["prompt", "acr_values", "max_age"]) {
    const value = form.get(name);
    if (value) parameters[name] = value;
  }
  if (form.get("id_token_hint") && state.signIn) parameters.id_token_hint = state.signIn.idToken;

  state.pending = pending;
  return NextResponse.redirect(client.buildAuthorizationUrl(config, parameters));
}
