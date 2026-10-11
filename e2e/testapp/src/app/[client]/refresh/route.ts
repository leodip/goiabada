import * as client from "openid-client";
import { describeError, webConfig } from "@/lib/oidc";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Refresh tokens: trade the refresh token for new tokens. Each refresh hands back a new refresh
// token and retires the old one, so the new one replaces it at once.
export async function POST(_request: Request, ctx: RouteContext<"/[client]/refresh">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  const signIn = state.signIn;
  if (!signIn?.refreshToken) {
    setResult(state, "Refresh failed", false, { error: "This sign-in has no refresh token." });
    return backTo(key);
  }
  try {
    const config = await webConfig(key);
    const tokens = await client.refreshTokenGrant(config, signIn.refreshToken);
    const expiresIn = tokens.expiresIn();
    state.signIn = {
      ...signIn,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? signIn.refreshToken,
      idToken: tokens.id_token ?? signIn.idToken,
      expiresAt: expiresIn === undefined ? undefined : Date.now() + expiresIn * 1000,
    };
    setResult(state, "Refreshed", true, {
      expires_in: expiresIn,
      scope: tokens.scope,
      new_refresh_token: tokens.refresh_token ? "received" : "none",
      new_id_token: tokens.id_token ? "received" : "none",
    });
  } catch (error) {
    setResult(state, "Refresh failed", false, describeError(error));
  }
  return backTo(key);
}
