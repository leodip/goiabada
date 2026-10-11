import * as client from "openid-client";
import { claims } from "@/lib/jwt";
import { describeError, webConfig } from "@/lib/oidc";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// /userinfo with the access token. It answers while the session the token came from is valid,
// which is what Protect an API suggests checking before an operation that must stop at once.
export async function POST(_request: Request, ctx: RouteContext<"/[client]/userinfo">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  const signIn = state.signIn;
  if (!signIn) {
    setResult(state, "/userinfo failed", false, { error: "Not signed in." });
    return backTo(key);
  }
  try {
    const config = await webConfig(key);
    const sub = String(claims(signIn.idToken)?.sub);
    const info = await client.fetchUserInfo(config, signIn.accessToken, sub);
    setResult(state, "/userinfo answered", true, info);
  } catch (error) {
    setResult(state, "/userinfo failed", false, describeError(error));
  }
  return backTo(key);
}
