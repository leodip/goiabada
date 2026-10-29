import * as client from "openid-client";
import { appUrl, webClients } from "@/lib/config";
import { describeError, webConfig } from "@/lib/oidc";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Sign users out, steps 3 and 4: revoke the refresh token at /auth/revoke, or the access token when
// there is none, which ends the whole grant; end the app's own session and forget its tokens; then
// post the ID token as id_token_hint, the post-logout redirect URI and a new state to /auth/logout,
// from a form the page submits on its own. A revocation that fails keeps the user signed in to the
// app, so the failure shows. hint=no leaves the hint out, to try the confirmation page, and
// sends a GET instead: the auth server refuses a cross-origin POST with no hint (Sign-out answers
// 403). With no hint, client_id says whose redirect URIs the post-logout redirect URI is checked
// against; without it the user stays on the auth server's "Signed out" page (Logout, "Where the user
// lands").
export async function POST(request: Request, ctx: RouteContext<"/[client]/logout">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  let endpoint: string | undefined;
  try {
    const config = await webConfig(key);
    endpoint = config.serverMetadata().end_session_endpoint;
    const token = state.signIn?.refreshToken ?? state.signIn?.accessToken;
    if (token) await client.tokenRevocation(config, token);
  } catch (error) {
    setResult(state, "Sign-out failed", false, describeError(error));
    return backTo(key);
  }
  if (!endpoint) {
    setResult(state, "Sign-out failed", false, { error: "The discovery document has no end_session_endpoint." });
    return backTo(key);
  }

  const withHint = (await request.formData()).get("hint") !== "no";
  const idToken = state.signIn?.idToken;
  state.signIn = undefined;
  state.logoutState = client.randomState();

  const fields: Record<string, string> = {
    post_logout_redirect_uri: `${appUrl}/${key}/signed-out`,
    state: state.logoutState,
  };
  if (withHint && idToken) fields.id_token_hint = idToken;
  if (!fields.id_token_hint) {
    fields.client_id = webClients[key].clientId;
    const url = new URL(endpoint);
    for (const [name, value] of Object.entries(fields)) url.searchParams.set(name, value);
    return Response.redirect(url, 303);
  }

  const inputs = Object.entries(fields)
    .map(([name, value]) => `<input type="hidden" name="${name}" value="${escape(value)}">`)
    .join("\n");
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Signing out</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${escape(endpoint)}">
${inputs}
<noscript><button>Continue signing out</button></noscript>
</form>
</body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
}

function escape(value: string) {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
