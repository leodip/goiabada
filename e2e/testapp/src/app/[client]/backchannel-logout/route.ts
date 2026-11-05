import { webClients, isWebClientKey } from "@/lib/config";
import { claims } from "@/lib/jwt";
import { LogoutTokenError, validateLogoutToken } from "@/lib/logout-token";
import { signingKeys, webConfig } from "@/lib/oidc";
import { endSignIns, recordLogoutToken } from "@/lib/session";

// Sign users out, "Get told when a session ends": the client's back-channel logout URI. The auth
// server POSTs a logout token here, server to server, when a session the app was on ends. Step 1:
// read logout_token from the form body. Step 2: check it (src/lib/logout-token.ts). Step 3: end the
// app's sessions it names, by sid when it has one, else every session of its sub. Step 4: answer 200,
// or 400 for a token that fails a check, both with Cache-Control: no-store.
export async function POST(request: Request, ctx: RouteContext<"/[client]/backchannel-logout">) {
  const { client: key } = await ctx.params;
  if (!isWebClientKey(key)) return new Response("Unknown client", { status: 404 });

  let token: FormDataEntryValue | null = null;
  try {
    token = (await request.formData()).get("logout_token");
  } catch {}
  if (typeof token !== "string" || !token) return refuse("The body has no logout_token.");

  let logout;
  try {
    const config = await webConfig(key);
    logout = await validateLogoutToken(token, {
      issuer: config.serverMetadata().issuer,
      audience: webClients[key].clientId,
      keys: signingKeys(config),
    });
  } catch (error) {
    if (error instanceof LogoutTokenError) return refuse(error.message);
    return refuse(`The token could not be checked: ${error instanceof Error ? error.message : String(error)}`);
  }

  const { sub, sid } = logout;
  const ended = endSignIns(
    key,
    (signIn) => {
      const idToken = claims(signIn.idToken);
      if (sid) return idToken?.sid === sid && (!sub || idToken?.sub === sub);
      return idToken?.sub === sub;
    },
    { title: "Signed out by the auth server", ok: true, body: { sub, sid: sid ?? "(none: every session of the user)", jti: logout.jti } },
  );
  // A token about a user the app has no session for is a success too: there's nothing left to end.
  for (const subject of new Set(sub ? [sub] : ended)) recordLogoutToken(key, subject, logout);
  return new Response(null, { status: 200, headers: { "cache-control": "no-store" } });
}

function refuse(description: string) {
  return Response.json(
    { error: "invalid_request", error_description: description },
    { status: 400, headers: { "cache-control": "no-store" } },
  );
}
