import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Ends the app's own session and nothing else: the auth server's session stays, so the next
// sign-in goes straight through (single sign-on).
export async function POST(_request: Request, ctx: RouteContext<"/[client]/forget">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  state.signIn = undefined;
  setResult(state, "Forgot this app's session", true, {
    note: "The auth server's session is untouched: signing in again should not ask for a password.",
  });
  return backTo(key);
}
