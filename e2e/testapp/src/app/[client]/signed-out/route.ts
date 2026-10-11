import type { NextRequest } from "next/server";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Sign users out, step 5: the auth server sends the browser back with the state the app sent.
export async function GET(request: NextRequest, ctx: RouteContext<"/[client]/signed-out">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  const returned = request.nextUrl.searchParams.get("state");
  const expected = state.logoutState;
  state.logoutState = undefined;
  const query = Object.fromEntries(request.nextUrl.searchParams);
  if (expected && returned === expected) {
    setResult(state, "Signed out", true, { state: "matches the one sent", query });
  } else {
    setResult(state, "Signed out, but the state doesn't match", false, { expected: expected ?? "(none kept)", query });
  }
  return backTo(key);
}
