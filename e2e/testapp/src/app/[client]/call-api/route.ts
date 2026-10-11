import { callApi } from "@/lib/call-api";
import { setResult } from "@/lib/session";
import { backTo, webRoute } from "@/lib/web-route";

// Step 5 of Protect an API: send the access token to the API in the Authorization header.
export async function POST(_request: Request, ctx: RouteContext<"/[client]/call-api">) {
  const route = await webRoute(ctx.params);
  if ("notFound" in route) return route.notFound;
  const { key, state } = route;

  if (!state.signIn) {
    setResult(state, "API call failed", false, { error: "Not signed in." });
    return backTo(key);
  }
  const answer = await callApi(state.signIn.accessToken);
  setResult(state, `The API answered ${answer.status}`, answer.status === 200, answer);
  return backTo(key);
}
