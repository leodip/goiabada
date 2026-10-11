import { NextResponse } from "next/server";
import * as client from "openid-client";
import { apiScope, appUrl } from "@/lib/config";
import { callApi } from "@/lib/call-api";
import { describeError, serviceConfig } from "@/lib/oidc";
import { clientState, setResult } from "@/lib/session";

// Protect an API, steps 3 to 5 of "Let a service call your API". The form chooses the scope:
// the API's permission by default, none at all, or openid, which the docs say is refused.
export async function POST(request: Request) {
  const state = await clientState("service");
  const form = await request.formData();
  const scope = form.has("scope") ? String(form.get("scope")) : apiScope;
  state.serviceToken = undefined;

  try {
    const config = await serviceConfig();
    const tokens = await client.clientCredentialsGrant(config, scope ? { scope } : {});
    state.serviceToken = tokens.access_token;
    const answer = await callApi(tokens.access_token);
    setResult(state, `Got a token; the API answered ${answer.status}`, answer.status === 200, {
      asked_for_scope: scope || "(none sent)",
      token_response: { token_type: tokens.token_type, expires_in: tokens.expiresIn(), scope: tokens.scope },
      api: answer,
    });
  } catch (error) {
    setResult(state, "The token request failed", false, { asked_for_scope: scope || "(none sent)", ...describeError(error) });
  }
  return NextResponse.redirect(`${appUrl}/service`, 303);
}
