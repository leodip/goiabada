// RFC 9700 sections 2.1 and 4.4, mix-up. A client talking to more than one authorization server must
// tell which one answered, and the defence the BCP prefers is the issuer named in the authorization
// response itself: the iss parameter of RFC 9207, which the server announces with
// authorization_response_iss_parameter_supported, or the iss claim of an ID token in the response.
// The client compares; the server has to send it, in every response, an error included (RFC 9207
// section 2).
import type { APIRequestContext } from "@playwright/test";
import { setImplicitGrant } from "../../lib/admin-console";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { jwtClaims } from "../../lib/oauth";
import { codeRequest, followAuthorize, responseParams } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

async function discovery(request: APIRequestContext) {
  return (await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
}

// The hidden fields of the auto-submitting form_post page.
function formFields(html: string): URLSearchParams {
  const fields = new URLSearchParams();
  for (const [, name, value] of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)) {
    fields.append(name, value.replaceAll("&amp;", "&").replaceAll("&#43;", "+").replaceAll("&#34;", '"').replaceAll("&#39;", "'"));
  }
  return fields;
}

// An implicit request: no PKCE, a nonce for the ID token.
function implicitRequest(clientId: string, responseType: string) {
  return { client_id: clientId, redirect_uri: testRedirectUri, response_type: responseType, scope: "openid", state: "s", nonce: "n" };
}

test("every authorization response names the issuer in iss, an error included, and the metadata says so (section 4.4.2.1, RFC 9207)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const metadata = await discovery(request);
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const answered = async (params: Record<string, string>) => (await followAuthorize(signIn.context.request, params)).redirect!;

  const code = await answered(codeRequest(client.identifier).params);
  const error = await answered(codeRequest(client.identifier, { scope: "openid unknown-resource:read" }).params);
  const fragment = await answered(implicitRequest(client.identifier, "token"));
  const formPost = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { response_mode: "form_post" }).params);
  await signIn.context.close();
  // Each is the response it should be, so a missing iss is the server's and not the test's.
  expect(code.searchParams.get("code")).toBeTruthy();
  expect(error.searchParams.get("error")).toBe("invalid_scope");
  expect(responseParams(fragment).get("access_token")).toBeTruthy();
  expect(formFields(formPost.page!.text).get("code")).toBeTruthy();

  expect({
    advertised: metadata.authorization_response_iss_parameter_supported,
    code: code.searchParams.get("iss"),
    error: error.searchParams.get("iss"),
    fragment: responseParams(fragment).get("iss"),
    formPost: formFields(formPost.page!.text).get("iss"),
  }).toEqual({ advertised: true, code: metadata.issuer, error: metadata.issuer, fragment: metadata.issuer, formPost: metadata.issuer });
});

test("an ID token in the authorization response names the issuer the metadata names (section 4.4.2.1)", async ({ page, browser, clients, users, request }) => {
  const { issuer } = await discovery(request);
  const user = await users.create();
  const { client } = await browserSignInClient(page, clients);
  await setImplicitGrant(page, client.id, "on");
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });

  const { redirect } = await followAuthorize(signIn.context.request, implicitRequest(client.identifier, "id_token"));
  await signIn.context.close();
  const idToken = responseParams(redirect!).get("id_token");
  expect(idToken, redirect?.href).toBeTruthy();
  const claims = jwtClaims(idToken!);
  expect(claims.iss).toBe(issuer);
  expect(claims.aud).toBe(client.identifier);
});
