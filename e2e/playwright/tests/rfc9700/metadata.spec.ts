// RFC 9700 section 2.6: authorization servers are RECOMMENDED to publish OAuth Authorization Server
// Metadata (RFC 8414), so that clients configure themselves from it rather than by hand, which is
// where misconfigured endpoints and missing security features come from. Goiabada publishes OpenID
// Connect Discovery's document at both its address and RFC 8414's; these check that it is right and
// that the two addresses serve it alike. Dynamic
// registration choosing no client_id (4.15.1) is in client-registration.system.ts. Asymmetric client
// authentication (2.5) is not implemented, and not tested.
import type { APIRequestContext } from "@playwright/test";
import { signInThroughClient, testRedirectUri } from "../../lib/browser-sign-in";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { codeToken, jwtClaims } from "../../lib/oauth";
import { codeRequest, followAuthorize } from "../../lib/rfc6749";
import { browserSignInClient } from "../../lib/test-clients";

const authOrigin = new URL(env.authUrl).origin;

async function discovery(request: APIRequestContext) {
  return (await (await request.get(`${env.authUrl}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
}

test("the RFC 8414 metadata is published at /.well-known/oauth-authorization-server (section 2.6 RECOMMENDED)", async ({ request }) => {
  const address = `${env.authUrl}/.well-known/oauth-authorization-server`;
  const oidc = await discovery(request);
  const response = await request.get(address, { failOnStatusCode: false });
  expect(response.status()).toBe(200);
  // The whole document is the OpenID Connect one, so the two addresses cannot disagree.
  expect(await response.json()).toEqual(oidc);

  await test.step("HEAD answers as GET does", async () => {
    const head = await request.head(address, { failOnStatusCode: false });
    expect(head.status()).toBe(200);
    expect(head.headers()["content-type"]).toBe(response.headers()["content-type"]);
  });

  await test.step("a script on another origin may read it", async () => {
    // A browser-based client, an MCP client among them, fetches the metadata cross-origin.
    const origin = "https://metadata-reader.example";
    const crossOrigin = await request.get(address, { headers: { Origin: origin }, failOnStatusCode: false });
    expect(crossOrigin.status()).toBe(200);
    expect(crossOrigin.headers()["access-control-allow-origin"]).toBe(origin);
  });
});

test("the discovery document matches the server: its issuer, its endpoints, and the response modes it lists (section 2.6)", async ({
  page,
  browser,
  clients,
  users,
  request,
}) => {
  const metadata = await discovery(request);
  // OpenID Connect Discovery 4.3: the issuer is the address the document is published under.
  expect(metadata.issuer).toBe(env.authUrl);
  expect(metadata.token_endpoint_auth_methods_supported).toEqual(["client_secret_post", "client_secret_basic", "none"]);
  expect(metadata.revocation_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post", "none"]);

  for (const field of ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "end_session_endpoint", "revocation_endpoint"]) {
    await test.step(field, async () => {
      const url = String(metadata[field]);
      expect(new URL(url).origin).toBe(authOrigin);
      const answer = await request.get(url, { failOnStatusCode: false, maxRedirects: 0 });
      expect(answer.status(), `${url} answered ${answer.status()}`).not.toBe(404);
      expect(answer.status()).toBeLessThan(500);
    });
  }
  const keys = (await (await request.get(String(metadata.jwks_uri))).json()).keys as unknown[];
  expect(keys.length).toBeGreaterThan(0);

  const user = await users.create();
  const { client, secret } = await browserSignInClient(page, clients);
  const signIn = await signInThroughClient(browser, { clientId: client.identifier, email: user.email, password: user.password, scope: "openid" });
  const tokens = await codeToken(request, client.identifier, secret, signIn.code, signIn.codeVerifier, testRedirectUri);
  expect(jwtClaims(tokens.body.id_token as string).iss).toBe(metadata.issuer);

  // Each response mode it lists delivers a code the way it says.
  const delivered: Record<string, boolean> = {};
  for (const mode of metadata.response_modes_supported as string[]) {
    const outcome = await followAuthorize(signIn.context.request, codeRequest(client.identifier, { response_mode: mode }).params);
    delivered[mode] =
      mode === "query"
        ? Boolean(outcome.redirect?.searchParams.get("code"))
        : mode === "fragment"
          ? new URLSearchParams(outcome.redirect?.hash.slice(1) ?? "").has("code")
          : /<input type="hidden" name="code" value="[^"]+"/.test(outcome.page?.text ?? "");
  }
  expect(delivered).toEqual({ query: true, fragment: true, form_post: true });
  await signIn.context.close();
});
