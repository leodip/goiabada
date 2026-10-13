// RFC 6749 sections 1.6, 3.1, 3.2 and 10.9 require TLS at the authorization and token endpoints and on
// every page a user sees; RFC 8996 retires TLS 1.0 and 1.1. TLS is the reverse proxy's, set up as the
// docs' Reverse proxy page describes, so these check the documented deployment as much as the server.
// Section 5.1's no-store reaches every response carrying a credential, the admin API's included.
import { connect } from "node:tls";
import { grantClientPermission, readClientSecret } from "../../lib/admin-console";
import { env } from "../../lib/environment";
import { expect, test } from "../../lib/fixtures";
import { basicAuth, codeRequest, expectNoStore, readAnswer } from "../../lib/rfc6749";

const authHost = new URL(env.authUrl).hostname;
const plainHttp = (path: string) => `http://${authHost}${path}`;

test("over plain HTTP the endpoints only redirect to HTTPS, and nothing is issued", async ({ page, clients, request }) => {
  const client = await clients.create({ authorizationCode: false, clientCredentials: true });
  await grantClientPermission(page, client.id, "authserver", "manage-account");
  const secret = await readClientSecret(page, client.id);

  const authorize = await request.get(plainHttp(`/auth/authorize?${new URLSearchParams(codeRequest(client.identifier).params)}`), {
    failOnStatusCode: false,
    maxRedirects: 0,
  });
  expect([301, 302, 307, 308]).toContain(authorize.status());
  expect(authorize.headers()["location"]).toMatch(new RegExp(`^https://${authHost}/auth/authorize\\?`));

  const token = await readAnswer(
    await request.post(plainHttp("/auth/token"), {
      form: { grant_type: "client_credentials", scope: "authserver:manage-account" },
      headers: { Authorization: basicAuth(client.identifier, secret) },
      failOnStatusCode: false,
      maxRedirects: 0,
    }),
  );
  expect([301, 302, 307, 308]).toContain(token.status);
  expect(token.text).not.toContain("access_token");
});

// The protocol a TLS handshake with the auth server settles on when the client offers only version, or
// the error it ends in. The client's own floor is lowered so that it can offer TLS 1.0 and 1.1 at all,
// leaving any refusal to the server.
function handshake(version: "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect({ host: authHost, port: 443, servername: authHost, minVersion: version, maxVersion: version, ciphers: "DEFAULT@SECLEVEL=0" }, () => {
      resolve(socket.getProtocol() ?? "none");
      socket.end();
    });
    socket.on("error", (error: NodeJS.ErrnoException) => resolve(`error ${error.code ?? error.message}`));
  });
}

test("TLS 1.2 and 1.3 are accepted, TLS 1.0 and 1.1 refused (RFC 8996)", async () => {
  expect(await handshake("TLSv1.2")).toBe("TLSv1.2");
  expect(await handshake("TLSv1.3")).toBe("TLSv1.3");
  for (const retired of ["TLSv1", "TLSv1.1"] as const) {
    // Refused by the server's protocol_version alert, not by this client failing to offer it.
    expect(await handshake(retired), `${retired} refused`).toBe("error ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION");
  }
});

test("the admin API, which returns client secrets, is never cached, its refusals included (section 5.1)", async ({ request }) => {
  const refused = await readAnswer(await request.get(`${env.authUrl}/api/v1/admin/clients/1/secret`, { failOnStatusCode: false }));
  expect(refused.status).toBe(401);
  expectNoStore(refused);
});
