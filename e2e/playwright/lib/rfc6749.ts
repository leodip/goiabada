// Raw requests for the RFC 6749 conformance tests (tests/rfc6749/), and the answer shapes the RFC
// requires. A body given as a string goes out byte for byte, so a test can repeat a parameter or send
// one empty, which the helpers in oauth.ts never do.
import { createHash, randomBytes } from "node:crypto";
import { expect, type APIRequestContext, type Browser } from "@playwright/test";
import { admitted, answerOf } from "./admission";
import { testRedirectUri } from "./browser-sign-in";
import { env } from "./environment";

export const tokenEndpoint = `${env.authUrl}/auth/token`;
export const authorizeEndpoint = `${env.authUrl}/auth/authorize`;

export interface RawAnswer {
  status: number;
  headers: Record<string, string>;
  // The JSON body, or {} when the body is not JSON.
  body: Record<string, unknown>;
  text: string;
}

// The characters section 5.2 allows in error and error_description (NQSCHAR), and in error_uri.
const errorChars = /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/;
const errorUriChars = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

// The Authorization header of client_secret_basic: both values form-urlencoded, then base64
// (section 2.3.1).
export function basicAuth(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString("base64")}`;
}

// Posts to the token endpoint. Pairs are form-encoded as a client would encode them; a string is sent
// as it is, under the form content type unless the headers name another.
export async function postToken(
  request: APIRequestContext,
  body: string | Record<string, string>,
  { headers = {}, query = "" }: { headers?: Record<string, string>; query?: string } = {},
): Promise<RawAnswer> {
  const response = await request.post(`${tokenEndpoint}${query}`, {
    data: typeof body === "string" ? body : new URLSearchParams(body).toString(),
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    failOnStatusCode: false,
    maxRedirects: 0,
  });
  return readAnswer(response);
}

export async function readAnswer(response: import("@playwright/test").APIResponse): Promise<RawAnswer> {
  const text = await response.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON: the assertions on the body say so.
  }
  return { status: response.status(), headers: response.headers(), body, text };
}

// Section 5.1 MUST: a response carrying tokens or credentials is never cached.
export function expectNoStore(answer: RawAnswer) {
  expect(answer.headers["cache-control"], "Cache-Control").toMatch(/\bno-store\b/);
  expect(answer.headers["pragma"], "Pragma").toMatch(/\bno-cache\b/);
}

// Section 5.1: 200, JSON, an access token of a type the client understands (compared ignoring case),
// its lifetime as a JSON number, and nothing cached.
export function expectTokenResponse(answer: RawAnswer) {
  expect(answer.status, answer.text).toBe(200);
  expect(answer.headers["content-type"]).toMatch(/^application\/json\b/);
  expect(typeof answer.body.access_token, answer.text).toBe("string");
  expect(String(answer.body.token_type).toLowerCase()).toBe("bearer");
  expect(typeof answer.body.expires_in, "expires_in is a JSON number").toBe("number");
  expectNoStore(answer);
}

// Section 5.2: the status, a JSON body whose error is this code (or one of these), error,
// error_description and error_uri within the characters the RFC allows, no token, and nothing cached.
export function expectTokenError(answer: RawAnswer, error: string | string[], status = 400) {
  expect(answer.status, answer.text).toBe(status);
  expect(answer.headers["content-type"]).toMatch(/^application\/json\b/);
  expect([error].flat().includes(String(answer.body.error)), `error is ${[error].flat().join(" or ")}: ${answer.text}`).toBe(true);
  expect(answer.body.error).toMatch(errorChars);
  if (answer.body.error_description !== undefined) expect(answer.body.error_description).toMatch(errorChars);
  if (answer.body.error_uri !== undefined) expect(answer.body.error_uri).toMatch(errorUriChars);
  expect(answer.body.access_token).toBeUndefined();
  expectNoStore(answer);
}

// Section 5.2's invalid_client: 401 with a challenge of the client's own scheme when it authenticated
// through the Authorization header (MUST); otherwise 400, or 401 with a challenge (MAY).
export function expectInvalidClient(answer: RawAnswer, { viaBasic }: { viaBasic: boolean }) {
  if (viaBasic || answer.status === 401) {
    expectTokenError(answer, "invalid_client", 401);
    expect(answer.headers["www-authenticate"], "WWW-Authenticate").toMatch(viaBasic ? /^Basic\b/i : /\S/);
  } else {
    expectTokenError(answer, "invalid_client", 400);
  }
}

// A browser with no cookies at all, so nothing in it is signed in: inside a test, browser.newContext()
// starts from the test's options, which carry the administrator's session. Its .request makes raw
// requests from the same cookie jar. The caller closes it.
export function emptyBrowser(browser: Browser) {
  return browser.newContext({ storageState: { cookies: [], origins: [] } });
}

// An authorization code request for clientId: the tests' redirect URI, scope openid, a fresh state and
// a PKCE challenge, which the auth server requires as seeded. An override replaces a parameter, or
// removes it when undefined. The verifier redeems the code.
export function codeRequest(clientId: string, overrides: Record<string, string | undefined> = {}) {
  const verifier = randomBytes(32).toString("base64url");
  const params: Record<string, string | undefined> = {
    client_id: clientId,
    redirect_uri: testRedirectUri,
    response_type: "code",
    scope: "openid",
    state: randomBytes(8).toString("hex"),
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    ...overrides,
  };
  const defined = Object.entries(params).filter((pair): pair is [string, string] => pair[1] !== undefined);
  return { params: Object.fromEntries(defined), verifier };
}

// An authorization request's parameters: pairs, so that one can be sent twice, or a record.
export type AuthorizeParams = Record<string, string> | [string, string][];

// One GET of the authorization endpoint, its redirect not followed, asked again while the admission
// budget refuses it.
export async function getAuthorize(api: APIRequestContext, params: AuthorizeParams): Promise<RawAnswer> {
  const url = `${authorizeEndpoint}?${new URLSearchParams(params)}`;
  const response = await admitted(() => api.get(url, { failOnStatusCode: false, maxRedirects: 0 }), answerOf);
  return readAnswer(response);
}

export interface AuthorizeOutcome {
  // Where the auth server sent the browser off its own origin: the client's redirect URI, and the
  // headers of the response that sent it there.
  redirect?: URL;
  redirectHeaders?: Record<string, string>;
  // Otherwise the page it stopped at, the password form or a refusal, and that page's address.
  page?: RawAnswer;
  pageUrl?: string;
}

// An authorization request followed through the auth server's own redirects, as a browser would, up
// to the first redirect off the auth server or the first page. Through a signed-in browser's .request
// it rides the session, so a request needing no password and no consent comes back with the answer.
export async function followAuthorize(api: APIRequestContext, params: AuthorizeParams): Promise<AuthorizeOutcome> {
  return followFrom(api, `${authorizeEndpoint}?${new URLSearchParams(params)}`);
}

// The same from any address on the auth server, such as the GET a POST to the authorization endpoint
// redirects to. A hop to the authorization endpoint is asked again while the admission budget refuses
// it.
export async function followFrom(api: APIRequestContext, start: string): Promise<AuthorizeOutcome> {
  let url = start;
  for (let hop = 0; hop < 10; hop++) {
    const get = () => api.get(url, { failOnStatusCode: false, maxRedirects: 0 });
    const response = new URL(url).pathname === "/auth/authorize" ? await admitted(get, answerOf) : await get();
    const location = response.headers()["location"];
    if (response.status() >= 300 && response.status() < 400 && location) {
      const next = new URL(location, url);
      if (next.origin !== new URL(env.authUrl).origin) return { redirect: next, redirectHeaders: response.headers() };
      url = next.href;
      continue;
    }
    return { page: await readAnswer(response), pageUrl: url };
  }
  throw new Error(`more than 10 redirects from ${authorizeEndpoint}`);
}

// The parameters of an authorization response: the query, or the fragment when there is one.
export function responseParams(url: URL): URLSearchParams {
  return url.hash.length > 1 ? new URLSearchParams(url.hash.slice(1)) : url.searchParams;
}

// Section 4.1.2.1: an error response's error, error_description and error_uri within the characters
// the RFC allows, and the state exactly as sent (none when none was).
export function expectAuthorizeError(url: URL, error: string, state: string | undefined) {
  const params = responseParams(url);
  expect(params.get("error"), url.href).toBe(error);
  expect(params.get("error")).toMatch(errorChars);
  if (params.has("error_description")) expect(params.get("error_description")).toMatch(errorChars);
  if (params.has("error_uri")) expect(params.get("error_uri")).toMatch(errorUriChars);
  expect(params.get("state")).toBe(state ?? null);
  expect(params.has("code")).toBe(false);
}

// Sections 3.1.2.4 and 4.1.2.1: a request the auth server must not redirect is answered on its own
// page, with no Location to follow.
export function expectRefusedOnPage(answer: RawAnswer, message: string | RegExp) {
  expect([200, 400], `answered on the page, not redirected: ${answer.status} ${answer.headers["location"] ?? ""}`).toContain(answer.status);
  expect(answer.headers["location"]).toBeUndefined();
  expect(answer.text).toContain("Unable to authorize");
  expect(answer.text).toMatch(message);
}
