import { randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { appUrl } from "./config";

// The app's own sessions, kept in memory: a restart signs everyone out of the app, which is fine
// for a test app. The browser holds only a random id in a cookie.

export type Pending = {
  state: string;
  nonce: string;
  codeVerifier: string;
  startedAt: number;
};

export type SignIn = {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  signedInAt: number;
};

export type Result = {
  title: string;
  ok: boolean;
  body: unknown;
  at: number;
};

// One entry per client: "web", "web2", "service".
export type ClientState = {
  pending?: Pending;
  signIn?: SignIn;
  // The sub of the last sign-in, kept after it ends, so the page can show the logout tokens about
  // that user.
  subject?: string;
  logoutState?: string;
  result?: Result;
  serviceToken?: string;
};

type Session = Record<string, ClientState>;

const cookieName = "testapp_session";

const globalStore = globalThis as unknown as { testappSessions?: Map<string, Session> };
const store = (globalStore.testappSessions ??= new Map<string, Session>());

// For pages: the session if there is one. Pages can't set cookies, so they never create one.
export async function readClientState(key: string): Promise<ClientState> {
  const id = (await cookies()).get(cookieName)?.value;
  return (id && store.get(id)?.[key]) || {};
}

// For route handlers: the session, created with its cookie when there isn't one yet.
export async function clientState(key: string): Promise<ClientState> {
  const jar = await cookies();
  let id = jar.get(cookieName)?.value;
  if (!id || !store.has(id)) {
    id = randomBytes(32).toString("base64url");
    store.set(id, {});
    jar.set(cookieName, id, {
      httpOnly: true,
      sameSite: "lax",
      secure: appUrl.startsWith("https://"),
      path: "/",
    });
  }
  const session = store.get(id)!;
  return (session[key] ??= {});
}

export function setResult(state: ClientState, title: string, ok: boolean, body: unknown) {
  state.result = { title, ok, body, at: Date.now() };
}

// For the back-channel logout route, which no browser calls: ends this client's sign-ins that
// matches picks, in every browser's session, with result as each one's outcome, and answers the sub
// of each sign-in ended.
export function endSignIns(key: string, matches: (signIn: SignIn) => boolean, result: Omit<Result, "at">): string[] {
  const ended: string[] = [];
  for (const session of store.values()) {
    const state = session[key];
    if (!state?.signIn || !matches(state.signIn)) continue;
    state.signIn = undefined;
    state.result = { ...result, at: Date.now() };
    if (state.subject) ended.push(state.subject);
  }
  return ended;
}

// The logout tokens the client accepted, by user, for its page: the newest ten for each user, kept
// for an hour.
type Received = { claims: Record<string, unknown>; at: number };

const globalReceived = globalThis as unknown as { testappLogoutTokens?: Map<string, Received[]> };
const received = (globalReceived.testappLogoutTokens ??= new Map<string, Received[]>());
const keptFor = 60 * 60 * 1000;

export function recordLogoutToken(key: string, subject: string, claims: Record<string, unknown>) {
  const now = Date.now();
  for (const [name, list] of received) {
    if (now - list[list.length - 1].at > keptFor) received.delete(name);
  }
  const name = `${key} ${subject}`;
  const list = received.get(name) ?? [];
  list.push({ claims, at: now });
  received.set(name, list.slice(-10));
}

export function logoutTokensAbout(key: string, subject: string | undefined): Record<string, unknown>[] {
  if (!subject) return [];
  return (received.get(`${key} ${subject}`) ?? []).map((entry) => entry.claims);
}
