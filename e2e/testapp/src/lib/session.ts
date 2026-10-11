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
