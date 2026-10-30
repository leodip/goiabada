"use client";

import { decodeJwt } from "jose";
import * as client from "openid-client";
import { useEffect, useRef, useState } from "react";

type Props = { issuer: string; clientId: string; redirectUri: string; scope: string; apiUrl: string };
type Tokens = { idToken: string; accessToken: string; refreshToken?: string };
type Shown = { title: string; ok: boolean; body: unknown };

// Add sign-in to a SPA or mobile app, in the browser. The state, nonce and PKCE verifier wait in
// sessionStorage while the browser is at the auth server; the tokens live only in memory. The
// redirect URI is this page, which handles the code when the browser comes back, and the
// post-logout redirect URI is this page too.
export function Spa({ issuer, clientId, redirectUri, scope, apiUrl }: Props) {
  const [config, setConfig] = useState<client.Configuration>();
  const [tokens, setTokens] = useState<Tokens>();
  const [shown, setShown] = useState<Shown>();
  const started = useRef(false);

  useEffect(() => {
    // React runs this twice in development; a code can be redeemed once.
    if (started.current) return;
    started.current = true;
    (async () => {
      let found: client.Configuration;
      try {
        found = await client.discovery(new URL(issuer), clientId, undefined, client.None());
        setConfig(found);
      } catch (error) {
        setShown({ title: "Discovery failed in the browser", ok: false, body: describe(error) });
        return;
      }

      const here = new URL(window.location.href);
      const pending = sessionStorage.getItem("spa-pending");
      const logoutState = sessionStorage.getItem("spa-logout-state");
      if (here.searchParams.has("code") || here.searchParams.has("error")) {
        sessionStorage.removeItem("spa-pending");
        window.history.replaceState(null, "", redirectUri);
        if (!pending) {
          setShown({ title: "Sign-in failed", ok: false, body: { error: "No sign-in was in progress in this tab." } });
          return;
        }
        const { state, nonce, codeVerifier } = JSON.parse(pending);
        try {
          const answer = await client.authorizationCodeGrant(found, here, {
            pkceCodeVerifier: codeVerifier,
            expectedState: state,
            expectedNonce: nonce,
            idTokenExpected: true,
          });
          setTokens({ idToken: answer.id_token!, accessToken: answer.access_token, refreshToken: answer.refresh_token });
          setShown({ title: "Signed in", ok: true, body: { scope: answer.scope, expires_in: answer.expiresIn() } });
        } catch (error) {
          setShown({ title: "Sign-in failed", ok: false, body: describe(error) });
        }
      } else if (here.searchParams.has("state") && logoutState) {
        sessionStorage.removeItem("spa-logout-state");
        window.history.replaceState(null, "", redirectUri);
        const matches = here.searchParams.get("state") === logoutState;
        setShown({ title: matches ? "Signed out" : "Signed out, but the state doesn't match", ok: matches, body: {} });
      }
    })();
  }, [issuer, clientId, redirectUri]);

  async function signIn() {
    if (!config) return;
    const state = client.randomState();
    const nonce = client.randomNonce();
    const codeVerifier = client.randomPKCECodeVerifier();
    sessionStorage.setItem("spa-pending", JSON.stringify({ state, nonce, codeVerifier }));
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: redirectUri,
      scope,
      code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: "S256",
      state,
      nonce,
    });
    window.location.assign(url.href);
  }

  async function refresh() {
    if (!config || !tokens?.refreshToken) return;
    try {
      const answer = await client.refreshTokenGrant(config, tokens.refreshToken);
      setTokens({
        idToken: answer.id_token ?? tokens.idToken,
        accessToken: answer.access_token,
        refreshToken: answer.refresh_token ?? tokens.refreshToken,
      });
      setShown({ title: "Refreshed", ok: true, body: { expires_in: answer.expiresIn(), scope: answer.scope } });
    } catch (error) {
      setShown({ title: "Refresh failed", ok: false, body: describe(error) });
    }
  }

  async function userinfo() {
    if (!config || !tokens) return;
    try {
      const sub = String(decodeJwt(tokens.idToken).sub);
      setShown({ title: "/userinfo answered", ok: true, body: await client.fetchUserInfo(config, tokens.accessToken, sub) });
    } catch (error) {
      setShown({ title: "/userinfo failed", ok: false, body: describe(error) });
    }
  }

  async function callApi() {
    if (!tokens) return;
    const response = await fetch(apiUrl, { headers: { authorization: `Bearer ${tokens.accessToken}` } });
    const body = await response.json().catch(() => null);
    setShown({ title: `The API answered ${response.status}`, ok: response.ok, body });
  }

  // Sign users out: revoke the refresh token, or the access token when there is none, with the
  // client_id alone, which ends the whole grant; then post to /auth/logout. A revocation that fails
  // keeps the tokens, so the failure shows.
  async function signOut() {
    const endpoint = config?.serverMetadata().end_session_endpoint;
    if (!config || !endpoint || !tokens) return;
    try {
      await client.tokenRevocation(config, tokens.refreshToken ?? tokens.accessToken);
    } catch (error) {
      setShown({ title: "Revocation failed", ok: false, body: describe(error) });
      return;
    }
    const state = client.randomState();
    sessionStorage.setItem("spa-logout-state", state);
    const form = document.createElement("form");
    form.method = "post";
    form.action = endpoint;
    for (const [name, value] of Object.entries({
      id_token_hint: tokens.idToken,
      post_logout_redirect_uri: redirectUri,
      state,
    })) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    setTokens(undefined);
    document.body.appendChild(form);
    form.submit();
  }

  return (
    <>
      {shown ? (
        <section>
          <h2 className={shown.ok ? "ok" : "bad"}>{shown.title}</h2>
          <pre>{JSON.stringify(shown.body, null, 2)}</pre>
        </section>
      ) : null}
      {!config ? <p>Reading the discovery document…</p> : null}
      {tokens ? (
        <>
          <p>
            Signed in as <code>{String(decodeJwt(tokens.idToken).sub)}</code>. Refresh token:{" "}
            {tokens.refreshToken ? "yes" : "none"}.
          </p>
          <button onClick={refresh}>Refresh the tokens</button> <button onClick={userinfo}>Call /userinfo</button>{" "}
          <button onClick={callApi}>Call the API</button> <button onClick={signOut}>Sign out</button>
          <h3>ID token claims</h3>
          <pre>{JSON.stringify(decodeJwt(tokens.idToken), null, 2)}</pre>
          <h3>Access token claims</h3>
          <pre>{JSON.stringify(decodeJwt(tokens.accessToken), null, 2)}</pre>
        </>
      ) : config ? (
        <button onClick={signIn}>Sign in</button>
      ) : null}
    </>
  );
}

function describe(error: unknown) {
  if (error instanceof client.ResponseBodyError || error instanceof client.AuthorizationResponseError) {
    return { error: error.error, error_description: error.error_description };
  }
  if (error instanceof Error) return { message: error.message, cause: String(error.cause ?? "") };
  return { error: String(error) };
}
