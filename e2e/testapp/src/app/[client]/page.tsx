import { notFound } from "next/navigation";
import { defaultScope, isWebClientKey, webClients } from "@/lib/config";
import { claims, shorten } from "@/lib/jwt";
import { readClientState } from "@/lib/session";
import { ResultBox } from "@/app/result-box";

// A confidential web app: Add sign-in to a web app, Sign users out, Require two-factor
// authentication, and Single sign-on across clients, with the second web app.
export default async function WebAppPage({ params }: PageProps<"/[client]">) {
  const { client: key } = await params;
  if (!isWebClientKey(key)) notFound();
  const { title, clientId } = webClients[key];
  const state = await readClientState(key);
  const signIn = state.signIn;
  const idClaims = claims(signIn?.idToken);
  const accessClaims = claims(signIn?.accessToken);
  const amr = Array.isArray(idClaims?.amr) ? (idClaims.amr as string[]) : [];

  return (
    <main>
      <h1>{title}</h1>
      <p>
        Client <code>{clientId}</code>, a confidential client: it signs users in on the server, with
        its secret.
      </p>

      <ResultBox result={state.result} />

      {signIn ? (
        <>
          <h2>Signed in</h2>
          <p>
            As <code>{String(idClaims?.sub)}</code>
            {idClaims?.email ? <> ({String(idClaims.email)})</> : null}.
          </p>
          <p>
            acr <code>{String(idClaims?.acr)}</code>, amr <code>{JSON.stringify(amr)}</code>. Entered a
            one-time code:{" "}
            {amr.includes("otp") ? <span className="ok">yes</span> : <span className="bad">no</span>}
          </p>
          <p>
            Access token {shorten(signIn.accessToken)}, expires{" "}
            {signIn.expiresAt ? new Date(signIn.expiresAt).toLocaleTimeString() : "(unknown)"}. Refresh
            token: {signIn.refreshToken ? "yes" : "none"}.
          </p>

          <form method="post" action={`/${key}/refresh`}>
            <button>Refresh the tokens</button>
          </form>
          <form method="post" action={`/${key}/userinfo`}>
            <button>Call /userinfo</button>
          </form>
          <form method="post" action={`/${key}/call-api`}>
            <button>Call the API</button>
          </form>
          <form method="post" action={`/${key}/logout`}>
            <input type="hidden" name="hint" value="yes" />
            <button>Sign out</button>
          </form>
          <form method="post" action={`/${key}/forget`}>
            <button>Forget this app&apos;s session only</button>
          </form>

          <h3>ID token claims</h3>
          <pre>{JSON.stringify(idClaims, null, 2)}</pre>
          <h3>Access token claims</h3>
          <pre>{JSON.stringify(accessClaims, null, 2)}</pre>
        </>
      ) : (
        <p>Not signed in to this app.</p>
      )}

      <h2>Sign in</h2>
      <form method="get" action={`/${key}/login`}>
        <fieldset>
          <label>
            scope <input name="scope" defaultValue={defaultScope} size={50} />
          </label>
          <label>
            prompt{" "}
            <select name="prompt" defaultValue="">
              <option value="">(none sent)</option>
              <option value="none">none</option>
              <option value="login">login</option>
              <option value="consent">consent</option>
            </select>
          </label>
          <label>
            acr_values{" "}
            <select name="acr_values" defaultValue="">
              <option value="">(none sent: the client&apos;s default level)</option>
              <option value="urn:goiabada:level1">urn:goiabada:level1</option>
              <option value="urn:goiabada:level2_optional">urn:goiabada:level2_optional</option>
              <option value="urn:goiabada:level2_mandatory">urn:goiabada:level2_mandatory</option>
            </select>
          </label>
          <label>
            max_age <input name="max_age" type="number" min={0} placeholder="seconds" />
          </label>
          {signIn ? (
            <label>
              <input type="checkbox" name="id_token_hint" value="yes" /> send my ID token as{" "}
              <code>id_token_hint</code>
            </label>
          ) : null}
          <button>Sign in</button>
        </fieldset>
      </form>

      <h2>Sign out without a hint</h2>
      <p>The auth server asks &quot;Are you sure?&quot;, then ends the whole session, every app&apos;s part.</p>
      <form method="post" action={`/${key}/logout`}>
        <input type="hidden" name="hint" value="no" />
        <button>Sign out with no id_token_hint</button>
      </form>
    </main>
  );
}
