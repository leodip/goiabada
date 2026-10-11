import { apiScope, serviceClient } from "@/lib/config";
import { claims } from "@/lib/jwt";
import { readClientState } from "@/lib/session";
import { ResultBox } from "@/app/result-box";

// Protect an API, "Let a service call your API": the client credentials flow, then the API.
export default async function ServicePage() {
  const state = await readClientState("service");
  return (
    <main>
      <h1>Service</h1>
      <p>
        Client <code>{serviceClient.clientId}</code>, which calls the API on its own, with no user. It
        asks the token endpoint for a token with <code>grant_type=client_credentials</code> and{" "}
        <code>scope={apiScope}</code>, then calls the API with it.
      </p>
      <form method="post" action="/service/run">
        <button>Get a token and call the API</button>
      </form>
      <form method="post" action="/service/run">
        <input type="hidden" name="scope" value="" />
        <button>Same, with no scope in the request</button>
      </form>
      <form method="post" action="/service/run">
        <input type="hidden" name="scope" value="openid" />
        <button>Ask for openid (should be refused)</button>
      </form>
      <ResultBox result={state.result} />
      {state.serviceToken ? (
        <>
          <h3>Access token claims</h3>
          <pre>{JSON.stringify(claims(state.serviceToken), null, 2)}</pre>
        </>
      ) : null}
    </main>
  );
}
