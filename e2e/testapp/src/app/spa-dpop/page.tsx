import { apiUrl, appUrl, defaultScope, issuer, spaDpopClientId } from "@/lib/config";
import { Spa } from "../spa/spa";

// Read at request time, so the image carries no configuration of its own.
export const dynamic = "force-dynamic";

// Add sign-in to a SPA or mobile app, "Bind the tokens to a key with DPoP". Everything happens in
// the browser: see ../spa/spa.tsx.
export default function SpaDpopPage() {
  return (
    <main>
      <h1>SPA with DPoP</h1>
      <p>
        Client <code>{spaDpopClientId}</code>, a public client that requires DPoP for token requests: its
        tokens are bound to a key the browser keeps, so a copied token is useless without it. Reloading the
        page forgets the tokens.
      </p>
      <Spa issuer={issuer} clientId={spaDpopClientId} redirectUri={`${appUrl}/spa-dpop`} scope={defaultScope} apiUrl={apiUrl} dpop />
    </main>
  );
}
