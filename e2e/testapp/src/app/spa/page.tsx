import { apiUrl, appUrl, defaultScope, issuer, spaClientId } from "@/lib/config";
import { Spa } from "./spa";

// Read at request time, so the image carries no configuration of its own.
export const dynamic = "force-dynamic";

// Add sign-in to a SPA or mobile app. Everything happens in the browser: see spa.tsx.
export default function SpaPage() {
  return (
    <main>
      <h1>SPA</h1>
      <p>
        Client <code>{spaClientId}</code>, a public client: it runs in the browser, has no secret, and
        keeps its tokens in memory, so reloading the page forgets them.
      </p>
      <Spa issuer={issuer} clientId={spaClientId} redirectUri={`${appUrl}/spa`} scope={defaultScope} apiUrl={apiUrl} />
    </main>
  );
}
