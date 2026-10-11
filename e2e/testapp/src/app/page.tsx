import { issuer, missing } from "@/lib/config";

// Read at request time, so the image carries no configuration of its own.
export const dynamic = "force-dynamic";

const docs = "https://goiabada.dev";

export default function Home() {
  return (
    <main>
      <h1>Goiabada test app</h1>
      <p>
        Each page follows one guide of the docs, against <a href={issuer}>{issuer}</a>.
      </p>
      {missing.length ? (
        <p className="bad">
          Not configured yet: {missing.join(", ")}. See <code>.env.example</code>.
        </p>
      ) : null}
      <ul>
        <li>
          <a href="/web">Web app</a>: a confidential client.{" "}
          <a href={`${docs}/guides/add-sign-in-to-a-web-app/`}>Add sign-in to a web app</a>,{" "}
          <a href={`${docs}/guides/sign-users-out/`}>Sign users out</a>,{" "}
          <a href={`${docs}/guides/require-two-factor-authentication/`}>Require two-factor authentication</a>
        </li>
        <li>
          <a href="/web2">Second web app</a>: another confidential client.{" "}
          <a href={`${docs}/guides/single-sign-on-across-clients/`}>Single sign-on across clients</a>
        </li>
        <li>
          <a href="/spa">SPA</a>: a public client, in the browser.{" "}
          <a href={`${docs}/guides/add-sign-in-to-a-spa-or-mobile-app/`}>Add sign-in to a SPA or mobile app</a>
        </li>
        <li>
          <a href="/service">Service</a>: the client credentials flow.{" "}
          <a href={`${docs}/guides/protect-an-api/`}>Protect an API</a>
        </li>
        <li>
          <a href="/api/products">The API</a>: answers only a token carrying its permission.
        </li>
      </ul>
    </main>
  );
}
