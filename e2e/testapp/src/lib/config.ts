// Everything the app needs to know, read from the environment once. See .env.example. A missing
// value doesn't stop the app: the home page lists it, and whatever needs it fails visibly.

export const missing: string[] = [];

function env(name: string, fallback?: string): string {
  const value = process.env[name] || fallback;
  if (!value) missing.push(name);
  return value ?? "";
}

export const issuer = env("GOIABADA_ISSUER");
export const appUrl = env("APP_URL").replace(/\/$/, "");

// The web apps are confidential clients: they sign users in on the server, with a secret. The
// second one exists to try single sign-on across clients. The third registered no back-channel logout
// URI, so it keeps its tokens when the user's session ends, as an app does before it's told or when a
// delivery is lost.
export const webClients = {
  web: {
    title: "Web app",
    clientId: env("WEB_CLIENT_ID", "testapp-web"),
    clientSecret: env("WEB_CLIENT_SECRET"),
  },
  web2: {
    title: "Second web app",
    clientId: env("WEB2_CLIENT_ID", "testapp-web2"),
    clientSecret: env("WEB2_CLIENT_SECRET"),
  },
  web3: {
    title: "Web app with no back-channel logout",
    clientId: env("WEB3_CLIENT_ID", "testapp-web3"),
    clientSecret: env("WEB3_CLIENT_SECRET"),
  },
} as const;

export type WebClientKey = keyof typeof webClients;

export function isWebClientKey(key: string): key is WebClientKey {
  return key in webClients;
}

// The SPA is a public client: it runs in the browser, with no secret.
export const spaClientId = env("SPA_CLIENT_ID", "testapp-spa");

// The service calls the API on its own, with the client credentials flow.
export const serviceClient = {
  clientId: env("SERVICE_CLIENT_ID", "testapp-service"),
  clientSecret: env("SERVICE_CLIENT_SECRET"),
};

// The API this app protects: a resource in Goiabada, and the permission it checks.
export const apiResource = env("API_RESOURCE", "product-api");
export const apiScope = env("API_SCOPE", "product-api:read");
export const apiUrl = `${appUrl}/api/products`;

// The API's own confidential client, listed for the API's resource on its Introspection tab, with
// which the API asks the auth server whether each token is still active.
export const apiClient = {
  clientId: env("API_CLIENT_ID", "testapp-api"),
  clientSecret: env("API_CLIENT_SECRET"),
};

export const defaultScope = `openid email profile ${apiScope}`;
