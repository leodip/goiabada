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

// The two web apps are confidential clients: they sign users in on the server, with a secret.
// The second one exists to try single sign-on across clients.
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

export const defaultScope = `openid email profile ${apiScope}`;
