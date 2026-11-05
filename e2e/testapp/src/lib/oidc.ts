import { createRemoteJWKSet, type JWTVerifyGetKey } from "jose";
import * as client from "openid-client";
import { issuer, serviceClient, webClients, type WebClientKey } from "./config";

// One openid-client Configuration per client, from the auth server's discovery document. The
// secret goes in an Authorization: Basic header, as the guides' curl examples send it.

const globalCache = globalThis as unknown as { testappConfigs?: Map<string, Promise<client.Configuration>> };
const cache = (globalCache.testappConfigs ??= new Map<string, Promise<client.Configuration>>());

function discover(clientId: string, clientSecret: string): Promise<client.Configuration> {
  let config = cache.get(clientId);
  if (!config) {
    config = client.discovery(new URL(issuer), clientId, undefined, client.ClientSecretBasic(clientSecret));
    // A failed discovery isn't kept, so the next request tries again.
    config.catch(() => cache.delete(clientId));
    cache.set(clientId, config);
  }
  return config;
}

export function webConfig(key: WebClientKey) {
  const { clientId, clientSecret } = webClients[key];
  return discover(clientId, clientSecret);
}

export function serviceConfig() {
  return discover(serviceClient.clientId, serviceClient.clientSecret);
}

// The auth server's signing keys, from the discovery document's jwks_uri, which sign its ID tokens
// and its logout tokens alike. jose fetches them when it first needs them, and again for a kid it
// doesn't know, so a rotated key is picked up.
const globalKeys = globalThis as unknown as { testappKeys?: Map<string, JWTVerifyGetKey> };
const keySets = (globalKeys.testappKeys ??= new Map<string, JWTVerifyGetKey>());

export function signingKeys(config: client.Configuration): JWTVerifyGetKey {
  const uri = config.serverMetadata().jwks_uri;
  if (!uri) throw new Error("The discovery document has no jwks_uri.");
  let keys = keySets.get(uri);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(uri));
    keySets.set(uri, keys);
  }
  return keys;
}

// What a failed call to the auth server said, for showing on the page.
export function describeError(error: unknown) {
  if (error instanceof client.ResponseBodyError) {
    return { error: error.error, error_description: error.error_description, status: error.status };
  }
  if (error instanceof client.AuthorizationResponseError) {
    return { error: error.error, error_description: error.error_description };
  }
  // A 401 with WWW-Authenticate, such as the token endpoint's invalid_client: the status and the
  // challenge, rather than "[object Object]".
  if (error instanceof client.WWWAuthenticateChallengeError) {
    return { status: error.status, challenges: error.cause };
  }
  if (error instanceof Error) {
    return { message: error.message, code: (error as { code?: string }).code, cause: String(error.cause ?? "") };
  }
  return { error: String(error) };
}
